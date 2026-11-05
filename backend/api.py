"""Minimal Cowrie ingestion API for the existing honeypot schema."""
import hashlib
import hmac
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, String, cast, create_engine, or_, select, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from pgvector.sqlalchemy import VECTOR  # registers pgvector type for reflection
from .analysis_state import public_state, states_for_sessions

load_dotenv()

SENSITIVE = {"password", "passwd", "passphrase", "secret", "token", "key"}


def safe(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE or "password" in k.lower() else safe(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    return value


def local_only(request: Request):
    allowed = {"127.0.0.1", "::1", os.getenv("DEV_HOST_IP", "")}
    if not request.client or request.client.host not in allowed:
        raise HTTPException(403, "Acceso local requerido")


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp requerido")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp sin zona horaria")
    return parsed


def event_identity(event):
    source = event.get("_collector")
    if not isinstance(source, dict) or not isinstance(source.get("source_id"), str):
        raise ValueError("identificador de origen requerido")
    digest = hashlib.sha256(source["source_id"].encode()).digest()
    return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1), int.from_bytes(digest[8:12], "big") & ((1 << 31) - 1)


class Batch(BaseModel):
    eventos: list[dict] = Field(min_length=1, max_length=500)


@asynccontextmanager
async def lifespan(app: FastAPI):
    required = ["DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "INGEST_API_KEY", "HONEYPOT_ID"]
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("Variables faltantes: " + ", ".join(missing))
    app.state.honeypot_id = UUID(os.environ["HONEYPOT_ID"])
    app.state.api_key = os.environ["INGEST_API_KEY"]
    url = URL.create("postgresql+psycopg", username=os.environ["DATABASE_USER"], password=os.environ["DATABASE_PASSWORD"], host=os.environ["DATABASE_HOST"], database=os.environ["DATABASE_NAME"])
    engine = create_engine(url, pool_pre_ping=True)
    meta = MetaData()
    names = ("honeypot", "sesion", "evento", "modelo_llm", "analisis_llm", "accion_identificada", "accion_evento", "tipo_ioc", "ioc", "deteccion_ioc", "accion_ioc", "tactica_mitre", "tecnica_mitre", "tecnica_tactica", "mapeo_mitre")
    tables = {name: Table(name, meta, schema="honeypot", autoload_with=engine) for name in names}
    expected = {"sesion": {"id_sesion", "id_honeypot", "cowrie_session_id", "fecha_inicio", "ip_origen", "puerto_origen", "puerto_destino", "protocolo", "fecha_fin"}, "evento": {"id_evento", "id_sesion", "numero_secuencia", "tipo_evento", "fecha_hora", "datos_originales"}}
    for name, columns in expected.items():
        if not columns <= set(tables[name].columns.keys()):
            raise RuntimeError(f"Esquema {name} incompatible")
    with engine.connect() as conn:
        if conn.execute(select(tables["honeypot"].c.id_honeypot).where(tables["honeypot"].c.id_honeypot == app.state.honeypot_id)).scalar_one_or_none() is None:
            raise RuntimeError("HONEYPOT_ID no existe")
    app.state.engine, app.state.tables = engine, tables
    yield
    engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.post("/api/ingesta/eventos")
def ingest(batch: Batch, x_api_key: str | None = Header(default=None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, app.state.api_key):
        raise HTTPException(401, "Clave inválida")
    return persist_events(batch.eventos)


def persist_events(events):
    try:
        return _persist_events(events)
    except (SQLAlchemyError, ValueError, TypeError):
        raise HTTPException(422, "El evento no cumple las restricciones de la base de datos") from None


def _persist_events(events):
    sesion, evento = app.state.tables["sesion"], app.state.tables["evento"]
    prepared = []
    try:
        for raw in events:
            sid = raw.get("session")
            if not isinstance(sid, str) or not sid.strip() or len(sid) > 100:
                raise ValueError("session inválida")
            kind = raw.get("eventid")
            if not isinstance(kind, str) or not kind.strip() or len(kind) > 100:
                raise ValueError("eventid inválido")
            event_id, sequence = event_identity(raw)
            when = timestamp(raw.get("timestamp"))
            prepared.append((raw, sid, kind, event_id, sequence, when))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    inserted = 0
    with app.state.engine.begin() as conn:
        for raw, sid, kind, event_id, sequence, when in prepared:
            session_values = {"id_honeypot": app.state.honeypot_id, "cowrie_session_id": sid, "fecha_inicio": when, "protocolo": str(raw.get("protocol") or "ssh")[:20]}
            if raw.get("src_ip"):
                session_values["ip_origen"] = raw["src_ip"]
            for source, dest in (("src_port", "puerto_origen"), ("dst_port", "puerto_destino")):
                if raw.get(source) is not None:
                    session_values[dest] = int(raw[source])
            base_statement = insert(sesion).values(**session_values)
            statement = base_statement.on_conflict_do_update(index_elements=["id_honeypot", "cowrie_session_id"], set_={"fecha_inicio": func.least(sesion.c.fecha_inicio, base_statement.excluded.fecha_inicio), "ip_origen": func.coalesce(sesion.c.ip_origen, base_statement.excluded.ip_origen), "actualizado_en": func.now()})
            conn.execute(statement)
            session_id = conn.execute(select(sesion.c.id_sesion).where(sesion.c.id_honeypot == app.state.honeypot_id, sesion.c.cowrie_session_id == sid)).scalar_one()
            if kind == "cowrie.session.closed":
                conn.execute(sesion.update().where(sesion.c.id_sesion == session_id, sesion.c.fecha_inicio <= when).values(fecha_fin=when, actualizado_en=func.now()))
            original = dict(raw)
            original.pop("_collector", None)
            duplicate = conn.execute(select(evento.c.id_evento).where(evento.c.id_sesion == session_id, evento.c.datos_originales == original).limit(1)).scalar_one_or_none()
            if duplicate is not None:
                continue
            stmt = insert(evento).values(id_evento=event_id, id_sesion=session_id, numero_secuencia=sequence, tipo_evento=kind, fecha_hora=when, datos_originales=original).on_conflict_do_nothing(index_elements=["id_evento"])
            result = conn.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                existing = conn.execute(select(evento.c.id_sesion, evento.c.numero_secuencia, evento.c.datos_originales).where(evento.c.id_evento == event_id)).one()
                if existing.id_sesion != session_id or existing.numero_secuencia != sequence or existing.datos_originales != original:
                    raise HTTPException(409, "Colisión de identificador de evento")
    return {"recibidos": len(prepared), "insertados": inserted, "duplicados": len(prepared) - inserted}


@app.get("/api/sesiones")
def sessions(request: Request, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), q: str = Query('', max_length=100)):
    local_only(request)
    table = app.state.tables["sesion"]
    events_table = app.state.tables["evento"]
    analysis_table = app.state.tables["analisis_llm"]
    count_events = select(func.count()).where(events_table.c.id_sesion == table.c.id_sesion).scalar_subquery().label("eventos")
    statement = select(table.c.id_sesion, table.c.cowrie_session_id, table.c.ip_origen, table.c.protocolo, table.c.fecha_inicio, table.c.fecha_fin, count_events).where(table.c.id_honeypot == app.state.honeypot_id)
    if q.strip():
        term = f'%{q.strip()}%'
        statement = statement.where(or_(table.c.cowrie_session_id.ilike(term), cast(table.c.ip_origen, String).ilike(term)))
    with app.state.engine.connect() as conn:
        rows = conn.execute(statement.order_by(table.c.fecha_inicio.desc()).limit(limit).offset(offset)).mappings().all()
        states = states_for_sessions(conn, analysis_table, {row.id_sesion: row.eventos for row in rows})
    return [{**{k: str(v) if isinstance(v, UUID) else v for k, v in row.items()}, **public_state(states[row.id_sesion])} for row in rows]


@app.get("/api/sesiones/{id}/eventos")
def events(id: UUID, request: Request, limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0)):
    local_only(request)
    table = app.state.tables["evento"]
    with app.state.engine.connect() as conn:
        rows = conn.execute(select(table.c.id_evento, table.c.tipo_evento, table.c.fecha_hora, table.c.datos_originales).where(table.c.id_sesion == id).order_by(table.c.fecha_hora, table.c.id_evento).limit(limit).offset(offset)).mappings().all()
    return [{**dict(row), "datos_originales": safe(row.datos_originales)} for row in rows]


from . import routes  # noqa: E402,F401 - registers extended routes
