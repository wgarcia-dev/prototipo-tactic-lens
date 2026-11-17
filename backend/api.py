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
from .db import database_engine
from .auth.config import Settings

load_dotenv()

SENSITIVE = {"password", "passwd", "passphrase", "secret", "token", "key"}


def safe(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE or "password" in k.lower() else safe(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    return value


def local_only(request: Request):
    # Kept as an internal compatibility name for the existing module routes.
    # A local IP is no longer an authentication credential.
    if not getattr(request.state, "user", None):
        from .auth.store import authorize_request
        authorize_request(request)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp requerido")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp sin zona horaria")
    return parsed


from .ingestion import event_identity  # compatibility import for existing callers/tests


class Batch(BaseModel):
    eventos: list[dict] = Field(min_length=1, max_length=500)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .ingest_transport import validate_demo_settings
    validate_demo_settings()
    required = ["DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "INGEST_API_KEY", "HONEYPOT_ID"]
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("Variables faltantes: " + ", ".join(missing))
    app.state.honeypot_id = UUID(os.environ["HONEYPOT_ID"])
    app.state.api_key = os.environ["INGEST_API_KEY"]
    app.state.auth_settings = Settings.load()
    from .auth.mail_config import MailConfig
    app.state.mail_config = MailConfig.load()
    engine = database_engine()
    meta = MetaData()
    names = ("honeypot", "sesion", "evento", "modelo_llm", "analisis_llm", "accion_identificada", "accion_evento", "tipo_ioc", "ioc", "observacion_ioc", "deteccion_ioc", "accion_ioc", "tactica_mitre", "tecnica_mitre", "tecnica_tactica", "mapeo_mitre", "usuario", "rol", "auth_factor", "auth_token", "auth_sesion", "auth_recuperacion", "auth_limite", "auth_auditoria", "auth_solicitud_password", "auth_soporte", "auth_notificacion", "evento_origen")
    tables = {name: Table(name, meta, schema="honeypot", autoload_with=engine) for name in names}
    expected = {"sesion": {"id_sesion", "id_honeypot", "cowrie_session_id", "fecha_inicio", "ip_origen", "puerto_origen", "puerto_destino", "protocolo", "fecha_fin"}, "evento": {"id_evento", "id_sesion", "numero_secuencia", "tipo_evento", "fecha_hora", "datos_originales"}}
    for name, columns in expected.items():
        if not columns <= set(tables[name].columns.keys()):
            raise RuntimeError(f"Esquema {name} incompatible")
    with engine.connect() as conn:
        if conn.execute(select(tables["honeypot"].c.id_honeypot).where(tables["honeypot"].c.id_honeypot == app.state.honeypot_id)).scalar_one_or_none() is None:
            raise RuntimeError("HONEYPOT_ID no existe")
    app.state.engine, app.state.tables = engine, tables
    from .monitoring import SnapshotCache
    app.state.dashboard_cache = SnapshotCache()
    from .realtime import MonitorHub
    app.state.monitor_hub = MonitorHub()
    yield
    engine.dispose()


app = FastAPI(lifespan=lifespan)
from .ingest_transport import IngestTransportMiddleware
app.add_middleware(IngestTransportMiddleware)


@app.post("/api/ingesta/eventos")
def ingest(batch: Batch, x_api_key: str | None = Header(default=None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, app.state.api_key):
        raise HTTPException(401, "Clave inválida")
    result = persist_events(batch.eventos, partial=True)
    if result["rechazados"] == result["recibidos"]:
        from fastapi.responses import JSONResponse
        return JSONResponse(result, status_code=422)
    return result


def persist_events(events, *, partial=False):
    from .ingestion import persist
    received_at = datetime.now(timezone.utc).isoformat()
    result = persist(app.state.engine, app.state.tables, app.state.honeypot_id, events, partial=partial)
    if result['insertados'] and getattr(app.state, 'dashboard_cache', None):
        app.state.dashboard_cache.invalidate()
    if result['insertados'] and getattr(app.state, 'monitor_hub', None):
        app.state.monitor_hub.publish(result, received_at)
    return result


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
from .auth.routes import router as auth_router
from .auth.middleware import AuthMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

app.include_router(auth_router)
from .auth.onboarding import router as onboarding_router
app.include_router(onboarding_router)
from .auth.recovery import router as recovery_router
from .auth.administration import router as administration_router
app.include_router(recovery_router)
app.include_router(administration_router)
from .auth.support import router as support_router
app.include_router(support_router)
app.add_middleware(AuthMiddleware)
from .realtime import monitor_socket
app.add_api_websocket_route('/api/monitor/ws', monitor_socket)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Pydantic's default JSON includes rejected input values (including secrets).
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]})
