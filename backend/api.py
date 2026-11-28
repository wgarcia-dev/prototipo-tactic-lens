"""Minimal Cowrie ingestion API for the existing honeypot schema."""
import asyncio
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
from sqlalchemy import MetaData, Table, String, and_, cast, create_engine, inspect, or_, select, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from pgvector.sqlalchemy import VECTOR  # registers pgvector type for reflection
from .analysis_state import current_inputs, public_state, states_for_sessions
from .db import database_engine
from .db_access import runtime_grants, verify_runtime_access
from .cowrie_provenance import event_mode, public_provenance, session_mode
from .sensitive import Redactor, redact as safe, session_redactors
from .auth.config import Settings

load_dotenv()

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
    from .correlation import transfer_window
    validate_demo_settings()
    required = ["DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "INGEST_API_KEY", "HONEYPOT_ID"]
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("Variables faltantes: " + ", ".join(missing))
    app.state.honeypot_id = UUID(os.environ["HONEYPOT_ID"])
    app.state.instances = {}
    for modality in ("cowrie_shell", "cowrie_proxy", "cowrie_llm"):
        value = os.getenv("HONEYPOT_ID_" + modality.upper())
        if value:
            instance = UUID(value)
            if instance == app.state.honeypot_id or instance in app.state.instances.values():
                raise RuntimeError("Cada modalidad requiere un honeypot exclusivo")
            app.state.instances[modality] = instance
    app.state.api_key = os.environ["INGEST_API_KEY"]
    app.state.auth_settings = Settings.load()
    app.state.ioc_transfer_window = transfer_window(os.getenv("IOC_CORRELACION_MAX_SEGUNDOS"))
    from .auth.mail_config import MailConfig
    app.state.mail_config = MailConfig.load()
    engine = database_engine()
    meta = MetaData()
    with engine.connect() as conn:
        if app.state.auth_settings.production or os.getenv("DATABASE_ENFORCE_RUNTIME_ROLE", "").lower() == "true":
            verify_runtime_access(conn, conn.scalar(select(func.current_user())))
        grants = runtime_grants(inspect(conn).get_table_names(schema="honeypot"))
    tables = {name: Table(name, meta, schema="honeypot", autoload_with=engine)
              for name in grants if name != "schema_migration"}
    expected = {"sesion": {"id_sesion", "id_honeypot", "cowrie_session_id", "fecha_inicio", "ip_origen", "puerto_origen", "puerto_destino", "protocolo", "fecha_fin", "revision_eventos"}, "evento": {"id_evento", "id_sesion", "numero_secuencia", "tipo_evento", "fecha_hora", "datos_originales"}}
    expected.update(observacion_ioc={"detalles"}, deteccion_ioc={"id_observacion"})
    for name, columns in expected.items():
        if not columns <= set(tables[name].columns.keys()):
            raise RuntimeError(f"Esquema {name} incompatible")
    with engine.connect() as conn:
        if set(conn.scalars(select(tables["honeypot"].c.id_honeypot).where(tables["honeypot"].c.id_honeypot.in_(sensor_ids())))) != set(sensor_ids()):
            raise RuntimeError("HONEYPOT_ID no existe")
    app.state.engine, app.state.tables = engine, tables
    from .safeguards import backfill, configure_legacy_archive, legacy_archive
    with engine.begin() as conn:
        configure_legacy_archive(app, conn)
        if not legacy_archive(app):
            backfill(conn, tables, sensor_ids())
    from .monitoring import SnapshotCache
    app.state.dashboard_cache = SnapshotCache()
    from .realtime import MonitorHub, PostgresMonitor
    from starlette.concurrency import run_in_threadpool
    app.state.monitor_hub = MonitorHub()
    monitor = PostgresMonitor(engine, app.state.monitor_hub, sensor_ids(), app.state.dashboard_cache)
    monitor.thread.start()
    await run_in_threadpool(monitor.ready.wait, 1)
    from .auth.notifications import drain_outbox
    outbox = (asyncio.create_task(drain_outbox(app))
              if os.getenv("MAIL_OUTBOX_ENABLED", "true").lower() == "true" else None)
    from .incident_automation import drain
    automation = asyncio.create_task(drain(app)) if "incidente_borrador" in tables else None
    try:
        yield
    finally:
        workers = [task for task in (outbox, automation) if task is not None]
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await run_in_threadpool(monitor.close)
        engine.dispose()


app = FastAPI(lifespan=lifespan)
from .ingest_transport import IngestTransportMiddleware
app.add_middleware(IngestTransportMiddleware)


def sensor_ids():
    return (app.state.honeypot_id, *app.state.instances.values())


@app.post("/api/ingesta/eventos")
def ingest(batch: Batch, x_api_key: str | None = Header(default=None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, app.state.api_key):
        raise HTTPException(401, "Clave inválida")
    result = persist_events(batch.eventos, partial=True, instances=app.state.instances)
    if result["rechazados"] == result["recibidos"]:
        from fastapi.responses import JSONResponse
        return JSONResponse(result, status_code=422)
    return result


def persist_events(events, *, partial=False, instances=None, legacy_manual_aliases=None):
    from .ingestion import persist
    received_at = datetime.now(timezone.utc).isoformat()
    result = persist(app.state.engine, app.state.tables, app.state.honeypot_id, events, partial=partial,
                     instances=instances, received_at=received_at, legacy_manual_aliases=legacy_manual_aliases)
    if result['insertados'] and getattr(app.state, 'dashboard_cache', None):
        app.state.dashboard_cache.invalidate()
    return result


@app.get("/api/sesiones")
def sessions(request: Request, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
             q: str = Query('', max_length=100), modalidad: str | None = None,
             antes_fecha: datetime | None = None, antes_id: UUID | None = None):
    local_only(request)
    table = app.state.tables["sesion"]
    events_table = app.state.tables["evento"]
    analysis_table = app.state.tables["analisis_llm"]
    mode = session_mode(table, events_table, app.state.instances)
    statement = select(table.c.id_sesion, table.c.id_honeypot, table.c.cowrie_session_id, table.c.ip_origen,
                       table.c.protocolo, table.c.fecha_inicio, table.c.fecha_fin).where(table.c.id_honeypot.in_(sensor_ids()))
    if modalidad is not None:
        if modalidad not in {"desconocido", "cowrie_shell", "cowrie_proxy", "cowrie_llm"}:
            raise HTTPException(422, "Modalidad no válida")
        statement = statement.where(mode == modalidad)
    if q.strip():
        term = f'%{q.strip()}%'
        statement = statement.where(or_(table.c.cowrie_session_id.ilike(term), cast(table.c.ip_origen, String).ilike(term)))
    if antes_fecha is not None or antes_id is not None:
        if antes_fecha is None or antes_fecha.tzinfo is None or antes_id is None or offset:
            raise HTTPException(422, "El cursor requiere fecha con zona horaria e identificador, sin desplazamiento")
        statement = statement.where(table.c.fecha_inicio <= antes_fecha, or_(table.c.fecha_inicio < antes_fecha,
            and_(table.c.fecha_inicio == antes_fecha, table.c.id_sesion > antes_id)))
    page = statement.add_columns(mode.label("modalidad")).order_by(
        table.c.fecha_inicio.desc(), table.c.id_sesion).limit(limit).offset(offset).subquery()
    count_events = select(func.count()).where(events_table.c.id_sesion == page.c.id_sesion).scalar_subquery().label("eventos")
    has_result = select(1).where(analysis_table.c.id_sesion == page.c.id_sesion,
                                 analysis_table.c.estado == 'completado').exists().label('tiene_resultado')
    with app.state.engine.connect() as conn:
        if not conn.in_transaction():
            conn.execution_options(isolation_level="REPEATABLE READ")
        rows = conn.execute(select(page, count_events, has_result).order_by(page.c.fecha_inicio.desc(), page.c.id_sesion)).mappings().all()
        current, _ = current_inputs(conn, app.state.tables, (row.id_sesion for row in rows if row.tiene_resultado),
                                    sensor_ids(), app.state.instances)
        inputs = {row.id_sesion: current.get(row.id_sesion, {}) for row in rows}
        states = states_for_sessions(conn, analysis_table, inputs)
        redactors = session_redactors(conn, events_table, states)
    return [redactors[row.id_sesion].payload({**{key:value for key,value in row.items() if key != 'tiene_resultado'},
            "procedencia": public_provenance(row.modalidad,
                {"fuentes": ["eventos_consistentes"]} if row.modalidad != "desconocido" else None),
            **public_state(states[row.id_sesion])}) for row in rows]


@app.get("/api/sesiones/{id}/eventos")
def events(id: UUID, request: Request, limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0),
           id_evento: int | None = Query(None, ge=0, le=(1 << 63) - 1), comandos_recientes: bool = False):
    local_only(request)
    table = app.state.tables["evento"]
    sessions = app.state.tables["sesion"]
    with app.state.engine.connect() as conn:
        fields = [table.c.procedencia_cowrie] if "procedencia_cowrie" in table.c else []
        query = (select(table.c.id_evento, table.c.tipo_evento, table.c.fecha_hora, table.c.datos_originales,
                        event_mode(table, sessions, app.state.instances).label("modalidad"), *fields)
                 .join(sessions, sessions.c.id_sesion == table.c.id_sesion)
                 .where(table.c.id_sesion == id, sessions.c.id_honeypot.in_(sensor_ids())))
        if id_evento is not None:
            query = query.where(table.c.id_evento == id_evento)
        order = (table.c.fecha_hora, table.c.numero_secuencia, table.c.id_evento)
        if comandos_recientes:
            query = query.where(table.c.tipo_evento == "cowrie.command.input")
            order = tuple(column.desc() for column in order)
        rows = conn.execute(query.order_by(*order).limit(limit).offset(offset)).mappings().all()
        if rows:
            redactor = session_redactors(conn, table, [id])[id]
    return [{**{k: v for k, v in row.items() if k != "procedencia_cowrie"}, "id_evento_texto": str(row.id_evento),
             "procedencia": public_provenance(row.modalidad, row.get("procedencia_cowrie")),
             "tipo_evento": redactor.text(row.tipo_evento),
             "datos_originales": redactor.payload(row.datos_originales, raw_event=True)} for row in rows]


from . import routes  # noqa: E402,F401 - registers extended routes
from .safeguards import router as safeguards_router
from .incident_routes import router as incidents_router
from .incident_response_routes import router as incident_response_router, board as incident_response_board
from .incident_automation_routes import router as incident_drafts, board as incident_automation_board
from .auth.routes import router as auth_router
from .auth.middleware import AuthMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

app.include_router(auth_router)
app.include_router(safeguards_router)
app.include_router(incidents_router)
app.include_router(incident_response_router)
app.include_router(incident_response_board)
app.include_router(incident_drafts)
app.include_router(incident_automation_board)
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
    redactor = Redactor((exc.body,))
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": redactor.payload(error["loc"]), "msg": redactor.text(error["msg"]), "type": error["type"]}
        for error in exc.errors()
    ]})
