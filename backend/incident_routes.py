from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import String, and_, case, cast, func, or_, select, tuple_

from .api import local_only, sensor_ids
from .auth.store import audit, require_admin
from .correlation import mapping_query
from .cowrie_provenance import event_mode
from .incidents import (MAX_EVIDENCE, SEVERITIES, evaluation_view, get_incident_for_response,
                        lock_incident, publish, register_analysis, scoped, seal_events)
from .sensitive import session_redactors

Decision = Literal["incidente_confirmado", "actividad_sospechosa", "actividad_autorizada", "evidencia_insuficiente"]
Severity = Literal["S0", "S1", "S2", "S3", "S4"]
Priority = Literal["baja", "media", "alta", "inmediata", "por_determinar"]
Mode = Literal["cowrie_shell", "cowrie_proxy", "cowrie_llm", "desconocido"]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=12, max_length=2000)]
EventId = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]{0,18}$")]

router = APIRouter(prefix="/api/incidentes", tags=["Incidentes"], dependencies=[Depends(local_only)])


def tables_from(request):
    tables = request.app.state.tables
    if "incidente" not in tables:
        raise HTTPException(503, "Instale la migración 016 para habilitar la evaluación de incidentes")
    return tables


def base_query(tables):
    i, e = tables["incidente"], tables["incidente_evaluacion"]
    return (select(i.c.id_incidente, i.c.revision_actual, i.c.actualizado_en, i.c.creado_en,
                   e.c.titulo, e.c.resumen, e.c.decision, e.c.severidad, e.c.prioridad, e.c.clasificacion,
                   e.c.detalle["modalidades"].label("modalidades"))
            .join(e, and_(e.c.id_incidente == i.c.id_incidente, e.c.revision_evaluacion == i.c.revision_actual))
            .where(scoped(i, tables, sensor_ids())))


def scoped_redact(conn, tables, rows):
    links = tables["incidente_sesion"]
    incidence = {row["id_incidente"]: [] for row in rows}
    for link in conn.execute(select(links.c.id_incidente, links.c.id_sesion).where(
        links.c.id_incidente.in_(incidence))):
        incidence[link.id_incidente].append(link.id_sesion)
    redactors = session_redactors(conn, tables["evento"], {sid for ids in incidence.values() for sid in ids})
    result = []
    for row in rows:
        public = dict(row)
        for sid in incidence[row["id_incidente"]]:
            public = redactors[sid].payload(public)
        result.append(public)
    return result


@router.get("")
def browse(request: Request, q: Annotated[str, Query(max_length=100)] = "",
           decision: Decision | None = None, severidad: Severity | None = None, prioridad: Priority | None = None,
           modalidad: Mode | None = None, id_sesion: UUID | None = None,
           orden: Literal["recientes", "antiguos", "severidad"] = "recientes",
           limite: Annotated[int, Query(ge=1, le=100)] = 25, cursor: Annotated[str | None, Query(max_length=1024)] = None):
    from datetime import datetime

    tables = tables_from(request)
    i, e, link, session = (tables[key] for key in ("incidente", "incidente_evaluacion", "incidente_sesion", "sesion"))
    query = base_query(tables)
    for column, value in ((e.c.decision, decision), (e.c.severidad, severidad), (e.c.prioridad, prioridad)):
        if value:
            query = query.where(column == value)
    if modalidad:
        query = query.where(e.c.detalle["modalidades"].contains([modalidad]))
    if id_sesion:
        query = query.where(select(1).where(link.c.id_incidente == i.c.id_incidente, link.c.id_sesion == id_sesion).exists())
    q = q.strip()
    if q:
        matching_session = (select(1).select_from(link.join(session, link.c.id_sesion == session.c.id_sesion))
                            .where(link.c.id_incidente == i.c.id_incidente,
                                   session.c.cowrie_session_id.icontains(q, autoescape=True)).exists())
        query = query.where(or_(e.c.titulo.icontains(q, autoescape=True), cast(i.c.id_incidente, String).startswith(q, autoescape=True),
                                matching_session))
    rank = case({s: n for n, s in enumerate(SEVERITIES, 1)}, value=e.c.severidad, else_=0)
    positions = (rank, i.c.actualizado_en, i.c.id_incidente) if orden == "severidad" else (i.c.actualizado_en, i.c.id_incidente)
    signer = URLSafeSerializer(request.app.state.auth_settings.secret, salt="incidentes-lista-v1")
    filters = [q, decision, severidad, prioridad, modalidad, str(id_sesion or ""), orden]
    if cursor:
        try:
            token = signer.loads(cursor)
            if token["filtros"] != filters:
                raise ValueError
            key = (datetime.fromisoformat(token["fecha"]), UUID(token["id"]))
            if orden == "severidad":
                key = (int(token["rango"]), *key)
        except (BadSignature, TypeError, ValueError, KeyError):
            raise HTTPException(422, "Cursor de incidentes inválido") from None
        condition = tuple_(*positions) > tuple_(*key) if orden == "antiguos" else tuple_(*positions) < tuple_(*key)
        query = query.where(condition)
    query = query.order_by(*(col.asc() if orden == "antiguos" else col.desc() for col in positions)).limit(limite+1)
    with request.app.state.engine.connect() as conn:
        rows = conn.execute(query).mappings().all()
        result = scoped_redact(conn, tables, rows[:limite])
    if len(rows) <= limite:
        return {"items": result, "cursor": None}
    last = rows[limite-1]
    return {"items": result, "cursor": signer.dumps({"filtros": filters, "fecha": last.actualizado_en.isoformat(),
            "id": str(last.id_incidente), "rango": SEVERITIES.index(last.severidad)+1 if last.severidad else 0})}


@router.get("/resumen")
def dashboard(request: Request):
    tables = tables_from(request)
    base = base_query(tables).subquery()
    with request.app.state.engine.connect() as conn:
        rows = conn.execute(select(base.c.decision, base.c.severidad, func.count().label("total"))
                            .group_by(base.c.decision, base.c.severidad).order_by(base.c.decision, base.c.severidad)).mappings()
        data = [dict(row) for row in rows]
    return {"total": sum(row["total"] for row in data), "distribucion": data, "poblacion": "Evaluaciones vigentes, sensores autorizados"}


def read(request, conn, id_incidente, revision=None):
    result = get_incident_for_response(conn, request.state.user, id_incidente, revision)
    if result is None:
        raise HTTPException(404, "Incidente o evaluación no encontrado")
    return result


@router.get("/{id_incidente}")
def detail(id_incidente: UUID, request: Request):
    tables = tables_from(request)
    with request.app.state.engine.connect() as conn:
        if not conn.in_transaction():
            conn.execution_options(isolation_level="REPEATABLE READ")
        view = read(request, conn, id_incidente)
        sessions, events, analysis, actor = (tables[k] for k in ("sesion", "evento", "incidente_analisis", "usuario"))
        evidence = {int(c["id_evento"]): c for c in view["evidencias"]}
        groups = {UUID(sid) for sid in view["alcance"]["sesiones"]}
        mode = event_mode(events, sessions, request.app.state.instances)
        timeline = (select(events.c.id_evento, events.c.id_sesion, events.c.tipo_evento, events.c.fecha_hora,
                           events.c.datos_originales, mode.label("modalidad"))
                    .join(sessions, sessions.c.id_sesion == events.c.id_sesion).where(events.c.id_evento.in_(evidence))
                    .order_by(events.c.fecha_hora, events.c.id_evento))
        redactors = session_redactors(conn, events, groups)
        items = []
        for row in conn.execute(timeline):
            command = row.datos_originales.get("input") if row.tipo_evento == "cowrie.command.input" else None
            safe = redactors.get(row.id_sesion)
            if safe:
                items.append(safe.payload({**evidence[row.id_evento], "tipo_evento": row.tipo_evento, "fecha_hora": row.fecha_hora,
                    "modalidad": row.modalidad, "comando": command if view["evidencia_verificable"] else None}))
        obs, ioc, kind = (tables[k] for k in ("observacion_ioc", "ioc", "tipo_ioc"))
        observations = conn.execute(select(obs.c.id_evento, obs.c.id_observacion, obs.c.estado_revision,
                        ioc.c.valor, kind.c.nombre.label("tipo"))
                        .join(ioc, ioc.c.id_ioc == obs.c.id_ioc).join(kind, kind.c.id_tipo_ioc == ioc.c.id_tipo_ioc)
                        .where(obs.c.id_evento.in_(evidence)).order_by(obs.c.id_evento, obs.c.id_observacion).limit(101)).mappings().all()
        findings = []
        for row in observations[:100]:
            cid = evidence[row.id_evento]
            findings.append(redactors[UUID(cid["id_sesion"])].payload({**row, "id_evento": str(row.id_evento),
                                                                    "id_sesion": cid["id_sesion"]}))
        citation = tables["mapeo_mitre_evento"]
        mappings = mapping_query(tables).join(citation, citation.c.id_mapeo == tables["mapeo_mitre"].c.id_mapeo).add_columns(
            citation.c.id_evento).where(citation.c.id_evento.in_(evidence)).order_by(citation.c.id_evento, citation.c.id_mapeo).limit(101)
        mapped = conn.execute(mappings).mappings().all()
        mitre = [{"id_evento": str(row.id_evento), "id_sesion": evidence[row.id_evento]["id_sesion"],
                  "codigo_tecnica": row.codigo_tecnica, "tecnica": row.tecnica, "estado_revision": row.estado_revision}
                 for row in mapped[:100]]
        provenance = conn.execute(select(analysis.c.id_analisis, analysis.c.id_sesion, analysis.c.revision_ingreso).where(
            analysis.c.id_incidente == id_incidente).order_by(analysis.c.revision_ingreso.desc()).limit(101)).mappings().all()
        information = conn.execute(select(sessions.c.id_sesion, sessions.c.cowrie_session_id, sessions.c.fecha_inicio)
                                   .where(sessions.c.id_sesion.in_(groups)).order_by(sessions.c.fecha_inicio)).mappings()
        revisions = tables["incidente_evaluacion"]
        history = conn.execute(select(revisions.c.revision_evaluacion, revisions.c.decision, revisions.c.severidad,
                revisions.c.prioridad, revisions.c.evaluado_en, actor.c.nombre_usuario.label("actor"))
                .outerjoin(actor, revisions.c.id_actor == actor.c.id_usuario).where(revisions.c.id_incidente == id_incidente)
                .order_by(revisions.c.revision_evaluacion.desc()).limit(101)).mappings().all()
        return {**view, "eventos": items, "iocs": findings if view["evidencia_verificable"] else [],
                "mitre": mitre if view["evidencia_verificable"] else [],
                "sesiones": [redactors[row.id_sesion].payload(dict(row)) for row in information],
                "analisis": [dict(row) for row in provenance[:100]], "historial": [dict(row) for row in history[:100]],
                "limites": {"revision": 100, "analisis": 100, "iocs": 100, "mitre": 100,
                            "hay_mas": any(len(group) > 100 for group in (observations, mapped, provenance, history))}}


@router.get("/{id_incidente}/evaluaciones/{revision}")
def revision_view(id_incidente: UUID, revision: int, request: Request):
    tables_from(request)
    if not 1 <= revision <= 2147483647:
        raise HTTPException(422, "Revisión fuera de rango")
    with request.app.state.engine.connect() as conn:
        return read(request, conn, id_incidente, revision)


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id_analisis: UUID
    motivo: Reason


@router.post("", status_code=201)
def create(body: Register, request: Request):
    tables = tables_from(request)
    with request.app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        incident_id = register_analysis(conn, tables, sensor_ids(), request.app.state.instances, body.id_analisis,
                                        manual=True, actor=actor.id_usuario, reason=body.motivo)
        audit(conn, request, "incidente_identificacion", actor=actor.id_usuario, reason=str(incident_id))
        return read(request, conn, incident_id)


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision_esperada: int = Field(ge=1, le=2147483647, strict=True)
    decision: Decision
    severidad: Severity | None
    prioridad: Priority
    motivo: Reason
    resumen: Reason
    impacto_confirmado: Reason | None = None
    corroboracion: Reason | None = None
    recursos_confirmados: list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=160)]] = Field(
        default_factory=list, max_length=20)
    eventos: list[EventId] = Field(min_length=1, max_length=MAX_EVIDENCE)


@router.post("/{id_incidente}/revisiones", status_code=201)
def review(id_incidente: UUID, body: Review, request: Request):
    tables = tables_from(request)
    with request.app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        incident = lock_incident(conn, tables, sensor_ids(), id_incidente, True)
        if incident is None:
            raise HTTPException(404, "Incidente no encontrado")
        current = evaluation_view(conn, tables, incident, None)
        if body.revision_esperada != incident.revision_actual or not current["evidencia_verificable"]:
            raise HTTPException(409, {"mensaje": "La revisión cambió o su evidencia ya no es verificable",
                                     "revision_actual": incident.revision_actual})
        existing = {item["id_evento"]: item for item in current["evidencias"]}
        if not set(body.eventos) <= existing.keys():
            raise HTTPException(422, "La revisión contiene citas ajenas al incidente")
        if body.decision == "incidente_confirmado" and (not body.severidad or body.prioridad == "por_determinar"):
            raise HTTPException(422, "Confirme severidad y prioridad antes de habilitar la respuesta")
        if (body.impacto_confirmado or body.recursos_confirmados) and not body.corroboracion:
            raise HTTPException(422, "Documente la fuente independiente que corrobora el alcance o el impacto")
        refs = {int(item): UUID(existing[item]["id_analisis"]) if existing[item]["id_analisis"] else None
                for item in body.eventos}
        sids = [UUID(value) for value in current["alcance"]["sesiones"]]
        citations = seal_events(conn, tables, request.app.state.instances, sids, refs)
        if len(citations) != len(refs) or any(c["procedencia"]["evento_sha256"] !=
            existing[str(c["id_evento"])]["procedencia"]["evento_sha256"] for c in citations):
            raise HTTPException(409, "La evidencia cambió durante la revisión")
        revision = incident.revision_actual + 1
        fields = {"decision": body.decision, "severidad": body.severidad, "prioridad": body.prioridad,
                  "clasificacion": current["clasificacion"], "titulo": current["titulo"], "resumen": body.resumen,
                  "id_actor": actor.id_usuario, "detalle": {**current["detalle"], "origen": "revision_humana",
                      "motivo": body.motivo, "impacto_confirmado": body.impacto_confirmado,
                      "corroboracion": body.corroboracion, "recursos_confirmados": body.recursos_confirmados,
                      "evidencias_incluidas": len(citations)}}
        for redactor in session_redactors(conn, tables["evento"], sids).values():
            fields = redactor.payload(fields)
        publish(conn, tables, id_incidente, revision, fields, citations, sids)
        audit(conn, request, "incidente_evaluacion_revisada", actor=actor.id_usuario,
              reason=str(id_incidente), revision=revision)
        return read(request, conn, id_incidente)
