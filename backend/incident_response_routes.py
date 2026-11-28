from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy import func, select

from . import incident_response_recommendations as llm, incident_response_report as reports
from .api import local_only, sensor_ids
from .auth.store import audit
from .db_access import RESPONSE_GRANTS
from .incident_response import (ResponseContext, action_transition, active_plan, add_action,
                                eligible_actor, open_plan, require_admin, review_plan, transition_plan)
from .incident_response_models import (ActionInput, ActionState, ActionTransition, BoardConfig, Change,
                                       ImportProposal, PlanInput, PlanReview, PlanTransition, Proposal)
from .realtime import notify_change
from .safeguard_risk import recommendation_references


def response_schema(request: Request):
    if not RESPONSE_GRANTS.keys() <= request.app.state.tables.keys():
        raise HTTPException(503, "La respuesta a incidentes requiere las migraciones 016 y 017")


dependencies = [Depends(local_only), Depends(response_schema)]
router = APIRouter(prefix="/api/incidentes/{id_incidente}/respuesta", dependencies=dependencies, tags=["Respuesta a incidentes"])
board = APIRouter(prefix="/api/respuestas-incidentes", dependencies=dependencies, tags=["Respuesta a incidentes"])
Limit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(pattern=r"^[1-9][0-9]{0,18}$")]


def context(conn, request, id_incidente, *, write=False):
    actor = eligible_actor(conn, request) if write else request.state.user
    return ResponseContext(conn, request, actor, id_incidente, lock=write)


def cursor_value(cursor):
    if cursor and int(cursor) > 9223372036854775807:
        raise HTTPException(422, "Cursor fuera de rango")
    return int(cursor) if cursor else None


@router.get("")
def get_plan(id_incidente: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        return context(conn, request, id_incidente).view()


@router.post("", status_code=201)
def create_plan(id_incidente: UUID, body: PlanInput, request: Request):
    with request.app.state.engine.begin() as conn:
        return open_plan(context(conn, request, id_incidente, write=True), body)


@router.post("/revisiones")
def revise_plan(id_incidente: UUID, body: PlanReview, request: Request):
    with request.app.state.engine.begin() as conn:
        return review_plan(context(conn, request, id_incidente, write=True), body)


@router.post("/transiciones")
def change_plan(id_incidente: UUID, body: PlanTransition, request: Request):
    with request.app.state.engine.begin() as conn:
        return transition_plan(context(conn, request, id_incidente, write=True), body)


def user_names(conn, tables, ids):
    user = tables["usuario"]
    return dict(conn.execute(select(user.c.id_usuario, user.c.nombre_usuario)
                             .where(user.c.id_usuario.in_(ids))).all())


def action_view(ctx, row, names):
    item = {key: value for key, value in row.items() if key != "clave_origen"}
    return ctx.safe({**item, "orden": str(row.orden), "responsable": names.get(row.id_responsable),
                     "incidente_titulo": ctx.evaluation.titulo, "estado_respuesta": ctx.plan.estado,
                     "revision_evaluacion_actual": ctx.revision, "desactualizada": ctx.header()["desactualizada"]})


def list_actions(conn, request, id_incidente, estado, id_responsable, limite, cursor):
    tables = request.app.state.tables
    actions = tables["incidente_accion"]
    visible = {}
    if id_incidente:
        ctx = context(conn, request, id_incidente)
        if ctx.plan is None:
            return {"items": [], "cursor": None}
        visible[id_incidente] = ctx
    query = select(actions)
    if id_incidente:
        query = query.where(actions.c.id_incidente == id_incidente)
    if estado:
        query = query.where(actions.c.estado.in_(estado))
    if id_responsable:
        query = query.where(actions.c.id_responsable == id_responsable)
    before = cursor_value(cursor)
    if before is not None:
        query = query.where(actions.c.orden < before)
    # Scope comes from D1's service. Bound scanning and return a continuation even
    # when a page contains only incidents outside this actor's scope.
    scan_limit = limite if id_incidente else min(200, limite * 4)
    rows = conn.execute(query.order_by(actions.c.orden.desc()).limit(scan_limit + 1)).mappings().all()
    names = user_names(conn, tables, {r.id_responsable for r in rows if r.id_responsable})
    selected = []
    cursor = None
    for index, row in enumerate(rows[:scan_limit]):
        if row.id_incidente not in visible:
            try:
                visible[row.id_incidente] = context(conn, request, row.id_incidente)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                visible[row.id_incidente] = None
        if ctx := visible[row.id_incidente]:
            selected.append(action_view(ctx, row, names))
        cursor = str(row.orden) if index + 1 < len(rows) else None
        if len(selected) == limite:
            break
    return {"items": selected, "cursor": cursor}


@router.get("/acciones")
def get_actions(id_incidente: UUID, request: Request, limite: Limit = 25, cursor: Cursor = None,
                estado: Annotated[list[ActionState] | None, Query(max_length=7)] = None, id_responsable: UUID | None = None):
    with request.app.state.engine.connect() as conn:
        return list_actions(conn, request, id_incidente, estado, id_responsable, limite, cursor)


@board.get("/acciones")
def board_actions(request: Request, limite: Limit = 25, cursor: Cursor = None, id_incidente: UUID | None = None,
                  estado: Annotated[list[ActionState] | None, Query(max_length=7)] = None, id_responsable: UUID | None = None):
    with request.app.state.engine.connect() as conn:
        return list_actions(conn, request, id_incidente, estado, id_responsable, limite, cursor)


@router.post("/acciones", status_code=201)
def create_action(id_incidente: UUID, body: ActionInput, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = context(conn, request, id_incidente, write=True)
        ctx.check(body)
        active_plan(ctx)
        row = add_action(ctx, body, body.motivo, reference=body.referencia)
        return action_view(ctx, row, {})


@router.get("/acciones/{id_accion}")
def get_action(id_incidente: UUID, id_accion: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        row = ctx.action(id_accion)
        evidence = ctx.tables["incidente_accion_evidencia"]
        values = conn.execute(select(evidence).where(evidence.c.id_accion == id_accion)
                              .order_by(evidence.c.id_evidencia.desc()).limit(101)).mappings().all()
        names = user_names(conn, ctx.tables, {row.id_responsable} if row.id_responsable else set())
        return {**action_view(ctx, row, names), "evidencia": ctx.safe([
            {**item, "id_evidencia": str(item.id_evidencia), "id_evento": str(item.id_evento) if item.id_evento else None}
            for item in values[:100]]), "hay_mas_evidencia": len(values) > 100}


@router.post("/acciones/{id_accion}/transiciones")
def change_action(id_incidente: UUID, id_accion: UUID, body: ActionTransition, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = context(conn, request, id_incidente, write=True)
        return action_transition(ctx, ctx.action(id_accion), body)


def source_proposals(ctx):
    analysis, origin = (ctx.tables[name] for name in ("analisis_llm", "salvaguarda_origen"))
    by_analysis = {}
    for e in ctx.evaluation.evidencias:
        if e.id_analisis:
            by_analysis.setdefault(e.id_analisis, set()).add(e.id_evento)
    if not by_analysis:
        return []
    query = select(analysis.c.id_analisis, analysis.c.resultado_estructurado).where(
        analysis.c.id_analisis.in_(by_analysis), analysis.c.id_sesion.in_(ctx.session_ids), analysis.c.estado == "completado")
    origins = {(row.id_analisis, row.posicion): row.id_salvaguarda for row in ctx.conn.execute(
        select(origin).where(origin.c.id_analisis.in_(by_analysis)))}
    proposals = []
    for row in ctx.conn.execute(query.order_by(analysis.c.id_analisis)):
        for position, item, events in recommendation_references(row.resultado_estructurado):
            proposals.append({"id_analisis": row.id_analisis, "posicion": position, "id_salvaguarda":
                origins.get((row.id_analisis, position)), "recomendacion": item,
                "importable": bool(events) and set(events) <= by_analysis[row.id_analisis]})
    return proposals


@router.get("/antecedentes")
def antecedents(id_incidente: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        items = source_proposals(ctx)
        return {"items": ctx.safe(items[:100]), "omitidos": max(0, len(items) - 100)}


@router.post("/importaciones", status_code=201)
def import_proposal(id_incidente: UUID, body: ImportProposal, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = context(conn, request, id_incidente, write=True)
        require_admin(ctx.actor)
        ctx.check(body)
        active_plan(ctx)
        from_legacy = body.id_salvaguarda is not None
        if (body.id_analisis is None) != (body.posicion is None) or from_legacy == bool(body.id_analisis):
            raise HTTPException(422, "Indique un origen de análisis o una salvaguarda")
        source = next((row for row in source_proposals(ctx) if row["importable"] and (
            row["id_salvaguarda"] == body.id_salvaguarda if from_legacy else
            (row["id_analisis"], row["posicion"]) == (body.id_analisis, body.posicion))), None)
        if not source:
            raise HTTPException(422, "El antecedente carece de citas compatibles con la evaluación")
        item = source["recomendacion"]
        try:
            proposal = Proposal(fase=body.fase, medida=item["salvaguarda"], objetivo=item["objetivo"],
                                justificacion=item.get("justificacion") or body.motivo,
                                criterio_verificacion=item["validacion"], eventos=[str(i) for i in item["eventos"]])
        except (ValidationError, KeyError, TypeError):
            raise HTTPException(422, "La recomendación requiere revisión manual") from None
        provenance = {"id_analisis": str(source["id_analisis"]), "posicion": source["posicion"],
                      "id_salvaguarda": str(source["id_salvaguarda"]) if source["id_salvaguarda"] else None}
        key = ("salvaguarda:" + provenance["id_salvaguarda"] if provenance["id_salvaguarda"]
               else f"analisis:{provenance['id_analisis']}:{source['posicion']}")
        row = add_action(ctx, proposal, body.motivo, origin="salvaguarda" if from_legacy else "analisis",
                         key=key, provenance=provenance)
        return action_view(ctx, row, {})


@router.get("/historial")
def get_history(id_incidente: UUID, request: Request, limite: Limit = 25, cursor: Cursor = None,
                id_accion: UUID | None = None):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        ctx.has_plan()
        history = ctx.tables["incidente_respuesta_historial"]
        query = select(history).where(history.c.id_respuesta == ctx.plan.id_respuesta)
        before = cursor_value(cursor)
        if before is not None:
            query = query.where(history.c.id_cambio < before)
        if id_accion:
            query = query.where(history.c.id_accion == id_accion)
        rows = conn.execute(query.order_by(history.c.id_cambio.desc()).limit(limite + 1)).mappings().all()
        names = user_names(conn, ctx.tables, {row.id_actor for row in rows})
        return {"items": ctx.safe([{**row, "id_cambio": str(row.id_cambio), "actor": names.get(row.id_actor)}
                                   for row in rows[:limite]]),
                "cursor": str(rows[limite - 1].id_cambio) if len(rows) > limite else None}


@router.post("/recomendaciones")
def recommend(id_incidente: UUID, body: Change, request: Request, response: Response,
              idempotency_key: Annotated[str, Header(min_length=8, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")]):
    engine = request.app.state.engine
    with engine.begin() as conn:
        ctx = context(conn, request, id_incidente, write=True)
        lot, work = llm.reserve(ctx, body, idempotency_key)
    if work:
        result, error = llm.generate(work)
        with engine.begin() as conn:
            ctx = context(conn, request, id_incidente, write=True)
            lot = llm.finish(ctx, UUID(str(lot["id_lote"])), work, result, error)
    if lot["estado"] == "en_proceso":
        response.status_code = 202
    return lot


@router.get("/recomendaciones/{id_lote}")
def get_recommendations(id_incidente: UUID, id_lote: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        return llm.public_lot(ctx, llm.find_lot(ctx, id_lote))


@router.get("/recomendaciones")
def recent_recommendations(id_incidente: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        ctx.has_plan()
        lots = ctx.tables["incidente_recomendacion_lote"]
        rows = conn.execute(select(lots).where(lots.c.id_respuesta == ctx.plan.id_respuesta)
                            .order_by(lots.c.creado_en.desc(), lots.c.id_lote).limit(10)).mappings()
        return [llm.public_lot(ctx, row) for row in rows]


@router.get("/informe")
def report(id_incidente: UUID, request: Request, formato: Literal["json", "pdf", "docx"] = "json",
           snapshot: Annotated[str | None, Query(max_length=1500)] = None):
    with request.app.state.engine.connect() as conn:
        if not conn.in_transaction():
            conn.execution_options(isolation_level="REPEATABLE READ")
        ctx = context(conn, request, id_incidente)
        ctx.has_plan()
        if formato != "json" and not snapshot:
            raise HTTPException(428, "Abra la vista previa antes de exportar")
        document = reports.assemble(ctx)
    finalized, token = reports.finalize(request.app.state.auth_settings, document, ctx.actor_id, snapshot)
    return {**finalized, "snapshot": token} if formato == "json" else reports.export(finalized, formato)


@board.get("/responsables")
def assignees(request: Request):
    user, roles = (request.app.state.tables[name] for name in ("usuario", "rol"))
    query = select(user.c.id_usuario, user.c.nombre_usuario).join(roles, user.c.id_rol == roles.c.id_rol).where(
        roles.c.codigo.in_(("analista", "administrador")), roles.c.activo, user.c.activo,
        func.coalesce(user.c.restriccion_acceso, "") == "", user.c.autorizacion == "aprobado",
        user.c.correo_verificado_en.is_not(None)).order_by(user.c.nombre_usuario, user.c.id_usuario)
    with request.app.state.engine.connect() as conn:
        return [dict(row) for row in conn.execute(query).mappings()]


@board.get("/configuracion")
def get_config(request: Request):
    config = request.app.state.tables["incidente_respuesta_config"]
    with request.app.state.engine.connect() as conn:
        return dict(conn.execute(select(config)).mappings().one())


@board.put("/configuracion")
def set_config(body: BoardConfig, request: Request):
    config = request.app.state.tables["incidente_respuesta_config"]
    with request.app.state.engine.begin() as conn:
        actor = eligible_actor(conn, request)
        require_admin(actor)
        row = conn.execute(select(config).with_for_update()).mappings().one()
        if row.revision_config != body.revision_esperada:
            raise HTTPException(409, {"mensaje": "La configuración cambió", "revision_config": row.revision_config})
        row = conn.execute(config.update().where(config.c.tablero.is_(True)).values(
            wip_activo=body.wip_activo, limite_wip=body.limite_wip,
            revision_config=config.c.revision_config + 1).returning(config)).mappings().one()
        audit(conn, request, "respuesta_incidente_configuracion", actor=UUID(actor["id_usuario"]),
              reason=f"wip:{body.wip_activo}:{body.limite_wip}", revision=row.revision_config)
        notify_change(conn, sensor_ids(), "respuesta_incidentes")
        return dict(row)
