"""Human review, assignment and inbox for the incident response workflow."""

from datetime import timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import and_, func, select

from .api import local_only, sensor_ids
from .auth.store import audit
from .incident_automation import (ELIGIBLE, DraftPlan, DraftResult, enqueue_draft, enabled,
                                  evidence_context, store_version, valid_view, verify_plan, view_for_job)
from .incident_notices import TEXT, incident_sensors, issue, visible_notices, workload
from .incident_response import (action_transition, active_plan, add_action, eligible_actor,
                                open_plan, require_admin, today_local, update_action, wip_available)
from .incident_response_models import ActionTransition, Change, Description, Model, PlanInput
from .incident_response_routes import context, response_schema
from .incidents import scoped
from .analysis_state import digest
from .realtime import notify_change


def automation_schema(request: Request):
    if "incidente_borrador" not in request.app.state.tables:
        raise HTTPException(503, "La automatización requiere la migración 018")


dependencies = [Depends(local_only), Depends(response_schema), Depends(automation_schema)]
router = APIRouter(prefix="/api/incidentes/{id_incidente}/respuesta/borradores", dependencies=dependencies)
board = APIRouter(prefix="/api/respuestas-incidentes", dependencies=dependencies)


class RequestDraft(Model):
    motivo: Description


class Decision(Model):
    estado: Literal["pendiente", "elegible", "rechazada"]
    motivo: Description
    id_responsable: UUID | None = None


class EditDraft(Change):
    plan: DraftPlan
    decisiones: dict[str, Decision] = Field(default_factory=dict, max_length=8)


class ApproveDraft(Change):
    acciones: list[str] | None = Field(default=None, min_length=1, max_length=8)


class HistoricalBatch(Model):
    limite: int = Field(default=21, strict=True, ge=1, le=21)
    vista_previa: bool = True


def administrative_context(conn, request, incident_id):
    ctx = context(conn, request, incident_id, write=True)
    require_admin(ctx.actor)
    return ctx


def draft_rows(ctx):
    table = ctx.tables["incidente_borrador"]
    query = select(table).where(table.c.id_incidente == ctx.id_incidente)
    return ctx.conn.execute(query.order_by(table.c.creado_en.desc(), table.c.generacion.desc()).limit(50)).mappings().all()


def versions(ctx, identifier, *, all_versions=False):
    version = ctx.tables["incidente_borrador_version"]
    return ctx.conn.execute(select(version).where(version.c.id_borrador == identifier)
                            .order_by(version.c.version.desc()).limit(100 if all_versions else 1)).mappings().all()


def state_view(ctx, job, *, history=False):
    ctx.read_evaluation(job.revision_evaluacion)
    data = {key: value for key, value in job.items() if key != "token_ejecucion"}
    current = ctx.evaluation.evidencia_verificable and ctx.evaluation.decision in ELIGIBLE and (
        ctx.evaluation.evidencia_sha256 == job.evidencia_sha256)
    rows = versions(ctx, job.id_borrador, all_versions=history)
    return ctx.safe({**data, "vigente": current, "versiones": [dict(row) for row in rows]})


def verify_edit(ctx, job, body):
    rows = versions(ctx, job.id_borrador)
    live = view_for_job(ctx.conn, ctx.tables, ctx.id_incidente)
    if (job.estado != "disponible" or not rows or rows[0].version != body.revision_esperada or
            ctx.revision != body.revision_evaluacion or not valid_view(live, job.evidencia_sha256)):
        ctx.conflict("El borrador o su evidencia cambió. Actualice antes de continuar.")
    return rows[0], evidence_context(ctx.conn, ctx.tables, live)


def verified(ctx, plan, evidence):
    try:
        verify_plan(plan, evidence)
    except ValueError:
        raise HTTPException(422, "Revise las citas, técnicas y antecedentes vinculados al plan") from None
    ctx.citations(plan.eventos)


def audit_draft(ctx, operation, *, reason=None, identifier=None):
    audit(ctx.conn, ctx.request, "respuesta_borrador_" + operation, actor=ctx.actor_id,
          reason=ctx.safe(reason) if reason else str(ctx.id_incidente),
          request_id=str(identifier or ctx.id_incidente), revision=ctx.revision)
    notify_change(ctx.conn, ctx.sensors, "respuesta_incidentes", "incidentes")


def suggested(people, role):
    return next((person for person in people if role == "indistinto" or person["rol"] == role), None)


@router.get("")
def list_drafts(id_incidente: UUID, request: Request):
    with request.app.state.engine.connect() as conn:
        ctx = context(conn, request, id_incidente)
        return {"items": [state_view(ctx, job) for job in draft_rows(ctx)], "generacion_habilitada": enabled()}


@router.get("/{id_borrador}")
def history(id_incidente: UUID, id_borrador: UUID, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = context(conn, request, id_incidente)
        job = get_job(ctx, id_borrador, lock=False)
        data = state_view(ctx, job, history=True)
        if ctx.actor["rol"] == "administrador" and data["versiones"]:
            newest = data["versiones"][0]["propuesta"].get("plan")
            if newest:
                people = workload(conn, ctx.tables, sensor_ids())
                data["responsables"] = people
                data["sugerencias"] = {item["clave"]: suggested(people, item["rol_sugerido"]) for item in newest["acciones"]}
                data["wip_disponible"] = wip_available(conn, ctx.tables, lock=False)
        return data


def get_job(ctx, identifier, *, lock=True):
    table = ctx.tables["incidente_borrador"]
    query = select(table).where(table.c.id_incidente == ctx.id_incidente, table.c.id_borrador == identifier)
    row = ctx.conn.execute(query.with_for_update() if lock else query).mappings().first()
    if row is None:
        raise HTTPException(404, "Borrador no encontrado")
    return row


@router.post("", status_code=202)
def request_draft(id_incidente: UUID, body: RequestDraft, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = administrative_context(conn, request, id_incidente)
        view = ctx.evaluation
        if not (enabled() and view.evidencia_verificable and view.decision in ELIGIBLE):
            ctx.conflict("La generación requiere habilitación y evidencia verificable")
        result = enqueue_draft(conn, ctx.tables, id_incidente, ctx.revision, view.evidencia_sha256, again=True,
                               historical=bool(view.detalle.get("retrospectiva")))
        if result is None:
            ctx.conflict("Ya existe una generación pendiente para este incidente")
        audit_draft(ctx, "solicitar", reason=body.motivo, identifier=result)
        return {"id_borrador": result, "estado": "pendiente"}


@router.put("/{id_borrador}")
def edit_draft(id_incidente: UUID, id_borrador: UUID, body: EditDraft, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = administrative_context(conn, request, id_incidente)
        job = get_job(ctx, id_borrador)
        previous, evidence = verify_edit(ctx, job, body)
        if not set(body.decisiones) <= {item.clave for item in body.plan.acciones}:
            raise HTTPException(422, "Revise las decisiones de las acciones incluidas")
        if any(item.estado == "elegible" for item in body.decisiones.values()) and not ctx.eligible:
            ctx.conflict("Confirme el incidente antes de aprobar acciones")
        clean = DraftResult.model_validate(ctx.safe(DraftResult(plan=body.plan).model_dump(mode="json")))
        verified(ctx, clean.plan, evidence)
        adopted = {key: val for key, val in previous.decisiones.items() if val.get("id_accion")}
        current = {item.clave: item for item in clean.plan.acciones}
        original = {item.clave: item for item in DraftResult.model_validate(previous.propuesta).plan.acciones}
        if any(current.get(key) != original[key] for key in adopted):
            ctx.conflict("Las acciones aprobadas se administran desde el tablero")
        people = {p["id_usuario"] for p in workload(conn, ctx.tables, sensor_ids())}
        if any(item.id_responsable and item.id_responsable not in people for item in body.decisiones.values()):
            raise HTTPException(422, "El responsable debe estar activo, aprobado y tener acceso al incidente")
        decisions = {key: value.model_dump(mode="json") for key, value in body.decisiones.items()}
        for key, item in decisions.items():
            if key not in adopted and item["estado"] == "rechazada" and previous.decisiones.get(key, {}).get("estado") != "rechazada":
                issue(conn, ctx.tables, ctx.id_incidente, ctx.sensors, "rechazar", f"{id_borrador}:{key}", admins=True)
        decisions.update(adopted)
        store_version(conn, ctx.tables, id_borrador, previous.version + 1, clean.model_dump(mode="json"),
                      actor=ctx.actor_id, reason=ctx.safe(body.motivo), decisions=ctx.safe(decisions))
        audit_draft(ctx, "editar", reason=body.motivo, identifier=id_borrador)
        return state_view(ctx, job)


@router.post("/{id_borrador}/rechazar")
def reject_draft(id_incidente: UUID, id_borrador: UUID, body: Change, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = administrative_context(conn, request, id_incidente)
        job = get_job(ctx, id_borrador)
        previous, _ = verify_edit(ctx, job, body)
        store_version(conn, ctx.tables, id_borrador, previous.version + 1, previous.propuesta,
                      actor=ctx.actor_id, reason=ctx.safe(body.motivo), decisions=previous.decisiones)
        change_draft(ctx, job, "rechazado")
        audit_draft(ctx, "rechazar", reason=body.motivo, identifier=id_borrador)
        return {"estado": "rechazado"}


def change_draft(ctx, job, state):
    table = ctx.tables["incidente_borrador"]
    ctx.conn.execute(table.update().where(table.c.id_borrador == job.id_borrador).values(estado=state))


def materialize(ctx, job, item, dependencies, reason):
    actions = ctx.tables["incidente_accion"]
    legacy = {"id_salvaguarda": item.antecedente, "eventos": item.eventos}
    key = "borrador:" + digest([item.fase, " ".join(item.medida.casefold().split())])
    if item.antecedente:
        safeguards = ctx.tables["salvaguarda"]
        legacy["estado_anterior"] = ctx.conn.scalar(select(safeguards.c.estado).where(
            safeguards.c.id_salvaguarda == UUID(item.antecedente)))
        key = "salvaguarda:" + item.antecedente
    previous = ctx.conn.execute(select(actions).where(actions.c.id_respuesta == ctx.plan.id_respuesta,
        (actions.c.clave_origen == key) | ((actions.c.fase == item.fase) &
            (func.lower(func.btrim(actions.c.medida)) == item.medida.strip().lower()))).order_by(actions.c.orden).limit(1)).mappings().first()
    if previous:
        if previous.estado in {"cancelada", "rechazada"}:
            ctx.conflict("Una acción equivalente fue rechazada o cancelada. Revise el borrador.", previous)
        pinned = (previous.procedencia or {}).get("dependencias", [])
        if set(pinned) != set(dependencies) and dependencies:
            ctx.conflict("La acción existente tiene dependencias distintas. Revise el borrador.", previous)
        return previous, False
    return add_action(ctx, item, reason, origin="salvaguarda" if item.antecedente else "llm", key=key,
        provenance={**{name: getattr(item, name) for name in ("descripcion", "rol_sugerido", "plazo_dias", "mitre", "resultado_esperado")},
                    **legacy, "id_borrador": str(job.id_borrador), "clave": item.clave, "dependencias": dependencies}), True


@router.post("/{id_borrador}/aprobar")
def approve_draft(id_incidente: UUID, id_borrador: UUID, body: ApproveDraft, request: Request):
    with request.app.state.engine.begin() as conn:
        ctx = administrative_context(conn, request, id_incidente)
        job = get_job(ctx, id_borrador)
        previous, evidence = verify_edit(ctx, job, body)
        if not ctx.eligible:
            ctx.conflict("Confirme el incidente antes de activar el plan")
        plan = DraftResult.model_validate(previous.propuesta).plan
        verified(ctx, plan, evidence)
        prior = previous.decisiones
        candidates = {item.clave for item in plan.acciones if prior.get(item.clave, {}).get("estado") != "rechazada"}
        adopted = {key: UUID(item["id_accion"]) for key, item in prior.items() if item.get("id_accion")}
        selected = (set(body.acciones) if body.acciones else candidates) - adopted.keys()
        resolved = selected | adopted.keys()
        if not selected or not resolved <= candidates or any(
            not set(item.dependencias) <= resolved for item in plan.acciones if item.clave in selected
        ):
            raise HTTPException(422, "Seleccione acciones elegibles e incluya sus dependencias")
        if ctx.plan is None:
            open_plan(ctx, PlanInput(revision_evaluacion=ctx.revision, objetivo=plan.objetivo, alcance=plan.alcance,
                                    criterio_cierre=plan.criterio_cierre))
            ctx.change_plan(origen="historica" if job.historico else "llm", detalle_plan=ctx.safe({
                **plan.model_dump(mode="json", exclude={"acciones"}), "id_borrador": str(id_borrador)}))
        else:
            ctx.check(Change(revision_evaluacion=ctx.revision, revision_esperada=ctx.plan.revision_respuesta, motivo=body.motivo))
            active_plan(ctx)
        stored = dict(adopted)
        for item in plan.acciones:
            if item.clave not in selected:
                continue
            predecessor = [ctx.action(stored[key]) for key in item.dependencias]
            if any(row.estado in {"rechazada", "cancelada"} for row in predecessor):
                ctx.conflict("Revise las dependencias rechazadas o canceladas")
            row, created = materialize(ctx, job, item, [str(row.id_accion) for row in predecessor], body.motivo)
            stored[item.clave] = row.id_accion
            if row.estado != "propuesta":
                continue
            manual = prior.get(item.clave, {}).get("id_responsable")
            people = workload(conn, ctx.tables, sensor_ids())
            if manual and not any(str(person["id_usuario"]) == manual for person in people):
                raise HTTPException(422, "Actualice el responsable. Su cuenta ya no es elegible.")
            person = suggested(people, item.rol_sugerido)
            chosen = UUID(manual) if manual else (person["id_usuario"] if person and not row.id_responsable else None)
            fields = {"revision_evaluacion": ctx.revision, "motivo": body.motivo}
            due = today_local() + timedelta(days=item.plazo_dias)
            if chosen or created:
                if chosen:
                    updated = action_transition(ctx, row, ActionTransition(**fields, revision_esperada=row.revision_accion,
                        operacion="asignar", id_responsable=chosen, vence_en=due))
                    row = ctx.action(updated["id_accion"])
                elif created:
                    row = update_action(ctx, row, vence_en=due)
            action_transition(ctx, row, ActionTransition(**fields, revision_esperada=row.revision_accion, operacion="aprobar"))
        decisions = {**prior, **{key: {**prior.get(key, {}), "id_accion": str(identifier)} for key, identifier in stored.items()}}
        store_version(conn, ctx.tables, id_borrador, previous.version + 1, previous.propuesta,
            actor=ctx.actor_id, reason=ctx.safe(body.motivo), decisions=decisions)
        if resolved == candidates:
            change_draft(ctx, job, "aprobado")
        ctx.record("importar_borrador", body.motivo, {"id_borrador": str(id_borrador), "acciones": sorted(selected)})
        audit_draft(ctx, "aprobar", reason=body.motivo, identifier=id_borrador)
        return {"acciones": stored, "plan": ctx.view()}


@board.post("/automatizacion/retrospectiva")
def retrospective(request: Request, body: HistoricalBatch):
    with request.app.state.engine.begin() as conn:
        actor = eligible_actor(conn, request)
        require_admin(actor)
        tables = request.app.state.tables
        incident, evaluation, jobs = (tables[name] for name in ("incidente", "incidente_evaluacion", "incidente_borrador"))
        exists = select(1).select_from(jobs).where(jobs.c.id_incidente == incident.c.id_incidente,
            jobs.c.evidencia_sha256 == evaluation.c.evidencia_sha256).correlate(incident, evaluation).exists()
        query = select(incident.c.id_incidente).join(evaluation, and_(incident.c.id_incidente == evaluation.c.id_incidente,
               incident.c.revision_actual == evaluation.c.revision_evaluacion)).where(
               scoped(incident, tables, sensor_ids()), evaluation.c.decision.in_(ELIGIBLE),
               evaluation.c.detalle.has_key("retrospectiva"), ~exists).order_by(incident.c.creado_en, incident.c.id_incidente)
        if not body.vista_previa and not enabled():
            raise HTTPException(409, "La generación automática está deshabilitada")
        result = []
        for incident_id in conn.scalars(query.limit(body.limite)).all():
            view = view_for_job(conn, tables, incident_id, lock=not body.vista_previa)
            if not view or not valid_view(view, view["evidencia_sha256"]):
                continue
            job = None if body.vista_previa else enqueue_draft(conn, tables, incident_id, view["revision_evaluacion"],
                                                                view["evidencia_sha256"], historical=True)
            if body.vista_previa or job:
                result.append({"id_incidente": incident_id, "id_borrador": job, "revision": view["revision_evaluacion"]})
                if job:
                    audit(conn, request, "respuesta_borrador_retrospectivo", actor=actor["id_usuario"], reason=str(incident_id))
                    notify_change(conn, incident_sensors(conn, tables, incident_id), "respuesta_incidentes")
        return {"vista_previa": body.vista_previa, "items": result, "total": len(result)}


@board.get("/avisos")
def inbox(request: Request, pagina: int = 1):
    if not 1 <= pagina <= 100:
        raise HTTPException(422, "Página de avisos fuera de rango")
    tables = request.app.state.tables
    notices = tables["incidente_aviso"]
    user = request.state.user["id_usuario"]
    scope = visible_notices(tables, sensor_ids(), user)
    with request.app.state.engine.connect() as conn:
        unread = conn.scalar(select(func.count()).select_from(notices).where(*scope, notices.c.leido_en.is_(None)))
        rows = conn.execute(select(notices.c.id_aviso, notices.c.id_incidente, notices.c.id_accion, notices.c.tipo,
            notices.c.creado_en, notices.c.leido_en).where(*scope).order_by(notices.c.creado_en.desc(), notices.c.id_aviso.desc())
            .offset(40 * (pagina - 1)).limit(41)).mappings().all()
        return {"items": [{**row, "titulo": TEXT[row.tipo]} for row in rows[:40]], "no_leidos": unread, "hay_mas": len(rows) > 40}


def read_notices(request, identifier=None):
    tables = request.app.state.tables
    notices = tables["incidente_aviso"]
    with request.app.state.engine.begin() as conn:
        user = eligible_actor(conn, request)["id_usuario"]
        query = notices.update().where(*visible_notices(tables, sensor_ids(), user), notices.c.leido_en.is_(None))
        if identifier:
            query = query.where(notices.c.id_aviso == identifier)
        count = conn.execute(query.values(leido_en=func.clock_timestamp())).rowcount
        if count:
            notify_change(conn, sensor_ids(), "avisos_incidentes", recipients=[user])
        return {"actualizados": count}


@board.post("/avisos/leer-todos")
def read_all(request: Request):
    return read_notices(request)


@board.post("/avisos/{id_aviso}/leer")
def read_one(request: Request, id_aviso: UUID):
    return read_notices(request, id_aviso)
