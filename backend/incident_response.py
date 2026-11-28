"""Transactional response operations. The incident aggregate belongs to D1."""
from importlib import import_module
from uuid import UUID

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import func, null, select

from .auth.store import approved, audit, identity, session
from .incident_response_models import Evaluation
from .realtime import notify_change
from .sensitive import session_redactors

TERMINAL = ("verificada", "rechazada", "cancelada")
TRANSITIONS = {
    "aprobar": (("propuesta",), "aprobada"),
    "rechazar": (("propuesta",), "rechazada"),
    "iniciar": (("aprobada",), "en_curso"),
    "ejecutar": (("en_curso",), "ejecutada"),
    "verificar": (("ejecutada",), "verificada"),
    "devolver": (("ejecutada",), "aprobada"),
    "cancelar": (("propuesta", "aprobada", "en_curso", "ejecutada"), "cancelada"),
}


def evaluation_for_response(conn, actor, id_incidente, revision=None, *, lock=False):
    try:
        service = import_module(".incidents", package=__package__)
    except ModuleNotFoundError as exc:
        if exc.name != f"{__package__}.incidents":
            raise
        service = None
    lookup = getattr(service, "get_incident_for_response", None)
    if lookup is None:
        raise HTTPException(503, "La integración con la evaluación de incidentes aún no está disponible")
    value = lookup(conn, actor, id_incidente, revision=revision, lock=lock)
    if value is None:
        raise HTTPException(404, "Incidente no encontrado")
    return value


def require_admin(actor):
    if actor["rol"] != "administrador":
        raise HTTPException(403, "Esta operación requiere un administrador de seguridad")


def eligible_actor(conn, request):
    _, actor = session(conn, request, {"completa"}, lock=False)
    return {"id_usuario": str(actor.id_usuario), "rol": actor.rol}


def eligible_assignee(conn, request, id_usuario):
    user = identity(conn, request, id_usuario, lock=True) if id_usuario else None
    if not approved(user):
        raise HTTPException(422, "Seleccione un responsable activo y aprobado")


class ResponseContext:
    def __init__(self, conn, request, actor, id_incidente, *, lock=False):
        from .api import sensor_ids

        self.conn, self.request, self.actor = conn, request, actor
        self.actor_id = UUID(str(actor["id_usuario"]))
        self.tables = request.app.state.tables
        self.id_incidente = id_incidente
        self.evaluation = self.read_evaluation(lock=lock)
        self.session_ids = set(self.evaluation.alcance.sesiones)
        plan = self.tables["incidente_respuesta"]
        query = select(plan).where(plan.c.id_incidente == id_incidente)
        self.plan = conn.execute(query.with_for_update() if lock else query).mappings().first()
        if self.plan:
            history = self.tables["incidente_respuesta_historial"]
            revisions = set(conn.scalars(select(history.c.revision_evaluacion).where(
                history.c.id_respuesta == self.plan.id_respuesta).distinct()))
            for revision in (revisions | {self.plan.revision_plan}) - {self.revision}:
                self.session_ids.update(self.read_evaluation(revision).alcance.sesiones)
        sessions = self.tables["sesion"]
        scope = dict(conn.execute(select(sessions.c.id_sesion, sessions.c.id_honeypot)
                                  .where(sessions.c.id_sesion.in_(self.session_ids))).all())
        if scope.keys() != self.session_ids or not set(scope.values()) <= set(sensor_ids()):
            raise HTTPException(404, "Incidente no encontrado")
        self.sensors = set(scope.values())
        self._redactors = None

    def read_evaluation(self, revision=None, *, lock=False):
        try:
            value = Evaluation.model_validate(evaluation_for_response(
                self.conn, self.actor, self.id_incidente, revision=revision, lock=lock))
        except ValidationError:
            raise HTTPException(503, "Contrato de evaluación de incidentes incompatible") from None
        if value.id_incidente != self.id_incidente or (revision is not None and value.revision_evaluacion != revision):
            raise HTTPException(503, "Revisión de incidente incompatible")
        return value

    def safe(self, value):
        if self._redactors is None:
            self._redactors = session_redactors(self.conn, self.tables["evento"], self.session_ids)
        for redactor in self._redactors.values():
            value = redactor.payload(value)
        return value

    @property
    def revision(self):
        return self.evaluation.revision_evaluacion

    @property
    def eligible(self):
        return (self.evaluation.decision == "incidente_confirmado" and self.evaluation.evidencia_verificable
                and bool(self.evaluation.evidencias))

    def header(self):
        return {"id_incidente": self.id_incidente, "id_respuesta": self.plan.id_respuesta if self.plan else None,
                "estado": self.plan.estado if self.plan else "sin_respuesta",
                "revision_respuesta": self.plan.revision_respuesta if self.plan else None,
                "revision_plan": self.plan.revision_plan if self.plan else None, "revision_evaluacion_actual": self.revision,
                "desactualizada": bool(self.plan and (self.plan.revision_plan != self.revision or not self.eligible))}

    def view(self):
        draft = None
        if self.eligible and self.plan is None:
            scope = self.evaluation.alcance
            resources = ", ".join(scope.recursos_confirmados)[:1400]
            draft = {
                "objetivo": "Verificar el alcance de la actividad documentada y sus consecuencias.",
                "alcance": ("Recursos corroborados en la evaluación: " + resources if resources else
                            f"Evidencia de {len(set(scope.sesiones))} sesiones. Impacto externo por corroborar."),
                "criterio_cierre": "Documentar los resultados verificados, las actuaciones y los riesgos pendientes.",
                "eventos": [item.id_evento for item in self.evaluation.evidencias[:20]],
            }
        return self.safe({**(dict(self.plan) if self.plan else {}), **self.header(), "borrador": draft,
                          "elegible": self.eligible, "evaluacion": self.evaluation.model_dump(mode="json")})

    def has_plan(self):
        if self.plan is None:
            raise HTTPException(404, "Respuesta no iniciada")

    def conflict(self, message, action=None):
        detail = {"mensaje": message, **self.header(), "id_incidente": str(self.id_incidente)}
        if self.plan:
            detail["id_respuesta"] = str(self.plan.id_respuesta)
        if action:
            detail["revision_accion"] = action.revision_accion
        raise HTTPException(409, detail)

    def check(self, body, action=None, *, current=True, allow_stale_plan=False):
        self.has_plan()
        revision = action.revision_accion if action else self.plan.revision_respuesta
        if body.revision_evaluacion != self.revision or body.revision_esperada != revision:
            self.conflict("La revisión cambió. Actualice antes de guardar.", action)
        if current and (not self.eligible or (not allow_stale_plan and self.plan.revision_plan != self.revision)):
            self.conflict("Se requiere una evaluación confirmada y un plan actualizado.", action)

    def citations(self, event_ids, evaluation=None):
        if not event_ids:
            return []
        evaluation = evaluation or self.evaluation
        wanted = set(event_ids)
        candidates = {c.id_evento: c for c in evaluation.evidencias if c.id_evento in wanted}
        event, analysis = (self.tables[name] for name in ("evento", "analisis_llm"))
        stored = dict(self.conn.execute(select(event.c.id_evento, event.c.id_sesion)
                                       .where(event.c.id_evento.in_([int(i) for i in candidates]))).all())
        bindings = {c.id_analisis for c in candidates.values() if c.id_analisis}
        histories = dict(self.conn.execute(select(analysis.c.id_analisis, analysis.c.id_sesion)
                                          .where(analysis.c.id_analisis.in_(bindings))).all()) if bindings else {}
        if candidates.keys() != wanted or any(
            c.id_sesion not in self.session_ids or c.id_sesion not in evaluation.alcance.sesiones
            or stored.get(int(c.id_evento)) != c.id_sesion
            or (c.id_analisis is not None and histories.get(c.id_analisis) != c.id_sesion)
            for c in candidates.values()
        ):
            raise HTTPException(422, "Las citas deben pertenecer a la evaluación y a su sesión")
        return [candidates[key] for key in dict.fromkeys(event_ids)]

    def change_plan(self, **values):
        plan = self.tables["incidente_respuesta"]
        self.plan = self.conn.execute(plan.update().where(plan.c.id_respuesta == self.plan.id_respuesta)
                                      .values(**values, revision_respuesta=plan.c.revision_respuesta + 1,
                                              actualizado_en=func.clock_timestamp()).returning(plan)).mappings().one()

    def record(self, operation, reason, detail=None, action_id=None, *, advance=True):
        if advance:
            self.change_plan()
        history = self.tables["incidente_respuesta_historial"]
        self.conn.execute(history.insert().values(
            id_respuesta=self.plan.id_respuesta, id_incidente=self.id_incidente, id_accion=action_id,
            revision_evaluacion=self.revision, revision_respuesta=self.plan.revision_respuesta, id_actor=self.actor_id,
            operacion=operation, motivo=self.safe(reason), detalle=self.safe(detail or {})))
        audit(self.conn, self.request, "respuesta_incidente_" + operation, actor=self.actor_id,
              reason=str(action_id or self.id_incidente), revision=self.plan.revision_respuesta)
        notify_change(self.conn, self.sensors, "respuesta_incidentes")

    def action(self, action_id):
        self.has_plan()
        actions = self.tables["incidente_accion"]
        row = self.conn.execute(select(actions).where(actions.c.id_respuesta == self.plan.id_respuesta,
                                                      actions.c.id_accion == action_id)).mappings().first()
        if row is None:
            raise HTTPException(404, "Acción no encontrada")
        return row

    def add_evidence(self, action_id, kind, citations, reference=None):
        evidence = self.tables["incidente_accion_evidencia"]
        values = [{"id_evento": int(c.id_evento), "id_sesion": c.id_sesion, "id_analisis": c.id_analisis,
                   "referencia": None} for c in citations]
        if reference:
            values.append({"id_evento": None, "id_sesion": None, "id_analisis": None,
                           "referencia": self.safe(reference)})
        if values:
            common = dict(id_accion=action_id, id_incidente=self.id_incidente, id_respuesta=self.plan.id_respuesta,
                          revision_evaluacion=self.revision, tipo=kind, id_actor=self.actor_id)
            self.conn.execute(evidence.insert(), [{**row, **common} for row in values])


def plan_fields(ctx, body):
    if body.id_responsable:
        eligible_assignee(ctx.conn, ctx.request, body.id_responsable)
    fields = body.model_dump(include={"objetivo", "alcance", "criterio_cierre", "fases_no_aplicables"})
    return {**ctx.safe(fields), "id_responsable": body.id_responsable, "revision_plan": ctx.revision}


def open_plan(ctx, body):
    require_admin(ctx.actor)
    if ctx.plan or not ctx.eligible or body.revision_evaluacion != ctx.revision:
        ctx.conflict("La respuesta ya existe o la evaluación no es elegible.")
    plan = ctx.tables["incidente_respuesta"]
    ctx.plan = ctx.conn.execute(plan.insert().values(id_incidente=ctx.id_incidente, **plan_fields(ctx, body))
                               .returning(plan)).mappings().one()
    ctx.record("apertura", "Apertura del plan de respuesta", advance=False)
    return ctx.view()


def add_action(ctx, proposal, reason, *, origin="manual", key=None, provenance=None, reference=None):
    citations = ctx.citations(proposal.eventos)
    if not citations and not reference:
        raise HTTPException(422, "Documente al menos una cita o una referencia verificable")
    if proposal.fase in ctx.plan.fases_no_aplicables:
        raise HTTPException(422, "La fase está marcada como no aplicable en el plan")
    actions = ctx.tables["incidente_accion"]
    if key:
        previous = ctx.conn.execute(select(actions).where(actions.c.id_respuesta == ctx.plan.id_respuesta,
                                                          actions.c.clave_origen == key)).mappings().first()
        if previous:
            return previous
    fields = proposal.model_dump(include={"fase", "medida", "objetivo", "justificacion", "criterio_verificacion"})
    action = ctx.conn.execute(actions.insert().values(
        **ctx.safe(fields), origen=origin, clave_origen=key, procedencia=ctx.safe(provenance or {}),
        id_respuesta=ctx.plan.id_respuesta, id_incidente=ctx.id_incidente, revision_origen=ctx.revision,
        revision_validada=ctx.revision, creado_por=ctx.actor_id).returning(actions)).mappings().one()
    ctx.add_evidence(action.id_accion, "propuesta", citations, reference)
    ctx.record("propuesta", reason, {"origen": origin, "eventos": proposal.eventos}, action.id_accion)
    return action


def active_plan(ctx):
    if ctx.plan.estado != "en_respuesta":
        ctx.conflict("La respuesta debe estar en curso para modificar sus acciones")


def update_action(ctx, row, **values):
    actions = ctx.tables["incidente_accion"]
    return ctx.conn.execute(actions.update().where(actions.c.id_accion == row.id_accion)
                            .values(**values, revision_accion=actions.c.revision_accion + 1,
                                    actualizado_en=func.clock_timestamp()).returning(actions)).mappings().one()


def wip_available(conn, tables):
    config, actions = (tables[name] for name in ("incidente_respuesta_config", "incidente_accion"))
    wip = conn.execute(select(config).with_for_update()).mappings().one()
    return not wip.wip_activo or conn.scalar(select(func.count()).select_from(actions)
                                            .where(actions.c.estado == "en_curso")) < wip.limite_wip


def action_transition(ctx, row, body):
    operation = body.operacion
    if operation not in {"iniciar", "avanzar", "ejecutar"}:
        require_admin(ctx.actor)
    elif ctx.actor["rol"] != "administrador" and row.id_responsable != ctx.actor_id:
        raise HTTPException(403, "Solo el responsable puede documentar la ejecución")
    ctx.check(body, row, current=operation not in {"avanzar", "ejecutar", "cancelar"})
    active_plan(ctx)
    if row.estado in TERMINAL:
        ctx.conflict("La acción ya está finalizada", row)
    if operation not in {"avanzar", "ejecutar", "cancelar"} and row.revision_validada != ctx.revision:
        ctx.conflict("Ratifica la acción en el plan actualizado", row)
    prior = row.estado
    values = {}
    if operation in TRANSITIONS:
        permitted, state = TRANSITIONS[operation]
        if prior not in permitted:
            ctx.conflict("Transición de acción no permitida", row)
        values["estado"] = state
    if operation == "asignar":
        if prior == "ejecutada":
            ctx.conflict("La acción está pendiente de verificación", row)
        eligible_assignee(ctx.conn, ctx.request, body.id_responsable)
        values.update(id_responsable=body.id_responsable, vence_en=body.vence_en)
    if operation == "avanzar" and prior != "en_curso":
        ctx.conflict("La acción debe estar en curso", row)
    if operation in {"ejecutar", "verificar", "devolver"} and (
        not body.resultado or not (body.referencia or body.eventos)
    ):
        raise HTTPException(422, "Indique el resultado y su evidencia verificable")
    if operation == "cancelar" and prior in {"en_curso", "ejecutada"} and not body.resultado:
        raise HTTPException(422, "Documente las actuaciones realizadas antes de cancelar")
    if operation == "iniciar":
        eligible_assignee(ctx.conn, ctx.request, row.id_responsable)
        if not wip_available(ctx.conn, ctx.tables):
            ctx.conflict("Se alcanzó el límite WIP", row)
    citations = ctx.citations(body.eventos)
    kind = {"ejecutar": "ejecucion", "verificar": "verificacion", "devolver": "verificacion",
            "cancelar": "cancelacion"}.get(operation, "avance")
    ctx.add_evidence(row.id_accion, kind, citations, body.referencia)
    updated = update_action(ctx, row, **values)
    ctx.record(operation, body.motivo, {"estado_anterior": prior, "estado": updated.estado,
               "resultado": body.resultado, "eventos": body.eventos, "referencia": body.referencia,
               "responsable_anterior": str(row.id_responsable) if row.id_responsable else None,
               "responsable": str(updated.id_responsable) if updated.id_responsable else None},
               updated.id_accion)
    return ctx.safe(dict(updated))


def review_plan(ctx, body):
    require_admin(ctx.actor)
    ctx.check(body, allow_stale_plan=True)
    active_plan(ctx)
    actions, evidence = (ctx.tables[name] for name in ("incidente_accion", "incidente_accion_evidencia"))
    pending = {row.id_accion: row for row in ctx.conn.execute(select(actions).where(
        actions.c.id_respuesta == ctx.plan.id_respuesta, actions.c.estado.not_in(TERMINAL))).mappings()}
    carry, cancel = set(body.ratificar), set(body.cancelar)
    if carry & cancel or carry | cancel != pending.keys():
        raise HTTPException(422, "Decida la ratificación o cancelación de cada acción pendiente")
    previous = ctx.plan
    ctx.change_plan(**plan_fields(ctx, body))
    for action_id, row in pending.items():
        if action_id in cancel:
            if row.estado in {"en_curso", "ejecutada"}:
                raise HTTPException(422, "Cancele las acciones iniciadas documentando su resultado")
            updated = update_action(ctx, row, estado="cancelada")
        else:
            if row.fase in ctx.plan.fases_no_aplicables:
                raise HTTPException(422, "Una acción ratificada pertenece a una fase no aplicable")
            original = list(ctx.conn.scalars(select(evidence.c.id_evento).where(evidence.c.id_accion == action_id,
                                   evidence.c.tipo == "propuesta", evidence.c.id_evento.is_not(None))))
            ctx.add_evidence(action_id, "ratificacion", ctx.citations([str(i) for i in original]))
            updated = update_action(ctx, row, revision_validada=ctx.revision)
        ctx.record("ratificacion" if action_id in carry else "cancelar", body.motivo,
                   {"estado_anterior": row.estado, "estado": updated.estado}, action_id, advance=False)
    before = {name: previous[name] for name in ("revision_plan", "objetivo", "alcance", "criterio_cierre",
                                                "fases_no_aplicables")}
    ctx.record("revision_plan", body.motivo, {"anterior": before}, advance=False)
    return ctx.view()


def transition_plan(ctx, body):
    require_admin(ctx.actor)
    op = body.operacion
    ctx.check(body, current=op != "cancelar", allow_stale_plan=op == "reabrir")
    prior = ctx.plan.estado
    allowed, target = {
        "resolver": (("en_respuesta",), "resuelto"), "cerrar": (("resuelto",), "cerrado"),
        "cancelar": (("en_respuesta", "resuelto"), "cancelado"),
        "reabrir": (("resuelto", "cerrado", "cancelado"), "en_respuesta"),
    }[op]
    if prior not in allowed:
        ctx.conflict("Transición de respuesta no permitida")
    actions = ctx.tables["incidente_accion"]
    states = set(ctx.conn.scalars(select(actions.c.estado).where(actions.c.id_respuesta == ctx.plan.id_respuesta)))
    if op in {"resolver", "cancelar"} and states.difference(TERMINAL):
        ctx.conflict("Verifique, rechace o cancele todas las acciones pendientes")
    values = {"estado": target}
    prior_resolution = ctx.plan.resolucion
    if op == "resolver":
        verified = ctx.conn.scalar(select(actions.c.id_accion).where(actions.c.id_respuesta == ctx.plan.id_respuesta,
            actions.c.estado == "verificada", actions.c.revision_validada == ctx.revision).limit(1))
        if not (body.resultado and body.riesgos_pendientes and body.referencia) or (
            not verified and not body.sin_acciones
        ):
            raise HTTPException(422, "Registre la comprobación, referencia, riesgos y justificación si no hubo acciones verificadas")
        values["resolucion"] = ctx.safe(body.model_dump(include={"resultado", "riesgos_pendientes", "referencia", "sin_acciones"}))
    elif op == "cerrar" and not (prior_resolution and body.resultado and body.referencia):
        raise HTTPException(422, "Documente el cumplimiento del criterio de cierre y su evidencia")
    elif op == "cancelar" and ctx.eligible:
        ctx.conflict("La cancelación requiere pérdida de elegibilidad")
    elif op == "reabrir":
        if states.difference(TERMINAL):
            ctx.conflict("Regularice las acciones pendientes antes de reabrir")
        values.update(revision_plan=ctx.revision, resolucion=null())
    ctx.change_plan(**values)
    ctx.record(op, body.motivo, {"estado_anterior": prior, "estado": target, "resolucion_anterior": prior_resolution,
                               "resultado": body.resultado, "referencia": body.referencia}, advance=False)
    return ctx.view()
