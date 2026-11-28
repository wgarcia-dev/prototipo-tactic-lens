"""Persistent, scoped notifications for response changes and deadlines."""

from datetime import timedelta
import os

from sqlalchemy import and_, case, func, select
from sqlalchemy.dialects.postgresql import insert

from .analysis_state import digest
from .auth.notifications import enqueue
from .auth.store import audit
from .incidents import scoped
from .realtime import notify_change

TEXT = {
    "candidato": "Nuevo candidato a incidente",
    "plan_generado": "Borrador generado por IA",
    "plan_pendiente": "Borrador pendiente de aprobación",
    "generacion_fallida": "Error al generar el borrador",
    "asignada": "Nueva acción asignada",
    "reasignada": "Responsable de acción cambiado",
    "sin_responsable": "Acción pendiente de asignación",
    "aprobar": "Acción aprobada",
    "rechazar": "Acción rechazada",
    "ejecutar": "Acción ejecutada pendiente de verificación",
    "proximo_vencimiento": "La acción vence pronto",
    "vencida": "La acción está vencida",
    "resolver": "Incidente resuelto",
    "cerrar": "Incidente cerrado",
    "reabrir": "Incidente reabierto",
}
DIRECT = {"asignada", "reasignada", "proximo_vencimiento", "vencida"}


def eligible_people(tables):
    user, role = tables["usuario"], tables["rol"]
    return (select(user.c.id_usuario, user.c.nombre_usuario, user.c.correo, role.c.codigo.label("rol"))
            .join(role, role.c.id_rol == user.c.id_rol).where(user.c.activo, role.c.activo,
                func.coalesce(user.c.restriccion_acceso, "") == "", user.c.autorizacion == "aprobado",
                user.c.correo_verificado_en.is_not(None), role.c.codigo.in_(("administrador", "analista"))))


def workload(conn, tables, sensors):
    users = eligible_people(tables).subquery()
    actions, incidents = (tables[name] for name in ("incidente_accion", "incidente"))
    valid = select(incidents.c.id_incidente).where(scoped(incidents, tables, sensors))
    active = (actions.c.estado.in_(("aprobada", "en_curso", "ejecutada")) & actions.c.id_incidente.in_(valid))
    rows = conn.execute(select(users.c.id_usuario, users.c.nombre_usuario, users.c.rol,
        func.count(actions.c.id_accion).label("carga"), func.count().filter(actions.c.estado == "en_curso").label("en_curso"))
        .select_from(users.outerjoin(actions, and_(users.c.id_usuario == actions.c.id_responsable, active)))
        .group_by(users.c.id_usuario, users.c.nombre_usuario, users.c.rol)
        .order_by("en_curso", "carga", users.c.nombre_usuario, users.c.id_usuario)).mappings()
    return [dict(row) for row in rows]


def incident_sensors(conn, tables, incident_id):
    links, sessions = tables["incidente_sesion"], tables["sesion"]
    return set(conn.scalars(select(sessions.c.id_honeypot).join(links, links.c.id_sesion == sessions.c.id_sesion)
                            .where(links.c.id_incidente == incident_id).distinct()))


def issue(conn, tables, incident_id, sensors, kind, version, *, action_id=None, users=(), admins=False, request=None, due=None):
    notices = tables.get("incidente_aviso")
    if notices is None or not sensors:
        return
    # The application currently grants an approved account every configured sensor.
    from .api import sensor_ids
    if not set(sensors) <= set(sensor_ids()):
        return
    people = eligible_people(tables)
    if admins:
        people = people.where((tables["rol"].c.codigo == "administrador") | tables["usuario"].c.id_usuario.in_(users))
    else:
        people = people.where(tables["usuario"].c.id_usuario.in_(users))
    recipients = []
    key = digest([str(incident_id), str(action_id), kind, version])
    for person in conn.execute(people):
        inserted = conn.scalar(insert(notices).values(destinatario=person.id_usuario, id_incidente=incident_id,
            id_accion=action_id, tipo=kind, clave=key, vencimiento=due).on_conflict_do_nothing().returning(notices.c.id_aviso))
        if not inserted:
            continue
        recipients.append(person.id_usuario)
        if request and kind in DIRECT and os.getenv("INCIDENT_RESPONSE_EMAIL_ENABLED", "false").lower() == "true":
            # Delivery and ambiguous SMTP failures are handled by the existing outbox after commit.
            event = audit(conn, request, "incidente_aviso_correo", user_id=person.id_usuario, request_id=str(inserted))
            enqueue(conn, request, kind="administrativa", destination=person.correo, event_id=event,
                    logical_key="incidente_aviso:" + str(inserted))
    for start in range(0, len(recipients), 100):
        notify_change(conn, sensors, "avisos_incidentes", recipients=recipients[start:start + 100])


def visible_notices(tables, sensors, user):
    notices, incidents = tables["incidente_aviso"], tables["incidente"]
    return (notices.c.destinatario == user,
            select(1).select_from(incidents).where(incidents.c.id_incidente == notices.c.id_incidente,
                                                  scoped(incidents, tables, sensors)).exists())


def response_notice(ctx, operation, row=None, previous=None):
    tables = ctx.tables
    if "incidente_aviso" not in tables:
        return
    if row is None:
        if operation in {"resolver", "cerrar", "reabrir"}:
            assignees = list(ctx.conn.scalars(select(tables["incidente_accion"].c.id_responsable).where(
                tables["incidente_accion"].c.id_respuesta == ctx.plan.id_respuesta,
                tables["incidente_accion"].c.id_responsable.is_not(None)).distinct()))
            if ctx.plan.id_responsable:
                assignees.append(ctx.plan.id_responsable)
            issue(ctx.conn, tables, ctx.id_incidente, ctx.sensors, operation, ctx.plan.revision_respuesta,
                  users=assignees, admins=True, request=ctx.request)
        return
    users = [row.id_responsable] if row.id_responsable else []
    if operation == "asignar" and row.id_responsable != previous.id_responsable:
        recipients = users + ([previous.id_responsable] if previous.id_responsable else [])
        issue(ctx.conn, tables, ctx.id_incidente, ctx.sensors, "reasignada" if previous.id_responsable else "asignada",
              row.revision_accion, action_id=row.id_accion, users=recipients, request=ctx.request)
    if operation in {"aprobar", "rechazar", "ejecutar"}:
        issue(ctx.conn, tables, ctx.id_incidente, ctx.sensors, operation, row.revision_accion,
              action_id=row.id_accion, users=users, admins=operation == "ejecutar" or not users, request=ctx.request)
        if operation == "aprobar" and not users:
            issue(ctx.conn, tables, ctx.id_incidente, ctx.sensors, "sin_responsable", row.revision_accion,
                  action_id=row.id_accion, admins=True)


def reminders(conn, request, today):
    from .api import sensor_ids
    tables = request.app.state.tables
    actions, plans, incidents, notices = (tables[name] for name in (
        "incidente_accion", "incidente_respuesta", "incidente", "incidente_aviso"))
    # Exclude already processed deadlines before limiting, so old overdue work
    # cannot permanently starve newer reminders.
    eligible = eligible_people(tables).subquery()
    overdue = actions.c.vence_en < today
    kind = case((overdue, "vencida"), else_="proximo_vencimiento")
    sent = select(1).select_from(notices).where(notices.c.id_accion == actions.c.id_accion,
        notices.c.destinatario == actions.c.id_responsable, notices.c.tipo == kind,
        notices.c.vencimiento == actions.c.vence_en).exists()
    rows = conn.execute(select(actions.c.id_accion, actions.c.id_incidente, actions.c.vence_en, actions.c.id_responsable, kind)
        .join(plans, plans.c.id_respuesta == actions.c.id_respuesta)
        .join(incidents, incidents.c.id_incidente == actions.c.id_incidente)
        .join(eligible, eligible.c.id_usuario == actions.c.id_responsable)
        .where(plans.c.estado == "en_respuesta", actions.c.estado.in_(("aprobada", "en_curso")),
               actions.c.vence_en <= today + timedelta(days=2), ~sent, scoped(incidents, tables, sensor_ids()))
        .order_by(actions.c.vence_en, actions.c.orden).limit(100)).all()
    for action, incident, due, user, kind in rows:
        issue(conn, tables, incident, incident_sensors(conn, tables, incident), kind, due.isoformat(),
              action_id=action, users=(user,), request=request, due=due)
