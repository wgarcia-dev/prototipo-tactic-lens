"""Durable safe-reference notifications, with Resend SMTP idempotency and bounded retries."""
import asyncio
from datetime import timedelta
import hmac
import logging
import os
from uuid import UUID

from fastapi import Request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from starlette.concurrency import run_in_threadpool

from . import mailer
from .security import fingerprint, now
from .store import approved, audit, identity, ip_hash, table


EVENTS = {
    "cuenta_creada": "Nueva solicitud de registro pendiente",
    "correo_verificado": "Nueva solicitud de registro pendiente",
    "cuenta_bloqueada": "Cuenta bloqueada administrativamente",
    "cuenta_suspendida": "Cuenta suspendida",
    "cuenta_reactivada": "Cuenta reactivada",
    "rol_cambiado": "Cambio de rol",
    "mfa_restablecido_administrativamente": "Restablecimiento administrativo de MFA completado",
    "recuperacion_solicitada": "Nueva solicitud de recuperación pendiente",
    "recuperacion_aprobada": "Recuperación de contraseña autorizada",
    "soporte_mfa_solicitado": "Solicitud de ayuda con MFA",
}
FAILURES = {"login_fallido", "mfa_rechazado", "reautenticacion_rechazada"}
RECOVERY_KINDS = {"recuperacion_enlace", "recuperacion_rechazo"}
CLAIM_LEASE = timedelta(minutes=5)
logger = logging.getLogger(__name__)


def recovery_secret(settings, recovery_id, token_id):
    return fingerprint(settings, "recuperacion_outbox_v1", f"{recovery_id}:{token_id}")


def enqueue(conn, request, *, kind, destination, event_id=None, support_id=None, actor=None, logical_key=None):
    if not destination:
        return None
    q = table(request, "auth_notificacion")
    key = fingerprint(request.app.state.auth_settings, "correo_notificacion", logical_key or f"{kind}:{event_id or support_id}")
    return conn.scalar(insert(q).values(clave=key, tipo=kind, destinatario=destination,
        id_auditoria=event_id, id_soporte=support_id, creado_por=actor).on_conflict_do_nothing().returning(q.c.id_notificacion))


def alert_slot(conn, request, scope):
    config = request.app.state.mail_config
    t = table(request, "auth_limite")
    key = fingerprint(request.app.state.auth_settings, "correo_alerta_cooldown", scope)
    return conn.scalar(insert(t).values(clave=key, ventana=now(), intentos=1).on_conflict_do_update(
        index_elements=["clave"], set_={"ventana":now(), "intentos":1},
        where=t.c.ventana <= now()-timedelta(seconds=config.cooldown_seconds)).returning(t.c.clave)) is not None


def queue_event(conn, request, event_id, kind, user_id, actor):
    config = getattr(request.app.state, "mail_config", None)
    if not config or not config.admin:
        return
    if kind in EVENTS:
        logical_key=None
        if kind in {"cuenta_creada","correo_verificado"}:
            u = table(request, "usuario")
            if not conn.scalar(select(u.c.id_usuario).where(u.c.id_usuario==user_id,
                    u.c.correo_verificado_en.is_not(None),u.c.autorizacion=="pendiente")):
                return
            logical_key="registro_pendiente:"+str(user_id)
        if kind=="recuperacion_solicitada":
            a,s=table(request,"auth_auditoria"),table(request,"auth_solicitud_password")
            reference=conn.scalar(select(a.c.metadatos).where(a.c.id_auditoria==event_id)).get("request_id")
            if not conn.scalar(select(s.c.id_solicitud).where(s.c.id_solicitud==reference,s.c.origen=="recuperacion")):
                return
        enqueue(conn, request, kind="administrativa", destination=config.admin, event_id=event_id, actor=actor,logical_key=logical_key)
    elif kind in FAILURES or kind == "autenticacion_limitada":
        a = table(request, "auth_auditoria")
        scope = str(user_id) if user_id else ip_hash(request)
        enough = kind == "autenticacion_limitada"
        if not enough:
            criteria = a.c.id_usuario == user_id if user_id else a.c.metadatos["ip_hash"].astext == ip_hash(request)
            count = conn.scalar(select(func.count()).select_from(a).where(a.c.tipo.in_(FAILURES), criteria,
                a.c.fecha_evento >= now()-timedelta(seconds=config.window_seconds)))
            enough = count >= config.threshold
        if enough and alert_slot(conn, request, scope):
            enqueue(conn, request, kind="alerta", destination=config.admin, event_id=event_id)


def event_time(value, config):
    value = value.astimezone(config.timezone)
    offset = value.strftime("%z")
    return value.strftime("%d/%m/%Y %H:%M:%S") + " " + config.timezone.key + " (UTC" + offset[:3] + ":" + offset[3:] + ")"


def recovery_reference(conn, request, row):
    if row.tipo not in RECOVERY_KINDS:
        return None
    a = table(request, "auth_auditoria")
    reference = conn.scalar(select(a.c.metadatos["request_id"].astext).where(a.c.id_auditoria == row.id_auditoria))
    try:
        return UUID(reference) if reference else None
    except ValueError:
        return None


def recovery_message(conn, request, row, recovery_id):
    q, t = table(request, "auth_solicitud_password"), table(request, "auth_token")
    record = conn.execute(select(q).where(q.c.id_solicitud == recovery_id)).mappings().first()
    if not record:
        return None
    user = identity(conn, request, record.id_usuario)
    if not approved(user) or user.correo != row.destinatario:
        return None
    if row.tipo == "recuperacion_rechazo" and record.estado == "rechazada":
        return user.id_usuario, "Solicitud de recuperación rechazada", (
            "Un administrador no autorizó su solicitud. Contacte al administrador por un canal conocido."), None
    if row.tipo != "recuperacion_enlace" or record.estado != "aprobada" or record.enlace_vence_en <= now():
        return None
    token = conn.execute(select(t).where(t.c.id_solicitud == recovery_id, t.c.proposito == "password",
        t.c.usado_en.is_(None), t.c.estado_registro == "vigente", t.c.vence_en > now())
        .order_by(t.c.creado_en.desc(), t.c.id_token).limit(1)).mappings().first()
    if token is None:
        return None
    settings = request.app.state.auth_settings
    secret = recovery_secret(settings, recovery_id, token.id_token)
    if not hmac.compare_digest(token.token_hash, fingerprint(settings, "password", secret)):
        return None
    subject = "Cuenta autorizada: defina su contraseña" if record.origen == "alta" else "Recuperación aprobada: restablezca su contraseña"
    link = settings.public_url + "/recuperar#token=" + secret
    return user.id_usuario, subject, (
        "Un administrador aprobó su solicitud. Abra este enlace personal de un solo uso:\n" + link
        + "\n\nEl enlace tiene vencimiento. No lo comparta. Google Authenticator seguirá siendo obligatorio."), None


def message_for(conn, request, row, recovery_id=None):
    config = request.app.state.mail_config
    if row.tipo in RECOVERY_KINDS:
        return recovery_message(conn, request, row, recovery_id)
    if row.id_auditoria:
        a, u = table(request, "auth_auditoria"), table(request, "usuario")
        event = conn.execute(select(a, u.c.nombre_usuario).outerjoin(u,a.c.id_usuario==u.c.id_usuario).where(a.c.id_auditoria==row.id_auditoria)).mappings().first()
        if not event:
            return None
        if event.tipo == "incidente_aviso_correo":
            from ..api import sensor_ids
            from ..incident_notices import visible_notices
            account = identity(conn, request, event.id_usuario)
            if not approved(account) or account.correo != row.destinatario or "incidente_aviso" not in request.app.state.tables:
                return None
            notices = table(request, "incidente_aviso")
            reference = event.metadatos.get("request_id")
            if not reference or not conn.scalar(select(notices.c.id_aviso).where(
                    notices.c.id_aviso == UUID(reference), *visible_notices(request.app.state.tables, sensor_ids(), account.id_usuario))):
                return None
            return account.id_usuario, "TacticLens · Actuación pendiente de consulta", (
                "Tiene un aviso sobre sus actuaciones en TacticLens. Consulte la plataforma con su sesión habitual:\n"
                + request.app.state.auth_settings.public_url + "/respuesta-incidentes"), None
        title = EVENTS.get(event.tipo, "Intentos reiterados de autenticación")
        if event.tipo == "autenticacion_limitada":
            title = "Acceso limitado temporalmente por intentos de autenticación"
        subject = title if event.tipo in {"cuenta_creada","correo_verificado"} else "Alerta administrativa · " + title
        state = "Pendiente de revisión" if event.tipo in {"cuenta_creada","correo_verificado","recuperacion_solicitada","soporte_mfa_solicitado"} else "Registrado en la auditoría"
        content = (title + ".\n\nReferencia del evento: " + str(event.id_auditoria)
            + "\nUsuario: " + (event.nombre_usuario or "No identificado")
            + "\nFecha: " + event_time(event.fecha_evento,config) + "\nEstado en el momento del evento: " + state
            + "\n\nRevise los detalles dentro de TacticLens. Debe iniciar sesión como administrador y completar MFA. "
            "Responder a este correo no aprueba cuentas ni modifica permisos.\n"
            + request.app.state.auth_settings.public_url + "/usuarios")
        return event.id_usuario, subject, content, None
    s = table(request, "auth_soporte")
    record = conn.execute(select(s).where(s.c.id_soporte==row.id_soporte)).mappings().first()
    if not record:
        return None
    if row.tipo == "confirmacion_soporte":
        u = table(request, "usuario")
        if not record.correo_verificado or not conn.scalar(select(u.c.id_usuario).where(u.c.id_usuario==record.id_usuario,
                u.c.correo==record.correo,u.c.correo_verificado_en.is_not(None))):
            return None
        return record.id_usuario, "Confirmación de solicitud de soporte", (
            "Su consulta quedó registrada para remisión al canal de soporte.\n\nReferencia: " + str(record.id_soporte)
            + "\nFecha: " + event_time(record.creado_en,config)
            + "\n\nEl personal de soporte responderá manualmente. Este aviso no confirma lectura ni resolución. "
            "Contactar a soporte no omite MFA ni modifica restricciones administrativas."), None
    verification = "Correo verificado de la cuenta autenticada" if record.correo_verificado else "Correo declarado sin verificación de identidad en este formulario"
    content = ("Una persona envió una solicitud de ayuda desde TacticLens.\n\nReferencia: " + str(record.id_soporte)
        + "\nFecha: " + event_time(record.creado_en,config) + "\nNombre: " + record.nombre
        + "\nCorreo de respuesta: " + record.correo + "\nIdentidad: " + verification
        + "\nCategoría: " + record.categoria + "\nAsunto: " + record.asunto
        + "\n\nDescripción:\n" + record.descripcion
        + "\n\nResponda manualmente desde el buzón de soporte. Este mensaje no autoriza cambios de contraseña, permisos ni MFA. "
        "Aplique el procedimiento de verificación de identidad cuando corresponda.")
    return record.id_usuario, "Nuevo mensaje de soporte · " + record.categoria, content, record.correo


def set_recovery_delivery(conn, request, recovery_id, state):
    if recovery_id:
        q = table(request, "auth_solicitud_password")
        conn.execute(q.update().where(q.c.id_solicitud == recovery_id,
            q.c.estado.in_(("aprobada", "rechazada", "completada"))).values(
            notificacion_estado={"aceptado": "enviada", "cancelado": "fallida"}.get(state, state),
            notificado_en=now() if state == "aceptado" else None))


def dispatch_one(request, identifier):
    """Claim one committed reference. An uncertain claim is never retried automatically."""
    q = table(request, "auth_notificacion")
    config = request.app.state.mail_config
    with request.app.state.engine.begin() as conn:
        row = conn.execute(select(q).where(q.c.id_notificacion == identifier)
                           .with_for_update(skip_locked=True)).mappings().first()
        if not row:
            return
        recovery_id = recovery_reference(conn, request, row)
        moment = now()
        if row.estado == "en_proceso":
            if row.ultimo_intento_en and row.ultimo_intento_en > moment - CLAIM_LEASE:
                return
            conn.execute(q.update().where(q.c.id_notificacion == identifier).values(
                estado="incierto", resultado="interrumpido_durante_envio", proximo_intento_en=None))
            set_recovery_delivery(conn, request, recovery_id, "incierto")
            audit(conn, request, "correo_notificacion_incierto", notification_id=str(identifier),
                  resultado="interrumpido_durante_envio")
            return
        if row.estado not in {"pendiente", "reintento", "fallido"} or row.intentos >= config.max_attempts:
            return
        if row.proximo_intento_en and row.proximo_intento_en > moment:
            return
        message = message_for(conn, request, row, recovery_id)
        if message is None or (row.primer_intento_en and row.primer_intento_en <= moment - timedelta(hours=23)):
            conn.execute(q.update().where(q.c.id_notificacion == identifier).values(
                estado="cancelado", resultado="referencia_no_disponible", proximo_intento_en=None))
            set_recovery_delivery(conn, request, recovery_id, "cancelado")
            return
        attempt = row.intentos + 1
        conn.execute(q.update().where(q.c.id_notificacion == identifier).values(estado="en_proceso",
            intentos=attempt, primer_intento_en=row.primer_intento_en or moment, ultimo_intento_en=moment,
            proximo_intento_en=None))
        set_recovery_delivery(conn, request, recovery_id, "en_proceso")
        audit(conn, request, "correo_notificacion_intento", message[0],
              notification_id=str(identifier), resultado="iniciado")
    user_id, subject, content, reply_to = message
    state, result = "aceptado", "buzon_local" if os.getenv("MAIL_TRANSPORT") == "file" else "smtp_aceptado"
    retryable = False
    try:
        kwargs = {"idempotency_key": "tacticlens/notificacion/" + str(identifier)}
        if reply_to:
            kwargs["reply_to"] = reply_to
        mailer.deliver(request.app.state.auth_settings, row.destinatario, subject, content, **kwargs)
    except mailer.DeliveryUncertain:
        state, result = "incierto", "aceptacion_no_confirmada"
    except mailer.smtplib.SMTPResponseException as error:
        state, result = "fallido", "error_smtp"
        retryable = 400 <= error.smtp_code < 500
    except OSError:
        state, result, retryable = "fallido", "transporte_no_disponible", True
    except (ValueError, RuntimeError, mailer.smtplib.SMTPException):
        state, result = "fallido", "error_transporte"
    retry_at = None
    if retryable and attempt < config.max_attempts:
        state = "reintento"
        retry_at = now() + timedelta(seconds=min(900, 30 * 2**attempt))
    with request.app.state.engine.begin() as conn:
        updated = conn.execute(q.update().where(q.c.id_notificacion == identifier,
            q.c.estado == "en_proceso", q.c.intentos == attempt).values(estado=state, resultado=result,
            aceptado_en=now() if state == "aceptado" else None, proximo_intento_en=retry_at))
        if updated.rowcount:
            set_recovery_delivery(conn, request, recovery_id, state)
            audit(conn, request, "correo_notificacion_" + state, user_id,
                  notification_id=str(identifier), resultado=result)


def dispatch_pending(app, limit=12):
    request = Request({"type":"http", "method":"GET", "path":"/tareas/cola-correo", "headers":[],
                       "query_string":b"", "app":app})
    q = table(request, "auth_notificacion")
    moment = now()
    with app.state.engine.connect() as conn:
        identifiers = list(conn.scalars(select(q.c.id_notificacion).where(or_(
            q.c.estado == "pendiente",
            and_(q.c.estado.in_(("reintento", "fallido")), q.c.proximo_intento_en <= moment,
                 q.c.intentos < app.state.mail_config.max_attempts),
            and_(q.c.estado == "en_proceso", or_(q.c.ultimo_intento_en.is_(None),
                                                 q.c.ultimo_intento_en <= moment - CLAIM_LEASE)),
        )).order_by(q.c.creado_en, q.c.id_notificacion).limit(limit)))
    for identifier in identifiers:
        try:
            dispatch_one(request, identifier)
        except Exception as error:
            logger.warning("Fallo de cola de correo (%s)", type(error).__name__)


async def drain_outbox(app):
    try:
        poll = max(1, min(60, int(os.getenv("MAIL_OUTBOX_POLL_SECONDS", "5"))))
    except ValueError:
        poll = 5
    while True:
        try:
            await run_in_threadpool(dispatch_pending, app)
        except Exception as error:
            logger.warning("No se pudo consultar la cola de correo (%s)", type(error).__name__)
        await asyncio.sleep(poll)
