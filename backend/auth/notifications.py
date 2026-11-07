"""Durable safe-reference notifications, with Resend SMTP idempotency and bounded retries."""
from datetime import timedelta
import os
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from . import mailer
from .security import fingerprint, now
from .store import audit, ip_hash, table


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


def schedule(request, notification_id):
    ids = getattr(request.state, "mail_jobs", None)
    if ids is None:
        ids = []
        request.state.mail_jobs = ids
    if notification_id not in ids:
        ids.append(notification_id)


def enqueue(conn, request, *, kind, destination, event_id=None, support_id=None, actor=None, logical_key=None):
    if not destination:
        return None
    q = table(request, "auth_notificacion")
    key = fingerprint(request.app.state.auth_settings, "correo_notificacion", logical_key or f"{kind}:{event_id or support_id}")
    identifier = conn.scalar(insert(q).values(clave=key, tipo=kind, destinatario=destination,
        id_auditoria=event_id, id_soporte=support_id, creado_por=actor).on_conflict_do_nothing().returning(q.c.id_notificacion))
    if identifier:
        schedule(request, identifier)
    return identifier


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


def message_for(conn, request, row):
    config = request.app.state.mail_config
    if row.id_auditoria:
        a, u = table(request, "auth_auditoria"), table(request, "usuario")
        event = conn.execute(select(a, u.c.nombre_usuario).outerjoin(u,a.c.id_usuario==u.c.id_usuario).where(a.c.id_auditoria==row.id_auditoria)).mappings().first()
        if not event:
            return None
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


def dispatch_one(request, identifier):
    """Claim before SMTP. A crashed claim is uncertain, not silently resent forever."""
    q = table(request,"auth_notificacion")
    config = request.app.state.mail_config
    with request.app.state.engine.begin() as conn:
        row = conn.execute(select(q).where(q.c.id_notificacion==identifier).with_for_update(skip_locked=True)).mappings().first()
        if not row or row.estado in {"aceptado","cancelado"} or row.intentos >= config.max_attempts:
            return
        if row.estado == "en_proceso" and row.ultimo_intento_en > now()-timedelta(minutes=5):
            return
        if row.proximo_intento_en and row.proximo_intento_en > now():
            return
        if row.primer_intento_en and row.primer_intento_en <= now()-timedelta(hours=23):
            conn.execute(q.update().where(q.c.id_notificacion==identifier).values(estado="incierto",resultado="ventana_idempotencia_vencida"))
            return
        message = message_for(conn,request,row)
        if message is None:
            conn.execute(q.update().where(q.c.id_notificacion==identifier).values(estado="cancelado",resultado="referencia_no_disponible"))
            return
        conn.execute(q.update().where(q.c.id_notificacion==identifier).values(estado="en_proceso",intentos=row.intentos+1,
            primer_intento_en=row.primer_intento_en or now(),ultimo_intento_en=now(),proximo_intento_en=None))
        audit(conn,request,"correo_notificacion_intento",message[0],notification_id=str(identifier),resultado="iniciado")
    user_id, subject, content, reply_to = message
    state, result = "aceptado", "buzon_local" if os.getenv("MAIL_TRANSPORT")=="file" else "smtp_aceptado"
    try:
        kwargs = {"idempotency_key":"tacticlens/notificacion/"+str(identifier)}
        if reply_to:
            kwargs["reply_to"] = reply_to
        mailer.deliver(request.app.state.auth_settings,row.destinatario,subject,content,**kwargs)
    except mailer.DeliveryUncertain:
        state,result = "incierto","aceptacion_no_confirmada"
    except (OSError,ValueError,RuntimeError,mailer.smtplib.SMTPException):
        state,result = "fallido","error_transporte"
    with request.app.state.engine.begin() as conn:
        conn.execute(q.update().where(q.c.id_notificacion==identifier).values(estado=state,resultado=result,
            aceptado_en=now() if state=="aceptado" else None,
            proximo_intento_en=now()+timedelta(seconds=min(900,60*2**row.intentos)) if state!="aceptado" else None))
        audit(conn,request,"correo_notificacion_"+state,user_id,
              notification_id=str(identifier),resultado=result)


def dispatch_scheduled(request):
    for identifier in getattr(request.state,"mail_jobs",[]):
        try:
            dispatch_one(request,identifier)
        except Exception:
            # Never log exception strings: transport errors can contain private content.
            # A persisted in-progress claim remains available for supervised recovery.
            continue
