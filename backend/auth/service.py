"""Security operations shared by HTTP handlers and the administrator CLI."""
from datetime import timedelta
import hmac
import secrets
import smtplib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import mailer
from .security import PASSWORDS, fingerprint, matching_interval, now, opaque_token, recovery_codes, verify_password
from .store import AuthError, audit, clear_account_rate, factor, identity, rate, table


def create_account(conn, request, data, admin=False, temporary_password=None, verified_email=False):
    u, r = table(request, "usuario"), table(request, "rol")
    role = conn.scalar(select(r.c.id_rol).where(r.c.codigo == ("administrador" if admin else "analista"), r.c.activo.is_(True)))
    if role is None:
        raise AuthError(503, "El catálogo de roles no está disponible")
    user_id = uuid4()
    try:
        with conn.begin_nested():
            conn.execute(u.insert().values(
                id_usuario=user_id, id_rol=role, nombre=data.nombres + " " + data.apellidos,
                cedula=data.cedula, nombres=data.nombres, apellidos=data.apellidos,
                nombre_usuario=data.nombre_usuario, correo=data.correo,
                password_hash=PASSWORDS.hash(opaque_token() if temporary_password else data.password.get_secret_value()),
                password_cambio_obligatorio=temporary_password is not None,
                password_temporal_hash=PASSWORDS.hash(temporary_password) if temporary_password else None,
                password_temporal_vence_en=now()+timedelta(seconds=request.app.state.auth_settings.temporary_password_seconds) if temporary_password else None,
                correo_verificado_en=now() if verified_email else None,
                autorizacion="aprobado" if admin else "pendiente",
                autorizado_por=user_id if admin else None, autorizado_en=now() if admin else None,
                creado_por=user_id,
            ))
    except IntegrityError:
        audit(conn, request, "registro_rechazado", reason="datos_no_disponibles")
        raise AuthError(409, "No se pudo registrar con esos datos. Revise la información o recupere su cuenta.") from None
    audit(conn, request, "cuenta_creada", user_id, actor=user_id)
    return identity(conn, request, user_id)


def issue_email_code(conn, request, user):
    t, settings = table(request, "auth_token"), request.app.state.auth_settings
    # Serialize resend decisions across requests and workers.
    user = identity(conn, request, user.id_usuario, lock=True)
    last = conn.execute(select(t).where(t.c.id_usuario == user.id_usuario, t.c.proposito == "correo").order_by(t.c.creado_en.desc()).limit(1)).mappings().first()
    if user.correo_verificado_en or (last and last.creado_en > now() - timedelta(seconds=settings.resend_seconds)):
        return None
    conn.execute(t.update().where(t.c.id_usuario == user.id_usuario, t.c.proposito == "correo", t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo"))
    code = f"{secrets.randbelow(1_000_000):06d}"
    token_id = uuid4()
    conn.execute(t.insert().values(id_token=token_id, id_usuario=user.id_usuario, proposito="correo",
        token_hash=fingerprint(settings, "correo:" + str(token_id), code), vence_en=now() + timedelta(seconds=settings.email_seconds), creado_por=user.id_usuario))
    return (user.correo, "Verifique su correo electrónico",
            f"Su código de verificación es: {code}\n\nCaduca en {settings.email_seconds // 60} minutos y solo puede usarse una vez.\nVerificar el correo no sustituye la autorización administrativa ni Google Authenticator.")


def notify(request, user_id, message):
    if not message:
        return False
    try:
        mailer.deliver(request.app.state.auth_settings, *message)
        return True
    except (OSError, smtplib.SMTPException, RuntimeError):
        # No exception string: an SMTP error can contain addresses or message contents.
        with request.app.state.engine.begin() as conn:
            audit(conn, request, "correo_entrega_fallida", user_id, reason="transporte")
        return False


def issue_reset(conn, request, user):
    t, settings = table(request, "auth_token"), request.app.state.auth_settings
    identity(conn, request, user.id_usuario, lock=True)
    last = conn.execute(select(t).where(t.c.id_usuario == user.id_usuario, t.c.proposito == "password").order_by(t.c.creado_en.desc()).limit(1)).mappings().first()
    if last and last.creado_en > now() - timedelta(seconds=settings.resend_seconds):
        return None
    conn.execute(t.update().where(t.c.id_usuario == user.id_usuario, t.c.proposito == "password", t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo"))
    token = opaque_token()
    conn.execute(t.insert().values(id_usuario=user.id_usuario, proposito="password", token_hash=fingerprint(settings, "password", token),
        vence_en=now() + timedelta(seconds=settings.reset_seconds), creado_por=user.id_usuario))
    audit(conn, request, "recuperacion_password_solicitada", user.id_usuario)
    link = settings.public_url + "/recuperar#token=" + token
    return (user.correo, "Restablecimiento de contraseña",
            f"Para establecer una nueva contraseña, abra este enlace:\n{link}\n\nCaduca en {settings.reset_seconds // 60} minutos. Google Authenticator seguirá siendo obligatorio.")


def verify_second_factor(conn, request, user, code, recovery=False):
    # A user row serializes both TOTP/recovery verification and administrative reset.
    identity(conn, request, user.id_usuario, lock=True)
    settings = request.app.state.auth_settings
    rate(conn, request, "segundo_factor", user.id_usuario, account_limit=settings.max_attempts)
    if recovery:
        t = table(request, "auth_recuperacion")
        hashed = fingerprint(settings, "recuperacion:" + str(user.id_usuario), code.strip().lower())
        used = conn.scalar(t.update().where(t.c.id_usuario == user.id_usuario, t.c.codigo_hash == hashed,
            t.c.usado_en.is_(None), t.c.estado_registro == "vigente").values(usado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario).returning(t.c.id_recuperacion))
        if used:
            audit(conn, request, "codigo_recuperacion_usado", user.id_usuario, actor=user.id_usuario)
            clear_account_rate(conn, request, "segundo_factor", user.id_usuario)
            return
    else:
        f = factor(conn, request, user.id_usuario, lock=True)
        if f and f.confirmado_en:
            secret = settings.cipher.decrypt(f.secreto_cifrado.encode()).decode()
            interval = matching_interval(secret, code, f.ultimo_intervalo)
            if interval is not None:
                conn.execute(table(request, "auth_factor").update().where(table(request, "auth_factor").c.id_usuario == user.id_usuario).values(ultimo_intervalo=interval, modificado_por=user.id_usuario))
                audit(conn, request, "mfa_validado", user.id_usuario, actor=user.id_usuario)
                clear_account_rate(conn, request, "segundo_factor", user.id_usuario)
                return
    audit(conn, request, "mfa_rechazado", user.id_usuario, reason="codigo_invalido_o_reutilizado")
    raise AuthError(400, "Código inválido, vencido o ya utilizado. Espere el siguiente código si acaba de usarlo.")


def reauthenticate(conn, request, user, payload):
    rate(conn, request, "reautenticacion", user.id_usuario, account_limit=request.app.state.auth_settings.max_attempts)
    if not verify_password(user.password_hash, payload.password.get_secret_value()):
        audit(conn, request, "reautenticacion_rechazada", user.id_usuario)
        raise AuthError(400, "No se pudo verificar su identidad")
    verify_second_factor(conn, request, user, payload.codigo.get_secret_value(), payload.recuperacion)
    clear_account_rate(conn, request, "reautenticacion", user.id_usuario)


def replace_recovery_codes(conn, request, user_id):
    t, settings = table(request, "auth_recuperacion"), request.app.state.auth_settings
    conn.execute(t.update().where(t.c.id_usuario == user_id, t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo", modificado_por=user_id))
    codes = recovery_codes()
    conn.execute(t.insert(), [{"id_usuario": user_id, "codigo_hash": fingerprint(settings, "recuperacion:" + str(user_id), code), "creado_por": user_id} for code in codes])
    return codes


def is_temporary_password(user, value):
    return bool(user.password_temporal_hash and verify_password(user.password_temporal_hash, value))


def validate_new_password(value, personal, user=None):
    from .security import validate_password
    if user is not None and is_temporary_password(user, value):
        raise AuthError(422, "Elija una contraseña distinta de la temporal recibida por correo.")
    try:
        return validate_password(value, personal)
    except ValueError as exc:
        raise AuthError(422, str(exc)) from None
