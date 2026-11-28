"""Cookie-based authentication: primary credentials never grant module access."""
import base64
from datetime import timedelta
import hmac
import hashlib
import io
import secrets
from uuid import UUID
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Request, Response, Query
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert

from .config import SESSION_COOKIE, CSRF_COOKIE, REGISTRATION_COOKIE
from .schemas import (RegistrationProfile, Login, EmailPayload, EmailCode, SecondFactor, Reauthentication,
                      PasswordReset, PasswordChange, UserUpdate, MfaReset, InitialPassword, PasswordAssessment)
from .security import DUMMY_HASH, PASSWORDS, fingerprint, matching_interval, now, opaque_token, verify_password, password_strength
from .service import (create_account, issue_email_code, issue_reset, notify, reauthenticate,
                      replace_recovery_codes, verify_second_factor, validate_new_password, is_temporary_password)
from ..sensitive import redact
from .store import (AuthError, approved, audit, eligible, factor, identity, new_session, next_stage,
                    public_user, rate, require_admin, revoke, session, table, transaction, clear_account_rate)

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])
GENERIC_EMAIL = {"mensaje": "Si la cuenta puede realizar esta operación, recibirá un correo con las instrucciones."}
GENERIC_RECOVERY = {"mensaje": "Si la cuenta es elegible, su solicitud se procesará para revisión administrativa. Si se aprueba, recibirá instrucciones en su correo."}


def csrf_serializer(request):
    return URLSafeTimedSerializer(request.app.state.auth_settings.secret, salt="tacticlens-csrf-v1", signer_kwargs={"digest_method": hashlib.sha256})


@router.get("/csrf")
def csrf(request: Request, response: Response):
    token = request.cookies.get(CSRF_COOKIE, "")
    try:
        csrf_serializer(request).loads(token, max_age=28800)
    except (BadSignature, SignatureExpired):
        token = csrf_serializer(request).dumps(opaque_token())
    response.set_cookie(CSRF_COOKIE, token, max_age=28800, httponly=True,
        secure=request.app.state.auth_settings.secure_cookie, samesite="strict", path="/api")
    return {"csrf_token": token}


@router.post("/registro", status_code=201)
def register(payload: RegistrationProfile, request: Request, response: Response):
    from .onboarding import pending_proof
    with transaction(request) as conn:
        rate(conn, request, "registro", payload.correo, account_limit=5, ip_limit=15)
        proof = pending_proof(conn, request, lock=True)
        if not proof or proof.correo != payload.correo or not proof.verificado_en or proof.vence_en <= now():
            raise AuthError(403, "Verifique este correo en el formulario antes de enviar la solicitud.")
        user = create_account(conn, request, payload, passwordless=True, verified_email=True)
        t = table(request, "auth_token")
        conn.execute(t.update().where(t.c.id_token == proof.id_token).values(usado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        audit(conn, request, "correo_verificado", user.id_usuario, actor=user.id_usuario)
        response.delete_cookie(REGISTRATION_COOKIE, path="/api/auth")
    delivered = notify(request, user.id_usuario, (user.correo, "Solicitud de registro recibida",
        "Su correo está verificado y su solicitud está pendiente de autorización. Cuando un administrador la apruebe, "
        "recibirá un enlace personal para definir su contraseña. No enviamos contraseñas por correo."))
    return {"mensaje": "Solicitud registrada. Espere la aprobación administrativa y el enlace para definir su contraseña.",
            "notificacion_enviada": delivered}



@router.post("/correo/reenviar", status_code=202)
def resend_email(payload: EmailPayload, request: Request):
    message, user = None, None
    with transaction(request) as conn:
        rate(conn, request, "reenviar_correo", payload.correo, account_limit=5, ip_limit=20)
        u = table(request, "usuario")
        user_id = conn.scalar(select(u.c.id_usuario).where(u.c.correo == payload.correo))
        user = identity(conn, request, user_id) if user_id else None
        if eligible(user):
            message = issue_email_code(conn, request, user)
    notify(request, user.id_usuario if user else None, message)
    return GENERIC_EMAIL


@router.post("/correo/verificar")
def verify_email(payload: EmailCode, request: Request):
    with transaction(request) as conn:
        settings, u, t = request.app.state.auth_settings, table(request, "usuario"), table(request, "auth_token")
        rate(conn, request, "verificar_correo", payload.correo, account_limit=settings.max_attempts)
        user_id = conn.scalar(select(u.c.id_usuario).where(u.c.correo == payload.correo))
        user = identity(conn, request, user_id, lock=True) if user_id else None
        record = conn.execute(select(t).where(t.c.id_usuario == user_id, t.c.proposito == "correo", t.c.usado_en.is_(None)).order_by(t.c.creado_en.desc()).limit(1).with_for_update()).mappings().first() if user else None
        if not eligible(user) or not record or record.vence_en <= now() or record.intentos >= settings.max_attempts:
            audit(conn, request, "correo_verificacion_rechazada", user_id, reason="invalido_o_vencido")
            raise AuthError(400, "Código inválido o vencido")
        expected = fingerprint(settings, "correo:" + str(record.id_token), payload.codigo.get_secret_value())
        if not hmac.compare_digest(record.token_hash, expected):
            attempts = record.intentos + 1
            conn.execute(t.update().where(t.c.id_token == record.id_token).values(intentos=attempts, usado_en=now() if attempts >= settings.max_attempts else None))
            audit(conn, request, "correo_verificacion_rechazada", user_id, reason="codigo_incorrecto")
            raise AuthError(400, "Código inválido o vencido")
        conn.execute(t.update().where(t.c.id_token == record.id_token).values(usado_en=now(), estado_registro="inactivo", modificado_por=user_id))
        conn.execute(u.update().where(u.c.id_usuario == user_id).values(correo_verificado_en=now(), modificado_por=user_id))
        audit(conn, request, "correo_verificado", user_id, actor=user_id)
    return {"mensaje": "Correo verificado. La autorización del administrador y Google Authenticator siguen siendo obligatorios."}


@router.post("/login")
def login(payload: Login, request: Request, response: Response):
    with transaction(request) as conn:
        rate(conn, request, "login", payload.correo)
        u = table(request, "usuario")
        user_id = conn.scalar(select(u.c.id_usuario).where(u.c.correo == payload.correo))
        user = identity(conn, request, user_id, lock=True) if user_id else None
        temporary = bool(user and user.password_cambio_obligatorio)
        hashed = (user.password_temporal_hash if temporary else user.password_hash) if user else DUMMY_HASH
        valid = verify_password(hashed or DUMMY_HASH, payload.password.get_secret_value())
        if temporary and (user.password_temporal_usada_en or not user.password_temporal_vence_en or user.password_temporal_vence_en <= now()):
            valid = False
        if not valid or not eligible(user):
            audit(conn, request, "login_fallido", user_id, reason="credenciales_o_estado")
            raise AuthError(401, "Credenciales inválidas o cuenta no disponible")
        if temporary:
            conn.execute(u.update().where(u.c.id_usuario == user_id).values(password_temporal_usada_en=now(), modificado_por=user_id))
            audit(conn, request, "password_temporal_utilizada", user_id, actor=user_id)
        elif PASSWORDS.check_needs_rehash(user.password_hash):
            conn.execute(u.update().where(u.c.id_usuario == user_id).values(password_hash=PASSWORDS.hash(payload.password.get_secret_value())))
        stage = next_stage(conn, request, user)
        # Revoke an existing browser challenge to prevent fixation; keep other devices.
        previous = request.cookies.get(SESSION_COOKIE)
        if previous:
            t = table(request, "auth_sesion")
            conn.execute(t.update().where(t.c.token_hash == fingerprint(request.app.state.auth_settings, "sesion", previous)).values(revocado_en=now(), estado_registro="inactivo"))
        new_session(conn, request, response, user, stage)
        audit(conn, request, "credenciales_primarias_validas", user_id, actor=user_id)
        clear_account_rate(conn, request, "login", payload.correo)
    return {"etapa": stage}


@router.post("/password/inicial")
def initial_password(payload: InitialPassword, request: Request, response: Response):
    with transaction(request) as conn:
        current, user = session(conn, request, {"crear_password"})
        if not user.password_cambio_obligatorio or not user.password_temporal_usada_en:
            raise AuthError(403, "Inicie sesión con la credencial temporal para crear su contraseña.")
        validate_new_password(payload.password.get_secret_value(), (user.nombres, user.apellidos, user.correo, user.nombre_usuario, user.cedula), user=user)
        u = table(request, "usuario")
        conn.execute(u.update().where(u.c.id_usuario == user.id_usuario).values(
            password_hash=PASSWORDS.hash(payload.password.get_secret_value()), password_cambio_obligatorio=False,
            password_temporal_vence_en=None, modificado_por=user.id_usuario))
        revoke(conn, request, user.id_usuario)
        updated = identity(conn, request, user.id_usuario)
        stage = next_stage(conn, request, updated)
        new_session(conn, request, response, updated, stage)
        audit(conn, request, "password_definitiva_creada", user.id_usuario, actor=user.id_usuario)
    return {"etapa": stage, "mensaje": "Contraseña creada. Continúe con los requisitos de acceso pendientes."}


@router.post("/password/fortaleza")
def assess_password(payload: PasswordAssessment, request: Request):
    with transaction(request) as conn:
        if payload.token:
            from .recovery import validated_token
            user, _, _ = validated_token(conn, request, payload.token.get_secret_value())
        else:
            _, user = session(conn, request, {"crear_password", "completa"})
        rate(conn, request, "fortaleza", user.id_usuario, account_limit=120, ip_limit=300)
        result = password_strength(payload.password.get_secret_value(), (user.nombres, user.apellidos, user.correo, user.nombre_usuario, user.cedula))
        result["no_reutiliza_temporal"] = not is_temporary_password(user, payload.password.get_secret_value())
        if not result["no_reutiliza_temporal"]:
            result.update(porcentaje=0, aceptable=False)
        return result


@router.get("/me")
def me(request: Request, response: Response):
    with transaction(request) as conn:
        current, user = session(conn, request)
        stage = current.etapa if current.etapa == "completa" else next_stage(conn, request, user)
        if stage != current.etapa:
            new_session(conn, request, response, user, stage, old=current)
        output = {"etapa": stage, "usuario": public_user(user)}
        if stage == "completa":
            r = table(request, "auth_recuperacion")
            output["codigos_disponibles"] = conn.scalar(select(func.count()).where(r.c.id_usuario == user.id_usuario, r.c.usado_en.is_(None), r.c.estado_registro == "vigente"))
    return output


@router.post("/mfa/configuracion")
def setup_mfa(request: Request):
    with transaction(request) as conn:
        _, user = session(conn, request, {"configurar_mfa"})
        if not approved(user):
            raise AuthError(403, "Verifique el correo y espere la autorización del administrador")
        identity(conn, request, user.id_usuario, lock=True)
        f, t, settings = factor(conn, request, user.id_usuario, lock=True), table(request, "auth_factor"), request.app.state.auth_settings
        if f and f.confirmado_en:
            raise AuthError(409, "Google Authenticator ya está configurado")
        rate(conn, request, "configurar_mfa", user.id_usuario)
        if f and f.vence_en > now():
            secret = settings.cipher.decrypt(f.secreto_cifrado.encode()).decode()
        else:
            secret = pyotp.random_base32()
            encrypted = settings.cipher.encrypt(secret.encode()).decode()
            conn.execute(insert(t).values(id_usuario=user.id_usuario, secreto_cifrado=encrypted,
                vence_en=now() + timedelta(minutes=10), creado_por=user.id_usuario).on_conflict_do_update(index_elements=["id_usuario"],
                set_={"secreto_cifrado": encrypted, "confirmado_en": None, "ultimo_intervalo": -1,
                      "vence_en": now() + timedelta(minutes=10), "estado_registro": "vigente", "modificado_por": user.id_usuario}))
        uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=user.correo, issuer_name="TacticLens")
        qr = qrcode.make(uri, image_factory=SvgPathImage)
        svg = qr.to_string()
    return {"clave_manual": secret, "uri": uri, "qr": "data:image/svg+xml;base64," + base64.b64encode(svg).decode()}


@router.post("/mfa/confirmar")
def confirm_mfa(payload: SecondFactor, request: Request, response: Response):
    with transaction(request) as conn:
        current, user = session(conn, request, {"configurar_mfa"})
        if not approved(user):
            raise AuthError(403, "La cuenta no está autorizada")
        identity(conn, request, user.id_usuario, lock=True)
        settings = request.app.state.auth_settings
        rate(conn, request, "confirmar_mfa", user.id_usuario, account_limit=settings.max_attempts)
        f = factor(conn, request, user.id_usuario, lock=True)
        if not f or f.confirmado_en or f.vence_en <= now() or payload.recuperacion:
            raise AuthError(400, "Reinicie la configuración de Google Authenticator")
        secret = settings.cipher.decrypt(f.secreto_cifrado.encode()).decode()
        interval = matching_interval(secret, payload.codigo.get_secret_value(), f.ultimo_intervalo)
        if interval is None:
            audit(conn, request, "mfa_configuracion_rechazada", user.id_usuario)
            raise AuthError(400, "Código de Google Authenticator inválido")
        conn.execute(table(request, "auth_factor").update().where(table(request, "auth_factor").c.id_usuario == user.id_usuario).values(confirmado_en=now(), ultimo_intervalo=interval, modificado_por=user.id_usuario))
        codes = replace_recovery_codes(conn, request, user.id_usuario)
        new_session(conn, request, response, user, "completa", old=current)
        audit(conn, request, "mfa_configurado", user.id_usuario, actor=user.id_usuario)
        audit(conn, request, "login_exitoso", user.id_usuario, actor=user.id_usuario)
    return {"etapa": "completa", "codigos_recuperacion": codes}


@router.post("/mfa/verificar")
def verify_mfa(payload: SecondFactor, request: Request, response: Response):
    with transaction(request) as conn:
        current, user = session(conn, request, {"mfa"})
        if not approved(user):
            raise AuthError(403, "La cuenta no está autorizada")
        verify_second_factor(conn, request, user, payload.codigo.get_secret_value(), payload.recuperacion)
        new_session(conn, request, response, user, "completa", old=current)
        audit(conn, request, "login_exitoso", user.id_usuario, actor=user.id_usuario)
    return {"etapa": "completa"}


@router.post("/mfa/codigos")
def regenerate_codes(payload: Reauthentication, request: Request):
    with transaction(request) as conn:
        _, user = session(conn, request, {"completa"})
        reauthenticate(conn, request, user, payload)
        codes = replace_recovery_codes(conn, request, user.id_usuario)
        audit(conn, request, "codigos_recuperacion_regenerados", user.id_usuario, actor=user.id_usuario)
    return {"codigos_recuperacion": codes}


@router.post("/password/solicitar", status_code=202)
def request_password(payload: EmailPayload, request: Request, background: BackgroundTasks):
    user, message = None, None
    with transaction(request) as conn:
        rate(conn, request, "solicitar_password", payload.correo, account_limit=5, ip_limit=20)
        u = table(request, "usuario")
        user_id = conn.scalar(select(u.c.id_usuario).where(u.c.correo == payload.correo))
        user = identity(conn, request, user_id) if user_id else None
        if approved(user):
            message = issue_reset(conn, request, user)
    if message:
        # Receipt contains no link/token. SMTP latency must not distinguish public responses.
        background.add_task(notify, request, user.id_usuario, message)
    return GENERIC_RECOVERY


@router.post("/password/restablecer")
def reset_password(payload: PasswordReset, request: Request):
    with transaction(request) as conn:
        from .recovery import validated_token
        settings, t = request.app.state.auth_settings, table(request, "auth_token")
        rate(conn, request, "restablecer_password", fingerprint(settings, "password", payload.token.get_secret_value()), account_limit=5)
        user, record, recovery = validated_token(conn, request, payload.token.get_secret_value())
        validate_new_password(payload.password.get_secret_value(), (user.nombres, user.apellidos, user.correo, user.nombre_usuario, user.cedula), user=user)
        conn.execute(t.update().where(t.c.id_usuario == user.id_usuario, t.c.proposito == "password", t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        u = table(request, "usuario")
        conn.execute(u.update().where(u.c.id_usuario == user.id_usuario).values(password_hash=PASSWORDS.hash(payload.password.get_secret_value()),
            password_cambio_obligatorio=False, password_temporal_vence_en=None, modificado_por=user.id_usuario))
        q = table(request, "auth_solicitud_password")
        conn.execute(q.update().where(q.c.id_solicitud == recovery.id_solicitud).values(
            estado="completada", completado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        from .recovery import cancel_requests
        cancel_requests(conn, request, user.id_usuario)
        revoke(conn, request, user.id_usuario)
        audit(conn, request, "password_restablecida", user.id_usuario, actor=user.id_usuario,
              request_id=str(recovery.id_solicitud), resultado="completada")
    notify(request, user.id_usuario, (user.correo, "Contraseña restablecida", "Se restableció su contraseña y se cerraron sus sesiones. Google Authenticator permanece activo."))
    return {"mensaje": "Contraseña actualizada. Inicie sesión y complete Google Authenticator."}


@router.post("/password/cambiar")
def change_password(payload: PasswordChange, request: Request, response: Response):
    with transaction(request) as conn:
        _, user = session(conn, request, {"completa"})
        reauthenticate(conn, request, user, payload)
        validate_new_password(payload.nueva_password.get_secret_value(), (user.correo, user.nombres, user.apellidos, user.nombre_usuario, user.cedula), user=user)
        u = table(request, "usuario")
        conn.execute(u.update().where(u.c.id_usuario == user.id_usuario).values(password_hash=PASSWORDS.hash(payload.nueva_password.get_secret_value()), modificado_por=user.id_usuario))
        tokens = table(request, "auth_token")
        conn.execute(tokens.update().where(tokens.c.id_usuario == user.id_usuario, tokens.c.proposito == "password", tokens.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        from .recovery import cancel_requests
        cancel_requests(conn, request, user.id_usuario)
        revoke(conn, request, user.id_usuario)
        audit(conn, request, "password_cambiada", user.id_usuario, actor=user.id_usuario)
        response.delete_cookie(SESSION_COOKIE, path="/api")
    notify(request, user.id_usuario, (user.correo, "Contraseña actualizada", "Se cambió su contraseña y se cerraron todas sus sesiones. Google Authenticator permanece activo."))
    return {"mensaje": "Contraseña actualizada. Inicie sesión nuevamente."}


@router.post("/logout")
def logout(request: Request, response: Response):
    with transaction(request) as conn:
        current, user = session(conn, request)
        t = table(request, "auth_sesion")
        conn.execute(t.update().where(t.c.id_sesion == current.id_sesion).values(revocado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        audit(conn, request, "logout", user.id_usuario, actor=user.id_usuario)
    response.delete_cookie(SESSION_COOKIE, path="/api")
    return {"mensaje": "Sesión cerrada"}


@router.post("/sesiones/revocar")
def revoke_all(payload: Reauthentication, request: Request, response: Response):
    with transaction(request) as conn:
        _, user = session(conn, request, {"completa"})
        reauthenticate(conn, request, user, payload)
        revoke(conn, request, user.id_usuario)
        audit(conn, request, "sesiones_revocadas", user.id_usuario, actor=user.id_usuario)
    response.delete_cookie(SESSION_COOKIE, path="/api")
    return {"mensaje": "Todas las sesiones fueron cerradas"}


@router.get("/admin/roles")
def roles(request: Request):
    with transaction(request) as conn:
        require_admin(conn, request)
        r = table(request, "rol")
        return [dict(row) for row in conn.execute(select(r.c.codigo, r.c.nombre).where(r.c.activo.is_(True), r.c.codigo.in_(["administrador", "analista"]))).mappings()]


@router.get("/admin/usuarios")
def users(request: Request, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
          estado: Literal["pendiente", "aprobado", "activo", "rechazado", "suspendido", "bloqueado"] | None = None,
          q: str = Query("", max_length=120), rol: Literal["administrador", "analista"] | None = None,
          orden: Literal["registro", "nombre", "ultimo_acceso", "actividad"] = "registro",
          direccion: Literal["asc", "desc"] = "desc"):
    from .administration import user_accounts
    with transaction(request) as conn:
        require_admin(conn, request)
        return user_accounts(conn, request, limit, offset, estado, q, rol, orden, direccion)


@router.patch("/admin/usuarios/{user_id}")
def update_user(user_id: UUID, payload: UserUpdate, request: Request):
    from .recovery import cancel_requests, create_request, send_approved_link
    link_delivered = None
    with transaction(request) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
        _, actor = require_admin(conn, request)
        target = identity(conn, request, user_id, lock=True)
        if not target:
            raise AuthError(404, "Usuario no encontrado")
        if user_id == actor.id_usuario:
            raise AuthError(403, "Otro administrador debe gestionar su rol y estado")
        if payload.rechazar and target.autorizacion != "pendiente":
            raise AuthError(409, "Solo se rechazan solicitudes pendientes")
        if payload.aprobar and target.autorizacion == "aprobado":
            raise AuthError(409, "La cuenta ya fue autorizada; use una acción de estado")
        if payload.accion and target.autorizacion != "aprobado":
            raise AuthError(409, "Solo se cambia el estado general de cuentas autorizadas")
        if payload.aprobar and payload.activo and target.autorizacion == "pendiente":
            if payload.recuperacion:
                raise AuthError(400, "Confirme la aprobación con el código actual de su Google Authenticator")
            verify_second_factor(conn, request, actor, payload.codigo.get_secret_value())
        else:
            if payload.password is None:
                raise AuthError(422, "Esta operación requiere su contraseña de administrador")
            reauthenticate(conn, request, actor, payload)
        u, r = table(request, "usuario"), table(request, "rol")
        action = payload.accion or ("reactivar" if payload.activo and not target.activo and target.autorizacion == "aprobado" else "suspender" if not payload.activo and target.activo and not payload.rechazar else None)
        enabled = False if action in {"suspender", "bloquear"} else True if action == "reactivar" else payload.activo
        if action == "reactivar" and target.activo and not target.restriccion_acceso:
            raise AuthError(409, "La cuenta ya está activa")
        if target.rol == "administrador" and target.activo and (not enabled or payload.rol != "administrador"):
            count = conn.scalar(select(func.count()).select_from(u.join(r, u.c.id_rol == r.c.id_rol)).where(
                r.c.codigo == "administrador", u.c.activo.is_(True), u.c.autorizacion == "aprobado", u.c.restriccion_acceso.is_(None)))
            if count <= 1:
                raise AuthError(409, "Debe conservarse al menos un administrador habilitado")
        role_id = conn.scalar(select(r.c.id_rol).where(r.c.codigo == payload.rol, r.c.activo.is_(True)))
        if role_id is None:
            raise AuthError(400, "Rol no disponible")
        values = {"id_rol":role_id, "activo":enabled, "desactivado_en":None if enabled else now(), "modificado_por":actor.id_usuario}
        if action in {"suspender", "bloquear"}:
            if not payload.motivo or len(payload.motivo.strip()) < 10:
                raise AuthError(422, "Indique un motivo de al menos diez caracteres")
            values.update(restriccion_acceso="bloqueado" if action == "bloquear" else "suspendido",
                          motivo_restriccion=payload.motivo.strip(), restriccion_por=actor.id_usuario, restriccion_en=now())
        if action == "reactivar" or payload.aprobar:
            values.update(restriccion_acceso=None, motivo_restriccion=None, restriccion_por=None, restriccion_en=None)
        if payload.aprobar:
            if not target.correo_verificado_en:
                raise AuthError(409, "El usuario debe verificar primero su correo")
            values.update(autorizacion="aprobado", autorizado_por=actor.id_usuario, autorizado_en=now(),
                          rechazado_por=None, rechazado_en=None, motivo_rechazo=None)
            audit(conn, request, "cuenta_autorizada", user_id, actor.id_usuario, resultado="aprobada")
        if payload.rechazar:
            values.update(autorizacion="rechazado", activo=False, desactivado_en=now(),
                          rechazado_por=actor.id_usuario, rechazado_en=now(), motivo_rechazo=payload.motivo_rechazo.strip())
            audit(conn, request, "cuenta_rechazada", user_id, actor.id_usuario, reason=payload.motivo_rechazo.strip(), resultado="rechazada")
        conn.execute(u.update().where(u.c.id_usuario == user_id).values(**values))
        revoke(conn, request, user_id, actor.id_usuario)
        if not payload.aprobar:
            cancel_requests(conn, request, user_id, actor.id_usuario)
        if action:
            kind = {"bloquear":"cuenta_bloqueada", "suspender":"cuenta_suspendida", "reactivar":"cuenta_reactivada"}[action]
            audit(conn, request, kind, user_id, actor.id_usuario, reason=payload.motivo.strip() if payload.motivo else "reactivacion", resultado="aplicada")
        audit(conn, request, "cuenta_estado_actualizado", user_id, actor.id_usuario, reason="habilitada" if values["activo"] else "suspendida")
        if target.rol != payload.rol:
            audit(conn, request, "rol_cambiado", user_id, actor.id_usuario, rol=payload.rol, resultado="aplicado")
        if payload.aprobar and target.password_cambio_obligatorio:
            updated = identity(conn, request, user_id)
            record = create_request(conn, request, updated, origin="alta")
            if record:
                link_delivered = send_approved_link(conn, request, updated, record, actor.id_usuario, "Autorización administrativa del registro")
    title = "Solicitud de cuenta rechazada" if payload.rechazar else "Solicitud de cuenta autorizada" if payload.aprobar else {"suspender":"Cuenta suspendida", "bloquear":"Cuenta bloqueada", "reactivar":"Cuenta reactivada"}.get(action, "Rol o estado de cuenta actualizado")
    delivered = False
    if link_delivered is None and target.correo_verificado_en:
        delivered = notify(request, user_id, (target.correo, title,
            title + ". Un administrador actualizó su cuenta. Sus sesiones previas fueron revocadas. "
            "La recuperación de contraseña no permite eludir restricciones. Contacte al administrador por un canal conocido si necesita una revisión."))
    return {"mensaje":"Cuenta actualizada; sus sesiones anteriores fueron revocadas", "notificacion_enviada":bool(delivered),
            "notificacion_estado":"pendiente" if link_delivered else "enviada" if delivered else "no_confirmada"}


@router.post("/admin/usuarios/{user_id}/mfa/restablecer")
def admin_reset_mfa(user_id: UUID, payload: MfaReset, request: Request):
    with transaction(request) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
        _, actor = require_admin(conn, request)
        if user_id == actor.id_usuario:
            raise AuthError(403,"No puede restablecer unilateralmente su propio MFA")
        target = identity(conn,request,user_id,lock=True)
        if not target:
            raise AuthError(404,"Usuario no encontrado")
        reauthenticate(conn,request,actor,payload)
        f = table(request,"auth_factor")
        conn.execute(f.update().where(f.c.id_usuario==user_id).values(secreto_cifrado=None,confirmado_en=None,estado_registro="inactivo",ultimo_intervalo=-1,modificado_por=actor.id_usuario))
        c = table(request,"auth_recuperacion")
        conn.execute(c.update().where(c.c.id_usuario==user_id,c.c.usado_en.is_(None)).values(usado_en=now(),estado_registro="inactivo",modificado_por=actor.id_usuario))
        revoke(conn,request,user_id,actor.id_usuario)
        audit(conn,request,"mfa_restablecido_administrativamente",user_id,actor.id_usuario,
            referencia_hash=fingerprint(request.app.state.auth_settings,"verificacion_identidad",payload.referencia_verificacion))
    notify(request,user_id,(target.correo,"Google Authenticator restablecido","Un administrador restableció su segundo factor tras verificar su identidad. Se cerraron todas sus sesiones. Debe volver a vincular Google Authenticator antes de acceder."))
    return {"mensaje":"MFA restablecido. Se notificó al titular y se revocaron sus sesiones."}


@router.post("/mfa/reemplazar")
def replace_own_mfa(payload: Reauthentication, request: Request, response: Response):
    with transaction(request) as conn:
        _, user = session(conn, request, {"completa"})
        reauthenticate(conn, request, user, payload)
        f, c = table(request, "auth_factor"), table(request, "auth_recuperacion")
        conn.execute(f.update().where(f.c.id_usuario == user.id_usuario).values(
            secreto_cifrado=None, confirmado_en=None, estado_registro="inactivo", ultimo_intervalo=-1, modificado_por=user.id_usuario))
        conn.execute(c.update().where(c.c.id_usuario == user.id_usuario, c.c.usado_en.is_(None)).values(
            usado_en=now(), estado_registro="inactivo", modificado_por=user.id_usuario))
        revoke(conn, request, user.id_usuario)
        # This is only an enrollment challenge, never an MFA bypass or full session.
        new_session(conn, request, response, user, "configurar_mfa")
        audit(conn, request, "mfa_reemplazo_iniciado", user.id_usuario, actor=user.id_usuario)
    notify(request, user.id_usuario, (user.correo, "Cambio de autenticador iniciado",
        "Se inició el reemplazo de Google Authenticator después de verificar su contraseña y segundo factor. Debe confirmar la nueva vinculación para recuperar el acceso a los módulos."))
    return {"etapa": "configurar_mfa"}


@router.get("/admin/auditoria")
def security_audit(request: Request, limit: int = Query(50,ge=1,le=100), offset: int = Query(0,ge=0),
                   usuario: UUID | None = None, tipo: str = Query("",max_length=80)):
    with transaction(request) as conn:
        require_admin(conn,request)
        t, u = table(request,"auth_auditoria"), table(request,"usuario")
        actor, subject = u.alias("actor"), u.alias("afectado")
        statement = select(t.c.id_auditoria,t.c.id_usuario,t.c.actor_id,t.c.tipo,t.c.fecha_evento,t.c.metadatos,
            actor.c.nombre.label("administrador"),subject.c.nombre.label("usuario")).outerjoin(actor,t.c.actor_id==actor.c.id_usuario).outerjoin(subject,t.c.id_usuario==subject.c.id_usuario)
        if usuario:
            statement = statement.where(t.c.id_usuario==usuario)
        if tipo:
            statement = statement.where(t.c.tipo==tipo)
        rows=conn.execute(statement.order_by(t.c.fecha_evento.desc(),t.c.id_auditoria.desc()).limit(limit).offset(offset)).mappings()
        return [{**dict(row), "metadatos":redact({k:v for k,v in row.metadatos.items()
                 if k in {"reason","rol","resultado","request_id"}})} for row in rows]
