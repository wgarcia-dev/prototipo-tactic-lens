"""Small Core helpers: durable attempts, row locks, authorization and audit."""
from contextlib import contextmanager
from datetime import timedelta
import hmac

from fastapi import HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert

from .config import SESSION_COOKIE
from .security import fingerprint, now, opaque_token


class AuthError(HTTPException):
    """Expected denial. Persist rate-limit counters and security audit, not secrets."""


@contextmanager
def transaction(request):
    denial = None
    with request.app.state.engine.begin() as conn:
        try:
            yield conn
        except AuthError as exc:
            # Expected denials commit failed-attempt counters. Unexpected errors roll back.
            denial = exc
    if denial:
        raise denial


def table(request, name):
    return request.app.state.tables[name]


def ip_hash(request):
    return fingerprint(request.app.state.auth_settings, "ip", request.client.host if request.client else "unknown")


def audit(conn, request, kind, user_id=None, actor=None, **metadata):
    allowed = {"reason", "rol", "referencia_hash", "session_id"}
    if set(metadata) - allowed:
        raise ValueError("Metadatos de auditoría no permitidos")
    conn.execute(table(request, "auth_auditoria").insert().values(
        id_usuario=user_id, actor_id=actor, tipo=kind,
        metadatos={"ip_hash": ip_hash(request), **metadata}, creado_por=actor,
    ))


def rate(conn, request, scope, account=None, account_limit=10, ip_limit=40):
    t = table(request, "auth_limite")
    moment = now()
    identities = [("ip:" + ip_hash(request), ip_limit)]
    if account:
        identities.append(("cuenta:" + str(account), account_limit))
    for identity, maximum in identities:
        key = fingerprint(request.app.state.auth_settings, "limite:" + scope, identity)
        expired = t.c.ventana < moment - timedelta(minutes=15)
        stmt = insert(t).values(clave=key, ventana=moment, intentos=1).on_conflict_do_update(
            index_elements=["clave"], set_={"intentos": case((expired, 1), else_=t.c.intentos + 1),
                                           "ventana": case((expired, moment), else_=t.c.ventana)})
        count = conn.scalar(stmt.returning(t.c.intentos))
        if count > maximum:
            raise AuthError(429, "Demasiados intentos. Espere quince minutos antes de volver a intentar.", headers={"Retry-After": "900"})


def identity(conn, request, user_id, lock=False):
    u, r = table(request, "usuario"), table(request, "rol")
    stmt = select(u, r.c.codigo.label("rol"), r.c.activo.label("rol_activo")).join(r, u.c.id_rol == r.c.id_rol).where(u.c.id_usuario == user_id)
    if lock:
        stmt = stmt.with_for_update(of=u)
    return conn.execute(stmt).mappings().first()


def eligible(user):
    return bool(user and user.activo and user.rol_activo and user.autorizacion != "rechazado" and user.rol in {"administrador", "analista"})


def approved(user):
    return eligible(user) and user.correo_verificado_en is not None and user.autorizacion == "aprobado"


def factor(conn, request, user_id, lock=False):
    t = table(request, "auth_factor")
    stmt = select(t).where(t.c.id_usuario == user_id, t.c.estado_registro == "vigente")
    return conn.execute(stmt.with_for_update() if lock else stmt).mappings().first()


def next_stage(conn, request, user):
    if user.correo_verificado_en is None:
        return "correo"
    if user.password_cambio_obligatorio:
        return "crear_password"
    if user.autorizacion != "aprobado":
        return "aprobacion"
    existing = factor(conn, request, user.id_usuario)
    return "mfa" if existing and existing.confirmado_en else "configurar_mfa"


def revoke(conn, request, user_id, actor=None):
    t = table(request, "auth_sesion")
    conn.execute(t.update().where(t.c.id_usuario == user_id, t.c.revocado_en.is_(None)).values(revocado_en=now(), estado_registro="inactivo", modificado_por=actor or user_id))


def set_session_cookie(request, response, value, seconds):
    response.set_cookie(SESSION_COOKIE, value, max_age=seconds, httponly=True,
                        secure=request.app.state.auth_settings.secure_cookie, samesite="strict", path="/api")


def new_session(conn, request, response, user, stage, old=None):
    settings, t = request.app.state.auth_settings, table(request, "auth_sesion")
    if old:
        conn.execute(t.update().where(t.c.id_sesion == old.id_sesion).values(revocado_en=now(), estado_registro="inactivo"))
    value = opaque_token()
    seconds = settings.session_seconds if stage == "completa" else settings.challenge_seconds
    conn.execute(t.insert().values(
        id_usuario=user.id_usuario, token_hash=fingerprint(settings, "sesion", value), etapa=stage,
        primaria_en=now(), mfa_en=now() if stage == "completa" else None,
        vence_en=now() + timedelta(seconds=seconds), ultima_actividad=now(), ip_hash=ip_hash(request), creado_por=user.id_usuario,
    ))
    set_session_cookie(request, response, value, seconds)


def session(conn, request, stages=None, lock=True):
    raw = request.cookies.get(SESSION_COOKIE, "")
    if not raw or len(raw) > 100:
        raise AuthError(401, "Inicie sesión para continuar")
    settings, t = request.app.state.auth_settings, table(request, "auth_sesion")
    stmt = select(t).where(t.c.token_hash == fingerprint(settings, "sesion", raw))
    row = conn.execute(stmt).mappings().first()
    # Consistent lock order: user -> session -> factor/recovery/token.
    # Suspension, password reset and MFA verification serialize on the same user.
    user = identity(conn, request, row.id_usuario, lock=lock) if row else None
    if row and lock:
        row = conn.execute(stmt.with_for_update()).mappings().first()
    moment = now()
    if not row or row.revocado_en or row.vence_en <= moment or row.ultima_actividad <= moment - timedelta(seconds=settings.idle_seconds):
        raise AuthError(401, "La sesión expiró. Inicie sesión nuevamente")
    if not eligible(user):
        raise AuthError(401, "La cuenta no está habilitada")
    if row.etapa == "completa":
        f = factor(conn, request, user.id_usuario)
        if not approved(user) or user.password_cambio_obligatorio or not row.mfa_en or not f or not f.confirmado_en:
            raise AuthError(401, "Complete la verificación de su cuenta")
    if stages and row.etapa not in stages:
        raise AuthError(403, "Complete la verificación requerida antes de acceder")
    # Background dashboard polling must not keep an unattended browser alive.
    if request.method not in {"GET", "HEAD", "OPTIONS"} or request.url.path == "/api/auth/me":
        conn.execute(t.update().where(t.c.id_sesion == row.id_sesion).values(ultima_actividad=moment))
    return row, user


def public_user(user):
    return {"id_usuario": str(user.id_usuario), "nombres": user.nombres or user.nombre,
            "apellidos": user.apellidos or "", "nombre_usuario": user.nombre_usuario,
            "correo": user.correo, "rol": user.rol}


def authorize_request(request):
    with transaction(request) as conn:
        _, user = session(conn, request, {"completa"})
        # Both roles can review and analyze. Manual file imports are administrative.
        if request.url.path == "/api/ingesta/cowrie" and user.rol != "administrador":
            raise AuthError(403, "Esta operación requiere un administrador de seguridad")
        request.state.user = public_user(user)


def require_admin(conn, request):
    current, user = session(conn, request, {"completa"})
    if user.rol != "administrador":
        raise AuthError(403, "Esta operación requiere un administrador de seguridad")
    return current, user


def clear_account_rate(conn, request, scope, account):
    t = table(request, "auth_limite")
    key = fingerprint(request.app.state.auth_settings, "limite:" + scope, "cuenta:" + str(account))
    conn.execute(t.update().where(t.c.clave == key).values(intentos=0))
