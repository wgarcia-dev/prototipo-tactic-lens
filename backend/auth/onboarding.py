"""Email ownership before signup, bound to an opaque browser cookie."""
from datetime import timedelta
import hmac
import re
import secrets
from uuid import uuid4

from fastapi import APIRouter, Request, Response
from sqlalchemy import select, text

from .config import REGISTRATION_COOKIE
from .schemas import EmailCode, EmailPayload
from .security import fingerprint, now, opaque_token
from .service import notify
from .store import AuthError, audit, rate, table, transaction

router = APIRouter(prefix="/api/auth/registro/correo", tags=["Registro"])


def binding(request):
    raw = request.cookies.get(REGISTRATION_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", raw):
        return None
    return fingerprint(request.app.state.auth_settings, "registro_navegador", raw)


def browser_lock(conn, hashed):
    conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": int(hashed[:15], 16)})


def pending_proof(conn, request, lock=False):
    hashed = binding(request)
    if not hashed:
        return None
    if lock:
        browser_lock(conn, hashed)
    t = table(request, "auth_token")
    query = select(t).where(t.c.proposito == "pre_registro", t.c.navegador_hash == hashed,
                           t.c.usado_en.is_(None), t.c.estado_registro == "vigente")
    query = query.order_by(t.c.creado_en.desc(), t.c.id_token.desc()).limit(1)
    return conn.execute(query.with_for_update() if lock else query).mappings().first()


def set_binding_cookie(request, response, raw, seconds):
    response.set_cookie(REGISTRATION_COOKIE, raw, max_age=seconds, httponly=True,
        secure=request.app.state.auth_settings.secure_cookie, samesite="strict", path="/api/auth")


@router.get("")
def email_status(request: Request):
    with transaction(request) as conn:
        row = pending_proof(conn, request)
        valid = bool(row and row.vence_en > now())
        return {"correo": row.correo if row else "", "enviado": valid,
                "verificado": bool(valid and row.verificado_en), "caducado": bool(row and not valid)}


@router.post("/enviar", status_code=202)
def send_code(payload: EmailPayload, request: Request, response: Response):
    settings = request.app.state.auth_settings
    with transaction(request) as conn:
        rate(conn, request, "registro_correo_enviar", payload.correo, account_limit=5, ip_limit=20)
        t = table(request, "auth_token")
        email_hash = fingerprint(settings, "registro_correo", payload.correo)
        browser_lock(conn, email_hash)
        last = conn.execute(select(t.c.creado_en).where(t.c.proposito == "pre_registro", t.c.correo == payload.correo)
                            .order_by(t.c.creado_en.desc()).limit(1)).scalar_one_or_none()
        if last and last > now() - timedelta(seconds=settings.resend_seconds):
            raise AuthError(429, f"Espere {settings.resend_seconds} segundos entre envíos.", headers={"Retry-After": str(settings.resend_seconds)})
        hashed = binding(request)
        raw = request.cookies.get(REGISTRATION_COOKIE, "") if hashed else opaque_token()
        hashed = fingerprint(settings, "registro_navegador", raw)
        browser_lock(conn, hashed)
        conn.execute(t.update().where(t.c.proposito == "pre_registro", t.c.navegador_hash == hashed,
            t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo"))
        code, token_id = f"{secrets.randbelow(1_000_000):06d}", uuid4()
        conn.execute(t.insert().values(id_token=token_id, proposito="pre_registro", correo=payload.correo,
            navegador_hash=hashed, token_hash=fingerprint(settings, "pre_registro:" + str(token_id), code),
            vence_en=now()+timedelta(seconds=settings.email_seconds)))
        set_binding_cookie(request, response, raw, settings.email_seconds+settings.registration_proof_seconds)
    delivered = notify(request, None, (payload.correo, "Verifique su correo para registrarse",
        f"Su código de verificación es: {code}\n\nCaduca en {settings.email_seconds // 60} minutos y solo puede usarse una vez. Escríbalo en el formulario de registro que tiene abierto. Si ya tiene cuenta, utilice el inicio de sesión o la recuperación de contraseña."))
    if not delivered:
        raise AuthError(503, "No se pudo entregar el código. Revise la configuración del correo o el buzón local y vuelva a solicitarlo después del intervalo de reenvío.")
    return {"mensaje": "Código enviado. Revise su correo o el buzón local de desarrollo.", "reenviar_en": settings.resend_seconds}


@router.post("/verificar")
def verify_code(payload: EmailCode, request: Request, response: Response):
    with transaction(request) as conn:
        settings, t = request.app.state.auth_settings, table(request, "auth_token")
        rate(conn, request, "registro_correo_verificar", payload.correo, account_limit=settings.max_attempts)
        row = pending_proof(conn, request, lock=True)
        if not row or row.correo != payload.correo or row.vence_en <= now() or row.verificado_en or row.intentos >= settings.max_attempts:
            raise AuthError(400, "Código inválido, vencido o ya utilizado. Solicite uno nuevo.")
        expected = fingerprint(settings, "pre_registro:" + str(row.id_token), payload.codigo.get_secret_value())
        if not hmac.compare_digest(row.token_hash, expected):
            attempts = row.intentos + 1
            conn.execute(t.update().where(t.c.id_token == row.id_token).values(intentos=attempts,
                usado_en=now() if attempts >= settings.max_attempts else None))
            audit(conn, request, "registro_correo_rechazado", reason="codigo_incorrecto")
            raise AuthError(400, "Código incorrecto. Revise los seis dígitos.")
        conn.execute(t.update().where(t.c.id_token == row.id_token).values(verificado_en=now(),
            vence_en=now()+timedelta(seconds=settings.registration_proof_seconds)))
        set_binding_cookie(request, response, request.cookies[REGISTRATION_COOKIE], settings.registration_proof_seconds)
        audit(conn, request, "registro_correo_verificado")
    return {"correo": payload.correo, "verificado": True, "mensaje": "Correo verificado. Ya puede enviar su solicitud."}


@router.post("/editar")
def edit_email(request: Request, response: Response):
    with transaction(request) as conn:
        rate(conn, request, "registro_correo_editar", ip_limit=40)
        hashed = binding(request)
        if hashed:
            browser_lock(conn, hashed)
            t = table(request, "auth_token")
            conn.execute(t.update().where(t.c.proposito == "pre_registro", t.c.navegador_hash == hashed,
                t.c.usado_en.is_(None)).values(usado_en=now(), estado_registro="inactivo"))
    response.delete_cookie(REGISTRATION_COOKIE, path="/api/auth")
    return {"mensaje": "Puede editar el correo. Debe verificar de nuevo la dirección que utilice."}
