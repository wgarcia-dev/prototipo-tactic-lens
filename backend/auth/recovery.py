"""Administratively approved, single-use password links; no plaintext token persistence."""
from datetime import timedelta
import hmac

from fastapi import APIRouter, Query, Request
from sqlalchemy import case, select
from uuid import UUID, uuid4

from .notifications import enqueue, recovery_secret
from .schemas import PasswordToken, RecoveryDecision
from .security import fingerprint, now
from .service import reauthenticate
from .store import (AuthError, approved, audit, identity, rate, require_admin, table, transaction)

router = APIRouter(prefix="/api/auth", tags=["Recuperación supervisada"])
INVALID_LINK = "Enlace inválido, vencido o no disponible"


def displayed_status(q):
    return case(
        ((q.c.estado == "pendiente") & (q.c.vence_en <= now()), "expirada"),
        ((q.c.estado == "aprobada") & (q.c.enlace_vence_en <= now()), "expirada"),
        else_=q.c.estado,
    )


def expire_requests(conn, request, user_id):
    q = table(request, "auth_solicitud_password")
    conn.execute(q.update().where(q.c.id_usuario == user_id,
        ((q.c.estado == "pendiente") & (q.c.vence_en <= now())) |
        ((q.c.estado == "aprobada") & (q.c.enlace_vence_en <= now()))
    ).values(estado="expirada", estado_registro="inactivo"))


def cancel_requests(conn, request, user_id, actor=None):
    q, t = table(request, "auth_solicitud_password"), table(request, "auth_token")
    conn.execute(q.update().where(q.c.id_usuario == user_id, q.c.estado.in_(["pendiente", "aprobada"])).values(
        estado="cancelada", estado_registro="inactivo", modificado_por=actor or user_id))
    conn.execute(t.update().where(t.c.id_usuario == user_id, t.c.proposito == "password", t.c.usado_en.is_(None)).values(
        usado_en=now(), estado_registro="inactivo", modificado_por=actor or user_id))


def create_request(conn, request, user, origin="recuperacion"):
    user = identity(conn, request, user.id_usuario, lock=True)
    if not approved(user):
        return None
    expire_requests(conn, request, user.id_usuario)
    q = table(request, "auth_solicitud_password")
    existing = conn.execute(select(q).where(q.c.id_usuario == user.id_usuario,
        q.c.estado.in_(["pendiente", "aprobada"]))).mappings().first()
    if existing:
        return None
    row = conn.execute(q.insert().values(id_usuario=user.id_usuario, origen=origin,
        vence_en=now() + timedelta(seconds=request.app.state.auth_settings.recovery_request_seconds),
        creado_por=user.id_usuario).returning(q)).mappings().one()
    audit(conn, request, "recuperacion_solicitada", user.id_usuario, request_id=str(row.id_solicitud), resultado="pendiente")
    return row


def send_approved_link(conn, request, user, record, actor, reason):
    """Register approval, token digest and outbox reference atomically."""
    settings = request.app.state.auth_settings
    q, t = table(request, "auth_solicitud_password"), table(request, "auth_token")
    token_id = uuid4()
    token = recovery_secret(settings, record.id_solicitud, token_id)
    expires = now() + timedelta(seconds=settings.reset_seconds)
    conn.execute(t.update().where(t.c.id_usuario == user.id_usuario, t.c.proposito == "password", t.c.usado_en.is_(None)).values(
        usado_en=now(), estado_registro="inactivo"))
    conn.execute(t.insert().values(id_token=token_id, id_usuario=user.id_usuario, id_solicitud=record.id_solicitud,
        proposito="password", token_hash=fingerprint(settings, "password", token), vence_en=expires,
        creado_por=actor))
    conn.execute(q.update().where(q.c.id_solicitud == record.id_solicitud).values(estado="aprobada", resuelto_por=actor,
        resuelto_en=now(), motivo_decision=reason, enlace_vence_en=expires, notificacion_estado="pendiente",
        notificado_en=None, modificado_por=actor))
    reference = audit(conn, request, "recuperacion_aprobada", user.id_usuario, actor,
        request_id=str(record.id_solicitud), reason=reason, resultado="pendiente")
    return enqueue(conn, request, kind="recuperacion_enlace", destination=user.correo, event_id=reference,
                   actor=actor, logical_key=f"recuperacion_enlace:{record.id_solicitud}")


def validated_token(conn, request, raw):
    settings, t, q = request.app.state.auth_settings, table(request, "auth_token"), table(request, "auth_solicitud_password")
    hashed = fingerprint(settings, "password", raw)
    record = conn.execute(select(t).where(t.c.token_hash == hashed, t.c.proposito == "password")).mappings().first()
    if not record or not record.id_solicitud:
        raise AuthError(400, INVALID_LINK)
    user = identity(conn, request, record.id_usuario, lock=True)
    recovery = conn.execute(select(q).where(q.c.id_solicitud == record.id_solicitud).with_for_update()).mappings().first()
    record = conn.execute(select(t).where(t.c.id_token == record.id_token).with_for_update()).mappings().one()
    if (not approved(user) or record.usado_en or record.estado_registro != "vigente" or record.vence_en <= now()
        or not recovery or recovery.estado != "aprobada" or not recovery.enlace_vence_en
        or recovery.enlace_vence_en <= now() or recovery.notificacion_estado not in {"enviada", "en_proceso", "incierto"}
        or not hmac.compare_digest(record.token_hash, hashed)):
        raise AuthError(400, INVALID_LINK)
    return user, record, recovery


@router.post("/password/validar")
def validate_link(payload: PasswordToken, request: Request):
    with transaction(request) as conn:
        rate(conn, request, "validar_enlace", fingerprint(request.app.state.auth_settings, "validar", payload.token.get_secret_value()), account_limit=30)
        _, record, _ = validated_token(conn, request, payload.token.get_secret_value())
        return {"valido": True, "vence_en": record.vence_en}


@router.get("/admin/recuperaciones")
def list_requests(request: Request, estado: str | None = None, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
    with transaction(request) as conn:
        require_admin(conn, request)
        q, u = table(request, "auth_solicitud_password"), table(request, "usuario")
        resolver = u.alias("resolver")
        statement = select(q.c.id_solicitud, q.c.id_usuario, u.c.nombres, u.c.apellidos, u.c.correo, q.c.origen,
            displayed_status(q).label("estado"), q.c.creado_en, q.c.resuelto_en, q.c.resuelto_por,
            resolver.c.nombre.label("administrador"), q.c.enlace_vence_en, q.c.notificacion_estado, q.c.motivo_decision,
            q.c.completado_en).join(u, q.c.id_usuario == u.c.id_usuario).outerjoin(resolver, q.c.resuelto_por == resolver.c.id_usuario)
        if estado:
            statement = statement.where(displayed_status(q) == estado)
        return [dict(row) for row in conn.execute(statement.order_by(q.c.creado_en.desc(), q.c.id_solicitud).limit(limit).offset(offset)).mappings()]


@router.post("/admin/recuperaciones/{request_id}/resolver")
def resolve_request(request_id: UUID, payload: RecoveryDecision, request: Request):
    from sqlalchemy import text
    with transaction(request) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
        _, actor = require_admin(conn, request)
        q = table(request, "auth_solicitud_password")
        row = conn.execute(select(q).where(q.c.id_solicitud == request_id)).mappings().first()
        if not row:
            raise AuthError(404, "Solicitud no encontrada")
        target = identity(conn, request, row.id_usuario, lock=True)
        row = conn.execute(select(q).where(q.c.id_solicitud == request_id).with_for_update()).mappings().one()
        if row.estado != "pendiente":
            raise AuthError(409, "La solicitud ya fue resuelta")
        if row.vence_en <= now():
            expire_requests(conn, request, target.id_usuario)
            raise AuthError(409, "La solicitud expiró")
        if not approved(target):
            raise AuthError(409, "La cuenta no está habilitada para recuperar acceso")
        if actor.id_usuario == target.id_usuario:
            raise AuthError(403, "Otro administrador debe resolver su recuperación")
        reauthenticate(conn, request, actor, payload)
        if payload.decision == "aprobar":
            send_approved_link(conn, request, target, row, actor.id_usuario, payload.motivo.strip())
        else:
            conn.execute(q.update().where(q.c.id_solicitud == request_id).values(estado="rechazada", resuelto_por=actor.id_usuario,
                resuelto_en=now(), motivo_decision=payload.motivo.strip(), estado_registro="inactivo", modificado_por=actor.id_usuario))
            reference = audit(conn, request, "recuperacion_rechazada", target.id_usuario, actor.id_usuario,
                  request_id=str(request_id), reason=payload.motivo.strip(), resultado="rechazada")
            enqueue(conn, request, kind="recuperacion_rechazo", destination=target.correo, event_id=reference,
                    actor=actor.id_usuario, logical_key=f"recuperacion_rechazo:{request_id}")
    return {"mensaje": "Solicitud resuelta", "notificacion_enviada": False, "notificacion_estado": "pendiente"}
