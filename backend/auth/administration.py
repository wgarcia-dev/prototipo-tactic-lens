"""Account/session supervision over the existing opaque session store."""
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Query, Request
from sqlalchemy import and_, case, func, or_, select, text

from .schemas import AdministrativeAction
from .security import now
from .service import reauthenticate
from .store import AuthError, audit, identity, require_admin, revoke, session, table, transaction

router = APIRouter(prefix="/api/auth", tags=["Administración"])


def account_state(u):
    return case((u.c.autorizacion == "pendiente", "pendiente"), (u.c.autorizacion == "rechazado", "rechazado"),
        (u.c.restriccion_acceso == "bloqueado", "bloqueado"), (u.c.activo.is_(False), "suspendido"), else_="activo")


def live_session(s, u, settings, role, factor):
    enabled_role = select(role.c.id_rol).where(role.c.id_rol == u.c.id_rol, role.c.activo.is_(True)).correlate(u).exists()
    confirmed_factor = select(factor.c.id_usuario).where(factor.c.id_usuario == u.c.id_usuario,
        factor.c.confirmado_en.is_not(None), factor.c.estado_registro == "vigente").correlate(u).exists()
    return and_(s.c.etapa == "completa", s.c.revocado_en.is_(None), s.c.vence_en > now(),
        s.c.ultima_actividad > now() - timedelta(seconds=settings.idle_seconds), u.c.activo.is_(True),
        u.c.autorizacion == "aprobado", u.c.restriccion_acceso.is_(None), u.c.correo_verificado_en.is_not(None),
        u.c.password_cambio_obligatorio.is_(False), enabled_role, confirmed_factor)


def user_accounts(conn, request, limit, offset, estado=None, q="", rol=None, orden="registro", direccion="desc"):
    u, r, f, s = (table(request, name) for name in ("usuario", "rol", "auth_factor", "auth_sesion"))
    settings = request.app.state.auth_settings
    valid = live_session(s, u, settings, r, f)
    active = select(func.count()).select_from(s).where(s.c.id_usuario == u.c.id_usuario, valid).correlate(u).scalar_subquery()
    recent = select(func.count()).select_from(s).where(s.c.id_usuario == u.c.id_usuario, valid,
        s.c.ultima_actividad > now() - timedelta(seconds=settings.recent_activity_seconds)).correlate(u).scalar_subquery()
    activity = select(func.max(s.c.ultima_actividad)).where(s.c.id_usuario == u.c.id_usuario,
        s.c.etapa == "completa").correlate(u).scalar_subquery()
    state = account_state(u)
    statement = select(u.c.id_usuario, u.c.nombres, u.c.apellidos, u.c.nombre_usuario, u.c.correo, u.c.activo,
        u.c.autorizacion, u.c.correo_verificado_en, u.c.creado_en, u.c.rechazado_en, u.c.motivo_rechazo,
        u.c.password_cambio_obligatorio, u.c.restriccion_acceso, u.c.motivo_restriccion, u.c.ultimo_acceso_en,
        r.c.codigo.label("rol"), f.c.confirmado_en.label("mfa_confirmado_en"), state.label("estado_cuenta"),
        activity.label("ultima_actividad"), active.label("sesiones_activas"),
        case((recent > 0, "recientemente_activo"), (active > 0, "inactivo"), else_="desconectado").label("conexion")
    ).join(r, u.c.id_rol == r.c.id_rol).outerjoin(f, f.c.id_usuario == u.c.id_usuario)
    if estado:
        statement = statement.where(state == ("activo" if estado == "aprobado" else estado))
    if q.strip():
        pattern = "%" + q.strip() + "%"
        statement = statement.where(or_(u.c.nombre.ilike(pattern), u.c.correo.ilike(pattern), u.c.nombre_usuario.ilike(pattern)))
    if rol:
        statement = statement.where(r.c.codigo == rol)
    order = {"registro": u.c.creado_en, "nombre": u.c.nombre, "ultimo_acceso": u.c.ultimo_acceso_en,
             "actividad": activity}.get(orden, u.c.creado_en)
    order = order.asc().nulls_last() if direccion == "asc" else order.desc().nulls_last()
    return [dict(row) for row in conn.execute(statement.order_by(order, u.c.id_usuario).limit(limit).offset(offset)).mappings()]


@router.post("/actividad", status_code=204)
def activity(request: Request):
    with transaction(request) as conn:
        session(conn, request, {"completa"})


@router.get("/admin/sesiones")
def sessions(request: Request, usuario: UUID | None = None, estado: str | None = None,
             limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
    with transaction(request) as conn:
        require_admin(conn, request)
        s, u = table(request, "auth_sesion"), table(request, "usuario")
        settings = request.app.state.auth_settings
        valid = live_session(s, u, settings, table(request, "rol"), table(request, "auth_factor"))
        status = case((s.c.revocado_en.is_not(None), "revocada"),
            ((s.c.vence_en <= now()) | (s.c.ultima_actividad <= now() - timedelta(seconds=settings.idle_seconds)), "expirada"),
            (s.c.etapa != "completa", "incompleta"), (valid, "vigente"), else_="revocada")
        activity_state = case((valid & (s.c.ultima_actividad > now() - timedelta(seconds=settings.recent_activity_seconds)), "recientemente_activo"),
                              (valid, "inactivo"), else_="desconectado")
        statement = select(s.c.id_sesion, s.c.id_usuario, u.c.nombre.label("usuario"), u.c.correo,
            s.c.mfa_en.label("inicio"), s.c.creado_en, s.c.ultima_actividad, s.c.vence_en, s.c.revocado_en,
            s.c.dispositivo, status.label("estado"), activity_state.label("actividad"),
        ).join(u, s.c.id_usuario == u.c.id_usuario)
        if usuario:
            statement = statement.where(s.c.id_usuario == usuario)
        if estado:
            statement = statement.where(status == estado)
        return [dict(row) for row in conn.execute(statement.order_by(s.c.ultima_actividad.desc(), s.c.id_sesion).limit(limit).offset(offset)).mappings()]


@router.post("/admin/sesiones/{session_id}/revocar")
def revoke_session(session_id: UUID, payload: AdministrativeAction, request: Request):
    with transaction(request) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
        current, actor = require_admin(conn, request)
        s = table(request, "auth_sesion")
        row = conn.execute(select(s).where(s.c.id_sesion == session_id)).mappings().first()
        if not row:
            raise AuthError(404, "Sesión no encontrada")
        if current.id_sesion == session_id:
            raise AuthError(403, "Use Cerrar sesión para finalizar su sesión actual")
        identity(conn, request, row.id_usuario, lock=True)
        reauthenticate(conn, request, actor, payload)
        result = conn.execute(s.update().where(s.c.id_sesion == session_id, s.c.revocado_en.is_(None)).values(
            revocado_en=now(), estado_registro="inactivo", modificado_por=actor.id_usuario))
        if not result.rowcount:
            raise AuthError(409, "La sesión ya fue revocada")
        audit(conn, request, "sesion_revocada_administrativamente", row.id_usuario, actor.id_usuario,
              session_id=str(session_id), reason=payload.motivo.strip(), resultado="revocada")
    return {"mensaje": "Sesión revocada"}


@router.post("/admin/usuarios/{user_id}/sesiones/revocar")
def revoke_user_sessions(user_id: UUID, payload: AdministrativeAction, request: Request):
    with transaction(request) as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
        _, actor = require_admin(conn, request)
        if actor.id_usuario == user_id:
            raise AuthError(403, "Use Seguridad de mi cuenta para cerrar sus propias sesiones")
        if not identity(conn, request, user_id, lock=True):
            raise AuthError(404, "Usuario no encontrado")
        reauthenticate(conn, request, actor, payload)
        revoke(conn, request, user_id, actor.id_usuario)
        audit(conn, request, "sesiones_revocadas_administrativamente", user_id, actor.id_usuario,
              reason=payload.motivo.strip(), resultado="revocadas")
    return {"mensaje": "Todas las sesiones del usuario fueron revocadas"}
