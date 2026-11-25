"""Interactive, offline bootstrap. No public elevation endpoint or default account."""
import asyncio
from getpass import getpass

from fastapi import Request
from pydantic import ValidationError
from sqlalchemy import MetaData, func, select, text

from backend.api import app, lifespan
from backend.auth.schemas import Registration, email
from backend.auth.service import create_account, issue_email_code, notify
from backend.auth.security import DUMMY_HASH, now, verify_password
from backend.auth.store import AuthError, audit, identity, revoke


def ensure_first_admin(conn, request):
    conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
    u, r = request.app.state.tables["usuario"], request.app.state.tables["rol"]
    if conn.scalar(select(func.count()).select_from(u.join(r, u.c.id_rol == r.c.id_rol)).where(r.c.codigo == "administrador")):
        raise AuthError(409, "Ya existe un administrador. Use la administración de usuarios para autorizar más cuentas.")


def promote_registered_account(conn, request, correo, password):
    """Offline bootstrap only: retain identity, password and all existing MFA state."""
    ensure_first_admin(conn, request)
    u, r = request.app.state.tables["usuario"], request.app.state.tables["rol"]
    user_id = conn.scalar(select(u.c.id_usuario).where(u.c.correo == email(correo)))
    user = identity(conn, request, user_id, lock=True) if user_id else None
    valid = verify_password(user.password_hash if user else DUMMY_HASH, password)
    if not valid or not user or not user.activo or not user.rol_activo or user.rol != "analista":
        raise AuthError(400, "No se pudo verificar la cuenta y su contraseña.")
    if not user.correo_verificado_en:
        raise AuthError(409, "Verifique primero el correo de la cuenta existente.")
    role_id = conn.scalar(select(r.c.id_rol).where(r.c.codigo == "administrador", r.c.activo.is_(True)))
    if role_id is None:
        raise AuthError(503, "El rol administrador no está disponible.")
    conn.execute(u.update().where(u.c.id_usuario == user_id).values(
        id_rol=role_id, autorizacion="aprobado", autorizado_por=user_id,
        autorizado_en=now(), modificado_por=user_id,
    ))
    revoke(conn, request, user_id)
    audit(conn, request, "primer_administrador_habilitado", user_id, actor=user_id)
    audit(conn, request, "cuenta_autorizada", user_id, actor=user_id)
    audit(conn, request, "rol_cambiado", user_id, actor=user_id, rol="administrador")
    return identity(conn, request, user_id)


def delete_previous_accounts(conn):
    """Reset account ownership inside the same transaction as the new signup."""
    metadata = MetaData()
    metadata.reflect(bind=conn, schema="honeypot")
    users = metadata.tables["honeypot.usuario"]
    user_ids = list(conn.scalars(select(users.c.id_usuario)))
    if not user_ids:
        return 0
    # A complete account reset also clears the append-only authentication log.
    conn.execute(text("TRUNCATE TABLE honeypot.auth_notificacion, honeypot.auth_auditoria"))
    # Remove dependent login state and signed review rows. Keep Cowrie evidence.
    for name in ("auth_token", "auth_solicitud_password", "auth_recuperacion",
                 "auth_sesion", "auth_factor", "revision_analisis"):
        table = metadata.tables.get("honeypot." + name)
        if table is not None:
            conn.execute(table.delete().where(table.c.id_usuario.in_(user_ids)))
    support = metadata.tables.get("honeypot.auth_soporte")
    if support is not None:
        conn.execute(support.update().where(support.c.id_usuario.in_(user_ids))
                     .values(id_usuario=None, correo_verificado=False))
    for table in metadata.tables.values():
        if table.name == "auth_auditoria":
            continue
        for column in table.columns:
            references_user = any(fk.column.table.fullname == users.fullname for fk in column.foreign_keys)
            if references_user:
                if not column.nullable:
                    remaining = conn.scalar(select(func.count()).select_from(table).where(column.in_(user_ids)))
                    if remaining:
                        raise RuntimeError("Dependencia obligatoria pendiente: " + table.name + "." + column.name)
                else:
                    conn.execute(table.update().where(column.in_(user_ids)).values({column.name: None}))
    conn.execute(users.delete().where(users.c.id_usuario.in_(user_ids)))
    return len(user_ids)


async def main(existing=False, replace_accounts=False):
    data = None
    if existing:
        try:
            correo = email(input("Correo de la cuenta ya verificada: "))
        except ValueError as exc:
            print(str(exc))
            return
        password = getpass("Contraseña actual (no se muestra): ")
    else:
        try:
            data = Registration(
                cedula=input("Cédula ecuatoriana: "), nombres=input("Nombres: "), apellidos=input("Apellidos: "),
                nombre_usuario=input("Nombre de usuario: "), correo=input("Correo electrónico: "),
                password=getpass("Contraseña (no se muestra): "), confirmacion=getpass("Confirme la contraseña: "),
            )
        except ValidationError as exc:
            for error in exc.errors(include_input=False, include_context=False):
                print(error["msg"])
            return
    async with lifespan(app):
        request = Request({"type": "http", "app": app, "client": ("127.0.0.1", 0), "headers": [], "path": "/cli/create-admin", "scheme": "http", "server": ("localhost", 0), "query_string": b""})
        try:
            with app.state.engine.begin() as conn:
                if replace_accounts:
                    conn.execute(text("SELECT pg_advisory_xact_lock(724610902)"))
                    removed = delete_previous_accounts(conn)
                if existing:
                    user = promote_registered_account(conn, request, correo, password)
                    message = (user.correo, "Cuenta habilitada como primer administrador",
                        "El procedimiento local habilitó su cuenta como primer administrador. Se cerraron las sesiones anteriores. Debe iniciar sesión y completar Google Authenticator antes de acceder.")
                else:
                    ensure_first_admin(conn, request)
                    user = create_account(conn, request, data, admin=True)
                    message = issue_email_code(conn, request, user)
        except AuthError as exc:
            print(exc.detail)
            if replace_accounts:
                raise SystemExit(1) from None
            return
        if replace_accounts:
            print(f"Cuentas anteriores eliminadas: {removed}")
        notify(request, user.id_usuario, message)
        if existing:
            print("Cuenta existente autorizada como primer administrador. Recargue la interfaz, inicie sesión y complete Google Authenticator.")
        else:
            print("Administrador creado y autorizado. Debe verificar su correo y vincular Google Authenticator desde la interfaz.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Configurar el primer administrador localmente, sin omitir correo verificado ni MFA.")
    parser.add_argument("--existente", action="store_true", help="Usar una cuenta ya registrada y con correo verificado; exige su contraseña actual y que no exista otro administrador.")
    parser.add_argument("--reemplazar-cuentas", action="store_true", help="Eliminar todas las cuentas y sus accesos antes de crear el administrador nuevo.")
    args = parser.parse_args()
    if args.existente and args.reemplazar_cuentas:
        parser.error("--existente y --reemplazar-cuentas son excluyentes")
    asyncio.run(main(existing=args.existente, replace_accounts=args.reemplazar_cuentas))
