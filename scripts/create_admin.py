"""Interactive, offline bootstrap. No public elevation endpoint or default account."""
import asyncio
from getpass import getpass

from fastapi import Request
from pydantic import ValidationError
from sqlalchemy import func, select, text

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


async def main(existing=False):
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
        with app.state.engine.begin() as conn:
            try:
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
                return
        notify(request, user.id_usuario, message)
        if existing:
            print("Cuenta existente autorizada como primer administrador. Recargue la interfaz, inicie sesión y complete Google Authenticator.")
        else:
            print("Administrador creado y autorizado. Debe verificar su correo y vincular Google Authenticator desde la interfaz.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Configurar el primer administrador localmente, sin omitir correo verificado ni MFA.")
    parser.add_argument("--existente", action="store_true", help="Usar una cuenta ya registrada y con correo verificado; exige su contraseña actual y que no exista otro administrador.")
    args = parser.parse_args()
    asyncio.run(main(existing=args.existente))
