"""Render synthetic local examples. Never loads .env or invokes SMTP."""
from html import escape
from pathlib import Path

from backend.auth.email_templates import render_email


SAMPLES = [
    ("admin-registro", "Registro para administración", "Nueva solicitud de registro pendiente",
     "Una cuenta verificada espera revisión.\n\nReferencia del evento: DEMO-1042\nUsuario: analista_demo\nFecha: 07/11/2026 10:30:00 America/Guayaquil (UTC-05:00)\nEstado en el momento del evento: Pendiente de revisión\n\nInicie sesión y complete MFA para revisar la cuenta. Responder a este correo no autoriza el acceso.\nhttps://tacticlens.example/usuarios"),
    ("admin-alerta", "Alerta administrativa", "Alerta administrativa · Intentos reiterados de autenticación",
     "Se alcanzó el umbral de intentos fallidos.\n\nReferencia del evento: DEMO-1043\nUsuario: analista_demo\nFecha: 07/11/2026 10:35:00 America/Guayaquil (UTC-05:00)\n\nRevise los detalles dentro de TacticLens. Este aviso no contiene contraseñas ni códigos.\nhttps://tacticlens.example/usuarios"),
    ("soporte", "Consulta para soporte", "Nuevo mensaje de soporte · acceso",
     "Una persona envió una solicitud de ayuda desde TacticLens.\n\nReferencia: DEMO-SOPORTE\nNombre: Persona de ejemplo\nIdentidad: Correo declarado sin verificación de identidad en este formulario\nCategoría: acceso\n\nDescripción:\nNo encuentro dónde consultar el estado de mi registro.\n\nResponda manualmente desde el buzón de soporte. Este mensaje no autoriza cambios de contraseña, permisos ni MFA."),
    ("soporte-confirmacion", "Confirmación de soporte", "Confirmación de solicitud de soporte",
     "Su consulta quedó registrada para remisión al canal de soporte.\n\nReferencia: DEMO-SOPORTE\nFecha: 07/11/2026 10:40:00 America/Guayaquil (UTC-05:00)\n\nEl personal de soporte responderá manualmente. Este aviso no confirma lectura ni resolución."),
    ("verificacion", "Verificación de correo", "Verifique su correo para registrarse",
     "Su código de verificación es: 482913\n\nCaduca en 5 minutos y solo puede usarse una vez. Escríbalo en el formulario de registro que tiene abierto. Si ya tiene cuenta, utilice el inicio de sesión o la recuperación de contraseña."),
    ("registro", "Registro recibido", "Solicitud de registro recibida",
     "Su correo está verificado y su solicitud está pendiente de autorización. Cuando un administrador la apruebe, recibirá un enlace personal para definir su contraseña. No enviamos contraseñas por correo."),
    ("primera-password", "Registro aprobado", "Cuenta autorizada: defina su contraseña",
     "Un administrador de seguridad aprobó su solicitud. Para establecer su contraseña, abra este enlace personal:\nhttps://tacticlens.example/recuperar#token=DEMO_ENLACE_SIN_VALIDEZ\n\nEl enlace caduca en 15 minutos y solo puede utilizarse una vez. No lo comparta. Abrirlo no cambia la contraseña; debe confirmar una nueva. Google Authenticator seguirá siendo obligatorio."),
    ("recuperacion", "Recuperación aprobada", "Recuperación aprobada: restablezca su contraseña",
     "Un administrador de seguridad aprobó su solicitud. Para establecer su contraseña, abra este enlace personal:\nhttps://tacticlens.example/recuperar#token=DEMO_ENLACE_SIN_VALIDEZ\n\nEl enlace caduca en 15 minutos y solo puede utilizarse una vez. No lo comparta. Abrirlo no cambia la contraseña; debe confirmar una nueva. Google Authenticator seguirá siendo obligatorio. Si no solicitó esta operación, contacte al administrador."),
    ("password-cambiada", "Contraseña actualizada", "Contraseña actualizada",
     "Se cambió su contraseña y se cerraron todas sus sesiones. Google Authenticator permanece activo."),
    ("suspension", "Cuenta suspendida", "Cuenta suspendida",
     "Cuenta suspendida. Un administrador actualizó su cuenta. Sus sesiones previas fueron revocadas. La recuperación de contraseña no permite eludir restricciones. Contacte al administrador por un canal conocido si necesita una revisión."),
    ("bloqueo", "Cuenta bloqueada", "Cuenta bloqueada",
     "Cuenta bloqueada. Un administrador actualizó su cuenta. Sus sesiones previas fueron revocadas. La recuperación de contraseña no permite eludir restricciones. Contacte al administrador por un canal conocido si necesita una revisión."),
    ("reactivacion", "Cuenta reactivada", "Cuenta reactivada",
     "Cuenta reactivada. Un administrador actualizó su cuenta. Sus sesiones previas fueron revocadas. Inicie sesión y complete Google Authenticator para continuar."),
    ("recuperacion-pendiente", "Recuperación recibida", "Solicitud de recuperación recibida",
     "Su solicitud quedó pendiente de revisión administrativa. Si se aprueba, recibirá un enlace personal de un solo uso. No se enviarán contraseñas por correo. Si no solicitó esta operación, contacte al administrador."),
    ("rechazo", "Solicitud rechazada", "Solicitud de recuperación rechazada",
     "Un administrador no autorizó su solicitud de recuperación. No se emitió ningún enlace. Contacte al administrador por un canal conocido para revisar su caso."),
    ("mfa", "Cambio de autenticador", "Google Authenticator restablecido",
     "Un administrador restableció su segundo factor tras verificar su identidad. Se cerraron todas sus sesiones. Debe volver a vincular Google Authenticator antes de acceder."),
]


def main():
    directory = Path(__file__).resolve().parents[1] / ".local" / "email-previews"
    directory.mkdir(parents=True, exist_ok=True)
    for slug, _, subject, content in SAMPLES:
        (directory / (slug + ".html")).write_text(render_email(subject, content, support_email="soporte@tacticlens.example"), encoding="utf-8")
    links = "".join('<a href="' + slug + '.html" target="mail-preview">' + escape(label) + '</a>' for slug, label, _, _ in SAMPLES)
    gallery = '''<!doctype html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Correos de TacticLens · Vista previa</title><style>
      *{box-sizing:border-box}body{margin:0;background:#0b1423;color:#e9f0fa;font:14px/1.6 'Segoe UI',Arial,sans-serif}header{max-width:1200px;margin:auto;padding:28px 24px 20px}h1{font-size:26px;margin:8px 0}small{color:#43d7d4;letter-spacing:2px}p{color:#a0b3c8;margin:0}main{display:grid;grid-template-columns:220px minmax(0,1fr);gap:24px;max-width:1200px;margin:auto;padding:0 24px 28px}nav a{display:block;color:#c5d6e8;border-bottom:1px solid #20344d;padding:10px 12px;text-decoration:none}nav a:hover,nav a:focus{color:#43d7d4;background:#132238;outline:1px solid #43d7d4}iframe{display:block;width:100%;height:1250px;border:0;border-radius:12px;background:#edf2f7}@media(max-width:700px){main{grid-template-columns:1fr;padding:0 12px 20px;gap:16px}nav{display:flex;gap:8px;flex-wrap:wrap}nav a{font-size:12px;padding:6px 10px;border:1px solid #20344d;border-radius:5px}header{padding:20px 16px}iframe{height:1400px}}
      </style></head><body><header><small>TACTICLENS · CORREOS TRANSACCIONALES</small><h1>Correos de seguridad de TacticLens</h1><p>Vista previa local con datos ficticios. No se ha enviado ningún correo. Los códigos y enlaces no son válidos.</p></header><main><nav aria-label="Tipos de correo">LINKS</nav><iframe title="Vista del correo seleccionado" name="mail-preview" src="verificacion.html" referrerpolicy="no-referrer" sandbox="allow-same-origin"></iframe></main></body></html>'''.replace("LINKS", links)
    (directory / "index.html").write_text(gallery, encoding="utf-8")
    print("Vistas previas ficticias generadas en " + str(directory / "index.html"))
    print("No se cargó .env ni se abrió una conexión SMTP.")


if __name__ == "__main__":
    main()
