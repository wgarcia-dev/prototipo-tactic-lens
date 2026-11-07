"""Responsive, self-contained transactional mail using the TacticLens palette.

The text supplied by existing services remains authoritative. Presentation profiles
only change hierarchy/labels; they never create links, codes or account decisions.
"""
from dataclasses import dataclass
from html import escape
import re
from urllib.parse import urlsplit


FONT = "'Segoe UI',Arial,Helvetica,sans-serif"
PALETTE = {
    "canvas": "#edf2f7", "paper": "#ffffff", "navy": "#0b1423",
    "console": "#132238", "ink": "#233449", "muted": "#607287",
    "edge": "#dce5ed", "signal": "#43d7d4", "teal": "#155e68",
}
TONES = {
    "neutral": ("#155e68", "#edf8f7", "#d1e9e7"),
    "warning": ("#805215", "#fff7e9", "#f0dfbd"),
    "restricted": ("#913f4b", "#fff0f2", "#f0d9de"),
}


@dataclass(frozen=True)
class EmailPresentation:
    label: str
    title: str
    preheader: str
    tone: str = "neutral"
    button: str = "Establecer mi contraseña"
    verification: bool = False


def presentation(subject):
    normalized = subject.casefold().strip()
    if normalized.startswith("verifique su correo"):
        return EmailPresentation("VERIFICACIÓN DE CORREO", "Confirme su correo electrónico",
            "Su código para continuar en TacticLens. Verifique su correo desde el formulario.", verification=True)
    if normalized.startswith("cuenta autorizada: defina"):
        return EmailPresentation("REGISTRO AUTORIZADO", "Defina su contraseña",
            "Su registro fue autorizado. Defina su contraseña con el enlace personal.", button="Crear mi contraseña")
    if normalized.startswith(("recuperación aprobada", "restablecimiento de contraseña")):
        return EmailPresentation("RECUPERACIÓN APROBADA", "Restablezca su contraseña",
            "Su solicitud fue aprobada. Use el enlace personal dentro de su vigencia.", button="Restablecer contraseña")
    if normalized in {"contraseña actualizada", "contraseña restablecida"}:
        return EmailPresentation("CAMBIO CONFIRMADO", "Su contraseña fue actualizada",
            "Confirmación de un cambio de contraseña en su cuenta TacticLens.")
    if normalized == "solicitud de registro recibida":
        return EmailPresentation("SOLICITUD RECIBIDA", "Su registro está en revisión",
            "Recibimos su registro. El administrador revisará su solicitud de acceso.")
    if normalized == "solicitud de recuperación recibida":
        return EmailPresentation("REVISIÓN ADMINISTRATIVA", "Recibimos su solicitud",
            "Su solicitud de recuperación está pendiente de revisión administrativa.")
    if "rechazada" in normalized or "no autorizada" in normalized:
        return EmailPresentation("SOLICITUD NO AUTORIZADA", subject,
            "Hay una decisión administrativa sobre su solicitud de TacticLens.", tone="warning")
    if normalized == "cuenta suspendida":
        return EmailPresentation("ACCESO SUSPENDIDO", "Su cuenta fue suspendida",
            "Se actualizó el estado de acceso de su cuenta TacticLens.", tone="warning")
    if normalized == "cuenta bloqueada":
        return EmailPresentation("ACCESO BLOQUEADO", "Su cuenta fue bloqueada",
            "Revise la notificación de restricción de su cuenta TacticLens.", tone="restricted")
    if normalized == "cuenta reactivada":
        return EmailPresentation("CUENTA REACTIVADA", "Su cuenta está habilitada de nuevo",
            "Se reactivó el acceso de su cuenta. Inicie sesión con sus factores habituales.")
    if "autenticador" in normalized or "authenticator" in normalized:
        return EmailPresentation("SEGUNDO FACTOR", subject,
            "Hay una actualización relacionada con el segundo factor de su cuenta.", tone="warning")
    if normalized == "solicitud de cuenta autorizada":
        return EmailPresentation("REGISTRO AUTORIZADO", "Su solicitud fue autorizada",
            "El administrador autorizó su solicitud de acceso a TacticLens.")
    if "prueba" in normalized:
        return EmailPresentation("COMPROBACIÓN DEL SERVICIO", "Correo de prueba de TacticLens",
            "Mensaje de comprobación del servicio de correo, sin credenciales ni códigos de acceso.")
    return EmailPresentation("SEGURIDAD DE LA CUENTA", subject,
        "Una notificación de TacticLens sobre la seguridad de su cuenta.")


def safe_link(value):
    if any(char.isspace() or ord(char) < 32 for char in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password)
    except ValueError:
        return False


def html_content(content):
    """Escaped body fallback, shared with the rendered template and legacy callers."""
    lines = []
    for line in content.splitlines():
        if safe_link(line):
            lines.append('<a style="color:#155e68;text-decoration:underline" rel="noreferrer noopener" href="' + escape(line, quote=True) + '">Establecer mi contraseña</a>')
        else:
            lines.append(escape(line))
    return "\n".join(lines)


def message_parts(content, profile):
    """Recognize only whole server-generated code/link lines; preserve other text."""
    code, link, body = None, None, []
    for line in content.replace("\r\n", "\n").split("\n"):
        match = re.fullmatch(r"Su código de verificación es: ([0-9]{6})", line.strip()) if profile.verification else None
        if match and code is None:
            code = match.group(1)
        elif link is None and safe_link(line.strip()):
            link = line.strip()
        else:
            body.append(line)
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", "\n".join(body)) if part.strip()]
    return code, link, paragraphs


def render_email(subject, content):
    profile = presentation(subject)
    code, link, paragraphs = message_parts(content, profile)
    tone, tint, tone_edge = TONES[profile.tone]
    p = PALETTE

    def paragraph(value):
        return '<p style="margin:0 0 20px;color:' + p["ink"] + ';font-size:15px;line-height:1.75;word-wrap:break-word">' + html_content(value).replace("\n", "<br>") + '</p>'

    body = ""
    if code:
        body += paragraph("Introduzca este código en el formulario de TacticLens para verificar su correo electrónico.")
        body += f'''<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin:24px 0;border:1px solid {tone_edge};border-radius:10px;background-color:{tint}">
          <tr><td align="center" style="padding:24px 16px 8px;font-family:{FONT};color:{p['teal']};font-size:10px;line-height:16px;font-weight:700;letter-spacing:1.8px">CÓDIGO DE VERIFICACIÓN</td></tr>
          <tr><td align="center" class="tl-code" style="padding:0 8px 16px 16px;color:{p['navy']};font-family:Consolas,'Courier New',monospace;font-size:42px;line-height:54px;letter-spacing:8px;font-weight:700">{code}</td></tr>
          <tr><td align="center" style="padding:0 20px 24px;color:{p['muted']};font-family:{FONT};font-size:12px;line-height:18px">Escriba o copie los seis dígitos. No comparta este código.</td></tr>
        </table>'''
    elif paragraphs:
        body += paragraph(paragraphs.pop(0))

    if link:
        href = escape(link, quote=True)
        body += f'''<table role="presentation" cellspacing="0" cellpadding="0" border="0" class="tl-button" style="margin:24px 0 28px">
          <tr><td align="center" bgcolor="{p['teal']}" style="background-color:{p['teal']};border-radius:7px;mso-padding-alt:16px 24px">
          <a href="{href}" rel="noreferrer noopener" style="display:inline-block;border:1px solid {p['teal']};border-radius:7px;padding:16px 24px;font-family:{FONT};font-size:15px;font-weight:700;line-height:20px;text-align:center;text-decoration:none;color:#ffffff">{escape(profile.button)}</a>
          </td></tr></table>'''

    body += "".join(paragraph(part) for part in paragraphs)
    if code:
        body += f'<p style="margin:4px 0 24px;color:{p["muted"]};font-size:12px;line-height:20px">Este código verifica su correo. Es diferente del código de Google Authenticator.</p>'
    if link:
        body += f'''<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="table-layout:fixed;margin:4px 0 24px;border-top:1px solid {p['edge']}"><tr><td style="padding-top:20px;font-family:{FONT}">
          <p style="margin:0 0 8px;color:{p['muted']};font-size:12px;line-height:20px">Si el botón no funciona, copie este enlace en su navegador:</p>
          <a href="{href}" rel="noreferrer noopener" style="color:{p['teal']};font-size:11px;line-height:18px;text-decoration:underline;word-break:break-all;overflow-wrap:anywhere">{escape(link)}</a>
        </td></tr></table>'''

    return f'''<!doctype html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><meta name="referrer" content="no-referrer"><title>{escape(subject)} · TacticLens</title>
<style>body{{margin:0!important;padding:0!important}}table{{border-collapse:separate}}a:focus{{outline:2px solid {p['teal']};outline-offset:3px}}@media screen and (max-width:620px){{.tl-shell{{padding:16px 12px!important}}.tl-header{{padding:28px 24px!important}}.tl-content{{padding:28px 24px!important}}.tl-title{{font-size:25px!important;line-height:32px!important}}.tl-code{{font-size:34px!important;letter-spacing:6px!important}}.tl-button{{width:100%!important}}.tl-button a{{display:block!important}}}}</style>
</head><body style="margin:0;padding:0;background-color:{p['canvas']};font-family:{FONT};-webkit-text-size-adjust:100%">
<div style="display:none;font-size:1px;color:{p['canvas']};line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all">{escape(profile.preheader)}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="{p['canvas']}" style="background-color:{p['canvas']}"><tr><td align="center" class="tl-shell" style="padding:40px 20px">
<!--[if mso]><table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;table-layout:fixed;border:1px solid {p['edge']};border-radius:14px;background-color:{p['paper']}">
<tr><td class="tl-header" bgcolor="{p['navy']}" style="padding:32px 40px;background-color:{p['navy']};border-top:4px solid {p['signal']};border-radius:13px 13px 0 0;font-family:{FONT}">
  <p style="margin:0;color:{p['signal']};font-size:26px;line-height:32px;font-weight:700;letter-spacing:-0.7px"><span style="color:#e9f0fa">Tactic</span>Lens</p>
  <p style="margin:7px 0 0;color:#a0b3c8;font-size:9px;line-height:15px;letter-spacing:2px;font-weight:600">OBSERVATORIO COWRIE</p>
</td></tr>
<tr><td class="tl-content" bgcolor="{p['paper']}" style="padding:36px 40px 32px;background-color:{p['paper']};border-radius:0 0 13px 13px;font-family:{FONT}">
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-bottom:20px"><tr><td bgcolor="{tint}" style="padding:6px 10px;border-radius:4px;background-color:{tint};color:{tone};font-family:{FONT};font-size:9px;line-height:14px;letter-spacing:1.2px;font-weight:700">{escape(profile.label)}</td></tr></table>
  <h1 class="tl-title" style="margin:0 0 20px;color:{p['navy']};font-family:{FONT};font-size:29px;line-height:37px;font-weight:700;letter-spacing:-0.6px">{escape(profile.title)}</h1>
  {body}
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="margin-top:28px;border-top:1px solid {p['edge']}"><tr><td style="padding-top:24px;font-family:{FONT}">
    <p style="margin:0 0 7px;color:{p['ink']};font-size:12px;line-height:19px;font-weight:700">¿No reconoce esta solicitud o actividad?</p>
    <p style="margin:0;color:{p['muted']};font-size:12px;line-height:20px">No comparta contraseñas, enlaces personales ni códigos de acceso. Contacte al administrador de su organización por su canal habitual.</p>
  </td></tr></table>
</td></tr></table>
<!--[if mso]></td></tr></table><![endif]-->
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px"><tr><td align="center" style="padding:24px 20px 4px;font-family:{FONT}">
  <p style="margin:0;color:#506479;font-size:11px;line-height:18px;font-weight:600">TacticLens · Seguridad de la cuenta</p>
  <p style="margin:5px 0 0;color:#6a7d91;font-size:11px;line-height:18px">Este mensaje se generó automáticamente.</p>
</td></tr></table>
</td></tr></table></body></html>'''
