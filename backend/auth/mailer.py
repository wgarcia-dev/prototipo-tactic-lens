"""Spanish multipart email; development mailbox is explicit and never served by HTTP."""
from email.message import EmailMessage
from email.utils import format_datetime
from html import escape
import os
from pathlib import Path
import smtplib
import ssl
from uuid import uuid4

from .security import now


def deliver(settings, recipient, subject, content):
    message = EmailMessage()
    message["From"] = os.getenv("MAIL_FROM", "TacticLens <no-reply@tacticlens.local>")
    message["To"] = recipient
    message["Subject"] = "TacticLens · " + subject
    message["Date"] = format_datetime(now())
    message.set_content(content + "\n\nTacticLens · Seguridad de la cuenta\nSi no solicitó esta operación, contacte al administrador.")
    message.add_alternative("""<!doctype html><html lang="es"><body style="margin:0;background:#edf2f7;font-family:Arial,sans-serif;color:#14243a">
      <main style="max-width:560px;margin:32px auto;background:white;padding:32px;border-top:4px solid #207b83">
      <p style="font-weight:bold;color:#207b83">TACTICLENS · SEGURIDAD</p><h1 style="font-size:24px">%s</h1>
      <p style="line-height:1.7;white-space:pre-wrap">%s</p><hr><p style="font-size:12px;color:#526579">
      Nunca comparta su contraseña ni los códigos de Google Authenticator. Si no solicitó esta operación, contacte al administrador.</p></main></body></html>""" % (escape(subject), escape(content)), subtype="html")
    transport = os.getenv("MAIL_TRANSPORT", "smtp")
    if transport == "file" and not settings.production:
        directory = Path(os.getenv("MAIL_DEV_DIRECTORY", ".local/mail"))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / (now().strftime("%Y%m%d-%H%M%S-") + uuid4().hex + ".eml")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(message.as_bytes())
        return
    if transport != "smtp":
        raise RuntimeError("Transporte de correo no permitido")
    host = os.getenv("SMTP_HOST", "")
    if not host:
        raise RuntimeError("Configure SMTP_HOST")
    implicit_tls = os.getenv("SMTP_SSL", "false").lower() == "true"
    starttls = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
    if settings.production and not (implicit_tls or starttls):
        raise RuntimeError("SMTP en producción requiere TLS")
    port = int(os.getenv("SMTP_PORT", "465" if implicit_tls else "587"))
    smtp_class = smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP
    kwargs = {"context": ssl.create_default_context()} if implicit_tls else {}
    with smtp_class(host, port, timeout=10, **kwargs) as smtp:
        if starttls and not implicit_tls:
            smtp.starttls(context=ssl.create_default_context())
        user = os.getenv("SMTP_USER", "")
        if user:
            smtp.login(user, os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(message)
