"""Spanish multipart email; development mailbox is explicit and never served by HTTP."""
from email.message import EmailMessage
from email.utils import format_datetime
import os
from pathlib import Path
import smtplib
import ssl
import re
from uuid import uuid4

from .security import now
from .email_templates import html_content, render_email
from .mail_config import MailConfig, address


class DeliveryUncertain(RuntimeError):
    """Connection failed during DATA: SMTP acceptance cannot be determined locally."""


def deliver(settings, recipient, subject, content, *, reply_to=None, idempotency_key=None):
    config = MailConfig.load()
    recipient = address(recipient)
    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = recipient
    message["Subject"] = "TacticLens · " + subject
    message["Date"] = format_datetime(now())
    if reply_to or config.support:
        message["Reply-To"] = address(reply_to or config.support)
    if idempotency_key:
        if not re.fullmatch(r"[A-Za-z0-9/_:-]{1,128}", idempotency_key):
            raise ValueError("Clave de idempotencia no válida")
        message["Resend-Idempotency-Key"] = idempotency_key
    footer = "\n\nTacticLens · Seguridad de la cuenta\nSi no solicitó esta operación, contacte al administrador."
    if config.support:
        footer += "\nSoporte oficial: " + config.support
    message.set_content(content + footer)
    message.add_alternative(render_email(subject, content, support_email=config.support), subtype="html")
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
        try:
            smtp.send_message(message)
        except (OSError, smtplib.SMTPServerDisconnected):
            raise DeliveryUncertain("No se pudo confirmar la aceptación SMTP") from None
