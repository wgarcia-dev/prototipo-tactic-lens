"""Public mail routing and alert policy. SMTP credentials retain their existing names."""
from dataclasses import dataclass
from email.utils import parseaddr
import os
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from email_validator import validate_email, EmailNotValidError

from .config import integer


def address(value):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Dirección de correo no válida")
    try:
        return validate_email(value.strip(), check_deliverability=False, allow_smtputf8=False).ascii_email.casefold()
    except (EmailNotValidError, AttributeError):
        raise ValueError("Dirección de correo no válida") from None


@dataclass(frozen=True)
class MailConfig:
    sender: str
    admin: str | None
    support: str | None
    timezone: ZoneInfo
    threshold: int
    window_seconds: int
    cooldown_seconds: int
    max_attempts: int

    @classmethod
    def load(cls):
        sender = os.getenv("MAIL_FROM", "TacticLens <no-reply@tacticlens.local>")
        if any(ord(c) < 32 or ord(c) == 127 for c in sender):
            raise RuntimeError("MAIL_FROM no es válido")
        _, sender_address = parseaddr(sender)
        # Retain the explicit development .local sender; real SMTP requires a valid address.
        if os.getenv("MAIL_TRANSPORT", "smtp") == "smtp":
            try:
                address(sender_address)
            except ValueError:
                raise RuntimeError("MAIL_FROM no es válido para SMTP") from None
        try:
            admin = address(os.environ["ADMIN_EMAIL"]) if os.getenv("ADMIN_EMAIL") else None
            support = address(os.environ["SUPPORT_EMAIL"]) if os.getenv("SUPPORT_EMAIL") else None
            zone = ZoneInfo(os.getenv("MAIL_TIMEZONE", "America/Guayaquil"))
        except (ValueError, ZoneInfoNotFoundError):
            raise RuntimeError("Revise ADMIN_EMAIL, SUPPORT_EMAIL y MAIL_TIMEZONE") from None
        return cls(sender, admin, support, zone, integer("MAIL_ALERT_THRESHOLD", 5, maximum=100),
            integer("MAIL_ALERT_WINDOW_SECONDS", 900, minimum=60),
            integer("MAIL_ALERT_COOLDOWN_SECONDS", 900, minimum=60),
            integer("MAIL_NOTIFICATION_MAX_ATTEMPTS", 3, maximum=5))
