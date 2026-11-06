"""Fail-closed settings; no baked-in cryptographic keys or accounts."""
from dataclasses import dataclass
import os
from urllib.parse import urlparse

from cryptography.fernet import Fernet, MultiFernet


def integer(name, default, minimum=1, maximum=86400):
    value = int(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} fuera de rango")
    return value


@dataclass(frozen=True)
class Settings:
    secret: str
    cipher: MultiFernet
    production: bool
    secure_cookie: bool
    origins: frozenset[str]
    public_url: str
    email_seconds: int
    resend_seconds: int
    max_attempts: int
    challenge_seconds: int
    session_seconds: int
    idle_seconds: int
    reset_seconds: int
    registration_proof_seconds: int
    temporary_password_seconds: int

    @classmethod
    def load(cls):
        secret = os.getenv("AUTH_SECRET_KEY", "")
        keys = os.getenv("AUTH_TOTP_KEYS", "")
        if len(secret) < 64 or not keys:
            raise RuntimeError("Configure AUTH_SECRET_KEY y AUTH_TOTP_KEYS; ejecute python -m scripts.configure_auth")
        try:
            cipher = MultiFernet([Fernet(k.strip().encode()) for k in keys.split(",")])
        except (ValueError, TypeError):
            raise RuntimeError("AUTH_TOTP_KEYS no contiene claves Fernet válidas") from None
        environment = os.getenv("AUTH_ENV", "production")
        if environment not in {"production", "development"}:
            raise RuntimeError("AUTH_ENV debe ser production o development")
        production = environment == "production"
        secure = os.getenv("AUTH_COOKIE_SECURE", "true").lower() == "true"
        public_url = os.getenv("AUTH_PUBLIC_URL", "http://127.0.0.1:5173").rstrip("/")
        origins = frozenset(x.strip().rstrip("/") for x in os.getenv("AUTH_ALLOWED_ORIGINS", public_url).split(","))
        if any(urlparse(o).scheme not in {"http", "https"} or not urlparse(o).netloc or urlparse(o).path for o in origins):
            raise RuntimeError("AUTH_ALLOWED_ORIGINS debe contener orígenes HTTP(S) exactos")
        if urlparse(public_url).scheme not in {"http", "https"} or urlparse(public_url).fragment or urlparse(public_url).query:
            raise RuntimeError("AUTH_PUBLIC_URL inválida")
        if production and (not secure or any(not o.startswith("https://") for o in origins) or not public_url.startswith("https://")):
            raise RuntimeError("Producción requiere HTTPS y AUTH_COOKIE_SECURE=true")
        if production and os.getenv("MAIL_TRANSPORT", "smtp") != "smtp":
            raise RuntimeError("El buzón de archivos solo está permitido en desarrollo")
        return cls(secret, cipher, production, secure, origins, public_url,
                   integer("AUTH_EMAIL_TTL_SECONDS", 300), integer("AUTH_RESEND_SECONDS", 60),
                   integer("AUTH_MAX_ATTEMPTS", 5, maximum=20), integer("AUTH_CHALLENGE_SECONDS", 300),
                   integer("AUTH_SESSION_SECONDS", 28800), integer("AUTH_IDLE_SECONDS", 1800),
                   integer("AUTH_RESET_SECONDS", 900), integer("AUTH_REGISTRATION_PROOF_SECONDS", 900),
                   integer("AUTH_TEMP_PASSWORD_SECONDS", 86400))


SESSION_COOKIE = "tacticlens_session"
CSRF_COOKIE = "tacticlens_csrf"
REGISTRATION_COOKIE = "tacticlens_registro"
