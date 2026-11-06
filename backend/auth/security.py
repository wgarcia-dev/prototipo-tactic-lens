"""Library-backed password hashing, TOTP and authenticated encryption."""
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
import pyotp
from zxcvbn import zxcvbn

# Explicit Argon2id parameters, above OWASP's minimum; salts are library-generated.
PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID)
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))


def now():
    return datetime.now(timezone.utc)


def opaque_token():
    return secrets.token_urlsafe(32)


def fingerprint(settings, purpose, value):
    return hmac.new(settings.secret.encode(), (purpose + ":" + value).encode(), hashlib.sha256).hexdigest()


def verify_password(encoded, value):
    try:
        return PASSWORDS.verify(encoded, value)
    except (VerificationError, InvalidHashError):
        return False


def password_strength(value, personal=()):
    length_ok = 12 <= len(value) <= 128
    common = re.sub(r"[^a-záéíóúñ]", "", value.casefold())
    common_ok = common not in {"contraseña", "contrasena", "password", "administrador", "tacticlens", "bienvenido", "seguridad", "ecuador"}
    score = zxcvbn(value, user_inputs=[str(x) for x in personal if x], max_length=128)["score"] * 25 if value and len(value) <= 128 else 0
    if not length_ok:
        score = min(score, 50)
    if not common_ok:
        score = min(score, 25)
    return {"porcentaje": score, "longitud_valida": length_ok, "no_comun": common_ok,
            "aceptable": length_ok and common_ok and score >= 75}


def validate_password(value, personal=()):
    strength = password_strength(value, personal)
    if not strength["longitud_valida"]:
        raise ValueError("La contraseña debe tener entre 12 y 128 caracteres")
    if not strength["no_comun"]:
        raise ValueError("Elija una contraseña menos común")
    if not strength["aceptable"]:
        raise ValueError("La contraseña debe alcanzar al menos 75% de fortaleza estimada; use varias palabras poco relacionadas")
    return value


def matching_interval(secret, code, last_interval, at=None):
    """Return an unused RFC 6238 interval, checking a strict +/- one-step window."""
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int((at or now()).timestamp()) // 30
    totp = pyotp.TOTP(secret, digits=6, interval=30, digest=hashlib.sha1)
    for interval in (current, current - 1, current + 1):
        if interval > last_interval and hmac.compare_digest(totp.at(interval * 30), code):
            return interval
    return None


def recovery_codes():
    # 128 random bits per one-time recovery code; HMAC hashes only go into SQL.
    values = [secrets.token_hex(16) for _ in range(10)]
    return ["-".join(value[i:i+8] for i in range(0, 32, 8)) for value in values]
