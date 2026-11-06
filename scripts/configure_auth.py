"""Initialize missing local secrets without printing them or replacing existing keys."""
import os
from pathlib import Path
import secrets

from cryptography.fernet import Fernet
from dotenv import dotenv_values


def main():
    path = Path(__file__).resolve().parents[1] / ".env"
    current = dotenv_values(path) if path.exists() else {}
    defaults = {
        "AUTH_SECRET_KEY": secrets.token_urlsafe(48),
        "AUTH_TOTP_KEYS": Fernet.generate_key().decode(),
        "AUTH_ENV": "development", "AUTH_COOKIE_SECURE": "false",
        "AUTH_PUBLIC_URL": "http://127.0.0.1:5173",
        "AUTH_ALLOWED_ORIGINS": "http://127.0.0.1:5173,http://localhost:5173",
        "MAIL_TRANSPORT": "file", "MAIL_DEV_DIRECTORY": ".local/mail",
        "MAIL_FROM": "TacticLens <no-reply@tacticlens.local>",
    }
    missing = {key: value for key, value in defaults.items() if not current.get(key)}
    if missing:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        # Replace empty assignments instead of introducing ambiguous duplicate keys.
        import re
        for key, value in missing.items():
            line = key + "=" + value
            if re.search(r"(?m)^" + key + r"\s*=", existing):
                existing = re.sub(r"(?m)^" + key + r"\s*=.*$", lambda _: line, existing)
            else:
                existing = existing.rstrip() + "\n" + line + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(existing)
    print("Configuración local preparada. Las claves existentes se conservaron; ningún secreto se imprime.")


if __name__ == "__main__":
    main()
