"""Explicit manual SMTP check. Never runs on import or server startup."""
import os
from pathlib import Path
import smtplib
import ssl

from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email

from backend.auth.config import Settings
from backend.auth.mailer import deliver


def main():
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    if os.getenv("MAIL_TRANSPORT") != "smtp":
        print("Configure MAIL_TRANSPORT=smtp en el .env del backend.")
        return 1
    if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_USER") or not os.getenv("SMTP_PASSWORD"):
        print("Complete SMTP_HOST, SMTP_USER y SMTP_PASSWORD en el .env privado.")
        return 1
    if not (os.getenv("SMTP_SSL", "false").lower() == "true" or os.getenv("SMTP_STARTTLS", "true").lower() == "true"):
        print("La prueba requiere SSL o STARTTLS con validación de certificados.")
        return 1
    try:
        settings = Settings.load()
        recipient = validate_email(input("Gmail destinatario para un único correo de prueba: ").strip(),
                                   check_deliverability=False).normalized
        deliver(settings, recipient, "Prueba de envío SMTP",
                "Este es un correo de prueba solicitado desde TacticLens. "
                "Permite comprobar la recepción del correo de seguridad. "
                "No contiene contraseñas, códigos de acceso ni claves API.")
    except EmailNotValidError:
        print("La dirección de correo no tiene un formato válido; no se envió el mensaje.")
        return 1
    except smtplib.SMTPAuthenticationError:
        print("Autenticación SMTP rechazada. Revise SMTP_USER y SMTP_PASSWORD en el .env.")
        return 1
    except smtplib.SMTPRecipientsRefused:
        print("El servidor SMTP rechazó el destinatario. Revise la dirección y el panel del proveedor.")
        return 1
    except ssl.SSLCertVerificationError:
        print("No se pudo validar el certificado SMTP. No se desactivó la verificación TLS.")
        return 1
    except (smtplib.SMTPException, OSError):
        print("No se pudo completar el envío SMTP. Revise conexión, puerto y panel del proveedor.")
        return 1
    except (RuntimeError, ValueError):
        print("Revise la configuración de autenticación y correo del .env. No se imprimen valores privados.")
        return 1
    print("El servidor SMTP aceptó el mensaje. Compruebe Gmail, Spam y el estado del mensaje en Resend; "
          "la aceptación SMTP no garantiza su entrega en la bandeja de entrada.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
