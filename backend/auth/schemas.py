"""All critical identity validation lives on the server."""
import re
import unicodedata

from email_validator import validate_email, EmailNotValidError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .security import validate_password


def email(value):
    try:
        normalized = validate_email(value.strip(), check_deliverability=False, allow_smtputf8=False).ascii_email
    except EmailNotValidError:
        raise ValueError("Correo electrónico inválido") from None
    if not normalized or len(normalized) > 254:
        raise ValueError("Correo electrónico inválido")
    return normalized.casefold()


def cedula(value):
    if not re.fullmatch(r"[0-9]{10}", value):
        raise ValueError("La cédula debe contener exactamente diez dígitos")
    province = int(value[:2])
    if (province not in range(1, 25) and province != 30) or int(value[2]) >= 6:
        raise ValueError("Cédula de persona natural inválida")
    total = sum((int(d)*2 if int(d)*2 < 10 else int(d)*2-9) if i % 2 == 0 else int(d) for i, d in enumerate(value[:9]))
    if (10 - total % 10) % 10 != int(value[-1]):
        raise ValueError("Dígito verificador de cédula inválido")
    return value


def person_name(value):
    value = " ".join(unicodedata.normalize("NFC", value).split())
    if not 1 <= len(value) <= 58 or not any(c.isalpha() for c in value):
        raise ValueError("Use entre 1 y 58 caracteres para nombres y apellidos")
    if any(not (unicodedata.category(c)[0] in {"L", "M"} or c in " '-’.") for c in value):
        raise ValueError("Nombres y apellidos contienen caracteres no válidos")
    return value


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class EmailPayload(Payload):
    correo: str = Field(max_length=320)
    _email = field_validator("correo")(email)


class RegistrationProfile(EmailPayload):
    cedula: str
    nombres: str
    apellidos: str
    nombre_usuario: str
    _cedula = field_validator("cedula")(cedula)
    _names = field_validator("nombres", "apellidos")(person_name)

    @field_validator("nombre_usuario")
    @classmethod
    def username(cls, value):
        value = unicodedata.normalize("NFKC", value).strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", value):
            raise ValueError("Usuario: entre 3 y 64 letras ASCII, números, punto, guion o guion bajo")
        return value


class Registration(RegistrationProfile):
    """Password-based identity input for the trusted bootstrap CLI, not public signup."""
    password: SecretStr = Field(max_length=128)
    confirmacion: SecretStr = Field(max_length=128)

    @model_validator(mode="after")
    def passwords(self):
        if self.password.get_secret_value() != self.confirmacion.get_secret_value():
            raise ValueError("Las contraseñas no coinciden")
        validate_password(self.password.get_secret_value(), (self.nombres, self.apellidos, self.correo, self.nombre_usuario, self.cedula))
        return self


class Login(EmailPayload):
    password: SecretStr = Field(min_length=1, max_length=128)


class EmailCode(EmailPayload):
    codigo: SecretStr = Field(min_length=6, max_length=6)


class SecondFactor(Payload):
    codigo: SecretStr = Field(min_length=6, max_length=64)
    recuperacion: bool = False


class Reauthentication(SecondFactor):
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordReset(Payload):
    token: SecretStr = Field(min_length=40, max_length=100)
    password: SecretStr = Field(max_length=128)
    confirmacion: SecretStr = Field(max_length=128)

    @model_validator(mode="after")
    def passwords(self):
        if self.password.get_secret_value() != self.confirmacion.get_secret_value():
            raise ValueError("Las contraseñas no coinciden")
        validate_password(self.password.get_secret_value())
        return self


class InitialPassword(Payload):
    password: SecretStr = Field(max_length=128)
    confirmacion: SecretStr = Field(max_length=128)

    @model_validator(mode="after")
    def passwords(self):
        if self.password.get_secret_value() != self.confirmacion.get_secret_value():
            raise ValueError("Las contraseñas no coinciden")
        validate_password(self.password.get_secret_value())
        return self


class PasswordAssessment(Payload):
    password: SecretStr = Field(max_length=128)
    token: SecretStr | None = Field(default=None, min_length=40, max_length=100)


class PasswordChange(Reauthentication):
    nueva_password: SecretStr = Field(max_length=128)
    confirmacion: SecretStr = Field(max_length=128)

    @model_validator(mode="after")
    def passwords(self):
        if self.nueva_password.get_secret_value() != self.confirmacion.get_secret_value():
            raise ValueError("Las contraseñas no coinciden")
        validate_password(self.nueva_password.get_secret_value())
        return self


class UserUpdate(SecondFactor):
    # Only a pending account approval can omit the administrator's password.
    # The handler verifies the persisted account state before choosing that flow.
    password: SecretStr | None = Field(default=None, min_length=1, max_length=128)
    rol: str = Field(pattern="^(administrador|analista)$")
    activo: bool
    aprobar: bool = False
    rechazar: bool = False
    motivo_rechazo: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def decision(self):
        if self.aprobar and self.rechazar:
            raise ValueError("Elija aceptar o rechazar, no ambas opciones")
        if not self.aprobar and self.password is None:
            raise ValueError("Esta operación requiere su contraseña de administrador")
        if self.rechazar and (not self.motivo_rechazo or len(self.motivo_rechazo.strip()) < 10):
            raise ValueError("Indique un motivo de rechazo de al menos diez caracteres")
        return self


class MfaReset(Reauthentication):
    referencia_verificacion: str = Field(min_length=20, max_length=160)
