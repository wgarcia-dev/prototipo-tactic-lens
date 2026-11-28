from datetime import date
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=200)]
Description = Annotated[str, StringConstraints(strip_whitespace=True, min_length=8, max_length=2000)]
EventId = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]{0,18}$")]
Revision = Annotated[int, Field(strict=True, ge=1, le=2147483647)]
Phase = Literal["contencion", "erradicacion", "recuperacion", "verificacion"]
ActionState = Literal["propuesta", "aprobada", "en_curso", "ejecutada", "verificada", "rechazada", "cancelada"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Citation(BaseModel):
    id_evento: EventId
    id_sesion: UUID
    id_analisis: UUID | None = None
    grado: Literal["observacion", "intento", "resultado_en_honeypot", "resultado_confirmado"]

    @field_validator("id_evento")
    @classmethod
    def postgres_bigint(cls, value):
        if int(value) > 9223372036854775807:
            raise ValueError("Identificador de evento inválido")
        return value


class Scope(BaseModel):
    sesiones: list[UUID] = Field(min_length=1)
    recursos_confirmados: list[str] = Field(default_factory=list)


class Evaluation(BaseModel):
    version_contrato: Literal[1]
    id_incidente: UUID
    revision_evaluacion: Revision
    decision: Literal["incidente_confirmado", "actividad_sospechosa", "actividad_autorizada", "evidencia_insuficiente"]
    severidad: Literal["S0", "S1", "S2", "S3", "S4"] | None
    titulo: str
    resumen: str
    evaluado_en: AwareDatetime
    alcance: Scope
    evidencia_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    evidencias: list[Citation]


class EvaluationChange(Model):
    revision_evaluacion: Revision


class Change(EvaluationChange):
    revision_esperada: Revision
    motivo: Description


class PlanInput(EvaluationChange):
    objetivo: Description
    alcance: Description
    criterio_cierre: Description
    id_responsable: UUID | None = None
    fases_no_aplicables: dict[Phase, Description] = Field(default_factory=dict)


class PlanReview(PlanInput, Change):
    ratificar: list[UUID] = Field(default_factory=list, max_length=500)
    cancelar: list[UUID] = Field(default_factory=list, max_length=500)


class PlanTransition(Change):
    operacion: Literal["resolver", "cerrar", "cancelar", "reabrir"]
    resultado: Description | None = None
    riesgos_pendientes: Description | None = None
    sin_acciones: Description | None = None
    referencia: Description | None = None


class Proposal(Model):
    fase: Phase
    medida: ShortText
    objetivo: Description
    justificacion: Description
    criterio_verificacion: Description
    eventos: list[EventId] = Field(default_factory=list, max_length=20)


class ActionInput(Proposal, Change):
    referencia: Description | None = None


class ActionTransition(Change):
    operacion: Literal["asignar", "aprobar", "rechazar", "iniciar", "avanzar", "ejecutar", "verificar",
                       "devolver", "cancelar"]
    id_responsable: UUID | None = None
    vence_en: date | None = None
    resultado: Description | None = None
    referencia: Description | None = None
    eventos: list[EventId] = Field(default_factory=list, max_length=20)


class ImportProposal(Change):
    fase: Phase
    id_analisis: UUID | None = None
    posicion: Revision | None = None
    id_salvaguarda: UUID | None = None


class BoardConfig(Model):
    revision_esperada: Revision
    wip_activo: bool
    limite_wip: Annotated[int, Field(strict=True, ge=1, le=10000)]
