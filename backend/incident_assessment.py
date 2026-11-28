"""Versioned triage criteria for Cowrie evidence and accountable human decisions."""
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, StrictInt, field_validator

from .analysis_state import evidence_snapshot

METHODOLOGY = "tacticlens-triaje-1"
REFERENCE = "https://csrc.nist.gov/pubs/sp/800/61/r3/final"


def assess(events, evaluation=None, impact=None):
    """Describe telemetry coverage without inferring organizational compromise."""
    criteria = [
        ("autenticacion_fallida", "Intentos de autenticación fallidos", {"cowrie.login.failed"}),
        ("acceso_senuelo", "Autenticación aceptada por el señuelo", {"cowrie.login.success"}),
        ("interaccion_shell", "Órdenes recibidas por la shell", {"cowrie.command.input"}),
        ("transferencia", "Transferencia registrada por Cowrie", {"cowrie.session.file_download", "cowrie.session.file_upload"}),
    ]
    findings = []
    for code, title, kinds in criteria:
        ids = [str(event.id_evento) for event in events if event.tipo_evento in kinds]
        findings.append({"criterio": code, "descripcion": title, "cumplido": bool(ids), "eventos": ids})
    active = {item["criterio"] for item in findings if item["cumplido"]}
    priority = "media" if active.intersection({"interaccion_shell", "transferencia"}) else "baja"
    classification = "actividad_por_evaluar" if active else "evento_observado"
    snapshot = evidence_snapshot(events)
    assessment = {"version": 1, "metodologia": METHODOLOGY, "referencia": REFERENCE,
            "generado_en": datetime.now(timezone.utc).isoformat(), "snapshot_sha256": snapshot["eventos_sha256"],
            "eventos_evaluados": len(events), "eventos": snapshot["eventos"], "clasificacion": classification,
            "estado": "pendiente_revision", "prioridad_triaje": priority,
            "fundamento_prioridad": ("Revisar " + " y ".join(description for criterion, description in (
                ("interaccion_shell", "las órdenes registradas"), ("transferencia", "los eventos de transferencia registrados")
            ) if criterion in active) + "." if priority == "media"
                else "Contrastar el contexto y la finalidad de la actividad registrada."),
            "criterios": findings, "severidad": "por_determinar",
            "impacto": {"confidencialidad": "sin_determinar", "integridad": "sin_determinar",
                        "disponibilidad": "sin_determinar", "alcance": "Telemetría de una sesión del honeypot Cowrie"},
            "limitaciones": ["La emulación requiere corroboración de efectos en sistemas reales.",
                             "La intención, autorización e impacto organizacional requieren evaluación humana."],
            "revisiones": []}
    if evaluation:
        level = evaluation["codigo_severidad"]
        decision = {
            "S0": ("evento_observado", "Correlacionar con otros registros solo si aparece actividad adicional."),
            "S1": ("actividad_de_alcance_limitado", "Contrastar autenticación y órdenes con el registro de sesiones autorizado."),
            "S2": ("actividad_sospechosa_sustentada", "Preservar las citas y comprobar el alcance sobre el recurso objetivo."),
            "S3": ("actividad_de_alta_relevancia", "Preservar evidencias y corroborar el estado del recurso en el activo objetivo."),
            "S4": ("afectacion_critica_documentada", "Escalar la revisión del alcance y activar el procedimiento de respuesta aplicable."),
        }
        classification, next_step = decision.get(level, ("evaluacion_limitada", "Verificar cobertura y procedencia antes de clasificar."))
        assessment.update(clasificacion=classification, severidad=level,
                          prioridad_triaje=evaluation["prioridad_investigacion"],
                          fundamento_prioridad=evaluation["fundamento_prioridad"])
        assessment["automatica"] = {
            "clasificacion":classification, "severidad":level, "prioridad":evaluation["prioridad_investigacion"],
            "fundamento":evaluation["fundamento_severidad"], "decision_recomendada":next_step,
            "impacto_potencial":evaluation["nivel_impacto_potencial"],
            "recursos":impact["recursos_en_riesgo"], "eventos":evaluation["eventos"],
            "factores_agravantes":evaluation["factores_agravantes"], "factores_limitantes":evaluation["factores_limitantes"],
        }
    return assessment


class IncidentDecision(BaseModel):
    revision_esperada: int = Field(ge=0)
    decision: Literal["incidente_confirmado", "actividad_sospechosa", "actividad_autorizada", "evidencia_insuficiente"]
    severidad: Literal["baja", "media", "alta", "critica", "por_determinar"]
    justificacion: str = Field(min_length=30, max_length=4000)
    criterio_incidente: str = Field(min_length=15, max_length=2000)
    impacto: str = Field(min_length=15, max_length=2000)
    alcance: str = Field(min_length=10, max_length=2000)
    responsable: str = Field(min_length=3, max_length=200)
    medidas: str = Field(min_length=15, max_length=3000)
    eventos: list[StrictInt] = Field(min_length=1, max_length=500)
    estado: Literal["en_investigacion", "en_respuesta", "cerrado"]
    criterio_cierre: str = Field(default="", max_length=2000)

    @field_validator("eventos", mode="before")
    @classmethod
    def exact_event_ids(cls, values):
        if isinstance(values, list):
            return [int(value) if isinstance(value, str) and value.isascii() and value.isdecimal() else value
                    for value in values]
        return values

    @field_validator("justificacion", "criterio_incidente", "impacto", "alcance", "responsable", "medidas")
    @classmethod
    def trim_text(cls, value):
        if len(value.strip()) < 3:
            raise ValueError("El texto debe contener una explicación")
        return value.strip()


def validate_decision(decision, valid_ids):
    if not set(decision.eventos) <= valid_ids:
        raise ValueError("La decisión cita eventos fuera del análisis")
    if decision.estado == "cerrado" and len(decision.criterio_cierre.strip()) < 20:
        raise ValueError("El cierre requiere documentar su criterio y verificación")
    if decision.decision == "incidente_confirmado" and decision.severidad == "por_determinar":
        raise ValueError("La confirmación requiere valorar la severidad")
