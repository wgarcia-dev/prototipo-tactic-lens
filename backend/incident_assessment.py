"""Versioned triage criteria for Cowrie evidence and accountable human decisions."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, StrictInt, field_validator

METHODOLOGY = "tacticlens-triaje-1"
REFERENCE = "https://csrc.nist.gov/pubs/sp/800/61/r3/final"


def assess(events):
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
    snapshot = [{"id": str(event.id_evento), "tipo": event.tipo_evento,
                 "fecha": event.fecha_hora.isoformat(), "datos": event.datos_originales} for event in events]
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()
    return {"version": 1, "metodologia": METHODOLOGY, "referencia": REFERENCE,
            "generado_en": datetime.now(timezone.utc).isoformat(), "snapshot_sha256": digest,
            "eventos_evaluados": len(events), "eventos": [str(event.id_evento) for event in events], "clasificacion": classification,
            "estado": "pendiente_revision", "prioridad_triaje": priority,
            "fundamento_prioridad": "La interacción y las transferencias requieren revisión prioritaria del señuelo."
                if priority == "media" else "La captura requiere comprobar el contexto y la finalidad de la conexión.",
            "criterios": findings, "severidad": "por_determinar",
            "impacto": {"confidencialidad": "sin_determinar", "integridad": "sin_determinar",
                        "disponibilidad": "sin_determinar", "alcance": "Telemetría de una sesión del honeypot Cowrie"},
            "limitaciones": ["La emulación requiere corroboración de efectos en sistemas reales.",
                             "La intención, autorización e impacto organizacional requieren evaluación humana."],
            "revisiones": []}


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
