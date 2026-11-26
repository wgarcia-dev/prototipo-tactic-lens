"""Versioned safeguard follow-up, bound to the immutable proposal's analysis."""
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from .analysis_report import safeguard_cards
from .rag.behavior import redact

TRANSITIONS = {
    "propuesta": {"aprobada", "descartada"},
    "aprobada": {"en_curso", "descartada"},
    "en_curso": {"verificada", "descartada"},
    "verificada": {"en_curso"},
    "descartada": {"propuesta"},
}


class SafeguardReview(BaseModel):
    revision_esperada: int = Field(ge=0)
    estado: Literal["propuesta", "aprobada", "en_curso", "verificada", "descartada"]
    responsable: str = Field(min_length=3, max_length=200)
    motivo: str = Field(min_length=10, max_length=2000)
    verificacion: str = Field(default="", max_length=3000)

    @field_validator("responsable", "motivo", "verificacion")
    @classmethod
    def trim(cls, value):
        return value.strip()


def proposal(payload, code):
    cards = safeguard_cards((payload.get("informe") or {}).get("recomendaciones") or [], payload.get("seguimiento_salvaguardas"))
    return next((card for card in cards if card["rows"][0][1] == code), None)


def append_review(payload, code, decision, actor_id):
    if proposal(payload, code) is None:
        raise HTTPException(404, "Salvaguarda no encontrada en este análisis")
    history = dict(payload.get("seguimiento_salvaguardas") or {})
    entries = list(history.get(code) or [])
    if decision.revision_esperada != len(entries):
        raise HTTPException(409, "La salvaguarda cambió. Recargue antes de guardar")
    current = entries[-1]["estado"] if entries else "propuesta"
    if decision.estado not in TRANSITIONS[current]:
        raise HTTPException(422, "Transición de estado no permitida")
    if len(decision.responsable) < 3 or len(decision.motivo) < 10:
        raise HTTPException(422, "Complete el responsable y el motivo de la revisión")
    if decision.estado == "verificada" and len(decision.verificacion) < 20:
        raise HTTPException(422, "Documente la comprobación de eficacia y su evidencia")
    entries.append({
        **decision.model_dump(exclude={"revision_esperada"}),
        "revisado_por": str(actor_id), "revisado_en": datetime.now(timezone.utc).isoformat(),
        "revision": len(entries) + 1,
    })
    history[code] = entries
    return {**payload, "seguimiento_salvaguardas": history}


def browse(conn, sensors, *, analysis_id=None, session_id=None, state=None, limit=25, offset=0):
    # Expand and paginate proposals in PostgreSQL, including historical analyses.
    rows = conn.execute(text("""
        WITH proposals AS (
            SELECT a.id_analisis, a.id_sesion, s.cowrie_session_id, s.fecha_inicio,
                   a.fecha_fin AS fecha_analisis, a.resultado_estructurado,
                   'SG-' || lpad(p.ordinal::text, 3, '0') AS codigo, p.item
            FROM honeypot.analisis_llm a
            JOIN honeypot.sesion s ON s.id_sesion = a.id_sesion
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(a.resultado_estructurado->'informe'->'recomendaciones') = 'array'
                     THEN a.resultado_estructurado->'informe'->'recomendaciones'
                     ELSE '[]'::jsonb END
            ) WITH ORDINALITY AS p(item, ordinal)
            WHERE a.estado = 'completado' AND s.id_honeypot = ANY(:sensors)
              AND (CAST(:session_id AS uuid) IS NULL OR a.id_sesion = CAST(:session_id AS uuid))
              AND (CAST(:analysis_id AS uuid) IS NULL OR a.id_analisis = CAST(:analysis_id AS uuid))
        ), tracked AS (
            SELECT *, coalesce(resultado_estructurado->'seguimiento_salvaguardas'->codigo,
                                '[]'::jsonb) AS historial
            FROM proposals
        )
        SELECT *, coalesce(historial->-1->>'estado', 'propuesta') AS estado,
               count(*) OVER () AS total
        FROM tracked
        WHERE (CAST(:state AS text) IS NULL OR coalesce(historial->-1->>'estado', 'propuesta') = :state)
        ORDER BY fecha_analisis DESC NULLS LAST, fecha_inicio DESC, id_analisis, codigo
        LIMIT :limit OFFSET :offset
    """), dict(sensors=list(sensors), analysis_id=analysis_id, session_id=session_id, state=state, limit=limit, offset=offset)).mappings()
    result = []
    for row in rows:
        result.append({
            "id_analisis": str(row.id_analisis), "id_sesion": str(row.id_sesion),
            "cowrie_session_id": row.cowrie_session_id, "codigo": row.codigo,
            "fecha_inicio": row.fecha_inicio, "fecha_analisis": row.fecha_analisis,
            "estado": row.estado, "ficha": proposal(row.resultado_estructurado, row.codigo),
            "historial": redact(row.historial), "total": row.total,
        })
    return result
