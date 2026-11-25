"""Derive a session analysis state from stored results and its current event count."""
from collections import defaultdict
from datetime import datetime
import hashlib
from itertools import chain
import json
import os

from sqlalchemy import func, select


def analyzed_count(row):
    payload = row.resultado_estructurado
    if isinstance(payload, dict):
        value = payload.get("eventos_analizados")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def is_expired(row):
    if row.estado != "en_proceso":
        return False
    started = row.fecha_inicio or row.creado_en
    if not started:
        return True
    timeout = max(300, float(os.getenv("LLM_TIMEOUT_SECONDS", "60")) * 2 + 60)
    return (datetime.now(started.tzinfo) - started).total_seconds() > timeout


def classification_fingerprint(events, configuration):
    digest = hashlib.sha256()
    event_data = (
        (event.id_evento, event.tipo_evento, event.fecha_hora.isoformat(), event.datos_originales)
        for event in events
    )
    for entry in chain((configuration,), event_data):
        digest.update(json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode())
        digest.update(b'\n')
    return digest.hexdigest()


def states_for_sessions(conn, analysis_table, counts, *, fingerprint=None):
    if not counts:
        return {}
    rows = conn.execute(
        select(
            analysis_table.c.id_analisis,
            analysis_table.c.id_sesion,
            analysis_table.c.estado,
            analysis_table.c.fecha_inicio,
            analysis_table.c.creado_en,
            analysis_table.c.resultado_estructurado,
            analysis_table.c.mensaje_error,
        )
        .where(analysis_table.c.id_sesion.in_(counts))
        .order_by(func.coalesce(analysis_table.c.fecha_inicio, analysis_table.c.creado_en).desc(), analysis_table.c.creado_en.desc(), analysis_table.c.id_analisis.desc())
    ).mappings().all()
    grouped = defaultdict(list)
    for row in rows:
        grouped[row.id_sesion].append(row)
    output = {}
    for session_id, event_count in counts.items():
        history = grouped[session_id]
        latest = history[0] if history else None
        completed = next((item for item in history if item.estado == "completado"), None)
        valid = next((item for item in history if item.estado == "completado" and analyzed_count(item) == event_count
                      and (fingerprint is None or item.resultado_estructurado.get('huella_clasificacion') == fingerprint)), None)
        expired = bool(latest and is_expired(latest))
        if latest and latest.estado == "en_proceso" and not expired:
            status = "en_proceso"
        elif valid:
            status = "analizada"
        elif latest and (latest.estado == "fallido" or expired):
            status = "error"
        else:
            status = "pendiente"
        output[session_id] = {
            "estado_analisis": status,
            "analisis_desactualizado": bool(completed and not valid),
            "analisis": {"id_analisis": str(completed.id_analisis), "estado": completed.estado,
                'metodo':(completed.resultado_estructurado or {}).get('rag',{}).get('metodo','deepseek_legacy')} if completed else None,
            "ultimo_intento": {
                "id_analisis": str(latest.id_analisis),
                "estado": "fallido" if expired else latest.estado,
                "mensaje_error": latest.mensaje_error,
            } if latest else None,
            "analisis_vigente_id": valid.id_analisis if valid else None,
            "analisis_en_proceso": bool(latest and latest.estado == "en_proceso" and not expired),
            "intento_expirado_id": latest.id_analisis if expired else None,
        }
    return output


def public_state(state):
    return {key: state[key] for key in ("estado_analisis", "analisis_desactualizado", "analisis", "ultimo_intento")}
