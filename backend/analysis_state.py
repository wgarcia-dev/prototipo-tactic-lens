"""Compare a saved analysis with the current evidence and analytical configuration."""
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path

from sqlalchemy import func, select, text

from .analysis_execution import DEFAULT_ATTEMPT_SECONDS, EXPIRED_MESSAGE, AnalysisFailure, positive_seconds

SNAPSHOT_VERSION = 1


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode()).hexdigest()


def evidence_snapshot(events):
    ordered = sorted(events, key=lambda event: (event.fecha_hora, event.id_evento))
    return {"eventos_sha256": digest([(event.id_evento, event.tipo_evento, event.fecha_hora.isoformat(),
                                       event.datos_originales) for event in ordered]),
            "eventos": [str(event.id_evento) for event in ordered]}


@lru_cache(maxsize=1)
def implementation_version():
    root = Path(__file__).parent
    components = ("analysis_model.py", "analysis_semantics.py", "analysis_consolidation.py", "analysis_impact.py",
                  "analysis_controls.py", "terminal_evidence.py", "threat_evaluation.py", "incident_assessment.py",
                  "safeguard_risk.py", "intelligence.py", "enrichment.py", "rag/behavior.py", "rag/retrieval.py",
                  "rag/pipeline.py", "rag/validation.py", "rag/mitre_evidence.py", "rag/mitre_command_rules.py")
    return digest({component: hashlib.sha256((root / component).read_text(encoding="utf-8").encode()).hexdigest()
                   for component in components})


def model_parameters():
    return {"temperature": 0, "thinking": {"type": "disabled"}, "response_format": {"type": "json_object"},
            "max_tokens": 8192}


def methodology_configuration(catalog, instances):
    from .analysis_report import REPORT_VERSION, analysis_instruction
    from .analysis_model import SIGNATURE
    from .rag import pipeline
    from .rag.embeddings import MODEL, REVISION
    from .rag.mitre_evidence import VALIDATOR_VERSION, contract_signature
    from .threat_evaluation import RECURRENCE

    # Store/return fingerprints, never the endpoint, credentials or prompt contents.
    return {"catalogo": dict(catalog) if catalog else None,
            "proveedor": os.getenv("LLM_PROVIDER", "openai"), "modelo": os.getenv("LLM_MODEL"),
            "endpoint_sha256": digest((os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")),
            "prompt_sha256": digest(analysis_instruction() + pipeline.RAG_INSTRUCTION),
            "parametros": model_parameters(), "metodo": pipeline.METHOD, "pipeline": pipeline.PIPELINE_VERSION,
            "validador": VALIDATOR_VERSION, "contratos": contract_signature(), "informe": REPORT_VERSION,
            "modelo_analitico": SIGNATURE, "implementacion": implementation_version(),
            "recurrencia": RECURRENCE, "embeddings": [MODEL, REVISION],
            "sensores": {name: str(value) for name, value in instances.items()},
            "enriquecimiento": {name: bool(os.getenv(name)) for name in (
                "MISP_WARNING_LISTS_DIR", "THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY")}}


# The same origins and time window used by the analytical comparison. This only
# reads session metadata and identities, never reconstructs neighbor behavior.
SESSION_INPUTS = text("""
WITH subject AS (
    SELECT s.id_sesion, s.id_honeypot, s.ip_origen, s.fecha_inicio, s.revision_eventos,
           count(e.id_evento) AS total, max(e.fecha_hora) AS upper_at
      FROM honeypot.sesion s LEFT JOIN honeypot.evento e USING (id_sesion)
     WHERE s.id_sesion = ANY(CAST(:ids AS uuid[]))
     GROUP BY s.id_sesion
)
SELECT subject.*, neighbor.id_sesion AS neighbor_id, neighbor.revision_eventos AS neighbor_revision,
       neighbor.id_honeypot AS neighbor_sensor, neighbor.ip_origen AS neighbor_origin,
       neighbor.fecha_inicio AS neighbor_start
  FROM subject
  LEFT JOIN LATERAL (
      SELECT other.id_sesion, other.revision_eventos, other.id_honeypot, other.ip_origen, other.fecha_inicio
      FROM (
          SELECT s.id_sesion
            FROM honeypot.sesion s
           WHERE s.id_honeypot = subject.id_honeypot AND s.id_sesion <> subject.id_sesion
             AND subject.ip_origen IS NOT NULL
             AND regexp_replace(host(s.ip_origen), '^::ffff:', '') =
                 regexp_replace(host(subject.ip_origen), '^::ffff:', '')
             AND s.fecha_inicio <= subject.upper_at
             AND EXISTS (SELECT 1 FROM honeypot.evento e WHERE e.id_sesion = s.id_sesion
                 AND e.fecha_hora BETWEEN subject.upper_at - make_interval(hours => :hours) AND subject.upper_at)
          UNION
          (SELECT DISTINCT destination.id_sesion
             FROM honeypot.evento source
             JOIN honeypot.observacion_ioc observed ON observed.id_evento = source.id_evento
             JOIN honeypot.ioc indicator ON indicator.id_ioc = observed.id_ioc
             JOIN honeypot.tipo_ioc kind ON kind.id_tipo_ioc = indicator.id_tipo_ioc
             JOIN honeypot.observacion_ioc shared ON shared.id_ioc = indicator.id_ioc
             JOIN honeypot.evento destination ON destination.id_evento = shared.id_evento
             JOIN honeypot.sesion owner ON owner.id_sesion = destination.id_sesion
            WHERE source.id_sesion = subject.id_sesion AND destination.id_sesion <> subject.id_sesion
              AND kind.nombre IN ('URL', 'Domain', 'Dominio', 'Hash')
              AND owner.id_honeypot = ANY(CAST(:sensors AS uuid[]))
              AND destination.fecha_hora BETWEEN subject.upper_at - make_interval(hours => :hours) AND subject.upper_at
            ORDER BY destination.id_sesion LIMIT 50)
      ) candidates JOIN honeypot.sesion other USING (id_sesion)
  ) neighbor ON true
 ORDER BY subject.id_sesion, neighbor.id_sesion
""")


def current_inputs(conn, tables, session_ids, sensors, instances):
    from .threat_evaluation import RECURRENCE

    ids = list(session_ids)
    if not ids:
        return {}, None
    catalog = tables["catalogo_mitre"]
    active = conn.execute(select(catalog.c.id_catalogo, catalog.c.version, catalog.c.sha256)
                          .where(catalog.c.activo.is_(True))).mappings().one_or_none()
    config = methodology_configuration(active, instances)
    config_digest = digest(config)
    grouped = defaultdict(list)
    for row in conn.execute(SESSION_INPUTS, {"ids": ids, "sensors": list(sensors), "hours": RECURRENCE["ventana_horas"]}):
        grouped[row.id_sesion].append(row)
    result = {}
    for sid, rows in grouped.items():
        row = rows[0]
        related = [(item.neighbor_id, item.neighbor_revision, item.neighbor_sensor, item.neighbor_origin,
                    item.neighbor_start) for item in rows if item.neighbor_id is not None]
        result[sid] = {"version": SNAPSHOT_VERSION, "eventos_total": row.total, "revision_eventos": row.revision_eventos,
                       "metodologia_sha256": config_digest,
                       "contexto_sha256": digest((row.id_honeypot, row.ip_origen, row.fecha_inicio, related)),
                       "sesiones_contexto": [item[0] for item in related], "limite_contexto": row.upper_at}
    return result, config


def result_freshness(payload, current):
    payload = payload or {}
    saved = payload.get("vigencia_snapshot") or {}
    count = payload.get("eventos_analizados")
    versioned = saved.get("version") == SNAPSHOT_VERSION and all(saved.get(key) is not None for key in (
        "revision_eventos", "contexto_sha256", "metodologia_sha256", "eventos_sha256"))
    complete = type(count) is int and count == current["eventos_total"]
    if versioned:
        complete = complete and saved["revision_eventos"] == current["revision_eventos"]
        method = ("vigente" if all(saved[key] == current[key] for key in ("metodologia_sha256", "contexto_sha256"))
                  else "desactualizada")
    else:
        method = "no_verificable"
    return {"cobertura_eventos": "completa" if complete else "incompleta", "metodologia": method,
            "eventos_actuales": current["eventos_total"], "eventos_analizados": count,
            "evidencia_verificable": versioned, "evidencia_sha256": saved.get("eventos_sha256") if versioned else None}


def latest_status(row):
    if row is None:
        return "sin_analizar"
    if row.estado == "fallido" and row.mensaje_error == EXPIRED_MESSAGE:
        return "vencido"
    if row.estado == "en_proceso":
        started = row.fecha_inicio or row.creado_en
        deadline = (getattr(row, "ejecucion", None) or {}).get("vence_en")
        if isinstance(deadline, str):
            try:
                ends = datetime.fromisoformat(deadline)
            except ValueError:
                pass
            else:
                return "vencido" if datetime.now(ends.tzinfo) >= ends else row.estado
        try:
            timeout = positive_seconds("LLM_ANALYSIS_TIMEOUT_SECONDS", DEFAULT_ATTEMPT_SECONDS)
        except AnalysisFailure:
            timeout = DEFAULT_ATTEMPT_SECONDS
        if not started or (datetime.now(started.tzinfo) - started).total_seconds() >= timeout:
            return "vencido"
    return row.estado


def analyzed_count(row):
    value = (row.resultado_estructurado or {}).get("eventos_analizados")
    return value if type(value) is int else None


def states_for_sessions(conn, analysis, inputs):
    if not inputs:
        return {}
    payload = analysis.c.resultado_estructurado
    columns = (analysis.c.id_analisis, analysis.c.id_sesion, analysis.c.estado, analysis.c.fecha_inicio,
               analysis.c.creado_en, analysis.c.mensaje_error, payload["eventos_analizados"].label("eventos_analizados"),
               payload["vigencia_snapshot"].label("vigencia_snapshot"), payload["rag"]["metodo"].astext.label("metodo"),
               payload["ejecucion"].label("ejecucion"))
    ordered = (func.coalesce(analysis.c.fecha_inicio, analysis.c.creado_en).desc(),
               analysis.c.creado_en.desc(), analysis.c.id_analisis.desc())
    query = select(*columns, func.row_number().over(partition_by=analysis.c.id_sesion, order_by=ordered)
                   .label("position")).where(analysis.c.id_sesion.in_(inputs))

    def first_rows(statement):
        ranked = statement.subquery()
        return {row.id_sesion: row for row in conn.execute(select(ranked).where(ranked.c.position == 1))}

    latest = first_rows(query)
    completed = first_rows(query.where(analysis.c.estado == "completado"))
    result = {}
    for sid, current in inputs.items():
        attempt, saved = latest.get(sid), completed.get(sid)
        attempt_status = latest_status(attempt)
        freshness = (result_freshness({"eventos_analizados": saved.eventos_analizados,
                     "vigencia_snapshot": saved.vigencia_snapshot}, current) if saved else None)
        valid = freshness and freshness["cobertura_eventos"] == "completa" and freshness["metodologia"] == "vigente"
        status = {"en_proceso": "en_proceso", "fallido": "error", "vencido": "error"}.get(
            attempt_status, "analizada" if valid else "pendiente")
        result[sid] = {"estado_analisis": status, "analisis_desactualizado": bool(saved and not valid),
                       "vigencia_analisis": freshness, "estado_ultimo_intento": attempt_status,
                       "analisis": {"id_analisis": str(saved.id_analisis), "estado": saved.estado,
                                    "metodo": saved.metodo or "deepseek_legacy"} if saved else None,
                       "ultimo_intento": {"id_analisis": str(attempt.id_analisis), "estado": attempt_status,
                                          "mensaje_error": attempt.mensaje_error,
                                          "error": (attempt.ejecucion or {}).get("error"),
                                          "vence_en": (attempt.ejecucion or {}).get("vence_en")} if attempt else None,
                       "analisis_vigente_id": saved.id_analisis if valid and attempt_status == "completado" else None,
                       "analisis_en_proceso": attempt_status == "en_proceso",
                       "intento_expirado_id": attempt.id_analisis if attempt_status == "vencido"
                       and attempt.estado == "en_proceso" else None}
    return result


def public_state(state):
    return {key: state[key] for key in ("estado_analisis", "analisis_desactualizado", "vigencia_analisis",
                                       "estado_ultimo_intento", "analisis", "ultimo_intento")}
