"""Academic prototype routes; all interactive writes are restricted to the Windows host."""
import hashlib
import hmac
import json
import os
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from uuid import UUID
from typing import Annotated, Literal

import httpx
from fastapi import Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, StrictInt, ValidationError, field_validator
from sqlalchemy import Date, DateTime, case, cast, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from .api import sensor_ids, app, local_only, persist_events
from .sensitive import Redactor, session_redactors
from .analysis_consolidation import structure_result
from .analysis_execution import (AnalysisFailure, AttemptBudget, DEFAULT_ATTEMPT_SECONDS, configuration_failure,
                                 expired, positive_seconds, post_provider, provider_configuration, remaining)
from .analysis_presentation import analytical_sections
from .analysis_model import evaluate_session, scoped_witnesses, session_pattern, resources
from .analysis_semantics import describe_events
from .analysis_trace import DiagnosticTrace
from .terminal_evidence import terminal_context
from .analysis_state import (EXPIRED_MESSAGE, current_inputs, evidence_snapshot, model_parameters, public_state,
                             result_freshness, states_for_sessions)
from .correlation import (action_link, action_observable_query, event_columns, mapping_evidence,
                          mitre_link, observed_correlations)
from .mitre_views import (MitreFilters, analytics, citation_query, mapping_rows, matrix,
                          observable_total, session_groups, technique_groups, technique_record)
from . import ioc_views
from . import safeguard_proposals
from .analysis_report import (BehaviorReport, REPORT_VERSION, analysis_instruction,
                              needs_report_upgrade, observation_context, validate_report_evidence)
from .intelligence import extract_observables, normalized_value, observables, persist_observables
from .intelligence_metrics import calendar_series, observable_totals, technique_count
from .enrichment import enrich
from .realtime import notify_change
from .incident_assessment import assess, IncidentDecision, validate_decision
from .auth.store import require_admin, audit
from .session_report import report_snapshot
from .rag.retrieval import context as retrieve_context, ready_embeddings, select_candidates
from .rag.mitre_evidence import AUTO_CLASSIFICATION, CONTRACTS, VALIDATOR_VERSION
from .rag.validation import validate as validate_mitre
from .rag.pipeline import METHOD, RAG_INSTRUCTION, evidence_sample, facts_for_model

# Legacy backfill compatibility only. New RAG classification NEVER filters by this set.
COWRIE_TECHNIQUES = {"T1110", "T1110.001", "T1059.004", "T1105", "T1082", "T1083",
                     "T1016", "T1033", "T1057", "T1005"}
MODEL_OBSERVABLE_LIMIT = 20


def table(name):
    return app.state.tables[name]


def sensor_sessions():
    sessions = table("sesion")
    return select(sessions.c.id_sesion).where(sessions.c.id_honeypot.in_(sensor_ids()))


def sensor_modality(sensor):
    return next((name for name, identifier in app.state.instances.items() if identifier == sensor), 'desconocido')


def sensor_events():
    events = table("evento")
    return select(events.c.id_evento).where(events.c.id_sesion.in_(sensor_sessions()))


def sensor_actions():
    actions, analyses = table("accion_identificada"), table("analisis_llm")
    return (select(actions.c.id_accion).join(analyses, actions.c.id_analisis == analyses.c.id_analisis)
            .where(analyses.c.id_sesion.in_(sensor_sessions())))


def plain(row):
    return {k: (str(v) if isinstance(v, UUID) else v) for k, v in dict(row).items()}


@app.get("/api/health")
def health():
    try:
        with app.state.engine.connect() as conn:
            conn.execute(select(1))
    except SQLAlchemyError:
        raise HTTPException(503, "Servicio temporalmente no disponible") from None
    return {"status": "ok", "database": "connected", "contrato_ingesta": "tacticlens.ingesta.v2"}


@app.get("/api/operacion", dependencies=[Depends(local_only)])
def operational_status(solo_recolector: bool = False):
    result = {"collector_last_seen": getattr(app.state, "collector_last_seen", None)}
    if solo_recolector:
        return result
    try:
        provider_configuration()
        configured = True
    except AnalysisFailure:
        configured = False
    with app.state.engine.connect() as conn:
        e, a = table("evento"), table("analisis_llm")
        stats = conn.execute(select(func.count().label("eventos"), func.max(e.c.ingresado_en).label("ultima_ingesta"))
                             .where(e.c.id_sesion.in_(sensor_sessions()))).mappings().one()
        checked = conn.scalar(select(func.max(a.c.fecha_fin)).where(a.c.id_sesion.in_(sensor_sessions()),
            a.c.estado == "completado", func.jsonb_typeof(a.c.resultado_estructurado["rag"]["respuesta_proveedor"]) == "object"))
    return {**result, "ingestion": dict(stats), "llm": {"configurado": configured, "disponibilidad_actual": "desconocida",
                                                        "ultima_respuesta_registrada": checked}}


@app.post("/api/ingesta/heartbeat")
def collector_heartbeat(x_api_key: str | None = Header(default=None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, app.state.api_key):
        raise HTTPException(401, "Clave inválida")
    app.state.collector_last_seen = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


@app.post("/api/ingesta/cowrie", dependencies=[Depends(local_only)])
def upload_cowrie(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".json", ".jsonl")):
        raise HTTPException(422, "Seleccione un archivo .json o .jsonl")
    from .cowrie_import import import_events
    return import_events(file.file, persist_events)


@app.get("/api/sesiones/{id_sesion}", dependencies=[Depends(local_only)])
def session_detail(id_sesion: UUID):
    s, e, a = table("sesion"), table("evento"), table("analisis_llm")
    with app.state.engine.connect() as conn:
        row = conn.execute(select(s, select(func.count()).where(e.c.id_sesion == s.c.id_sesion).scalar_subquery().label("eventos")).where(s.c.id_sesion == id_sesion, s.c.id_honeypot.in_(sensor_ids()))).mappings().first()
        if row:
            inputs, _ = current_inputs(conn, app.state.tables, [id_sesion], sensor_ids(), app.state.instances)
            state = states_for_sessions(conn, a, inputs)[id_sesion]
        if row:
            redactor = session_redactors(conn, e, [id_sesion])[id_sesion]
    if not row:
        raise HTTPException(404, "Sesion no encontrada")
    return redactor.payload({**plain(row), "modalidad": sensor_modality(row.id_honeypot), **public_state(state)})


def dashboard_snapshot():
    s, e, a = (table(n) for n in ("sesion", "evento", "analisis_llm"))
    sessions = sensor_sessions()
    filters = ioc_views.IocFilters()
    with app.state.engine.connect() as conn:
        iocs = ioc_views.filtered_scope(conn, app.state.tables, sensor_ids(), app.state.instances, filters)
        mappings = mapping_rows(app.state.tables, sensor_ids(), app.state.instances, MitreFilters()).subquery().c
        observable_counts = dict(conn.execute(observable_totals(iocs.c)).mappings().one())
        counts = dict(conn.execute(select(
            select(func.count()).select_from(s).where(s.c.id_honeypot.in_(sensor_ids())).scalar_subquery().label('sesiones'),
            select(func.count()).select_from(e).where(e.c.id_sesion.in_(sessions)).scalar_subquery().label('eventos'),
            select(func.count(func.distinct(a.c.id_sesion))).where(a.c.estado == 'completado', a.c.id_sesion.in_(sessions)).scalar_subquery().label('sesiones_analizadas'),
            select(technique_count(mappings)).scalar_subquery().label('tecnicas_mitre'),
        )).mappings().one())
        counts.update(iocs=observable_counts['observables'], iocs_verificables=observable_counts['verificables'])
        totals = conn.execute(select(s.c.id_honeypot, func.count(func.distinct(s.c.id_sesion)), func.count(e.c.id_evento))
            .select_from(s.outerjoin(e, e.c.id_sesion == s.c.id_sesion)).where(s.c.id_honeypot.in_(sensor_ids()))
            .group_by(s.c.id_honeypot)).all()
        groups = {sensor: (sessions_count, events_count) for sensor, sessions_count, events_count in totals}
        counts["por_modalidad"] = {label: dict(zip(("sesiones", "eventos"), groups.get(sensor, (0, 0))))
            for label, sensor in {"desconocido": app.state.honeypot_id, **app.state.instances}.items()}
        day = cast(func.timezone('America/Guayaquil', e.c.fecha_hora), Date).label('dia')
        today = datetime.now(ioc_views.ECUADOR).date()
        start = today - timedelta(days=6)
        by_day = conn.execute(select(day, func.count().label('total')).where(e.c.id_sesion.in_(sessions),
            e.c.fecha_hora >= datetime.combine(start, datetime.min.time(), ioc_views.ECUADOR))
            .group_by(day).order_by(day)).mappings().all()
        by_type = conn.execute(select(e.c.tipo_evento, func.count().label("total")).where(e.c.id_sesion.in_(sessions)).group_by(e.c.tipo_evento).order_by(func.count().desc()).limit(8)).mappings().all()
        latest_event = conn.scalar(select(func.max(e.c.fecha_hora)).where(e.c.id_sesion.in_(sessions)))
        commands = conn.execute(select(e.c.id_evento,e.c.id_sesion,e.c.fecha_hora,e.c.datos_originales)
            .where(e.c.tipo_evento=='cowrie.command.input', e.c.id_sesion.in_(sessions))
            .order_by(e.c.fecha_hora.desc(),e.c.id_evento.desc()).limit(5)).mappings().all()
        redactors = session_redactors(conn, e, {row.id_sesion for row in commands})
    recent_commands=[{'id_evento':row['id_evento'],'id_evento_texto':str(row['id_evento']),'id_sesion':str(row['id_sesion']),
        'fecha_hora':row.fecha_hora,'comando':redactors[row.id_sesion].text(str(row.datos_originales.get('input','')))[:2000]}
        for row in commands]
    activity, period = calendar_series(by_day, 'dia', {'total':0}, start=start, end=today)
    return {**counts, "actividad": activity, "periodo_actividad": period,
            "poblacion": {"alcance":"sensores configurados, sin filtros", "iocs":"IoCs únicos observados",
                          "mitre":"técnicas distintas con mapeo registrado, incluye histórico y descartado"},
            "tipos_evento": [plain(x) for x in by_type], "ultimo_evento": latest_event,
            'ultimos_comandos':recent_commands}


@app.get("/api/sesiones/{id_sesion}/informe", dependencies=[Depends(local_only)])
def session_report(id_sesion: UUID, request: Request, formato: Literal["json", "pdf", "docx"] = "json",
                   id_analisis: UUID | None = None, snapshot: str | None = Query(None, max_length=1024),
                   actual: bool = False):
    from .report_snapshot import finalize_report, load_snapshot
    actor = request.state.user.get("id_usuario")
    settings = app.state.auth_settings
    s = table("sesion")
    with app.state.engine.connect() as conn:
        if not conn.in_transaction():
            conn.execution_options(isolation_level="REPEATABLE READ")
        sensor = conn.scalar(select(s.c.id_honeypot).where(s.c.id_sesion == id_sesion, s.c.id_honeypot.in_(sensor_ids())))
        if sensor is None:
            raise HTTPException(404, "Sesión no encontrada")
        pinned = None
        if snapshot:
            pinned, id_analisis = load_snapshot(settings, snapshot, id_sesion, id_analisis, actor)
        elif formato != "json" and not actual:
            raise HTTPException(428, "Abra la vista previa antes de exportar o solicite explícitamente un informe actual.")
        report = report_snapshot(conn, app.state.tables, sensor, id_sesion, analysis_id=id_analisis,
                                 modality=sensor_modality(sensor), sensors=sensor_ids(), instances=app.state.instances)
    report, token = finalize_report(settings, report, actor, pinned)
    if formato == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse({**report,"snapshot":snapshot or token}, headers={"Cache-Control": "no-store, private"})
    from .report_export import PDF_TYPE, WORD_TYPE, render_docx, render_pdf

    try:
        content, media_type = (render_pdf(report), PDF_TYPE) if formato == "pdf" else (render_docx(report), WORD_TYPE)
    except (subprocess.SubprocessError, OSError):
        raise HTTPException(503, "No se pudo generar el archivo. Verifique el motor de exportación y vuelva a intentar") from None
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="TacticLens-{id_sesion}-{id_analisis or "actual"}.{formato}"',
        "X-TacticLens-Snapshot": report["snapshot_id"],
        "Cache-Control": "no-store, private",
    })


@app.get("/api/dashboard/resumen", dependencies=[Depends(local_only)])
def dashboard():
    result = app.state.dashboard_cache.get((app.state.engine, app.state.honeypot_id), dashboard_snapshot)
    return {**result, 'collector_last_seen': getattr(app.state, 'collector_last_seen', None)}


class IocProposal(BaseModel):
    tipo: str
    valor: str | None = None
    evento: int
    referencia: int | None = None
    evidencia: str = "Observable vinculado por el análisis"
    confianza: float = Field(default=0.7, ge=0, le=1)


class MitreProposal(BaseModel):
    codigo: str
    codigo_tactica: str | None = None
    comportamiento_observado: str | None = Field(default=None,max_length=500)
    justificacion: str = Field(default='',max_length=3000)
    confianza: float = Field(default=0.5, ge=0, le=1)
    eventos: list[StrictInt] = Field(default_factory=list)
    grado_evidencia: Literal['intento','resultado_en_honeypot'] = 'intento'
    limitaciones: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    tipo: str = Field(min_length=1, max_length=80)
    descripcion: str = Field(min_length=1)
    confianza: float = Field(ge=0, le=1)
    eventos: list[StrictInt] = Field(min_length=1)
    iocs: list[IocProposal] = Field(default_factory=list)
    mitre: list[MitreProposal] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    resumen: str = Field(min_length=1)
    acciones: list[Finding]
    informe: BehaviorReport | None = None


def extract_iocs(command, event_id):
    return [{"tipo": kind, "valor": value, "evento": event_id}
            for kind, value, _ in observables({"eventid": "cowrie.command.input", "input": command})]


def mitre_catalog():
    tt, tech, tac = (table(n) for n in ("tecnica_tactica", "tecnica_mitre", "tactica_mitre"))
    with app.state.engine.connect() as conn:
        catalog = conn.execute(select(tech.c.codigo_tecnica, tech.c.nombre, tac.c.nombre.label("tactica"))
            .join(tt, tech.c.codigo_tecnica == tt.c.codigo_tecnica)
            .join(tac, tac.c.codigo_tactica == tt.c.codigo_tactica)
            .where(~tech.c.revocada,~tech.c.deprecada,tt.c.activa_en_catalogo)).mappings().all()
    return [dict(row) for row in catalog]


def rag_context(events, modality='desconocido', sample=None):
    return retrieve_context(app.state.engine,events,modality=modality,sample=sample)


def event_observables(events):
    return {event.id_evento: tuple(extract_observables(event.datos_originales or {})) for event in events}


def supported_proposals(action, by_event):
    """Match the complete normalized value and type in the exact cited event."""
    for proposal in action.iocs:
        if proposal.evento not in action.eventos or proposal.evento not in by_event:
            yield proposal, None, "evento_ajeno_a_la_accion"
            continue
        items = by_event[proposal.evento]
        value = None
        if proposal.valor is not None:
            try:
                value = normalized_value(proposal.tipo, proposal.valor)
            except ValueError:
                yield proposal, None, "tipo_o_formato_invalido"
                continue
        if proposal.referencia is not None:
            index = proposal.referencia - 1
            if not 0 <= index < min(len(items), MODEL_OBSERVABLE_LIMIT):
                yield proposal, None, "referencia_invalida"
                continue
            item = items[index]
            if item.tipo == proposal.tipo and (value is None or item.valor == value):
                yield proposal, item.valor, None
                continue
        elif value is not None and any(item.tipo == proposal.tipo and item.valor == value for item in items):
            yield proposal, value, None
            continue
        yield proposal, None, "sin_evidencia_determinista"


def real_result(events, rag=None, trace=None, *, send=None, max_output_tokens=None):
    base, model, key, provider_timeout = provider_configuration()
    rag = rag if rag is not None else rag_context(events)
    sample = evidence_sample(events,rag.get('modalidad','desconocido'))
    facts = facts_for_model(sample, secret_source=events)
    modality = rag.get("modalidad","desconocido")
    admissible, _, _, _ = scoped_witnesses(sample, modality)
    behaviors = describe_events(sample, modality, admissible, resources)
    for fact in facts:
        # The provider receives server-derived semantics. Raw shell text, URL values,
        # paths and endpoint addresses are unnecessary for proposing cited statements.
        data = fact["datos"]
        allowed = {"eventid","protocol","dst_port","duration","duration_ms","size","username","password"}
        fact["datos"] = {key:value for key,value in data.items() if key in allowed}
    tty_refs = [event.id_evento for event in sample if event.tipo_evento=="cowrie.log.closed"
                and isinstance(event.datos_originales.get("ttylog"),str) and event.datos_originales["ttylog"].strip()]
    # Values remain in the usual redacted facts; the supplemental list carries
    # only provenance and references, keeping full URLs and query values local.
    observed = {str(event_id): [{"referencia": index, "tipo": item.tipo, "campo": item.campo,
                                "comportamiento": item.comportamiento, "grado_evidencia": item.grado_evidencia}
                               for index, item in enumerate(items[:MODEL_OBSERVABLE_LIMIT], start=1)]
                for event_id, items in event_observables(sample).items() if items}
    witnesses = defaultdict(list)
    for witness in admissible:
        witnesses[witness.code].append({"eventos":list(witness.ids),"grado":witness.grade})
    candidates = []
    for row in rag["candidatos"]:
        code = row["codigo_tecnica"]
        if code not in witnesses or row.get("revocada") or row.get("deprecada"):
            continue
        contract = CONTRACTS[code]
        tactics = [t for t in row["tacticas"] if not contract.tactics or t["codigo_tactica"] in contract.tactics]
        if tactics:
            candidates.append({"codigo_tecnica":code,"nombre":row["nombre"],"tacticas":tactics,
                               "testigos":witnesses[code]})
    payload = {"contexto_calculado": observation_context(events), "eventos": facts,
               "observables_por_evento": observed,
               "tecnicas_mitre_permitidas": candidates,'catalogo':rag['catalogo'],
               'comportamiento_observado':[b.public() for b in behaviors.values()],
               'referencias_tty':tty_refs,
               'muestreo':{'eventos_snapshot':len(events),'eventos_en_prompt':len(facts)},
               'enriquecimiento_verificado':rag.get('enriquecimiento_prompt', {}),
               'modalidad_sensor':rag.get('modalidad','desconocido'),
               'evidencia_mitre':{c["codigo_tecnica"]: c["testigos"] for c in candidates}}
    payload["criterios_triaje"] = {"criterios": assess(events)["criterios"]}
    terminal, terminal_counts = terminal_context(events, {event.id_evento for event in sample}, modality)
    payload["evidencia_terminal"] = {"registros":terminal, "cobertura":terminal_counts}
    redactor = Redactor(event.datos_originales for event in events)
    payload = redactor.payload(payload)
    if trace:
        trace.record("contexto_entregado",payload)
    parameters = model_parameters()
    if max_output_tokens is not None:
        parameters["max_tokens"] = max_output_tokens
    request_body={"model":model,**parameters,"messages":[
            {"role":"system","content":analysis_instruction()+RAG_INSTRUCTION},
            {"role":"user","content":json.dumps(payload,ensure_ascii=False,default=str)}]}
    rag['solicitud_sha256']=hashlib.sha256(json.dumps(request_body,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()
    started=time.perf_counter();requested_at=datetime.now(timezone.utc)
    try:
        response = (send or post_provider)(base + "/chat/completions", headers={"Authorization": f"Bearer {key}"},
            json=request_body,timeout=remaining("proveedor", provider_timeout))
        response.raise_for_status()
    except httpx.TimeoutException:
        raise AnalysisFailure("proveedor", "timeout_proveedor", "El proveedor LLM agotó su tiempo de respuesta.", True, 504) from None
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in (401, 403):
            raise configuration_failure("El proveedor LLM rechazó la autenticación.") from None
        raise AnalysisFailure("proveedor", "proveedor_http", "El proveedor LLM rechazó la solicitud.",
                              status in (408, 429) or status >= 500) from None
    except httpx.RequestError:
        raise AnalysisFailure("proveedor", "proveedor_no_disponible", "No se pudo conectar con el proveedor LLM.", True) from None
    try:
        body = response.json()
        usage = body.get('usage') or {}
        choice = body["choices"][0]
        if choice.get("finish_reason") == "length":
            raise AnalysisFailure("validacion", "respuesta_truncada", "El proveedor truncó el informe.", False)
        content = choice["message"]["content"]
        if not isinstance(content, str) or not content.strip() or not isinstance(usage, dict):
            raise ValueError
        result = AnalysisResult.model_validate_json(content)
        if result.informe is None:
            raise AnalysisFailure("validacion", "informe_incompleto", "El proveedor omitió el informe detallado.", False)
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        raise AnalysisFailure("validacion", "respuesta_invalida", "El proveedor devolvió un informe incompleto o incompatible.", False) from None
    try:
        validate_report_evidence(result.informe, {event.id_evento for event in sample})
    except ValueError:
        raise AnalysisFailure("validacion", "citas_invalidas", "El informe cita eventos ajenos a la evidencia entregada.", False) from None
    fields=('prompt_tokens','completion_tokens','total_tokens','prompt_cache_hit_tokens','prompt_cache_miss_tokens')
    rag['respuesta_proveedor']={'solicitado_en':requested_at.isoformat(),'duracion_segundos':round(time.perf_counter()-started,3),
        'modelo_reportado':redactor.text(str(body.get('model',model)))[:160],
        'uso':{field:usage[field] for field in fields if type(usage.get(field)) is int and usage[field]>=0}}
    if trace:
        trace.record("propuestas_estructuradas",result.model_dump(exclude_none=True))
    return result


def ensure_model(conn):
    t = table("modelo_llm")
    provider = os.getenv("LLM_PROVIDER", "openai")
    name = os.getenv("LLM_MODEL", "")
    if not name:
        raise ValueError("LLM_MODEL requerida")
    conn.execute(insert(t).values(proveedor=provider, nombre_modelo=name, version_modelo="demo").on_conflict_do_nothing(index_elements=["proveedor", "nombre_modelo", "version_modelo"]))
    return conn.scalar(select(t.c.id_modelo).where(t.c.proveedor == provider, t.c.nombre_modelo == name, t.c.version_modelo == "demo"))


@app.post("/api/sesiones/{id_sesion}/analizar", dependencies=[Depends(local_only)])
def analyze(id_sesion: UUID, actualizar_informe: bool = False, actualizar_rag: bool = False):
    try:
        return execute_analysis(id_sesion, actualizar_informe, actualizar_rag)
    except SQLAlchemyError:
        failure = AnalysisFailure("persistencia", "inicio_no_disponible",
                                  "No se pudo reservar el análisis. Intente de nuevo.", True, 503)
        raise HTTPException(failure.status, failure.public()) from None


def execute_analysis(id_sesion, actualizar_informe, actualizar_rag):
    s, e, a = table("sesion"), table("evento"), table("analisis_llm")
    catalogs=table('catalogo_mitre')
    # Lock the session row while deciding whether to reuse or start an analysis.
    # Concurrent requests serialize here, including requests from another worker.
    with app.state.engine.begin() as conn:
        conn.execute(text("SET LOCAL lock_timeout = '5s'"))
        conn.execute(text("SET LOCAL statement_timeout = '15s'"))
        session = conn.execute(
            select(s).where(s.c.id_sesion == id_sesion, s.c.id_honeypot.in_(sensor_ids())).with_for_update()
        ).mappings().first()
        if session is None:
            raise HTTPException(404, "Sesion no encontrada")
        sensor = session.id_honeypot
        modality=sensor_modality(sensor)
        inputs, config = current_inputs(conn, app.state.tables, [id_sesion], sensor_ids(), app.state.instances)
        current_input = inputs[id_sesion]
        if not current_input["eventos_total"]:
            raise HTTPException(422, "La sesion no tiene eventos")
        catalog = config["catalogo"]
        state = states_for_sessions(conn, a, inputs)[id_sesion]
        if state["intento_expirado_id"]:
            old_id = state["intento_expirado_id"]
            ended = conn.execute(a.update().where(a.c.id_analisis == old_id,
                a.c.estado == "en_proceso").values(
                estado="fallido", fecha_fin=func.clock_timestamp(), mensaje_error=EXPIRED_MESSAGE,
                actualizado_en=func.clock_timestamp()
            ))
            if not ended.rowcount:
                state = states_for_sessions(conn, a, inputs)[id_sesion]
            else:
                notify_change(conn, [sensor], "analisis")
        if state["analisis_en_proceso"]:
            raise HTTPException(409, "El analisis de esta sesion ya esta en proceso")
        if catalog and state['analisis_vigente_id']:
            saved=conn.scalar(select(a.c.resultado_estructurado).where(a.c.id_analisis==state['analisis_vigente_id']))
            upgrade = (actualizar_informe and needs_report_upgrade(saved)
                       or actualizar_rag and (saved.get('rag') or {}).get('metodo')!=METHOD)
            if not upgrade:
                redactor = session_redactors(conn, e, [id_sesion])[id_sesion]
                return redactor.payload({"id_analisis": str(state["analisis_vigente_id"]), "estado": "completado", "modo": "real",
                        "reutilizado": True, "clasificacion_mitre":saved.get('clasificacion_mitre'),
                        "evaluacion_amenaza": saved.get("evaluacion_amenaza")})
        try:
            provider_configuration()
            duration = positive_seconds("LLM_ANALYSIS_TIMEOUT_SECONDS", DEFAULT_ATTEMPT_SECONDS)
            if not catalog or not catalog["sha256"]:
                raise configuration_failure("Importe y active el catálogo MITRE antes de analizar.")
            ready_embeddings(conn, catalog["id_catalogo"])
        except AnalysisFailure as failure:
            raise HTTPException(failure.status, failure.public()) from None
        except RuntimeError:
            failure = configuration_failure("Genere los embeddings del catálogo MITRE activo antes de analizar.")
            raise HTTPException(failure.status, failure.public()) from None
        events = conn.execute(select(e.c.id_evento, e.c.tipo_evento, e.c.fecha_hora, e.c.datos_originales, e.c.id_sesion)
            .where(e.c.id_sesion == id_sesion).order_by(e.c.fecha_hora, e.c.id_evento)).all()
        redactor = Redactor(item.datos_originales for item in events)
        evidence = evidence_snapshot(events)
        snapshot = {key: current_input[key] for key in ("version", "revision_eventos", "metodologia_sha256", "contexto_sha256")}
        snapshot.update(evidence)
        snapshot["sesiones_contexto"] = [str(sid) for sid in current_input["sesiones_contexto"]]
        snapshot["prompt_sha256"] = config["prompt_sha256"]
        history = comparable_sessions(conn, s, e, current_input["sesiones_contexto"], current_input["limite_contexto"])
        model_id = ensure_model(conn)
        budget = AttemptBudget(duration)
        started = conn.scalar(select(func.clock_timestamp()))
        deadline = started + timedelta(seconds=duration)
        execution = {"vence_en": deadline.isoformat()}
        pending = {"vigencia_snapshot": snapshot, "ejecucion": execution}
        analysis_id = conn.scalar(insert(a).values(
            id_sesion=id_sesion, id_modelo=model_id, estado="en_proceso", fecha_inicio=started, creado_en=started,
            resultado_estructurado=pending
        ).returning(a.c.id_analisis))
        notify_change(conn, [sensor], "analisis")
    trace = DiagnosticTrace.configured()
    phase = "recuperacion_rag"
    active = (a.c.id_analisis == analysis_id, a.c.estado == "en_proceso",
              cast(a.c.resultado_estructurado["ejecucion"]["vence_en"].astext, DateTime(timezone=True)) > func.clock_timestamp())
    try:
        sample=evidence_sample(events,modality)
        rag=budget.run(phase, lambda: rag_context(events,modality,sample))
        if not catalog or str(catalog["id_catalogo"])!=rag['catalogo']['id_catalogo'] or catalog["sha256"]!=rag['catalogo']['sha256']:
            raise ValueError('El catálogo cambió; vuelva a analizar')
        rag['candidatos']=select_candidates(rag['candidatos'])
        rag['modelo_llm']={'proveedor':os.getenv('LLM_PROVIDER','openai'),'modelo':os.getenv('LLM_MODEL','')}
        rag['modalidad']=modality
        rag['version_pipeline']=config["pipeline"]
        rag['eventos_entregados']=[e.id_evento for e in sample]
        rag['eventos_snapshot']=len(events)
        phase = "enriquecimiento"
        enrichment = budget.run(phase, lambda: enrich(events))
        # Provider identifiers and URLs are server-owned. The model sees only
        # bounded status and event references, never external keys or raw URLs.
        rag['enriquecimiento_prompt'] = [{"tipo": item['tipo'], "eventos": item['eventos'],
            "proveedores": {name: ({"estado": value.get('estado')} if isinstance(value, dict) else
                                    {"coincidencias": len(value)}) for name, value in item['proveedores'].items()}}
            for item in enrichment['observables']]
        phase = "proveedor"
        result = budget.run(phase, lambda: real_result(events,rag=rag,trace=trace) if trace.enabled else real_result(events,rag=rag))
        phase = "validacion"
        (by_event, provenance, discarded, rejected_iocs, classification, unvalidated, structured,
         incident_assessment) = budget.run(phase, lambda: evaluate_output(
            result, rag, events, session, modality, history, enrichment, trace))
        # Results and all linked findings commit together. A failure leaves no partial IoCs.
        phase = "persistencia"
        with app.state.engine.begin() as conn:
            milliseconds = str(max(1, int(budget.left(phase) * 1000)))
            conn.execute(text("SELECT set_config('statement_timeout', :ms, true)"), {"ms": milliseconds})
            if conn.dialect.server_version_info >= (17,):
                conn.execute(text("SELECT set_config('transaction_timeout', :ms, true)"), {"ms": milliseconds})
            conn.execute(text('SELECT pg_advisory_xact_lock(724610902)'))
            current=conn.execute(select(catalogs.c.id_catalogo,catalogs.c.sha256).where(catalogs.c.activo)).one_or_none()
            if not current or str(current.id_catalogo)!=rag['catalogo']['id_catalogo'] or current.sha256!=catalog["sha256"]:
                raise ValueError('El catálogo cambió; vuelva a analizar')
            if not conn.scalar(select(a.c.id_analisis).where(*active).with_for_update()):
                raise expired(phase)
            action_ids = persist_findings(conn, analysis_id, result, events, rag=rag, provenance=provenance,
                                          by_event=by_event, redactor=redactor)
            for action_data, action_id in zip(structured["acciones"], action_ids, strict=True):
                action_data["id_accion_relacional"] = str(action_id)
            persisted = {**structured, "eventos_analizados":len(events), "version_informe":REPORT_VERSION if result.informe else 1,
                         "mapeos_descartados":discarded, "propuestas_ioc_descartadas":rejected_iocs, "rag":rag,
                         "clasificacion_mitre":classification,
                         "candidatas_mitre_no_validadas":unvalidated, "enriquecimiento":enrichment,
                         "evaluacion_incidente":incident_assessment}
            from .safeguards import register_recommendations
            persisted = redactor.payload(persisted)
            persisted["vigencia_snapshot"] = snapshot
            persisted["ejecucion"] = execution
            register_recommendations(conn, app.state.tables, analysis_id, id_sesion, persisted)
            budget.left(phase)
            completed = conn.execute(a.update().where(*active).values(
                estado="completado", fecha_fin=func.clock_timestamp(), resumen=redactor.text(result.resumen),
                resultado_estructurado=persisted, actualizado_en=func.clock_timestamp()
            ))
            if not completed.rowcount:
                raise expired(phase)
            notify_change(conn, [sensor], "analisis", "iocs", "mitre", "salvaguardas", "panel")
    except Exception as exc:
        messages = {"recuperacion_rag": "No se pudo recuperar el contexto MITRE.",
                    "enriquecimiento": "No se pudo preparar el enriquecimiento de observables.",
                    "proveedor": "El proveedor LLM no está disponible.",
                    "validacion": "El resultado contiene evidencia o datos incompatibles.",
                    "persistencia": "No se pudo guardar el análisis. Los resultados anteriores siguen disponibles."}
        failure = (exc if isinstance(exc, AnalysisFailure) else
                   expired(phase) if getattr(getattr(exc, "orig", None), "sqlstate", None) == "57014" else
                   AnalysisFailure(phase, f"fallo_{phase}", messages[phase], phase != "validacion"))
        try:
            budget.left(phase)
        except AnalysisFailure as timed_out:
            failure = timed_out
        metadata = failure.public(analysis_id)
        if trace.enabled:
            trace.record_failure(failure)
            trace.write(analysis_id)
        try:
            with app.state.engine.begin() as conn:
                conn.execute(text("SET LOCAL statement_timeout = '5s'"))
                failed = conn.execute(a.update().where(a.c.id_analisis == analysis_id, a.c.estado == "en_proceso").values(
                    estado="fallido", fecha_fin=func.clock_timestamp(), mensaje_error=str(failure),
                    resultado_estructurado={**pending, "ejecucion": {**execution, "error": metadata}},
                    actualizado_en=func.clock_timestamp()
                ))
                if failed.rowcount:
                    notify_change(conn, [sensor], "analisis")
        except SQLAlchemyError:
            # The persisted deadline still lets clients recover from an unavailable database.
            failure = AnalysisFailure("persistencia", "registro_fallo_no_disponible",
                                      "No se pudo registrar el fallo. El intento vencerá al agotar su plazo.", True, 503)
        raise HTTPException(failure.status, failure.public(analysis_id)) from None
    if trace.enabled:
        trace.record("persistencia_confirmada", persisted)
        trace.write(analysis_id)
    return redactor.payload({"id_analisis": str(analysis_id), "estado": "completado", "modo": "real", "reutilizado": False,
            "clasificacion_mitre":classification, "evaluacion_amenaza": structured["evaluacion_amenaza"]})


def evaluate_output(result, rag, events, session, modality, history, enrichment, trace):
    if trace.enabled:
        trace.record("propuestas_estructuradas", result.model_dump(exclude_none=True))
    valid_ids = {x.id_evento for x in events}
    validate_report_evidence(result.informe, valid_ids & set(rag["eventos_entregados"]))
    by_event = event_observables(events)
    rejected_iocs = []
    delivered = set(rag['eventos_entregados'])
    for action_index, action in enumerate(result.acciones):
        if not set(action.eventos) <= valid_ids or not set(action.eventos) <= delivered:
            raise ValueError("El LLM cito eventos ajenos a la sesion")
        accepted = {}
        for proposal, value, reason in supported_proposals(action, by_event):
            if reason:
                rejected_iocs.append({"accion": action_index, "evento": proposal.evento, "motivo": reason})
            else:
                accepted.setdefault((proposal.evento, proposal.tipo, value), proposal.model_copy(update={"valor": value}))
        action.iocs = list(accepted.values())
    diagnostics,provenance = validate_mitre(result,events,rag)
    if trace.enabled:
        trace.record("validacion", {"resultado":result.model_dump(exclude_none=True),"descartes_mitre":diagnostics,
                                    "descartes_ioc":rejected_iocs})
    unvalidated=[item for item in diagnostics if item['estado']=='candidata_no_validada']
    discarded=[item for item in diagnostics if item['estado']=='descartada']
    classification={
        'estado':AUTO_CLASSIFICATION if provenance else 'no_determinada',
        'modalidad':modality,'version_validador':VALIDATOR_VERSION,
        'candidatas_no_validadas':len(unvalidated),
        'motivo':('Modalidad sin reglas verificadas de clasificación automática.' if not any(modality in c.modes for c in CONTRACTS.values())
                  else 'Ninguna propuesta cumplió los criterios de evidencia específica.' if not provenance else None),
    }
    evaluated = evaluate_session(events, delivered, session, modality, history)
    decisions = {} if trace.enabled else None
    structured = structure_result(result, evaluated, delivered, modality, by_event, enrichment, decisions=decisions)
    incident_assessment = assess(events, structured["evaluacion_amenaza"], structured["evaluacion_impacto"])
    if trace.enabled:
        trace.record("consolidacion", {"resultado":structured,"motivos_por_campo":decisions})
    return by_event, provenance, discarded, rejected_iocs, classification, unvalidated, structured, incident_assessment


def comparable_sessions(conn, sessions, event, candidates, upper):
    """Reconstruct behaviors only when starting a new analysis."""
    if not candidates:
        return []
    grouped = defaultdict(list)
    result = conn.execute(select(event.c.id_evento, event.c.tipo_evento, event.c.fecha_hora,
        event.c.datos_originales, event.c.id_sesion, sessions.c.id_honeypot, sessions.c.ip_origen)
        .join(sessions,sessions.c.id_sesion==event.c.id_sesion)
        .where(event.c.id_sesion.in_(candidates), event.c.fecha_hora <= upper)
        .order_by(event.c.fecha_hora, event.c.id_evento))
    for item in result:
        grouped[item.id_sesion].append(item)
    history = []
    for session_id, records in grouped.items():
        previous = records[0]
        previous_mode = sensor_modality(previous.id_honeypot)
        mitre, extra, _, _ = scoped_witnesses(records, previous_mode)
        history.append(session_pattern({"id_sesion":session_id,"id_honeypot":previous.id_honeypot,
                                        "ip_origen":previous.ip_origen,"modalidad":previous_mode}, mitre + extra, records))
    return history


def persist_findings(conn, analysis_id, result, events, rag=None, provenance=None, by_event=None, redactor=None):
    redactor = redactor or Redactor(event.datos_originales for event in events)
    action_t, link_t = table("accion_identificada"), table("accion_evento")
    mitre_t, mapping_t = table("tecnica_tactica"), table("mapeo_mitre")
    detection_t, action_ioc_t = table("deteccion_ioc"), table("accion_ioc")
    original_events = {event.id_evento: event for event in events}
    by_event = event_observables(events) if by_event is None else by_event
    observed = {}
    action_ids = []
    for action_index,finding in enumerate(result.acciones):
        action_id = conn.scalar(insert(action_t).values(id_analisis=analysis_id,
            tipo_accion=redactor.text(finding.tipo)[:80], descripcion=redactor.text(finding.descripcion),
            confianza=finding.confianza).returning(action_t.c.id_accion))
        action_ids.append(action_id)
        for event_id in finding.eventos:
            if event_id not in original_events:
                raise ValueError("Evidencia ajena a la sesión")
            conn.execute(insert(link_t).values(id_accion=action_id, id_evento=event_id, evidencia=f"Evento Cowrie {event_id}"))
        for proposed, value, reason in supported_proposals(finding, by_event):
            if reason:
                continue
            event_id = proposed.evento
            if event_id not in observed:
                event = original_events[event_id]
                observed[event_id] = persist_observables(conn, app.state.tables, event.datos_originales,
                    event_id, event.fecha_hora, extracted=by_event[event_id])
            identity = observed[event_id].get((proposed.tipo, value))
            if identity is None:
                raise RuntimeError("Falta el tipo de observable en el catálogo local")
            ioc_id, observation_id = identity
            detection_id = conn.scalar(insert(detection_t).values(
                id_ioc=ioc_id, id_analisis=analysis_id, id_evento=event_id, id_observacion=observation_id,
                evidencia=redactor.text(proposed.evidencia)[:500] or "Observable vinculado por el análisis",
                confianza=proposed.confianza).on_conflict_do_nothing(
                index_elements=["id_ioc", "id_analisis", "id_evento"]).returning(detection_t.c.id_deteccion))
            if detection_id is None:
                detection_id = conn.scalar(select(detection_t.c.id_deteccion).where(
                    detection_t.c.id_ioc == ioc_id, detection_t.c.id_analisis == analysis_id,
                    detection_t.c.id_evento == event_id))
            conn.execute(insert(action_ioc_t).values(id_accion=action_id, id_deteccion=detection_id)
                .on_conflict_do_nothing(index_elements=["id_accion", "id_deteccion"]))
        for proposed in finding.mitre:
            if not rag or provenance is None:raise ValueError('Se requiere contexto RAG validado')
            code = proposed.codigo
            te=table('tecnica_mitre');meta=provenance[(action_index,code,proposed.codigo_tactica)]
            if meta.get('clasificacion')!=AUTO_CLASSIFICATION or not meta.get('citas_explicitas') or not proposed.eventos:
                raise ValueError('El mapeo requiere clasificación validada y citas explícitas')
            tactic=table('tactica_mitre')
            match = conn.scalar(select(mitre_t.c.id_vinculo).join(te,mitre_t.c.codigo_tecnica==te.c.codigo_tecnica)
                .join(tactic,mitre_t.c.codigo_tactica==tactic.c.codigo_tactica).where(
                mitre_t.c.codigo_tecnica==code,mitre_t.c.codigo_tactica==proposed.codigo_tactica,
                mitre_t.c.activa_en_catalogo,~te.c.revocada,~te.c.deprecada,
                mitre_t.c.id_catalogo==te.c.id_catalogo,tactic.c.id_catalogo==te.c.id_catalogo,~tactic.c.revocada,~tactic.c.deprecada,
                te.c.id_catalogo==UUID(rag['catalogo']['id_catalogo']),te.c.objeto_sha256==meta['definicion_sha256']))
            if not match:raise ValueError('La tecnica o relacion oficial dejo de estar vigente')
            mapping_id = conn.scalar(insert(mapping_t).values(id_accion=action_id,id_vinculo=match,
                evidencia=f"Eventos: {', '.join(map(str,proposed.eventos))}",justificacion=redactor.text(proposed.justificacion),
                confianza=proposed.confianza,rag_procedencia=redactor.payload({**meta,'modelo_llm':rag['modelo_llm']}),
                grado_evidencia=proposed.grado_evidencia).returning(mapping_t.c.id_mapeo))
            citations = table("mapeo_mitre_evento")
            conn.execute(insert(citations), [
                {"id_mapeo": mapping_id, "id_accion": action_id, "id_evento": event_id, "metodo": "rag_validado_v1"}
                for event_id in proposed.eventos])
    return action_ids


@app.get("/api/analisis/{id_analisis}", dependencies=[Depends(local_only)])
def get_analysis(id_analisis: UUID):
    from .safeguards import linked_tasks
    a, action, link = (table(n) for n in ("analisis_llm", "accion_identificada", "accion_evento"))
    with app.state.engine.connect() as conn:
        row = conn.execute(select(a).where(a.c.id_analisis == id_analisis, a.c.id_sesion.in_(sensor_sessions()))).mappings().first()
        if not row:
            raise HTTPException(404, "Análisis no encontrado")
        actions = conn.execute(select(action).where(action.c.id_analisis == id_analisis)).mappings().all()
        ids = [item.id_accion for item in actions]
        evidence, mappings, observables_by_action = defaultdict(list), defaultdict(list), defaultdict(list)
        if ids:
            for citation in conn.execute(select(link.c.id_accion, link.c.id_evento)
                                         .where(link.c.id_accion.in_(ids)).order_by(link.c.id_evento)):
                evidence[citation.id_accion].append(citation.id_evento)
            for mapping in mapping_evidence(conn, app.state.tables, action_ids=ids):
                mappings[mapping["id_accion"]].append(mapping)
            for detected in conn.execute(action_observable_query(app.state.tables)
                                         .where(action.c.id_accion.in_(ids))).mappings():
                relation = action_link(detected)
                if relation["vinculo_determinista"]:
                    observables_by_action[detected.id_accion].append(relation)
        output = [{**plain(item), "eventos": evidence[item.id_accion],
                   "eventos_texto": [str(event_id) for event_id in evidence[item.id_accion]], "mitre": mappings[item.id_accion],
                   "observables": observables_by_action[item.id_accion]} for item in actions]
        safeguard_links = linked_tasks(conn, app.state.tables, id_analisis)
        redactor = session_redactors(conn, table("evento"), [row.id_sesion])[row.id_sesion]
        inputs, _ = current_inputs(conn, app.state.tables, [row.id_sesion], sensor_ids(), app.state.instances)
        state = states_for_sessions(conn, a, inputs)[row.id_sesion]
        freshness = result_freshness(row.resultado_estructurado, inputs[row.id_sesion]) if row.estado == "completado" else None
    from .analysis_report import safeguard_cards
    payload = redactor.payload(row.resultado_estructurado)
    additions = {item["id_accion_relacional"]: item for item in (payload or {}).get("acciones", [])
                 if "id_accion_relacional" in item}
    for item in output:
        if structured := additions.get(str(item["id_accion"])):
            item["evaluacion_tecnica"] = {key: structured[key] for key in
                ("id_accion", "recurso_objetivo", "estado", "resultado", "grado_evidencia", "confianza_analitica")}
    report = (payload or {}).get("informe") or {}
    for item in (report.get("fases") or []) + (report.get("hipotesis") or []):
        item["eventos_texto"] = [str(eid) for eid in item.get("eventos", [])]
    projected = redactor.payload({**plain(row), "resultado_estructurado": payload, "acciones": output,
            "salvaguardas": safeguard_cards(report.get("recomendaciones") or [], payload or {}, safeguard_links),
            "presentacion_analitica": analytical_sections(payload or {})})
    return {**projected, "vigencia_analisis": freshness, "estado_ultimo_intento": state["estado_ultimo_intento"],
            "ultimo_resultado_exitoso": state["analisis"]}


@app.post("/api/analisis/{id_analisis}/evaluacion-incidente", dependencies=[Depends(local_only)])
def review_incident(id_analisis: UUID, decision: IncidentDecision, request: Request):
    analysis = table("analisis_llm")
    with app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        row = conn.execute(select(analysis).where(analysis.c.id_analisis == id_analisis,
            analysis.c.id_sesion.in_(sensor_sessions())).with_for_update()).mappings().first()
        if row is None:
            raise HTTPException(404, "Análisis no encontrado")
        if row.estado != "completado":
            raise HTTPException(409, "Se requiere un análisis completado")
        payload = dict(row.resultado_estructurado or {})
        assessment = dict(payload.get("evaluacion_incidente") or {})
        if not assessment:
            raise HTTPException(409, "El análisis histórico requiere preparar su evaluación")
        revisions = list(assessment.get("revisiones", []))
        if decision.revision_esperada != len(revisions):
            raise HTTPException(409, "La evaluación cambió. Recargue antes de guardar")
        valid_ids = {int(eid) for eid in assessment["eventos"]}
        try:
            validate_decision(decision, valid_ids)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        revision = {**decision.model_dump(exclude={"revision_esperada"}), "eventos": [str(eid) for eid in decision.eventos],
                    "revisado_por": str(actor.id_usuario), "revisado_en": datetime.now(timezone.utc).isoformat()}
        redactor = session_redactors(conn, table("evento"), [row.id_sesion])[row.id_sesion]
        revisions.append(redactor.payload(revision))
        assessment.update(revisiones=revisions, estado=decision.estado, clasificacion=decision.decision,
                          severidad=decision.severidad)
        payload["evaluacion_incidente"] = assessment
        conn.execute(analysis.update().where(analysis.c.id_analisis == id_analisis).values(
            resultado_estructurado=payload, actualizado_en=func.clock_timestamp()))
        audit(conn, request, "evaluacion_incidente_revisada", actor=actor.id_usuario,
              reason=f"{id_analisis}:{decision.decision}:{decision.estado}")
        sessions = table("sesion")
        sensor = conn.scalar(select(sessions.c.id_honeypot).where(sessions.c.id_sesion == row.id_sesion))
        notify_change(conn, [sensor], "analisis")
    return redactor.payload(assessment)


@app.post("/api/analisis/{id_analisis}/preparar-evaluacion", dependencies=[Depends(local_only)])
def prepare_incident(id_analisis: UUID, request: Request):
    analysis, event = table("analisis_llm"), table("evento")
    with app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        row = conn.execute(select(analysis).where(analysis.c.id_analisis == id_analisis,
            analysis.c.id_sesion.in_(sensor_sessions())).with_for_update()).mappings().first()
        if row is None:
            raise HTTPException(404, "Análisis no encontrado")
        if row.estado != "completado":
            raise HTTPException(409, "Se requiere un análisis completado")
        payload = dict(row.resultado_estructurado or {})
        if payload.get("evaluacion_incidente"):
            redactor = session_redactors(conn, event, [row.id_sesion])[row.id_sesion]
            return redactor.payload(payload["evaluacion_incidente"])
        events = conn.execute(select(event.c.id_evento, event.c.tipo_evento, event.c.fecha_hora,
            event.c.datos_originales).where(event.c.id_sesion == row.id_sesion)
            .order_by(event.c.fecha_hora, event.c.id_evento)).all()
        assessment = Redactor(item.datos_originales for item in events).payload(assess(events))
        assessment["origen"] = "Evaluación posterior sobre los eventos actualmente almacenados de la sesión"
        payload["evaluacion_incidente"] = assessment
        conn.execute(analysis.update().where(analysis.c.id_analisis == id_analisis).values(
            resultado_estructurado=payload, actualizado_en=func.clock_timestamp()))
        audit(conn, request, "evaluacion_incidente_preparada", actor=actor.id_usuario, reason=str(id_analisis))
        sessions = table("sesion")
        sensor = conn.scalar(select(sessions.c.id_honeypot).where(sessions.c.id_sesion == row.id_sesion))
        notify_change(conn, [sensor], "analisis")
    return assessment


@app.get("/api/iocs", dependencies=[Depends(local_only)])
def list_iocs(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), id_ioc: UUID | None = None):
    i, typ, obs, event = (table(n) for n in ("ioc", "tipo_ioc", "observacion_ioc", "evento"))
    verified = func.jsonb_array_length(obs.c.detalles) > 0
    supported_count = func.count(obs.c.id_observacion).filter(verified)
    low_state = func.min(obs.c.estado_revision).filter(verified)
    high_state = func.max(obs.c.estado_revision).filter(verified)
    latest = func.coalesce(func.max(event.c.fecha_hora), i.c.ultima_observacion)

    def representative(column):
        return (select(column).select_from(obs.join(event, event.c.id_evento == obs.c.id_evento))
                .where(obs.c.id_ioc == i.c.id_ioc, event.c.id_sesion.in_(sensor_sessions()))
                .order_by(verified.desc(), event.c.fecha_hora.desc(), event.c.id_evento.desc())
                .limit(1).correlate(i).scalar_subquery().label(column.name))

    with app.state.engine.connect() as conn:
        query = (select(i.c.id_ioc, typ.c.nombre.label("tipo"),
            i.c.valor, func.coalesce(func.min(event.c.fecha_hora), i.c.primera_observacion).label("primera_observacion"),
            latest.label("ultima_observacion"), representative(obs.c.id_evento),
            representative(event.c.id_sesion), representative(obs.c.evidencia),
            func.count(obs.c.id_observacion).label("evidencias"),
            func.count(func.distinct(event.c.id_sesion)).label("sesiones"),
            supported_count.label("observaciones_verificables"),
            func.count(obs.c.id_observacion).filter(~verified).label("observaciones_historicas"),
            case((supported_count == 0, "historico"), (low_state == high_state, low_state),
                 else_="mixto").label("estado_revision"))
            .join(typ, i.c.id_tipo_ioc == typ.c.id_tipo_ioc)
            .outerjoin(obs, obs.c.id_ioc == i.c.id_ioc)
            .outerjoin(event, event.c.id_evento == obs.c.id_evento)
            .where(event.c.id_sesion.in_(sensor_sessions()))
            .group_by(i.c.id_ioc, typ.c.nombre)
            .order_by(latest.desc(), i.c.id_ioc)
            .limit(limit).offset(offset))
        if id_ioc is not None:
            query = query.where(i.c.id_ioc == id_ioc)
        rows = conn.execute(query).mappings().all()
        scope = (select(obs.c.id_ioc, event.c.id_sesion).join(event, obs.c.id_evento == event.c.id_evento)
                 .where(event.c.id_sesion.in_(sensor_sessions())).subquery())
        redactors = ioc_views.ioc_redactors(conn, app.state.tables, scope, (row.id_ioc for row in rows))
    return [ioc_views.publish_ioc(dict(row), redactors) for row in rows]


@app.get("/api/iocs/{id_ioc}/observaciones", dependencies=[Depends(local_only)])
def ioc_observations(id_ioc: UUID, filters: Annotated[ioc_views.IocFilters, Depends()],
                     limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                     id_evento: int | None = Query(None, ge=0, le=(1 << 63) - 1),
                     categoria: Literal["prioritarias","autenticacion","comandos","transferencias","dns",
                                        "conexiones","desconexiones","ssh","todas"] = "todas",
                     orden_evidencia: Literal["relevancia","recientes","antiguas"] = "recientes",
                     vista_segura: bool = False):
    ioc, obs, event = table("ioc"), table("observacion_ioc"), table("evento")
    type_table = table("tipo_ioc")
    detection = table("deteccion_ioc")
    actions_by_event = defaultdict(list)
    with app.state.engine.connect() as conn:
        indicator = conn.execute(select(ioc.c.valor.label("valor_normalizado"), type_table.c.nombre.label("tipo"))
            .join(type_table, ioc.c.id_tipo_ioc == type_table.c.id_tipo_ioc)
            .where(ioc.c.id_ioc == id_ioc)).mappings().first()
        if indicator is None:
            raise HTTPException(404, "Observable no encontrado")
        category_filter, ordering = ioc_views.observation_filter(event, obs, categoria, orden_evidencia)
        session, sensor = table("sesion"), table("honeypot")
        query = (select(obs, *event_columns(event)[1:], event.c.datos_originales)
                 .join(event, event.c.id_evento == obs.c.id_evento).where(obs.c.id_ioc == id_ioc, event.c.id_sesion.in_(sensor_sessions()))
                 .order_by(*ordering)
                 .limit(limit).offset(offset))
        if id_evento is not None:
            query = query.where(obs.c.id_evento == id_evento)
        else:
            query = query.where(category_filter)
        if vista_segura:
            query = (query.join(session, session.c.id_sesion == event.c.id_sesion)
                     .join(sensor, sensor.c.id_honeypot == session.c.id_honeypot)
                     .add_columns(session.c.cowrie_session_id, sensor.c.nombre.label("sensor"),
                                  ioc_views.modality_column(session,app.state.instances).label("modalidad")))
            if id_evento is None and filters.model_dump(exclude_defaults=True, exclude={"orden"}):
                scope = ioc_views.filtered_scope(conn,app.state.tables,sensor_ids(),app.state.instances,filters,id_ioc)
                query = query.where(obs.c.id_observacion.in_(select(scope.c.id_observacion)))
        rows = conn.execute(query).mappings().all()
        correlations = observed_correlations(conn, app.state.tables, indicator, rows, app.state.ioc_transfer_window)
        if rows:
            links = conn.execute(action_observable_query(app.state.tables).where(
                detection.c.id_ioc == id_ioc, detection.c.id_evento.in_([row.id_evento for row in rows]))).mappings().all()
            mappings = defaultdict(list)
            if links:
                for mapping in mapping_evidence(conn, app.state.tables, action_ids={link.id_accion for link in links}):
                    mappings[mapping["id_accion"]].append(mapping)
            for link in links:
                association = action_link(link)
                techniques = [match for mapping in mappings[link.id_accion]
                              if (match := mitre_link(link, association, mapping)) is not None]
                actions_by_event[link.id_evento].append({**association, "tecnicas": techniques})
        redactors = session_redactors(conn, event, {row.id_sesion for row in rows})
    return [redactors[row.id_sesion].payload({**plain(row), **indicator, "id_evento": str(row.id_evento),
             "acciones": actions_by_event[row.id_evento],
             "correlaciones": correlations[row.id_evento],
             "estado_relacion": "directa" if row.detalles else "insuficiente"})
            for row in rows]


@app.get("/api/iocs/explorar", dependencies=[Depends(local_only)])
def ioc_explorer(filters: Annotated[ioc_views.IocFilters, Depends()],
                 limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    with app.state.engine.connect() as conn:
        scope = ioc_views.filtered_scope(conn,app.state.tables,sensor_ids(),app.state.instances,filters)
        return ioc_views.explorer_rows(conn,app.state.tables,scope,filters,limit,offset)


@app.get("/api/iocs/resumen", dependencies=[Depends(local_only)])
def ioc_summary(filters: Annotated[ioc_views.IocFilters, Depends()]):
    with app.state.engine.connect() as conn:
        scope = ioc_views.filtered_scope(conn,app.state.tables,sensor_ids(),app.state.instances,filters)
        return ioc_views.summary(conn,app.state.tables,scope,filters)


@app.get("/api/iocs/{id_ioc}/perfil", dependencies=[Depends(local_only)])
def ioc_profile(id_ioc: UUID, filters: Annotated[ioc_views.IocFilters, Depends()]):
    with app.state.engine.connect() as conn:
        scope = ioc_views.filtered_scope(conn,app.state.tables,sensor_ids(),app.state.instances,filters,id_ioc)
        return ioc_views.profile(conn,app.state.tables,scope,filters)


@app.get("/api/iocs/{id_ioc}/sesiones", dependencies=[Depends(local_only)])
def ioc_sessions(id_ioc: UUID, filters: Annotated[ioc_views.IocFilters, Depends()],
                 limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    with app.state.engine.connect() as conn:
        scope = ioc_views.filtered_scope(conn,app.state.tables,sensor_ids(),app.state.instances,filters,id_ioc)
        return ioc_views.session_page(conn,app.state.tables,scope,filters,limit,offset,sensor_ids(),app.state.instances)


@app.get("/api/mitre/mapeos", dependencies=[Depends(local_only)])
def list_mappings(filters: Annotated[MitreFilters, Depends()], limit: int = 100, offset: int = 0,
                  id_mapeo: UUID | None = None):
    mapping = table('mapeo_mitre')
    query = (mapping_rows(app.state.tables, sensor_ids(), app.state.instances, filters)
             .order_by(mapping.c.fecha_mapeo.desc(), mapping.c.id_mapeo)
             .limit(min(max(limit, 1), 200)).offset(max(offset, 0)))
    if id_mapeo is not None:
        query = query.where(mapping.c.id_mapeo == id_mapeo)
    with app.state.engine.connect() as conn:
        rows = conn.execute(query).mappings().all()
        redactors = session_redactors(conn, table("evento"), {row.id_sesion for row in rows})
    return [public_mitre_record(plain(row), redactors[row.id_sesion]) for row in rows]


def public_mitre_record(record, redactor):
    sanitized = redactor.payload(record)
    provenance = sanitized.get('rag_procedencia')
    if isinstance(provenance, dict):
        allowed = {'clasificacion', 'modalidad', 'catalogo', 'modelo_llm', 'stix_id', 'metodo', 'version_validador', 'alcance_sensor',
                   'version_contrato', 'contrato_evidencia', 'limitaciones', 'comportamiento_observado'}
        sanitized['rag_procedencia'] = {key: value for key, value in provenance.items() if key in allowed}
        for key, fields in (('catalogo', ('version',)), ('modelo_llm', ('modelo', 'proveedor'))):
            nested = provenance.get(key)
            if isinstance(nested, dict):
                sanitized['rag_procedencia'][key] = {field: nested[field] for field in fields if field in nested}
    return sanitized


@app.get('/api/mitre/tecnicas', dependencies=[Depends(local_only)])
def list_mitre_techniques(filters: Annotated[MitreFilters, Depends()],
                          limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = mapping_rows(app.state.tables, sensor_ids(), app.state.instances, filters)
    with app.state.engine.connect() as conn:
        return [plain(row) for row in conn.execute(technique_groups(rows, filters.orden).limit(limit).offset(offset)).mappings()]


@app.get('/api/mitre/tecnicas/{codigo_tecnica}/sesiones', dependencies=[Depends(local_only)])
def list_mitre_technique_sessions(codigo_tecnica: str, filters: Annotated[MitreFilters, Depends()],
                                  limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = mapping_rows(app.state.tables, sensor_ids(), app.state.instances,
                        filters.model_copy(update={'codigo': codigo_tecnica}))
    with app.state.engine.connect() as conn:
        return [plain(row) for row in conn.execute(
            session_groups(rows, app.state.tables, filters.orden).limit(limit).offset(offset)).mappings()]


@app.get('/api/mitre/resumen', dependencies=[Depends(local_only)])
def mitre_summary(filters: Annotated[MitreFilters, Depends()]):
    rows = mapping_rows(app.state.tables, sensor_ids(), app.state.instances, filters)
    with app.state.engine.connect() as conn:
        catalog = table('catalogo_mitre')
        version = conn.scalar(select(catalog.c.version).where(catalog.c.activo.is_(True)))
        return {'version_catalogo': version, **analytics(conn, app.state.tables, rows, filters)}


@app.get('/api/mitre/matriz', dependencies=[Depends(local_only)])
def mitre_matrix(filters: Annotated[MitreFilters, Depends()], catalogo: bool = False):
    rows = mapping_rows(app.state.tables, sensor_ids(), app.state.instances, filters)
    with app.state.engine.connect() as conn:
        return matrix(conn, app.state.tables, rows, filters, catalogo)


@app.get('/api/mitre/tecnicas/{codigo_tecnica}', dependencies=[Depends(local_only)])
def mitre_technique(codigo_tecnica: str, filters: Annotated[MitreFilters, Depends()]):
    scoped = filters.model_copy(update={'codigo': codigo_tecnica})
    rows = mapping_rows(app.state.tables, sensor_ids(), app.state.instances, scoped)
    with app.state.engine.connect() as conn:
        official = technique_record(conn, app.state.tables, codigo_tecnica)
        details = analytics(conn, app.state.tables, rows, scoped)
        details['totales']['observables'] = observable_total(conn, app.state.tables, rows)
        return {'catalogo': official, **details}


@app.get("/api/mitre/mapeos/{id_mapeo}/observables", dependencies=[Depends(local_only)])
def mapping_observables(id_mapeo: UUID, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                        detallar_citas: bool = False):
    action, detection = table("accion_identificada"), table("deteccion_ioc")
    with app.state.engine.connect() as conn:
        m, analysis, event = table("mapeo_mitre"), table("analisis_llm"), table("evento")
        sid = conn.scalar(select(analysis.c.id_sesion).select_from(m.join(action,
            m.c.id_accion == action.c.id_accion).join(analysis, action.c.id_analisis == analysis.c.id_analisis))
            .where(m.c.id_mapeo == id_mapeo, analysis.c.id_sesion.in_(sensor_sessions())))
        if sid is None:
            raise HTTPException(404, "Mapeo MITRE no encontrado")
        mapping = next(iter(mapping_evidence(conn, app.state.tables, mapping_id=id_mapeo)), None)
        if mapping is None:
            raise HTTPException(404, "Mapeo MITRE no encontrado")
        redactor = session_redactors(conn, event, [sid])[sid]
        if detallar_citas:
            references = citation_query(app.state.tables).where(m.c.id_mapeo == id_mapeo).subquery()
            commands = conn.execute(select(event.c.id_evento, event.c.datos_originales['input'].astext)
                                    .where(event.c.id_evento.in_(select(references.c.id_evento)),
                                           event.c.tipo_evento == 'cowrie.command.input')).all()
            public_commands = {str(event_id): redactor.text(command) for event_id, command in commands if command}
            for reference in mapping["eventos"]:
                reference["comando"] = public_commands.get(reference["id_evento"])
        links = []
        if mapping["estado_revision"] != "descartado" and mapping["eventos"]:
            rows = conn.execute(action_observable_query(app.state.tables).where(
                action.c.id_accion == mapping["id_accion"],
                detection.c.id_evento.in_([int(ref["id_evento"]) for ref in mapping["eventos"]]))).mappings()
            for row in rows:
                link = action_link(row)
                match = mitre_link(row, link, mapping)
                if match and match["estado"] != "insuficiente":
                    relation = {**link, **{field: match[field] for field in ("estado", "metodo", "limitaciones")},
                                "justificacion": match["fundamento"]}
                    if detallar_citas:
                        relation["papeles"] = sorted({detail["comportamiento"] for detail in row.detalles})
                    links.append(relation)
    result = {"mapeo": mapping, "observables": links[offset:offset+limit], "hay_mas": len(links) > offset+limit}
    if detallar_citas:
        result["mapeo"] = public_mitre_record(mapping, redactor)
    return redactor.payload(result)


@app.get("/api/propuestas-salvaguardas", dependencies=[Depends(local_only)])
def list_safeguard_proposals(id_analisis: UUID | None = None, id_sesion: UUID | None = None,
                    estado: Literal["propuesta", "aprobada", "en_curso", "verificada", "descartada"] | None = None,
                    limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
    with app.state.engine.connect() as conn:
        return safeguard_proposals.browse(conn, app.state.tables, sensor_ids(), analysis_id=id_analisis, session_id=id_sesion,
                                 state=estado, limit=limit, offset=offset)


@app.post("/api/analisis/{id_analisis}/salvaguardas/{codigo}/revision", dependencies=[Depends(local_only)])
def review_safeguard(id_analisis: UUID, codigo: str, decision: safeguard_proposals.SafeguardReview, request: Request):
    analysis = table("analisis_llm")
    with app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        row = conn.execute(select(analysis).where(
            analysis.c.id_analisis == id_analisis, analysis.c.id_sesion.in_(sensor_sessions())
        ).with_for_update()).mappings().first()
        if row is None:
            raise HTTPException(404, "Análisis no encontrado")
        if row.estado != "completado":
            raise HTTPException(409, "Se requiere un análisis completado")
        payload = row.resultado_estructurado or {}
        if safeguard_proposals.proposal(payload, codigo) is None:
            raise HTTPException(404, "Salvaguarda no encontrada en este análisis")
        origins = table("salvaguarda_origen")
        if conn.scalar(select(origins.c.id_salvaguarda).where(
            origins.c.id_analisis == id_analisis, origins.c.posicion == int(codigo[3:])
        )) is not None:
            raise HTTPException(409, "Esta salvaguarda se gestiona desde el tablero")
        redactor = session_redactors(conn, table("evento"), [row.id_sesion])[row.id_sesion]
        updated = safeguard_proposals.append_review(payload, codigo, decision, actor.id_usuario, redactor)
        conn.execute(analysis.update().where(analysis.c.id_analisis == id_analisis).values(
            resultado_estructurado=updated, actualizado_en=func.clock_timestamp()))
        audit(conn, request, "salvaguarda_revisada", actor=actor.id_usuario,
              reason=f"{id_analisis}:{codigo}:{decision.estado}")
        sensor = conn.scalar(select(table("sesion").c.id_honeypot).where(
            table("sesion").c.id_sesion == row.id_sesion))
        notify_change(conn, [sensor], "salvaguardas", "analisis")
    return {"historial": redactor.payload(updated["seguimiento_salvaguardas"][codigo])}


@app.get("/api/mitre/clasificadores", dependencies=[Depends(local_only)])
def mitre_classifiers():
    technique, catalog = table("tecnica_mitre"), table("catalogo_mitre")
    with app.state.engine.connect() as conn:
        names = dict(conn.execute(select(technique.c.codigo_tecnica, technique.c.nombre)
                                  .join(catalog, catalog.c.id_catalogo == technique.c.id_catalogo)
                                  .where(catalog.c.activo, ~technique.c.revocada, ~technique.c.deprecada,
                                         technique.c.codigo_tecnica.in_(CONTRACTS))).all())
    return {"version": VALIDATOR_VERSION, "clasificadores": [
        {"codigo": code, "nombre": names.get(code, code), "version": contract.version,
         "modalidades": sorted(contract.modes), "tacticas": sorted(contract.tactics),
         "minimo_evidencias_distintas": contract.minimum_distinct,
         "limitacion": contract.limitation, "presente_en_catalogo": code in names}
        for code, contract in sorted(CONTRACTS.items())
    ]}


@app.get('/api/mitre/catalogo',dependencies=[Depends(local_only)])
def catalog_status():
    with app.state.engine.connect() as conn:
        row=conn.execute(text('SELECT id_catalogo,version,fuente,sha256,conteos,importado_en FROM honeypot.catalogo_mitre WHERE activo')).mappings().first()
        if not row:raise HTTPException(503,'Catalogo oficial no preparado')
        ready=conn.scalar(text('SELECT count(*) FROM honeypot.tecnica_mitre WHERE id_catalogo=:id AND NOT revocada AND NOT deprecada AND embedding_rag IS NOT NULL'),{'id':row.id_catalogo})
    return {**plain(row),'embeddings_vigentes':ready,'metodo':METHOD,'similitud_no_es_probabilidad':True}


@app.post('/api/sesiones/{id_sesion}/mitre/candidatos',dependencies=[Depends(local_only)])
def session_candidates(id_sesion:UUID,request:Request):
    from .auth.store import transaction,rate
    with transaction(request) as conn:
        rate(conn,request,'rag_busqueda',account=request.state.user['id_usuario'],account_limit=60,ip_limit=120)
    s,e=table('sesion'),table('evento')
    with app.state.engine.connect() as conn:
        sensor=conn.scalar(select(s.c.id_honeypot).where(s.c.id_sesion==id_sesion,s.c.id_honeypot.in_(sensor_ids())))
        if sensor is None:
            raise HTTPException(404,'Sesion no encontrada')
        events=conn.execute(select(e.c.id_evento,e.c.tipo_evento,e.c.fecha_hora,e.c.datos_originales,e.c.id_sesion).where(e.c.id_sesion==id_sesion).order_by(e.c.fecha_hora,e.c.id_evento)).all()
    if not events:raise HTTPException(422,'La sesion no tiene eventos')
    try:
        return Redactor(event.datos_originales for event in events).payload(rag_context(events,sensor_modality(sensor)))
    except RuntimeError:raise HTTPException(503,'Buscador no preparado; revise catalogo y embeddings') from None


class ReviewDecision(BaseModel):
    revision_esperada: str | None = Field(max_length=80)
    estado: Literal["confirmado", "descartado"]
    motivo: str = Field(min_length=10, max_length=500)

    @field_validator("motivo")
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Escriba un motivo de al menos diez caracteres")
        return value


def review_targets(conn, kind, item_id, *, lock=False):
    observations, ioc, mapping = (table(name) for name in ("observacion_ioc", "ioc", "mapeo_mitre"))
    if kind == "ioc":
        scope = select(ioc.c.id_ioc).where(ioc.c.id_ioc == item_id, ioc.c.id_ioc.in_(
            select(observations.c.id_ioc).where(observations.c.id_evento.in_(sensor_events()))))
        if not conn.scalar(scope.with_for_update() if lock else scope):
            raise HTTPException(404, "Hallazgo no encontrado")
        target, key = observations, observations.c.id_observacion
        conditions = (observations.c.id_ioc == item_id, observations.c.id_evento.in_(sensor_events()),
                      func.jsonb_array_length(observations.c.detalles) > 0)
    elif kind == "observacion_ioc":
        target, key = observations, observations.c.id_observacion
        conditions = (key == item_id, target.c.id_evento.in_(sensor_events()))
    else:
        target, key = mapping, mapping.c.id_mapeo
        conditions = (key == item_id, mapping.c.id_accion.in_(sensor_actions()))
    statement = select(target).where(*conditions).order_by(key)
    rows = conn.execute(statement.with_for_update() if lock else statement).mappings().all()
    if not rows:
        raise HTTPException(409 if kind == "ioc" else 404, "No hay observaciones revisables en el alcance")
    versions = [(str(row[key.name]), row.estado_revision, row.revisado_en.isoformat() if row.revisado_en else None)
                for row in rows]
    version = hashlib.sha256(json.dumps(versions).encode()).hexdigest() if kind == "ioc" else versions[0][2]
    return target, key, rows, versions, version


@app.get("/api/inteligencia/{kind}/{item_id}/revision", dependencies=[Depends(local_only)])
def intelligence_revision(kind: Literal["ioc", "observacion_ioc", "mitre"], item_id: UUID):
    with app.state.engine.connect() as conn:
        _, _, rows, _, version = review_targets(conn, kind, item_id)
    return {"revision":version,"afectadas":len(rows),"colectiva":kind=="ioc"}


@app.patch("/api/inteligencia/{kind}/{item_id}/revision", dependencies=[Depends(local_only)])
def review_intelligence(kind: Literal["ioc", "observacion_ioc", "mitre"], item_id: UUID,
                        decision: ReviewDecision, request: Request):
    with app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        reviewed, key, rows, previous, version = review_targets(conn, kind, item_id, lock=True)
        expected = decision.revision_esperada
        if expected and kind != "ioc":
            try:
                expected = datetime.fromisoformat(expected.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
            except ValueError:
                raise HTTPException(422, "Versión de revisión inválida") from None
            if version:
                version = datetime.fromisoformat(version).astimezone(timezone.utc).isoformat()
        if expected != version:
            raise HTTPException(409, {"mensaje":"La revisión cambió. Recargue antes de decidir.",
                                      "revision":version,"afectadas":len(rows)})
        if kind == "mitre" and decision.estado == "confirmado":
            existing = rows[0]
            if (existing.rag_procedencia or {}).get("clasificacion") == AUTO_CLASSIFICATION:
                citations = table("mapeo_mitre_evento")
                if not conn.scalar(select(citations.c.id_mapeo).where(citations.c.id_mapeo == item_id).limit(1)):
                    raise HTTPException(409, "El mapeo carece de citas explícitas verificables")
        if kind == "observacion_ioc" and decision.estado == "confirmado" and not rows[0].detalles:
            raise HTTPException(409, "La revisión requiere una observación con respaldo determinista")
        sessions, events = table("sesion"), table("evento")
        if kind == "mitre":
            action, analysis = table("accion_identificada"), table("analisis_llm")
            affected = select(analysis.c.id_sesion).join(action, action.c.id_analisis == analysis.c.id_analisis).where(
                action.c.id_accion == rows[0].id_accion)
        else:
            affected = select(events.c.id_sesion).where(events.c.id_evento.in_([row.id_evento for row in rows]))
        scope = conn.execute(select(sessions.c.id_sesion, sessions.c.id_honeypot).where(
            sessions.c.id_sesion.in_(affected))).all()
        redactors = session_redactors(conn, events, [row.id_sesion for row in scope])
        reason = decision.motivo
        for redactor in redactors.values():
            reason = redactor.text(reason)
        timestamp = conn.scalar(select(func.clock_timestamp()))
        conn.execute(reviewed.update().where(key.in_([row[key.name] for row in rows])).values(
            estado_revision=decision.estado, motivo_revision=reason, revisado_por=actor.id_usuario, revisado_en=timestamp))
        audit(conn, request, "inteligencia_revisada", actor=actor.id_usuario,
              reason=f"{kind}:{item_id}:{decision.estado}",
              revision={"motivo":reason,"anterior":previous,"afectadas":len(rows),"en":timestamp.isoformat()})
        notify_change(conn, [row.id_honeypot for row in scope], "iocs", "mitre", "panel", "analisis")
        _, _, _, _, new_version = review_targets(conn, kind, item_id)
    return {"estado":decision.estado,"revision":new_version,"afectadas":len(rows),"colectiva":kind=="ioc"}
