"""Academic prototype routes; all interactive writes are restricted to the Windows host."""
import hashlib
import hmac
import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from uuid import UUID
from typing import Literal

import httpx
from fastapi import Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import case, func, select, text
from sqlalchemy.dialects.postgresql import insert

from .api import app, local_only, persist_events, safe
from .analysis_state import public_state, states_for_sessions
from .correlation import (action_link, action_observable_query, event_columns, mapping_evidence,
                          mapping_query, mitre_link, observed_correlations)
from .analysis_report import (BehaviorReport, REPORT_VERSION, analysis_instruction,
                              needs_report_upgrade, observation_context, validate_report_evidence)
from .intelligence import extract_observables, normalized_value, observables, persist_observables
from .auth.store import require_admin, audit
from .session_report import report_snapshot
from .rag.retrieval import context as retrieve_context
from .rag.validation import validate as validate_mitre
from .rag.pipeline import METHOD, RAG_INSTRUCTION, evidence_sample, facts_for_model

# Legacy backfill compatibility only. New RAG classification NEVER filters by this set.
COWRIE_TECHNIQUES = {"T1110", "T1110.001", "T1059.004", "T1105", "T1082", "T1083",
                     "T1016", "T1033", "T1057", "T1005"}
MODEL_OBSERVABLE_LIMIT = 20


def table(name):
    return app.state.tables[name]


def plain(row):
    return {k: (str(v) if isinstance(v, UUID) else v) for k, v in dict(row).items()}


@app.get("/api/health")
def health():
    with app.state.engine.connect() as conn:
        conn.execute(select(1))
        e,s=table("evento"),table("sesion")
        stats=conn.execute(select(func.count().label("eventos"),func.max(e.c.ingresado_en).label("ultima_ingesta"))
            .select_from(e.join(s,e.c.id_sesion==s.c.id_sesion)).where(s.c.id_honeypot==app.state.honeypot_id)).mappings().one()
    return {"status": "ok", "database": "connected", "llm_mode": "real", "collector_last_seen": getattr(app.state, "collector_last_seen", None),
            "contrato_ingesta":"tacticlens.ingesta.v2","ingestion":dict(stats)}


@app.post("/api/ingesta/heartbeat")
def collector_heartbeat(x_api_key: str | None = Header(default=None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, app.state.api_key):
        raise HTTPException(401, "Clave inválida")
    app.state.collector_last_seen = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


@app.post("/api/ingesta/cowrie", dependencies=[Depends(local_only)])
async def upload_cowrie(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".json", ".jsonl")):
        raise HTTPException(422, "Seleccione un archivo .json o .jsonl")
    content = await file.read(10_000_001)
    if len(content) > 10_000_000:
        raise HTTPException(413, "Máximo 10 MB por archivo")
    if not content:
        raise HTTPException(422, "Archivo vacío")
    valid, errors = parse_jsonl(content)
    inserted = duplicates = 0
    for event in valid:
        try:
            result = persist_events([event])
            inserted += result["insertados"]
            duplicates += result["duplicados"]
        except Exception as exc:
            errors.append({"linea": "evento", "error": type(exc).__name__})
    return {"procesados": len(content.splitlines()), "insertados": inserted, "duplicados": duplicates, "errores": errors[:100]}


def parse_jsonl(content):
    valid, errors, seen = [], [], Counter()
    for number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("se esperaba un objeto JSON")
            signature = hashlib.sha256(line.strip()).hexdigest()
            seen[signature] += 1
            event["_collector"] = {"source_id": f"manual:{signature}:{seen[signature]}"}
            valid.append(event)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            errors.append({"linea": number, "error": str(exc)[:120]})
    return valid, errors


@app.get("/api/sesiones/{id_sesion}", dependencies=[Depends(local_only)])
def session_detail(id_sesion: UUID):
    s, e, a = table("sesion"), table("evento"), table("analisis_llm")
    with app.state.engine.connect() as conn:
        row = conn.execute(select(s, select(func.count()).where(e.c.id_sesion == s.c.id_sesion).scalar_subquery().label("eventos")).where(s.c.id_sesion == id_sesion, s.c.id_honeypot == app.state.honeypot_id)).mappings().first()
        state = states_for_sessions(conn, a, {id_sesion: row.eventos})[id_sesion] if row else None
    if not row:
        raise HTTPException(404, "Sesion no encontrada")
    return {**plain(row), **public_state(state)}


def dashboard_snapshot():
    s, e, a, obs, m = (table(n) for n in ("sesion", "evento", "analisis_llm", "observacion_ioc", "mapeo_mitre"))
    with app.state.engine.connect() as conn:
        counts = dict(conn.execute(select(
            select(func.count()).select_from(s).scalar_subquery().label('sesiones'),
            select(func.count()).select_from(e).scalar_subquery().label('eventos'),
            select(func.count(func.distinct(a.c.id_sesion))).where(a.c.estado == 'completado').scalar_subquery().label('sesiones_analizadas'),
            select(func.count(func.distinct(obs.c.id_ioc))).where(
                func.jsonb_array_length(obs.c.detalles) > 0).scalar_subquery().label('iocs'),
            select(func.count(func.distinct(m.c.id_vinculo))).scalar_subquery().label('tecnicas_mitre'),
        )).mappings().one())
        by_day = conn.execute(select(func.date(e.c.fecha_hora).label("dia"), func.count().label("total")).group_by(func.date(e.c.fecha_hora)).order_by(func.date(e.c.fecha_hora).desc()).limit(7)).mappings().all()
        by_type = conn.execute(select(e.c.tipo_evento, func.count().label("total")).group_by(e.c.tipo_evento).order_by(func.count().desc()).limit(8)).mappings().all()
        latest_event = conn.scalar(select(func.max(e.c.fecha_hora)))
        commands = conn.execute(select(e.c.id_evento,e.c.id_sesion,e.c.fecha_hora,e.c.datos_originales)
            .where(e.c.tipo_evento=='cowrie.command.input')
            .order_by(e.c.fecha_hora.desc(),e.c.id_evento.desc()).limit(5)).mappings().all()
    recent_commands=[{'id_evento':row['id_evento'],'id_sesion':str(row['id_sesion']),
        'fecha_hora':row['fecha_hora'],'comando':str(row['datos_originales'].get('input',''))[:2000]}
        for row in commands]
    return {**counts, "actividad": [plain(x) for x in reversed(by_day)], "tipos_evento": [plain(x) for x in by_type], "ultimo_evento": latest_event,
            'ultimos_comandos':recent_commands}


@app.get("/api/sesiones/{id_sesion}/informe", dependencies=[Depends(local_only)])
def session_report(id_sesion: UUID, formato: Literal["json", "pdf", "docx"] = "json"):
    with app.state.engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
        report = report_snapshot(conn, app.state.tables, app.state.honeypot_id, id_sesion)
    if formato == "json":
        return report
    from .report_export import PDF_TYPE, WORD_TYPE, render_docx, render_pdf

    content, media_type = (render_pdf(report), PDF_TYPE) if formato == "pdf" else (render_docx(report), WORD_TYPE)
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="TacticLens-{id_sesion}.{formato}"',
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
    justificacion: str = Field(default='',max_length=3000)
    confianza: float = Field(default=0.5, ge=0, le=1)
    eventos: list[int] = Field(default_factory=list)
    grado_evidencia: Literal['intento','resultado_en_honeypot'] = 'intento'
    limitaciones: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    tipo: str = Field(min_length=1, max_length=80)
    descripcion: str = Field(min_length=1)
    confianza: float = Field(ge=0, le=1)
    eventos: list[int] = Field(min_length=1)
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


def rag_context(events):
    return retrieve_context(app.state.engine,events)


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


def real_result(events, rag=None):
    key = os.getenv("LLM_API_KEY")
    model = os.getenv("LLM_MODEL")
    base = (os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    if not key or not model:
        raise ValueError("Configure LLM_API_KEY y LLM_MODEL")
    rag = rag if rag is not None else rag_context(events)
    sample = evidence_sample(events)
    facts = facts_for_model(sample)
    # Values remain in the usual redacted facts; the supplemental list carries
    # only provenance and references, keeping full URLs and query values local.
    observed = {str(event_id): [{"referencia": index, "tipo": item.tipo, "campo": item.campo,
                                "comportamiento": item.comportamiento, "grado_evidencia": item.grado_evidencia}
                               for index, item in enumerate(items[:MODEL_OBSERVABLE_LIMIT], start=1)]
                for event_id, items in event_observables(sample).items() if items}
    candidates=[{**row,'definicion':row['definicion'][:3000]} for row in rag['candidatos']]
    payload = {"contexto_calculado": observation_context(events), "eventos": facts,
               "observables_por_evento": observed,
               "tecnicas_mitre_permitidas": candidates,'catalogo':rag['catalogo'],
               'comportamiento_observado':rag['representacion'],
               'muestreo':{'eventos_snapshot':len(events),'eventos_en_prompt':len(facts)}}
    request_body={"model":model,"temperature":0,"thinking":{"type":"disabled"},
        "response_format":{"type":"json_object"},"max_tokens":8192,"messages":[
            {"role":"system","content":analysis_instruction()+RAG_INSTRUCTION},
            {"role":"user","content":json.dumps(payload,ensure_ascii=False,default=str)}]}
    rag['solicitud_sha256']=hashlib.sha256(json.dumps(request_body,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()
    started=time.perf_counter();requested_at=datetime.now(timezone.utc)
    response = httpx.post(base + "/chat/completions", headers={"Authorization": f"Bearer {key}"},
        json=request_body,timeout=float(os.getenv("LLM_TIMEOUT_SECONDS", "60")))
    response.raise_for_status()
    body=response.json();usage=body.get('usage') or {}
    fields=('prompt_tokens','completion_tokens','total_tokens','prompt_cache_hit_tokens','prompt_cache_miss_tokens')
    rag['respuesta_proveedor']={'solicitado_en':requested_at.isoformat(),'duracion_segundos':round(time.perf_counter()-started,3),
        'modelo_reportado':str(body.get('model',model))[:160],
        'uso':{field:usage[field] for field in fields if type(usage.get(field)) is int and usage[field]>=0}}
    choice = body["choices"][0]
    if choice.get("finish_reason") == "length":
        raise ValueError("El proveedor truncó el informe; no se guardará un resultado incompleto")
    content = choice["message"]["content"]
    if not content or not content.strip():
        raise ValueError("El proveedor devolvió una respuesta JSON vacía")
    result = AnalysisResult.model_validate_json(content)
    if result.informe is None:
        raise ValueError("El proveedor no incluyó el informe detallado solicitado")
    validate_report_evidence(result.informe, {event.id_evento for event in events})
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
    s, e, a = table("sesion"), table("evento"), table("analisis_llm")
    # Lock the session row while deciding whether to reuse or start an analysis.
    # Concurrent requests serialize here, including requests from another worker.
    with app.state.engine.begin() as conn:
        session_id = conn.scalar(
            select(s.c.id_sesion)
            .where(s.c.id_sesion == id_sesion, s.c.id_honeypot == app.state.honeypot_id)
            .with_for_update()
        )
        if not session_id:
            raise HTTPException(404, "Sesion no encontrada")
        events = conn.execute(
            select(e.c.id_evento, e.c.tipo_evento, e.c.fecha_hora, e.c.datos_originales)
            .where(e.c.id_sesion == id_sesion)
            .order_by(e.c.fecha_hora, e.c.id_evento)
        ).all()
        if not events:
            raise HTTPException(422, "La sesion no tiene eventos")
        state = states_for_sessions(conn, a, {id_sesion: len(events)})[id_sesion]
        if state["intento_expirado_id"]:
            conn.execute(a.update().where(a.c.id_analisis == state["intento_expirado_id"]).values(
                estado="fallido", fecha_fin=func.clock_timestamp(), mensaje_error="Tiempo de analisis agotado",
                actualizado_en=func.clock_timestamp()
            ))
        if state["analisis_en_proceso"]:
            raise HTTPException(409, "El analisis de esta sesion ya esta en proceso")
        upgrade = False
        if state["analisis_vigente_id"] and actualizar_informe:
            saved = conn.scalar(select(a.c.resultado_estructurado).where(a.c.id_analisis == state["analisis_vigente_id"]))
            upgrade = needs_report_upgrade(saved)
        if state['analisis_vigente_id'] and actualizar_rag:
            saved=conn.scalar(select(a.c.resultado_estructurado).where(a.c.id_analisis==state['analisis_vigente_id']))
            upgrade = upgrade or (saved or {}).get('rag',{}).get('metodo')!=METHOD
        if state["analisis_vigente_id"] and not upgrade:
            return {"id_analisis": str(state["analisis_vigente_id"]), "estado": "completado", "modo": "real", "reutilizado": True}
        model_id = ensure_model(conn)
        analysis_id = conn.scalar(insert(a).values(
            id_sesion=id_sesion, id_modelo=model_id, estado="en_proceso", fecha_inicio=func.clock_timestamp(), creado_en=func.clock_timestamp()
        ).returning(a.c.id_analisis))
    try:
        rag=rag_context(events)
        rag['candidatos']=rag['candidatos'][:24]
        rag['modelo_llm']={'proveedor':os.getenv('LLM_PROVIDER','deepseek'),'modelo':os.getenv('LLM_MODEL','')}
        rag['eventos_entregados']=[e.id_evento for e in evidence_sample(events)]
        rag['eventos_snapshot']=len(events)
        result = real_result(events,rag=rag)
        valid_ids = {x.id_evento for x in events}
        validate_report_evidence(result.informe, valid_ids)
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
        discarded,provenance = validate_mitre(result,events,rag)
        # Results and all linked findings commit together. A failure leaves no partial IoCs.
        with app.state.engine.begin() as conn:
            conn.execute(text('SELECT pg_advisory_xact_lock(724610902)'))
            current=conn.scalar(select(table('catalogo_mitre').c.id_catalogo).where(table('catalogo_mitre').c.activo))
            if str(current)!=rag['catalogo']['id_catalogo']:raise ValueError('El catalogo cambio; vuelva a analizar')
            conn.execute(a.update().where(a.c.id_analisis == analysis_id).values(
                estado="completado", fecha_fin=func.clock_timestamp(), resumen=result.resumen,
                resultado_estructurado={**result.model_dump(exclude_none=True), "eventos_analizados": len(events),
                    "version_informe": REPORT_VERSION if result.informe else 1,
                    "contexto_observado": observation_context(events), "mapeos_descartados": discarded,
                    "propuestas_ioc_descartadas": rejected_iocs, 'rag':rag},
                actualizado_en=func.clock_timestamp()
            ))
            persist_findings(conn, analysis_id, result, events, rag=rag, provenance=provenance, by_event=by_event)
    except Exception as exc:
        with app.state.engine.begin() as conn:
            conn.execute(a.update().where(a.c.id_analisis == analysis_id).values(
                estado="fallido", fecha_fin=func.clock_timestamp(),
                mensaje_error=f"RAG/LLM no disponible o respuesta no valida ({type(exc).__name__})", actualizado_en=func.clock_timestamp()
            ))
        raise HTTPException(502, "El analisis fallo; consulte el estado del analisis") from exc
    return {"id_analisis": str(analysis_id), "estado": "completado", "modo": "real", "reutilizado": False}


def persist_findings(conn, analysis_id, result, events, rag=None, provenance=None, by_event=None):
    action_t, link_t = table("accion_identificada"), table("accion_evento")
    mitre_t, mapping_t = table("tecnica_tactica"), table("mapeo_mitre")
    detection_t, action_ioc_t = table("deteccion_ioc"), table("accion_ioc")
    original_events = {event.id_evento: event for event in events}
    by_event = event_observables(events) if by_event is None else by_event
    observed = {}
    for action_index,finding in enumerate(result.acciones):
        action_id = conn.scalar(insert(action_t).values(id_analisis=analysis_id, tipo_accion=finding.tipo, descripcion=finding.descripcion, confianza=finding.confianza).returning(action_t.c.id_accion))
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
                evidencia=proposed.evidencia[:500] or "Observable vinculado por el análisis",
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
            match = conn.scalar(select(mitre_t.c.id_vinculo).join(te,mitre_t.c.codigo_tecnica==te.c.codigo_tecnica).where(
                mitre_t.c.codigo_tecnica==code,mitre_t.c.codigo_tactica==proposed.codigo_tactica,
                mitre_t.c.activa_en_catalogo,~te.c.revocada,~te.c.deprecada,
                te.c.id_catalogo==UUID(rag['catalogo']['id_catalogo']),te.c.objeto_sha256==meta['definicion_sha256']))
            if not match:raise ValueError('La tecnica o relacion oficial dejo de estar vigente')
            mapping_id = conn.scalar(insert(mapping_t).values(id_accion=action_id,id_vinculo=match,
                evidencia=f"Eventos: {', '.join(map(str,proposed.eventos))}",justificacion=proposed.justificacion,
                confianza=proposed.confianza,rag_procedencia={**meta,'modelo_llm':rag['modelo_llm']},
                grado_evidencia=proposed.grado_evidencia).returning(mapping_t.c.id_mapeo))
            if meta["citas_explicitas"]:
                citations = table("mapeo_mitre_evento")
                conn.execute(insert(citations).on_conflict_do_nothing(index_elements=["id_mapeo", "id_evento"]), [
                    {"id_mapeo": mapping_id, "id_accion": action_id, "id_evento": event_id, "metodo": "rag_validado_v1"}
                    for event_id in proposed.eventos])


@app.get("/api/analisis/{id_analisis}", dependencies=[Depends(local_only)])
def get_analysis(id_analisis: UUID):
    a, action, link = (table(n) for n in ("analisis_llm", "accion_identificada", "accion_evento"))
    with app.state.engine.connect() as conn:
        row = conn.execute(select(a).where(a.c.id_analisis == id_analisis)).mappings().first()
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
    return {**plain(row), "resultado_estructurado": safe(row.resultado_estructurado), "acciones": output}


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
                .where(obs.c.id_ioc == i.c.id_ioc)
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
            .group_by(i.c.id_ioc, typ.c.nombre)
            .order_by(latest.desc(), i.c.id_ioc)
            .limit(limit).offset(offset))
        if id_ioc is not None:
            query = query.where(i.c.id_ioc == id_ioc)
        rows = conn.execute(query).mappings().all()
    return [plain(x) for x in rows]


@app.get("/api/iocs/{id_ioc}/observaciones", dependencies=[Depends(local_only)])
def ioc_observations(id_ioc: UUID, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                     id_evento: int | None = Query(None, ge=0, le=(1 << 63) - 1)):
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
        query = (select(obs, *event_columns(event)[1:], event.c.datos_originales)
                 .join(event, event.c.id_evento == obs.c.id_evento).where(obs.c.id_ioc == id_ioc)
                 .order_by(event.c.fecha_hora.desc(), event.c.numero_secuencia.desc(), event.c.id_evento.desc())
                 .limit(limit).offset(offset))
        if id_evento is not None:
            query = query.where(obs.c.id_evento == id_evento)
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
    return [{**plain(row), **indicator, "id_evento": str(row.id_evento),
             "datos_originales": safe(row.datos_originales), "acciones": actions_by_event[row.id_evento],
             "correlaciones": correlations[row.id_evento],
             "estado_relacion": "directa" if row.detalles else "insuficiente"}
            for row in rows]


@app.get("/api/mitre/mapeos", dependencies=[Depends(local_only)])
def list_mappings(limit: int = 100, offset: int = 0, id_mapeo: UUID | None = None):
    m, act, analysis = (table(n) for n in ("mapeo_mitre", "accion_identificada", "analisis_llm"))
    query = (mapping_query(app.state.tables).add_columns(act.c.id_analisis, analysis.c.id_sesion)
             .join(act, m.c.id_accion == act.c.id_accion).join(analysis, act.c.id_analisis == analysis.c.id_analisis)
             .order_by(m.c.fecha_mapeo.desc(), m.c.id_mapeo).limit(min(max(limit, 1), 200)).offset(max(offset, 0)))
    if id_mapeo is not None:
        query = query.where(m.c.id_mapeo == id_mapeo)
    with app.state.engine.connect() as conn:
        rows = conn.execute(query).mappings().all()
    return [plain(x) for x in rows]


@app.get("/api/mitre/mapeos/{id_mapeo}/observables", dependencies=[Depends(local_only)])
def mapping_observables(id_mapeo: UUID, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    action, detection = table("accion_identificada"), table("deteccion_ioc")
    with app.state.engine.connect() as conn:
        mapping = next(iter(mapping_evidence(conn, app.state.tables, mapping_id=id_mapeo)), None)
        if mapping is None:
            raise HTTPException(404, "Mapeo MITRE no encontrado")
        links = []
        if mapping["estado_revision"] != "descartado" and mapping["eventos"]:
            rows = conn.execute(action_observable_query(app.state.tables).where(
                action.c.id_accion == mapping["id_accion"],
                detection.c.id_evento.in_([int(ref["id_evento"]) for ref in mapping["eventos"]]))).mappings()
            for row in rows:
                link = action_link(row)
                match = mitre_link(row, link, mapping)
                if match and match["estado"] != "insuficiente":
                    links.append({**link, **{field: match[field] for field in ("estado", "metodo", "limitaciones")},
                                  "justificacion": match["fundamento"]})
    return {"mapeo": mapping, "observables": links[offset:offset+limit], "hay_mas": len(links) > offset+limit}


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
        if not conn.scalar(select(s.c.id_sesion).where(s.c.id_sesion==id_sesion,s.c.id_honeypot==app.state.honeypot_id)):
            raise HTTPException(404,'Sesion no encontrada')
        events=conn.execute(select(e.c.id_evento,e.c.tipo_evento,e.c.fecha_hora,e.c.datos_originales).where(e.c.id_sesion==id_sesion).order_by(e.c.fecha_hora,e.c.id_evento)).all()
    if not events:raise HTTPException(422,'La sesion no tiene eventos')
    try:return rag_context(events)
    except RuntimeError:raise HTTPException(503,'Buscador no preparado; revise catalogo y embeddings') from None


class ReviewDecision(BaseModel):
    estado: Literal["confirmado", "descartado"]
    motivo: str = Field(min_length=10, max_length=500)

    @field_validator("motivo")
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Escriba un motivo de al menos diez caracteres")
        return value


@app.patch("/api/inteligencia/{kind}/{item_id}/revision", dependencies=[Depends(local_only)])
def review_intelligence(kind: Literal["ioc", "observacion_ioc", "mitre"], item_id: UUID,
                        decision: ReviewDecision, request: Request):
    target_name, key_name = {"ioc": ("ioc", "id_ioc"),
                             "observacion_ioc": ("observacion_ioc", "id_observacion"),
                             "mitre": ("mapeo_mitre", "id_mapeo")}[kind]
    target = table(target_name)
    key = target.c[key_name]
    with app.state.engine.begin() as conn:
        _, actor = require_admin(conn, request)
        existing = conn.execute(select(target).where(key == item_id).with_for_update()).mappings().first()
        if existing is None:
            raise HTTPException(404, "Hallazgo no encontrado")
        reviewed = table("observacion_ioc") if kind == "ioc" else target
        review_key = reviewed.c.id_ioc if kind == "ioc" else key
        review = reviewed.update().where(review_key == item_id)
        if kind == "ioc" or (kind == "observacion_ioc" and decision.estado == "confirmado"):
            review = review.where(func.jsonb_array_length(reviewed.c.detalles) > 0)
        result = conn.execute(review.values(
            estado_revision=decision.estado, motivo_revision=decision.motivo.strip(),
            revisado_por=actor.id_usuario, revisado_en=func.now()))
        if not result.rowcount:
            raise HTTPException(409, "La revisión requiere una observación con respaldo determinista")
        audit(conn, request, "inteligencia_revisada", actor=actor.id_usuario,
              reason=f"{kind}:{item_id}:{decision.estado}")
    return {"estado": decision.estado}
