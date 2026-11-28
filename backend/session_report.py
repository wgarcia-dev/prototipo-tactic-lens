"""A consistent, read-only view of the evidence behind a Cowrie session."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import func, select

from .analysis_state import analyzed_count, current_inputs, result_freshness, states_for_sessions
from .correlation import mapping_evidence
from .intelligence_metrics import observable_totals, technique_count
from .ioc_views import IocFilters, observation_query
from .mitre_views import MitreFilters, mapping_rows
from .rag.mitre_evidence import AUTO_CLASSIFICATION
from .sensitive import Redactor, session_redactors

EVENT_LIMIT = 500
OBSERVABLE_LIMIT = 100
FINDING_LIMIT = 100


def ecuador_time(value):
    if value is None:
        return "Sin registro"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo("America/Guayaquil")).strftime("%Y-%m-%d %H:%M:%S UTC-05:00")


def stored_time(value):
    if not value:
        return "Sin fecha"
    try:
        return ecuador_time(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return "Fecha sin verificar"


def report_snapshot(conn, tables, honeypot_id, session_id, analysis_id=None, modality="desconocido",
                    sensors=None, instances=None):
    session, event, analysis = (tables[name] for name in ("sesion", "evento", "analisis_llm"))
    record = conn.execute(select(session).where(
        session.c.id_sesion == session_id, session.c.id_honeypot == honeypot_id
    )).mappings().first()
    if not record:
        raise HTTPException(404, "Sesión no encontrada")

    events = conn.execute(select(event.c.id_evento, event.c.tipo_evento, event.c.fecha_hora)
        .where(event.c.id_sesion == session_id)
        .order_by(event.c.fecha_hora, event.c.numero_secuencia, event.c.id_evento).limit(EVENT_LIMIT)).all()
    groups = conn.execute(select(event.c.tipo_evento, func.count(), func.min(event.c.id_evento))
        .where(event.c.id_sesion == session_id).group_by(event.c.tipo_evento)).all()
    counts = {kind: count for kind, count, _ in groups}
    examples = {kind: eid for kind, _, eid in groups}
    total = sum(counts.values())
    analysis_query = select(analysis).where(
        analysis.c.id_sesion == session_id, analysis.c.estado == "completado"
    )
    if analysis_id is not None:
        analysis_query = analysis_query.where(analysis.c.id_analisis == analysis_id)
    saved = conn.execute(analysis_query.order_by(func.coalesce(analysis.c.fecha_inicio, analysis.c.creado_en).desc(),
               analysis.c.id_analisis.desc()).limit(1)).mappings().first()
    if not saved:
        raise HTTPException(409, "Complete el análisis de esta sesión antes de generar el informe")
    covered = analyzed_count(saved) if saved else None
    inputs, _ = current_inputs(conn, tables, [session_id], sensors or (honeypot_id,), instances or {})
    freshness = result_freshness(saved.resultado_estructurado, inputs[session_id])
    state = states_for_sessions(conn, analysis, inputs)[session_id]
    status = ("Análisis histórico · vigencia no verificable" if freshness["metodologia"] == "no_verificable"
              else "Análisis desactualizado" if freshness["metodologia"] == "desactualizada"
              or freshness["cobertura_eventos"] == "incompleta" else "Análisis vigente")

    obs, ioc, typ = (tables[name] for name in ("observacion_ioc", "ioc", "tipo_ioc"))
    observed = select(typ.c.nombre, ioc.c.valor, obs.c.estado_revision,
        func.count(func.distinct(obs.c.id_evento)), func.min(obs.c.id_evento))
    observed = (observed
        .select_from(obs).join(event, obs.c.id_evento == event.c.id_evento)
        .join(ioc, obs.c.id_ioc == ioc.c.id_ioc).join(typ, typ.c.id_tipo_ioc == ioc.c.id_tipo_ioc)
        .where(event.c.id_sesion == session_id)
        .group_by(typ.c.nombre, ioc.c.valor, obs.c.estado_revision)
        .order_by(typ.c.nombre, ioc.c.valor, obs.c.estado_revision))
    observations = conn.execute(observed.limit(OBSERVABLE_LIMIT + 1)).all()
    observation_total = (conn.scalar(select(func.count()).select_from(observed.order_by(None).subquery()))
                         if len(observations)>OBSERVABLE_LIMIT else len(observations))

    mappings = list(mapping_evidence(conn,tables,analysis_id=saved.id_analisis,limit=FINDING_LIMIT+1))

    commands = conn.execute(select(event.c.id_evento, event.c.fecha_hora,
        event.c.datos_originales["input"].as_string()).where(event.c.id_sesion == session_id,
        event.c.tipo_evento == "cowrie.command.input").order_by(event.c.fecha_hora,
        event.c.numero_secuencia, event.c.id_evento).limit(EVENT_LIMIT)).all()
    report = assemble_report(record, total, counts, events, saved, covered, status, observations, mappings, examples)
    sections = report["sections"]
    sensor_scope = sensors or (honeypot_id,)
    ioc_scope = observation_query(tables, sensor_scope, instances or {}, IocFilters()).where(
        session.c.id_sesion == session_id).subquery().c
    mitre_scope = mapping_rows(tables, sensor_scope, instances or {}, MitreFilters()).where(
        analysis.c.id_analisis == saved.id_analisis).subquery().c
    intelligence = conn.execute(observable_totals(ioc_scope)).mappings().one()
    sections.append({"title":"Indicadores del alcance", "columns":["Indicador", "Cantidad"], "paragraphs":[
        "IoCs únicos observados en la sesión y técnicas distintas con mapeo en el análisis seleccionado. Los totales incluyen registros históricos y descartados."],
        "rows":[["IoCs observados",str(intelligence.observables)],["IoCs con evidencia verificable",str(intelligence.verificables)],
                ["Técnicas MITRE registradas",str(conn.scalar(select(technique_count(mitre_scope))))]]})
    mapping_total = (conn.scalar(select(func.count()).select_from(mitre_scope.codigo_tecnica.table))
                     if len(mappings)>FINDING_LIMIT else len(mappings))
    coverage_rows = [("Cronología y reglas de captura",total,len(events)),
                     ("Registro de comandos",counts.get("cowrie.command.input",0),len(commands)),
                     ("Grupos de observables por revisión",observation_total,min(len(observations),OBSERVABLE_LIMIT)),
                     ("Mapeos MITRE",mapping_total,min(len(mappings),FINDING_LIMIT))]
    coverage = [{"seccion":name,"disponibles":available,"incluidos":included,"omitidos":available-included,
                 "estado":"no_disponible" if not available else "limitada" if available>included else "disponible"}
                for name,available,included in coverage_rows]
    sections.insert(1,{"title":"Cobertura por sección", "paragraphs":["Los totales corresponden al alcance identificado del informe."],
        "columns":["Sección","Disponibles","Incluidos","Omitidos","Estado"],
        "rows":[[item["seccion"],str(item["disponibles"]),str(item["incluidos"]),str(item["omitidos"]),
                 {"no_disponible":"No disponible","limitada":"Limitada","disponible":"Disponible"}[item["estado"]]] for item in coverage]})
    evidence_digest = freshness["evidencia_sha256"] or "Sin huella histórica"
    sections.insert(0, dict(title="Vigencia y cobertura del análisis", columns=["Campo", "Valor"], rows=[
        ["Cobertura de eventos", freshness["cobertura_eventos"]],
        ["Vigencia metodológica", freshness["metodologia"].replace("_", " ")],
        ["Último intento de la sesión", state["estado_ultimo_intento"].replace("_", " ")],
        ["Huella de la evidencia seleccionada", evidence_digest],
    ], paragraphs=[
        "El análisis seleccionado no conserva un conteo verificable." if covered is None else
        f"El resultado registra {covered} eventos analizados. Actualmente hay {total} almacenados.",
        "La cronología y los observables corresponden a los registros actuales de la sesión. La interpretación y los mapeos corresponden al análisis seleccionado.",
    ]))
    sections.insert(1, dict(title="Registro de comandos", columns=["Hora Ecuador", "Entrada en Cowrie", "Evento"],
        paragraphs=[f"{len(commands)} entradas mostradas de {counts.get('cowrie.command.input', 0)} registradas. "
                    "Cada fila identifica el texto recibido por el señuelo. La entrada por sí sola no acredita su resultado."],
        rows=[[ecuador_time(when), command or "Entrada sin texto", f"#{eid}"] for eid, when, command in commands]))
    detail = ((saved.resultado_estructurado or {}).get("informe") or {}) if saved else {}
    enrichment = (saved.resultado_estructurado or {}).get("enriquecimiento") or {}
    external_rows = []
    for observable in enrichment.get("observables", []):
        for provider, result in observable.get("proveedores", {}).items():
            results = result if isinstance(result, list) else [result, *result.get("coincidencias", [])] if isinstance(result, dict) else []
            for entry in results:
                if entry.get("estado") == "omitido":
                    reason = ("Esta integración de URLhaus evalúa archivos por SHA-256. La dirección IP no identifica un archivo."
                              if provider == "urlhaus" else
                              "La IP tiene alcance local. Su reputación pública no permite atribuir la actividad de esta sesión. Contrastar con los registros de la red del sensor.")
                    external_rows.append([provider, observable.get("valor", ""), reason, "Evaluación local, sin consulta remota"])
                    continue
                external_rows.append([provider, observable.get("valor", ""), str(entry.get("estado", entry.get("resultado", "coincidencia"))),
                                      stored_time(entry.get("consultado_en")) + " " + str(entry.get("url", ""))])
    if external_rows:
        sections.append(dict(title="Evaluación por fuente externa", columns=["Proveedor", "Observable", "Evaluación", "Referencia"],
                             paragraphs=[], rows=external_rows))
    assessment = ((saved.resultado_estructurado or {}).get("evaluacion_incidente") or {}) if saved else {}
    if assessment:
        if evidence := assessment.get("snapshot_sha256"):
            sections.append(dict(title="Conjunto de evidencia del triaje", columns=[], rows=[], paragraphs=[
                f"Eventos de la evaluación {assessment['eventos_evaluados']}. Huella SHA-256 {evidence}."
            ]))
        for revision in assessment.get("revisiones", []):
            sections.append(dict(title="Decisión documentada del analista", columns=["Campo", "Valor"], paragraphs=[],
                rows=[[key.replace('_', ' '), stored_time(revision.get(key)) if key == "revisado_en" else str(revision.get(key, ""))] for key in
                      ("decision", "severidad", "justificacion", "criterio_incidente", "impacto", "alcance",
                       "responsable", "medidas", "estado", "criterio_cierre", "revisado_por", "revisado_en", "eventos")]))
    narrative = []
    def add(title, paragraphs):
        text = [item for item in paragraphs if isinstance(item, str) and item.strip()]
        if text:
            narrative.append(dict(title=title, paragraphs=text, columns=[], rows=[]))
    add("Contexto del análisis LLM", [detail.get("contexto")])
    for phase in detail.get("fases") or []:
        refs = ", ".join(f"#{eid}" for eid in phase.get("eventos", []))
        add(phase.get("fase") or "Fase observada", [
            f"{label}: {phase[key]}" for key, label in (("observado","Observación"),("interpretacion","Interpretación del modelo"),("resultado","Resultado documentado")) if phase.get(key)
        ] + ([f"Evidencia: {refs}"] if refs else []))
    for hypothesis in detail.get("hipotesis") or []:
        refs = ", ".join(f"#{eid}" for eid in hypothesis.get("eventos", []))
        add("Hipótesis del modelo", [hypothesis.get("descripcion"), f"Evidencia vinculada: {refs}" if refs else None])
    add("Conclusión del análisis", [detail.get("conclusion")])
    add("Limitaciones de la evidencia", detail.get("limitaciones") or [])
    safeguards = detail.get("recomendaciones") or []
    from .analysis_report import safeguard_cards
    for card in safeguard_cards(safeguards):
        narrative.append(dict(title="Propuesta de salvaguarda · " + card["rows"][0][1],
                              paragraphs=[], columns=["Campo", "Detalle"], rows=card["rows"]))
    index = next(i for i, item in enumerate(sections) if item["title"] == "Cronología de evidencia")
    sections[index:index] = narrative
    from .operational_report import analyst_sections
    from .safeguards import linked_tasks
    safeguard_links = linked_tasks(conn, tables, saved.id_analisis) if "salvaguarda" in tables else {}
    report = analyst_sections(report, saved.resultado_estructurado or {}, commands, safeguard_links)
    raw_events = conn.execute(select(event.c.id_evento, event.c.tipo_evento, event.c.fecha_hora, event.c.datos_originales)
        .where(event.c.id_sesion == session_id).order_by(event.c.fecha_hora, event.c.id_evento).limit(EVENT_LIMIT)).all()
    from .report_evidence import complete_assessment
    report = complete_assessment(report, raw_events, record, saved.resultado_estructurado or {}, total, modality=modality)
    report["sections"] = [item for item in report["sections"]
                          if item["title"] != "Salvaguardas defensivas para un servidor Linux en producción"]
    from .analysis_presentation import analytical_sections
    report["sections"][1:1] = analytical_sections(saved.resultado_estructurado or {})
    report = session_redactors(conn, event, [session_id])[session_id].payload(report)
    return {**report, "cobertura_secciones": coverage, "revision_eventos":record.revision_eventos,
            "vigencia_analisis": freshness, "estado_ultimo_intento": state["estado_ultimo_intento"],
            "ultimo_resultado_exitoso": state["analisis"]}


def observable_value(kind, value):
    return Redactor((value,)).text(value, observable_url=kind == "URL")


def assemble_report(record, total, counts, events, saved, covered, status, observations, mappings, examples=None):
    def section(title, paragraphs=(), columns=(), rows=()):
        return dict(title=title, paragraphs=list(paragraphs), columns=list(columns), rows=list(rows))

    def reference(event_id):
        if isinstance(event_id, (list, tuple)):
            return ", ".join(f"#{eid}" for eid in event_id) or "Sin cita específica guardada"
        return f"#{event_id}" if event_id is not None else "Sin referencia"

    review = {"pendiente": "Pendiente", "confirmado": "Confirmado", "descartado": "Descartado"}
    if examples is None:
        examples = {kind: eid for eid, kind, _ in events}
    safeguards = []
    for kind, measure, check in (
        ("cowrie.login.success", "Verificar el origen del acceso", "Contrastar la IP y la hora con los registros de acceso y autorización disponibles."),
        ("cowrie.login.failed", "Revisar los intentos de acceso", "Comparar origen y frecuencia con otras sesiones antes de proponer restricciones."),
        ("cowrie.command.input", "Proteger el registro de comandos", "Conservar el original con acceso restringido y revisar las entradas por si contienen secretos antes de compartir el informe."),
        ("cowrie.session.file_download", "Revisar la salida de red del señuelo", "Contrastar el destino registrado con las reglas de salida de la VM."),
    ):
        if kind in examples:
            safeguards.append((measure, check, reference(examples[kind])))
    for kind, value, state, _, eid in observations[:OBSERVABLE_LIMIT]:
        if state == "pendiente":
            safeguards.append(("Validar el observable", f"Contrastar {kind} {observable_value(kind, value)} con su evento en Observables e IoCs.", reference(eid)))
    mapping_rows = []
    mitre_outcome = ((saved.resultado_estructurado or {}).get('clasificacion_mitre') or {}) if saved else {}
    no_mapping = ('No determinada: ' + mitre_outcome['motivo'] if mitre_outcome.get('motivo') else
                  'El análisis guardado no contiene mapeos registrados.')
    degrees = {'intento':'Intento','resultado_en_honeypot':'Resultado observado en el honeypot'}
    for mapping in mappings[:FINDING_LIMIT]:
        provenance = mapping['rag_procedencia'] or {}
        code, name, state = (mapping[key] for key in ('codigo_tecnica','tecnica','estado_revision'))
        references = ', '.join(reference(event['id_evento']) for event in mapping['eventos']) or 'Sin citas verificables'
        automatic = provenance.get('clasificacion') == AUTO_CLASSIFICATION
        if automatic:
            classification = {'descartado':'Descartada por revisión',
                              'confirmado':'Identificada automáticamente · Confirmada en revisión'}.get(state,'Identificada automáticamente')
        else:
            classification = {'pendiente':'Histórico · pendiente de revisión','confirmado':'Histórico · confirmado',
                              'descartado':'Histórico · descartado'}.get(state,'Mapeo histórico')
        limitations = provenance.get('limitaciones')
        limits = ' '.join(item for item in limitations if isinstance(item,str)) if isinstance(limitations,list) else ''
        mapping_rows.append((f'{code} · {name}', f"{mapping['codigo_tactica']} · {mapping['tactica']}",
                             '\n'.join((classification, degrees.get(mapping['grado_evidencia'],'Sin grado registrado'),
                                        provenance.get('modalidad') or 'Modalidad no registrada')),
                             references, '\n'.join(filter(None,(mapping['justificacion'],limits))) or 'Sin detalle registrado'))
        if state == 'pendiente' and not automatic:
            safeguards.append((f'Revisar {code}', f'Verificar la propuesta histórica «{name}» en MITRE ATT&CK.', references))
    summary = [
        f"Eventos registrados: {total}. Comandos: {counts.get('cowrie.command.input', 0)}. "
        f"Autenticaciones aceptadas por el señuelo: {counts.get('cowrie.login.success', 0)}.",
        "Alcance: una sesión de un honeypot Cowrie en el laboratorio. "
        "La actividad del señuelo no permite determinar impacto en sistemas reales.",
    ]
    if saved and covered is not None:
        summary.append(f"El análisis guardado examinó {covered} de los {total} eventos registrados.")
    sections = [
        section("Resumen y alcance", summary),
        section("Distribución de actividad", ["Frecuencia de cada tipo de evento en la sesión completa."],
                ("Tipo de evento", "Registros"),
                [(kind, str(count)) for kind, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]),
        section("Cronología de evidencia",
                [f"Se muestran los primeros {len(events)} de {total} eventos. Consulte la sesión para revisar el resto."]
                if total > len(events) else ([] if events else ["No hay eventos registrados."]),
                ("Hora Ecuador", "Evento Cowrie", "Referencia"),
                [(ecuador_time(when), kind, reference(event_id)) for event_id, kind, when in events]),
        section("Observables",
                ["Los valores se agrupan por estado de revisión. Las URL se muestran sin credenciales, consulta ni fragmento. La referencia es un evento de ejemplo."] +
                (["Se muestran los primeros 100 grupos."] if len(observations) > OBSERVABLE_LIMIT else []) +
                ([] if observations else ["No hay observables registrados para esta sesión."]),
                ("Tipo", "Valor", "Revisión", "Eventos", "Referencia"),
                [(kind, observable_value(kind, value), review.get(state, state), str(count), reference(event_id))
                 for kind, value, state, count, event_id in observations[:OBSERVABLE_LIMIT]]),
        section("Mapeos MITRE ATT&CK",
                ["Las referencias son las citas conservadas para cada técnica. Los mapeos históricos sin citas verificables requieren revisión. La identificación automática no confirma el éxito del ataque."] +
                (["Se muestran los primeros 100 mapeos."] if len(mappings) > FINDING_LIMIT else []) +
                ([] if mappings else [no_mapping]),
                ("Técnica", "Táctica", "Estado, grado y modalidad", "Eventos", "Justificación y limitaciones"),
                mapping_rows),
        section("Comprobaciones automáticas de la captura",
                ["Lista calculada por reglas según los tipos de evento y revisiones pendientes. La referencia identifica su evidencia. Las salvaguardas específicas del análisis se presentan en sus fichas."]
                if safeguards else ["La evidencia disponible no activa una recomendación específica."],
                ("Medida propuesta", "Comprobación", "Evento de referencia"), safeguards),
    ]
    if saved and saved.resumen:
        sections.insert(1, section("Interpretación del análisis guardado", [
            "Resumen generado por el modelo y sujeto a revisión.",
            saved.resumen if (saved.resultado_estructurado or {}).get("version_esquema") else
            saved.resumen[:3500] + ("… Consulte el resultado completo en TacticLens." if len(saved.resumen) > 3500 else ""),
        ]))
    return {
        "title": "Informe de análisis de sesión " + record.cowrie_session_id,
        "reference": str(record.id_sesion) + " / " + str(saved.id_analisis) if saved else str(record.id_sesion),
        "id_sesion": str(record.id_sesion),
        "id_analisis": str(saved.id_analisis) if saved else None,
        "status": status,
        "metadata": [
            ("Sesión Cowrie", record.cowrie_session_id),
            ("Origen observado", str(record.ip_origen or "Sin registro")),
            ("Inicio de la sesión (Ecuador)", ecuador_time(record.fecha_inicio)),
            ("Cierre de la sesión (Ecuador)", ecuador_time(record.fecha_fin)),
            ("ID de sesión", str(record.id_sesion)),
            ("Análisis", str(saved.id_analisis) if saved else "Sin registro"),
        ],
        "event_counts": counts,
        "sections": sections,
    }
