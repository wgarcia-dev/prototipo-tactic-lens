"""A consistent, read-only view of the evidence behind a Cowrie session."""
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException
from sqlalchemy import func, select

from .analysis_state import analyzed_count
from .rag.behavior import redact

EVENT_LIMIT = 500
OBSERVABLE_LIMIT = 100
FINDING_LIMIT = 100


def utc(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if value else "Sin registro"


def report_snapshot(conn, tables, honeypot_id, session_id):
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
    saved = conn.execute(select(analysis).where(
        analysis.c.id_sesion == session_id, analysis.c.estado == "completado"
    ).order_by(func.coalesce(analysis.c.fecha_inicio, analysis.c.creado_en).desc(),
               analysis.c.id_analisis.desc()).limit(1)).mappings().first()
    covered = analyzed_count(saved) if saved else None
    status = (
        "Sin análisis guardado" if not saved else
        "Cobertura del análisis sin verificar" if covered is None else
        "Análisis desactualizado" if covered != total else "Análisis vigente"
    )

    obs, ioc, typ = (tables[name] for name in ("observacion_ioc", "ioc", "tipo_ioc"))
    observations = conn.execute(select(typ.c.nombre, ioc.c.valor, obs.c.estado_revision,
        func.count(func.distinct(obs.c.id_evento)), func.min(obs.c.id_evento))
        .select_from(obs).join(event, obs.c.id_evento == event.c.id_evento)
        .join(ioc, obs.c.id_ioc == ioc.c.id_ioc).join(typ, typ.c.id_tipo_ioc == ioc.c.id_tipo_ioc)
        .where(event.c.id_sesion == session_id)
        .group_by(typ.c.nombre, ioc.c.valor, obs.c.estado_revision)
        .order_by(typ.c.nombre, ioc.c.valor, obs.c.estado_revision)
        .limit(OBSERVABLE_LIMIT + 1)).all()

    mappings = []
    if saved:
        m, a, tt, tech = (tables[name] for name in
            ("mapeo_mitre", "accion_identificada", "tecnica_tactica", "tecnica_mitre"))
        link = tables["accion_evento"]
        example = select(func.min(link.c.id_evento)).where(link.c.id_accion == a.c.id_accion)
        example = example.correlate(a).scalar_subquery()
        mappings = conn.execute(select(tech.c.codigo_tecnica, tech.c.nombre, m.c.estado_revision, example)
            .select_from(m).join(a, m.c.id_accion == a.c.id_accion)
            .join(tt, m.c.id_vinculo == tt.c.id_vinculo)
            .join(tech, tt.c.codigo_tecnica == tech.c.codigo_tecnica)
            .where(a.c.id_analisis == saved.id_analisis)
            .order_by(tech.c.codigo_tecnica, m.c.id_mapeo).limit(FINDING_LIMIT + 1)).all()

    commands = conn.execute(select(event.c.id_evento, event.c.fecha_hora,
        event.c.datos_originales["input"].as_string()).where(event.c.id_sesion == session_id,
        event.c.tipo_evento == "cowrie.command.input").order_by(event.c.fecha_hora,
        event.c.numero_secuencia, event.c.id_evento).limit(EVENT_LIMIT)).all()
    report = assemble_report(record, total, counts, events, saved, covered, status, observations, mappings, examples)
    sections = report["sections"]
    sections.insert(1, dict(title="Registro de comandos", columns=["Hora UTC", "Entrada en Cowrie", "Evento"],
        paragraphs=[f"{len(commands)} entradas mostradas de {counts.get('cowrie.command.input', 0)} registradas. "
                    "Cada fila identifica el texto recibido por el señuelo. La entrada por sí sola no acredita su resultado."],
        rows=[[utc(when), command or "Entrada sin texto", f"#{eid}"] for eid, when, command in commands]))
    detail = ((saved.resultado_estructurado or {}).get("informe") or {}) if saved else {}
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
    # Preserve every section and row, including tuple-backed SQL results.
    report["metadata"] = [[label, redact(value)] for label, value in report["metadata"]]
    for section in sections:
        section["title"] = redact(section["title"])
        section["paragraphs"] = [redact(value) for value in section["paragraphs"]]
        section["rows"] = [[redact(value) for value in row] for row in section["rows"]]
    return report


def observable_value(kind, value):
    if kind != "URL":
        return value
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return "URL no disponible"
        return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))
    except ValueError:
        return "URL no disponible"


def assemble_report(record, total, counts, events, saved, covered, status, observations, mappings, examples=None):
    def section(title, paragraphs=(), columns=(), rows=()):
        return dict(title=title, paragraphs=list(paragraphs), columns=list(columns), rows=list(rows))

    def reference(event_id):
        return f"#{event_id}" if event_id is not None else "Sin referencia"

    review = {"pendiente": "Pendiente", "confirmado": "Confirmado", "descartado": "Descartado"}
    if examples is None:
        examples = {kind: eid for eid, kind, _ in events}
    safeguards = []
    for kind, measure, check in (
        ("cowrie.login.success", "Verificar el origen del acceso", "Contrastar la IP y la hora con las pruebas autorizadas del laboratorio."),
        ("cowrie.login.failed", "Revisar los intentos de acceso", "Comparar origen y frecuencia con otras sesiones antes de proponer restricciones."),
        ("cowrie.command.input", "Proteger el registro de comandos", "Conservar el original con acceso restringido y revisar las entradas por si contienen secretos antes de compartir el informe."),
        ("cowrie.session.file_download", "Revisar la salida de red del señuelo", "Contrastar el destino registrado con las reglas de salida de la VM."),
    ):
        if kind in examples:
            safeguards.append((measure, check, reference(examples[kind])))
    for kind, value, state, _, eid in observations[:OBSERVABLE_LIMIT]:
        if state == "pendiente":
            safeguards.append(("Validar el observable", f"Contrastar {kind} {observable_value(kind, value)} con su evento en Observables e IoCs.", reference(eid)))
    for code, name, state, eid in mappings[:FINDING_LIMIT]:
        if state == "pendiente":
            safeguards.append((f"Revisar {code}", f"Verificar la propuesta «{name}» en MITRE ATT&CK y registrar el motivo de la decisión.", reference(eid)))
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
                ("Hora UTC", "Evento Cowrie", "Referencia"),
                [(utc(when), kind, reference(event_id)) for event_id, kind, when in events]),
        section("Observables",
                ["Los valores se agrupan por estado de revisión. Las URL se muestran sin credenciales, consulta ni fragmento. La referencia es un evento de ejemplo."] +
                (["Se muestran los primeros 100 grupos."] if len(observations) > OBSERVABLE_LIMIT else []) +
                ([] if observations else ["No hay observables registrados para esta sesión."]),
                ("Tipo", "Valor", "Revisión", "Eventos", "Referencia"),
                [(kind, observable_value(kind, value), review.get(state, state), str(count), reference(event_id))
                 for kind, value, state, count, event_id in observations[:OBSERVABLE_LIMIT]]),
        section("Mapeos MITRE ATT&CK",
                ["Asociaciones del análisis guardado. La referencia corresponde a un evento de la acción asociada."] +
                (["Se muestran los primeros 100 mapeos."] if len(mappings) > FINDING_LIMIT else []) +
                ([] if mappings else ["No hay mapeos registrados para el análisis de la sesión."]),
                ("Técnica", "Revisión", "Referencia"),
                [(f"{code} · {name}", review.get(state, state), reference(event_id))
                 for code, name, state, event_id in mappings[:FINDING_LIMIT]]),
        section("Comprobaciones vinculadas a la evidencia",
                ["Medidas propuestas para revisión humana. La referencia identifica un evento de la sesión o de la acción asociada."]
                if safeguards else ["La evidencia disponible no activa una recomendación específica."],
                ("Medida propuesta", "Comprobación", "Evento de referencia"), safeguards),
    ]
    if saved and saved.resumen:
        sections.insert(1, section("Interpretación del análisis guardado", [
            "Resumen generado por el modelo y sujeto a revisión.",
            saved.resumen[:3500] + ("… Consulte el resultado completo en TacticLens." if len(saved.resumen) > 3500 else ""),
        ]))
    return {
        "title": "Informe de actividad observada",
        "reference": str(record.id_sesion),
        "status": status,
        "metadata": [
            ("Sesión Cowrie", record.cowrie_session_id),
            ("Origen observado", str(record.ip_origen or "Sin registro")),
            ("Inicio UTC", utc(record.fecha_inicio)),
            ("Cierre UTC", utc(record.fecha_fin)),
            ("Generado UTC", utc(datetime.now(timezone.utc))),
            ("Análisis", str(saved.id_analisis) if saved else "Sin registro"),
        ],
        "event_counts": counts,
        "sections": sections,
    }
