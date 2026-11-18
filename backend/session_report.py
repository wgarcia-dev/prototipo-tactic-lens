"""A consistent, read-only view of the evidence behind a Cowrie session."""
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException
from sqlalchemy import func, select

from .analysis_state import analyzed_count

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
    counts = dict(conn.execute(select(event.c.tipo_evento, func.count())
        .where(event.c.id_sesion == session_id).group_by(event.c.tipo_evento)).tuples().all())
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

    return assemble_report(record, total, counts, events, saved, covered, status, observations, mappings)


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


def assemble_report(record, total, counts, events, saved, covered, status, observations, mappings):
    def section(title, paragraphs=(), columns=(), rows=()):
        return dict(title=title, paragraphs=list(paragraphs), columns=list(columns), rows=list(rows))

    def reference(event_id):
        return f"#{event_id}" if event_id is not None else "Sin referencia"

    review = {"pendiente": "Pendiente", "confirmado": "Confirmado", "descartado": "Descartado"}
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
        section("Seguimiento",
                ["Revisar los observables y mapeos pendientes con sus eventos de origen.",
                 "Correlacionar con fuentes externas al señuelo antes de determinar impacto.",
                 "Conservar los registros originales de Cowrie para consultas posteriores."]),
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
        "sections": sections,
    }
