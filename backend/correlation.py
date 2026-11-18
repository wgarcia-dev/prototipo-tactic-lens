"""Evidence joins for Cowrie observables, actions and existing MITRE mappings."""
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import Text, and_, cast, func, select
from sqlalchemy.dialects.postgresql import JSONB

from .intelligence import DOWNLOAD, FAILED_DOWNLOAD
from .rag.behavior import technique_profiles


TRANSFER_METHOD = "url_sesion_orden_cowrie_v1"
ACTION_METHOD = "deteccion_observacion_accion_evento_v1"
MITRE_METHOD = "cita_mitre_evento_compartido_v1"
ATTEMPT = "intento_descarga"
OUTCOMES = {DOWNLOAD: "descarga_registrada", FAILED_DOWNLOAD: "descarga_fallida"}
MAX_VISIBLE_CANDIDATES = 20
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MICROSECOND = timedelta(microseconds=1)


def transfer_window(value):
    if not value or not value.strip():
        return None
    try:
        seconds = int(value)
        if seconds > 0:
            return seconds
    except ValueError:
        pass
    raise ValueError("IOC_CORRELACION_MAX_SEGUNDOS debe ser un entero positivo o quedar vacío")


def event_columns(event):
    return [event.c.id_evento, event.c.id_sesion, event.c.tipo_evento, event.c.fecha_hora,
            event.c.ingresado_en, event.c.numero_secuencia]


def event_ref(row):
    return {name: row[name] for name in ("id_sesion", "tipo_evento", "fecha_hora", "ingresado_en", "numero_secuencia")} | {
        "id_evento": str(row["id_evento"]),
    }


def roles(row):
    return {detail["comportamiento"] for detail in row["detalles"]}


def transfer_role(row):
    if row["tipo_evento"] == "cowrie.command.input" and ATTEMPT in roles(row):
        return ATTEMPT
    outcome = OUTCOMES.get(row["tipo_evento"])
    return outcome if outcome and outcome in roles(row) else None


def chronology(row):
    return row["fecha_hora"], row["numero_secuencia"], row["id_evento"]


def time_key(row):
    return (row["fecha_hora"] - EPOCH) // MICROSECOND


def transfer_correlations(rows, anchors, seconds=None):
    """Compare earlier commands and later results for one URL in each session."""
    sessions = defaultdict(lambda: ([], []))
    for row in sorted(rows, key=chronology):
        role = transfer_role(row)
        if role:
            sessions[row["id_sesion"]][role != ATTEMPT].append(row)
    results = {}
    window = None if seconds is None else seconds * 1_000_000
    for attempts, transfers in sessions.values():
        groups = (attempts, transfers)
        times = tuple([time_key(row) for row in group] for group in groups)

        def candidates(side, at):
            other = times[1 - side]
            if side == 0:
                return bisect_left(other, at), len(other) if window is None else bisect_right(other, at + window)
            return 0 if window is None else bisect_left(other, at - window), bisect_right(other, at)

        for side, group in enumerate(groups):
            for row in group:
                if row["id_evento"] not in anchors:
                    continue
                at = time_key(row)
                start, end = candidates(side, at)
                total = end - start
                related = groups[1 - side][start:min(start + MAX_VISIBLE_CANDIDATES, end)]
                if not related:
                    status = "insuficiente"
                    justification = ("No se encontró un resultado posterior de esta URL en la sesión." if side == 0 else
                                     "No se encontró un comando anterior con esta URL en la sesión.")
                elif total > 1:
                    status = "candidata"
                    justification = "Varios eventos de la misma sesión coinciden con la URL en el intervalo admisible."
                else:
                    counterpart_time = time_key(related[0])
                    other_start, other_end = candidates(1 - side, counterpart_time)
                    if counterpart_time == at:
                        status = "candidata"
                        justification = "Los eventos comparten timestamp de Cowrie y su orden es indeterminado."
                    elif other_end - other_start > 1:
                        status = "candidata"
                        justification = "La contraparte también coincide con otros eventos; el emparejamiento es ambiguo."
                    else:
                        status = "contextual"
                        justification = "Comando anterior y resultado posterior con la misma URL en la misma sesión."
                results[row["id_evento"]] = {
                    "tipo": "comando_transferencia", "estado": status, "metodo": TRANSFER_METHOD,
                    "justificacion": justification, "ventana_segundos": seconds, "total_candidatos": total,
                    "limitaciones": ["La secuencia y la URL no demuestran causalidad ni ejecución del archivo."],
                    "eventos": [{**event_ref(item), "rol": transfer_role(item)} for item in (row, *related)],
                }
    return results


def observed_correlations(conn, tables, indicator, rows, window):
    """Correlations are computed on read so late arrivals can change ambiguity."""
    obs, event, ioc, kind = (tables[name] for name in ("observacion_ioc", "evento", "ioc", "tipo_ioc"))
    result = defaultdict(list)
    if indicator["tipo"] == "URL":
        anchors = {row.id_evento for row in rows if transfer_role(row)}
        if anchors:
            sessions = {row.id_sesion for row in rows if row.id_evento in anchors}
            related = conn.execute(select(*event_columns(event), obs.c.detalles)
                .select_from(obs.join(event, event.c.id_evento == obs.c.id_evento))
                .where(obs.c.id_ioc == rows[0].id_ioc, event.c.id_sesion.in_(sessions),
                       event.c.tipo_evento.in_(("cowrie.command.input", *OUTCOMES)),
                       func.jsonb_array_length(obs.c.detalles) > 0)).mappings()
            for event_id, correlation in transfer_correlations(related, anchors, window).items():
                result[event_id].append(correlation)
    other_role = {"URL": "archivo_capturado", "Hash": "descarga_registrada"}.get(indicator["tipo"])
    expected_role = {"URL": "descarga_registrada", "Hash": "archivo_capturado"}.get(indicator["tipo"])
    files = {row.id_evento: row for row in rows if other_role and row.tipo_evento == DOWNLOAD and expected_role in roles(row)}
    if files:
        counterparts = conn.execute(select(obs.c.id_evento, obs.c.id_ioc, obs.c.id_observacion, ioc.c.valor,
            kind.c.nombre.label("tipo"), obs.c.detalles)
            .select_from(obs.join(ioc, ioc.c.id_ioc == obs.c.id_ioc)
                .join(kind, kind.c.id_tipo_ioc == ioc.c.id_tipo_ioc))
            .where(obs.c.id_evento.in_(files),
                   kind.c.nombre == ("Hash" if indicator["tipo"] == "URL" else "URL"))
            .order_by(obs.c.id_evento, obs.c.id_ioc)).mappings()
        for other in counterparts:
            if other_role in roles(other):
                result[other.id_evento].append({
                    "tipo": "url_archivo", "estado": "directa", "metodo": "url_shasum_mismo_evento_v1",
                    "justificacion": "Cowrie registró la URL y el SHA-256 en el mismo evento de descarga.",
                    "limitaciones": ["El SHA-256 procede del sensor. La transferencia no demuestra ejecución."],
                    "eventos": [event_ref(files[other.id_evento])],
                    "observable": {key: other[key] for key in ("id_ioc", "id_observacion", "tipo", "valor")},
                })
    return result


def action_observable_query(tables):
    d, ai, action, evidence, obs, event, analysis, ioc, kind = (tables[name] for name in (
        "deteccion_ioc", "accion_ioc", "accion_identificada", "accion_evento", "observacion_ioc", "evento",
        "analisis_llm", "ioc", "tipo_ioc"))
    features = analysis.c.resultado_estructurado["rag"]["representacion"]["rasgos_por_evento"].op(
        "->", return_type=JSONB)(cast(d.c.id_evento, Text))
    return (select(d.c.id_ioc, action.c.id_accion, action.c.tipo_accion, d.c.id_analisis,
        d.c.id_observacion.label("id_observacion_verificada"), obs.c.id_observacion,
        obs.c.detalles, obs.c.estado_revision.label("revision_observable"),
        evidence.c.id_evento.label("evento_accion"), d.c.evidencia.label("interpretacion"),
        d.c.confianza.label("confianza_llm"), kind.c.nombre.label("tipo"), ioc.c.valor,
        features.label("rasgos"), *event_columns(event))
        .select_from(d.join(ai, ai.c.id_deteccion == d.c.id_deteccion)
            .join(action, and_(action.c.id_accion == ai.c.id_accion, action.c.id_analisis == d.c.id_analisis))
            .join(analysis, analysis.c.id_analisis == action.c.id_analisis)
            .join(event, and_(event.c.id_evento == d.c.id_evento, event.c.id_sesion == analysis.c.id_sesion))
            .join(ioc, ioc.c.id_ioc == d.c.id_ioc).join(kind, kind.c.id_tipo_ioc == ioc.c.id_tipo_ioc)
            .outerjoin(evidence, and_(evidence.c.id_accion == action.c.id_accion, evidence.c.id_evento == d.c.id_evento))
            .outerjoin(obs, and_(obs.c.id_ioc == d.c.id_ioc, obs.c.id_evento == d.c.id_evento)))
        .where(analysis.c.estado == "completado")
        .order_by(event.c.fecha_hora, d.c.id_evento, action.c.id_accion, d.c.id_ioc))


def action_link(row):
    direct = bool(row.id_observacion_verificada and row.id_observacion_verificada == row.id_observacion
                  and row.evento_accion is not None and row.detalles)
    data = {key: row[key] for key in ("id_ioc", "id_observacion", "tipo", "valor", "id_accion", "tipo_accion",
                                    "id_analisis", "interpretacion", "confianza_llm", "revision_observable")}
    return {**data, "id_evento": str(row.id_evento), "eventos": [event_ref(row)],
            "vinculo_determinista": direct, "estado": "directa" if direct else "insuficiente", "metodo": ACTION_METHOD,
            "justificacion": ("La detección y la acción citan el mismo evento con una observación verificable." if direct else
                              "El vínculo histórico carece de la cadena completa entre observación y evento de la acción."),
            "limitaciones": ["La descripción de la acción es una interpretación del análisis."]}


def mapping_query(tables):
    m, tt, tech, tac = (tables[name] for name in ("mapeo_mitre", "tecnica_tactica", "tecnica_mitre", "tactica_mitre"))
    return (select(m.c.id_mapeo, m.c.id_accion, tech.c.codigo_tecnica, tech.c.nombre.label("tecnica"),
            tac.c.nombre.label("tactica"), m.c.evidencia, m.c.justificacion, m.c.confianza, m.c.estado_revision,
            m.c.motivo_revision, m.c.grado_evidencia, m.c.rag_procedencia, m.c.revisado_por, m.c.revisado_en)
            .select_from(m.join(tt, m.c.id_vinculo == tt.c.id_vinculo)
                .join(tech, tt.c.codigo_tecnica == tech.c.codigo_tecnica)
                .join(tac, tt.c.codigo_tactica == tac.c.codigo_tactica)))


def mapping_evidence(conn, tables, *, action_ids=None, mapping_id=None):
    m, citation, event = (tables[name] for name in ("mapeo_mitre", "mapeo_mitre_evento", "evento"))
    query = mapping_query(tables)
    if mapping_id is not None:
        query = query.where(m.c.id_mapeo == mapping_id)
    else:
        query = query.where(m.c.id_accion.in_(action_ids))
    mappings = {row.id_mapeo: {**row, "eventos": []} for row in conn.execute(
        query.order_by(m.c.id_accion, m.c.id_mapeo)).mappings()}
    if mappings:
        refs = conn.execute(select(citation.c.id_mapeo, citation.c.metodo, *event_columns(event))
            .select_from(citation.join(event, event.c.id_evento == citation.c.id_evento))
            .where(citation.c.id_mapeo.in_(mappings))
            .order_by(event.c.fecha_hora, event.c.numero_secuencia, event.c.id_evento)).mappings()
        for row in refs:
            mappings[row.id_mapeo]["eventos"].append({**event_ref(row), "metodo": row.metodo})
    return mappings.values()


def mitre_link(row, link, mapping):
    """A shared citation is necessary. Only admit observable roles covered by its technique."""
    citation = next((ref for ref in mapping["eventos"] if ref["id_evento"] == link["id_evento"]), None)
    if not link["vinculo_determinista"] or citation is None:
        return None
    provenance = mapping["rag_procedencia"]
    tags = {tag for tag in row.rasgos if isinstance(tag, str)} if isinstance(row.rasgos, list) else set()
    name = provenance.get("nombre_oficial")
    active = tags & technique_profiles(name if isinstance(name, str) else mapping["tecnica"])
    observed_roles = roles(row)
    compatible = (
        ("transfer" in active and bool(observed_roles & {ATTEMPT, "descarga_registrada", "archivo_capturado"}))
        or ("shell" in active and any(detail["campo"] == "input" for detail in row.detalles))
        or ("auth_repeated" in active and row.tipo_evento == "cowrie.login.failed" and "origen_sesion" in observed_roles)
    )
    if not compatible:
        return None
    status = {"pendiente": "candidata", "confirmado": "contextual", "descartado": "insuficiente"}[mapping["estado_revision"]]
    rationale = "La técnica y la detección de la acción citan el mismo evento con un comportamiento compatible."
    if mapping["estado_revision"] == "descartado":
        rationale += " La revisión descartó el mapeo."
    if row.revision_observable == "descartado":
        status = "insuficiente"
        rationale += " La revisión descartó la relevancia de esta observación."
    limitations = provenance.get("limitaciones")
    limitations = [value for value in limitations if isinstance(value, str)] if isinstance(limitations, list) else []
    if citation["metodo"] == "cita_rag_historica_v1":
        limitations.append("El análisis histórico conserva la cita validada, pero no distingue si el modelo la eligió explícitamente.")
        if status == "contextual":
            status = "candidata"
    return {**mapping, "estado": status, "metodo": MITRE_METHOD,
            "fundamento": rationale,
            "evento_compartido": link["id_evento"],
            "limitaciones": [*limitations,
                            "La revisión corresponde al mapeo MITRE. El vínculo con el observable no atribuye causalidad."]}
