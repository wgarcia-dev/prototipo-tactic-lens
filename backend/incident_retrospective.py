"""Recover historical Cowrie candidates without rerunning or confirming an analysis."""

from collections import Counter, defaultdict

from sqlalchemy import select

from .analysis_state import digest
from .correlation import mapping_query
from .incident_assessment import assess
from .incidents import (RELEVANT, SEVERITIES, _automatic_projection, analysis_source, event_fingerprint, grade,
                        saved_evidence, selected_events)
from .ingestion import prepare
from .safeguard_risk import evidence_ids, recommendation_references
from .sensitive import session_redactors


def legacy_citations(conn, tables, source, payload):
    actions, links, events, receipts = (tables[k] for k in (
        "accion_identificada", "accion_evento", "evento", "evento_origen"))
    triage = payload.get("evaluacion_incidente") or {}
    cited = set(conn.scalars(select(links.c.id_evento).join(actions, links.c.id_accion == actions.c.id_accion)
                             .where(actions.c.id_analisis == source.id_analisis)))
    relevant = {"acceso_senuelo": {"cowrie.login.success"}, "interaccion_shell": {"cowrie.command.input"},
                "transferencia": {"cowrie.session.file_download", "cowrie.session.file_upload"}}
    by_event = defaultdict(set)
    for criterion in triage.get("criterios") or []:
        if not isinstance(criterion, dict) or not criterion.get("cumplido"):
            continue
        kinds = relevant.get(criterion.get("criterio"), set())
        for value in evidence_ids(criterion.get("eventos")):
            if kinds:
                by_event[int(value)].update(kinds)
    query = (select(events, receipts.c.origen_id, receipts.c.contenido_sha256)
             .join(receipts, receipts.c.id_evento == events.c.id_evento)
             .where(events.c.id_sesion == source.id_sesion, events.c.id_evento.in_(cited | by_event.keys()),
                    events.c.fecha_hora <= source.analizado_en, receipts.c.registrado_en <= source.analizado_en,
                    receipts.c.id_honeypot == source.id_honeypot))
    verified = []
    for row in conn.execute(query):
        if row.id_evento not in cited and row.tipo_evento not in by_event[row.id_evento]:
            continue
        raw = row.datos_originales
        try:
            _, when, _, checksum = prepare({**raw, "_collector": {"source_id": row.origen_id}})
        except (TypeError, ValueError, OverflowError):
            continue
        if (checksum == row.contenido_sha256 and when == row.fecha_hora and
                raw["eventid"] == row.tipo_evento and raw["session"] == source.cowrie_session_id):
            verified.append(row)
    return verified


def source_material(conn, tables, source, payload, events):
    ids = {row.id_evento for row in events}
    action, links, observations, citations, origin, safeguard = (tables[key] for key in (
        "accion_identificada", "accion_evento", "observacion_ioc", "mapeo_mitre_evento", "salvaguarda_origen", "salvaguarda"))
    behavior = conn.execute(select(action.c.tipo_accion, links.c.id_evento).join(links, links.c.id_accion == action.c.id_accion)
                            .where(action.c.id_analisis == source.id_analisis, links.c.id_evento.in_(ids))
                            .order_by(links.c.id_evento, action.c.tipo_accion)).all()
    obs = conn.execute(select(observations.c.id_observacion, observations.c.id_evento)
                       .where(observations.c.id_evento.in_(ids)).order_by(observations.c.id_observacion)).all()
    mapped = mapping_query(tables).subquery()
    mappings = conn.execute(select(mapped.c.codigo_tecnica, citations.c.id_evento, mapped.c.estado_revision)
                            .select_from(citations.join(mapped, mapped.c.id_mapeo == citations.c.id_mapeo)
                                         .join(action, action.c.id_accion == mapped.c.id_accion))
                            .where(action.c.id_analisis == source.id_analisis, citations.c.id_evento.in_(ids))
                            .order_by(citations.c.id_evento, mapped.c.codigo_tecnica, mapped.c.estado_revision)).all()
    recommendations = {position: refs for position, _, refs in recommendation_references(payload)}
    text_ids = set(map(str, ids))
    safeguards = conn.execute(select(origin.c.posicion, safeguard.c.id_salvaguarda, safeguard.c.codigo, safeguard.c.estado)
                              .join(safeguard, safeguard.c.id_salvaguarda == origin.c.id_salvaguarda)
                              .where(origin.c.id_analisis == source.id_analisis, safeguard.c.id_sesion == source.id_sesion)
                              .order_by(safeguard.c.codigo, origin.c.posicion)).all()
    return {
        "comportamientos": [{"tipo": label, "id_evento": str(eid)} for label, eid in behavior],
        "observables": [{"id_observacion": str(oid), "id_evento": str(eid)} for oid, eid in obs],
        "mitre": [{"tecnica": code, "id_evento": str(eid), "revision": state} for code, eid, state in mappings],
        "salvaguardas": [{"id_salvaguarda": str(row.id_salvaguarda), "codigo": f"SG-{row.codigo:05d}",
                          "estado": row.estado, "posicion": row.posicion,
                          "citas_compatibles": bool(refs := recommendations.get(row.posicion)) and set(refs) <= text_ids}
                         for row in safeguards],
    }


def assess_source(conn, tables, source, linked):
    base = {"id_analisis": str(source.id_analisis), "id_sesion": str(source.id_sesion),
            "id_sensor": str(source.id_honeypot), "modalidad": source.modalidad,
            "inicio_sesion": source.fecha_inicio.isoformat(), "analizado_en": source.analizado_en.isoformat(),
            "estado_analisis": source.estado}
    if case := linked.get(source.id_sesion):
        return dict(base, estado="sesion_ya_registrada", id_incidente=str(case)), None
    payload = source.resultado_estructurado
    if (source.estado != "completado" or not isinstance(payload, dict) or not payload or
            any(payload.get(key) and not isinstance(payload[key], dict) for key in (
                "vigencia_snapshot", "evaluacion_incidente", "evaluacion_amenaza", "evaluacion_impacto"))):
        return dict(base, estado="requiere_reevaluacion", motivo="analisis_sin_resultado_utilizable"), None
    projection = _automatic_projection(payload, source.id_analisis, source.modalidad)
    originals, snapshot = saved_evidence(conn, tables["evento"], source, payload)
    base.update(snapshot_historico=snapshot, severidad_guardada=projection["severidad"],
                prioridad_guardada=projection["prioridad"], impacto_guardado=projection["impacto_tecnico"])
    if originals:
        signals = set(projection["criterios"]) & RELEVANT
        if not signals and projection["severidad"] not in SEVERITIES[2:]:
            return dict(base, estado="sin_indicios_suficientes"), None
        status = "recuperable_directamente"
        proof = snapshot
    else:
        originals = legacy_citations(conn, tables, source, payload)
        signals = {row["criterio"] for row in assess(originals)["criterios"] if row["cumplido"]} & RELEVANT
        if not signals:
            return dict(base, estado="requiere_reevaluacion", motivo="sin_evidencia_citada_independiente_suficiente"), None
        status = "recuperable_con_revision"
        proof = "recibos_y_citas"
    selected = selected_events(originals)
    history = {"id_analisis": str(source.id_analisis), "base_evidencia": proof, "snapshot_historico": snapshot,
               "actividad_desde": min(row.fecha_hora for row in originals).isoformat(),
               "actividad_hasta": max(row.fecha_hora for row in originals).isoformat(),
               "analizado_en": source.analizado_en.isoformat()}
    material = source_material(conn, tables, source, payload, selected)
    detail = dict(base, estado=status, senales=sorted(signals), **history, **material,
                  evidencia=[{"id_evento": str(row.id_evento), "tipo_evento": row.tipo_evento,
                              "grado": grade(row), "sha256": event_fingerprint(row)} for row in selected])
    projection = dict(projection, base_evidencia=proof, criterios=sorted(signals))
    return detail, (source, projection, originals, history)


def preview(conn, tables, sensors, modes):
    source_query = analysis_source(tables, sensors, modes).subquery()
    sources = conn.execute(select(source_query).order_by(source_query.c.analizado_en.desc(),
                                                         source_query.c.id_analisis)).mappings().all()
    links = tables["incidente_sesion"]
    linked = dict(conn.execute(select(links.c.id_sesion, links.c.id_incidente).where(
        links.c.id_sesion.in_({source.id_sesion for source in sources}))).all())
    read_models, plans, grouped = [], {}, defaultdict(list)
    redactors = session_redactors(conn, tables["evento"], {source.id_sesion for source in sources})
    for source in sources:
        row, plan = assess_source(conn, tables, source, linked)
        if plan:
            plans[row["id_analisis"]] = plan
        redactor = redactors[source.id_sesion]
        if "impacto_guardado" in row:
            row["impacto_guardado"] = redactor.payload(row["impacto_guardado"])
        for behavior in row.get("comportamientos", []):
            behavior["tipo"] = redactor.text(behavior["tipo"])
        grouped[source.id_sesion].append(row)
        read_models.append(row)

    ranking = {"recuperable_directamente": 0, "recuperable_con_revision": 1, "sesion_ya_registrada": 2,
               "requiere_reevaluacion": 3, "sin_indicios_suficientes": 4}
    choices = [min(rows, key=lambda row: ranking[row["estado"]]) for rows in grouped.values()]
    selected = sorted((row for row in choices if row["id_analisis"] in plans),
                      key=lambda row: (row["inicio_sesion"], row["id_analisis"]))
    selected_plans = [plans[row["id_analisis"]] for row in selected]
    counts = Counter(row["estado"] for row in choices)
    summary = {"analisis_revisados": len(read_models), "sesiones_revisadas": len(choices),
               **{status: counts[status] for status in ranking}, "confirmados_automaticamente": 0,
               "salvaguardas_con_citas_compatibles": len({item["id_salvaguarda"] for row in selected
                                                         for item in row["salvaguardas"] if item["citas_compatibles"]})}
    # Compare authoritative input as well as the protected preview. Redaction can
    # hide a change in a confidential stored field that still invalidates the preview.
    seal = digest([sorted(map(str, sensors)), modes, read_models,
                   [(source.id_analisis, source.resultado_estructurado,
                     [(row.id_evento, event_fingerprint(row)) for row in events])
                    for source, _, events, _ in selected_plans]])
    return {"revision_vista_previa": seal, "resumen": summary, "seleccion": selected,
            "sesiones": [{"id_sesion": row["id_sesion"], "id_analisis": row["id_analisis"], "estado": row["estado"]}
                         for row in choices], "analisis": read_models}, selected_plans
