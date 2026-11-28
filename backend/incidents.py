"""Versioned analytical incident aggregate and the D2 read/lock contract."""
from datetime import timedelta
import re
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select, text

from .analysis_state import digest, evidence_snapshot
from .cowrie_provenance import event_mode, public_provenance, session_mode
from .realtime import notify_change
from .sensitive import session_redactors

MAX_EVIDENCE = 500
SEVERITIES = ("S0", "S1", "S2", "S3", "S4")
PRIORITIES = ("baja", "media", "alta", "inmediata")
RELEVANT = {"acceso_senuelo", "interaccion_shell", "transferencia"}
TRANSFERS = {"cowrie.session.file_download", "cowrie.session.file_upload"}
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def scoped(incident, tables, sensors):
    links, sessions = (tables[key] for key in ("incidente_sesion", "sesion"))
    belongs = (select(1).select_from(links).where(links.c.id_incidente == incident.c.id_incidente)
               .correlate(incident).exists())
    foreign = (select(1).select_from(links.join(sessions, sessions.c.id_sesion == links.c.id_sesion))
               .where(links.c.id_incidente == incident.c.id_incidente, sessions.c.id_honeypot.not_in(sensors))
               .correlate(incident).exists())
    return and_(belongs, ~foreign)


def lock_incident(conn, tables, sensors, id_incidente, lock=False):
    incident = tables["incidente"]
    query = select(incident).where(incident.c.id_incidente == id_incidente, scoped(incident, tables, sensors))
    return conn.execute(query.with_for_update() if lock else query).mappings().first()


def event_fingerprint(row):
    fields = (row.id_evento, row.id_sesion, row.tipo_evento, row.fecha_hora.isoformat(), row.datos_originales)
    return digest(fields)


def evaluation_view(conn, tables, incident, revision, *, supports_check=True):
    evaluations, evidence, joined, event, sessions = (tables[k] for k in (
        "incidente_evaluacion", "incidente_evidencia", "incidente_sesion", "evento", "sesion"))
    row = conn.execute(select(evaluations).where(evaluations.c.id_incidente == incident.id_incidente,
        evaluations.c.revision_evaluacion == (revision or incident.revision_actual))).mappings().first()
    if row is None:
        return None
    links = conn.execute(select(joined).where(joined.c.id_incidente == incident.id_incidente,
        joined.c.revision_ingreso <= row.revision_evaluacion).order_by(joined.c.revision_ingreso, joined.c.id_sesion)).mappings().all()
    cited = conn.execute(select(evidence).where(evidence.c.id_incidente == incident.id_incidente,
        evidence.c.revision_evaluacion == row.revision_evaluacion).order_by(evidence.c.id_evento)).mappings().all()
    ids = [link.id_sesion for link in links]
    valid = bool(cited)
    sealed = row.detalle.get("revisiones_sesion", {})
    if supports_check and cited:
        current = conn.execute(select(sessions.c.id_sesion, sessions.c.revision_eventos)
                               .where(sessions.c.id_sesion.in_(ids))).all()
        if any(sealed.get(str(item.id_sesion)) != item.revision_eventos for item in current):
            originals = {item.id_evento: event_fingerprint(item) for item in conn.execute(select(event).where(
                event.c.id_evento.in_([c.id_evento for c in cited])))}
            valid = all(originals.get(c.id_evento) == c.procedencia.get("evento_sha256") for c in cited)
    view = {
        "version_contrato": 1, "id_incidente": str(row.id_incidente), "revision_evaluacion": row.revision_evaluacion,
        "revision_actual": incident.revision_actual, "decision": row.decision, "severidad": row.severidad,
        "prioridad": row.prioridad, "clasificacion": row.clasificacion, "titulo": row.titulo, "resumen": row.resumen,
        "evaluado_en": row.evaluado_en.isoformat(), "id_actor": str(row.id_actor) if row.id_actor else None,
        "evidencia_sha256": row.evidencia_sha256, "evidencia_verificable": valid,
        "alcance": {"sesiones": [str(sid) for sid in ids], "recursos_confirmados": row.detalle.get("recursos_confirmados", [])},
        "evidencias": [{"id_evento": str(c.id_evento), "id_sesion": str(c.id_sesion),
                        "id_analisis": str(c.id_analisis) if c.id_analisis else None, "grado": c.grado,
                        "procedencia": c.procedencia} for c in cited],
        "correlaciones": [{"id_sesion": str(link.id_sesion), **link.correlacion} for link in links],
        "detalle": {k: v for k,v in row.detalle.items() if k != "revisiones_sesion"},
    }
    return view


def get_incident_for_response(conn, actor, id_incidente, revision=None, lock=False):
    """Receive an authenticated actor. D1/D2 share the transaction and row lock."""
    from .api import app, sensor_ids

    if actor.get("rol") not in {"analista", "administrador"} or not actor.get("id_usuario"):
        return None
    tables = app.state.tables
    if "incidente" not in tables:
        return None
    incident = lock_incident(conn, tables, sensor_ids(), id_incidente, lock)
    if incident is None:
        return None
    view = evaluation_view(conn, tables, incident, revision)
    if view:
        for redactor in session_redactors(conn, tables["evento"], [UUID(s) for s in view["alcance"]["sesiones"]]).values():
            view = redactor.payload(view)
    return view


def grade(row):
    if row.tipo_evento in TRANSFERS or row.tipo_evento == "cowrie.login.success":
        return "resultado_en_honeypot"
    if row.tipo_evento in {"cowrie.command.input", "cowrie.login.failed", "cowrie.session.file_download.failed"}:
        return "intento"
    return "observacion"


def seal_events(conn, tables, modes, sids, references):
    event, sessions = tables["evento"], tables["sesion"]
    identifiers = list(references)
    query = (select(event, event_mode(event, sessions, modes).label("modalidad"))
             .join(sessions, sessions.c.id_sesion == event.c.id_sesion)
             .where(event.c.id_evento.in_(identifiers), event.c.id_sesion.in_(sids)))
    return [
        {"id_evento": row.id_evento, "id_sesion": row.id_sesion, "id_analisis": references[row.id_evento],
         "grado": grade(row), "procedencia": {**public_provenance(row.modalidad, row.get("procedencia_cowrie")),
                                               "evento_sha256": event_fingerprint(row)}}
        for row in conn.execute(query).mappings()
    ]


def publish(conn, tables, incident_id, revision, fields, evidence, sids):
    incidents, revisions, cites, sessions = (tables[k] for k in (
        "incidente", "incidente_evaluacion", "incidente_evidencia", "sesion"))
    sensor_rows = conn.execute(select(sessions.c.id_sesion, sessions.c.id_honeypot, sessions.c.revision_eventos)
                               .where(sessions.c.id_sesion.in_(sids))).all()
    detail = dict(fields["detalle"], revisiones_sesion={str(row.id_sesion): row.revision_eventos for row in sensor_rows})
    checksum = digest([sorted(map(str, sids)), sorted(evidence, key=lambda row: row["id_evento"])])
    conn.execute(revisions.insert().values(**{**fields, "detalle": detail}, id_incidente=incident_id,
                                          revision_evaluacion=revision, evidencia_sha256=checksum))
    if evidence:
        conn.execute(cites.insert(), [dict(row, id_incidente=incident_id, revision_evaluacion=revision) for row in evidence])
    conn.execute(incidents.update().where(incidents.c.id_incidente == incident_id).values(
        revision_actual=revision, actualizado_en=func.clock_timestamp()))
    notify_change(conn, [row.id_honeypot for row in sensor_rows], "incidentes", "respuesta_incidentes")


def related_incident(conn, tables, sensors, modes, session, evidence):
    """Only a verified artifact, common source and time window can group sessions."""
    events, sessions, links, incidents, reviews, cited = (tables[k] for k in (
        "evento", "sesion", "incidente_sesion", "incidente", "incidente_evaluacion", "incidente_evidencia"))
    if not session.ip_origen or session.modalidad == "desconocido":
        return None
    transfers = conn.execute(select(events.c.id_evento, events.c.fecha_hora, events.c.datos_originales).where(
        events.c.id_evento.in_([row["id_evento"] for row in evidence]), events.c.tipo_evento.in_(TRANSFERS))).all()
    artifacts = [(row, value.lower()) for row in transfers
                 if isinstance(value := row.datos_originales.get("shasum"), str) and SHA256.fullmatch(value)
                 and len(set(value)) > 1]
    candidates = {}
    for row, fingerprint in artifacts[:20]:
        matches = conn.execute(select(incidents.c.id_incidente, events.c.id_evento).select_from(
            events.join(sessions, events.c.id_sesion == sessions.c.id_sesion)
            .join(links, links.c.id_sesion == sessions.c.id_sesion).join(incidents, incidents.c.id_incidente == links.c.id_incidente)
            .join(reviews, and_(reviews.c.id_incidente == incidents.c.id_incidente,
                                 reviews.c.revision_evaluacion == incidents.c.revision_actual))
            .join(cited, and_(cited.c.id_incidente == incidents.c.id_incidente,
                 cited.c.revision_evaluacion == incidents.c.revision_actual, cited.c.id_evento == events.c.id_evento)))
            .where(sessions.c.id_sesion != session.id_sesion, sessions.c.ip_origen == session.ip_origen,
                   scoped(incidents, tables, sensors), reviews.c.decision == "actividad_sospechosa",
                   events.c.tipo_evento.in_(TRANSFERS), event_mode(events, sessions, modes) != "desconocido",
                   func.lower(events.c.datos_originales["shasum"].astext) == fingerprint,
                   events.c.fecha_hora.between(row.fecha_hora - timedelta(hours=1), row.fecha_hora + timedelta(hours=1)))
            .order_by(events.c.id_evento).limit(101)).all()
        if len(matches) > 100:
            return None
        for match in matches:
            candidates[match.id_incidente] = {
                "metodo": "sha256_origen_60m_v1", "sha256": fingerprint,
                "eventos": [str(match.id_evento), str(row.id_evento)], "ventana_segundos": 3600,
                "limitacion": "Coincidencia contextual de artefacto y origen. No atribuye identidad ni ejecución.",
            }
        if len(candidates) > 1:
            return None
    return next(iter(candidates.items()), None)


def _automatic_projection(payload, analysis_id, mode):
    triage = payload.get("evaluacion_incidente") or {}
    threat = payload.get("evaluacion_amenaza") or {}
    impact = payload.get("evaluacion_impacto") or {}
    severity = threat.get("codigo_severidad") or triage.get("severidad")
    priority = threat.get("prioridad_investigacion") or triage.get("prioridad_triaje")
    return {
        "id_analisis": str(analysis_id), "modalidad_al_analizar": mode,
        "clasificacion": triage.get("clasificacion") or "actividad_por_evaluar",
        "severidad": severity if severity in SEVERITIES else None,
        "prioridad": priority if priority in PRIORITIES else "por_determinar",
        "impacto_tecnico": {key: impact[key] for key in (
            "confidencialidad", "integridad", "disponibilidad", "impacto_observado", "impacto_potencial",
            "fundamento") if key in impact},
        "criterios": [item["criterio"] for item in triage.get("criterios", []) if item.get("cumplido")],
    }


def register_analysis(conn, tables, sensors, modes, analysis_id, *, manual=False, actor=None, reason=None):
    """Identify cases from a completed, already-paid analysis without new provider calls."""
    if "incidente" not in tables:
        return None
    analyses, sessions, event, links, joined, incident = (tables[k] for k in (
        "analisis_llm", "sesion", "evento", "incidente_sesion", "incidente_analisis", "incidente"))
    query = (select(analyses.c.resultado_estructurado, analyses.c.resumen, sessions,
                    session_mode(sessions, event, modes).label("modalidad"))
             .join_from(analyses, sessions, analyses.c.id_sesion == sessions.c.id_sesion)
             .where(analyses.c.id_analisis == analysis_id, analyses.c.estado == "completado",
                    sessions.c.id_honeypot.in_(sensors)))
    source = conn.execute(query).mappings().first()
    if not source:
        if manual:
            raise HTTPException(404, "Análisis completado no encontrado")
        return None
    payload = source.resultado_estructurado or {}
    triage = payload.get("evaluacion_incidente") or {}
    snapshot = payload.get("vigencia_snapshot") or {}
    assessment = _automatic_projection(payload, analysis_id, source.modalidad)
    if not manual and not (set(assessment["criterios"]) & RELEVANT or assessment["severidad"] in SEVERITIES[2:]):
        return None
    saved_ids = snapshot.get("eventos") or triage.get("eventos") or []
    expected = snapshot.get("eventos_sha256") or triage.get("snapshot_sha256")
    if not expected or not saved_ids:
        if manual:
            raise HTTPException(422, "El análisis histórico carece de un snapshot de evidencia verificable")
        return None
    # Compare the exact saved set rather than expanding it to events ingested later.
    try:
        stored_ids = {int(value) for value in saved_ids}
    except (TypeError, ValueError, OverflowError):
        stored_ids = set()
    originals = conn.execute(select(event).where(event.c.id_sesion == source.id_sesion,
                                                event.c.id_evento.in_(stored_ids))).all()
    if not originals or len(originals) != len(stored_ids) or evidence_snapshot(originals)["eventos_sha256"] != expected:
        if manual:
            raise HTTPException(409, "Los eventos citados ya no coinciden con el análisis guardado")
        return None
    selected = sorted(originals, key=lambda row: (grade(row) == "observacion", row.fecha_hora, row.id_evento))[:MAX_EVIDENCE]
    citations = seal_events(conn, tables, modes, [source.id_sesion], {row.id_evento: analysis_id for row in selected})
    conn.execute(text("SELECT pg_advisory_xact_lock(724610916)"))
    published = conn.scalar(select(joined.c.id_incidente).where(joined.c.id_analisis == analysis_id))
    if published:
        return published
    proposed = conn.scalar(select(links.c.id_incidente).where(links.c.id_sesion == source.id_sesion))
    relation = None
    if not proposed and (match := related_incident(conn, tables, sensors, modes, source, citations)):
        proposed, relation = match
    existing = lock_incident(conn, tables, sensors, proposed, True) if proposed else None
    if proposed and not existing:
        if manual:
            raise HTTPException(404, "Incidente fuera del alcance autorizado")
        return None
    prior = evaluation_view(conn, tables, existing, None, supports_check=False) if existing else None
    # Do not append an unrelated session if the incident was confirmed while the candidate was being found.
    if relation and prior["decision"] != "actividad_sospechosa":
        existing, prior, relation = None, None, None
    if prior and not relation and prior["id_actor"] is not None:
        sealed = {int(c["id_evento"]): c["procedencia"]["evento_sha256"] for c in prior["evidencias"]
                  if c["id_sesion"] == str(source.id_sesion)}
        if sealed and sealed == {row["id_evento"]: row["procedencia"]["evento_sha256"] for row in citations}:
            conn.execute(joined.insert().values(id_incidente=existing.id_incidente, id_sesion=source.id_sesion,
                id_analisis=analysis_id, revision_ingreso=existing.revision_actual))
            return existing.id_incidente
    incident_id = existing.id_incidente if existing else conn.scalar(incident.insert().returning(incident.c.id_incidente))
    revision = existing.revision_actual + 1 if existing else 1
    sids = [UUID(value) for value in prior["alcance"]["sesiones"]] if prior else []
    if source.id_sesion not in sids:
        conn.execute(links.insert().values(id_incidente=incident_id, id_sesion=source.id_sesion, revision_ingreso=revision,
                                           correlacion=relation or {"metodo": "sesion_base"}))
        sids.append(source.id_sesion)
    conn.execute(joined.insert().values(id_incidente=incident_id, id_sesion=source.id_sesion,
                                        id_analisis=analysis_id, revision_ingreso=revision))
    previous_assessments = prior["detalle"].get("analisis", []) if prior else []
    analytic = [item for item in previous_assessments if item.get("id_sesion") != str(source.id_sesion)]
    analytic.append({**assessment, "id_sesion": str(source.id_sesion)})
    prior_refs = {} if prior is None else {int(c["id_evento"]): c for c in prior["evidencias"] if c["id_sesion"] != str(source.id_sesion)}
    carried = [{"id_evento": eid, "id_sesion": UUID(c["id_sesion"]), "id_analisis": UUID(c["id_analisis"]) if c["id_analisis"] else None,
                "grado": c["grado"], "procedencia": c["procedencia"]} for eid, c in prior_refs.items()]
    evidence = (citations + carried)[:MAX_EVIDENCE]
    strongest = max(analytic, key=lambda item: SEVERITIES.index(item["severidad"]) if item["severidad"] in SEVERITIES else -1)
    priority = max(analytic, key=lambda item: PRIORITIES.index(item["prioridad"]) if item["prioridad"] in PRIORITIES else -1)
    fields = {
        "decision": "actividad_sospechosa", "severidad": strongest["severidad"], "clasificacion": strongest["clasificacion"],
        "prioridad": priority["prioridad"], "titulo": f"Actividad Cowrie · {source.cowrie_session_id}"[:200],
        "resumen": source.resumen or "Actividad observada en el señuelo, pendiente de revisión.",
        "id_actor": actor,
        "detalle": {"origen": "analisis_guardado", "motivo": reason, "analisis": analytic, "modalidades": sorted(
            set(item["modalidad_al_analizar"] for item in analytic)), "recursos_confirmados": [],
            "impacto_confirmado": None, "evidencias_disponibles": len(originals), "evidencias_incluidas": len(evidence)},
    }
    for redactor in session_redactors(conn, event, sids).values():
        fields = redactor.payload(fields)
    publish(conn, tables, incident_id, revision, fields, evidence, sids)
    return incident_id
