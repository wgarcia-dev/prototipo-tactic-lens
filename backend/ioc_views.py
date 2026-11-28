"""Sensor-scoped, read-only queries for the observable explorer."""
from collections import defaultdict
from datetime import date, datetime, time
import re
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Date, String, and_, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB

from .correlation import action_link, action_observable_query, mapping_query, mitre_link
from .intelligence import DOWNLOAD, FAILED_DOWNLOAD, UPLOAD, ip_scope, normalize_ip, SHA256
from .intelligence_metrics import calendar_series, observable_totals
from .sensitive import Redactor, redact, session_redactors

ECUADOR = ZoneInfo("America/Guayaquil")
AUTH = ("cowrie.login.success", "cowrie.login.failed")
COMMANDS = ("cowrie.command.input", "cowrie.command.failed")
TRANSFERS = (DOWNLOAD, FAILED_DOWNLOAD, UPLOAD)
CONNECTIONS = ("cowrie.session.connect", "cowrie.direct-tcpip.request", "cowrie.forward-tcpip.request")
DISCONNECT = "cowrie.session.closed"
DNS_COMMAND = r"^\s*(?:\S*/)?(?:dig|host|nslookup)\s"


class IocFilters(BaseModel):
    q: str = Field("", max_length=150)
    tipo: str = Field("", max_length=60)
    estado: Literal["pendiente", "confirmado", "descartado", "historico", "mixto"] | None = None
    alcance: str = Field("", max_length=40)
    modalidad: Literal["cowrie_shell", "cowrie_proxy", "cowrie_llm", "desconocido"] | None = None
    sesion: str = Field("", max_length=100)
    sensor: str = Field("", max_length=80)
    evento: str = Field("", max_length=90)
    tecnica: str = Field("", max_length=20)
    tactica: str = Field("", max_length=80)
    evidencia: Literal["verificable", "historica"] | None = None
    relacion: Literal["directa", "contextual", "candidata", "insuficiente"] | None = None
    desde: date | None = None
    hasta: date | None = None
    orden: Literal["primera", "ultima", "observaciones", "sesiones", "tipo", "valor", "estado"] = "ultima"


def safe_url(value):
    return Redactor((value,)).url(value)


def public_payload(value):
    return Redactor((value,)).payload(value, raw_event=True)


def ioc_redactors(conn, tables, scope, identifiers):
    keys = tuple(identifiers)
    if not keys:
        return {}
    event = tables["evento"]
    pairs = select(scope.c.id_ioc, scope.c.id_sesion).where(scope.c.id_ioc.in_(keys)).distinct()
    sessions_by_ioc = defaultdict(list)
    for ioc_id, session_id in conn.execute(pairs):
        sessions_by_ioc[ioc_id].append(session_id)
    redactors = session_redactors(conn, event, {sid for items in sessions_by_ioc.values() for sid in items})
    return {key: [redactors[sid] for sid in sessions_by_ioc[key] if redactors[sid].captured] for key in keys}


def publish_ioc(row, redactors):
    for redactor in redactors[row["id_ioc"]]:
        row = redactor.payload(row)
    return redact(row)


def technical_profile(kind, value):
    if kind == "IP":
        try:
            address = normalize_ip(value)
            return {"version_ip": address.version, "alcance": ip_scope(address)}
        except ValueError:
            return {}
    if kind == "URL":
        try:
            url = urlsplit(safe_url(value))
            scope = None
            if url.hostname:
                try:
                    scope = ip_scope(normalize_ip(url.hostname))
                except ValueError:
                    pass
            return {"esquema": url.scheme, "host": url.hostname, "puerto": url.port,
                    "ruta_segura": url.path, "alcance_destino": scope or ("dominio" if url.hostname else None)}
        except ValueError:
            return {}
    if kind == "Hash" and SHA256.fullmatch(value):
        return {"algoritmo": "SHA-256"}
    return {}


def details_have(details, *roles):
    return or_(*(cast(details, JSONB).contains([{"comportamiento": role}]) for role in roles))


def observation_query(tables, sensor_ids, instances, filters, ioc_id=None):
    from .cowrie_provenance import event_mode
    ioc, kind, obs, event, session, sensor = (tables[name] for name in
        ("ioc", "tipo_ioc", "observacion_ioc", "evento", "sesion", "honeypot"))
    verified = func.jsonb_array_length(obs.c.detalles) > 0
    mode = event_mode(event, session, instances)
    item = func.jsonb_array_elements(obs.c.detalles).column_valued("detalle_alcance", joins_implicitly=True)
    scope = (select(func.min(func.jsonb_extract_path_text(item, "alcance_ip")))
             .where(func.jsonb_extract_path_text(item, "campo") == "src_ip")
             .correlate(obs).scalar_subquery())
    # A host mentioned in a command can be verified without a src_ip role.
    any_scope = select(func.min(func.jsonb_extract_path_text(item, "alcance_ip"))).correlate(obs).scalar_subquery()
    scope = case((kind.c.nombre == "IP", func.coalesce(scope, any_scope)), else_=None)
    dns = and_(event.c.tipo_evento == "cowrie.command.input",
               event.c.datos_originales["input"].astext.op("~")(DNS_COMMAND),
               details_have(obs.c.detalles, "host_mencionado", "origen_sesion"))
    statement = (select(obs.c.id_observacion, ioc.c.id_ioc, ioc.c.valor, kind.c.nombre.label("tipo"),
                        obs.c.estado_revision, obs.c.detalles, obs.c.revisado_en, verified.label("verificable"),
                        scope.label("alcance"), mode.label("modalidad"), dns.label("dns"),
                        event.c.id_evento, event.c.tipo_evento, event.c.fecha_hora, session.c.id_sesion,
                        session.c.cowrie_session_id, session.c.fecha_inicio, session.c.fecha_fin,
                        func.host(session.c.ip_origen).label("ip_origen"), sensor.c.nombre.label("sensor"))
                 .select_from(obs.join(ioc, obs.c.id_ioc == ioc.c.id_ioc).join(kind, ioc.c.id_tipo_ioc == kind.c.id_tipo_ioc)
                              .join(event, obs.c.id_evento == event.c.id_evento).join(session, event.c.id_sesion == session.c.id_sesion)
                              .join(sensor, session.c.id_honeypot == sensor.c.id_honeypot))
                 .where(session.c.id_honeypot.in_(sensor_ids)))
    for term, columns in ((filters.q, (ioc.c.valor, session.c.cowrie_session_id, cast(session.c.id_sesion, String))),
                          (filters.sesion, (session.c.cowrie_session_id, cast(session.c.id_sesion, String))),
                          (filters.sensor, (sensor.c.nombre,)), (filters.evento, (event.c.tipo_evento,))):
        if term.strip():
            statement = statement.where(or_(*(col.icontains(term.strip(), autoescape=True) for col in columns)))
    if ioc_id is not None:
        statement = statement.where(ioc.c.id_ioc == ioc_id)
    if filters.tipo:
        statement = statement.where(func.lower(kind.c.nombre) == filters.tipo.lower())
    if filters.alcance:
        statement = statement.where(scope == filters.alcance)
    if filters.modalidad:
        statement = statement.where(mode == filters.modalidad)
    if filters.evidencia:
        statement = statement.where(verified if filters.evidencia == "verificable" else ~verified)
    if filters.relacion in ("directa", "insuficiente"):
        statement = statement.where(verified if filters.relacion == "directa" else ~verified)
    if filters.desde and filters.hasta and filters.desde > filters.hasta:
        raise HTTPException(422, "La fecha inicial debe preceder a la final")
    if filters.desde:
        statement = statement.where(event.c.fecha_hora >= datetime.combine(filters.desde, time.min, ECUADOR))
    if filters.hasta:
        statement = statement.where(event.c.fecha_hora <= datetime.combine(filters.hasta, time.max, ECUADOR))
    return statement


def exact_mitre(conn, tables, scope, filters):
    """Resolve compatible relations in a batch using the same validator as evidence detail."""
    ref, action, detect = (tables[name] for name in ("mapeo_mitre_evento", "accion_identificada", "deteccion_ioc"))
    mapping = mapping_query(tables).subquery()
    query = (action_observable_query(tables).order_by(None).join(
        scope, and_(scope.c.id_ioc == detect.c.id_ioc, scope.c.id_evento == detect.c.id_evento))
        .join(mapping, mapping.c.id_accion == action.c.id_accion)
        .join(ref, and_(ref.c.id_mapeo == mapping.c.id_mapeo, ref.c.id_evento == detect.c.id_evento))
        .add_columns(scope.c.id_observacion.label("observacion_explorador"), mapping.c.id_mapeo, mapping.c.tecnica,
                     mapping.c.codigo_tecnica, mapping.c.codigo_tactica, mapping.c.tactica, mapping.c.grado_evidencia,
                     mapping.c.estado_revision, mapping.c.rag_procedencia, ref.c.metodo.label("metodo_cita"))
        .where(mapping.c.estado_revision != "descartado", scope.c.verificable))
    if filters.tecnica.strip():
        query = query.where(mapping.c.codigo_tecnica == filters.tecnica.strip().upper())
    if filters.tactica.strip():
        term = filters.tactica.strip()
        query = query.where(or_(mapping.c.codigo_tactica.icontains(term, autoescape=True),
                                mapping.c.tactica.icontains(term, autoescape=True)))
    result = []
    for row in conn.execute(query).mappings():
        link = action_link(row)
        mapped = {key: row[key] for key in ("id_mapeo","codigo_tecnica","tecnica","codigo_tactica","tactica",
                                            "grado_evidencia","estado_revision","rag_procedencia")}
        mapped["eventos"] = [{**link["eventos"][0], "metodo": row.metodo_cita}]
        match = mitre_link(row, link, mapped)
        if match and match["estado"] != "insuficiente" and (filters.relacion not in ("contextual", "candidata")
                                                            or match["estado"] == filters.relacion):
            result.append((row.observacion_explorador, row.id_ioc, {**match, "id_sesion": row.id_sesion,
                                                                 "id_accion": row.id_accion, "id_analisis": row.id_analisis}))
    return result


def filtered_scope(conn, tables, sensors, instances, filters, ioc_id=None):
    base = observation_query(tables, sensors, instances, filters, ioc_id)
    if filters.tecnica or filters.tactica or filters.relacion in ("contextual", "candidata"):
        matches = exact_mitre(conn, tables, base.subquery(), filters)
        base = base.where(tables["observacion_ioc"].c.id_observacion.in_({key for key, _, _ in matches}))
    scope = base.cte("observaciones_base")
    if filters.estado:
        groups = group_observables(scope).order_by(None).subquery()
        return (select(scope).where(scope.c.id_ioc.in_(select(groups.c.id_ioc)
                                      .where(groups.c.estado_revision == filters.estado))).cte("observaciones_filtradas"))
    return scope


def group_observables(scope, order="ultima"):
    rows = scope.c
    verified_count = func.count().filter(rows.verificable)
    low = func.min(rows.estado_revision).filter(rows.verificable)
    high = func.max(rows.estado_revision).filter(rows.verificable)
    state = case((verified_count == 0, "historico"), (low == high, low), else_="mixto")
    first, last = func.min(rows.fecha_hora), func.max(rows.fecha_hora)
    count, sessions = func.count(), func.count(func.distinct(rows.id_sesion))
    sort = {"primera":first.asc(), "ultima":last.desc(), "observaciones":count.desc(), "sesiones":sessions.desc(),
            "tipo":rows.tipo, "valor":rows.valor, "estado":state}[order]
    return (select(rows.id_ioc, rows.tipo, rows.valor, state.label("estado_revision"),
                   verified_count.label("observaciones_verificables"), func.min(rows.alcance).label("alcance"),
                   first.label("primera_observacion"), last.label("ultima_observacion"), count.label("observaciones"),
                   sessions.label("sesiones"), func.count(func.distinct(rows.id_evento)).label("eventos"))
            .group_by(rows.id_ioc, rows.tipo, rows.valor).order_by(sort, rows.id_ioc))


def explorer_rows(conn, tables, scope, filters, limit, offset):
    page = [dict(row) for row in conn.execute(group_observables(scope, filters.orden).limit(limit).offset(offset)).mappings()]
    page_scope = select(scope).where(scope.c.id_ioc.in_([row["id_ioc"] for row in page])).subquery()
    by_ioc = defaultdict(set)
    for _, ioc_id, match in exact_mitre(conn, tables, page_scope, filters):
        by_ioc[ioc_id].add(match["codigo_tecnica"])
    redactors = ioc_redactors(conn, tables, page_scope, (row["id_ioc"] for row in page))
    return [publish_ioc({**row, "tecnicas":len(by_ioc[row["id_ioc"]])}, redactors) for row in page]


def summary(conn, tables, scope, filters):
    rows = scope.c
    groups = group_observables(scope).order_by(None).subquery().c
    totals = dict(conn.execute(observable_totals(rows)).mappings().one())
    totals["con_mitre"] = len({ioc_id for _, ioc_id, _ in exact_mitre(conn, tables, scope, filters)})
    states = [dict(row) for row in conn.execute(select(groups.estado_revision.label("categoria"),
        func.count().label("observables")).group_by(groups.estado_revision).order_by(groups.estado_revision)).mappings()]
    day = cast(func.timezone("America/Guayaquil", rows.fecha_hora), Date)
    dimensions = (rows.tipo, rows.modalidad, rows.alcance, day)
    names = ("tipos", "modalidades", "alcances", "dias")
    breakdown = {name: [] for name in names}
    aggregates = select(*dimensions, *(func.grouping(field) for field in dimensions),
                        func.count(func.distinct(rows.id_ioc)), func.count()).group_by(func.grouping_sets(*dimensions))
    for row in conn.execute(aggregates):
        index = row[4:8].index(0)
        if row[index] is not None and (index != 2 or row[index]):
            breakdown[names[index]].append({"categoria":row[index], "observables":row[8], "observaciones":row[9]})
    for items in breakdown.values():
        items.sort(key=lambda item: item["categoria"])
    recurring = conn.execute(group_observables(scope, "sesiones").limit(8)).mappings().all()
    redactors = ioc_redactors(conn, tables, scope, (row.id_ioc for row in recurring))
    series, period = calendar_series(breakdown.pop("dias"), "categoria", {"observables":0,"observaciones":0},
                                     start=filters.desde, end=filters.hasta)
    return {"totales":totals, **breakdown,
            "estados":states, "evolucion":series, "periodo_evolucion":period,
            "poblacion":{"unidad":"IoC único observado", "filtros":filters.model_dump()},
            "recurrentes":[publish_ioc({"id_ioc":row.id_ioc,"valor":row.valor,"sesiones":row.sesiones}, redactors)
                          for row in recurring]}


def observation_filter(event, obs, category, order):
    kind = event.c.tipo_evento
    direct = func.jsonb_array_length(obs.c.detalles) > 0
    dns = and_(kind == "cowrie.command.input", event.c.datos_originales["input"].astext.op("~")(DNS_COMMAND))
    transfer = or_(kind.in_(TRANSFERS), details_have(obs.c.detalles, "intento_descarga"))
    categories = {
        "prioritarias": and_(direct, or_(kind.in_((*AUTH, *COMMANDS, *TRANSFERS, *CONNECTIONS[1:], "cowrie.client.kex")), transfer)),
        "autenticacion":kind.in_(AUTH), "comandos":kind.in_(COMMANDS), "transferencias":transfer,
        "dns":dns, "conexiones":kind.in_(CONNECTIONS), "desconexiones":kind == DISCONNECT,
        "ssh":kind == "cowrie.client.kex", "todas":literal(True),
    }
    rank = case((~direct, 0), (or_(transfer, kind.in_(AUTH)), 3),
                (kind.in_((*COMMANDS, *CONNECTIONS[1:], "cowrie.client.kex")), 2),
                (kind == DISCONNECT, 0), else_=1)
    chronology = (event.c.fecha_hora.asc(), event.c.numero_secuencia.asc(), event.c.id_evento.asc()) if order == "antiguas" else (
        event.c.fecha_hora.desc(), event.c.numero_secuencia.desc(), event.c.id_evento.desc())
    return categories[category], (rank.desc(), *chronology) if order == "relevancia" else chronology


def profile(conn, tables, scope, filters):
    row = conn.execute(group_observables(scope)).mappings().first()
    if not row:
        raise HTTPException(404, "Observable no encontrado en los sensores autorizados")
    item = dict(row)
    rows = scope.c
    verified = rows.verificable
    def recorded(name, *kinds):
        return func.count(func.distinct(rows.id_evento)).filter(verified, rows.tipo_evento.in_(kinds)).label(name)
    behavior = dict(conn.execute(select(
        recorded("autenticaciones", *AUTH), recorded("autenticaciones_fallidas", AUTH[1]),
        recorded("autenticaciones_aceptadas", AUTH[0]), recorded("comandos", COMMANDS[0]),
        recorded("comandos_fallidos", COMMANDS[1]), recorded("descargas", DOWNLOAD),
        recorded("descargas_fallidas", FAILED_DOWNLOAD), recorded("archivos_subidos", UPLOAD),
        recorded("conexiones", *CONNECTIONS), recorded("desconexiones", DISCONNECT),
        func.count(func.distinct(rows.id_evento)).filter(verified, rows.dns).label("ordenes_dns"),
        func.count(func.distinct(rows.id_evento)).filter(verified, details_have(rows.detalles, "intento_descarga")).label("intentos_descarga"),
        func.count(func.distinct(rows.id_sesion)).filter(verified, rows.tipo_evento == COMMANDS[0]).label("sesiones_con_comandos"),
        func.array_agg(func.distinct(rows.modalidad)).label("modalidades"),
        func.array_agg(func.distinct(rows.sensor)).label("sensores"),
        func.max(rows.revisado_en).label("ultima_revision"))).mappings().one())
    links = exact_mitre(conn, tables, scope, filters)
    event = tables["evento"]
    actions = linked_actions(tables, scope)
    behavior["acciones"] = conn.scalar(select(func.count(func.distinct(actions.c.id_accion))))
    behavior["tecnicas"] = len({match["codigo_tecnica"] for _, _, match in links})
    behavior["usuarios_objetivo"] = conn.scalar(
        select(func.count(func.distinct(event.c.datos_originales["username"].astext)))
        .select_from(scope.join(event, rows.id_evento == event.c.id_evento))
        .where(verified, rows.tipo_evento.in_(AUTH), event.c.datos_originales["username"].astext != ""))
    evidence = (select(event.c.tipo_evento, event.c.datos_originales["hassh"].astext.label("hassh"),
                       func.coalesce(event.c.datos_originales["filename"].astext,
                                     event.c.datos_originales["outfile"].astext).label("archivo"),
                       event.c.datos_originales["size"].astext.label("tamano"), rows.id_sesion, rows.id_evento)
                .select_from(scope.join(event, rows.id_evento == event.c.id_evento))
                .where(verified, or_(event.c.tipo_evento == "cowrie.client.kex", event.c.tipo_evento.in_(TRANSFERS)))
                .order_by(event.c.fecha_hora.desc(), event.c.id_evento.desc()).limit(20))
    artifacts = []
    for source in conn.execute(evidence).mappings():
        data = {"id_evento":str(source.id_evento), "id_sesion":source.id_sesion}
        if item["tipo"]=="IP" and source.hassh and re.fullmatch("[0-9a-fA-F]{32}",source.hassh):
            artifacts.append({**data, "hassh":source.hassh})
        if item["tipo"]=="Hash" and source.tipo_evento in (DOWNLOAD, UPLOAD):
            if source.archivo:
                data["archivo"] = public_payload(re.split(r"[/\\]",source.archivo)[-1])
            if source.tamano and source.tamano.isdecimal() and len(source.tamano)<16:
                data["tamano"] = int(source.tamano)
            if "archivo" in data or "tamano" in data:
                artifacts.append(data)
    redactors = ioc_redactors(conn, tables, scope, [item["id_ioc"]])
    return publish_ioc({**item, "clasificacion":technical_profile(item["tipo"],item["valor"]),
        "comportamiento":behavior, "artefactos":artifacts, "enriquecimiento":stored_enrichment(conn,tables,scope,item)}, redactors)


def linked_actions(tables, scope):
    detection = tables["deteccion_ioc"]
    action_evidence = tables["accion_evento"]
    return (action_observable_query(tables).order_by(None)
            .join(scope, and_(scope.c.id_ioc == detection.c.id_ioc, scope.c.id_evento == detection.c.id_evento))
            .where(scope.c.verificable, detection.c.id_observacion == scope.c.id_observacion,
                   action_evidence.c.id_evento.is_not(None)).subquery())


def stored_enrichment(conn, tables, scope, item):
    """Only read results already attributed to this exact value by a stored analysis."""
    analysis = tables["analisis_llm"]
    enrichment = analysis.c.resultado_estructurado["enriquecimiento"]
    items = case((func.jsonb_typeof(enrichment["observables"]) == "array", enrichment["observables"]),
                 else_=literal([], type_=JSONB))
    observations = func.jsonb_array_elements(items).column_valued("enriquecimiento_observable", joins_implicitly=True)
    query = (select(analysis.c.id_analisis, analysis.c.id_sesion, enrichment["fuentes"].label("fuentes"),
                    func.jsonb_extract_path(observations, "proveedores").label("proveedores"))
             .where(analysis.c.id_sesion.in_(select(scope.c.id_sesion)), analysis.c.estado == "completado",
                    func.jsonb_typeof(enrichment["observables"]) == "array",
                    func.jsonb_extract_path_text(observations,"tipo") == item["tipo"],
                    func.jsonb_extract_path_text(observations,"valor") == item["valor"])
             .order_by(analysis.c.fecha_inicio.desc(),analysis.c.id_analisis).limit(10))
    entries, seen = [], set()
    configured = False
    names = ("threatfox","urlhaus","misp_warning_lists")
    for row in conn.execute(query).mappings():
        configured = configured or any((row.fuentes or {}).get(name) is True for name in names)
        for provider in names:
            result = (row.proveedores or {}).get(provider)
            if not result or provider in seen:
                continue
            seen.add(provider)
            for entry in result if isinstance(result,list) else [result, *result.get("coincidencias", [])] if isinstance(result,dict) else []:
                if isinstance(entry,dict):
                    entries.append({"proveedor":provider, "id_analisis":row.id_analisis, "id_sesion":row.id_sesion,
                                    **public_payload({key:entry[key] for key in (
                                        "estado","resultado","motivo","consultado_en","nombre","version","categoria") if key in entry})})
    return {"estado":"guardado" if entries else "sin_resultados_guardados" if configured else "sin_configuracion_registrada",
            "resultados":entries}


def session_page(conn, tables, scope, filters, limit, offset, sensors, instances):
    from .analysis_state import current_inputs, states_for_sessions
    rows = scope.c
    query = (select(rows.id_sesion, rows.cowrie_session_id, rows.modalidad, rows.sensor, rows.ip_origen,
                    rows.fecha_inicio, rows.fecha_fin, func.count().label("observaciones"),
                    func.count().filter(rows.verificable).label("observaciones_verificables"))
             .group_by(rows.id_sesion, rows.cowrie_session_id, rows.modalidad, rows.sensor, rows.ip_origen,
                       rows.fecha_inicio, rows.fecha_fin)
             .order_by(func.max(rows.fecha_hora).desc(), rows.id_sesion).limit(limit).offset(offset))
    page = [dict(row) for row in conn.execute(query).mappings()]
    if not page:
        return []
    event = tables["evento"]
    ids = [row["id_sesion"] for row in page]
    event_counts = dict(conn.execute(select(event.c.id_sesion, func.count()).where(
        event.c.id_sesion.in_(ids)).group_by(event.c.id_sesion)).all())
    inputs, _ = current_inputs(conn, tables, ids, sensors, instances)
    states = states_for_sessions(conn, tables["analisis_llm"], inputs)
    page_scope = select(scope).where(rows.id_sesion.in_(ids)).subquery()
    actions = linked_actions(tables, page_scope)
    action_counts = dict(conn.execute(select(actions.c.id_sesion,func.count(func.distinct(actions.c.id_accion)))
                                    .group_by(actions.c.id_sesion)).all())
    techniques = defaultdict(set)
    for _, _, match in exact_mitre(conn, tables, page_scope, filters):
        techniques[match["id_sesion"]].add(match["codigo_tecnica"])
    for row in page:
        sid, start, end = row["id_sesion"], row["fecha_inicio"], row["fecha_fin"]
        row.update(eventos=event_counts[sid], acciones=action_counts.get(sid,0),
                   tecnicas=sorted(techniques[sid]), estado_analisis=states[sid]["estado_analisis"],
                   analisis=states[sid]["analisis"], duracion_segundos=(end-start).total_seconds() if end else None)
    redactors = session_redactors(conn, event, ids)
    return [redactors[row["id_sesion"]].payload(row) for row in page]
