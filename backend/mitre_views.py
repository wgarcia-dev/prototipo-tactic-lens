"""Read models for browsing persisted MITRE results without expanding their citations."""

from datetime import date, datetime, time
from typing import Literal
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Date, String, and_, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONB

from .correlation import action_link, action_observable_query, mapping_query, mitre_link
from .intelligence_metrics import calendar_series, technique_count
from .rag.mitre_evidence import AUTO_CLASSIFICATION


class MitreFilters(BaseModel):
    q: str = Field(default='', max_length=100)
    codigo: str = Field(default='', max_length=12)
    tactica: str = Field(default='', max_length=100)
    sesion: str = Field(default='', max_length=100)
    id_sesion: UUID | None = None
    modalidad: Literal['cowrie_shell', 'cowrie_proxy', 'cowrie_llm', 'desconocido'] | None = None
    estado: Literal['automatica', 'confirmada', 'historica_pendiente', 'historica_confirmada', 'descartada'] | None = None
    plataforma: str = Field(default='', max_length=50)
    ip: str = Field(default='', max_length=64)
    citas: Literal['con', 'sin'] | None = None
    grado: Literal['intento', 'resultado_en_honeypot', 'sin_registro'] | None = None
    desde: date | None = None
    hasta: date | None = None
    orden: Literal['codigo', 'nombre', 'sesiones', 'mapeos', 'primera', 'ultima'] = 'ultima'


ECUADOR = ZoneInfo('America/Guayaquil')


def citation_query(tables):
    ref, event, mapping, action, analysis = (tables[name] for name in (
        'mapeo_mitre_evento', 'evento', 'mapeo_mitre', 'accion_identificada', 'analisis_llm',
    ))
    return (select(ref.c.id_mapeo, event.c.id_evento, event.c.fecha_hora)
            .select_from(ref.join(event, ref.c.id_evento == event.c.id_evento)
                         .join(mapping, ref.c.id_mapeo == mapping.c.id_mapeo)
                         .join(action, action.c.id_accion == mapping.c.id_accion)
                         .join(analysis, analysis.c.id_analisis == action.c.id_analisis))
            .where(event.c.id_sesion == analysis.c.id_sesion))


def mapping_rows(tables, sensors, instances, filters):
    from .cowrie_provenance import session_mode
    mapping, action, analysis, session, technique, tactic = (tables[name] for name in (
        'mapeo_mitre', 'accion_identificada', 'analisis_llm', 'sesion', 'tecnica_mitre', 'tactica_mitre',
    ))
    modality = session_mode(session, tables["evento"], instances)
    automatic = mapping.c.rag_procedencia['clasificacion'].astext == AUTO_CLASSIFICATION
    state = case(
        (mapping.c.estado_revision == 'descartado', 'descartada'),
        (and_(mapping.c.estado_revision == 'confirmado', automatic), 'confirmada'),
        (automatic, 'automatica'),
        (mapping.c.estado_revision == 'confirmado', 'historica_confirmada'),
        else_='historica_pendiente',
    )
    citations = citation_query(tables).subquery()
    cited = (select(func.min(citations.c.fecha_hora).label('primera_cita'),
                    func.max(citations.c.fecha_hora).label('ultima_cita'),
                    func.count().label('citas'))
             .where(citations.c.id_mapeo == mapping.c.id_mapeo)
             .correlate(mapping).lateral())
    seen = func.coalesce(cited.c.primera_cita, session.c.fecha_inicio)
    sensor = tables['honeypot']
    statement = (mapping_query(tables).add_columns(
        action.c.id_analisis, session.c.id_sesion, session.c.cowrie_session_id, session.c.fecha_inicio,
        session.c.fecha_fin, func.host(session.c.ip_origen).label('ip_origen'),
        sensor.c.nombre.label('sensor'), analysis.c.estado.label('estado_analisis'),
        action.c.tipo_accion, action.c.descripcion.label('descripcion_accion'), mapping.c.fecha_mapeo,
        func.coalesce(analysis.c.fecha_fin, analysis.c.fecha_inicio, analysis.c.creado_en).label('fecha_analisis'),
        analysis.c.resultado_estructurado['version_informe'].astext.label('version_informe'),
        analysis.c.resultado_estructurado['rag']['version_pipeline'].astext.label('version_pipeline'),
        modality.label('modalidad'), state.label('estado_identificacion'),
        func.coalesce(automatic, False).label('origen_automatico'), cited.c.citas,
        seen.label('primera_aparicion'),
        func.coalesce(cited.c.ultima_cita, session.c.fecha_inicio).label('ultima_aparicion'),
    ).join(action, mapping.c.id_accion == action.c.id_accion)
        .join(analysis, action.c.id_analisis == analysis.c.id_analisis)
        .join(session, analysis.c.id_sesion == session.c.id_sesion)
        .join(sensor, session.c.id_honeypot == sensor.c.id_honeypot)
        .join(cited, literal(True))
        .where(session.c.id_honeypot.in_(sensors)))
    search_fields = (technique.c.codigo_tecnica, technique.c.nombre, tactic.c.codigo_tactica, tactic.c.nombre,
                     session.c.cowrie_session_id, cast(session.c.id_sesion, String))
    for term, columns in ((filters.q, search_fields), (filters.tactica, search_fields[2:4]),
                          (filters.sesion, search_fields[4:])):
        if term.strip():
            statement = statement.where(or_(*(column.icontains(term.strip(), autoescape=True) for column in columns)))
    if filters.codigo.strip():
        statement = statement.where(technique.c.codigo_tecnica == filters.codigo.strip().upper())
    if filters.id_sesion:
        statement = statement.where(session.c.id_sesion == filters.id_sesion)
    if filters.modalidad:
        statement = statement.where(modality == filters.modalidad)
    if filters.estado:
        statement = statement.where(state == filters.estado)
    if filters.plataforma:
        statement = statement.where(cast(technique.c.plataformas, JSONB).contains([filters.plataforma]))
    if filters.ip:
        statement = statement.where(func.host(session.c.ip_origen).icontains(filters.ip.strip(), autoescape=True))
    if filters.citas:
        statement = statement.where(cited.c.citas > 0 if filters.citas == 'con' else cited.c.citas == 0)
    if filters.grado:
        statement = statement.where(mapping.c.grado_evidencia.is_(None) if filters.grado == 'sin_registro'
                                    else mapping.c.grado_evidencia == filters.grado)
    if filters.desde and filters.hasta and filters.desde > filters.hasta:
        raise HTTPException(422, 'La fecha inicial debe preceder a la final')
    if filters.desde:
        statement = statement.where(seen >= datetime.combine(filters.desde, time.min, ECUADOR))
    if filters.hasta:
        statement = statement.where(seen <= datetime.combine(filters.hasta, time.max, ECUADOR))
    return statement


def counters(rows):
    return (
        func.count().label('mapeos'),
        func.count().filter(rows.origen_automatico, rows.estado_identificacion != 'descartada').label('automaticas'),
        func.count().filter(rows.estado_revision == 'confirmado').label('confirmadas'),
        func.count().filter(rows.estado_revision == 'pendiente').label('pendientes'),
        func.count().filter(~rows.origen_automatico).label('historicas'),
        func.count().filter(rows.estado_identificacion == 'descartada').label('descartadas'),
        func.count().filter(rows.citas > 0).label('con_citas'),
        func.count().filter(rows.citas == 0).label('sin_citas'),
    )


def technique_groups(rows, order='ultima'):
    rows = rows.subquery().c
    sessions = func.count(func.distinct(rows.id_sesion)).label('sesiones')
    first = func.min(rows.primera_aparicion).label('primera_aparicion')
    last = func.max(rows.ultima_aparicion).label('ultima_aparicion')
    sort = {'codigo': rows.codigo_tecnica, 'nombre': rows.tecnica, 'sesiones': sessions.desc(),
            'mapeos': func.count().desc(), 'primera': first.asc(), 'ultima': last.desc()}[order]
    return (select(rows.codigo_tecnica, rows.tecnica,
                   func.array_agg(func.distinct(rows.tactica)).label('tacticas'),
                   func.array_agg(func.distinct(rows.estado_identificacion)).label('estados'),
                   sessions, first, last, *counters(rows),
                   func.max(rows.fecha_analisis).label('ultimo_analisis'))
            .group_by(rows.codigo_tecnica, rows.tecnica)
            .order_by(sort.nulls_last(), rows.codigo_tecnica))


def session_groups(rows, tables, order='ultima'):
    rows = rows.subquery().c
    events = tables['evento']
    total = select(func.count()).where(events.c.id_sesion == rows.id_sesion).correlate(rows.id_sesion.table)
    sort = {'codigo': rows.cowrie_session_id, 'nombre': rows.cowrie_session_id, 'sesiones': func.count().desc(),
            'mapeos': func.count().desc(), 'primera': rows.fecha_inicio, 'ultima': func.max(rows.ultima_aparicion).desc()}[order]
    return (select(rows.id_sesion, rows.cowrie_session_id, rows.fecha_inicio, rows.fecha_fin,
                   rows.ip_origen, rows.sensor, total.scalar_subquery().label('eventos'),
                   func.extract('epoch', rows.fecha_fin - rows.fecha_inicio).label('duracion_segundos'),
                   func.array_agg(func.distinct(rows.modalidad)).label('modalidades'),
                   func.array_agg(func.distinct(rows.estado_identificacion)).label('estados'),
                   func.array_agg(func.distinct(rows.estado_analisis)).label('estados_analisis'),
                   func.count(func.distinct(rows.id_accion)).label('acciones'), *counters(rows),
                   func.max(rows.fecha_analisis).label('ultimo_analisis'))
            .group_by(rows.id_sesion, rows.cowrie_session_id, rows.fecha_inicio, rows.fecha_fin,
                      rows.ip_origen, rows.sensor)
            .order_by(sort.nulls_last(), rows.id_sesion))


def breakdown(conn, rows, *fields):
    return [dict(row) for row in conn.execute(select(*fields, *counters(rows))
                                            .group_by(*fields).order_by(*fields)).mappings()]


def timeline(conn, rows, filters):
    day = cast(func.timezone('America/Guayaquil', rows.primera_aparicion), Date).label('fecha')
    source = case((rows.citas > 0, 'evento_citado'), else_='inicio_sesion').label('origen_fecha')
    zero = {field.name: 0 for field in counters(rows)}
    return calendar_series(breakdown(conn, rows, day, source), 'fecha', {**zero,'origen_fecha':'sin_actividad'},
                           start=filters.desde, end=filters.hasta)


def totals(conn, tables, rows):
    refs = citation_query(tables).subquery()
    cited_events = (select(func.count(func.distinct(refs.c.id_evento))).select_from(
        refs.join(rows, refs.c.id_mapeo == rows.c.id_mapeo)).correlate(None).scalar_subquery())
    rows = rows.c
    values = conn.execute(select(
        technique_count(rows).label('tecnicas'),
        func.count(func.distinct(rows.codigo_tactica)).label('tacticas'),
        func.count(func.distinct(rows.id_sesion)).label('sesiones'),
        func.count(func.distinct(rows.id_accion)).label('acciones'),
        func.count(func.distinct(rows.ip_origen)).label('ips'),
        func.min(rows.primera_aparicion).label('primera_aparicion'),
        func.max(rows.ultima_aparicion).label('ultima_aparicion'),
        cited_events.label('eventos_citados'), *counters(rows))).mappings().one()
    return dict(values)


def analytics(conn, tables, statement, filters=None):
    filters = filters or MitreFilters()
    rows = statement.subquery().c
    series, period = timeline(conn, rows, filters)
    return {
        'totales': totals(conn, tables, rows.codigo_tecnica.table),
        'tacticas': breakdown(conn, rows, rows.codigo_tactica, rows.tactica),
        'modalidades': breakdown(conn, rows, rows.modalidad),
        'estados': breakdown(conn, rows, rows.estado_identificacion),
        'evolucion': series, 'periodo_evolucion': period,
        'poblacion': {'unidad':'técnica distinta con mapeo registrado', 'filtros':filters.model_dump()},
        'recurrentes': [dict(row) for row in conn.execute(technique_groups(statement, 'sesiones').limit(8)).mappings()],
    }


def observable_total(conn, tables, statement):
    rows = statement.subquery()
    citation = tables['mapeo_mitre_evento']
    detection = tables['deteccion_ioc']
    action = tables['accion_identificada']
    query = (action_observable_query(tables)
             .join(rows, rows.c.id_accion == action.c.id_accion)
             .join(citation, and_(citation.c.id_mapeo == rows.c.id_mapeo,
                                  citation.c.id_evento == detection.c.id_evento))
             .add_columns(rows.c.codigo_tecnica, rows.c.tecnica, rows.c.rag_procedencia,
                          rows.c.estado_revision.label('revision_mitre'), citation.c.metodo.label('metodo_cita'))
             .where(rows.c.estado_identificacion != 'descartada', tables['evento'].c.id_sesion == rows.c.id_sesion))
    accepted = set()
    for row in conn.execute(query).mappings():
        link = action_link(row)
        mapping = {'codigo_tecnica': row.codigo_tecnica, 'tecnica': row.tecnica,
                   'estado_revision': row.revision_mitre, 'rag_procedencia': row.rag_procedencia,
                   'eventos': [{'id_evento': link['id_evento'], 'metodo': row.metodo_cita}]}
        match = mitre_link(row, link, mapping)
        if match and match['estado'] != 'insuficiente':
            accepted.add(row.id_ioc)
    return len(accepted)


def official_status(technique, catalog):
    return case((technique.c.revocada, 'revocada'), (technique.c.deprecada, 'deprecada'),
                (catalog.c.activo.is_(True), 'vigente'), else_='historica').label('estado_catalogo')


def matrix(conn, tables, statement, filters, include_catalog):
    rows = statement.subquery().c
    counts = (select(rows.codigo_tecnica, rows.codigo_tactica,
                     func.count(func.distinct(rows.id_sesion)).label('sesiones'), *counters(rows))
              .group_by(rows.codigo_tecnica, rows.codigo_tactica).subquery())
    link, technique, tactic, catalog = (tables[name] for name in (
        'tecnica_tactica', 'tecnica_mitre', 'tactica_mitre', 'catalogo_mitre'))
    term = filters.tactica.strip()
    active = and_(catalog.c.activo.is_(True), link.c.activa_en_catalogo.is_(True),
                  link.c.id_catalogo == catalog.c.id_catalogo, ~technique.c.revocada, ~technique.c.deprecada,
                  ~tactic.c.revocada, ~tactic.c.deprecada)
    catalog_scope = active
    if term:
        catalog_scope = and_(catalog_scope, or_(tactic.c.nombre.icontains(term, autoescape=True),
                                                tactic.c.codigo_tactica.icontains(term, autoescape=True)))
    if filters.plataforma:
        catalog_scope = and_(catalog_scope, cast(technique.c.plataformas, JSONB).contains([filters.plataforma]))
    columns = ('sesiones', 'mapeos', 'automaticas', 'confirmadas', 'pendientes', 'descartadas', 'con_citas', 'sin_citas')
    query = (select(tactic.c.codigo_tactica, tactic.c.nombre.label('tactica'), technique.c.codigo_tecnica,
                    technique.c.nombre.label('tecnica'), technique.c.tecnica_padre_id, official_status(technique, catalog),
                    active.label('relacion_vigente'), *(func.coalesce(counts.c[key], 0).label(key) for key in columns))
             .select_from(link.join(technique, link.c.codigo_tecnica == technique.c.codigo_tecnica)
                          .join(tactic, link.c.codigo_tactica == tactic.c.codigo_tactica)
                          .outerjoin(catalog, technique.c.id_catalogo == catalog.c.id_catalogo)
                          .outerjoin(counts, and_(counts.c.codigo_tecnica == link.c.codigo_tecnica,
                                                  counts.c.codigo_tactica == link.c.codigo_tactica)))
             .where(or_(counts.c.mapeos > 0, catalog_scope) if include_catalog else counts.c.mapeos > 0)
             .order_by(tactic.c.codigo_tactica, technique.c.codigo_tecnica))
    return [dict(row) for row in conn.execute(query).mappings()]


def technique_record(conn, tables, code):
    technique, tactic, link, catalog = (tables[name] for name in (
        'tecnica_mitre', 'tactica_mitre', 'tecnica_tactica', 'catalogo_mitre'))
    query = (select(technique.c.codigo_tecnica, technique.c.nombre, technique.c.descripcion,
                    technique.c.plataformas, technique.c.stix_id, technique.c.version_objeto,
                    technique.c.version_attack, technique.c.tecnica_padre_id, technique.c.jerarquia_fuente,
                    official_status(technique, catalog))
             .select_from(technique.outerjoin(catalog, technique.c.id_catalogo == catalog.c.id_catalogo))
             .where(technique.c.codigo_tecnica == code))
    record = conn.execute(query).mappings().first()
    if record is None:
        raise HTTPException(404, 'Técnica MITRE no encontrada')
    official = (select(tactic.c.codigo_tactica, tactic.c.nombre, link.c.activa_en_catalogo)
                .select_from(link.join(tactic, link.c.codigo_tactica == tactic.c.codigo_tactica))
                .where(link.c.codigo_tecnica == code).order_by(tactic.c.codigo_tactica))
    children = (select(technique.c.codigo_tecnica, technique.c.nombre, technique.c.revocada, technique.c.deprecada,
                       technique.c.jerarquia_fuente).where(technique.c.tecnica_padre_id == code)
                .order_by(technique.c.codigo_tecnica))
    return {**record, 'tacticas': [dict(row) for row in conn.execute(official).mappings()],
            'subtecnicas': [dict(row) for row in conn.execute(children).mappings()]}
