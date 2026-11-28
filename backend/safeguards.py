"""Persist recommendations and maintain a separate, authorized execution history."""
from datetime import date, datetime, timezone
from hashlib import sha256
import json
import unicodedata
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert

from .api import local_only, sensor_ids
from .realtime import notify_change
from .auth.store import approved, identity, session
from .safeguard_risk import assess_safeguard
from .sensitive import session_redactors

router = APIRouter(prefix="/api/salvaguardas", dependencies=[Depends(local_only)])
STATES = ("pendiente", "en_desarrollo", "realizada")


def capacity(conn, tables, *, lock=False, require_space=False):
    config, task = tables["salvaguarda_config"], tables["salvaguarda"]
    query = select(config.c.wip_activo, config.c.limite_wip).where(config.c.tablero.is_(True))
    settings = conn.execute(query.with_for_update() if lock else query).one()
    # Read after acquiring the singleton lock. Another transition may have
    # committed while this transaction was waiting for the lock.
    current = conn.scalar(select(func.count()).select_from(task).where(
        task.c.estado == "en_desarrollo", task.c.id_sesion.in_(scope(tables))))
    available = max(0, settings.limite_wip - current) if settings.wip_activo else None
    if require_space and available == 0:
        raise HTTPException(409, f"Límite WIP alcanzado ({current}/{settings.limite_wip}). Finalice una salvaguarda antes de iniciar otra.")
    return {"wip_activo": settings.wip_activo, "limite_wip": settings.limite_wip,
            "en_desarrollo": current, "disponibles": available}


def register_recommendations(conn, tables, analysis_id, session_id, payload):
    task, origin, events = (tables[key] for key in ("salvaguarda","salvaguarda_origen","evento"))
    recommendations = (payload.get("informe") or {}).get("recomendaciones") or []
    original = set(conn.scalars(select(origin.c.posicion).where(origin.c.id_analisis == analysis_id)))
    for index, item in enumerate(recommendations, 1):
        if index in original or not isinstance(item, dict) or not all(isinstance(item.get(key),str) and item[key].strip()
                for key in ("salvaguarda","activo","riesgo","objetivo","medidas","validacion")):
            continue
        assessment = assess_safeguard(item, payload)
        if not assessment["nivel"]:
            continue
        ids = [int(eid) for eid in assessment["eventos"]]
        if set(conn.scalars(select(events.c.id_evento).where(
                events.c.id_sesion == session_id, events.c.id_evento.in_(ids)))) != set(ids):
            continue
        identity_fields = [" ".join(unicodedata.normalize("NFKC", item[key]).casefold().split()).rstrip(".")
                           for key in ("salvaguarda","activo","objetivo","medidas")]
        digest = sha256(json.dumps(identity_fields, ensure_ascii=False).encode()).hexdigest()
        priority = item.get("prioridad_recomendada")
        inserted = conn.scalar(insert(task).values(id_sesion=session_id,huella=digest,nombre=item["salvaguarda"],
            nivel_riesgo=assessment["nivel"],prioridad=priority if priority in {"baja","media","alta","inmediata"} else None)
            .on_conflict_do_nothing(index_elements=[task.c.id_sesion, task.c.huella]).returning(task.c.id_salvaguarda))
        if inserted is None:
            inserted = conn.scalar(select(task.c.id_salvaguarda).where(task.c.id_sesion==session_id,task.c.huella==digest))
        conn.execute(insert(origin).values(id_analisis=analysis_id,posicion=index,id_salvaguarda=inserted,
            recomendacion=item,valoracion=assessment).on_conflict_do_nothing())


def backfill(conn, tables, sensors):
    analysis, sessions = tables["analisis_llm"], tables["sesion"]
    query = select(analysis.c.id_analisis,analysis.c.id_sesion,analysis.c.resultado_estructurado).join(
        sessions, sessions.c.id_sesion == analysis.c.id_sesion).where(analysis.c.estado=="completado",
        sessions.c.id_honeypot.in_(sensors)).order_by(func.coalesce(analysis.c.fecha_fin,analysis.c.creado_en),analysis.c.id_analisis)
    for row in conn.execute(query):
        if isinstance(row.resultado_estructurado, dict):
            register_recommendations(conn, tables, row.id_analisis, row.id_sesion, row.resultado_estructurado)


def linked_tasks(conn, tables, analysis_id):
    source, task = tables["salvaguarda_origen"], tables["salvaguarda"]
    return {row.posicion:{"id":str(row.id_salvaguarda),"codigo":f"SG-{row.codigo:05d}","valoracion":row.valoracion}
            for row in conn.execute(select(source.c.posicion, task.c.id_salvaguarda, task.c.codigo, source.c.valoracion).join(
                task, task.c.id_salvaguarda==source.c.id_salvaguarda).where(source.c.id_analisis==analysis_id))}


def scope(tables):
    return select(tables["sesion"].c.id_sesion).where(tables["sesion"].c.id_honeypot.in_(sensor_ids()))


def public_row(row):
    data = dict(row)
    data["codigo"] = f"SG-{data['codigo']:05d}"
    data.pop("huella", None)
    return data


@router.get("")
def list_safeguards(request: Request, estado: Literal["pendiente","en_desarrollo","realizada"] | None=None,
                    riesgo: Literal["bajo","medio","alto","critico"] | None=None,
                    prioridad: Literal["baja","media","alta","inmediata"] | None=None,
                    responsable: UUID | None=None, id_sesion: UUID | None=None,
                    desde: date | None=None, hasta: date | None=None, mias: bool=False, sin_asignar: bool=False,
                    q: Annotated[str, Query(max_length=150)]="", limite: Annotated[int, Query(ge=1, le=200)]=90,
                    offset: Annotated[int, Query(ge=0)]=0,
                    orden: Literal["prioridad","riesgo","vencimiento","creacion"]="creacion"):
    tables = request.app.state.tables
    t, user = tables["salvaguarda"], tables["usuario"]
    query = select(t,user.c.nombre_usuario.label("responsable")).outerjoin(user, t.c.id_responsable==user.c.id_usuario)
    query = query.where(t.c.id_sesion.in_(scope(tables)))
    for column, value in ((t.c.estado,estado),(t.c.nivel_riesgo,riesgo),(t.c.prioridad,prioridad),
                          (t.c.id_responsable,responsable),(t.c.id_sesion,id_sesion)):
        if value is not None:
            query = query.where(column == value)
    if mias:
        query = query.where(t.c.id_responsable==UUID(request.state.user["id_usuario"]))
    if sin_asignar:
        query = query.where(t.c.id_responsable.is_(None))
    if desde:
        query = query.where(func.date(t.c.creado_en) >= desde)
    if hasta:
        query = query.where(func.date(t.c.creado_en) <= hasta)
    if q.strip():
        term = q.strip()
        formatted = literal("SG-") + func.lpad(t.c.codigo.cast(t.c.nombre.type), 5, "0")
        numeric = term.upper().removeprefix("SG-")
        query = query.where(or_(t.c.nombre.icontains(term,autoescape=True), formatted.icontains(term,autoescape=True),
            t.c.codigo==int(numeric) if numeric.isascii() and numeric.isdigit() and len(numeric)<=18 else False))
    with request.app.state.engine.connect() as conn:
        total = conn.scalar(select(func.count()).select_from(query.subquery()))
        order = {
            "prioridad":case({"inmediata":4,"alta":3,"media":2,"baja":1},value=t.c.prioridad,else_=0).desc(),
            "riesgo":case({"critico":4,"alto":3,"medio":2,"bajo":1},value=t.c.nivel_riesgo,else_=0).desc(),
            "vencimiento":t.c.vence_en.asc().nulls_last(),
            "creacion":t.c.creado_en.desc(),
        }
        items = [public_row(row) for row in conn.execute(query.order_by(order[orden],t.c.codigo.desc()).offset(offset).limit(limite)).mappings()]
        redactors = session_redactors(conn, tables["evento"], {item["id_sesion"] for item in items})
        items = [redactors[item["id_sesion"]].payload(item) for item in items]
    return {"items":items,"total":total}


@router.get("/indicadores")
def indicators(request: Request):
    tables = request.app.state.tables
    t = tables["salvaguarda"]
    query = select(func.count().label("total"), *(func.count().filter(t.c.estado==state).label(state) for state in STATES),
        func.count().filter(t.c.id_responsable.is_(None)).label("sin_asignar"),
        func.count().filter(t.c.estado!="realizada", t.c.vence_en < func.current_date()).label("vencidas")).where(
            t.c.id_sesion.in_(scope(tables)))
    with request.app.state.engine.connect() as conn:
        return {**dict(conn.execute(query).mappings().one()),"wip":capacity(conn,tables)}


class BoardConfig(BaseModel):
    wip_activo: bool
    limite_wip: int = Field(ge=1, le=10000, strict=True)


@router.get("/configuracion")
def board_config(request: Request):
    with request.app.state.engine.connect() as conn:
        return capacity(conn,request.app.state.tables)


@router.put("/configuracion")
def configure_board(body: BoardConfig, request: Request):
    tables = request.app.state.tables
    config = tables["salvaguarda_config"]
    with request.app.state.engine.begin() as conn:
        _, actor = session(conn,request,{"completa"})
        if actor.rol != "administrador":
            raise HTTPException(403,"Solo un administrador puede configurar el límite WIP")
        conn.execute(config.update().where(config.c.tablero.is_(True)).values(**body.model_dump()))
        notify_change(conn, sensor_ids(), "salvaguardas")
        return capacity(conn,tables)


@router.get("/analistas")
def analysts(request: Request):
    tables = request.app.state.tables
    u, r = tables["usuario"], tables["rol"]
    query = select(u.c.id_usuario,u.c.nombre_usuario).join(r,u.c.id_rol==r.c.id_rol).where(
        r.c.codigo=="analista",r.c.activo,u.c.activo,func.coalesce(u.c.restriccion_acceso, "") == "",
        u.c.autorizacion=="aprobado",u.c.correo_verificado_en.is_not(None),
        ~u.c.password_cambio_obligatorio).order_by(u.c.nombre_usuario)
    with request.app.state.engine.connect() as conn:
        return [dict(row) for row in conn.execute(query).mappings()]


def get_task(conn, tables, task_id, lock=False):
    t = tables["salvaguarda"]
    query = select(t).where(t.c.id_salvaguarda==task_id,t.c.id_sesion.in_(scope(tables)))
    row = conn.execute(query.with_for_update() if lock else query).mappings().first()
    if not row:
        raise HTTPException(404,"Salvaguarda no encontrada")
    return row


def history(conn, tables, task_id):
    h, u = tables["salvaguarda_historial"], tables["usuario"]
    return [dict(row) for row in conn.execute(select(h,u.c.nombre_usuario.label("actor")).join(
        u,u.c.id_usuario==h.c.id_actor).where(h.c.id_salvaguarda==task_id).order_by(h.c.id_cambio)).mappings()]


@router.get("/{task_id}")
def detail(task_id: UUID, request: Request):
    tables = request.app.state.tables
    s, a, u = (tables[key] for key in ("salvaguarda_origen","analisis_llm","usuario"))
    with request.app.state.engine.connect() as conn:
        task = public_row(get_task(conn,tables,task_id))
        task["responsable"] = conn.scalar(select(u.c.nombre_usuario).where(u.c.id_usuario==task["id_responsable"]))
        origins = [dict(row) for row in conn.execute(select(s.c.id_analisis,s.c.posicion,s.c.recomendacion,s.c.valoracion,
            a.c.fecha_fin).join(a,a.c.id_analisis==s.c.id_analisis).where(s.c.id_salvaguarda==task_id).order_by(
                a.c.fecha_fin.asc().nulls_last(),s.c.id_analisis,s.c.posicion)).mappings()]
        sid = task["id_sesion"]
        redactor = session_redactors(conn, tables["evento"], [sid])[sid]
        return redactor.payload({**task,"origenes":origins,"historial":history(conn,tables,task_id)})


@router.get("/{task_id}/historial")
def task_history(task_id: UUID, request: Request):
    tables = request.app.state.tables
    with request.app.state.engine.connect() as conn:
        task = get_task(conn,tables,task_id)
        return session_redactors(conn, tables["evento"], [task.id_sesion])[task.id_sesion].payload(history(conn,tables,task_id))


class Change(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    responsable: UUID | None = None
    estado: Literal["pendiente","en_desarrollo","realizada"] | None = None
    vence_en: date | None = None
    observacion: str = Field(default="",max_length=4000)
    evidencia: str = Field(default="",max_length=4000)
    resultado: str = Field(default="",max_length=4000)
    criterio_aplicado: str = Field(default="",max_length=2000)


@router.post("/{task_id}/{operation}")
def change(task_id: UUID, operation: Literal["asignacion","estado","avance","evidencia","reapertura"],
           body: Change, request: Request):
    tables = request.app.state.tables
    task, log = tables["salvaguarda"], tables["salvaguarda_historial"]
    with request.app.state.engine.begin() as conn:
        _, actor = session(conn,request,{"completa"})
        row = get_task(conn,tables,task_id,lock=True)
        admin = actor.rol=="administrador"
        if not admin and (row.id_responsable != actor.id_usuario or operation in {"asignacion","reapertura"}):
            raise HTTPException(403,"Solo el responsable puede gestionar esta salvaguarda. La asignación y reapertura son administrativas.")
        if row.estado=="realizada" and operation not in {"reapertura","asignacion"}:
            raise HTTPException(409,"Reabra la salvaguarda antes de cambiar su seguimiento")
        moment = datetime.now(timezone.utc)
        values = {}
        data = {}
        starting = operation=="estado" and row.estado=="pendiente" and body.estado=="en_desarrollo"
        assigns_on_start = starting and body.responsable is not None
        if assigns_on_start and not admin:
            raise HTTPException(403,"Solo un administrador puede asignar al iniciar")
        responsible = body.responsable if operation=="asignacion" or assigns_on_start else row.id_responsable
        reopening_into_work = operation=="reapertura" and body.estado!="pendiente"
        if operation in {"asignacion","estado"} or reopening_into_work:
            person = identity(conn, request, responsible, lock=True) if responsible else None
            if not approved(person) or person.rol!="analista" or person.password_cambio_obligatorio:
                raise HTTPException(422,"Seleccione un analista activo y habilitado")
        if operation=="asignacion":
            values = {"id_responsable":responsible,"asignado_en":moment}
            if "vence_en" in body.model_fields_set:
                values["vence_en"] = body.vence_en
            data = {"anterior":str(row.id_responsable) if row.id_responsable else None,"responsable":str(responsible),
                    "nombre_responsable":person.nombre_usuario,"vence_en":str(values.get("vence_en",row.vence_en) or "")}
        elif operation=="estado":
            if starting:
                capacity(conn,tables,lock=True,require_space=True)
                values = {"estado":"en_desarrollo","iniciado_en":moment}
                if assigns_on_start:
                    values.update(id_responsable=responsible,asignado_en=moment)
                    conn.execute(log.insert().values(id_salvaguarda=task_id,id_actor=actor.id_usuario,
                        operacion="asignacion",detalle={"anterior":str(row.id_responsable) if row.id_responsable else None,
                            "responsable":str(responsible),"nombre_responsable":person.nombre_usuario}))
            elif body.estado=="realizada" and row.estado=="en_desarrollo":
                if not all(len(value)>=8 for value in (body.resultado,body.evidencia,body.criterio_aplicado)):
                    raise HTTPException(422,"Describa el resultado, la evidencia verificable y el criterio aplicado")
                values = {"estado":"realizada","finalizado_en":moment}
                data = {"resultado":body.resultado,"evidencia":body.evidencia,"criterio_aplicado":body.criterio_aplicado}
                if body.observacion:
                    data["observacion"] = body.observacion
            else:
                raise HTTPException(409,"Transición de estado inválida")
            data.update(anterior=row.estado,estado=values["estado"])
        elif operation=="reapertura":
            if row.estado!="realizada" or len(body.observacion)<12:
                raise HTTPException(422,"La reapertura requiere una salvaguarda realizada y una justificación")
            if body.estado not in {None,"pendiente","en_desarrollo"}:
                raise HTTPException(409,"Destino de reapertura inválido")
            destination = body.estado or "en_desarrollo"
            if destination=="en_desarrollo":
                capacity(conn,tables,lock=True,require_space=True)
                values = {"estado":destination,"finalizado_en":None,"iniciado_en":moment}
            else:
                values = {"estado":destination,"finalizado_en":None,"iniciado_en":None}
            data = {"anterior":row.estado,"estado":destination,"justificacion":body.observacion}
        else:
            value = body.observacion if operation=="avance" else body.evidencia
            if row.estado!="en_desarrollo" or len(value)<8:
                raise HTTPException(422,"Se requiere una salvaguarda en desarrollo y una descripción verificable")
            data["observacion" if operation=="avance" else "evidencia"] = value
        if values:
            conn.execute(task.update().where(task.c.id_salvaguarda==task_id).values(**values))
        conn.execute(log.insert().values(id_salvaguarda=task_id,id_actor=actor.id_usuario,operacion=operation,detalle=data))
        sessions = tables["sesion"]
        sensor = conn.scalar(select(sessions.c.id_honeypot).where(sessions.c.id_sesion == row.id_sesion))
        notify_change(conn, [sensor], "salvaguardas")
    return {"estado":values.get("estado",row.estado)}
