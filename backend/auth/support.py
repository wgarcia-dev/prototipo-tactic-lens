"""Support submission and supervised mail retries; no mailbox-reading integration."""
from datetime import timedelta
import re
import unicodedata
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import Field, field_validator
from sqlalchemy import select, text

from .notifications import enqueue
from .schemas import AdministrativeAction, EmailPayload
from .security import fingerprint, now
from .service import reauthenticate
from .store import AuthError, audit, rate, require_admin, session, table, transaction

router=APIRouter(prefix="/api/auth",tags=["Correo y soporte"])


class SupportRequest(EmailPayload):
    nombre: str=Field(min_length=2,max_length=120)
    asunto: str=Field(min_length=5,max_length=140)
    categoria: Literal["acceso","mfa","recuperacion","funcional","general"]
    descripcion: str=Field(min_length=20,max_length=3000)

    @field_validator("nombre","asunto","descripcion")
    @classmethod
    def clean_text(cls,value,info):
        value=unicodedata.normalize("NFC",value).strip()
        if any(unicodedata.category(c)=="Cc" and (info.field_name!="descripcion" or c not in "\n\r\t") for c in value):
            raise ValueError("No se admiten caracteres de control")
        if info.field_name!="descripcion":
            value=" ".join(value.split())
        if len(value)<{"nombre":2,"asunto":5,"descripcion":20}[info.field_name]:
            raise ValueError("Complete el campo con información suficiente")
        if re.search(r"(?i)\b(?:password|contraseña|api[_ -]?key|secreto[_ -]?totp|token)\s*[:=]\s*\S+|\b(?:re_|sk-)[A-Za-z0-9_-]{20,}",value):
            raise ValueError("No incluya contraseñas, tokens ni claves; describa únicamente el problema")
        return value


@router.get("/contacto")
def contact(request: Request):
    config=request.app.state.mail_config
    return {"support_email":config.support,"support_enabled":bool(config.support)}


@router.post("/soporte",status_code=202)
def support(payload: SupportRequest,request: Request):
    config=request.app.state.mail_config
    if not config.support:
        raise AuthError(503,"El canal de soporte aún no está configurado")
    with transaction(request) as conn:
        rate(conn,request,"soporte_ip",ip_limit=10)
        user=None
        try:
            _,user=session(conn,request,{"completa"})
        except AuthError:
            pass
        verified=bool(user and user.correo==payload.correo and user.correo_verificado_en)
        user_id=user.id_usuario if verified else None
        s=table(request,"auth_soporte")
        key=fingerprint(request.app.state.auth_settings,"soporte_dedupe",
            "\n".join([payload.correo,payload.nombre,payload.asunto,payload.categoria,payload.descripcion]))
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),{"key":key})
        existing=conn.scalar(select(s.c.id_soporte).where(s.c.dedupe_hash==key,s.c.creado_en>now()-timedelta(minutes=5)))
        if existing:
            return {"id_solicitud":str(existing),"mensaje":"Su consulta ya fue recibida. No se creó un envío duplicado."}
        rate(conn,request,"soporte_correo",payload.correo,account_limit=3,ip_limit=20)
        identifier=conn.scalar(s.insert().values(id_usuario=user_id,nombre=payload.nombre,correo=payload.correo,
            asunto=payload.asunto,categoria=payload.categoria,descripcion=payload.descripcion,correo_verificado=verified,
            dedupe_hash=key,creado_por=user_id).returning(s.c.id_soporte))
        enqueue(conn,request,kind="soporte",destination=config.support,support_id=identifier,actor=user_id)
        if verified:
            enqueue(conn,request,kind="confirmacion_soporte",destination=user.correo,support_id=identifier,actor=user_id)
        audit(conn,request,"soporte_mfa_solicitado" if payload.categoria=="mfa" else "soporte_solicitado",user_id,
              request_id=str(identifier),resultado="recibido")
    return {"id_solicitud":str(identifier),"mensaje":"Su consulta quedó registrada para remisión a soporte. Las respuestas se realizan manualmente por correo."}


@router.get("/soporte/mis-solicitudes")
def own_support(request: Request,limit: int=Query(10,ge=1,le=25)):
    with transaction(request) as conn:
        _,user=session(conn,request,{"completa"})
        s,q=table(request,"auth_soporte"),table(request,"auth_notificacion")
        return [dict(row) for row in conn.execute(select(s.c.id_soporte,s.c.asunto,s.c.categoria,s.c.creado_en,
            q.c.estado.label("estado_envio"),q.c.resultado).join(q,(q.c.id_soporte==s.c.id_soporte)&(q.c.tipo=="soporte"))
            .where(s.c.id_usuario==user.id_usuario).order_by(s.c.creado_en.desc()).limit(limit)).mappings()]


@router.get("/admin/notificaciones")
def notifications(request: Request,estado: str|None=None,limit: int=Query(25,ge=1,le=100),offset: int=Query(0,ge=0)):
    with transaction(request) as conn:
        require_admin(conn,request)
        q=table(request,"auth_notificacion")
        statement=select(q.c.id_notificacion,q.c.tipo,q.c.id_auditoria,q.c.id_soporte,q.c.destinatario,
            q.c.estado,q.c.intentos,q.c.creado_en,q.c.ultimo_intento_en,q.c.proximo_intento_en,q.c.aceptado_en,q.c.resultado)
        if estado:
            statement=statement.where(q.c.estado==estado)
        return [dict(row) for row in conn.execute(statement.order_by(q.c.creado_en.desc(),q.c.id_notificacion).limit(limit).offset(offset)).mappings()]


@router.post("/admin/notificaciones/{identifier}/reintentar",status_code=202)
def retry_notification(identifier: UUID,payload: AdministrativeAction,request: Request):
    with transaction(request) as conn:
        _,actor=require_admin(conn,request)
        rate(conn,request,"correo_reintentar",actor.id_usuario,account_limit=10)
        reauthenticate(conn,request,actor,payload)
        q=table(request,"auth_notificacion")
        row=conn.execute(select(q).where(q.c.id_notificacion==identifier).with_for_update()).mappings().first()
        if not row:
            raise AuthError(404,"Notificación no encontrada")
        if row.estado not in {"fallido", "reintento"} or row.intentos>=request.app.state.mail_config.max_attempts:
            raise AuthError(409,"La notificación no admite más reintentos")
        if row.primer_intento_en and row.primer_intento_en<=now()-timedelta(hours=23):
            raise AuthError(409,"La ventana segura de idempotencia expiró; revise el caso manualmente")
        if row.proximo_intento_en and row.proximo_intento_en>now():
            raise AuthError(409,"Espere hasta la fecha indicada para volver a intentar")
        conn.execute(q.update().where(q.c.id_notificacion == identifier).values(
            estado="reintento", proximo_intento_en=now()))
        audit(conn,request,"correo_reintento_solicitado",actor.id_usuario,actor.id_usuario,
              notification_id=str(identifier),reason=payload.motivo,resultado="programado")
    return {"mensaje":"Reintento programado con la misma referencia; no se confirma entrega en el buzón."}
