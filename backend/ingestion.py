"""Durable occurrence identity, sequential ordering and explicit per-event receipts."""
import hashlib
import ipaddress
import json
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DataError, IntegrityError, SQLAlchemyError
from .intelligence import persist_observables

CONTRACT = "tacticlens.ingesta.v2"


def event_identity(raw):
    """Full occurrence identity; never reduce it to a sequence-number hash."""
    origin = raw.get("_collector", {}).get("source_id") if isinstance(raw.get("_collector"), dict) else None
    if not isinstance(origin, str) or not origin.strip() or len(origin) > 512 or any(ord(c)<32 or ord(c)==127 for c in origin):
        raise ValueError("origen_invalido")
    return origin


def prepare(raw):
    for key in ("session", "eventid"):
        if not isinstance(raw.get(key), str) or not raw[key].strip() or len(raw[key]) > 100:
            raise ValueError("estructura_invalida")
    origin=event_identity(raw)
    value = raw.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("fecha_invalida")
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("fecha_sin_zona")
    if raw.get("src_ip"):
        ipaddress.ip_address(raw["src_ip"])
    for key in ("src_port", "dst_port"):
        if raw.get(key) is not None:
            port = raw[key]
            if isinstance(port, bool) or not isinstance(port, (int,str)) or not str(port).isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("puerto_invalido")
    original = {k:v for k,v in raw.items() if k!="_collector"}
    encoded = json.dumps(original, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode()
    if len(encoded)>131072:
        raise ValueError("evento_demasiado_grande")
    return origin, when, original, hashlib.sha256(encoded).hexdigest()


def save_event(conn, tables, sensor, raw, prepared):
    s,e,o = (tables[n] for n in ("sesion","evento","evento_origen"))
    origin,when,original,digest = prepared
    previous = conn.execute(select(o.c.id_evento,o.c.contenido_sha256).where(o.c.id_honeypot==sensor,o.c.origen_id==origin)).first()
    if previous:
        if previous.contenido_sha256!=digest:
            raise ValueError("origen_reutilizado_con_otro_contenido")
        return previous.id_evento, "duplicado"
    values = {"id_honeypot":sensor,"cowrie_session_id":raw["session"],"fecha_inicio":when,
              "protocolo":str(raw.get("protocol") or "ssh")[:20]}
    if raw.get("src_ip"):
        values["ip_origen"]=raw["src_ip"]
    for src,dest in (("src_port","puerto_origen"),("dst_port","puerto_destino")):
        if raw.get(src) is not None:
            values[dest]=int(raw[src])
    base=insert(s).values(**values)
    sid=conn.scalar(base.on_conflict_do_update(index_elements=["id_honeypot","cowrie_session_id"],set_={
        "fecha_inicio":func.least(s.c.fecha_inicio,base.excluded.fecha_inicio),
        "ip_origen":func.coalesce(s.c.ip_origen,base.excluded.ip_origen),
        "puerto_origen":func.coalesce(s.c.puerto_origen,base.excluded.puerto_origen),
        "puerto_destino":func.coalesce(s.c.puerto_destino,base.excluded.puerto_destino),
        "actualizado_en":func.now()}).returning(s.c.id_sesion))
    # Compatibility only for the EXACT old source identity, never JSON equality
    # alone: an identical new occurrence must not consume an unrelated old row.
    legacy_id=int.from_bytes(hashlib.sha256(origin.encode()).digest()[:8],'big') & ((1<<63)-1)
    legacy=conn.scalar(select(e.c.id_evento).where(e.c.id_evento==legacy_id,e.c.id_sesion==sid,e.c.datos_originales==original,
        ~select(o.c.id_evento).where(o.c.id_evento==e.c.id_evento).exists()).order_by(e.c.id_evento).limit(1))
    if legacy is not None:
        event_id,state=legacy,"duplicado"
    else:
        sequence=conn.scalar(select(func.coalesce(func.max(e.c.numero_secuencia),0)+1).where(e.c.id_sesion==sid))
        event_id=None
        # Historical imports supplied explicit IDs; skip occupied values without
        # renumbering them or moving the identity sequence into the hash range.
        for _ in range(32):
            event_id=conn.scalar(insert(e).values(id_sesion=sid,numero_secuencia=sequence,
                tipo_evento=raw["eventid"],fecha_hora=when,datos_originales=original)
                .on_conflict_do_nothing(index_elements=["id_evento"]).returning(e.c.id_evento))
            if event_id is not None:
                break
        if event_id is None:
            raise RuntimeError("identity_sequence_busy")
        state="insertado"
    # Observables, event and receipt are one transaction. An exporter must never
    # receive a durable acknowledgement for only part of the ingestion work.
    persist_observables(conn,tables,original,event_id,when)
    conn.execute(o.insert().values(id_honeypot=sensor,origen_id=origin,id_evento=event_id,contenido_sha256=digest))
    if raw["eventid"]=="cowrie.session.closed":
        conn.execute(s.update().where(s.c.id_sesion==sid,s.c.fecha_inicio<=when).values(
            fecha_fin=func.greatest(s.c.fecha_fin,when),actualizado_en=func.now()))
    return event_id,state


def persist(engine, tables, sensor, events, *, partial=False, instances=None):
    receipts=[]
    try:
        with engine.begin() as conn:
            # Serialize ingestion for this sensor, including concurrent retries.
            # Analysis uses session locks but never takes this advisory lock.
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),{"key":"ingesta:"+str(sensor)})
            for index,raw in enumerate(events):
                source=raw.get("_collector",{}).get("source_id") if isinstance(raw.get("_collector"),dict) else None
                receipt={"indice":index,"source_id":source if isinstance(source,str) and len(source)<=512 else None}
                try:
                    prepared=prepare(raw)
                    collector = raw["_collector"]
                    instance = sensor
                    if "instance_id" in collector:
                        name = collector["instance_id"]
                        if not isinstance(name, str) or name not in ("cowrie_shell", "cowrie_proxy", "cowrie_llm"):
                            raise ValueError("instancia_invalida")
                        if not instances or name not in instances:
                            raise HTTPException(503, "Instancia pendiente de registro")
                        instance = instances[name]
                    with conn.begin_nested():
                        event_id,state=save_event(conn,tables,instance,raw,prepared)
                    receipt.update(estado=state,id_evento=event_id)
                except (ValueError, TypeError, OverflowError, IntegrityError, DataError):
                    if not partial:
                        raise HTTPException(422,"El evento no cumple el contrato de ingesta") from None
                    receipt.update(estado="rechazado",error="evento_invalido_o_identidad_en_conflicto")
                receipts.append(receipt)
    except (SQLAlchemyError,RuntimeError):
        # Infrastructure failures must never acknowledge or quarantine valid data.
        raise HTTPException(503,"Ingesta temporalmente no disponible; conserve y reintente el lote") from None
    result={"contrato":CONTRACT,"recibidos":len(events),
        "insertados":sum(r["estado"]=="insertado" for r in receipts),
        "duplicados":sum(r["estado"]=="duplicado" for r in receipts),
        "rechazados":sum(r["estado"]=="rechazado" for r in receipts),"confirmaciones":receipts}
    return result
