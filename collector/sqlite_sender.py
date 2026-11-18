#!/usr/bin/env python3
"""Delivery adapter for an INSPECTED existing SQLite queue. No second log reader.

Explicit mapping and schema fingerprint are mandatory. Original rows are never
deleted. Delivery metadata is added to the same DB only after an online backup.
"""
import argparse
from contextlib import closing,contextmanager
from datetime import datetime,timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit,quote
from uuid import uuid4

CONTRACT='tacticlens.ingesta.v2'


def ident(name):
    if not isinstance(name,str) or not name or '\x00' in name:
        raise ValueError('Identificador SQLite inválido')
    return '"'+name.replace('"','""')+'"'


def read_env(path):
    result={}
    for line in Path(path).read_text().splitlines():
        match=re.fullmatch(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)',line.strip())
        if match:
            result[match[1]]=match[2].strip().strip('\"\'')
    return result


def schema_hash(conn,table):
    row=conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
    if not row:
        raise ValueError('No existe la tabla configurada')
    indexes=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? ORDER BY name",(table,)).fetchall()
    return hashlib.sha256(json.dumps([row[0],indexes],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def validate_mapping(conn,mapping):
    if set(mapping)-{'table','id_column','json_column','sent_column','sent_value','schema_sha256'}:
        raise ValueError('Opciones de mapeo no reconocidas')
    table=mapping['table']
    if table.startswith('tacticlens_'):
        raise ValueError('Seleccione la cola original, no las tablas técnicas')
    if schema_hash(conn,table)!=mapping['schema_sha256']:
        raise ValueError('El esquema no coincide con el diagnóstico revisado')
    columns={r[1]:r for r in conn.execute('PRAGMA table_info('+ident(table)+')')}
    pk=mapping['id_column'];payload=mapping['json_column'];sent=mapping.get('sent_column')
    if pk==payload or pk not in columns or payload not in columns or (sent and (sent not in columns or sent in {pk,payload})):
        raise ValueError('Columnas de mapeo no válidas')
    primary=[r[1] for r in columns.values() if r[5]]
    if primary!=[pk]:
        raise ValueError('Se exige una clave primaria simple estable por ocurrencia; no un hash del contenido')
    if conn.execute('SELECT 1 FROM '+ident(table)+' WHERE '+ident(pk)+' IS NULL LIMIT 1').fetchone():
        raise ValueError('La clave primaria contiene nulos')


def connect(path):
    conn=sqlite3.connect('file:'+quote(str(Path(path).resolve()),safe='/')+'?mode=rw',uri=True,timeout=30,isolation_level=None)
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA synchronous=FULL')
    return conn


def prepare_queue(path,mapping,backup_dir):
    """SQLite backup includes committed WAL data; do not copy the .db alone."""
    folder=Path(backup_dir);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    dest=folder/('cola-antes-envio-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex[:8]+'.sqlite3')
    # sqlite3.Connection.__exit__ commits/rolls back but does not close handles.
    # Preserve transaction semantics and release both files deterministically.
    with closing(connect(path)) as conn, conn:
        validate_mapping(conn,mapping)
        with closing(sqlite3.connect(dest)) as backup, backup:
            conn.backup(backup)
        os.chmod(dest,0o600)
        conn.executescript('''BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS tacticlens_envio_meta (clave TEXT PRIMARY KEY,valor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tacticlens_entregas (
 origen_pk TEXT PRIMARY KEY,contenido_sha256 TEXT NOT NULL,
 estado TEXT NOT NULL CHECK(estado IN ('pendiente','enviado','revision')),
 intentos INTEGER NOT NULL DEFAULT 0,proximo_intento REAL NOT NULL DEFAULT 0,
 error TEXT,evento_backend TEXT,confirmado_en TEXT);
COMMIT;''')
        conn.execute("INSERT OR IGNORE INTO tacticlens_envio_meta VALUES('queue_uuid',?)",(str(uuid4()),))
        conn.execute("INSERT OR IGNORE INTO tacticlens_envio_meta VALUES('source_table',?)",(mapping['table'],))
        if conn.execute("SELECT valor FROM tacticlens_envio_meta WHERE clave='source_table'").fetchone()[0]!=mapping['table']:
            raise ValueError('Esta base ya tiene otro mapeo de cola')
    return dest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def validate_endpoint(url,key,transport='ssh-loopback'):
    parsed=urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path!='/api/ingesta/eventos':
        raise ValueError('Destino de ingesta no válido')
    if transport=='demo-http':
        host=ipaddress.ip_address(parsed.hostname or '')
        private=host.version==4 and any(host in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        if parsed.scheme!='http' or parsed.port!=8000 or not private:
            raise ValueError('HTTP de demostración requiere una IPv4 privada y puerto 8000')
    elif transport=='ssh-loopback':
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.port!=18765:
            raise ValueError('HTTP directo requiere activar explícitamente demo-http')
    else:
        raise ValueError('Modalidad de transporte no reconocida')
    if not key or any(ord(c)<33 or ord(c)>126 for c in key):
        raise ValueError('Clave de ingesta no válida')


def post(url,key,events,transport='ssh-loopback'):
    validate_endpoint(url,key,transport)
    body=json.dumps({'eventos':events},allow_nan=False,separators=(',',':'),ensure_ascii=False).encode()
    if len(body)>2_000_000:
        raise ValueError('Lote demasiado grande; reduzca BATCH_SIZE')
    request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-API-Key':key},method='POST')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        response=opener.open(request,timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code!=422:
            raise RuntimeError('http_'+str(exc.code)) from None
        response=exc
    with response:
        raw=response.read(524289)
    if len(raw)>524288:
        raise RuntimeError('confirmacion_demasiado_grande')
    return json.loads(raw)


def validate_receipts(result,events):
    if not isinstance(result,dict) or result.get('contrato')!=CONTRACT or type(result.get('recibidos')) is not int or result.get('recibidos')!=len(events):
        raise ValueError('Respuesta sin contrato válido; no marcar enviados')
    receipts=result.get('confirmaciones')
    if not isinstance(receipts,list) or len(receipts)!=len(events):
        raise ValueError('Faltan confirmaciones individuales')
    counters={'insertado':0,'duplicado':0,'rechazado':0}
    for index,(receipt,event) in enumerate(zip(receipts,events)):
        if not isinstance(receipt,dict) or type(receipt.get('indice')) is not int or receipt.get('indice')!=index or receipt.get('source_id')!=event['_collector']['source_id'] or receipt.get('estado') not in counters:
            raise ValueError('Confirmación no corresponde al lote')
        if receipt['estado']!='rechazado' and (type(receipt.get('id_evento')) is not int or receipt['id_evento']<=0):
            raise ValueError('No se confirmó el identificador persistido')
        counters[receipt['estado']]+=1
    if any(type(result.get(key)) is not int or result.get(key)!=counters[state] for key,state in [('insertados','insertado'),('duplicados','duplicado'),('rechazados','rechazado')]):
        raise ValueError('Contadores de confirmación inconsistentes')
    return receipts


def deliver_pending(conn,mapping,url,key,batch_size=50,transport='ssh-loopback'):
    validate_mapping(conn,mapping)
    queue_uuid=conn.execute("SELECT valor FROM tacticlens_envio_meta WHERE clave='queue_uuid'").fetchone()[0]
    if conn.execute("SELECT valor FROM tacticlens_envio_meta WHERE clave='source_table'").fetchone()[0]!=mapping['table']:
        raise ValueError('Mapeo de cola diferente')
    query=('SELECT CAST(q.'+ident(mapping['id_column'])+' AS TEXT),q.'+ident(mapping['json_column'])
        +' FROM '+ident(mapping['table'])+' q LEFT JOIN tacticlens_entregas d ON d.origen_pk=CAST(q.'+ident(mapping['id_column'])+' AS TEXT)'
        +" WHERE d.estado IS NULL OR (d.estado='pendiente' AND d.proximo_intento<=?) ORDER BY q."+ident(mapping['id_column'])+' LIMIT ?')
    rows=conn.execute(query,(time.time(),batch_size)).fetchall()
    events=[];identities=[];size_used=16
    conn.execute('BEGIN IMMEDIATE')
    try:
        for pk,payload in rows:
            try:
                digest=hashlib.sha256(payload if isinstance(payload,bytes) else payload.encode()).hexdigest()
                previous=conn.execute('SELECT contenido_sha256 FROM tacticlens_entregas WHERE origen_pk=?',(pk,)).fetchone()
                if previous and previous[0]!=digest:
                    raise ValueError('fila_modificada')
                event=json.loads(payload)
                if not isinstance(event,dict):
                    raise ValueError('json_no_objeto')
                if len(json.dumps(event,allow_nan=False,ensure_ascii=False,separators=(',',':')).encode())>131072:
                    raise ValueError('evento_demasiado_grande')
                source='sqlite:'+queue_uuid+':'+quote(pk,safe='')
                if len(source)>512:
                    raise ValueError('identidad_demasiado_larga')
                event['_collector']={'source_id':source}
                # Validate finite JSON before constructing the network batch.
                event_size=len(json.dumps(event,allow_nan=False,ensure_ascii=False,separators=(',',':')).encode())+1
                if size_used+event_size>1_900_000:
                    break
                size_used+=event_size
                conn.execute("INSERT OR IGNORE INTO tacticlens_entregas(origen_pk,contenido_sha256,estado) VALUES(?,?,'pendiente')",(pk,digest))
                events.append(event);identities.append(pk)
            except (ValueError,TypeError,UnicodeError,AttributeError):
                conn.execute("INSERT INTO tacticlens_entregas(origen_pk,contenido_sha256,estado,error) VALUES(?,?,'revision','formato_o_fila_modificada') ON CONFLICT(origen_pk) DO UPDATE SET estado='revision',error=excluded.error",(pk,'invalido'))
        conn.commit()
    except Exception:
        conn.rollback();raise
    if not events:
        return 0
    try:
        result=post(url,key,events,transport=transport) if transport!='ssh-loopback' else post(url,key,events)
        receipts=validate_receipts(result,events)
    except (OSError,ValueError,RuntimeError,TimeoutError) as exc:
        error=str(exc) if re.fullmatch(r'http_[1-5][0-9][0-9]',str(exc)) else 'transporte_o_confirmacion'
        conn.execute('BEGIN IMMEDIATE')
        try:
            for pk in identities:
                attempts=conn.execute('SELECT intentos FROM tacticlens_entregas WHERE origen_pk=?',(pk,)).fetchone()[0]+1
                conn.execute("UPDATE tacticlens_entregas SET intentos=?,proximo_intento=?,error=? WHERE origen_pk=?",
                    (attempts,time.time()+min(300,5*2**min(attempts,6)),error,pk))
            conn.commit()
        except Exception:
            conn.rollback();raise
        print('Entrega pendiente; detalle seguro:',type(exc).__name__)
        return 0
    conn.execute('BEGIN IMMEDIATE')
    try:
        for pk,receipt in zip(identities,receipts):
            accepted=receipt['estado']!='rechazado'
            conn.execute('UPDATE tacticlens_entregas SET estado=?,intentos=intentos+1,error=?,evento_backend=?,confirmado_en=? WHERE origen_pk=?',
                ('enviado' if accepted else 'revision',None if accepted else 'rechazado_por_api',str(receipt.get('id_evento') or ''),datetime.now(timezone.utc).isoformat() if accepted else None,pk))
            if accepted and mapping.get('sent_column'):
                conn.execute('UPDATE '+ident(mapping['table'])+' SET '+ident(mapping['sent_column'])+'=? WHERE CAST('+ident(mapping['id_column'])+' AS TEXT)=?',(mapping['sent_value'],pk))
        conn.commit()
    except Exception:
        conn.rollback();raise
    return len(events)


def status(conn,mapping):
    total=conn.execute('SELECT count(*) FROM '+ident(mapping['table'])).fetchone()[0]
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_entregas'").fetchone():
        return {'total_cola':total,'integracion':'sin_preparar'}
    counts=dict(conn.execute('SELECT estado,count(*) FROM tacticlens_entregas GROUP BY estado'))
    return {'total_cola':total,'enviados':counts.get('enviado',0),'revision':counts.get('revision',0),
            'pendientes':total-counts.get('enviado',0)-counts.get('revision',0)}


@contextmanager
def sender_lock(path):
    import fcntl
    with Path(str(path)+'.tacticlens-sender.lock').open('a+') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield



if __name__=='__main__':
    raise SystemExit('Modulo de entrega: utilice el exportar_eventos.py existente ya adaptado.')
