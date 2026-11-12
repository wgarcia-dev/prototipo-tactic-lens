#!/usr/bin/env python3
"""Adaptation of the inspected Ubuntu exporter 36f42dc347ef33d4899536ce2bba7a17bd8f0268fc023b8fe0142d9ea7c17003.

Retains events(id,payload,created_at), cursor and TACTICLENS_* configuration.
Capture commits occurrence + cursor atomically; delivery never deletes rows.
"""
import argparse
from contextlib import closing
from datetime import datetime,timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4
try:
    from . import sqlite_sender as delivery
except ImportError:
    import sqlite_sender as delivery

LOG=Path('/home/cowrie/honeypot/var/log/cowrie/cowrie.json')
DB=Path('/var/lib/tacticlens-cowrie/cola.sqlite3')
ENV=Path('/etc/tacticlens-cowrie/exportador.env')


def mapping(conn):
    columns={r[1]:r for r in conn.execute('PRAGMA table_info(events)')}
    if set(columns)!={'id','payload','created_at'} or not columns['id'][5]:
        raise ValueError('El esquema real de events cambió; no modificar automáticamente')
    return {'table':'events','id_column':'id','json_column':'payload','sent_column':None,'sent_value':None,
            'schema_sha256':delivery.schema_hash(conn,'events')}


def capture_init(conn):
    conn.executescript('''BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS tacticlens_archivos (
 generacion TEXT PRIMARY KEY,inode TEXT NOT NULL,archivo TEXT NOT NULL,offset INTEGER NOT NULL,
 prefijo TEXT NOT NULL,prefijo_bytes INTEGER NOT NULL,confirmado_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tacticlens_captura_origen (
 origen TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE REFERENCES events(id));
CREATE TABLE IF NOT EXISTS tacticlens_legacy (event_id TEXT PRIMARY KEY REFERENCES events(id));
CREATE TABLE IF NOT EXISTS tacticlens_captura_revision (
 origen TEXT PRIMARY KEY,generacion TEXT NOT NULL,offset INTEGER NOT NULL,
 raw BLOB NOT NULL,error TEXT NOT NULL,creado_en TEXT NOT NULL);
COMMIT;''')
    # Freeze the pre-migration set once; new occurrences never become legacy aliases.
    conn.execute('BEGIN IMMEDIATE')
    try:
        if not conn.execute("SELECT 1 FROM tacticlens_envio_meta WHERE clave='captura_v2'").fetchone():
            conn.execute('INSERT OR IGNORE INTO tacticlens_legacy SELECT id FROM events')
            conn.execute("INSERT INTO tacticlens_envio_meta VALUES('captura_v2','1')")
        conn.commit()
    except Exception:
        conn.rollback();raise


def prepare(path,backup_dir):
    with closing(delivery.connect(path)) as conn:
        config=mapping(conn)
    backup=delivery.prepare_queue(path,config,backup_dir)
    with closing(delivery.connect(path)) as conn:
        capture_init(conn)
    return backup


def candidates(log):
    paths=[p for p in log.parent.glob(log.name+'*') if p.is_file() and
           (p.name==log.name or p.name.startswith(log.name+'.') or p.name.startswith(log.name+'-'))]
    return sorted(paths,key=lambda p:(p.stat().st_mtime_ns,p.name))


def open_log(path):
    return gzip.open(path,'rb') if path.suffix=='.gz' else path.open('rb')


def prefix_digest(stream,length):
    stream.seek(0);digest=hashlib.sha256()
    while length:
        chunk=stream.read(min(length,1048576))
        if not chunk:
            raise ValueError('archivo_truncado_durante_lectura')
        digest.update(chunk);length-=len(chunk)
    return digest


def file_state(conn,path,stream,live_inodes):
    info=path.stat();inode=f'{info.st_dev}:{info.st_ino}'
    stream.seek(0);prefix=stream.read(256)
    stream.seek(0,os.SEEK_END);size=stream.tell()
    selection='SELECT generacion,inode,archivo,offset,prefijo,prefijo_bytes,confirmado_sha256 FROM tacticlens_archivos'
    row=conn.execute(selection+' WHERE inode=? ORDER BY rowid DESC LIMIT 1',(inode,)).fetchone()
    if row is None and path.suffix=='.gz':
        row=conn.execute(selection+' WHERE archivo=? ORDER BY rowid DESC LIMIT 1',(str(path.with_suffix('')),)).fetchone()
        if row is None:
            # Compression may happen between polls, removing the inode before its
            # renamed path was observed. Match the FULL committed byte prefix.
            matches=[r for r in conn.execute(selection).fetchall() if r[1] not in live_inodes and 0<r[3]<=size
                and hashlib.sha256(prefix[:r[5]]).hexdigest()==r[4] and prefix_digest(stream,r[3]).hexdigest()==r[6]]
            row=matches[0] if len(matches)==1 else None
    if row and (row[3]>size or hashlib.sha256(prefix[:row[5]]).hexdigest()!=row[4]):
        row=None  # Observable truncation or inode reuse: a new occurrence generation.
    generation,offset=(row[0],row[3]) if row else (str(uuid4()),0)
    conn.execute('INSERT INTO tacticlens_archivos VALUES(?,?,?,?,?,?,?) ON CONFLICT(generacion) DO UPDATE SET inode=excluded.inode,archivo=excluded.archivo,prefijo=excluded.prefijo,prefijo_bytes=excluded.prefijo_bytes',
        (generation,inode,str(path),offset,hashlib.sha256(prefix).hexdigest(),len(prefix),row[6] if row else hashlib.sha256().hexdigest()))
    stream.seek(offset)
    return generation,inode


def ingest(conn,log=LOG,max_pending=50000):
    config=mapping(conn)
    pending=delivery.status(conn,config)['pendientes']
    new=revision=0
    paths=candidates(log)
    live_inodes={f'{p.stat().st_dev}:{p.stat().st_ino}' for p in paths}
    for path in paths:
        with open_log(path) as stream:
            generation,inode=file_state(conn,path,stream,live_inodes)
            digest=prefix_digest(stream,stream.tell())
            while pending<max_pending:
                start=stream.tell();raw=stream.readline()
                if not raw or not raw.endswith(b'\n'):
                    break
                digest.update(raw)
                origin=generation+':'+str(start)+':'+hashlib.sha256(raw).hexdigest()
                try:
                    obj=json.loads(raw)
                    if not isinstance(obj,dict):
                        raise ValueError('objeto_requerido')
                    payload=json.dumps(obj,ensure_ascii=False,separators=(',',':'),allow_nan=False)
                    old_id=hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
                except (ValueError,UnicodeError):
                    obj=None
                conn.execute('BEGIN IMMEDIATE')
                try:
                    if obj is None:
                        conn.execute("INSERT OR IGNORE INTO tacticlens_captura_revision VALUES(?,?,?,?,?,?)",(origin,generation,start,raw,'json_invalido',datetime.now(timezone.utc).isoformat()))
                        revision+=1
                    elif not conn.execute('SELECT 1 FROM tacticlens_captura_origen WHERE origen=?',(origin,)).fetchone():
                        legacy=conn.execute('SELECT 1 FROM tacticlens_legacy l WHERE event_id=? AND NOT EXISTS(SELECT 1 FROM tacticlens_captura_origen o WHERE o.event_id=l.event_id)',(old_id,)).fetchone()
                        event_id=old_id if legacy else 'occ:'+hashlib.sha256(origin.encode()).hexdigest()
                        if not legacy:
                            conn.execute('INSERT INTO events(id,payload,created_at) VALUES(?,?,?)',(event_id,payload,datetime.now(timezone.utc).isoformat()))
                            new+=1;pending+=1
                        conn.execute('INSERT INTO tacticlens_captura_origen VALUES(?,?)',(origin,event_id))
                    conn.execute('UPDATE tacticlens_archivos SET offset=?,confirmado_sha256=? WHERE generacion=?',(stream.tell(),digest.hexdigest(),generation))
                    if path==log:
                        conn.execute("INSERT INTO cursor(name,inode,offset) VALUES('cowrie_json',?,?) ON CONFLICT(name) DO UPDATE SET inode=excluded.inode,offset=excluded.offset",(inode,stream.tell()))
                    conn.commit()
                except Exception:
                    conn.rollback();raise
    return {'nuevos':new,'revision_captura':revision,'limite_pendientes':pending>=max_pending}


def full_status(conn):
    result=delivery.status(conn,mapping(conn))
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_entregas'").fetchone():
        result['errores_envio']=dict(conn.execute("SELECT error,count(*) FROM tacticlens_entregas WHERE error IS NOT NULL GROUP BY error"))
        retry=conn.execute("SELECT min(proximo_intento) FROM tacticlens_entregas WHERE estado='pendiente'").fetchone()[0]
        result['reintento_desde']=datetime.fromtimestamp(retry,timezone.utc).isoformat() if retry else None
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_captura_revision'").fetchone():
        result['revision_captura']=conn.execute('SELECT count(*) FROM tacticlens_captura_revision').fetchone()[0]
    return result


def heartbeat(url,key):
    delivery.validate_endpoint(url,key)
    request=delivery.urllib.request.Request(url.rsplit('/',1)[0]+'/heartbeat',data=b'{}',method='POST',headers={'Content-Type':'application/json','X-API-Key':key})
    opener=delivery.urllib.request.build_opener(delivery.urllib.request.ProxyHandler({}),delivery.NoRedirect())
    with opener.open(request,timeout=5) as response:
        return response.status==200


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status',action='store_true');parser.add_argument('--prepare',action='store_true')
    parser.add_argument('--capture-only',action='store_true')
    parser.add_argument('--retry-now',action='store_true',help='Reintento manual supervisado, sin esperar el backoff')
    args=parser.parse_args()
    config={**(delivery.read_env(ENV) if ENV.exists() else {}),**os.environ}
    if args.prepare:
        print('Respaldo privado SQLite:',prepare(DB,DB.parent/'backups'))
        return
    with delivery.sender_lock(DB),closing(delivery.connect(DB)) as conn:
        if args.status:
            print(json.dumps(full_status(conn)))
            return
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_captura_origen'").fetchone():
            raise ValueError('Ejecute --prepare antes de cambiar la captura')
        if args.retry_now:
            conn.execute("UPDATE tacticlens_entregas SET proximo_intento=0 WHERE estado='pendiente'")
        url=config.get('TACTICLENS_URL','').strip();key=config.get('TACTICLENS_TOKEN','').strip()
        result=ingest(conn,max_pending=int(config.get('TACTICLENS_MAX_PENDING','50000')))
        if url and not args.capture_only:
            size=max(1,min(200,int(config.get('TACTICLENS_BATCH_SIZE','50'))))
            delivery.deliver_pending(conn,mapping(conn),url,key,size)
            try:
                heartbeat(url,key)
            except (OSError,ValueError,RuntimeError):
                pass
        print(json.dumps({**result,**full_status(conn)}))


if __name__=='__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as exc:
        raise SystemExit('Exportador detenido sin borrar pendientes: '+type(exc).__name__+'; revise el estado tecnico') from None
