"""Harmless Cowrie command and SQL latency measurement; never administrative SSH.

Uses Git for Windows' existing SSH client and a throwaway simulated password on
TCP/2222 only. The dashboard can be observed separately after --armar is ready.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine
from backend.ingest_transport import private_ipv4


def main(host, armed):
    load_dotenv()
    with socket.create_connection((host,2222),timeout=4):pass
    folder=Path('.local/monitoreo').resolve();folder.mkdir(parents=True,exist_ok=True)
    nonce=uuid4().hex[:12];marker='TacticLensLive_'+nonce
    password='TacticLensSimulado_'+uuid4().hex
    askpass=folder/('askpass-'+nonce+'.sh')
    askpass.write_text("#!/bin/sh\nprintf '%s\\n' '"+password+"'\n",encoding='utf-8',newline='\n')
    os.chmod(askpass,0o700)
    ssh=Path('C:/Program Files/Git/usr/bin/ssh.exe')
    if not ssh.exists():raise RuntimeError('Falta el cliente SSH existente de Git para la prueba')
    env={**os.environ,'SSH_ASKPASS':askpass.as_posix(),'SSH_ASKPASS_REQUIRE':'force','DISPLAY':'tacticlens-demo'}
    args=[str(ssh),'-T','-p','2222','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
        '-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=accept-new',
        '-o','UserKnownHostsFile='+str(folder/'known_hosts_cowrie'),'-o','LogLevel=ERROR','root@'+host]
    client=None;engine=database_engine();output=bytearray();lock=threading.Lock()
    result={'marker':marker,'comando':'echo '+marker,'ubuntu':host,'estado':'conectando'}
    record=folder/(marker+'.json');trigger=folder/(marker+'.go')
    def save():
        record.write_text(json.dumps(result,ensure_ascii=False,default=str),encoding='utf-8')
        (folder/'actual.json').write_text(json.dumps({'archivo':str(record),'disparo':str(trigger)}),encoding='utf-8')
    def lookup(command):
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            return conn.execute(text("""SELECT e.id_evento,e.id_sesion,e.ingresado_en,o.origen_id
                FROM honeypot.evento e JOIN honeypot.evento_origen o USING(id_evento)
                WHERE e.tipo_evento='cowrie.command.input' AND e.datos_originales->>'input'=:value
                ORDER BY e.id_evento LIMIT 1"""),{'value':command}).mappings().first()
    try:
        client=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        def read_output():
            while True:
                chunk=os.read(client.stdout.fileno(),4096)
                if not chunk:break
                with lock:output.extend(chunk)
        threading.Thread(target=read_output,daemon=True).start()
        warmup='echo TacticLensReady_'+nonce
        client.stdin.write((warmup+'\n').encode());client.stdin.flush()
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            if client.poll() is not None:raise RuntimeError('La conexion simulada termino antes de ejecutar el comando')
            with lock:ready=('TacticLensReady_'+nonce).encode() in output
            row=lookup(warmup) if ready else None
            if row:break
            time.sleep(0.2)
        else:raise RuntimeError('No se confirmo el comando preparatorio; revise autenticacion simulada/cola/timer')
        result.update(estado='lista',sesion=str(row['id_sesion']),evento_preparacion=row['id_evento'])
        save();print(json.dumps(result),flush=True)
        if armed:
            deadline=time.monotonic()+180
            while not trigger.exists():
                if time.monotonic()>deadline:raise RuntimeError('No se recibio el disparo de medicion')
                time.sleep(0.1)
        sent=time.time();started=time.monotonic()
        result.update(estado='enviada',enviado_utc=datetime.fromtimestamp(sent,timezone.utc).isoformat(),enviado_ms=sent*1000)
        client.stdin.write((result['comando']+'\n').encode());client.stdin.flush();save()
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            row=lookup(result['comando'])
            if row:
                result.update(estado='persistida',id_evento=row['id_evento'],id_sesion=str(row['id_sesion']),
                    origen=row['origen_id'],ingresado_utc=row['ingresado_en'].isoformat(),
                    latencia_persistencia_ms=round((row['ingresado_en'].timestamp()-sent)*1000,1),
                    detectado_sql_ms=round((time.monotonic()-started)*1000,1))
                save();print(json.dumps(result),flush=True);break
            time.sleep(0.1)
        else:raise RuntimeError('El comando todavia no tiene recibo persistido; no se declara una latencia exitosa')
    except Exception as exc:
        result.update(estado='incompleta',error=type(exc).__name__);save()
        raise
    finally:
        if client is not None:
            try:client.stdin.write(b'exit\n');client.stdin.flush();client.wait(timeout=4)
            except (OSError,subprocess.TimeoutExpired):client.kill();client.wait()
        askpass.unlink(missing_ok=True);engine.dispose()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ubuntu',type=private_ipv4,default='192.168.0.100')
    parser.add_argument('--armar',action='store_true')
    args=parser.parse_args()
    try:main(args.ubuntu,args.armar)
    except RuntimeError as exc:raise SystemExit(str(exc)) from None
    except Exception as exc:raise SystemExit('Medicion incompleta: '+type(exc).__name__) from None
