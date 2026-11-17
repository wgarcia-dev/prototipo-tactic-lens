#!/usr/bin/env python3
"""Set the existing oneshot timer to 2 s, preserving its sender and SQLite."""
import argparse
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

TIMER = 'tacticlens-exportador.timer'
SERVICE = 'tacticlens-exportador.service'
DROPIN = '''[Timer]
OnActiveSec=
OnBootSec=
OnStartupSec=
OnUnitActiveSec=
OnUnitInactiveSec=
OnCalendar=
OnActiveSec=1s
OnUnitInactiveSec=2s
AccuracySec=100ms
RandomizedDelaySec=0
Unit=tacticlens-exportador.service
'''


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def timer_state():
    return command('systemctl','show',TIMER,'-p','ActiveState','-p','TimersMonotonic',
                   '-p','AccuracyUSec','-p','RandomizedDelayUSec')


def atomic_write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False) as stream:
            temporary=Path(stream.name);stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,mode)
        if path.exists():os.chown(temporary,path.stat().st_uid,path.stat().st_gid)
        os.replace(temporary,path)
    finally:
        if temporary:temporary.unlink(missing_ok=True)


def configure(url):
    if os.geteuid()!=0:raise RuntimeError('Ejecute con sudo; no comparta credenciales')
    sys.path.insert(0,'/opt/tacticlens-cowrie')
    import sqlite_sender as sender
    config=Path('/etc/tacticlens-cowrie/exportador.env')
    if config.is_symlink():raise RuntimeError('Revise la ruta de configuracion')
    values=sender.read_env(config)
    if values.get('TACTICLENS_TRANSPORT')!='demo-http':raise RuntimeError('Conserve la modalidad HTTP local existente')
    sender.validate_endpoint(url,values.get('TACTICLENS_TOKEN',''),'demo-http')
    if command('systemctl','show',SERVICE,'-p','Type','--value')!='oneshot':
        raise RuntimeError('La unidad no es oneshot: no se modifica el temporizador')
    if command('systemctl','show',SERVICE,'-p','RemainAfterExit','--value')!='no':
        raise RuntimeError('RemainAfterExit debe estar desactivado')
    executable=command('systemctl','show',SERVICE,'-p','ExecStart','--value')
    if '/opt/tacticlens-cowrie/exportar_eventos.py' not in executable:
        raise RuntimeError('ExecStart no corresponde al exportador existente')
    lock_source=inspect.getsource(sender.sender_lock)
    if 'LOCK_EX' not in lock_source or 'flock' not in lock_source:
        raise RuntimeError('No se pudo confirmar el bloqueo exclusivo del emisor')
    if subprocess.run(['systemctl','is-active','--quiet','cowrie-ingest.service']).returncode==0:
        raise RuntimeError('Hay otro recolector activo; no se habilita envio simultaneo')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),sender.NoRedirect())
    request=urllib.request.Request(url,data=json.dumps({'eventos':[{'session':'','eventid':'',
        '_collector':{'source_id':'comprobacion-monitoreo-sin-persistencia'}}]}).encode(),
        headers={'Content-Type':'application/json','X-API-Key':values['TACTICLENS_TOKEN']})
    try:response=opener.open(request,timeout=8)
    except urllib.error.HTTPError as exc:response=exc
    with response:
        result=json.load(response)
        if response.status!=422 or result.get('contrato')!='tacticlens.ingesta.v2' or result.get('rechazados')!=1:
            raise RuntimeError('La API no acepto la clave existente; no se cambia configuracion')
    print('TEMPORIZADOR ANTES:\n'+timer_state(),flush=True)
    target=Path('/etc/systemd/system')/(TIMER+'.d')/'20-monitoreo-local.conf'
    content=config.read_text(encoding='utf-8')
    pattern=r'(?m)^(?:export\s+)?TACTICLENS_URL\s*=.*$'
    if len(re.findall(pattern,content))!=1:raise RuntimeError('Revise la variable TACTICLENS_URL existente')
    updated=re.sub(pattern,lambda _:'TACTICLENS_URL='+url,content)
    existing=target.read_text(encoding='utf-8') if target.exists() else None
    if existing!=DROPIN or content!=updated:
        backup=Path('/var/lib/tacticlens-cowrie/backups')/('monitoreo-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(parents=True,mode=0o700)
        shutil.copy2(config,backup/'exportador.env');os.chmod(backup/'exportador.env',0o600)
        if existing is not None:shutil.copy2(target,backup/'20-monitoreo-local.conf')
        subprocess.run(['systemctl','stop',TIMER],check=True)
        try:
            for _ in range(45):
                state=command('systemctl','show',SERVICE,'-p','ActiveState','--value')
                if state not in {'active','activating','deactivating'}:break
                time.sleep(1)
            else:raise RuntimeError('El emisor sigue ejecutandose; no se interrumpe su transaccion')
            if content!=updated:atomic_write(config,updated,0o600)
            atomic_write(target,DROPIN)
            subprocess.run(['systemctl','daemon-reload'],check=True)
            subprocess.run(['systemctl','start',TIMER],check=True)
        except Exception:
            atomic_write(config,content,0o600)
            if existing is None:target.unlink(missing_ok=True)
            else:atomic_write(target,existing)
            subprocess.run(['systemctl','daemon-reload'],check=False)
            subprocess.run(['systemctl','start',TIMER],check=False)
            raise
        print('Respaldo privado:',backup,flush=True)
    else:
        subprocess.run(['systemctl','start',TIMER],check=True)
        print('La configuracion solicitada ya existe; no se repite su escritura.',flush=True)
    print('TEMPORIZADOR DESPUES:\n'+timer_state(),flush=True)
    print('URL HTTP:',url,flush=True)
    print('El mismo servicio oneshot envia 2 s despues de terminar. SQLite, claves y reintentos conservados.',flush=True)


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    args=parser.parse_args()
    try:configure(args.url)
    except RuntimeError as exc:raise SystemExit(str(exc)) from None
    except Exception as exc:raise SystemExit('Ajuste incompleto: '+type(exc).__name__+'; no publique secretos') from None
