#!/usr/bin/env python3
"""Back up and switch the SAME installed exporter service from timer to inotify."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def activate(url, expected_exporter, expected_sender):
    if os.geteuid() != 0:
        raise RuntimeError('Ejecute con sudo')
    root = Path('/opt/tacticlens-cowrie')
    kit = Path(__file__).parent
    helpers = [(kit/name,root/name) for name in ('event_status.py','event_watch.py')]+[(kit/name,root/'scripts'/name) for name in ('estado.sh','verificar.sh','sincronizar.sh','probar-reconexion.sh')]
    if not all(source.is_file() for source,_ in helpers):
        raise RuntimeError('Kit incompleto; no se cambia el servicio')
    for name, expected in [('exportar_eventos.py', expected_exporter), ('sqlite_sender.py', expected_sender)]:
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('El modulo instalado difiere del revisado: ' + name + '; no se cambia')
    sys.path.insert(0, str(root))
    import exportar_eventos as exporter
    config = exporter.ENV
    if config.is_symlink():
        raise RuntimeError('Configuracion enlazada; revise manualmente')
    values = exporter.delivery.read_env(config)
    exporter.delivery.validate_endpoint(url, values['TACTICLENS_TOKEN'], values.get('TACTICLENS_TRANSPORT'))
    if command('systemctl', 'show', 'tacticlens-exportador.service', '-p', 'Type', '--value') not in {'oneshot', 'simple'}:
        raise RuntimeError('Unidad no compatible')
    if subprocess.run(['systemctl','is-active','--quiet','cowrie-ingest.service']).returncode == 0:
        raise RuntimeError('Otro recolector activo; no se inicia un segundo emisor')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), exporter.delivery.NoRedirect())
    req = urllib.request.Request(url, data=b'{"eventos":[{}]}', headers={'Content-Type':'application/json', 'X-API-Key':values['TACTICLENS_TOKEN']})
    try:
        response = opener.open(req, timeout=8)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = json.load(response)
        if response.status != 422 or body.get('contrato') != exporter.delivery.CONTRACT:
            raise RuntimeError('URL o clave no aceptadas; no se cambia el servicio')
    content = config.read_text(encoding='utf-8')
    pattern = r'(?m)^(?:export\s+)?TACTICLENS_URL\s*=.*$'
    if len(re.findall(pattern, content)) != 1:
        raise RuntimeError('URL no univoca')
    updated = re.sub(pattern, lambda _: 'TACTICLENS_URL=' + url, content)
    backup = exporter.DB.parent/'backups'/('eventos-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True,mode=0o700)
    shutil.copy2(config, backup/'exportador.env')
    os.chmod(backup/'exportador.env', 0o600)
    unit = 'tacticlens-exportador.service'
    timer = 'tacticlens-exportador.timer'
    enabled = subprocess.run(['systemctl','is-enabled','--quiet',timer]).returncode == 0
    dropin = Path('/etc/systemd/system')/(unit+'.d')/'30-eventos.conf'
    original = dropin.read_bytes() if dropin.exists() else None
    if original is not None:
        (backup/'30-eventos.conf').write_bytes(original)
    helper_previous = {target:target.read_bytes() if target.exists() else None for _,target in helpers}
    for target,previous in helper_previous.items():
        if previous is not None:(backup/target.name).write_bytes(previous)
    (backup/'servicio.txt').write_text(command('systemctl','cat',unit), encoding='utf-8')
    with closing(sqlite3.connect('file:'+quote(str(exporter.DB.resolve()),safe='/')+'?mode=ro', uri=True)) as source, closing(sqlite3.connect(backup/'cola.sqlite3')) as target:
        source.backup(target)
    subprocess.run(['systemctl','disable','--now',timer], check=True)
    replaced = False
    kind = command('systemctl','show',unit,'-p','Type','--value')
    try:
        if kind == 'oneshot':
            for _ in range(45):
                if command('systemctl','show',unit,'-p','ActiveState','--value') not in {'active','activating','deactivating'}:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Envio en curso; no se interrumpe')
        else:
            replaced = True
            subprocess.run(['systemctl','stop',unit], check=True)
        replaced = True
        shutil.copy2(Path(__file__).with_name('event_watch.py'), root/'event_watch.py')
        os.chmod(root/'event_watch.py', 0o644)
        if updated != content:
            # Keep original ownership and permissions; write via atomic rename.
            temp = config.with_name(config.name+'.eventos.tmp')
            temp.write_text(updated, encoding='utf-8'); os.chmod(temp,0o600)
            os.chown(temp,config.stat().st_uid,config.stat().st_gid);os.replace(temp,config)
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text('[Service]\nType=simple\nRemainAfterExit=no\nExecStart=\nExecStart=/usr/bin/python3 /opt/tacticlens-cowrie/event_watch.py\nRestart=on-failure\nRestartSec=2\nTimeoutStopSec=30\n', encoding='utf-8')
        subprocess.run(['systemctl','daemon-reload'], check=True)
        subprocess.run(['systemctl','start',unit], check=True)
        time.sleep(3)
        if command('systemctl','show',unit,'-p','ActiveState','--value') != 'active':
            raise RuntimeError('Vigilancia no activa')
        for source,target in helpers:
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target);os.chmod(target,0o644 if target.suffix=='.py' else 0o755)
        # The old timer started the service at boot. Keep boot activation after
        # disabling it, even when the original oneshot had no [Install] section.
        subprocess.run(['systemctl','add-wants','multi-user.target',unit],check=True)
    except Exception:
        if replaced:subprocess.run(['systemctl','stop',unit], check=False)
        shutil.copy2(backup/'exportador.env', config)
        if original is None:
            dropin.unlink(missing_ok=True)
        else:
            dropin.write_bytes(original)
        for target,previous in helper_previous.items():
            if previous is None:target.unlink(missing_ok=True)
            else:target.write_bytes(previous)
        subprocess.run(['systemctl','daemon-reload'], check=False)
        if kind == 'simple' and replaced:
            subprocess.run(['systemctl','start',unit], check=False)
        elif enabled:
            subprocess.run(['systemctl','enable','--now',timer], check=False)
        raise
    print('Respaldo privado:', backup)
    print('MISMO servicio activo con inotify; timer deshabilitado. Un unico emisor, SQLite y clave conservadas.')
    print('URL HTTP:', url)
    with closing(exporter.delivery.connect(exporter.DB)) as conn:
        print(json.dumps(exporter.full_status(conn)))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--exporter-sha', required=True)
    parser.add_argument('--sender-sha', required=True)
    args = parser.parse_args()
    try:
        activate(args.url, args.exporter_sha, args.sender_sha)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit('Activacion incompleta: '+type(exc).__name__+'; revise conectividad/huellas/clave sin publicar secretos') from None
