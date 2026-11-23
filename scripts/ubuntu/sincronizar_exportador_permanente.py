#!/usr/bin/env python3
"""Change the receiver of the running Cowrie exporter without replacing its queue."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


CONFIG = Path('/etc/tacticlens-cowrie/exportador.env')
QUEUE = Path('/var/lib/tacticlens-cowrie/cola.sqlite3')
EXPORTER = Path('/opt/tacticlens-cowrie')
UNIT = 'tacticlens-exportador.service'
TIMER = 'tacticlens-exportador.timer'
COWRIE = 'cowrie-tacticlens.service'
EGRESS = 'tacticlens-egress-guard.service'
BACKUPS = Path('/var/backups')
CONTRACT = 'tacticlens.ingesta.v2'
PROBE = 'tacticlens-comprobacion-clave-sin-persistencia'
ASSIGNMENT = re.compile(rb'^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[^\r\n]*', re.M)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def authentication_probe(url, key):
    target = urlsplit(url)
    ip = ipaddress.ip_address(target.hostname or '')
    private = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    if (not any(ip in ipaddress.ip_network(net) for net in private)
            or url != f'http://{ip}:8000/api/ingesta/eventos'):
        raise RuntimeError('Se requiere la URL HTTP exacta de ingesta en IPv4 privada')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    # Empty session and event type fail before the backend can insert any row.
    body = json.dumps({'eventos': [{'session': '', 'eventid': '', '_collector': {'source_id': PROBE}}]}).encode()
    request = urllib.request.Request(url, body, {'Content-Type': 'application/json', 'X-API-Key': key})
    try:
        response = opener.open(request, timeout=8)
    except urllib.error.HTTPError as exc:
        response = exc
    except OSError:
        raise RuntimeError('No se alcanzo ingesta por TCP/HTTP. Revise red, firewall y proceso de Windows') from None
    with response:
        if response.status == 401:
            raise RuntimeError('HTTP 401: la clave de demostracion no fue aceptada')
        if response.status == 403:
            raise RuntimeError('HTTP 403: FastAPI rechazo la interfaz o la IP de origen')
        if response.status >= 500:
            raise RuntimeError(f'HTTP {response.status}: backend de ingesta no disponible')
        if response.status != 422:
            raise RuntimeError(f'HTTP {response.status}: la ruta de ingesta no cumple el contrato esperado')
        try:
            result = json.load(response)
        except ValueError:
            raise RuntimeError('HTTP 422 sin recibo de ingesta valido') from None
    expected = {'contrato': CONTRACT, 'recibidos': 1, 'insertados': 0, 'duplicados': 0, 'rechazados': 1}
    if (not isinstance(result, dict) or any(type(result.get(k)) is not type(v) or result[k] != v for k, v in expected.items())
            or result.get('confirmaciones') != [{'indice': 0, 'source_id': PROBE, 'estado': 'rechazado',
                                                  'error': 'evento_invalido_o_identidad_en_conflicto'}]):
        raise RuntimeError('HTTP 422 sin recibo compatible con tacticlens.ingesta.v2')
    return {'http': 422, **expected}


def update_config(content, url, key):
    updates = {b'TACTICLENS_URL': url.encode(), b'TACTICLENS_TOKEN': key.encode(),
               b'TACTICLENS_TRANSPORT': b'demo-http'}
    found = set()

    def replace(match):
        name = match[1]
        if name not in updates:
            return match[0]
        if name in found:
            raise RuntimeError('Configuracion ambigua: variable de ingesta duplicada')
        found.add(name)
        return name + b'=' + updates[name]

    result = ASSIGNMENT.sub(replace, content)
    newline = b'\r\n' if b'\r\n' in content else b'\n'
    for name, value in updates.items():
        if name not in found:
            result += (b'' if not result or result.endswith(b'\n') else newline) + name + b'=' + value + newline
    return result


def atomic_config(content, metadata):
    fd, name = tempfile.mkstemp(prefix='.exportador-', dir=CONFIG.parent)
    with closing(os.fdopen(fd, 'wb')) as stream:
        try:
            stream.write(content)
            stream.flush()
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fsync(stream.fileno())
            os.replace(name, CONFIG)
        finally:
            Path(name).unlink(missing_ok=True)


def system(*args):
    return subprocess.check_output(['systemctl', *args], text=True, stderr=subprocess.DEVNULL, timeout=120).strip()


def property_of(unit, field):
    return system('show', unit, '-p', field, '--value')


def verify_installed_exporter():
    # Check the installed interfaces without importing or replacing Ubuntu code.
    expected = {
        'event_watch.py': ('read_env', 'TACTICLENS_URL', 'TACTICLENS_TOKEN', 'TACTICLENS_TRANSPORT',
                           'deliver_pending', 'proximo_intento', 'SIGTERM', 'inotify'),
        'exportar_eventos.py': (str(CONFIG), str(QUEUE), 'tacticlens_captura_origen'),
        'sqlite_sender.py': (CONTRACT, 'demo-http', 'X-API-Key', 'source_id', 'proximo_intento'),
    }
    for filename, required in expected.items():
        source = (EXPORTER / filename).read_text()
        missing = [name for name in required if name not in source]
        if missing:
            raise RuntimeError(f'Contrato de instalacion distinto en {filename}: {", ".join(missing)}')


def preflight():
    if (property_of(UNIT, 'Type') != 'simple' or property_of(UNIT, 'SubState') != 'running'
            or property_of(TIMER, 'ActiveState') != 'inactive'
            or any(property_of(unit, 'ActiveState') != 'active' for unit in (COWRIE, EGRESS))):
        raise RuntimeError('La unidad permanente o sus dependencias no tienen el estado comprobado')
    if any(property_of(unit, 'ActiveState') in {'active', 'activating'}
           for unit in ('cowrie-ingest.service', 'tacticlens-eventos.service')):
        raise RuntimeError('Hay otro exportador que debe revisarse antes de cambiar el destino')
    pid = int(property_of(UNIT, 'MainPID'))
    if not pid or b'event_watch' not in (Path('/proc') / str(pid) / 'cmdline').read_bytes():
        raise RuntimeError('El PID de systemd no corresponde al vigilante continuo esperado')
    verify_installed_exporter()
    metadata = CONFIG.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or mode not in (0o600, 0o640):
        raise RuntimeError('Permisos o tipo del archivo privado incompatibles')
    return metadata


def open_queue(path):
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=15)


def counters(conn):
    total = conn.execute('SELECT count(*) FROM events').fetchone()[0]
    deliveries = dict(conn.execute('SELECT estado,count(*) FROM tacticlens_entregas GROUP BY estado'))
    sent, review = (deliveries.get(state, 0) for state in ('enviado', 'revision'))
    last = conn.execute("SELECT max(confirmado_en) FROM tacticlens_entregas WHERE estado='enviado'").fetchone()[0]
    return {'total': total, 'enviados': sent, 'revision': review, 'pendientes': total - sent - review,
            'ultima_confirmacion': last}


def backup_queue(source, target):
    with closing(open_queue(source)) as live, closing(sqlite3.connect(target)) as copy:
        size = live.execute('PRAGMA page_count').fetchone()[0] * live.execute('PRAGMA page_size').fetchone()[0]
        if shutil.disk_usage(target.parent).free <= size:
            raise RuntimeError('Espacio insuficiente para una copia consistente de SQLite')
        live.backup(copy)
        if copy.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RuntimeError('La copia SQLite no paso integrity_check')
        if not copy.execute("SELECT 1 FROM tacticlens_envio_meta WHERE clave='queue_uuid'").fetchone():
            raise RuntimeError('No se encontro la identidad durable de la cola en el respaldo')
        return counters(copy)


def preserved_rows(source, snapshot):
    with closing(open_queue(source)) as live:
        live.execute('ATTACH DATABASE ? AS respaldo', (snapshot.as_uri() + '?mode=ro',))
        live.execute('BEGIN')
        missing = live.execute('''SELECT count(*) FROM respaldo.events old
            LEFT JOIN main.events current ON current.id=old.id
             AND current.payload=old.payload AND current.created_at=old.created_at
            WHERE current.id IS NULL''').fetchone()[0]
        same_uuid = live.execute('''SELECT (SELECT valor FROM main.tacticlens_envio_meta WHERE clave='queue_uuid') =
            (SELECT valor FROM respaldo.tacticlens_envio_meta WHERE clave='queue_uuid')''').fetchone()[0] == 1
        missing_origins = live.execute('''SELECT count(*) FROM respaldo.tacticlens_captura_origen old
            LEFT JOIN main.tacticlens_captura_origen current ON current.origen=old.origen
             AND current.event_id=old.event_id WHERE current.origen IS NULL''').fetchone()[0]
        return missing, same_uuid, missing_origins, counters(live)


def start_exporter():
    system('start', UNIT)
    for _ in range(10):
        if property_of(UNIT, 'SubState') == 'running' and int(property_of(UNIT, 'MainPID')):
            time.sleep(1)
            if property_of(UNIT, 'SubState') == 'running':
                return
        time.sleep(1)
    raise RuntimeError('El exportador permanente no volvio a active/running')


def transition(url, key):
    metadata = preflight()
    original = CONFIG.read_bytes()
    updated = update_config(original, url, key)
    auth = authentication_probe(url, key)
    print('TACTICLENS_AUTH=' + json.dumps(auth), flush=True)
    if updated == original:
        print('TACTICLENS_TRANSITION=' + json.dumps({'sin_cambios': True}), flush=True)
        return
    backup = Path(tempfile.mkdtemp(prefix='tacticlens-demo-http-', dir=BACKUPS))
    (backup / 'exportador.env').write_bytes(original)
    if (backup / 'exportador.env').read_bytes() != original:
        raise RuntimeError('El respaldo de la configuracion no coincide')
    saved_queue = backup / 'cola.sqlite3'
    initial = backup_queue(QUEUE, saved_queue)
    print('TACTICLENS_BACKUP=' + json.dumps({'directorio': str(backup), 'sqlite_integridad': 'ok', 'cola': initial}), flush=True)
    missing, same_uuid, missing_origins, _ = preserved_rows(QUEUE, saved_queue)
    if missing or missing_origins or not same_uuid:
        raise RuntimeError('La cola activa cambio de forma incompatible durante el respaldo')
    if CONFIG.read_bytes() != original:
        raise RuntimeError('La configuracion cambio durante el respaldo')
    try:
        system('stop', UNIT)
        if property_of(UNIT, 'ActiveState') != 'inactive':
            raise RuntimeError('No se confirmo la detencion del unico exportador')
        with closing(open_queue(QUEUE)) as live:
            live.execute('BEGIN')
            before = counters(live)
        atomic_config(updated, metadata)
        start_exporter()
    except (Exception, KeyboardInterrupt):
        try:
            if CONFIG.read_bytes() != original:
                system('stop', UNIT)
                atomic_config(original, metadata)
            start_exporter()
            print('TACTICLENS_ROLLBACK=configuracion anterior restaurada y exportador activo', flush=True)
        except (Exception, KeyboardInterrupt):
            raise RuntimeError('Recuperacion automatica incompleta. Revise el respaldo registrado y la unidad') from None
        raise
    missing, same_uuid, missing_origins, after = preserved_rows(QUEUE, saved_queue)
    result = {'cola_al_detener': before, 'cola_al_reiniciar': after, 'registros_originales_ausentes_o_modificados': missing,
              'origenes_ausentes_o_modificados': missing_origins, 'misma_identidad_cola': same_uuid, 'tipo': property_of(UNIT, 'Type'),
              'exportador': property_of(UNIT, 'SubState'), 'timer': property_of(TIMER, 'ActiveState'),
              'cowrie': property_of(COWRIE, 'ActiveState'), 'egress': property_of(EGRESS, 'ActiveState'),
              'fecha_utc': datetime.now(timezone.utc).isoformat()}
    print('TACTICLENS_TRANSITION=' + json.dumps(result), flush=True)
    if missing or missing_origins or not same_uuid:
        raise RuntimeError('La comprobacion de los registros originales requiere revision')


def main(path, url):
    import fcntl
    import pwd

    caller = pwd.getpwnam(os.environ['SUDO_USER'])
    folder = path.parent
    if (os.geteuid() != 0 or path.name != 'key' or folder.parent != Path(caller.pw_dir)
            or not re.fullmatch(r'\.tacticlens-key-[a-f0-9]{32}', folder.name)):
        raise RuntimeError('Entrada temporal privada incompatible')
    directory = os.open(folder, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        info = os.fstat(directory)
        if info.st_uid != caller.pw_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('Permisos incorrectos de la entrada privada')
        try:
            with os.fdopen(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory), 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != caller.pw_uid or stat.S_IMODE(info.st_mode) != 0o600:
                    raise RuntimeError('Permisos incorrectos de la clave temporal')
                key = stream.read(129)
            if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}', key):
                raise RuntimeError('La clave exclusiva de demostracion no tiene el formato esperado')
        finally:
            os.unlink(path.name, dir_fd=directory)
    finally:
        os.close(directory)
        try:
            folder.rmdir()
        except OSError:
            pass
    with open('/run/tacticlens-cambio-demo-http.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # An SSH disconnect must not interrupt the stop/change/start sequence.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        transition(url, key.decode('ascii'))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--url', required=True)
    args = parser.parse_args()
    try:
        main(args.key_file, args.url)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit('Transicion incompleta: ' + type(exc).__name__) from None
