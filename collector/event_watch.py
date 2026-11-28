#!/usr/bin/env python3
"""Linux inotify wakes the existing durable capture/HTTP sender; no log polling."""
from contextlib import closing
import ctypes
import os
from pathlib import Path
import select
import signal
import struct
import time

try:
    from . import exportar_eventos as exporter
except ImportError:
    import exportar_eventos as exporter


class LogWatch:
    def __init__(self, paths):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify_init1')
        self.names = {}
        try:
            for path in paths:
                descriptor = libc.inotify_add_watch(self.fd, os.fsencode(path.parent), 0x00000FCA)
                if descriptor < 0:
                    raise OSError(ctypes.get_errno(), 'inotify_add_watch')
                self.names.setdefault(descriptor, set()).add(os.fsencode(path.name))
        except BaseException:
            os.close(self.fd)
            raise

    def wait(self, timeout):
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        changed = False
        while True:
            try:
                chunk = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            offset = 0
            while offset < len(chunk):
                descriptor, mask, _, length = struct.unpack_from('iIII', chunk, offset)
                name = chunk[offset + 16:offset + 16 + length].split(b'\0')[0]
                offset += 16 + length
                if mask & (0x8000 | 0x400 | 0x800):
                    raise RuntimeError('Directorio vigilado movido o eliminado; systemd recuperara la vigilancia')
                # Overflow forces a full durable-cursor rescan. Rotation names included.
                changed |= bool(mask & 0x4000) or any(
                    name == base or name.startswith((base + b'.', base + b'-'))
                    for base in self.names.get(descriptor, ())
                )
        return changed

    def close(self):
        os.close(self.fd)


def run():
    config = exporter.delivery.read_env(exporter.ENV)
    url, key = config['TACTICLENS_URL'], config['TACTICLENS_TOKEN']
    transport = config.get('TACTICLENS_TRANSPORT', 'demo-http')
    exporter.delivery.validate_endpoint(url, key, transport)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sources = exporter.log_sources(config)
    extras = [Path(item.strip()) for item in config.get('TACTICLENS_EXTRA_LOGS', '').split(',') if item.strip()]
    logs = [*sources.values(), *extras]
    if len({path.resolve() for path in logs}) != len(logs):
        raise ValueError('Rutas de Cowrie duplicadas')
    max_pending = int(config.get('TACTICLENS_MAX_PENDING', '50000'))
    # Watch BEFORE the initial scan, eliminating the scan/subscribe race.
    with exporter.delivery.sender_lock(exporter.DB), closing(LogWatch(logs)) as watch, closing(exporter.delivery.connect(exporter.DB)) as conn:
        mapping = exporter.mapping(conn)
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_captura_origen'").fetchone():
            raise RuntimeError('La cola debe estar previamente preparada; no se migra automaticamente')
        exporter.register_sources(conn,sources)
        dirty, heartbeat_at = True, 0
        while not stopping:
            if dirty:
                result = exporter.ingest_sources(conn,sources,max_pending)
                dirty = result['limite_pendientes']
                for path in extras:
                    if dirty:
                        break
                    dirty = exporter.ingest(conn, log=path, max_pending=max_pending,
                                            update_legacy_cursor=False)['limite_pendientes']
            size = max(1, min(200, int(config.get('TACTICLENS_BATCH_SIZE', '50'))))
            # Drain backlog fairly; kernel changes remain queued while HTTP is running.
            sent = 0
            for _ in range(20):
                sent = exporter.delivery.deliver_pending(conn, mapping, url, key, size, transport=transport)
                if sent < size or stopping:
                    break
            if time.monotonic() >= heartbeat_at:
                try:
                    exporter.heartbeat(url, key, transport)
                except (OSError, ValueError, RuntimeError):
                    pass
                heartbeat_at = time.monotonic() + 15
            retry = conn.execute("SELECT min(proximo_intento) FROM tacticlens_entregas WHERE estado='pendiente'").fetchone()[0]
            timeout = max(0.1, heartbeat_at - time.monotonic())
            if retry is not None:
                timeout = min(timeout, max(0.1, retry - time.time()))
            if (dirty and sent > 0) or sent == size:
                timeout = 0.1
            dirty = watch.wait(timeout) or dirty


if __name__ == '__main__':
    os.umask(0o077)
    try:
        run()
    except Exception as exc:
        # No payloads, keys, captured passwords or exception strings in journald.
        raise SystemExit('Vigilancia detenida sin borrar pendientes: ' + type(exc).__name__) from None
