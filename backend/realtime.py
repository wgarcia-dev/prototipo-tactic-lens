"""Bounded invalidation stream. Database receipts remain the source of truth."""
import asyncio
from datetime import datetime, timezone
import json
import logging
from threading import Event, Thread
from uuid import uuid4

from anyio import CancelScope
from fastapi import Request, WebSocket, WebSocketDisconnect
import psycopg
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from .auth.store import AuthError, rate, session, transaction

PROTOCOL = 'tacticlens.monitor.v1'
HEARTBEAT_SECONDS = 15
CLIENT_IDLE_SECONDS = 40
CHANNEL = 'tacticlens_monitor_v1'
DOMAINS = ('sesiones', 'analisis', 'iocs', 'mitre', 'salvaguardas', 'incidentes', 'panel')
logger = logging.getLogger(__name__)


def notify_change(conn, sensors, *domains, events=(), received_at=None):
    """Register a small invalidation on the write transaction itself."""
    payload = {'sensores': sorted({str(sensor) for sensor in sensors}), 'dominios': sorted(set(domains)),
               'eventos': [event for event in events[:100] if type(event) is int],
               'recibido_api': received_at}
    conn.execute(text('SELECT pg_notify(:channel, :payload)'),
                 {'channel': CHANNEL, 'payload': json.dumps(payload, separators=(',', ':'))})


class PostgresMonitor:
    """One LISTEN connection per API worker, including Windows event loops."""
    def __init__(self, engine, hub, sensors, cache):
        self.hub, self.cache = hub, cache
        self.sensors = {str(sensor) for sensor in sensors}
        self.connection = engine.url.translate_connect_args(username='user', database='dbname')
        self.stop, self.ready = Event(), Event()
        self.thread = Thread(target=self.listen, name='tacticlens-listen', daemon=True)

    def listen(self):
        resync = False
        while not self.stop.is_set():
            try:
                with psycopg.connect(**self.connection, autocommit=True, connect_timeout=3) as conn:
                    conn.execute('LISTEN ' + CHANNEL)
                    if resync:
                        self.dispatch({'dominios': list(DOMAINS)})
                    resync = True
                    self.ready.set()
                    while not self.stop.is_set():
                        for notification in conn.notifies(timeout=1):
                            if notice := self.parse(notification.payload):
                                self.dispatch(notice)
            except (psycopg.Error, OSError, RuntimeError):
                if not self.stop.is_set():
                    resync = True
                    logger.warning('Suscripción PostgreSQL de monitoreo interrumpida; se reintentará.')
                    self.stop.wait(1)

    def parse(self, payload):
        try:
            value = json.loads(payload)
            sensors, domains = value['sensores'], value['dominios']
            if not isinstance(sensors, list) or not isinstance(domains, list) or not self.sensors.intersection(sensors):
                return None
            domains = [domain for domain in DOMAINS if domain in domains]
            if "incidentes" in domains and not set(sensors) <= self.sensors:
                domains.remove("incidentes")
            if not domains:
                return None
            notice = {'dominios': domains}
            if 'sesiones' in domains:
                events = value.get('eventos') or []
                if isinstance(events, list):
                    notice['eventos'] = [item for item in events[:100] if type(item) is int and item > 0]
                received = value.get('recibido_api')
                if isinstance(received, str) and len(received) <= 40:
                    notice['recibido_api'] = datetime.fromisoformat(received).isoformat()
            return notice
        except (AttributeError, KeyError, TypeError, ValueError):
            return None

    def dispatch(self, notice):
        if 'panel' in notice['dominios']:
            self.cache.invalidate()
        self.hub.loop.call_soon_threadsafe(self.hub._broadcast,
            {'tipo': 'cambio', 'confirmado_api': datetime.now(timezone.utc).isoformat(), **notice})

    def close(self):
        self.stop.set()
        self.thread.join(timeout=4)


class MonitorHub:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.epoch = uuid4().hex
        self.revision = 0
        self.clients = {}

    def subscribe(self, user):
        if len(self.clients) >= 64 or sum(owner == user for owner, _ in self.clients.values()) >= 3:
            raise ValueError('limite_conexiones')
        queue = asyncio.Queue(maxsize=1)
        key = uuid4().hex
        self.clients[key] = (user, queue)
        return key, queue

    def unsubscribe(self, key):
        self.clients.pop(key, None)

    def _broadcast(self, notice):
        self.revision += 1
        notice = {**notice, 'revision': self.revision, 'epoca': self.epoch}
        for _, queue in tuple(self.clients.values()):
            # Coalesce invalidations, never durable events. Slow tabs resync SQL.
            if queue.full():
                previous = queue.get_nowait()
                merged = {**previous, **notice,
                          'dominios': sorted(set(previous.get('dominios', ())) | set(notice.get('dominios', ()))),
                          'eventos': list(dict.fromkeys(previous.get('eventos', []) + notice.get('eventos', [])))[-100:]}
                queue.put_nowait(merged)
            else:
                queue.put_nowait(notice)


def authorize_socket(ws, initial=False):
    scope = {**ws.scope, 'type': 'http', 'method': 'GET',
             'scheme': 'https' if ws.url.scheme == 'wss' else 'http'}
    request = Request(scope)
    with transaction(request) as conn:
        current, user = session(conn, request, {'completa'}, lock=False)
        if initial:
            rate(conn, request, 'monitor_ws', account=str(user.id_usuario), account_limit=40, ip_limit=120)
        return str(user.id_usuario)


async def monitor_socket(ws: WebSocket):
    settings = ws.app.state.auth_settings
    if (ws.query_params or ws.headers.get('origin') not in settings.origins
            or PROTOCOL not in ws.scope.get('subprotocols', [])
            or (settings.production and ws.url.scheme != 'wss')):
        await ws.close(code=1008)
        return
    key = None
    hub = ws.app.state.monitor_hub
    try:
        user = await run_in_threadpool(authorize_socket, ws, True)
        key, queue = hub.subscribe(user)
    except AuthError:
        await ws.close(code=4401)
        return
    except ValueError:
        await ws.close(code=1013)
        return
    try:
        await ws.accept(subprotocol=PROTOCOL)
        await asyncio.wait_for(ws.send_json({'tipo': 'listo', 'epoca': hub.epoch, 'revision': hub.revision}), 5)
        receive_task = asyncio.create_task(ws.receive_text())
        change_task = asyncio.create_task(queue.get())
        try:
            last_pong = hub.loop.time()
            next_check = last_pong + HEARTBEAT_SECONDS
            messages = 0
            while True:
                done, _ = await asyncio.wait({receive_task, change_task},
                    timeout=max(0, next_check - hub.loop.time()), return_when=asyncio.FIRST_COMPLETED)
                if receive_task in done:
                    value = receive_task.result()
                    messages += 1
                    if value != 'pong' or messages > 4:
                        await ws.close(code=1008)
                        break
                    last_pong = hub.loop.time()
                    receive_task = asyncio.create_task(ws.receive_text())
                if change_task in done or hub.loop.time() >= next_check:
                    # Never send a new notice to a suspended/revoked/incomplete account.
                    await run_in_threadpool(authorize_socket, ws)
                    if hub.loop.time() - last_pong > CLIENT_IDLE_SECONDS:
                        await ws.close(code=1001)
                        break
                    if change_task in done:
                        await asyncio.wait_for(ws.send_json(change_task.result()), 5)
                        change_task = asyncio.create_task(queue.get())
                    if hub.loop.time() >= next_check:
                        await asyncio.wait_for(ws.send_json({'tipo': 'ping'}), 5)
                        next_check = hub.loop.time() + HEARTBEAT_SECONDS
                        messages = 0
        finally:
            # Finish child-task cleanup even if ASGI cancels a disconnected
            # socket. Keep cancellation propagating after the bounded cleanup.
            with CancelScope(shield=True):
                for task in (receive_task, change_task):
                    task.cancel()
                await asyncio.gather(receive_task, change_task, return_exceptions=True)
    except AuthError:
        await ws.close(code=4401)
    except asyncio.TimeoutError:
        try:
            await ws.close(code=1013)
        except (RuntimeError, OSError):
            pass
    except (WebSocketDisconnect, OSError, RuntimeError):
        pass
    finally:
        if key:
            hub.unsubscribe(key)
