"""Bounded invalidation stream. Database receipts remain the source of truth."""
import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from anyio import CancelScope
from fastapi import Request, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from .auth.store import AuthError, rate, session, transaction

PROTOCOL = 'tacticlens.monitor.v1'
HEARTBEAT_SECONDS = 15
CLIENT_IDLE_SECONDS = 40


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

    def publish(self, result, received_at):
        # Called ONLY after persist() has committed. Thread-safe for sync routes.
        notice = {'tipo': 'cambio', 'recibido_api': received_at,
                  'confirmado_api': datetime.now(timezone.utc).isoformat(),
                  'eventos': [r['id_evento'] for r in result['confirmaciones'] if r['estado'] == 'insertado']}
        if notice['eventos']:
            self.loop.call_soon_threadsafe(self._broadcast, notice)

    def _broadcast(self, notice):
        self.revision += 1
        notice = {**notice, 'revision': self.revision, 'epoca': self.epoch}
        for _, queue in tuple(self.clients.values()):
            # Coalesce invalidations, never durable events. Slow tabs resync SQL.
            if queue.full():
                queue.get_nowait()
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
