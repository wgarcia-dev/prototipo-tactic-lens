import asyncio
from contextlib import ExitStack
import unittest
from unittest.mock import patch

from starlette.websockets import WebSocketDisconnect

import test_auth as fixtures
from backend.api import app
from backend.realtime import MonitorHub, PROTOCOL, notify_change


class HubTests(unittest.IsolatedAsyncioTestCase):
    async def test_incident_notifications_stay_private_to_the_recipient(self):
        hub = MonitorHub()
        _, owner = hub.subscribe("authorized-user")
        _, other = hub.subscribe("another-user")
        hub._broadcast({"tipo": "cambio", "dominios": ["avisos_incidentes"], "destinatarios": ["authorized-user"]})
        self.assertTrue(other.empty())
        notice = owner.get_nowait()
        self.assertEqual(notice["dominios"], ["avisos_incidentes"])
        self.assertNotIn("destinatarios", notice)

    async def test_coalesces_slow_clients_and_releases_slots(self):
        hub = MonitorHub()
        key, queue = hub.subscribe('user')
        hub._broadcast({'tipo':'cambio','eventos':[1]})
        hub._broadcast({'tipo':'cambio','eventos':[2]})
        self.assertEqual(queue.qsize(),1)
        self.assertEqual((await queue.get())['revision'],2)
        hub.subscribe('user');hub.subscribe('user')
        with self.assertRaises(ValueError):hub.subscribe('user')
        hub.unsubscribe(key)
        self.assertEqual(len(hub.clients),2)


class RealtimeTests(fixtures.AuthFixture):
    def ws(self, path='/api/monitor/ws', origin='http://127.0.0.1:5173', protocol=PROTOCOL):
        return self.client.websocket_connect(path,headers={'origin':origin},subprotocols=[protocol])

    def denied(self, **kwargs):
        with self.assertRaises(WebSocketDisconnect):
            with self.ws(**kwargs):pass

    def test_denies_missing_session_pending_mfa_wrong_origin_protocol_and_query_secrets(self):
        self.denied()
        _, data, _ = self.account(96,approve=True)
        self.login(data,'configurar_mfa')
        self.denied()
        self.enroll(97)
        self.denied(origin='https://attacker.example')
        self.denied(protocol='other')
        self.denied(path='/api/monitor/ws?token=forbidden')

    def test_ingestion_queues_only_one_invalidation_on_its_transaction(self):
        self.enroll(98)
        with self.ws() as ws:
            self.assertEqual(ws.receive_json()['tipo'],'listo')
            raw={'session':'ws-fixture','eventid':'cowrie.command.input','timestamp':self.clock.isoformat(),
                 'input':'echo websocket','_collector':{'source_id':'ws-fixture:1'}}
            with patch('backend.realtime.notify_change', wraps=notify_change) as publish:
                response=self.client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key},json={'eventos':[raw]})
                self.assertEqual(response.status_code,200)
                duplicate=self.client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key},json={'eventos':[raw]})
                self.assertEqual(duplicate.json()['duplicados'],1)
                publish.assert_called_once()
                self.assertEqual(list(publish.call_args.kwargs['events']), [response.json()['confirmaciones'][0]['id_evento']])
                self.assertNotIn('input',str(publish.call_args.kwargs))
            self.assertEqual(len(app.state.monitor_hub.clients),1)
        self.assertEqual(len(app.state.monitor_hub.clients),0)

    def test_revalidates_revocation_before_sending_any_notice(self):
        self.enroll(99)
        with self.ws() as ws:
            ws.receive_json()
            self.post('/logout')
            app.state.monitor_hub.loop.call_soon_threadsafe(app.state.monitor_hub._broadcast,
                {'tipo':'cambio','dominios':['avisos_incidentes']})
            with self.assertRaises(WebSocketDisconnect) as caught:ws.receive_json()
            self.assertEqual(caught.exception.code,4401)

    def test_failed_transaction_never_publishes(self):
        with patch('backend.ingestion.persist',side_effect=RuntimeError('fixture')),patch('backend.realtime.notify_change') as publish:
            with self.assertRaises(RuntimeError):
                from backend.api import persist_events
                persist_events([{}])
            publish.assert_not_called()

    def test_lan_cannot_open_browser_socket_in_demo_mode(self):
        from starlette.testclient import TestClient
        with patch.dict('os.environ',{'INGEST_TRANSPORT':'demo-http','AUTH_ENV':'development','INGEST_DEMO_UBUNTU_IP':'192.168.0.103'}):
            client=TestClient(app,client=('192.168.0.103',43000))
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect('/api/monitor/ws',headers={'origin':'http://127.0.0.1:5173'},subprotocols=[PROTOCOL]):pass

    def test_connection_limit_and_cleanup(self):
        self.enroll(994)
        with ExitStack() as stack:
            sockets=[]
            for _ in range(3):
                ws=stack.enter_context(self.ws());ws.receive_json();sockets.append(ws)
            with self.assertRaises(WebSocketDisconnect):
                with self.ws():pass
            self.assertEqual(len(app.state.monitor_hub.clients),3)
            # Complete the close handshake before TestClient tears down several
            # concurrent contexts. Abrupt portal cancellation races cleanup.
            for ws in sockets:
                ws.send_text('invalid-close-test')
                with self.assertRaises(WebSocketDisconnect):ws.receive_json()
            async def wait_cleanup():
                while app.state.monitor_hub.clients:
                    await asyncio.sleep(0.001)
            self.client.portal.call(lambda:asyncio.wait_for(wait_cleanup(),1))
        self.assertEqual(len(app.state.monitor_hub.clients),0)

    def test_heartbeat_pong_and_invalid_frames(self):
        self.enroll(993)
        with patch('backend.realtime.HEARTBEAT_SECONDS',0.03):
            with self.ws() as ws:
                ws.receive_json()
                self.assertEqual(ws.receive_json()['tipo'],'ping')
                ws.send_text('pong')
                self.assertEqual(ws.receive_json()['tipo'],'ping')
                ws.send_text('not-a-pong')
                with self.assertRaises(WebSocketDisconnect) as caught:ws.receive_json()
                self.assertEqual(caught.exception.code,1008)

    def test_idle_client_without_pong_is_closed(self):
        self.enroll(992)
        with patch('backend.realtime.HEARTBEAT_SECONDS',0.02),patch('backend.realtime.CLIENT_IDLE_SECONDS',0.09):
            with self.ws() as ws:
                ws.receive_json()
                with self.assertRaises(WebSocketDisconnect) as caught:
                    for _ in range(10):ws.receive_json()
                self.assertEqual(caught.exception.code,1001)
