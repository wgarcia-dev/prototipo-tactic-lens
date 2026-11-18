"""Read restored real history without Ubuntu or a paid LLM; fixture user rolls back."""
from unittest.mock import patch
from sqlalchemy import text
import test_auth as fixtures
from backend.api import app
from backend.realtime import PROTOCOL


class LocalHistoryTests(fixtures.AuthFixture):
    def test_history_and_rag_remain_available_with_no_new_sensor_events(self):
        self.enroll(908,admin=True)
        with patch('backend.routes.httpx.post',side_effect=AssertionError('No DeepSeek in portability checks')):
            dashboard=self.client.get('/api/dashboard/resumen')
            self.assertEqual(dashboard.status_code,200)
            total=self.connection.scalar(text('SELECT count(*) FROM honeypot.evento'))
            self.assertGreater(total,0)
            self.assertEqual(dashboard.json()['eventos'],total)
            sessions=self.client.get('/api/sesiones').json();self.assertTrue(sessions)
            sid=sessions[0]['id_sesion']
            self.assertEqual(self.client.get('/api/sesiones/'+sid+'/eventos').status_code,200)
            self.assertEqual(self.client.get('/api/iocs').status_code,200)
            self.assertEqual(self.client.get('/api/mitre/mapeos').status_code,200)
            self.assertEqual(self.client.get('/api/auth/admin/usuarios').status_code,200)
            self.assertEqual(self.client.get('/api/mitre/catalogo').json()['version'],'20.1')
            candidates=self.client.post('/api/sesiones/'+sid+'/mitre/candidatos')
            self.assertEqual(candidates.status_code,200)
            self.assertEqual(candidates.json()['catalogo']['version'],'20.1')
            self.assertTrue(candidates.json()['candidatos'])
            aid=self.connection.scalar(text("SELECT id_analisis FROM honeypot.analisis_llm WHERE estado='completado' ORDER BY fecha_fin DESC LIMIT 1"))
            self.assertIsNotNone(aid)
            self.assertEqual(self.client.get('/api/analisis/'+str(aid)).status_code,200)
            sid=self.connection.scalar(text("SELECT id_sesion FROM honeypot.evento WHERE tipo_evento='cowrie.command.input' LIMIT 1"))
            candidates=self.client.post('/api/sesiones/'+str(sid)+'/mitre/candidatos')
            self.assertEqual(candidates.status_code,200)
            self.assertTrue(candidates.json()['candidatos'])
            with self.client.websocket_connect('/api/monitor/ws',headers={'origin':'http://127.0.0.1:5173'},subprotocols=[PROTOCOL]) as ws:
                self.assertEqual(ws.receive_json()['tipo'],'listo')
            self.assertEqual(self.connection.scalar(text('SELECT count(*) FROM honeypot.evento')),total)
