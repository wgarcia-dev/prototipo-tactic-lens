"""Read-only integration checks against the configured PostgreSQL instance."""
import unittest
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select, func

from backend import app
from platform_api import AnalysisResult, Finding, IocProposal, MitreProposal


class LiveTests(unittest.TestCase):
    def test_import_and_reimport_in_rolled_back_transaction(self):
        with TestClient(app, client=("192.168.56.1", 50000)) as client:
            engine = app.state.engine
            with engine.connect() as connection:
                outer = connection.begin()

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
                    with patch.dict("os.environ", {"LLM_MODEL": "test-provider-model", "LLM_PROVIDER": "test"}), patch("platform_api.real_result", return_value=result):
                        analysis = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(analysis.status_code, 200)
                    details = client.get("/api/analisis/" + analysis.json()["id_analisis"]).json()
                    self.assertEqual(details["estado"], "completado")
                    self.assertEqual(len(details["acciones"]), 1)
                    self.assertEqual(len(details["acciones"][0]["mitre"]), 1)
                    self.assertEqual(connection.scalar(select(func.count()).select_from(app.state.tables["deteccion_ioc"]).where(app.state.tables["deteccion_ioc"].c.id_analisis == details["id_analisis"])), 1)
                    with patch.dict("os.environ", {"LLM_MODE": "real", "LLM_MODEL": "test-provider-model", "LLM_PROVIDER": "test"}), patch("platform_api.real_result", side_effect=RuntimeError("provider unavailable")):
                        failed = client.post(f"/api/sesiones/{session_id}/analizar")
                    self.assertEqual(failed.status_code, 502)
                    analysis_t = app.state.tables["analisis_llm"]
                    self.assertEqual(connection.scalar(select(func.count()).where(analysis_t.c.id_sesion == session_id, analysis_t.c.estado == "fallido")), 1)
                finally:
                    app.state.engine = engine
                    outer.rollback()

    def test_database_and_api(self):
        with TestClient(app, client=("192.168.56.1", 50000)) as client:
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
            self.assertEqual(client.get("/api/sesiones").status_code, 403)
            self.assertEqual(client.post("/api/ingesta/cowrie", files={"file": ("x.json", b"{}\n")}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
