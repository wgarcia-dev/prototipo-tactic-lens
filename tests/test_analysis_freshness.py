"""State agreement across public reads using synthetic events and a simulated LLM."""
import os
from datetime import datetime, timedelta, timezone
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select

from backend.api import app
from backend.routes import AnalysisResult
from test_auth import AuthFixture


@skipUnless(os.getenv("TACTICLENS_ISOLATED_FRESHNESS_TEST") == "1", "requires isolated PostgreSQL")
class AnalysisFreshnessTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if (os.getenv("DATABASE_HOST") != "127.0.0.1" or os.getenv("DATABASE_PORT") in {None, "", "5432"}
                or not os.getenv("DATABASE_NAME", "").startswith("tacticlens_h02_h05")):
            raise RuntimeError("Se requiere la base temporal de H05")
        super().setUpClass()

    def ingest(self, name, second, command):
        event = {"session": name, "eventid": "cowrie.command.input", "input": command,
                 "timestamp": f"2026-11-25T01:00:{second:02d}+00:00", "src_ip": "10.20.30.44",
                 "_collector": {"source_id": f"{name}:{second}"}}
        response = self.client.post("/api/ingesta/eventos", json={"eventos": [event]},
                                    headers={"x-api-key": os.environ["INGEST_API_KEY"]})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["confirmaciones"][0]["id_evento"]

    def status(self, session, analysis, expected_attempt, expected_coverage, expected_method):
        base = f"/api/sesiones/{session}"
        response = self.client.get(base)
        self.assertEqual(response.status_code, 200, response.text)
        pages = [response, self.client.get("/api/sesiones", params={"limit": 5, "q": response.json()["cowrie_session_id"]}),
                 self.client.get(f"/api/analisis/{analysis}"), self.client.get(base + "/informe")]
        for response in pages:
            self.assertEqual(response.status_code, 200, response.text)
        detail, listing, selected, report = (response.json() for response in pages)
        panel_session = next(item for item in listing if item["id_sesion"] == str(session))
        for item in (detail, panel_session, selected, report):
            self.assertEqual(item["estado_ultimo_intento"], expected_attempt)
            freshness = item["vigencia_analisis"]
            self.assertEqual((freshness["cobertura_eventos"], freshness["metodologia"]),
                             (expected_coverage, expected_method))
        self.assertEqual(detail["analisis"]["id_analisis"], analysis)
        self.assertEqual(report["id_analisis"], analysis)
        panel = self.client.get("/api/dashboard/resumen")
        self.assertEqual(panel.status_code, 200)
        self.assertGreaterEqual(panel.json()["sesiones_analizadas"], 1)
        return selected, report

    def test_public_reads_share_version_coverage_and_last_attempt(self):
        self.enroll(9505, admin=True)
        name = uuid4().hex
        event_id = self.ingest(name, 0, "pwd")
        event = app.state.tables["evento"]
        session = self.connection.scalar(select(event.c.id_sesion).where(event.c.id_evento == event_id))
        run = f"/api/sesiones/{session}/analizar"
        model_output = AnalysisResult(resumen="Resultado sintético de vigencia", acciones=[])
        with patch("backend.routes.real_result", return_value=model_output) as provider:
            first = self.client.post(run)
            self.assertEqual(first.status_code, 200, first.text)
            aid = first.json()["id_analisis"]
            self.assertTrue(self.client.post(run).json()["reutilizado"])
            provider.assert_called_once()
        selected, _ = self.status(session, aid, "completado", "completa", "vigente")
        old = selected["resultado_estructurado"]
        self.assertEqual(old["vigencia_snapshot"]["eventos"], [str(event_id)])
        self.assertEqual(old["vigencia_snapshot"]["eventos_sha256"], old["evaluacion_incidente"]["snapshot_sha256"])

        for target, value in (("LLM_MODEL", "otro-modelo"), ("LLM_PROVIDER", "otro-proveedor"),
                              ("MISP_WARNING_LISTS_DIR", "fixture-config-diferente")):
            with self.subTest(target=target), patch.dict("os.environ", {target: value}):
                self.status(session, aid, "completado", "completa", "desactualizada")
        with patch("backend.rag.pipeline.PIPELINE_VERSION", "fixture-v999"):
            self.status(session, aid, "completado", "completa", "desactualizada")
        with patch("backend.analysis_report.analysis_instruction", return_value="Prompt de prueba cambiado"):
            self.status(session, aid, "completado", "completa", "desactualizada")
        catalog = app.state.tables["catalogo_mitre"]
        savepoint = self.connection.begin_nested()
        try:
            self.connection.execute(catalog.update().where(catalog.c.activo).values(sha256="a" * 64))
            self.status(session, aid, "completado", "completa", "desactualizada")
        finally:
            savepoint.rollback()

        # A same-source neighboring session changes the recurrence input only.
        self.ingest(uuid4().hex, 0, "whoami")
        self.status(session, aid, "completado", "completa", "desactualizada")
        self.connection.execute(event.update().where(event.c.id_evento == event_id).values(
            datos_originales={"input": "date", "eventid": "cowrie.command.input"}))
        self.status(session, aid, "completado", "incompleta", "desactualizada")
        self.ingest(name, 1, "whoami")
        self.status(session, aid, "completado", "incompleta", "desactualizada")

        with patch("backend.routes.real_result", side_effect=RuntimeError("fallo sintético")):
            self.assertEqual(self.client.post(run).status_code, 502)
        self.status(session, aid, "fallido", "incompleta", "desactualizada")

        analysis = app.state.tables["analisis_llm"]
        payload = {key: value for key, value in old.items() if key not in {"vigencia_snapshot", "evaluacion_incidente"}}
        self.connection.execute(analysis.update().where(analysis.c.id_analisis == aid).values(resultado_estructurado=payload))
        self.status(session, aid, "fallido", "incompleta", "no_verificable")
        triaje = self.client.post(f"/api/analisis/{aid}/preparar-evaluacion")
        self.assertEqual(triaje.status_code, 200, triaje.text)
        self.assertEqual(triaje.json()["eventos_evaluados"], 2)
        self.assertNotEqual(triaje.json()["snapshot_sha256"], old["vigencia_snapshot"]["eventos_sha256"])

        now = datetime.now(timezone.utc)
        self.connection.execute(analysis.update().where(analysis.c.id_sesion == session).values(
            fecha_inicio=now - timedelta(days=1)))
        model = self.connection.scalar(select(analysis.c.id_modelo).where(analysis.c.id_analisis == aid))
        self.connection.execute(analysis.insert().values(id_sesion=session, id_modelo=model,
            estado="en_proceso", fecha_inicio=now - timedelta(hours=1)))
        self.status(session, aid, "vencido", "incompleta", "no_verificable")
