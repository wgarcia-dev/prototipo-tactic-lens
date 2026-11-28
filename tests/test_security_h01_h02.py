"""Synthetic privacy and PostgreSQL privilege regressions for H01/H02."""
from io import BytesIO
import json
import os
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch
from uuid import uuid4

from docx import Document
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

import test_auth as auth
from test_analysis import report_data
from test_rag import proposal
from backend.api import app
from backend.analysis_trace import DiagnosticTrace
from backend.auth.middleware import AuthMiddleware
from backend.db import database_engine, migration_engine
from backend.db_access import verify_runtime_access
from backend.sensitive import Redactor

PASSWORD = "fixture-Cowrie-A9!secret"
TOKEN = "fixture-T0ken-XY"
API_KEY = "fixture-apiKey-7245"
URL_PASSWORD = "fixture-Userinfo-S89"
LEGIT_URL = "https://updates.corp.local/file?platform=linux"
LEGIT_HASH = "a1b2c3d4" * 8
HOST = "203.0.113.56"
SECRETS = (PASSWORD, TOKEN, API_KEY, URL_PASSWORD)


class RedactionTests(TestCase):
    def test_nested_fields_urls_and_free_text_share_the_same_projection(self):
        raw = {"password": PASSWORD, "nested": [{"accessToken": TOKEN, "x-api-key": API_KEY}],
               "input": f"echo {PASSWORD} {TOKEN} {API_KEY} {URL_PASSWORD}",
               "url": f"ftp://fixture-user:{URL_PASSWORD}@updates.example.org/file?accessToken={TOKEN}",
               "artifact": {"IP": HOST, "sha256": LEGIT_HASH, "url": LEGIT_URL},
               "stdout": "opaque terminal material"}
        redactor = Redactor([raw])
        safe = redactor.payload(raw, raw_event=True)
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(safe))
            self.assertIn(secret, json.dumps(raw))
        self.assertEqual(safe["artifact"], raw["artifact"])
        self.assertEqual(safe["url"], "ftp://updates.example.org/file")
        self.assertEqual(safe["stdout"], "[REDACTED]")
        self.assertEqual(redactor.text(f"artifact located at {LEGIT_URL}"), f"artifact located at {LEGIT_URL}")
        self.assertEqual(redactor.text("passphrase='fixture multiple words'"), "passphrase=[REDACTED]")
        self.assertEqual(Redactor([{"password": "42"}]).payload({"eventos": ["42"]}), {"eventos": ["42"]})

    def test_minimized_trace_omits_sensitive_fields_and_free_text(self):
        trace = DiagnosticTrace(enabled=True)
        trace.record("fixture", {"evento": "42", "codigo_mitre": "T1105", "accessToken": TOKEN,
                                  "headers": {"x-api-key": API_KEY}, "observado": PASSWORD})
        self.assertEqual(trace.stages["fixture"]["evento"], "42")
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(trace.stages))

    def test_unexpected_api_error_logs_only_the_exception_class(self):
        import asyncio

        async def broken_app(scope, receive, send):
            raise RuntimeError(PASSWORD)

        async def run():
            sent = []
            async def send(value):
                sent.append(value)
            await AuthMiddleware(broken_app)({"type": "http", "path": "/api/health", "method": "GET",
                 "headers": [], "query_string": b""}, None, send)
            return sent

        with self.assertLogs("backend.auth.middleware", level="ERROR") as logs:
            response = asyncio.run(run())
        self.assertEqual(response[0]["status"], 500)
        self.assertNotIn(PASSWORD, str(response) + str(logs.output))


@skipUnless(os.getenv("TACTICLENS_ISOLATED_SECURITY_TEST") == "1", "requires the isolated PostgreSQL fixture")
class IsolatedSecurityTests(auth.AuthFixture):
    @classmethod
    def setUpClass(cls):
        if (os.getenv("DATABASE_HOST") not in {"127.0.0.1", "localhost"}
                or not os.getenv("DATABASE_NAME", "").startswith("tacticlens_h02_")
                or os.getenv("DATABASE_PORT", "5432") == "5432"
                or os.getenv("DATABASE_ENFORCE_RUNTIME_ROLE") != "true"):
            raise RuntimeError("Esta suite solo acepta PostgreSQL temporal en loopback con control de rol activo")
        engine = database_engine()
        try:
            with engine.connect() as conn:
                database, port, role = conn.execute(text("SELECT current_database(), inet_server_port(), current_user")).one()
                if (database, port, role) != (os.environ["DATABASE_NAME"], int(os.environ["DATABASE_PORT"]),
                                               os.environ["DATABASE_USER"]):
                    raise RuntimeError("El servidor no corresponde a la base aislada esperada")
                verify_runtime_access(conn, role)
        finally:
            engine.dispose()
        super().setUpClass()

    def assert_public(self, response):
        self.assertEqual(response.status_code, 200, response.text[:160])
        for secret in SECRETS:
            self.assertNotIn(secret, response.text)
        return response.json()

    def test_runtime_flows_original_evidence_and_public_exports(self):
        from pypdf import PdfReader

        _, _, _, _ = self.enroll(9181, admin=True)
        analyst, _, _ = self.account(9182, approve=True)
        self.assertEqual(self.client.get("/api/auth/admin/usuarios").status_code, 200)
        batch = str(uuid4())
        command = f"wget {LEGIT_URL}; echo {PASSWORD} {TOKEN} {API_KEY} {URL_PASSWORD}"
        raw = [
            {"eventid": "cowrie.login.failed", "username": "fixture-user", "password": PASSWORD,
             "details": {"accessToken": TOKEN, "apiKey": API_KEY},
             "url": f"https://fixture-user:{URL_PASSWORD}@updates.example.org/login"},
            {"eventid": "cowrie.command.input", "input": command},
            {"eventid": "cowrie.session.file_download", "url": LEGIT_URL, "shasum": LEGIT_HASH},
        ]
        events = [{**item, "timestamp": f"2026-11-06T10:00:0{index}Z", "session": batch, "src_ip": HOST,
                   "_collector": {"source_id": f"{batch}:{index}", "instance_id": "cowrie_shell"}}
                  for index, item in enumerate(raw)]
        receipts = self.assert_public(self.client.post("/api/ingesta/eventos", json={"eventos": events},
                                      headers={"x-api-key": os.environ["INGEST_API_KEY"]}))
        self.assertEqual(receipts["insertados"], len(events))
        event_ids = [receipt["id_evento"] for receipt in receipts["confirmaciones"]]
        table = app.state.tables["evento"]
        stored = self.connection.execute(select(table.c.id_sesion, table.c.datos_originales)
                    .where(table.c.id_evento.in_(event_ids)).order_by(table.c.id_evento)).all()
        session_id = stored[0].id_sesion
        self.assertEqual([item.datos_originales for item in stored],
                         [{k: v for k, v in event.items() if k != "_collector"} for event in events])
        session_path = f"/api/sesiones/{session_id}"
        dashboard = self.assert_public(self.client.get("/api/dashboard/resumen"))
        self.assert_public(self.client.get("/api/sesiones"))
        self.assert_public(self.client.get(session_path))
        command_view, = self.assert_public(self.client.get(session_path + "/eventos",
                                            params={"id_evento": event_ids[1]}))
        command_public = command_view["datos_originales"]["input"]
        self.assertIn(LEGIT_URL, command_public)
        self.assertIn(command_public, [item["comando"] for item in dashboard["ultimos_comandos"]])
        all_events = self.assert_public(self.client.get(session_path + "/eventos"))
        self.assertEqual(all_events[0]["datos_originales"]["details"]["accessToken"], "[REDACTED]")

        observables = self.assert_public(self.client.get("/api/iocs/explorar"))
        by_value = {row["valor"]: row for row in observables}
        self.assertTrue({HOST, LEGIT_URL, LEGIT_HASH} <= by_value.keys())
        ioc_path = "/api/iocs/" + by_value[LEGIT_URL]["id_ioc"]
        for view in (False, True):
            self.assert_public(self.client.get(ioc_path + "/observaciones", params={"vista_segura": view}))
        self.assert_public(self.client.get(ioc_path + "/perfil"))
        self.assert_public(self.client.patch("/api/inteligencia/ioc/" + by_value[LEGIT_URL]["id_ioc"] + "/revision",
            json={"estado": "confirmado", "motivo": "Revisión válida con evidencia sintética"}))

        report = report_data()
        report["fases"][0].update(eventos=[event_ids[1]], observado="Orden de transferencia observada")
        report["hipotesis"][0]["eventos"] = [event_ids[1]]
        resp = Mock()
        resp.json.return_value = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
            "resumen": f"Resumen sintético {TOKEN}",
            "acciones": [{"tipo": "comando", "descripcion": f"Transferencia registrada {API_KEY}", "confianza": 0.9,
                          "eventos": event_ids[1:], "mitre": [proposal(eventos=[event_ids[2]],
                              grado_evidencia="resultado_en_honeypot").model_dump()]}],
            "informe": report,
        })}}]}
        with patch("backend.routes.post_provider", return_value=resp) as provider:
            analysis_id = self.assert_public(self.client.post(session_path + "/analizar"))["id_analisis"]
            provider.assert_called_once()
        outbound = json.dumps(provider.call_args.kwargs["json"])
        for secret in SECRETS:
            self.assertNotIn(secret, outbound)
        self.assertIn("T1105", outbound)

        analysis_path = f"/api/analisis/{analysis_id}"
        analysis = self.assert_public(self.client.get(analysis_path))
        mapping, = analysis["acciones"][0]["mitre"]
        self.assertEqual(mapping["codigo_tecnica"], "T1105")
        mappings = app.state.tables["mapeo_mitre"]
        self.connection.execute(mappings.update().where(mappings.c.id_mapeo == mapping["id_mapeo"])
                                .values(justificacion=f"Cita histórica {PASSWORD}"))
        mapping_path = "/api/mitre/mapeos/" + mapping["id_mapeo"] + "/observables"
        for option in (False, True):
            self.assert_public(self.client.get(mapping_path, params={"detallar_citas": option}))
        self.assert_public(self.client.patch("/api/inteligencia/mitre/" + mapping["id_mapeo"] + "/revision",
            json={"estado": "confirmado", "motivo": "Cita MITRE sintética revisada"}))
        self.assert_public(self.client.get("/api/mitre/mapeos"))

        # Simulate a historical narrative stored before the masking boundary existed.
        analyses = app.state.tables["analisis_llm"]
        old_payload = analysis["resultado_estructurado"]
        old_payload["informe"]["contexto"] = f"Registro histórico {PASSWORD}"
        self.connection.execute(analyses.update().where(analyses.c.id_analisis == analysis_id)
                                .values(resumen=f"Resumen histórico {TOKEN}", resultado_estructurado=old_payload))
        self.assert_public(self.client.get(analysis_path))
        report_path = session_path + "/informe"
        json_report = self.assert_public(self.client.get(report_path, params={"id_analisis": analysis_id}))
        self.assertIn(command_public, json.dumps(json_report, ensure_ascii=False))
        for format in ("pdf", "docx"):
            file = self.client.get(report_path, params={"formato": format, "id_analisis": analysis_id,
                                                         "snapshot": json_report["snapshot"]})
            self.assertEqual(file.status_code, 200)
            if format == "pdf":
                rendered = " ".join(page.extract_text() for page in PdfReader(BytesIO(file.content)).pages)
            else:
                doc = Document(BytesIO(file.content))
                rendered = " ".join([p.text for p in doc.paragraphs]
                    + [cell.text for table in doc.tables for row in table.rows for cell in row.cells])
            self.assertIn("updates.corp.local", rendered)
            self.assertIn("[REDACTED]", rendered)
            for secret in SECRETS:
                self.assertNotIn(secret, rendered)

        tasks = self.assert_public(self.client.get("/api/salvaguardas", params={"id_sesion": str(session_id)}))["items"]
        self.assertTrue(tasks)
        task = "/api/salvaguardas/" + tasks[0]["id_salvaguarda"]
        self.assert_public(self.client.post(task + "/asignacion", json={"responsable": str(analyst)}))
        self.assert_public(self.client.post(task + "/estado", json={"estado": "en_desarrollo"}))
        self.assert_public(self.client.post(task + "/evidencia", json={"evidencia": f"Evidencia histórica {TOKEN}"}))
        self.assert_public(self.client.post(task + "/estado", json={"estado": "realizada", "resultado": "Contraste finalizado",
            "evidencia": "Registro de evidencia sintético", "criterio_aplicado": "Insumos mínimos verificados"}))
        self.assert_public(self.client.get(task))
        self.assert_public(self.client.get(task + "/historial"))
        self.assertTrue(self.assert_public(self.client.get("/api/auth/admin/auditoria")))

    def test_runtime_denies_administration_and_audit_modification(self):
        self.enroll(9183, admin=True)
        self.assertGreater(self.connection.scalar(text("SELECT count(*) FROM honeypot.auth_auditoria")), 0)
        statements = (
            "UPDATE honeypot.auth_auditoria SET metadatos = '{}' WHERE false",
            "DELETE FROM honeypot.auth_auditoria WHERE false",
            "TRUNCATE honeypot.auth_auditoria",
            "DROP TABLE honeypot.auth_auditoria",
            "ALTER TABLE honeypot.auth_auditoria DISABLE TRIGGER trg_auth_auditoria_inmutable",
            "DROP FUNCTION honeypot.impedir_cambio_auditoria()",
            "CREATE TABLE honeypot.security_fixture_denied(id integer)",
            "CREATE TEMP TABLE security_fixture_denied(id integer)",
            "SET session_replication_role = replica",
            "UPDATE honeypot.schema_migration SET checksum = '' WHERE false",
            "SELECT * FROM honeypot.configuracion_integracion",
        )
        owner = self.connection.dialect.identifier_preparer.quote_identifier(os.environ["DATABASE_MIGRATION_USER"])
        for statement in (*statements, f"SET ROLE {owner}"):
            with self.subTest(statement=statement), self.assertRaises(DBAPIError) as raised:
                with self.connection.begin_nested():
                    self.connection.exec_driver_sql(statement)
            self.assertEqual(raised.exception.orig.sqlstate, "42501")

    def test_migrator_owns_objects_and_future_objects_default_to_denial(self):
        engine = migration_engine()
        self.addCleanup(engine.dispose)
        with engine.connect() as conn, conn.begin() as transaction:
            self.assertEqual(conn.scalar(text("SELECT current_user")), os.environ["DATABASE_MIGRATION_USER"])
            migrations = conn.scalars(text("SELECT version FROM honeypot.schema_migration ORDER BY version")).all()
            self.assertIn("002_auditoria_inmutable.sql", migrations)
            self.assertIn("013_salvaguardas_wip.sql", migrations)
            conn.exec_driver_sql("CREATE TABLE honeypot.security_fixture_future (id integer)")
            conn.exec_driver_sql("CREATE FUNCTION honeypot.security_fixture_future() RETURNS int LANGUAGE sql AS 'SELECT 1'")
            flags = conn.execute(text("""
                SELECT has_table_privilege(:runtime,'honeypot.security_fixture_future','SELECT,INSERT,UPDATE'),
                       has_function_privilege(:runtime,'honeypot.security_fixture_future()','EXECUTE')
            """), {"runtime": os.environ["DATABASE_USER"]}).one()
            self.assertEqual(tuple(flags), (False, False))
            transaction.rollback()
