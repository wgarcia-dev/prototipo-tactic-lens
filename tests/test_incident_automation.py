from datetime import timedelta
import json
import os
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import uuid4

from fastapi import Request
import httpx
from sqlalchemy import func, select

from backend.api import app
from backend.auth.notifications import message_for
from backend.incident_automation import DraftResult, claim, finish, generate, verify_plan, work_once
from backend.incident_notices import reminders
from backend.incidents import publish, register_analysis, seal_events
from backend.realtime import PostgresMonitor
from test_auth import AuthFixture
from test_incident_response import EID, REASON, SECRET
import test_incidents

ISOLATED = (os.getenv("DATABASE_HOST"), os.getenv("DATABASE_PORT"), os.getenv("DATABASE_NAME")) == (
    "127.0.0.1", "56591", "tacticlens_incidentes_integracion")
CONFIG = ("https://provider.invalid/v1", "deepseek-fixture", "fixture-only", 4, 10)
INBOX = "/api/respuestas-incidentes/avisos"


def proposal(event=EID):
    first = {"clave": "A1", "fase": "investigacion", "medida": "Contrastar el registro de Cowrie",
             "descripcion": "Comparar las fuentes de evidencia disponibles", "objetivo": "Documentar el alcance observado",
             "justificacion": "Interacción registrada con el señuelo", "prioridad": "alta", "rol_sugerido": "analista",
             "plazo_dias": 0, "dependencias": [], "eventos": [event], "mitre": [],
             "resultado_esperado": "Alcance documentado con referencias", "criterio_verificacion": "La evidencia documenta el alcance"}
    second = {**first, "clave": "A2", "fase": "verificacion", "medida": "Verificar la documentación",
              "dependencias": ["A1"], "rol_sugerido": "indistinto"}
    return {"plan": {"titulo": "Revisión técnica del incidente", "objetivo": "Documentar los resultados observados",
            "resumen": "Interacción observada en el entorno de prueba", "alcance": "Sesión observada del sensor de prueba",
            "estrategia": "Revisión manual de las fuentes", "prioridad": "media", "resultado_esperado": "Evidencia verificable",
            "criterio_resolucion": "Verificar las fuentes originales", "criterio_cierre": "Documentar la resolución y sus límites",
            "eventos": [event], "acciones": [first, second]}}


def answer(result):
    return httpx.Response(200, request=httpx.Request("POST", CONFIG[0]), json={
        "usage": {"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 150},
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(result)}}],
    })


class AutomationUnitTests(TestCase):
    def test_unverified_cites_dependencies_and_legacy_references_fail(self):
        context = {"evidencia": [{"evento": EID}], "mitre": [], "antecedentes": []}
        verify_plan(DraftResult.model_validate(proposal()).plan, context)
        with self.assertRaises(ValueError):
            verify_plan(DraftResult.model_validate(proposal("123")).plan, context)
        for name, value in (("mitre", ["T1059"]), ("antecedente", str(uuid4()))):
            document = proposal()
            document["plan"]["acciones"][0][name] = value
            with self.assertRaises(ValueError):
                verify_plan(DraftResult.model_validate(document).plan, context)
        cycle = proposal()
        cycle["plan"]["acciones"][0]["dependencias"] = ["A2"]
        with self.assertRaises(ValueError):
            DraftResult.model_validate(cycle)

    def test_provider_errors_and_truncation_have_no_plan(self):
        context = {"evidencia": [{"evento": EID}], "mitre": [], "antecedentes": []}
        for error, expected, retry in ((httpx.ConnectError("offline"), "proveedor_no_disponible", True),
                                      (httpx.ReadTimeout("late"), "plazo_agotado", False)):
            with patch("backend.incident_automation.post_provider", side_effect=error):
                self.assertEqual(generate(CONFIG, context)[2:], (expected, retry))
        with patch("backend.incident_automation.post_provider", return_value=answer(proposal("123"))):
            result, _, code, retry = generate(CONFIG, context)
            self.assertEqual((result, code, retry), (None, "respuesta_o_citas_invalidas", False))

    def test_notice_monitor_routes_to_authenticated_recipient_only(self):
        monitor = PostgresMonitor.__new__(PostgresMonitor)
        monitor.sensors = {"fixture"}
        recipient = str(uuid4())
        payload = {"sensores": ["fixture"], "dominios": ["avisos_incidentes"], "destinatarios": [recipient]}
        self.assertEqual(monitor.parse(json.dumps(payload)), {"dominios": ["avisos_incidentes"], "destinatarios": [recipient]})
        self.assertIsNone(monitor.parse(json.dumps({**payload, "sensores": ["foreign"]})))


@skipUnless(ISOLATED, "requires the isolated incident PostgreSQL database")
class AutomationIntegrationTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        async def no_worker(_):
            return None

        with patch("backend.incident_automation.drain", new=no_worker):
            super().setUpClass()

    def setUp(self):
        super().setUp()
        self.config = patch.dict(os.environ, {"INCIDENT_RESPONSE_AUTO_ENABLED": "true", "INCIDENT_RESPONSE_EMAIL_ENABLED": "false"})
        self.config.start()
        self.addCleanup(self.config.stop)
        self.tables = app.state.tables
        self.iid, self.sid = uuid4(), uuid4()
        self.path = f"/api/incidentes/{self.iid}/respuesta"
        self.connection.execute(self.tables["sesion"].insert().values(id_sesion=self.sid,
            id_honeypot=app.state.honeypot_id, cowrie_session_id=str(self.sid), fecha_inicio=self.clock))
        self.connection.execute(self.tables["evento"].insert().values(id_evento=int(EID), id_sesion=self.sid,
            numero_secuencia=1, fecha_hora=self.clock, tipo_evento="cowrie.login.success",
            datos_originales={"password": SECRET, "input": "UNTRUSTED FIXTURE TEXT " + SECRET}))
        self.connection.execute(self.tables["incidente"].insert().values(id_incidente=self.iid))
        self.connection.execute(self.tables["incidente_sesion"].insert().values(id_incidente=self.iid,
            id_sesion=self.sid, revision_ingreso=1, correlacion={}))

    def revise(self, revision, decision="actividad_sospechosa", historical=False):
        fields = {"decision": decision, "severidad": "S2", "prioridad": "media", "clasificacion": "acceso_senuelo",
                  "titulo": "Interacción sintética", "resumen": "Evidencia de laboratorio " + SECRET,
                  "detalle": {"retrospectiva": [{"base_evidencia": "recibos_y_citas"}]} if historical else {}}
        events = seal_events(self.connection, self.tables, app.state.instances, {self.sid}, {int(EID): None})
        publish(self.connection, self.tables, self.iid, revision, fields, events, {self.sid})

    def call(self, method, path, expected, body=None):
        response = self.client.request(method, path, **({"json": body} if body is not None else {}))
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def draft(self):
        item, = self.call("GET", self.path+"/borradores", 200)["items"]
        return item

    def consume(self, document=None):
        with patch("backend.incident_automation.configuration", return_value=CONFIG), patch(
                "backend.incident_automation.post_provider", return_value=answer(document or proposal())) as provider:
            work_once(app)
            work_once(app)
            provider.assert_called_once()
            outbound = provider.call_args.kwargs["json"]
            self.assertNotIn(SECRET, json.dumps(outbound))
            self.assertNotIn("UNTRUSTED FIXTURE TEXT", json.dumps(outbound))
            self.assertIn(EID, outbound["messages"][1]["content"])

    def test_automatic_draft_review_assignment_reminders_and_resolution(self):
        analyst, *_ = self.account(4821, approve=True)
        self.enroll(4822, admin=True)
        self.revise(1)
        self.assertEqual(self.draft()["estado"], "pendiente")
        self.consume()
        draft = self.draft()
        self.assertEqual(draft["estado"], "disponible")
        self.assertEqual(draft["consumo"]["total_tokens"], 150)
        endpoint = self.path + "/borradores/" + draft["id_borrador"]
        data = {"revision_esperada": 1, "revision_evaluacion": 1, "motivo": REASON}
        self.call("POST", endpoint+"/aprobar", 409, data)
        self.revise(2, "incidente_confirmado")
        self.assertEqual(self.draft()["id_borrador"], draft["id_borrador"])
        changed = proposal()["plan"]
        changed["resumen"] = "Alcance revisado por el administrador"
        data["revision_evaluacion"] = 2
        self.call("PUT", endpoint, 200, {**data, "plan": changed})
        self.call("PUT", endpoint, 409, {**data, "plan": changed})
        data["revision_esperada"] = 2
        self.call("POST", endpoint+"/aprobar", 422, {**data, "acciones": ["A2"]})
        with patch.dict(os.environ, {"INCIDENT_RESPONSE_EMAIL_ENABLED": "true"}):
            partial = self.call("POST", endpoint+"/aprobar", 200, {**data, "acciones": ["A1"]})
            self.assertEqual(set(partial["acciones"]), {"A1"})
            result = self.call("POST", endpoint+"/aprobar", 200, {**data, "revision_esperada": 3, "acciones": ["A2"]})
        self.call("POST", endpoint+"/aprobar", 409, data)
        self.assertEqual(result["plan"]["origen"], "llm")
        self.assertEqual(result["plan"]["progreso"]["estados"]["aprobada"], 2)
        first = self.call("GET", self.path+"/acciones/"+result["acciones"]["A1"], 200)
        self.assertEqual(first["id_responsable"], str(analyst))
        self.assertEqual(first["prioridad"], "alta")
        outbox, audit = (self.tables[name] for name in ("auth_notificacion", "auth_auditoria"))
        pending = self.connection.execute(select(outbox).join(audit, audit.c.id_auditoria == outbox.c.id_auditoria)
            .where(audit.c.tipo == "incidente_aviso_correo", audit.c.id_usuario == analyst)).mappings().one()
        email_request = Request({"type": "http", "headers": [], "app": app})
        email = message_for(self.connection, email_request, pending)
        self.assertEqual(email[0], analyst)
        self.assertIn("/respuesta-incidentes", email[2])
        self.assertNotIn(SECRET, email[2])
        self.assertNotIn(EID, email[2])
        second = self.call("GET", self.path+"/acciones/"+result["acciones"]["A2"], 200)
        self.assertEqual(second["procedencia"]["dependencias"], [first["id_accion"]])

        def move(action, operation, expected=200):
            return self.call("POST", self.path+"/acciones/"+action["id_accion"]+"/transiciones", expected,
                {"revision_evaluacion": 2, "revision_esperada": action["revision_accion"], "motivo": REASON,
                 "operacion": operation, "eventos": [EID], "resultado": REASON})

        move(second, "iniciar", 409)
        request = Request({"type": "http", "headers": [], "app": app})
        reminders(self.connection, request, self.clock.date()+timedelta(days=3))
        reminders(self.connection, request, self.clock.date()+timedelta(days=3))
        notices = self.tables["incidente_aviso"]
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(notices).where(
            notices.c.tipo == "vencida", notices.c.id_accion == first["id_accion"])), 1)
        inbox = self.call("GET", INBOX, 200)
        private = self.connection.scalar(select(notices.c.id_aviso).where(notices.c.destinatario == analyst, notices.c.tipo == "asignada"))
        self.assertNotIn(str(private), [item["id_aviso"] for item in inbox["items"]])
        self.assertEqual(self.call("POST", INBOX+f"/{private}/leer", 200)["actualizados"], 0)
        self.call("POST", INBOX+"/leer-todos", 200)
        self.assertEqual(self.call("GET", INBOX, 200)["no_leidos"], 0)
        for action in (first, second):
            move(move(move(action, "iniciar"), "ejecutar"), "verificar")
        plan = self.call("GET", self.path, 200)
        self.assertTrue(plan["progreso"]["listo_resolver"])
        for operation in ("resolver", "cerrar", "reabrir"):
            plan = self.call("POST", self.path+"/transiciones", 200, {"revision_evaluacion": 2,
                "revision_esperada": plan["revision_respuesta"], "operacion": operation, "motivo": REASON,
                "resultado": REASON, "riesgos_pendientes": REASON, "referencia": REASON})
        self.assertEqual(plan["estado"], "en_respuesta")
        board = self.call("GET", "/api/respuestas-incidentes/acciones?mias=true&origen=llm&prioridad=alta", 200)
        self.assertEqual([item["id_accion"] for item in board["items"]], [second["id_accion"]])
        history = self.call("GET", endpoint, 200)["versiones"]
        self.assertEqual([item["version"] for item in history], [4, 3, 2, 1])
        report = self.call("GET", self.path+"/informe", 200)
        self.assertIn("Alcance revisado por el administrador", json.dumps(report))
        self.assertNotIn(SECRET, json.dumps(report))

    def test_historical_batch_is_explicit_idempotent_and_validation_fails_closed(self):
        self.enroll(4824, admin=True)
        self.revise(1, historical=True)
        path = "/api/respuestas-incidentes/automatizacion/retrospectiva"
        self.assertEqual(self.call("GET", self.path+"/borradores", 200)["items"], [])
        self.assertEqual(self.call("POST", path, 200, {"vista_previa": True})["total"], 1)
        self.assertEqual(self.call("GET", self.path+"/borradores", 200)["items"], [])
        self.assertEqual(self.call("POST", path, 200, {"vista_previa": False})["total"], 1)
        self.assertEqual(self.call("POST", path, 200, {"vista_previa": False})["total"], 0)
        self.consume(proposal("123"))
        self.assertEqual(self.draft()["estado"], "fallido")
        self.assertEqual(self.draft()["versiones"], [])
        self.assertIsNone(self.call("GET", self.path, 200)["id_respuesta"])
        self.assertIn("generacion_fallida", [row["tipo"] for row in self.call("GET", INBOX, 200)["items"]])

    def test_saved_analysis_registers_and_queues_once_without_an_admin_request(self):
        self.enroll(4826)
        sid = uuid4()
        self.connection.execute(self.tables["sesion"].insert().values(id_sesion=sid,
            id_honeypot=app.state.honeypot_id, cowrie_session_id=str(sid), fecha_inicio=self.clock))
        self.connection.execute(self.tables["evento"].insert().values(id_sesion=sid, numero_secuencia=1,
            fecha_hora=self.clock, tipo_evento="cowrie.session.file_download", datos_originales={"size": 42}))
        analysis = test_incidents.IncidentsTests.saved_analysis(self, sid)
        args = (self.connection, self.tables, (app.state.honeypot_id,), app.state.instances, analysis)
        self.iid = register_analysis(*args)
        self.assertIsNotNone(self.iid)
        self.assertEqual(register_analysis(*args), self.iid)
        self.path = f"/api/incidentes/{self.iid}/respuesta"
        self.assertEqual(self.draft()["estado"], "pendiente")
        self.call("POST", self.path+"/borradores", 403, {"motivo": REASON})
        self.call("POST", "/api/respuestas-incidentes/automatizacion/retrospectiva", 403, {"vista_previa": False})

    def test_lease_prevents_duplicates_and_fences_stale_generation(self):
        self.enroll(4825, admin=True)
        self.revise(1)
        with patch("backend.incident_automation.configuration", return_value=CONFIG):
            claimed = claim(self.connection, self.tables)
            self.assertIsNotNone(claimed)
            self.assertIsNone(claim(self.connection, self.tables))
        row, token, _, _ = claimed
        self.revise(2, "evidencia_insuficiente")
        finish(self.connection, self.tables, row, token, (DraftResult.model_validate(proposal()), {}, None, False))
        finish(self.connection, self.tables, row, token, (DraftResult.model_validate(proposal()), {}, None, False))
        self.assertEqual(self.draft()["estado"], "sustituido")
        self.assertEqual(self.draft()["versiones"], [])
