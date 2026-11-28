from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
import os
from threading import Barrier
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

from docx import Document
from fastapi import HTTPException
import httpx
import psycopg
from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table, select

from backend.api import app
from backend.db import database_engine
from backend.db_access import INCIDENT_GRANTS, RESPONSE_GRANTS, RUNTIME_GRANTS, runtime_grants
from backend.incident_response import wip_available
from backend.incident_response_recommendations import Recommendations
from backend.incidents import publish, seal_events
from backend.realtime import CHANNEL, PostgresMonitor, notify_change
from backend.routes import ensure_model
from test_auth import AuthFixture

ISOLATED = (os.getenv("DATABASE_HOST"), os.getenv("DATABASE_PORT"), os.getenv("DATABASE_NAME")) == (
    "127.0.0.1", "56591", "tacticlens_incidentes_integracion")
SECRET = "ClaveFixtureSintetica_515782_Exclusiva"
EID = "9007199254740993"
REASON = "Registro de verificación técnica por el equipo de prueba"
PROPOSAL = dict(fase="verificacion", medida="Contrastar registros autorizados", objetivo="Comprobar el alcance",
                justificacion="La evidencia acredita interacción con el señuelo",
                criterio_verificacion="Comparar el resultado con el registro existente", eventos=[EID])


class ResponseUnitTests(TestCase):
    def test_optional_grants_preserve_old_schema_and_history_is_append_only(self):
        self.assertEqual(runtime_grants(RUNTIME_GRANTS), RUNTIME_GRANTS)
        grants = runtime_grants({**RUNTIME_GRANTS, **INCIDENT_GRANTS, **RESPONSE_GRANTS})
        self.assertEqual(grants["incidente_respuesta_historial"], ("SELECT", "INSERT"))
        self.assertEqual(grants["incidente_accion_evidencia"], ("SELECT", "INSERT"))
        with self.assertRaises(RuntimeError):
            runtime_grants({**RUNTIME_GRANTS, "incidente_respuesta": ("SELECT",)})

    def test_model_requires_proposals_or_abstention_and_preserves_bigint(self):
        result = Recommendations(sugerencias=[PROPOSAL])
        self.assertEqual(result.sugerencias[0].eventos, [EID])
        with self.assertRaises(ValueError):
            Recommendations(sugerencias=[PROPOSAL], abstencion=REASON)
        with self.assertRaises(ValueError):
            Recommendations(sugerencias=[])

    def test_monitor_requires_complete_scope_and_returns_only_domain(self):
        monitor = PostgresMonitor.__new__(PostgresMonitor)
        monitor.sensors = {"fixture-a"}
        notice = {"sensores": ["fixture-a", "fixture-b"], "dominios": ["respuesta_incidentes"], "eventos": [123]}
        self.assertIsNone(monitor.parse(json.dumps(notice)))
        monitor.sensors.add("fixture-b")
        self.assertEqual(monitor.parse(json.dumps(notice)), {"dominios": ["respuesta_incidentes"]})


@skipUnless(ISOLATED, "requires incident response fixture on the isolated PostgreSQL port")
class ResponseIntegrationTests(AuthFixture):
    def setUp(self):
        super().setUp()
        self.iid, self.sid = uuid4(), uuid4()
        self.path = f"/api/incidentes/{self.iid}/respuesta"
        tables = app.state.tables
        self.connection.execute(tables["sesion"].insert().values(
            id_sesion=self.sid, id_honeypot=app.state.honeypot_id, cowrie_session_id=str(self.sid), fecha_inicio=self.clock))
        self.connection.execute(tables["evento"].insert().values(
            id_evento=int(EID), id_sesion=self.sid, numero_secuencia=1, fecha_hora=self.clock,
            tipo_evento="cowrie.login.success", datos_originales={"password": SECRET, "username": "fixture"}))
        self.connection.execute(tables["incidente"].insert().values(id_incidente=self.iid))
        self.revision(1)

    def revision(self, number, decision="incidente_confirmado", sessions=None, analysis=None):
        tables = app.state.tables
        ids = {UUID(str(value)) for value in (sessions or [self.sid])}
        links = tables["incidente_sesion"]
        known = set(self.connection.scalars(select(links.c.id_sesion).where(links.c.id_incidente == self.iid)))
        for sid in ids - known:
            self.connection.execute(links.insert().values(id_incidente=self.iid, id_sesion=sid,
                revision_ingreso=number, correlacion={"metodo":"sesion_base"}))
        evidence = seal_events(self.connection, tables, app.state.instances, ids, {int(EID):analysis})
        publish(self.connection, tables, self.iid, number, {
            "decision":decision, "severidad":"S2", "prioridad":"media", "clasificacion":"actividad_sospechosa",
            "titulo":"Interacción sintética", "resumen":"Evidencia de laboratorio " + SECRET,
            "detalle":{"origen":"fixture_con_servicio_real","modalidades":["desconocido"],"recursos_confirmados":[]},
        }, evidence, ids)

    def request_post(self, suffix, body, status=200, **kwargs):
        response = self.client.post(self.path + suffix, json=body, **kwargs)
        self.assertEqual(response.status_code, status, response.text)
        return response.json()

    def plan(self):
        result = self.client.get(self.path)
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def fields(self, plan=None):
        current = plan or self.plan()
        return {"revision_evaluacion": current["revision_evaluacion_actual"],
                "revision_esperada": current["revision_respuesta"], "motivo": REASON}

    def open_plan(self):
        plan = self.plan()
        self.assertEqual(plan["estado"], "sin_respuesta")
        self.assertEqual(plan["borrador"]["eventos"], [EID])
        return self.request_post("", {"revision_evaluacion": plan["revision_evaluacion_actual"], "objetivo": "Comprobar el alcance",
                                 "alcance": "Sensores de laboratorio", "criterio_cierre": "Cotejar los resultados"}, 201)

    def propose(self, **overrides):
        return self.request_post("/acciones", self.fields() | PROPOSAL | overrides, 201)

    def move(self, action, operation, status=200, **data):
        body = self.fields() | {"revision_esperada": action["revision_accion"], "operacion": operation} | data
        return self.request_post("/acciones/" + action["id_accion"] + "/transiciones", body, status)

    def test_full_lifecycle_evidence_report_and_audit(self):
        admin, *_ = self.enroll(6881, admin=True)
        self.open_plan()
        row = self.propose(justificacion="Resultado de ejemplo " + SECRET)
        self.assertNotIn(SECRET, json.dumps(row))
        self.move(row, "iniciar", 409)
        approved = self.move(row, "aprobar")
        self.move(row, "aprobar", 409)
        assigned = self.move(approved, "asignar", id_responsable=str(admin))
        current = self.move(assigned, "iniciar")
        self.move(current, "ejecutar", 422, resultado=REASON)
        executed = self.move(current, "ejecutar", resultado=REASON, eventos=[EID])
        returned = self.move(executed, "devolver", resultado=REASON, referencia="Ticket de prueba 657")
        current = self.move(returned, "iniciar")
        executed = self.move(current, "ejecutar", resultado=REASON, eventos=[EID])
        self.assertEqual(self.move(executed, "verificar", resultado=REASON, eventos=[EID])["estado"], "verificada")
        details = self.client.get(self.path+"/acciones/"+row["id_accion"]).json()
        self.assertTrue(any(item["id_evento"] == EID for item in details["evidencia"]))
        self.assertEqual(self.request_post("/transiciones", self.fields() | {"operacion":"resolver",
            "resultado":REASON, "riesgos_pendientes":"Riesgos revisados sin hallazgos adicionales",
            "referencia":"Registro de verificación 123"})["estado"], "resuelto")
        self.assertEqual(self.request_post("/transiciones", self.fields() | {"operacion":"cerrar",
            "resultado":REASON, "referencia":"Registro de cierre 123"})["estado"], "cerrado")
        preview = self.client.get(self.path+"/informe")
        self.assertEqual(preview.status_code, 200, preview.text)
        result = preview.json()
        self.assertNotIn(SECRET, preview.text)
        self.assertIn(EID, preview.text)
        for fmt in ("docx", "pdf"):
            reply = self.client.get(self.path+"/informe", params={"formato":fmt, "snapshot":result["snapshot"]})
            self.assertEqual(reply.status_code, 200, reply.text if reply.status_code != 200 else "")
            self.assertEqual(reply.headers["x-tacticlens-snapshot"], result["snapshot_id"])
            if fmt == "docx":
                doc = Document(BytesIO(reply.content))
                plain = " ".join([p.text for p in doc.paragraphs] + [
                    cell.text for table in doc.tables for record in table.rows for cell in record.cells])
            else:
                from pypdf import PdfReader
                plain = " ".join(p.extract_text() for p in PdfReader(BytesIO(reply.content)).pages)
            self.assertIn(result["snapshot_id"], plain)
            self.assertIn(EID, plain)
            self.assertNotIn(SECRET, plain)
        with patch("backend.incident_response_report.snapshot_ttl", return_value=-1):
            self.assertEqual(self.client.get(self.path+"/informe", params={
                "formato":"docx", "snapshot":result["snapshot"]}).status_code, 410)
        self.assertEqual(self.request_post("/transiciones", self.fields() | {"operacion":"reabrir"})["estado"], "en_respuesta")
        self.assertEqual(self.client.get(self.path+"/informe", params={
            "formato":"docx", "snapshot":result["snapshot"]}).status_code, 409)
        history = self.client.get(self.path+"/historial", params={"limite":2}).json()
        self.assertEqual(history["items"][0]["operacion"], "reabrir")
        self.assertIsNotNone(history["cursor"])
        table = app.state.tables["auth_auditoria"]
        self.assertTrue(self.connection.scalar(select(table.c.id_auditoria).where(table.c.tipo=="respuesta_incidente_cerrar")))

    def test_stale_evaluation_and_ineligible_cancellation(self):
        self.enroll(6882, admin=True)
        self.open_plan()
        row = self.propose()
        self.revision(2)
        self.assertTrue(self.plan()["desactualizada"])
        self.move(row, "aprobar", 409)
        self.request_post("/revisiones", self.fields() | {"objetivo":"Comprobar el alcance",
            "alcance":"Sensores de laboratorio", "criterio_cierre":"Cotejar los resultados",
            "ratificar":[row["id_accion"]], "cancelar":[]})
        updated = self.client.get(self.path+"/acciones/"+row["id_accion"]).json()
        self.assertEqual(updated["revision_validada"], 2)
        self.revision(3, "evidencia_insuficiente")
        self.move(updated, "cancelar")
        self.assertEqual(self.request_post("/transiciones", self.fields() | {"operacion":"cancelar"})["estado"], "cancelado")
        self.request_post("/transiciones", self.fields() | {"operacion":"reabrir"}, 409)
        self.revision(4)
        self.assertEqual(self.request_post("/transiciones", self.fields() | {"operacion":"reabrir"})["revision_plan"], 4)

    def test_changed_cowrie_evidence_blocks_operational_approval_without_deleting_history(self):
        self.enroll(6891, admin=True)
        self.open_plan()
        action = self.propose()
        events = app.state.tables["evento"]
        self.connection.execute(events.update().where(events.c.id_evento == int(EID)).values(
            datos_originales={"eventid":"cowrie.login.success", "username":"fixture-modificado"}))
        current = self.plan()
        self.assertTrue(current["desactualizada"])
        self.assertFalse(current["elegible"])
        self.move(action, "aprobar", 409)
        self.assertEqual(self.client.get(self.path+"/acciones").json()["items"][0]["estado"], "propuesta")

    def test_scope_roles_assignee_and_foreign_evidence(self):
        self.enroll(6883, admin=True)
        self.open_plan()
        self.request_post("/acciones", self.fields() | PROPOSAL | {"eventos":["999"]}, 422)
        action = self.propose()
        user, *_ = self.enroll(6884)
        self.move(action, "aprobar", 403)
        self.propose(medida="Otra propuesta manual")
        self.enroll(6885, admin=True)
        self.move(action, "asignar", id_responsable=str(user))
        table = app.state.tables["usuario"]
        self.connection.execute(table.update().where(table.c.id_usuario == user).values(activo=False))
        self.move(self.client.get(self.path+"/acciones/"+action["id_accion"]).json(),
                  "asignar", 422, id_responsable=str(user))
        foreign_sensor, foreign_sid = uuid4(), uuid4()
        tables = app.state.tables
        self.connection.execute(tables["honeypot"].insert().values(id_honeypot=foreign_sensor, nombre="Aislado", host="localhost"))
        self.connection.execute(tables["sesion"].insert().values(id_sesion=foreign_sid, id_honeypot=foreign_sensor,
            cowrie_session_id=str(foreign_sid), fecha_inicio=self.clock))
        self.revision(2, sessions=[str(self.sid), str(foreign_sid)])
        self.assertEqual(self.client.get(self.path).status_code, 404)
        self.assertEqual(self.client.get(self.path+"/informe").status_code, 404)
        board = self.client.get("/api/respuestas-incidentes/acciones").json()
        self.assertFalse(board["items"])
        self.client.cookies.clear()
        self.assertEqual(self.client.get(self.path).status_code, 401)

    def test_import_preserves_historical_task_and_deduplicates_both_sources(self):
        self.enroll(6888, admin=True)
        tables = app.state.tables
        item = {"salvaguarda":"Contrastar registro histórico", "objetivo":"Confirmar el alcance autorizado",
                "validacion":"Comparar registros históricos de prueba", "eventos":[EID]}
        analysis = self.connection.scalar(tables["analisis_llm"].insert().values(
            id_modelo=ensure_model(self.connection), id_sesion=self.sid, estado="completado", fecha_inicio=self.clock,
            fecha_fin=self.clock, resultado_estructurado={"informe":{"recomendaciones":[item]}})
            .returning(tables["analisis_llm"].c.id_analisis))
        legacy = self.connection.scalar(tables["salvaguarda"].insert().values(id_sesion=self.sid, huella="c"*64,
            nombre=item["salvaguarda"], nivel_riesgo="medio").returning(tables["salvaguarda"].c.id_salvaguarda))
        self.connection.execute(tables["salvaguarda_origen"].insert().values(id_analisis=analysis,
            posicion=1, id_salvaguarda=legacy, recomendacion=item, valoracion={}))
        self.revision(2, analysis=analysis)
        self.open_plan()
        source = self.client.get(self.path+"/antecedentes").json()["items"][0]
        self.assertTrue(source["importable"])
        a = self.request_post("/importaciones", self.fields() | {"fase":"verificacion",
            "id_salvaguarda":str(legacy)}, 201)
        b = self.request_post("/importaciones", self.fields() | {"fase":"verificacion",
            "id_analisis":str(analysis), "posicion":1}, 201)
        self.assertEqual(a["estado"], "propuesta")
        self.assertEqual(a["id_accion"], b["id_accion"])
        self.assertEqual(self.connection.scalar(select(tables["salvaguarda"].c.estado).where(
            tables["salvaguarda"].c.id_salvaguarda == legacy)), "pendiente")

    def test_missing_d1_disables_only_response_routes(self):
        self.enroll(6889, admin=True)
        with patch("backend.incident_response.evaluation_for_response",
                   side_effect=HTTPException(503, "Integración pendiente")):
            self.assertEqual(self.client.get(self.path).status_code, 503)
        self.assertEqual(self.client.get("/api/salvaguardas").status_code, 200)

    def test_lease_blocks_concurrent_reservation_and_integrity_rejects_wrong_revision(self):
        from sqlalchemy.exc import IntegrityError
        from backend.incident_response_models import Change
        from backend.incident_response_recommendations import reserve
        from backend.incident_response_routes import context
        from fastapi import Request
        self.enroll(6890, admin=True)
        plan = self.open_plan()
        # Exercise a duplicate while the first attempt is reserved and no provider has answered.
        scope = {"type":"http", "app":app, "method":"POST", "path":self.path, "headers":[
            (b"cookie", "; ".join(f"{name}={value}" for name,value in self.client.cookies.items()).encode()),
            (b"user-agent", self.client.headers["user-agent"].encode())],
            "client":("127.0.0.1",51000), "scheme":"http", "server":("127.0.0.1",8000)}
        req = Request(scope)
        body = Change.model_validate(self.fields(plan))
        with patch("backend.incident_response_recommendations.configuration",
                   return_value=("https://fixture.invalid/v1","fixture","key",2,2)):
            with self.connection.begin_nested():
                first, work = reserve(context(self.connection, req, self.iid, write=True), body, "synthetic-one")
                self.assertIsNotNone(work)
            with self.connection.begin_nested():
                second, work = reserve(context(self.connection, req, self.iid, write=True), body, "synthetic-two")
                self.assertEqual(first["id_lote"], second["id_lote"])
                self.assertIsNone(work)
        responses = app.state.tables["incidente_respuesta"]
        with self.assertRaises(IntegrityError), self.connection.begin_nested():
            self.connection.execute(responses.update().where(responses.c.id_incidente == self.iid).values(revision_plan=987))

    def provider(self, item):
        return httpx.Response(200, request=httpx.Request("POST", "https://fixture.invalid/v1/chat/completions"),
            json={"choices":[{"finish_reason":"stop","message":{"content":json.dumps(item)}}]})

    def test_llm_replays_redacts_abstains_and_rejects_wrong_citations(self):
        self.enroll(6886, admin=True)
        self.open_plan()
        config = ("https://fixture.invalid/v1","deepseek-fixture","synthetic-key",2,2)
        with patch("backend.incident_response_recommendations.configuration", return_value=config), patch(
            "backend.incident_response_recommendations.post_provider", return_value=self.provider(
                {"sugerencias":[PROPOSAL],"abstencion":None})) as provider:
            first = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-llm-1"})
            same = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-llm-1"})
            different = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-llm-2"})
            self.assertEqual(first["estado"], "completado")
            self.assertEqual(first["id_lote"], same["id_lote"])
            self.assertEqual(first["id_lote"], different["id_lote"])
            self.assertEqual(provider.call_count, 1)
            self.assertNotIn(SECRET, json.dumps(provider.call_args.kwargs["json"]))
        for model, output, expected in (("ds-b", {"sugerencias":[], "abstencion":"Evidencia insuficiente"}, "completado"),
               ("ds-c", {"sugerencias":[PROPOSAL | {"eventos":["1"]}]}, "fallido")):
            with patch("backend.incident_response_recommendations.configuration", return_value=(
                config[0], model, *config[2:])), patch("backend.incident_response_recommendations.post_provider",
                                                       return_value=self.provider(output)):
                lot = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-"+model})
                self.assertEqual(lot["estado"], expected)
        self.assertEqual(len(self.client.get(self.path+"/acciones").json()["items"]), 1)

    def test_llm_timeout_and_stale_result_preserve_last_decisions(self):
        self.enroll(6887, admin=True)
        self.open_plan()
        approved = self.move(self.propose(), "aprobar")
        config = ("https://fixture.invalid/v1","deepseek-fixture","synthetic-key",2,2)
        with patch("backend.incident_response_recommendations.configuration", return_value=config):
            with patch("backend.incident_response_recommendations.post_provider", side_effect=httpx.ReadTimeout("synthetic")):
                lot = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-timeout"})
                self.assertEqual(lot["estado"], "vencido")
            def stale(_):
                self.revision(2)
                return Recommendations(sugerencias=[PROPOSAL]), None
            with patch("backend.incident_response_recommendations.generate", side_effect=stale):
                lot = self.request_post("/recomendaciones", self.fields(), headers={"Idempotency-Key":"synthetic-stale"})
                self.assertEqual(lot["estado"], "sustituido")
        actions = self.client.get(self.path+"/acciones").json()["items"]
        self.assertEqual([(row["id_accion"], row["estado"]) for row in actions], [(approved["id_accion"],"aprobada")])


@skipUnless(ISOLATED, "requires incident response fixture on the isolated PostgreSQL port")
class ResponseConcurrencyTests(TestCase):
    def test_two_transactions_compete_for_last_wip_slot(self):
        engine = database_engine()
        token = uuid4().hex
        meta = MetaData()
        config = Table("config_"+token, meta, Column("id", Integer, primary_key=True),
                       Column("wip_activo", Boolean), Column("limite_wip", Integer))
        actions = Table("action_"+token, meta, Column("id", Integer, primary_key=True), Column("estado", String))
        tables = {"incidente_respuesta_config":config, "incidente_accion":actions}
        self.addCleanup(engine.dispose)
        with engine.begin() as conn:
            meta.create_all(conn)
            self.addCleanup(meta.drop_all, engine)
            conn.execute(config.insert().values(id=1,wip_activo=True,limite_wip=1))
            conn.execute(actions.insert(), [{"id":n,"estado":"aprobada"} for n in (1,2)])
        start = Barrier(2,timeout=5)
        def write(n):
            with engine.begin() as conn:
                start.wait()
                allowed = wip_available(conn,tables)
                if allowed:
                    conn.execute(actions.update().where(actions.c.id==n).values(estado="en_curso"))
                return allowed
        with ThreadPoolExecutor(2) as pool:
            self.assertCountEqual(pool.map(write,(1,2)), [True,False])

    def test_notification_is_delivered_only_after_commit(self):
        engine = database_engine()
        self.addCleanup(engine.dispose)
        with psycopg.connect(**engine.url.translate_connect_args(username="user", database="dbname"), autocommit=True) as monitor:
            monitor.execute("LISTEN " + CHANNEL)
            with engine.connect() as conn:
                notify_change(conn, ["synthetic-response"], "respuesta_incidentes")
                self.assertEqual(list(monitor.notifies(timeout=0.1)), [])
                conn.rollback()
            self.assertEqual(list(monitor.notifies(timeout=0.1)), [])
            with engine.begin() as conn:
                notify_change(conn, ["synthetic-response"], "respuesta_incidentes")
            notices = list(monitor.notifies(timeout=2, stop_after=1))
            self.assertEqual(json.loads(notices[0].payload)["dominios"], ["respuesta_incidentes"])
