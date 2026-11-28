from datetime import timedelta
import json
import os
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

from sqlalchemy import select
import httpx

from backend.analysis_state import evidence_snapshot
from backend.api import app
from backend.cowrie_provenance import SOURCES, capture
from backend.incident_assessment import assess
from backend.incidents import get_incident_for_response
from backend.routes import ensure_model
from test_auth import AuthFixture
import test_rag as rag_fixtures

ISOLATED = (os.getenv("DATABASE_HOST"), os.getenv("DATABASE_PORT"), os.getenv("DATABASE_NAME")) == (
    "127.0.0.1", "56591", "tacticlens_incidentes_integracion")
REASON = "Contrastación de la evidencia en el expediente sintético"
SHA256 = "a3"*32
SECRET = "SecretoCowrieSinteticoParaPruebas7812"
EID = 9007199254740993


class AttributionTests(TestCase):
    def test_port_hint_is_not_identity_and_mismatch_is_retained_conservatively(self):
        registry = {mode: uuid4() for mode in SOURCES}
        base = uuid4()
        for mode,(label,kind,port) in SOURCES.items():
            instance, data = capture({"sensor":label,"instance_type":kind,"dst_port":port}, registry, base)
            self.assertEqual(instance, registry[mode])
            self.assertEqual(data["modalidad"], mode)
        self.assertEqual(capture({"dst_port":2222,"instance_type":"shell"},registry,base)[0],base)
        chosen, data = capture({"sensor":"tacticlens-cowrie-proxy","dst_port":2222},registry,base)
        self.assertEqual((chosen,data["estado"]),(base,"conflicto"))


@skipUnless(ISOLATED, "requires the incident integration database on port 56591")
class IncidentsTests(AuthFixture):
    def setUp(self):
        super().setUp()
        self.registry = {name: uuid4() for name in SOURCES}
        instances = patch.object(app.state, "instances", self.registry)
        instances.start()
        self.addCleanup(instances.stop)
        self.connection.execute(app.state.tables["honeypot"].insert(), [
            {"id_honeypot": value, "nombre": SOURCES[key][0], "host":"localhost"} for key,value in self.registry.items()])

    def telemetry(self, mode, *, start=None, marker=SHA256, origin="192.0.2.44", include_login=False):
        source = uuid4().hex
        label, kind, port = SOURCES[mode]
        when = start or self.clock
        values = {"session":source,"src_ip":origin,"dst_port":int(port),"sensor":label,"instance_type":kind,
                  "backend_label":"guest-fixture","eventid":"cowrie.session.file_download","shasum":marker,"size":42,
                  "timestamp":when.isoformat(),"_collector":{"source_id":"sqlite:"+source+":1"}}
        batch = [values]
        if include_login:
            batch.append({**values, "eventid":"cowrie.login.success", "password":SECRET, "username":"fixture",
                          "timestamp":(when+timedelta(seconds=1)).isoformat(),
                          "_collector":{"source_id":"sqlite:"+source+":2","instance_id":mode}})
        reply = self.client.post("/api/ingesta/eventos",json={"eventos":batch},headers={"X-API-Key":app.state.api_key})
        self.assertEqual(reply.status_code,200,reply.text)
        event = app.state.tables["evento"]
        eid = reply.json()["confirmaciones"][0]["id_evento"]
        row = self.connection.execute(select(event).where(event.c.id_evento==eid)).mappings().one()
        self.assertEqual(row.datos_originales,{key:value for key,value in values.items() if key!="_collector"})
        self.assertEqual(row.procedencia_cowrie["modalidad"],mode)
        return row.id_sesion, row.id_evento

    def saved_analysis(self, sid, severity="S2"):
        events, analysis = (app.state.tables[key] for key in ("evento","analisis_llm"))
        selected = self.connection.execute(select(events).where(events.c.id_sesion==sid)).all()
        triage = assess(selected)
        triage["clasificacion"] = "actividad_sospechosa_sustentada"
        report = {"vigencia_snapshot":evidence_snapshot(selected), "evaluacion_incidente":triage,
                  "evaluacion_amenaza":{"codigo_severidad":severity,"prioridad_investigacion":"media"},
                  "evaluacion_impacto":{"impacto_potencial":"medio",
                                       "integridad":{"estado_observado":"IO02","fundamento":"Intento observado"}}}
        return self.connection.scalar(analysis.insert().values(id_sesion=sid,id_modelo=ensure_model(self.connection),
            estado="completado",fecha_inicio=self.clock,fecha_fin=self.clock,resumen="Análisis sintético",resultado_estructurado=report)
            .returning(analysis.c.id_analisis))

    def case_from(self, aid, status=201):
        reply = self.client.post("/api/incidentes", json={"id_analisis":str(aid),"motivo":REASON})
        self.assertEqual(reply.status_code,status,reply.text)
        return reply.json()

    def review(self, case, *, expected=None, decision="incidente_confirmado", status=201, **overrides):
        data = {"revision_esperada":case["revision_evaluacion"] if expected is None else expected,
                "decision":decision,"severidad":"S2","prioridad":"media","motivo":REASON,
                "resumen":"Resultado: interacción en Cowrie, alcance externo pendiente",
                "eventos":[item["id_evento"] for item in case["evidencias"]]} | overrides
        reply = self.client.post(f"/api/incidentes/{case['id_incidente']}/revisiones",json=data)
        self.assertEqual(reply.status_code,status,reply.text)
        return reply.json()

    def test_three_modalities_and_correlated_cases_reuse_saved_analyses(self):
        self.enroll(7931,admin=True)
        a, _ = self.telemetry("cowrie_shell", include_login=True)
        b, _ = self.telemetry("cowrie_proxy",start=self.clock+timedelta(minutes=10))
        c, _ = self.telemetry("cowrie_llm",start=self.clock+timedelta(minutes=11),marker="b4"*32)
        aid = self.saved_analysis(a)
        first = self.case_from(aid)
        self.assertEqual(self.case_from(aid)["id_incidente"],first["id_incidente"])
        merged = self.case_from(self.saved_analysis(b))
        separate = self.case_from(self.saved_analysis(c))
        self.assertEqual(merged["id_incidente"],first["id_incidente"])
        self.assertNotEqual(separate["id_incidente"],first["id_incidente"])
        self.assertEqual(merged["revision_evaluacion"],2)
        self.assertEqual({item["procedencia"]["modalidad"] for item in merged["evidencias"]},{"cowrie_shell","cowrie_proxy"})
        self.assertEqual(merged["correlaciones"][1]["metodo"],"sha256_origen_60m_v1")
        self.assertNotIn("resultado_confirmado",{item["grado"] for item in merged["evidencias"]})
        path = "/api/incidentes/"+merged["id_incidente"]
        detail = self.client.get(path)
        self.assertEqual(detail.status_code,200,detail.text)
        self.assertNotIn(SECRET,detail.text)
        self.assertTrue(detail.json()["iocs"])
        body=self.client.get("/api/incidentes",params={"limite":1,"orden":"severidad"}).json()
        self.assertEqual(len(body["items"]),1)
        self.assertTrue(body["cursor"])
        other=self.client.get("/api/incidentes",params={"limite":1,"orden":"severidad","cursor":body["cursor"]}).json()
        self.assertNotEqual(body["items"][0]["id_incidente"],other["items"][0]["id_incidente"])
        self.assertEqual(self.client.get("/api/incidentes",params={"modalidad":"cowrie_llm"}).json()["items"][
            0]["id_incidente"],separate["id_incidente"])
        self.assertEqual(self.client.get(path+"/evaluaciones/1").json()["alcance"]["sesiones"],[str(a)])

    def test_human_review_version_scope_and_integrity(self):
        actor,*_=self.enroll(7932,admin=True)
        sid,_=self.telemetry("cowrie_proxy")
        event=app.state.tables["evento"]
        self.connection.execute(event.insert().values(id_evento=EID,id_sesion=sid,numero_secuencia=2,
            tipo_evento="cowrie.command.input",fecha_hora=self.clock,datos_originales={"input":"pwd"}))
        first=self.case_from(self.saved_analysis(sid))
        self.review(first,status=422,eventos=["99"])
        self.review(first,status=422,impacto_confirmado="Afectación indicada sin documentación")
        result=self.review(first)
        self.assertEqual(result["decision"],"incidente_confirmado")
        self.assertIn(str(EID),{item["id_evento"] for item in result["evidencias"]})
        self.assertIsNone(result["detalle"]["impacto_confirmado"])
        self.review(first,status=409)
        projection=get_incident_for_response(self.connection,{"rol":"administrador","id_usuario":str(actor)},
                                             uuid4(),lock=True)
        self.assertIsNone(projection)
        analyst,*_=self.enroll(7933)
        self.review(result,status=403)
        with patch.object(app.state,"instances",{}):
            self.assertIsNone(get_incident_for_response(self.connection,{"rol":"analista","id_usuario":str(analyst)},
                                                       UUID(first["id_incidente"])))
        self.connection.execute(event.update().where(event.c.id_evento==EID).values(
            datos_originales={"eventid":"cowrie.session.file_download","shasum":"b9"*32}))
        detail=self.client.get("/api/incidentes/"+first["id_incidente"]).json()
        self.assertFalse(detail["evidencia_verificable"])
        self.assertEqual(detail["iocs"],[])

    def test_historical_identity_can_be_derived_without_rewriting_events(self):
        self.enroll(7936,admin=True)
        events, sessions = (app.state.tables[key] for key in ("evento","sesion"))
        for label, storage, mode in (
            ("ubuntuserver", self.registry["cowrie_proxy"], "desconocido"),
            ("tacticlens-cowrie-proxy", app.state.honeypot_id, "cowrie_proxy"),
            ("tacticlens-cowrie-proxy", self.registry["cowrie_llm"], "desconocido"),
        ):
            sid=self.connection.scalar(sessions.insert().values(id_honeypot=storage, cowrie_session_id=uuid4().hex,
                           fecha_inicio=self.clock).returning(sessions.c.id_sesion))
            raw={"eventid":"cowrie.session.connect","sensor":label,"instance_type":"proxy","dst_port":2223}
            eid=self.connection.scalar(events.insert().values(id_sesion=sid,numero_secuencia=1,
                fecha_hora=self.clock,tipo_evento=raw["eventid"],datos_originales=raw).returning(events.c.id_evento))
            response=self.client.get(f"/api/sesiones/{sid}")
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.json()["modalidad"],mode)
            stored=self.connection.execute(select(events.c.datos_originales,events.c.procedencia_cowrie)
                                           .where(events.c.id_evento==eid)).one()
            self.assertEqual(tuple(stored),(raw,None))

    def test_cowrie_llm_identification_through_response_close_and_reopen(self):
        if "incidente_respuesta" not in app.state.tables:
            self.skipTest("requires migration 017")
        admin,*_=self.enroll(7934,admin=True)
        sid, event_ids = rag_fixtures.RagIntegrationTests.session_with(self, ["whoami"], "cowrie_shell")
        candidate=rag_fixtures.proposal(code="T1033",tactic="TA0007",eventos=event_ids).model_dump()
        candidate["justificacion"]="El comando solicita conocer el usuario del entorno observado."
        with rag_fixtures.RagIntegrationTests.llm(self,event_ids,[candidate]) as provider:
            first=self.client.post(f"/api/sesiones/{sid}/analizar")
            self.assertEqual(first.status_code,200,first.text)
            replay=self.client.post(f"/api/sesiones/{sid}/analizar")
            self.assertEqual(replay.status_code,200,replay.text)
            self.assertTrue(replay.json()["reutilizado"])
            self.assertEqual(provider.call_count,1)
            self.assertIn("tacticlens-cowrie-01",json.dumps(provider.call_args.kwargs["json"]))
        cases=self.client.get("/api/incidentes",params={"id_sesion":str(sid)}).json()["items"]
        self.assertEqual(len(cases),1)
        path="/api/incidentes/"+cases[0]["id_incidente"]
        evaluation=self.client.get(path).json()
        self.assertEqual(evaluation["mitre"][0]["codigo_tecnica"],"T1033")
        self.assertEqual(evaluation["eventos"][0]["comando"],"whoami")
        self.assertEqual(evaluation["decision"],"actividad_sospechosa")
        confirmed=self.review(evaluation)
        self.assertTrue(confirmed["evidencia_verificable"])
        response=path+"/respuesta"
        revision=confirmed["revision_evaluacion"]

        def post(suffix, data, status=200, **kwargs):
            reply=self.client.post(response+suffix,json=data,**kwargs)
            self.assertEqual(reply.status_code,status,reply.text)
            return reply.json()

        current=post("", {"revision_evaluacion":revision, "objetivo":"Verificar el alcance observado",
                          "alcance":"Entorno autorizado de prueba", "criterio_cierre":"Contrastar la evidencia obtenida"},201)
        suggestions={"sugerencias":[{"fase":"verificacion","medida":"Contrastar la bitácora",
            "objetivo":"Confirmar el alcance de la actividad observada","justificacion":"Eventos del señuelo documentados",
            "criterio_verificacion":"Cotejar el resultado con evidencia autorizada",
            "eventos":[str(event_ids[0])]}]}
        result=httpx.Response(200,request=httpx.Request("POST","https://fixture.invalid/v1/chat/completions"),
            json={"choices":[{"finish_reason":"stop","message":{"content":json.dumps(suggestions)}}]})
        with patch("backend.incident_response_recommendations.post_provider",return_value=result) as mock:
            batch=post("/recomendaciones",{"revision_evaluacion":revision,"revision_esperada":current["revision_respuesta"],
                       "motivo":REASON},headers={"Idempotency-Key":"incidente-integral-fixture"})
            self.assertEqual(mock.call_count,1)
        self.assertEqual(batch["estado"],"completado")
        action_path="/acciones/"+batch["resultado"]["acciones"][0]
        item=self.client.get(response+action_path).json()
        for operation,values in (("aprobar",{}),("asignar",{"id_responsable":str(admin)}),("iniciar",{}),
                ("ejecutar",{"resultado":REASON,"eventos":[str(event_ids[0])]}),
                ("verificar",{"resultado":REASON,"referencia":"Registro independiente de prueba"})):
            item=post(action_path+"/transiciones",{"operacion":operation,"motivo":REASON,"revision_evaluacion":revision,
                                                  "revision_esperada":item["revision_accion"],**values})
        self.assertEqual(item["estado"],"verificada")
        current=self.client.get(response).json()
        for operation, values in (("resolver",{"resultado":REASON,"referencia":"Registro independiente de prueba",
                                               "riesgos_pendientes":"El alcance externo sigue pendiente de contraste"}),
                                  ("cerrar",{"resultado":REASON,"referencia":"Acta sintética de cierre"}),
                                  ("reabrir",{})):
            current=post("/transiciones",{"operacion":operation,"motivo":REASON,"revision_evaluacion":revision,
                                         "revision_esperada":current["revision_respuesta"],**values})
            self.assertEqual(current["estado"],{"resolver":"resuelto","cerrar":"cerrado","reabrir":"en_respuesta"}[operation])
        preview=self.client.get(response+"/informe")
        self.assertEqual(preview.status_code,200,preview.text)
        self.assertIn("tacticlens-cowrie-01",preview.text)
        self.assertIn(confirmed["evidencia_sha256"],preview.text)
        self.assertEqual(self.client.get(path+"/evaluaciones/1").json()["decision"],"actividad_sospechosa")

    def test_archive_opt_in_waits_for_pending_safeguards_without_removing_views(self):
        if "incidente_respuesta" not in app.state.tables:
            self.skipTest("requires migration 017")
        from backend.safeguards import configure_legacy_archive
        self.enroll(7935,admin=True)
        sid,_=self.telemetry("cowrie_shell")
        tasks=app.state.tables["salvaguarda"]
        task_id=self.connection.scalar(tasks.insert().values(id_sesion=sid,huella="e3"*32,
            nombre="Medida histórica abierta",nivel_riesgo="medio").returning(tasks.c.id_salvaguarda))
        with (
            patch.dict(os.environ, {"INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS":"true"}),
            patch.object(app.state, "safeguard_archive_active", False),
            patch.object(app.state, "safeguard_archive_requested", False),
        ):
            configure_legacy_archive(app,self.connection)
            status=self.client.get("/api/salvaguardas/archivo").json()
            self.assertEqual(status["tareas_por_conciliar"],1)
            self.assertFalse(status["archivo_activo"])
            self.connection.execute(tasks.update().where(tasks.c.id_salvaguarda==task_id).values(
                estado="realizada",iniciado_en=self.clock,finalizado_en=self.clock,
                id_responsable=UUID(self.client.get("/api/auth/me").json()["usuario"]["id_usuario"])))
            configure_legacy_archive(app,self.connection)
            self.assertTrue(self.client.get("/api/salvaguardas/archivo").json()["archivo_activo"])
            self.assertEqual(self.client.get(f"/api/salvaguardas/{task_id}").status_code,200)
            blocked=self.client.post(f"/api/salvaguardas/{task_id}/reapertura",json={"observacion":REASON})
            self.assertEqual(blocked.status_code,409,blocked.text)
