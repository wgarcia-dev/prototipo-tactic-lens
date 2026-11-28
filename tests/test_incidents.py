from datetime import timedelta
import os
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

from sqlalchemy import select

from backend.analysis_state import evidence_snapshot
from backend.api import app
from backend.cowrie_provenance import SOURCES, capture
from backend.incident_assessment import assess
from backend.incidents import get_incident_for_response
from backend.routes import ensure_model
from test_auth import AuthFixture

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
