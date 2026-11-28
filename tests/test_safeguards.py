from copy import deepcopy
from unittest import TestCase
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from backend.api import app
from backend.routes import ensure_model
from backend.safeguard_proposals import SafeguardReview, append_review
from backend.operational_report import analyst_sections
from backend.rag.mitre_evidence import CONTRACTS, VALIDATOR_VERSION
import test_collaborative_integration as fixtures
from test_auth import AuthFixture
from scripts.seed_catalog import seed_catalog


def decision(state, revision=0, **updates):
    return SafeguardReview(estado=state, revision_esperada=revision, responsable="Equipo de seguridad",
                          motivo="Medida revisada con el responsable del activo", **updates)


PAYLOAD = {"informe": {"recomendaciones": [{
    "salvaguarda": "Restringir SSH", "activo": "Servidor", "riesgo": "Acceso no autorizado",
    "objetivo": "Limitar acceso", "medidas": "Restringir orígenes", "validacion": "Probar acceso",
}]}}


class SafeguardUnitTests(TestCase):
    def test_history_preserves_original_and_rejects_conflicts(self):
        original = deepcopy(PAYLOAD)
        updated = append_review(original, "SG-001", decision("aprobada"), uuid4())
        self.assertEqual(original, PAYLOAD)
        self.assertEqual(updated["seguimiento_salvaguardas"]["SG-001"][0]["revision"], 1)
        with self.assertRaises(HTTPException) as failure:
            append_review(updated, "SG-001", decision("en_curso"), uuid4())
        self.assertEqual(failure.exception.status_code, 409)

    def test_verification_requires_progress_and_evidence(self):
        with self.assertRaises(HTTPException):
            append_review(PAYLOAD, "SG-001", decision("verificada"), uuid4())
        updated = append_review(PAYLOAD, "SG-001", decision("aprobada"), uuid4())
        updated = append_review(updated, "SG-001", decision("en_curso", 1), uuid4())
        with self.assertRaises(HTTPException):
            append_review(updated, "SG-001", decision("verificada", 2), uuid4())
        updated = append_review(updated, "SG-001", decision("verificada", 2,
            verificacion="Pruebas de acceso permitido y denegado archivadas en el ticket 42"), uuid4())
        report = analyst_sections({"id_sesion":"fixture", "metadata":[], "status":"Vigente", "sections":[]}, updated, [])
        text = str(report)
        self.assertIn("Historial de SG-001", text)
        self.assertIn("verificada", text)
        self.assertIn("ticket 42", text)


class SafeguardIntegrationTests(AuthFixture):
    event = fixtures.CollaborativeIntegrationTests.event
    ingest = fixtures.CollaborativeIntegrationTests.ingest

    def setUp(self):
        super().setUp()
        seed_catalog(self.connection, app.state.tables)

    def test_follow_up_is_scoped_versioned_and_persisted(self):
        self.enroll(81, admin=True)
        receipt = self.ingest([self.event()])["confirmaciones"][0]
        events, analyses = app.state.tables["evento"], app.state.tables["analisis_llm"]
        sid = self.connection.scalar(select(events.c.id_sesion).where(events.c.id_evento == receipt["id_evento"]))
        aid = self.connection.scalar(analyses.insert().values(
            id_sesion=sid, id_modelo=ensure_model(self.connection), estado="completado",
            fecha_inicio=self.clock, fecha_fin=self.clock, resultado_estructurado=PAYLOAD
        ).returning(analyses.c.id_analisis))
        path = f"/api/propuestas-salvaguardas?id_analisis={aid}"
        initial = self.client.get(path)
        self.assertEqual(initial.status_code, 200, initial.text)
        self.assertEqual(initial.json()[0]["estado"], "propuesta")
        endpoint = f"/api/analisis/{aid}/salvaguardas/SG-001/revision"
        response = self.client.post(endpoint, json=decision("aprobada").model_dump())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.post(endpoint, json=decision("aprobada").model_dump()).status_code, 409)
        self.assertEqual(self.client.post(endpoint.replace("SG-001", "SG-999"),
                                         json=decision("aprobada").model_dump()).status_code, 404)
        reviewed = self.client.get(path+"&estado=aprobada").json()[0]
        self.assertEqual(len(reviewed["historial"]), 1)
        self.assertIn(["Estado", "aprobada"], reviewed["ficha"]["rows"])
        report = self.client.get(f"/api/sesiones/{sid}/informe", params={"id_analisis": aid})
        self.assertEqual(report.status_code, 200, report.text)
        self.assertIn("Historial de SG-001", {section["title"] for section in report.json()["sections"]})
        self.assertEqual(self.client.get(path+"&estado=propuesta").json(), [])
        self.assertEqual(self.client.get(path+"&offset=25").json(), [])
        new = self.connection.scalar(analyses.insert().values(
            id_sesion=sid, id_modelo=ensure_model(self.connection), estado="completado",
            fecha_inicio=self.clock, fecha_fin=self.clock, resultado_estructurado=PAYLOAD
        ).returning(analyses.c.id_analisis))
        self.assertEqual(self.client.get(f"/api/propuestas-salvaguardas?id_analisis={new}").json()[0]["historial"], [])
        self.assertEqual(len(self.client.get(path).json()[0]["historial"]), 1)
        versions = self.client.get(f"/api/propuestas-salvaguardas?id_sesion={sid}").json()
        self.assertEqual({item["id_analisis"] for item in versions}, {str(aid), str(new)})
        self.assertEqual(self.client.get(f"/api/propuestas-salvaguardas?id_sesion={uuid4()}").json(), [])
        self.client.cookies.clear()
        self.assertEqual(self.client.get(path).status_code, 401)

    def test_analyst_reads_but_cannot_change_and_classifiers_are_visible(self):
        self.enroll(82)
        result = self.client.get("/api/mitre/clasificadores")
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["version"], VALIDATOR_VERSION)
        codes = {item["codigo"] for item in result.json()["clasificadores"]}
        self.assertEqual(codes, set(CONTRACTS))
        self.assertTrue({"T1098.004", "T1046", "T1018"} <= codes)
        self.assertEqual(self.client.post(f"/api/analisis/{uuid4()}/salvaguardas/SG-001/revision",
                                         json=decision("aprobada").model_dump()).status_code, 403)
