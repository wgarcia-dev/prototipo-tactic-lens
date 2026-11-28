from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import unittest
from uuid import uuid4

from sqlalchemy import func, select
from backend.api import app
from backend.realtime import PROTOCOL
from test_auth import AuthFixture


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H1016")=="1","requires disposable PostgreSQL")
class IntelligenceConsistencyTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if os.getenv("DATABASE_NAME")!="tacticlens_h02_h05_h1016" or os.getenv("DATABASE_PORT")!="56588":
            raise RuntimeError("Se requiere PostgreSQL aislado")
        super().setUpClass()

    def test_counts_public_health_and_zero_days(self):
        self.enroll(8210,admin=True)
        now=datetime.now(timezone.utc)
        self.client.post("/api/ingesta/eventos",json={"eventos":[
            {"session":uuid4().hex,"eventid":"cowrie.command.input","timestamp":(now-timedelta(days=days)).isoformat(),
             "input":"wget http://metricas.corp.local/fixture","_collector":{"source_id":uuid4().hex}}
            for days in (1,3)]},headers={"x-api-key":os.environ["INGEST_API_KEY"]})
        public=self.client.get("/api/health").json()
        self.assertEqual(set(public),{"status","database","contrato_ingesta"})
        status=self.client.get("/api/operacion").json()
        self.assertEqual(status["llm"]["disponibilidad_actual"],"desconocida")
        panel=self.client.get("/api/dashboard/resumen").json()
        ioc=self.client.get("/api/iocs/resumen").json()
        mitre=self.client.get("/api/mitre/resumen").json()
        self.assertEqual(panel["iocs"],ioc["totales"]["observables"])
        self.assertEqual(panel["tecnicas_mitre"],mitre["totales"]["tecnicas"])
        self.assertEqual(len(panel["actividad"]),7)
        self.assertTrue(any(row["total"]==0 for row in panel["actividad"]))
        restricted=self.client.get("/api/iocs/resumen",params={"q":"metricas.corp.local",
            "desde":(now-timedelta(days=4)).date().isoformat(),"hasta":now.date().isoformat()}).json()
        self.assertEqual(len(restricted["evolucion"]),5)
        self.assertTrue(any(row["observaciones"]==0 for row in restricted["evolucion"]))
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/operacion").status_code,401)

    def test_collective_review_and_concurrent_stale_version(self):
        self.enroll(210000+int(uuid4().hex[:4],16),admin=True)
        domain="ioc-"+uuid4().hex[:10]+".corp.local"
        self.outer.commit()
        self.outer=self.connection.begin()
        app.state.engine=self.engine
        with self.client.websocket_connect("/api/monitor/ws",subprotocols=[PROTOCOL]) as socket:
            self.assertEqual(socket.receive_json()["tipo"],"listo")
            reply=self.client.post("/api/ingesta/eventos",json={"eventos":[
                {"session":uuid4().hex,"eventid":"cowrie.command.input","timestamp":datetime.now(timezone.utc).isoformat(),
                 "input":"wget http://"+domain+"/fixture","_collector":{"source_id":uuid4().hex}} for _ in range(2)]},
                headers={"x-api-key":os.environ["INGEST_API_KEY"]})
            self.assertEqual(reply.status_code,200,reply.text)
            self.assertIn("iocs",socket.receive_json()["dominios"])
            ioc=app.state.tables["ioc"]
            with self.engine.connect() as conn:
                identifier=conn.scalar(select(ioc.c.id_ioc).where(ioc.c.valor=="http://"+domain+"/fixture"))
            url=f"/api/inteligencia/ioc/{identifier}/revision"
            before=self.client.get(url).json()
            self.assertEqual(before["afectadas"],2)
            with ThreadPoolExecutor(2) as workers:
                outcomes=list(workers.map(lambda state:self.client.patch(url,json={"estado":state,
                    "motivo":"Decisión de prueba concurrente","revision_esperada":before["revision"]}),["confirmado","descartado"]))
            self.assertEqual(sorted(response.status_code for response in outcomes),[200,409])
            accepted=next(response.json() for response in outcomes if response.status_code==200)
            self.assertEqual((accepted["colectiva"],accepted["afectadas"]),(True,2))
            self.assertIn("panel",socket.receive_json()["dominios"])
            audit=app.state.tables["auth_auditoria"]
            with self.engine.connect() as conn:
                entry=conn.scalar(select(audit.c.metadatos).where(audit.c.tipo=="inteligencia_revisada",
                    audit.c.metadatos["reason"].astext.contains(str(identifier))))
                self.assertEqual(entry["revision"]["afectadas"],2)
                self.assertEqual(len(entry["revision"]["anterior"]),2)
