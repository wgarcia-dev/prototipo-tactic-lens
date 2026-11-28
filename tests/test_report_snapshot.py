from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
import os
import unittest
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from docx import Document
from sqlalchemy import select
from backend.api import app
from test_auth import AuthFixture


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H1016")=="1","requires disposable PostgreSQL")
class ReportSnapshotTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if os.getenv("DATABASE_NAME")!="tacticlens_h02_h05_h1016" or os.getenv("DATABASE_PORT")!="56588":
            raise RuntimeError("Se requiere PostgreSQL desechable")
        super().setUpClass()

    def ingest(self,name):
        response=self.client.post("/api/ingesta/eventos",json={"eventos":[{
            "eventid":"cowrie.command.input","session":name,"timestamp":datetime.now(timezone.utc).isoformat(),
            "src_ip":"192.0.2.51","input":"wget http://snapshot.corp.local/fixture",
            "_collector":{"source_id":uuid4().hex}}]},headers={"x-api-key":os.environ["INGEST_API_KEY"]})
        self.assertEqual(response.status_code,200,response.text)

    def test_real_exports_pin_content_limits_and_stale_access(self):
        from pypdf import PdfReader
        self.enroll(8250,admin=True)
        name=uuid4().hex
        self.ingest(name)
        t=app.state.tables
        session=self.connection.scalar(select(t["sesion"].c.id_sesion).where(t["sesion"].c.cowrie_session_id==name))
        model=self.connection.scalar(t["modelo_llm"].insert().values(proveedor="fixture",nombre_modelo=uuid4().hex,
                     version_modelo="test").returning(t["modelo_llm"].c.id_modelo))
        analysis=self.connection.scalar(t["analisis_llm"].insert().values(id_sesion=session,id_modelo=model,estado="completado",
            fecha_inicio=datetime.now(timezone.utc),fecha_fin=datetime.now(timezone.utc),
            resumen="Resumen documental de prueba",resultado_estructurado={"eventos_analizados":1}).returning(t["analisis_llm"].c.id_analisis))
        self.connection.execute(t["evento"].insert(),[
           {"id_sesion":session,"tipo_evento":"cowrie.command.input","numero_secuencia":i+2,
            "fecha_hora":datetime.now(timezone.utc),"datos_originales":{"input":"pwd","eventid":"cowrie.command.input"}}
           for i in range(505)])
        url=f"/api/sesiones/{session}/informe"
        preview=self.client.get(url,params={"id_analisis":str(analysis)})
        self.assertEqual(preview.status_code,200,preview.text)
        data=preview.json()
        limits={item["seccion"]: item for item in data["cobertura_secciones"]}
        self.assertEqual(limits["Registro de comandos"]["omitidos"],6)
        self.assertEqual(self.client.get(url,params={"formato":"docx"}).status_code,428)
        params={"snapshot":data["snapshot"]}
        wanted=(data["snapshot_id"],"Resumen documental de prueba","Cobertura por sección")
        for format in ("pdf","docx"):
            reply=self.client.get(url,params={**params,"formato":format})
            self.assertEqual(reply.status_code,200,reply.text if reply.status_code!=200 else "")
            self.assertEqual(reply.headers["X-TacticLens-Snapshot"],data["snapshot_id"])
            if format=="pdf":
                document=PdfReader(BytesIO(reply.content))
                rendered=" ".join(page.extract_text() for page in document.pages)
                self.assertGreater(len(document.pages),2)
            else:
                document=Document(BytesIO(reply.content))
                rendered=" ".join([p.text for p in document.paragraphs]+[
                    cell.text for table in document.tables for row in table.rows for cell in row.cells])
            for marker in wanted:
                self.assertIn(marker," ".join(rendered.split()))
        with patch("backend.report_snapshot.snapshot_ttl",return_value=-1):
            expired=self.client.get(url,params={**params,"formato":"docx"})
        self.assertEqual(expired.status_code,410)
        obs=t["observacion_ioc"]
        observed=self.connection.scalar(select(obs.c.id_observacion).where(obs.c.id_evento.in_(
            select(t["evento"].c.id_evento).where(t["evento"].c.id_sesion==session))).limit(1))
        review=self.client.patch(f"/api/inteligencia/observacion_ioc/{observed}/revision",json={
            "estado":"descartado","motivo":"Revisión posterior a la vista previa","revision_esperada":None})
        self.assertEqual(review.status_code,200,review.text)
        self.assertEqual(self.client.get(url,params={**params,"formato":"docx"}).status_code,409)
        changed=self.client.get(url).json()
        entered, release=Event(),Event()
        def render(canonical):
            self.assertEqual(canonical["snapshot_id"],changed["snapshot_id"])
            entered.set()
            release.wait(4)
            return b"fixture export in progress"
        with patch("backend.report_export.render_docx", side_effect=render), ThreadPoolExecutor(1) as pool:
            export=pool.submit(self.client.get,url,params={"snapshot":changed["snapshot"],"formato":"docx"})
            try:
                self.assertTrue(entered.wait(2))
                self.ingest(name)
            finally:
                release.set()
            self.assertEqual(export.result(3).headers["X-TacticLens-Snapshot"],changed["snapshot_id"])
        self.assertEqual(self.client.get(url,params={"snapshot":changed["snapshot"],"formato":"pdf"}).status_code,409)
        self.client.cookies.clear()
        self.assertEqual(self.client.get(url,params={**params,"formato":"docx"}).status_code,401)
