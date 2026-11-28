from datetime import datetime, timedelta, timezone
import os
import unittest
from uuid import uuid4
from test_auth import AuthFixture


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H1016")=="1","requires disposable PostgreSQL")
class CursorTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if os.getenv("DATABASE_NAME")!="tacticlens_h02_h05_h1016" or os.getenv("DATABASE_PORT")!="56588":
            raise RuntimeError("Se requiere PostgreSQL aislado")
        super().setUpClass()

    def test_newer_ingestion_does_not_repeat_rows_after_cursor(self):
        self.enroll(8270,admin=True)
        scope=uuid4().hex
        now=datetime.now(timezone.utc)
        def send(values):
            result=self.client.post("/api/ingesta/eventos",json={"eventos":[
                {"session":scope+str(i),"eventid":"cowrie.command.input","timestamp":(now+timedelta(seconds=i)).isoformat(),
                 "input":"pwd","_collector":{"source_id":uuid4().hex}} for i in values]},
                headers={"x-api-key":os.environ["INGEST_API_KEY"]})
            self.assertEqual(result.status_code,200,result.text)
        send((0,1,2,3))
        url="/api/sesiones"
        params={"limit":2,"q":scope}
        first=self.client.get(url,params=params).json()
        self.assertEqual([item["cowrie_session_id"] for item in first],[scope+"3",scope+"2"])
        send((4,))
        response=self.client.get(url,params={**params,"antes_fecha":first[-1]["fecha_inicio"],"antes_id":first[-1]["id_sesion"]})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual([item["cowrie_session_id"] for item in response.json()],[scope+"1",scope+"0"])
        self.assertEqual(self.client.get(url,params={**params,"antes_id":first[0]["id_sesion"]}).status_code,422)
