from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
import json
import os
from threading import Event
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select
from backend.api import app
from backend.cowrie_import import import_events
from test_auth import AuthFixture


def raw(name="fixture"):
    return {"eventid": "cowrie.command.input", "session": name,
            "timestamp": datetime.now(timezone.utc).isoformat(), "input": "pwd"}


class ImportParserTests(unittest.TestCase):
    def test_formats_preserve_identity_and_error_locations(self):
        event = raw()
        ids = []
        def persist(batch, **kwargs):
            ids.extend(item["_collector"]["source_id"] for item in batch)
            return {"insertados":len(batch), "duplicados":0, "confirmaciones":[]}
        for source in (json.dumps(event, indent=2), json.dumps([event]), json.dumps(event)+"\ninvalid\n7"):
            result = import_events(BytesIO(source.encode()), persist)
            self.assertEqual(result["insertados"], 1)
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(result["errores"], [{"linea":2,"error":"json_invalido"},{"linea":3,"error":"se_esperaba_un_objeto"}])

    def test_positions_validation_size_record_limit_and_batch(self):
        sink = Mock(return_value={"insertados":1,"duplicados":0,"confirmaciones":[]})
        with patch.dict(os.environ, {"COWRIE_IMPORT_MAX_BYTES":"10"}), self.assertRaises(HTTPException) as error:
            import_events(BytesIO(b"x"*11), sink)
        self.assertEqual(error.exception.status_code, 413)
        with patch.dict(os.environ, {"COWRIE_IMPORT_MAX_RECORDS":"1"}), self.assertRaises(HTTPException) as error:
            import_events(BytesIO(b"[{},{}]"), sink)
        self.assertEqual(error.exception.status_code, 413)
        sink.assert_not_called()
        with patch.dict(os.environ, {"COWRIE_IMPORT_BATCH_SIZE":"1"}):
            result=import_events(BytesIO(json.dumps([raw(),{"password":"synthetic-fixture"},raw()]).encode()),sink)
        self.assertEqual(sink.call_count, 2)
        self.assertEqual(result["errores"], [{"posicion":2,"error":"estructura_invalida"}])
        self.assertNotIn("synthetic-fixture", str(result))


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H1016") == "1", "requires disposable PostgreSQL")
class ImportHttpTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if os.getenv("DATABASE_NAME") != "tacticlens_h02_h05_h1016" or os.getenv("DATABASE_PORT") != "56588":
            raise RuntimeError("Se requiere la base desechable H10–H16")
        super().setUpClass()

    def test_partial_persistence_and_equivalent_reimport(self):
        self.enroll(8100,admin=True)
        name=uuid4().hex
        event=raw(name)
        first=self.client.post("/api/ingesta/cowrie",files={"file":("cowrie.json",json.dumps([event,{},event]))})
        self.assertEqual(first.status_code,200,first.text)
        self.assertEqual((first.json()["insertados"],first.json()["rechazados"]), (2,1))
        second=self.client.post("/api/ingesta/cowrie",files={"file":("cowrie.jsonl","\n".join([json.dumps(event)]*2))})
        self.assertEqual(second.json()["duplicados"],2)
        sessions=app.state.tables["sesion"]
        self.assertEqual(self.connection.scalar(select(sessions.c.revision_eventos).where(sessions.c.cowrie_session_id==name)),2)

    def test_slow_import_leaves_health_responsive(self):
        self.enroll(8101,admin=True)
        entered,release=Event(),Event()
        def slow(*args):
            entered.set()
            release.wait(3)
            return {"insertados":0}
        with patch("backend.cowrie_import.import_events",side_effect=slow), ThreadPoolExecutor(2) as pool:
            job=pool.submit(self.client.post,"/api/ingesta/cowrie",files={"file":("cowrie.json","{}")})
            try:
                self.assertTrue(entered.wait(1))
                response=pool.submit(self.client.get,"/api/health").result(1.5)
                self.assertEqual(response.status_code,200)
            finally:
                release.set()
            self.assertEqual(job.result(2).status_code,200)
