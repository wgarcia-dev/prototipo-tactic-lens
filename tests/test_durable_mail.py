from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
import re
from threading import Event
from uuid import uuid4
import unittest
from unittest.mock import patch

from fastapi import Request
from sqlalchemy import select

from backend.api import app
from backend.auth import mailer
from backend.auth.notifications import dispatch_pending
from backend.auth.recovery import create_request, send_approved_link, validated_token
from backend.auth.store import identity
from test_auth import AuthFixture


@unittest.skipUnless(os.getenv("TACTICLENS_ISOLATED_H1016")=="1","requires disposable PostgreSQL")
class DurableMailTests(AuthFixture):
    @classmethod
    def setUpClass(cls):
        if os.getenv("DATABASE_NAME")!="tacticlens_h02_h05_h1016" or os.getenv("DATABASE_PORT")!="56588":
            raise RuntimeError("Se requiere la base desechable H10–H16")
        super().setUpClass()

    def setUp(self):
        super().setUp()
        for name in ("backend.auth.notifications.now", "backend.auth.recovery.now"):
            clock=patch(name, side_effect=lambda:self.clock)
            clock.start()
            self.addCleanup(clock.stop)

    def setup_recovery(self):
        if not hasattr(self, "fixture_engine"):
            self.fixture_engine=app.state.engine
        app.state.engine=self.fixture_engine
        number=200000 + 2*int(uuid4().hex[:4],16)
        admin, _, secret, _ = self.enroll(number, admin=True)
        user, *_ = self.account(number+1,approve=True)
        self.outer.commit()
        self.outer=self.connection.begin()
        app.state.engine=self.engine
        request=Request({"type":"http","app":app,"method":"GET","path":"/fixture","headers":[],"query_string":b""})
        with self.engine.begin() as conn:
            target=identity(conn,request,user)
            record=create_request(conn,request,target)
        return request, record, admin, target, secret

    def state(self, record):
        q=app.state.tables["auth_solicitud_password"]
        with self.engine.connect() as conn:
            return conn.execute(select(q.c.estado,q.c.notificacion_estado).where(q.c.id_solicitud==record.id_solicitud)).one()

    def test_approval_commits_first_and_restart_safe_concurrent_dispatch(self):
        request,record,admin,target,secret=self.setup_recovery()
        with self.assertRaises(RuntimeError), self.engine.begin() as conn:
            send_approved_link(conn,request,target,record,admin,"Retroceso controlado")
            raise RuntimeError("rollback")
        with patch("backend.auth.mailer.deliver") as sender:
            dispatch_pending(app)
            self.assertEqual(sender.call_count, 0)
        self.assertEqual(self.state(record),("pendiente","pendiente"))
        payload={**self.reauth(secret),"decision":"aprobar","motivo":"Verificación manual de identidad"}
        approved=self.client.post(f"/api/auth/admin/recuperaciones/{record.id_solicitud}/resolver",json=payload)
        self.assertEqual(approved.status_code,200,approved.text)
        self.assertEqual(self.state(record),("aprobada","pendiente"))
        entered,release=Event(),Event()
        def send(_settings,_destination,_subject,body,**kwargs):
            token=re.search(r"#token=([a-z0-9]+)",body)[1]
            with self.engine.begin() as conn:
                self.assertEqual(validated_token(conn,request,token)[0].id_usuario,target.id_usuario)
            self.assertIn("tacticlens/notificacion/",kwargs["idempotency_key"])
            entered.set()
            release.wait(3)
        with patch("backend.auth.mailer.deliver",side_effect=send) as sender, ThreadPoolExecutor(2) as pool:
            one=pool.submit(dispatch_pending,app)
            try:
                self.assertTrue(entered.wait(2))
                pool.submit(dispatch_pending,app).result(2)
                self.assertEqual(sender.call_count,1)
            finally:
                release.set()
            one.result(3)
            dispatch_pending(app)
        self.assertEqual(self.state(record),("aprobada","enviada"))

    def test_retry_uncertain_and_expiration(self):
        request,record,admin,target,_=self.setup_recovery()
        with self.engine.begin() as conn:
            nid=send_approved_link(conn,request,target,record,admin,"Recuperación aprobada por seguridad")
        with patch("backend.auth.mailer.deliver",side_effect=TimeoutError("synthetic")):
            dispatch_pending(app)
        self.assertEqual(self.state(record),("aprobada","reintento"))
        q=app.state.tables["auth_notificacion"]
        with self.engine.begin() as conn:
            conn.execute(q.update().where(q.c.id_notificacion==nid).values(proximo_intento_en=self.clock-timedelta(seconds=1)))
        with patch("backend.auth.mailer.deliver",side_effect=mailer.DeliveryUncertain("synthetic")) as sender:
            dispatch_pending(app)
            dispatch_pending(app)
            self.assertEqual(sender.call_count,1)
        self.assertEqual(self.state(record),("aprobada","incierto"))

        request,record,admin,target,_=self.setup_recovery()
        with self.engine.begin() as conn:
            send_approved_link(conn,request,target,record,admin,"Solicitud caducada de prueba")
        self.clock+=timedelta(hours=2)
        with patch("backend.auth.mailer.deliver") as sender:
            dispatch_pending(app)
            self.assertEqual(sender.call_count, 0)
        self.assertEqual(self.state(record),("aprobada","fallida"))
