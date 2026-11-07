"""Two real HTTP requests on separate PostgreSQL connections in an isolated schema."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4
import re
import secrets
import unittest

from cryptography.fernet import Fernet
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, select
from sqlalchemy.schema import CreateSchema, DropSchema

import test_auth as fixtures
from backend.api import app
from backend.auth.recovery import create_request, send_approved_link
from backend.auth.schemas import Registration
from backend.auth.service import create_account
from backend.auth.store import identity


class PasswordConcurrencyTests(unittest.TestCase):
    def test_two_simultaneous_resets_only_one_consumes_the_token(self):
        environment={"AUTH_ENV":"development","AUTH_COOKIE_SECURE":"false",
            "AUTH_PUBLIC_URL":"http://127.0.0.1:5173","AUTH_ALLOWED_ORIGINS":"http://127.0.0.1:5173",
            "AUTH_SECRET_KEY":secrets.token_urlsafe(48),"AUTH_TOTP_KEYS":Fernet.generate_key().decode(),"MAIL_TRANSPORT":"file",
            "ADMIN_EMAIL":"","SUPPORT_EMAIL":""}
        messages=[]
        with patch.dict("os.environ",environment), patch("backend.auth.mailer.deliver",side_effect=lambda settings,*message:messages.append(message)):
            with TestClient(app,client=("127.0.0.1",51010)) as client:
                original=app.state.tables
                engine=app.state.engine
                schema="test_tacticlens_"+uuid4().hex
                meta=MetaData()
                names=("usuario","rol","auth_factor","auth_sesion","auth_token","auth_recuperacion","auth_solicitud_password","auth_auditoria","auth_limite")
                copied={name:original[name].to_metadata(meta,schema=schema,referred_schema_fn=lambda *args:schema) for name in names}
                created=False
                try:
                    with engine.begin() as conn:
                        conn.execute(CreateSchema(schema))
                        meta.create_all(conn)
                    created=True
                    app.state.tables={**original,**copied}
                    request=Request({"type":"http","app":app,"client":("127.0.0.1",51010),"headers":[],"path":"/test","scheme":"http","server":("localhost",0),"query_string":b""})
                    with engine.begin() as conn:
                        conn.execute(copied["rol"].insert().values(id_rol=1,nombre="Analista de seguridad",codigo="analista",activo=True))
                        user=create_account(conn,request,Registration(**fixtures.payload(801)),verified_email=True)
                        conn.execute(copied["usuario"].update().where(copied["usuario"].c.id_usuario==user.id_usuario).values(autorizacion="aprobado"))
                        user=identity(conn,request,user.id_usuario)
                        recovery=create_request(conn,request,user)
                        self.assertTrue(send_approved_link(conn,request,user,recovery,user.id_usuario,"Aprobación controlada para prueba concurrente"))
                        user_id=user.id_usuario
                    token=re.search(r"#token=([^\s]+)",messages[-1][2])[1]
                    client.headers["origin"]="http://127.0.0.1:5173"
                    client.headers["x-csrf-token"]=client.get("/api/auth/csrf").json()["csrf_token"]
                    barrier=Barrier(2)
                    def reset():
                        barrier.wait(timeout=15)
                        return client.post("/api/auth/password/restablecer",json={"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD})
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures=[pool.submit(reset) for _ in range(2)]
                        responses=[future.result(timeout=30) for future in futures]
                    self.assertEqual(sorted(r.status_code for r in responses),[200,400],[r.text for r in responses])
                    with engine.connect() as conn:
                        state=conn.scalar(select(copied["auth_solicitud_password"].c.estado).where(copied["auth_solicitud_password"].c.id_usuario==user_id))
                        self.assertEqual(state,"completada")
                finally:
                    app.state.tables=original
                    if created:
                        # Only this randomly named, disposable test schema is removed.
                        assert schema.startswith("test_tacticlens_") and len(schema)==48
                        with engine.begin() as conn:
                            conn.execute(DropSchema(schema,cascade=True))
