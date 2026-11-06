"""Real PostgreSQL integration tests. Each case rolls back all its data.

Only email transport and the TOTP clock are controlled; cookies, Argon2id,
CSRF, roles, tokens, row locks and SQL constraints use the actual implementation.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import re
import secrets
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
from cryptography.fernet import Fernet

from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pyotp
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, DBAPIError

from backend.api import app
from backend.auth.config import SESSION_COOKIE
from backend.auth.schemas import Registration, cedula, email
from backend.auth.security import PASSWORDS, matching_interval, now, validate_password, verify_password
from backend.auth.config import Settings

PASSWORD = "Faro!Nebulosa-Cobre-Tulipan-9472"
NEW_PASSWORD = "Orbita!Bosque-Linterna-Cuarzo-3816"


def sample_cedula(number):
    prefix = "171" + f"{number:06d}"
    total = sum((2 * int(d) % 9 if int(d) != 9 else 9) if i % 2 == 0 else int(d) for i, d in enumerate(prefix))
    return prefix + str((10 - total % 10) % 10)


def payload(number=1):
    return {"cedula": sample_cedula(number), "nombres": "Ángela María", "apellidos": "O'Neill Ñúñez",
            "nombre_usuario": f"persona{number}", "correo": f"persona{number}@example.org",
            "password": PASSWORD, "confirmacion": PASSWORD}


class IdentityTests(unittest.TestCase):
    def test_development_mailbox_writes_a_private_email_without_external_delivery(self):
        from backend.auth.mailer import deliver
        with TemporaryDirectory() as folder, patch.dict("os.environ", {"AUTH_ENV":"development","MAIL_TRANSPORT":"file","MAIL_DEV_DIRECTORY":folder}):
            deliver(Settings.load(), "destinatario@example.org", "Verificación de prueba", "Código de prueba: 123456")
            messages = list(Path(folder).glob("*.eml"))
            self.assertEqual(len(messages),1)
            from email import policy
            from email.parser import BytesParser
            parsed=BytesParser(policy=policy.default).parsebytes(messages[0].read_bytes())
            self.assertIn("123456",parsed.get_body(preferencelist=('plain',)).get_content())
            self.assertIn("TacticLens",parsed["Subject"])

    def test_production_rejects_insecure_cookies_and_file_mail(self):
        with patch.dict("os.environ", {"AUTH_ENV":"production","AUTH_COOKIE_SECURE":"false"}), self.assertRaises(RuntimeError):
            Settings.load()
        with patch.dict("os.environ", {"AUTH_ENV":"production","AUTH_COOKIE_SECURE":"true","AUTH_PUBLIC_URL":"https://tacticlens.example.org","AUTH_ALLOWED_ORIGINS":"https://tacticlens.example.org","MAIL_TRANSPORT":"file"}), self.assertRaises(RuntimeError):
            Settings.load()
    def test_valid_identity_and_normalization(self):
        data = Registration(**{**payload(), "nombre_usuario": " PERSONA1 ", "correo": " PERSONA1@EXAMPLE.ORG "})
        self.assertEqual(data.nombre_usuario, "persona1")
        self.assertEqual(data.correo, "persona1@example.org")
        self.assertEqual(data.nombres, "Ángela María")

    def test_invalid_cedulas(self):
        for value in ("123", "0000000000", "9912345678", "1760000000", "abcdefghij", sample_cedula(1)[:-1] + str((int(sample_cedula(1)[-1])+1)%10)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cedula(value)

    def test_weak_passwords_and_confirmation(self):
        for value in ("123456", "Password123!", "Contrasena123456!", "aaaaaaaaaaaaaaaaaaaa"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_password(value)
        with self.assertRaises(ValidationError):
            Registration(**{**payload(), "confirmacion": "otra contraseña"})

    def test_role_cannot_be_chosen_and_injection_rejected(self):
        with self.assertRaises(ValidationError):
            Registration(**{**payload(), "rol": "administrador"})
        with self.assertRaises(ValidationError):
            Registration(**{**payload(), "nombre_usuario": "'; DROP TABLE usuario;--"})

    def test_argon2id_and_long_password(self):
        value = "Cuarzo nebulosa campanario brujula!" * 3
        validate_password(value)
        hashed = PASSWORDS.hash(value)
        self.assertTrue(hashed.startswith("$argon2id$"))
        self.assertTrue(verify_password(hashed, value))
        self.assertFalse(verify_password(hashed, "incorrecta"))

    def test_rfc6238_window_and_replay(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        at = datetime.fromtimestamp(59, timezone.utc)
        self.assertEqual(matching_interval(secret, "287082", -1, at), 1)
        self.assertIsNone(matching_interval(secret, "287082", 1, at))
        self.assertIsNone(matching_interval(secret, "287082", -1, at + timedelta(seconds=90)))
        self.assertIsNone(matching_interval(secret, "12345x", -1, at))


class AuthIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings_patch = patch.dict("os.environ", {
            "AUTH_ENV": "development", "AUTH_COOKIE_SECURE": "false",
            "AUTH_PUBLIC_URL": "http://127.0.0.1:5173", "AUTH_ALLOWED_ORIGINS": "http://127.0.0.1:5173",
            "AUTH_SECRET_KEY": secrets.token_urlsafe(48), "AUTH_TOTP_KEYS": Fernet.generate_key().decode(),
            "AUTH_MAX_ATTEMPTS": "5", "AUTH_IDLE_SECONDS": "1800", "AUTH_RESEND_SECONDS": "60",
            "AUTH_EMAIL_TTL_SECONDS": "300", "AUTH_CHALLENGE_SECONDS": "300", "MAIL_TRANSPORT": "file",
        })
        cls.settings_patch.start()
        cls.context = TestClient(app, client=("127.0.0.1", 51000))
        try:
            cls.client = cls.context.__enter__()
        except Exception:
            cls.settings_patch.stop()
            raise
        cls.engine = app.state.engine

    @classmethod
    def tearDownClass(cls):
        app.state.engine = cls.engine
        cls.context.__exit__(None, None, None)
        cls.settings_patch.stop()

    def setUp(self):
        self.connection = self.engine.connect()
        self.outer = self.connection.begin()
        connection = self.connection

        class TransactionEngine:
            @contextmanager
            def begin(self):
                with connection.begin_nested():
                    yield connection

            @contextmanager
            def connect(self):
                yield connection

        app.state.engine = TransactionEngine()
        self.client.cookies.clear()
        self.client.headers.update({"origin": "http://127.0.0.1:5173"})
        self.messages = []
        self.mail = patch("backend.auth.mailer.deliver", side_effect=lambda settings, *message: self.messages.append(message))
        self.mail.start()
        self.clock = now()
        self.clock_patch = patch("backend.auth.security.now", side_effect=lambda: self.clock)
        self.clock_patch.start()
        token = self.client.get("/api/auth/csrf").json()["csrf_token"]
        self.client.headers["x-csrf-token"] = token

    def tearDown(self):
        self.clock_patch.stop()
        self.mail.stop()
        app.state.engine = self.engine
        self.outer.rollback()
        self.connection.close()
        self.client.headers.pop("x-csrf-token", None)

    def post(self, path, data=None, expected=200):
        response = self.client.post("/api/auth" + path, json=data or {})
        self.assertEqual(response.status_code, expected, response.text)
        return response

    def account(self, number=1, verify=True, approve=False, admin=False):
        # Existing password accounts / trusted CLI fixtures. New signup is tested below via HTTP.
        data = payload(number)
        from backend.auth.service import create_account, issue_email_code, notify
        request = Request({"type":"http","app":app,"client":("127.0.0.1",0),"headers":[],"path":"/cli/test-fixture","scheme":"http","server":("localhost",0),"query_string":b""})
        with app.state.engine.begin() as conn:
            created = create_account(conn,request,Registration(**data))
            message = issue_email_code(conn,request,created)
        notify(request,created.id_usuario,message)
        code = re.search(r"es: ([0-9]{6})", self.messages[-1][2])[1]
        u, r = app.state.tables["usuario"], app.state.tables["rol"]
        user_id = self.connection.scalar(select(u.c.id_usuario).where(u.c.correo == data["correo"]))
        if verify:
            self.post("/correo/verificar", {"correo": data["correo"], "codigo": code})
        if approve:
            role_id = self.connection.scalar(select(r.c.id_rol).where(r.c.codigo == ("administrador" if admin else "analista")))
            self.connection.execute(u.update().where(u.c.id_usuario == user_id).values(autorizacion="aprobado", autorizado_por=user_id, autorizado_en=now(), id_rol=role_id))
        return user_id, data, code

    def login(self, data, expected_stage=None):
        result = self.post("/login", {"correo": data["correo"], "password": PASSWORD}).json()
        if expected_stage:
            self.assertEqual(result["etapa"], expected_stage)
        return result

    def enroll(self, number=1, admin=False):
        user_id, data, _ = self.account(number, approve=True, admin=admin)
        self.login(data, "configurar_mfa")
        setup = self.post("/mfa/configuracion").json()
        secret = setup["clave_manual"]
        self.assertTrue(setup["qr"].startswith("data:image/svg+xml;base64,"))
        self.assertIn("issuer=TacticLens", setup["uri"])
        before = self.client.cookies.get(SESSION_COOKIE)
        result = self.post("/mfa/confirmar", {"codigo": self.otp(secret)}).json()
        self.assertNotEqual(before, self.client.cookies.get(SESSION_COOKIE))
        self.assertEqual(len(result["codigos_recuperacion"]), 10)
        return user_id, data, secret, result["codigos_recuperacion"]

    def otp(self, secret):
        return pyotp.TOTP(secret).at(self.clock)

    def advance(self):
        self.clock += timedelta(seconds=30)

    def reauth(self, secret):
        self.advance()
        return {"password": PASSWORD, "codigo": self.otp(secret)}

    def profile(self, number=1):
        return {key:value for key,value in payload(number).items() if key not in {"password","confirmacion"}}

    def verify_registration_email(self, number=1):
        data=self.profile(number)
        self.post("/registro/correo/enviar",{"correo":data["correo"]},202)
        code=re.search(r"es: ([0-9]{6})",self.messages[-1][2])[1]
        self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":code})
        return data,code

    def guided_signup(self, number=1):
        data,_=self.verify_registration_email(number)
        result=self.post("/registro",data,201)
        self.assertTrue(result.json()["credencial_enviada"])
        temporary=re.search(r"temporal es: ([^\s]+)",self.messages[-1][2])[1]
        self.assertNotIn(temporary,result.text)
        u=app.state.tables["usuario"]
        user_id=self.connection.scalar(select(u.c.id_usuario).where(u.c.correo==data["correo"]))
        return user_id,data,temporary

    def test_guided_registration_requires_email_proof_and_rejects_client_flags(self):
        data=self.profile()
        self.post("/registro",data,403)
        self.post("/registro",{**data,"correo_verificado":True},422)
        self.post("/registro",{**data,"password":PASSWORD,"confirmacion":PASSWORD},422)
        _,data,temporary=self.guided_signup()
        u=app.state.tables["usuario"]
        row=self.connection.execute(select(u).where(u.c.correo==data["correo"])).mappings().one()
        self.assertTrue(row.password_cambio_obligatorio)
        self.assertIsNotNone(row.correo_verificado_en)
        self.assertEqual(row.autorizacion,"pendiente")
        self.assertTrue(verify_password(row.password_temporal_hash,temporary))
        self.assertFalse(verify_password(row.password_hash,temporary))
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)
        self.post("/registro",data,403)

    def test_email_before_registration_is_browser_bound_and_code_single_use(self):
        data,code=self.verify_registration_email()
        self.assertTrue(self.client.get("/api/auth/registro/correo").json()["verificado"])
        self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":code},400)
        other=TestClient(app,client=("127.0.0.1",51001))
        other.headers["origin"]="http://127.0.0.1:5173"
        other.headers["x-csrf-token"]=other.get("/api/auth/csrf").json()["csrf_token"]
        self.assertEqual(other.post("/api/auth/registro",json=data).status_code,403)
        other.close()
        self.post("/registro",data,201)

    def test_editing_email_invalidates_verified_proof(self):
        data,_=self.verify_registration_email()
        self.post("/registro/correo/editar")
        self.assertFalse(self.client.get("/api/auth/registro/correo").json()["verificado"])
        self.post("/registro",data,403)
        newer,_=self.verify_registration_email(2)
        self.post("/registro",data,403)
        self.post("/registro",{**data,"correo":newer["correo"]},201)

    def test_registration_email_expiration_retries_and_cooldown(self):
        data=self.profile()
        self.post("/registro/correo/enviar",{"correo":data["correo"]},202)
        code=re.search(r"es: ([0-9]{6})",self.messages[-1][2])[1]
        self.post("/registro/correo/enviar",{"correo":data["correo"]},429)
        wrong="000000" if code!="000000" else "111111"
        for _ in range(5):
            self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":wrong},400)
        self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":code},429)
        t=app.state.tables["auth_token"]
        self.assertEqual(self.connection.scalar(select(t.c.intentos).where(t.c.correo==data["correo"],t.c.proposito=="pre_registro")),5)

    def test_expired_registration_email_cannot_verify_or_register(self):
        data=self.profile()
        self.post("/registro/correo/enviar",{"correo":data["correo"]},202)
        code=re.search(r"es: ([0-9]{6})",self.messages[-1][2])[1]
        t=app.state.tables["auth_token"]
        self.connection.execute(t.update().where(t.c.correo==data["correo"]).values(vence_en=now()-timedelta(seconds=1)))
        self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":code},400)
        self.post("/registro",data,403)

    def test_temporary_password_is_one_use_and_cannot_access_modules(self):
        user_id,data,temporary=self.guided_signup()
        self.assertEqual(self.post("/login",{"correo":data["correo"],"password":temporary}).json()["etapa"],"crear_password")
        u=app.state.tables["usuario"]
        row=self.connection.execute(select(u).where(u.c.id_usuario==user_id)).mappings().one()
        self.assertTrue(row.password_temporal_hash.startswith("$argon2id$"))
        self.assertIsNotNone(row.password_temporal_usada_en)
        self.assertEqual(self.client.get("/api/sesiones").status_code,403)
        self.post("/mfa/configuracion",expected=403)
        self.post("/login",{"correo":data["correo"],"password":temporary},401)
        reused=self.post("/password/fortaleza",{"password":temporary}).json()
        self.assertFalse(reused["aceptable"])
        self.post("/password/inicial",{"password":temporary,"confirmacion":temporary},422)
        self.post("/password/inicial",{"password":"Contrasena123456!","confirmacion":"Contrasena123456!"},422)
        self.post("/password/inicial",{"password":PASSWORD,"confirmacion":"diferente"},422)
        self.post("/password/inicial",{"password":PASSWORD,"confirmacion":PASSWORD,"porcentaje":100},422)
        self.assertEqual(self.post("/password/inicial",{"password":PASSWORD,"confirmacion":PASSWORD}).json()["etapa"],"aprobacion")
        self.post("/login",{"correo":data["correo"],"password":temporary},401)
        self.login(data,"aprobacion")

    def test_expired_temporary_password_recovers_without_approving_or_disabling_mfa(self):
        user_id,data,temporary=self.guided_signup()
        u=app.state.tables["usuario"]
        self.connection.execute(u.update().where(u.c.id_usuario==user_id).values(password_temporal_vence_en=now()-timedelta(seconds=1)))
        self.post("/login",{"correo":data["correo"],"password":temporary},401)
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        token=re.search(r"#token=([^\s]+)",self.messages[-1][2])[1]
        self.post("/password/restablecer",{"token":token,"password":PASSWORD,"confirmacion":PASSWORD})
        self.login(data,"aprobacion")
        row=self.connection.execute(select(u).where(u.c.id_usuario==user_id)).mappings().one()
        self.assertFalse(row.password_cambio_obligatorio)
        self.assertEqual(row.autorizacion,"pendiente")

    def test_strength_meter_requires_proof_and_matches_final_75_percent_policy(self):
        self.post("/password/fortaleza",{"password":PASSWORD},401)
        _,data,temporary=self.guided_signup()
        self.post("/login",{"correo":data["correo"],"password":temporary})
        weak=self.post("/password/fortaleza",{"password":"Contrasena123456!"}).json()
        self.assertLess(weak["porcentaje"],75)
        self.assertFalse(weak["aceptable"])
        strong=self.post("/password/fortaleza",{"password":PASSWORD}).json()
        self.assertGreaterEqual(strong["porcentaje"],75)
        self.assertTrue(strong["aceptable"])
        self.assertNotIn(PASSWORD,str(strong))
        self.post("/password/inicial",{"password":PASSWORD,"confirmacion":PASSWORD})

    def test_admin_accepts_guided_signup_but_password_and_mfa_still_required(self):
        target_id,data,temporary=self.guided_signup()
        _,_,secret,_=self.enroll(99,admin=True)
        self.advance()
        response=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={"codigo":self.otp(secret),"rol":"analista","activo":True,"aprobar":True})
        self.assertEqual(response.status_code,200,response.text)
        pending=self.client.get("/api/auth/admin/usuarios?estado=pendiente").json()
        self.assertNotIn(str(target_id),[u["id_usuario"] for u in pending])
        approved=self.client.get("/api/auth/admin/usuarios?estado=aprobado").json()
        self.assertIn(str(target_id),[u["id_usuario"] for u in approved])
        self.post("/logout")
        self.assertEqual(self.post("/login",{"correo":data["correo"],"password":temporary}).json()["etapa"],"crear_password")
        self.assertEqual(self.post("/password/inicial",{"password":PASSWORD,"confirmacion":PASSWORD}).json()["etapa"],"configurar_mfa")
        self.assertEqual(self.client.get("/api/sesiones").status_code,403)
        setup=self.post("/mfa/configuracion").json()
        self.post("/mfa/confirmar",{"codigo":self.otp(setup["clave_manual"])})
        self.assertEqual(self.client.get("/api/sesiones").status_code,200)
        self.assertEqual(self.client.get("/api/auth/admin/usuarios").status_code,403)

    def test_approval_requires_fresh_admin_totp_and_rejects_missing_invalid_expired_codes(self):
        target_id,_,_=self.account(2)
        _,_,secret,_=self.enroll(admin=True)
        url=f"/api/auth/admin/usuarios/{target_id}"
        decision={"rol":"analista","activo":True,"aprobar":True}
        self.assertEqual(self.client.patch(url,json=decision).status_code,422)
        # Enrollment already consumed this interval.
        self.assertEqual(self.client.patch(url,json={**decision,"codigo":self.otp(secret)}).status_code,400)
        self.assertEqual(self.client.patch(url,json={**decision,"codigo":"12x456"}).status_code,400)
        expired=self.otp(secret)
        self.clock += timedelta(seconds=90)
        self.assertEqual(self.client.patch(url,json={**decision,"codigo":expired}).status_code,400)
        self.assertEqual(self.client.patch(url,json={**decision,"codigo":self.otp(secret)}).status_code,200)

    def test_approval_totp_cannot_be_reused_for_another_account(self):
        first,_,_=self.account(2)
        second,_,_=self.account(3)
        actor_id,_,secret,_=self.enroll(admin=True)
        self.advance()
        decision={"codigo":self.otp(secret),"rol":"analista","activo":True,"aprobar":True}
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{first}",json=decision).status_code,200)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{second}",json=decision).status_code,400)
        u,a=app.state.tables["usuario"],app.state.tables["auth_auditoria"]
        self.assertEqual(self.connection.scalar(select(u.c.autorizacion).where(u.c.id_usuario==second)),"pendiente")
        event=self.connection.execute(select(a).where(a.c.id_usuario==first,a.c.tipo=="cuenta_autorizada")).mappings().one()
        self.assertEqual(event.actor_id,actor_id)

    def test_approval_rejects_recovery_code_without_consuming_it(self):
        target_id,_,_=self.account(2)
        actor_id,_,_,codes=self.enroll(admin=True)
        decision={"codigo":codes[0],"recuperacion":True,"rol":"analista","activo":True,"aprobar":True}
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json=decision).status_code,400)
        c=app.state.tables["auth_recuperacion"]
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(c).where(c.c.id_usuario==actor_id,c.c.usado_en.is_(None))),10)

    def test_approval_flag_does_not_remove_password_for_existing_account_changes(self):
        target_id,_,_=self.account(2,approve=True)
        pending_id,_,_=self.account(3)
        _,_,secret,_=self.enroll(admin=True)
        self.advance()
        decision={"codigo":self.otp(secret),"rol":"administrador","activo":True,"aprobar":True}
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json=decision).status_code,422)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**decision,"aprobar":False}).status_code,422)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{pending_id}",json={**decision,"aprobar":False,"rechazar":True,"motivo_rechazo":"Solicitud no autorizada"}).status_code,422)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**decision,"password":PASSWORD}).status_code,200)

    def test_approval_with_only_totp_still_requires_admin_role_and_full_session(self):
        target_id,_,_=self.account(2)
        _,data,secret,_=self.enroll()
        self.advance()
        decision={"codigo":self.otp(secret),"rol":"analista","activo":True,"aprobar":True}
        url=f"/api/auth/admin/usuarios/{target_id}"
        self.assertEqual(self.client.patch(url,json=decision).status_code,403)
        self.post("/logout")
        self.login(data,"mfa")
        self.assertEqual(self.client.patch(url,json=decision).status_code,403)

    def test_admin_rejects_pending_request_and_revokes_its_access(self):
        target_id,data,temporary=self.guided_signup()
        self.post("/login",{"correo":data["correo"],"password":temporary})
        self.post("/password/inicial",{"password":PASSWORD,"confirmacion":PASSWORD})
        target_cookies=dict(self.client.cookies)
        self.client.cookies.clear()
        self.client.headers["x-csrf-token"]=self.client.get("/api/auth/csrf").json()["csrf_token"]
        _,_,secret,_=self.enroll(99,admin=True)
        decision={**self.reauth(secret),"rol":"analista","activo":False,"rechazar":True,"motivo_rechazo":"La cuenta no corresponde al equipo autorizado."}
        response=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json=decision)
        self.assertEqual(response.status_code,200,response.text)
        rejected=self.client.get("/api/auth/admin/usuarios?estado=rechazado").json()
        self.assertIn(str(target_id),[u["id_usuario"] for u in rejected])
        u=app.state.tables["usuario"]
        row=self.connection.execute(select(u).where(u.c.id_usuario==target_id)).mappings().one()
        self.assertEqual(row.autorizacion,"rechazado")
        self.assertFalse(row.activo)
        self.assertIsNotNone(row.rechazado_en)
        self.client.cookies.clear();self.client.cookies.update(target_cookies)
        self.assertEqual(self.client.get("/api/auth/me").status_code,401)
        self.client.headers["x-csrf-token"]=self.client.get("/api/auth/csrf").json()["csrf_token"]
        self.post("/login",{"correo":data["correo"],"password":PASSWORD},401)

    def test_reject_decision_requires_admin_reauth_reason_and_unambiguous_choice(self):
        target_id,_,_=self.account(2)
        _,_,secret,_=self.enroll(admin=True)
        base={**self.reauth(secret),"rol":"analista","activo":False,"rechazar":True}
        response=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json=base)
        self.assertEqual(response.status_code,422)
        response=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**base,"aprobar":True,"motivo_rechazo":"Motivo de rechazo documentado"})
        self.assertEqual(response.status_code,422)
        response=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**base,"password":"incorrecta","motivo_rechazo":"Motivo de rechazo documentado"})
        self.assertEqual(response.status_code,400)

    def test_registration_email_delivery_failure_creates_no_user(self):
        data=self.profile()
        with patch("backend.auth.mailer.deliver",side_effect=OSError("fallo de transporte")):
            self.post("/registro/correo/enviar",{"correo":data["correo"]},503)
        u=app.state.tables["usuario"]
        self.assertEqual(self.connection.scalar(select(func.count()).where(u.c.correo==data["correo"])),0)

    def test_existing_password_accounts_keep_hashes_and_separate_states(self):
        user_id, data, _ = self.account(verify=False)
        u = app.state.tables["usuario"]
        row = self.connection.execute(select(u).where(u.c.id_usuario == user_id)).mappings().one()
        self.assertNotIn(PASSWORD, row.password_hash)
        self.assertTrue(row.password_hash.startswith("$argon2id$"))
        self.assertEqual(row.autorizacion, "pendiente")
        self.assertIsNone(row.correo_verificado_en)
        self.login(data, "correo")
        self.assertEqual(self.client.get("/api/sesiones").status_code, 403)

    def test_duplicate_email_username_and_cedula_constraints(self):
        self.account(verify=False)
        from backend.auth.service import create_account
        from backend.auth.store import AuthError
        request = Request({"type":"http","app":app,"client":("127.0.0.1",0),"headers":[],"path":"/cli/test-fixture","scheme":"http","server":("localhost",0),"query_string":b""})
        for change in ({"correo": "PERSONA1@EXAMPLE.ORG"}, {"nombre_usuario": " PERSONA1 "}, {"cedula": sample_cedula(1)}):
            with self.assertRaises(AuthError):
                create_account(self.connection,request,Registration(**{**payload(2),**change}))
        u = app.state.tables["usuario"]
        with self.assertRaises(IntegrityError), self.connection.begin_nested():
            self.connection.execute(u.insert().values(id_rol=2, nombre="Duplicado", correo="PERSONA1@EXAMPLE.ORG", password_hash="unused"))

    def test_email_wrong_correct_used_and_pending_approval(self):
        _, data, code = self.account(verify=False)
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": "000000" if code != "000000" else "111111"}, 400)
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": code})
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": code}, 400)
        self.login(data, "aprobacion")
        self.post("/mfa/configuracion", expected=403)
        self.assertEqual(self.client.get("/api/dashboard/resumen").status_code, 403)

    def test_expired_code_and_resend_invalidation_cooldown(self):
        user_id, data, code = self.account(verify=False)
        t = app.state.tables["auth_token"]
        self.connection.execute(t.update().where(t.c.id_usuario == user_id).values(vence_en=now()-timedelta(seconds=1), creado_en=now()-timedelta(minutes=2)))
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": code}, 400)
        self.post("/correo/reenviar", {"correo": data["correo"]}, 202)
        self.assertEqual(len(self.messages), 2)
        self.post("/correo/reenviar", {"correo": data["correo"]}, 202)
        self.assertEqual(len(self.messages), 2)
        new_code = re.search(r"es: ([0-9]{6})", self.messages[-1][2])[1]
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": new_code})

    def test_rate_limit_and_attempts_survive_rejected_requests(self):
        user_id, data, code = self.account(verify=False)
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(5):
            self.post("/correo/verificar", {"correo": data["correo"], "codigo": wrong}, 400)
        self.post("/correo/verificar", {"correo": data["correo"], "codigo": code}, 429)
        t = app.state.tables["auth_token"]
        attempts = self.connection.scalar(select(t.c.intentos).where(t.c.id_usuario == user_id))
        self.assertEqual(attempts, 5)

    def test_mfa_required_for_private_routes_and_direct_bypass(self):
        _, data, _ = self.account(approve=True)
        self.login(data, "configurar_mfa")
        for path in ("/api/sesiones", "/api/iocs", "/api/mitre/mapeos", "/api/dashboard/resumen"):
            self.assertEqual(self.client.get(path).status_code, 403)
        self.post("/mfa/verificar", {"codigo": "123456"}, 403)
        self.post("/login", {"correo": data["correo"], "password": PASSWORD, "mfa_completado": True}, 422)

    def test_totp_enrollment_invalid_code_encryption_and_secret_not_exposed(self):
        user_id, data, _ = self.account(approve=True)
        self.login(data)
        secret = self.post("/mfa/configuracion").json()["clave_manual"]
        valid_window = {pyotp.TOTP(secret).at(self.clock+timedelta(seconds=offset)) for offset in (-30,0,30)}
        invalid = next(str(i).zfill(6) for i in range(10) if str(i).zfill(6) not in valid_window)
        self.post("/mfa/confirmar", {"codigo": invalid}, 400)
        self.post("/mfa/confirmar", {"codigo": self.otp(secret)})
        f = app.state.tables["auth_factor"]
        encrypted = self.connection.scalar(select(f.c.secreto_cifrado).where(f.c.id_usuario == user_id))
        self.assertNotIn(secret, encrypted)
        self.assertEqual(app.state.auth_settings.cipher.decrypt(encrypted.encode()).decode(), secret)
        self.post("/mfa/configuracion", expected=403)
        self.assertNotIn(secret, self.client.get("/api/auth/me").text)

    def test_totp_login_replay_and_invalid_codes(self):
        _, data, secret, _ = self.enroll()
        self.post("/logout")
        self.login(data, "mfa")
        self.post("/mfa/verificar", {"codigo": self.otp(secret)}, 400)
        self.post("/mfa/verificar", {"codigo": "no-otp"}, 400)
        self.advance()
        self.post("/mfa/verificar", {"codigo": self.otp(secret)})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 200)

    def test_recovery_code_one_time_and_audit(self):
        user_id, data, _, codes = self.enroll()
        self.post("/logout")
        self.login(data)
        self.post("/mfa/verificar", {"codigo": codes[0], "recuperacion": True})
        self.post("/logout")
        self.login(data)
        self.post("/mfa/verificar", {"codigo": codes[0], "recuperacion": True}, 400)
        a = app.state.tables["auth_auditoria"]
        events = self.connection.execute(select(a.c.tipo,a.c.metadatos).where(a.c.id_usuario == user_id)).all()
        self.assertIn("codigo_recuperacion_usado", [x.tipo for x in events])
        serialized = str(events)
        self.assertNotIn(codes[0], serialized)
        self.assertNotIn(PASSWORD, serialized)

    def test_password_reset_preserves_mfa_revokes_sessions_and_token_is_single_use(self):
        user_id, data, secret, _ = self.enroll()
        self.post("/password/solicitar", {"correo": data["correo"]}, 202)
        token = re.search(r"#token=([^\s]+)", self.messages[-1][2])[1]
        self.post("/password/restablecer", {"token": token, "password": NEW_PASSWORD, "confirmacion": NEW_PASSWORD})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 401)
        self.post("/password/restablecer", {"token": token, "password": NEW_PASSWORD, "confirmacion": NEW_PASSWORD}, 400)
        result = self.post("/login", {"correo": data["correo"], "password": NEW_PASSWORD}).json()
        self.assertEqual(result["etapa"], "mfa")
        self.advance()
        self.post("/mfa/verificar", {"codigo": self.otp(secret)})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 200)

    def test_analyst_cannot_admin_or_import(self):
        self.enroll()
        self.assertEqual(self.client.get("/api/auth/admin/usuarios").status_code, 403)
        self.assertEqual(self.client.get("/api/auth/admin/auditoria").status_code, 403)
        self.assertEqual(self.client.post("/api/ingesta/cowrie", files={"file": ("x.json", b"{}\n")}).status_code, 403)

    def test_admin_approves_changes_role_suspends_and_revokes(self):
        target_id, target_data, _ = self.account(2)
        _, _, secret, _ = self.enroll(admin=True)
        response = self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**self.reauth(secret),"rol":"administrador","activo":True,"aprobar":True})
        self.assertEqual(response.status_code, 200, response.text)
        u = app.state.tables["usuario"]
        self.assertEqual(self.connection.scalar(select(u.c.autorizacion).where(u.c.id_usuario == target_id)), "aprobado")
        listed=self.client.get("/api/auth/admin/usuarios").json()
        self.assertEqual(next(row["rol"] for row in listed if row["id_usuario"]==str(target_id)),"administrador")
        self.assertEqual(self.client.get("/api/auth/admin/roles").status_code, 200)
        self.advance()
        response = self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**self.reauth(secret),"rol":"analista","activo":False})
        self.assertEqual(response.status_code, 200, response.text)
        self.post("/logout")
        self.post("/login", {"correo":target_data["correo"],"password":PASSWORD}, 401)

    def test_admin_reset_mfa_requires_reauth_no_self_reset_and_notifies(self):
        target_id, _, _, _ = self.enroll(2)
        self.post("/logout")
        admin_id, _, secret, _ = self.enroll(admin=True)
        data={**self.reauth(secret),"referencia_verificacion":"Expediente de verificación presencial ABC-2026"}
        self.post(f"/admin/usuarios/{admin_id}/mfa/restablecer",data,403)
        self.post(f"/admin/usuarios/{target_id}/mfa/restablecer",{**data,"password":"incorrecta"},400)
        self.post(f"/admin/usuarios/{target_id}/mfa/restablecer",data)
        f=app.state.tables["auth_factor"]
        self.assertIsNone(self.connection.scalar(select(f.c.confirmado_en).where(f.c.id_usuario==target_id)))
        self.assertIn("Google Authenticator restablecido", self.messages[-1][1])

    def test_admin_cannot_change_own_role_or_state(self):
        user_id,_,secret,_=self.enroll(admin=True)
        response=self.client.patch(f"/api/auth/admin/usuarios/{user_id}",json={**self.reauth(secret),"rol":"analista","activo":False})
        self.assertEqual(response.status_code,403)
        self.assertEqual(self.client.get("/api/auth/me").json()["usuario"]["rol"],"administrador")

    def test_logout_and_session_expiration(self):
        user_id, data, _, _ = self.enroll()
        self.post("/logout")
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)
        self.login(data)
        s=app.state.tables["auth_sesion"]
        self.connection.execute(s.update().where(s.c.id_usuario==user_id).values(vence_en=now()-timedelta(seconds=1)))
        self.post("/mfa/verificar",{"codigo":"123456"},401)

    def test_csrf_origin_cookies_and_no_secret_in_validation(self):
        response=self.client.post("/api/auth/login",json={"correo":"persona@example.org","password":"secreto-rechazado"},headers={"x-csrf-token":"incorrecto"})
        self.assertEqual(response.status_code,403)
        response=self.client.post("/api/auth/login",json={"correo":"persona@example.org","password":"secreto-rechazado"},headers={"x-csrf-token":b"\xff"})
        self.assertEqual(response.status_code,403)
        response=self.client.post("/api/auth/login",json={"correo":"persona@example.org","password":"secreto-rechazado"},headers={"origin":"https://malicioso.example"})
        self.assertEqual(response.status_code,403)
        response=self.post("/registro",{**payload(),"password":"123","confirmacion":"123"},422)
        self.assertNotIn('"input"',response.text)
        self.assertNotIn('"confirmacion":"123"',response.text)
        self.enroll()
        cookie=str(self.client.cookies)
        self.assertNotIn(PASSWORD,cookie)
        self.assertEqual(self.client.get("/api/sesiones").headers.get("cache-control"),"no-store")

    def test_ingestion_keeps_machine_key_and_needs_no_browser_session(self):
        response=self.client.post("/api/ingesta/heartbeat",headers={"X-API-Key":app.state.api_key})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.client.post("/api/ingesta/heartbeat").status_code,401)
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)

    def test_recovery_regeneration_requires_reauth_and_invalidates_old_codes(self):
        user_id, _, secret, codes = self.enroll()
        self.post("/mfa/codigos", {"password": "incorrecta", "codigo": codes[0], "recuperacion": True}, 400)
        result = self.post("/mfa/codigos", self.reauth(secret)).json()
        self.assertEqual(len(result["codigos_recuperacion"]), 10)
        self.assertTrue(set(codes).isdisjoint(result["codigos_recuperacion"]))
        r = app.state.tables["auth_recuperacion"]
        self.assertEqual(self.connection.scalar(select(func.count()).where(r.c.id_usuario==user_id,r.c.usado_en.is_(None))), 10)

    def test_replacing_phone_with_recovery_requires_new_totp_before_modules(self):
        _, data, _, codes = self.enroll()
        self.post("/mfa/reemplazar", {"password": PASSWORD, "codigo": codes[0], "recuperacion": True})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 403)
        self.assertEqual(self.client.get("/api/auth/me").json()["etapa"], "configurar_mfa")
        secret = self.post("/mfa/configuracion").json()["clave_manual"]
        self.post("/mfa/confirmar", {"codigo": self.otp(secret)})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 200)

    def test_password_change_requires_two_factors_and_invalidates_reset_links(self):
        _, data, secret, _ = self.enroll()
        self.post("/password/solicitar", {"correo": data["correo"]}, 202)
        token = re.search(r"#token=([^\s]+)", self.messages[-1][2])[1]
        self.post("/password/cambiar", {**self.reauth(secret), "nueva_password": NEW_PASSWORD, "confirmacion": NEW_PASSWORD})
        self.assertEqual(self.client.get("/api/sesiones").status_code, 401)
        self.post("/password/restablecer", {"token": token, "password": NEW_PASSWORD, "confirmacion": NEW_PASSWORD}, 400)
        self.assertEqual(self.post("/login", {"correo": data["correo"], "password": NEW_PASSWORD}).json()["etapa"], "mfa")

    def test_background_polling_does_not_extend_idle_session(self):
        user_id,_,_,_=self.enroll()
        s = app.state.tables["auth_sesion"]
        moment = now() - timedelta(minutes=5)
        self.connection.execute(s.update().where(s.c.id_usuario==user_id,s.c.revocado_en.is_(None)).values(ultima_actividad=moment))
        self.assertEqual(self.client.get("/api/dashboard/resumen").status_code, 200)
        recorded = self.connection.scalar(select(s.c.ultima_actividad).where(s.c.id_usuario==user_id,s.c.revocado_en.is_(None)))
        self.assertEqual(recorded, moment)
        self.connection.execute(s.update().where(s.c.id_usuario==user_id,s.c.revocado_en.is_(None)).values(ultima_actividad=now()-timedelta(hours=1)))
        self.assertEqual(self.client.get("/api/dashboard/resumen").status_code, 401)

    def test_email_codes_and_recovery_hashes_never_stored_as_plaintext(self):
        user_id, data, code = self.account(verify=False)
        t = app.state.tables["auth_token"]
        row = self.connection.execute(select(t).where(t.c.id_usuario==user_id)).mappings().one()
        self.assertNotEqual(row.token_hash, code)
        self.assertEqual(len(row.token_hash),64)
        self.assertNotIn("confirmacion", app.state.tables["usuario"].columns)

    def test_unauthenticated_admin_routes_and_expired_reset_are_rejected(self):
        self.assertEqual(self.client.get("/api/auth/admin/usuarios").status_code,401)
        self.assertEqual(self.client.get("/api/auth/admin/auditoria").status_code,401)
        user_id, data, _ = self.account()
        self.post("/password/solicitar", {"correo":data["correo"]},202)
        token=re.search(r"#token=([^\s]+)", self.messages[-1][2])[1]
        t=app.state.tables["auth_token"]
        self.connection.execute(t.update().where(t.c.id_usuario==user_id,t.c.proposito=="password").values(vence_en=now()-timedelta(seconds=1)))
        self.post("/password/restablecer",{"token":token,"password":NEW_PASSWORD,"confirmacion":NEW_PASSWORD},400)

    def test_suspension_revokes_an_existing_session(self):
        target_id, _, _, _ = self.enroll(2)
        target_cookies = dict(self.client.cookies)
        # Use another browser identity, keeping the target session alive in SQL.
        self.client.cookies.clear()
        self.client.headers["x-csrf-token"] = self.client.get("/api/auth/csrf").json()["csrf_token"]
        _, _, secret, _ = self.enroll(admin=True)
        result=self.client.patch(f"/api/auth/admin/usuarios/{target_id}",json={**self.reauth(secret),"rol":"analista","activo":False})
        self.assertEqual(result.status_code,200,result.text)
        self.client.cookies.clear()
        self.client.cookies.update(target_cookies)
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)

    def test_cookie_flags_and_oversized_auth_request(self):
        response=self.client.get("/api/auth/csrf")
        cookie=response.headers["set-cookie"].lower()
        self.assertIn("httponly",cookie)
        self.assertIn("samesite=strict",cookie)
        self.assertIn("path=/api",cookie)
        response=self.client.post("/api/auth/login",content=json.dumps({"correo":"persona@example.org","password":"x"*20000}),headers={"content-type":"application/json"})
        self.assertEqual(response.status_code,413)

    def test_resending_invalidates_an_unexpired_previous_email_code(self):
        with patch("backend.auth.service.secrets.randbelow", side_effect=[123456,654321]):
            user_id,data,old_code=self.account(verify=False)
            t=app.state.tables["auth_token"]
            self.connection.execute(t.update().where(t.c.id_usuario==user_id).values(creado_en=now()-timedelta(minutes=2)))
            self.post("/correo/reenviar",{"correo":data["correo"]},202)
        self.post("/correo/verificar",{"correo":data["correo"],"codigo":old_code},400)
        self.post("/correo/verificar",{"correo":data["correo"],"codigo":"654321"})

    def test_expired_totp_is_rejected_by_login_endpoint(self):
        _,data,secret,_=self.enroll()
        old_code=self.otp(secret)
        self.post("/logout")
        self.login(data,"mfa")
        self.clock+=timedelta(seconds=90)
        while old_code in {pyotp.TOTP(secret).at(self.clock+timedelta(seconds=offset)) for offset in (-30,0,30)}:
            self.clock+=timedelta(seconds=30)
        self.post("/mfa/verificar",{"codigo":old_code},400)
        self.post("/mfa/verificar",{"codigo":self.otp(secret)})

    def test_migration_is_idempotent_and_preserves_data(self):
        from scripts.migrate import migrate
        before={name:self.connection.scalar(select(func.count()).select_from(app.state.tables[name])) for name in ("usuario","rol","sesion","evento")}
        migrate(app.state.engine)
        after={name:self.connection.scalar(select(func.count()).select_from(app.state.tables[name])) for name in before}
        self.assertEqual(before,after)

    def test_database_forbids_full_session_without_mfa(self):
        user_id,_,_,_=self.enroll()
        s=app.state.tables["auth_sesion"]
        with self.assertRaises(IntegrityError),self.connection.begin_nested():
            self.connection.execute(s.update().where(s.c.id_usuario==user_id,s.c.etapa=="completa").values(mfa_en=None))

    def test_security_audit_is_append_only_in_postgresql(self):
        user_id,_,_=self.account()
        a=app.state.tables["auth_auditoria"]
        with self.assertRaises(DBAPIError),self.connection.begin_nested():
            self.connection.execute(a.update().where(a.c.id_usuario==user_id).values(tipo="alterado"))
        with self.assertRaises(DBAPIError),self.connection.begin_nested():
            self.connection.execute(a.delete().where(a.c.id_usuario==user_id))

    def test_bootstrap_registered_account_requires_password_email_and_mfa(self):
        from scripts.create_admin import promote_registered_account
        from backend.auth.store import AuthError
        u,r=app.state.tables["usuario"],app.state.tables["rol"]
        request=Request({"type":"http","app":app,"client":("127.0.0.1",0),"headers":[],"path":"/cli/create-admin","scheme":"http","server":("localhost",0),"query_string":b""})
        has_admin=self.connection.scalar(select(func.count()).select_from(u.join(r,u.c.id_rol==r.c.id_rol)).where(r.c.codigo=="administrador"))
        user_id,data,code=self.account(verify=False)
        if has_admin:
            with self.assertRaises(AuthError):
                promote_registered_account(self.connection,request,data["correo"],PASSWORD)
            return
        with self.assertRaises(AuthError):
            promote_registered_account(self.connection,request,data["correo"],"incorrecta")
        with self.assertRaises(AuthError):
            promote_registered_account(self.connection,request,data["correo"],PASSWORD)
        self.post("/correo/verificar",{"correo":data["correo"],"codigo":code})
        self.login(data,"aprobacion")
        before=self.connection.execute(select(u).where(u.c.id_usuario==user_id)).mappings().one()
        count=self.connection.scalar(select(func.count()).select_from(u))
        result=promote_registered_account(self.connection,request,data["correo"],PASSWORD)
        self.assertEqual(result.rol,"administrador")
        self.assertEqual(result.autorizacion,"aprobado")
        self.assertEqual(result.password_hash,before.password_hash)
        self.assertEqual(result.correo_verificado_en,before.correo_verificado_en)
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(u)),count)
        self.assertEqual(self.client.get("/api/auth/me").status_code,401)
        self.login(data,"configurar_mfa")
        self.assertEqual(self.client.get("/api/sesiones").status_code,403)
        with self.assertRaises(AuthError):
            promote_registered_account(self.connection,request,data["correo"],PASSWORD)

    def test_bootstrap_never_elevates_a_second_administrator(self):
        from scripts.create_admin import promote_registered_account
        from backend.auth.store import AuthError, identity
        self.enroll(admin=True)
        user_id,data,_=self.account(2)
        request=Request({"type":"http","app":app,"client":("127.0.0.1",0),"headers":[],"path":"/cli/create-admin","scheme":"http","server":("localhost",0),"query_string":b""})
        with self.assertRaises(AuthError):
            promote_registered_account(self.connection,request,data["correo"],PASSWORD)
        self.assertEqual(identity(self.connection,request,user_id).rol,"analista")


if __name__ == "__main__":
    unittest.main()
