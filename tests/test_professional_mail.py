"""Professional routing over real PostgreSQL; every external send is mocked."""
from datetime import timedelta
import json
import re
import unittest
from unittest.mock import patch

from sqlalchemy import select
import test_auth as fixtures

from backend.api import app
from backend.auth.mail_config import MailConfig
from backend.auth.mailer import DeliveryUncertain
from backend.auth.security import now


class ProfessionalMailTests(fixtures.AuthFixture):
    def setUp(self):
        super().setUp()
        self.previous_config = app.state.mail_config
        self.routing = patch.dict("os.environ", {"ADMIN_EMAIL":"admin@example.org", "SUPPORT_EMAIL":"soporte@example.org",
            "MAIL_ALERT_THRESHOLD":"5", "MAIL_ALERT_WINDOW_SECONDS":"900", "MAIL_ALERT_COOLDOWN_SECONDS":"900",
            "MAIL_NOTIFICATION_MAX_ATTEMPTS":"3"})
        self.routing.start()
        app.state.mail_config = MailConfig.load()
        self.mail.stop()
        self.envelopes = []
        self.mail = patch("backend.auth.mailer.deliver", side_effect=self.capture)
        self.mail.start()

    def capture(self, settings, *message, **kwargs):
        self.messages.append(message)
        self.envelopes.append((message, kwargs))

    def tearDown(self):
        app.state.mail_config = self.previous_config
        self.routing.stop()
        super().tearDown()

    def queue(self):
        q = app.state.tables["auth_notificacion"]
        return self.connection.execute(select(q).order_by(q.c.creado_en,q.c.id_notificacion)).mappings().all()

    def support_data(self, **changes):
        return {"nombre":"Ángela María", "correo":"consulta@example.org", "asunto":"No puedo acceder a mi cuenta",
                "categoria":"acceso", "descripcion":"Necesito ayuda para entender el estado de mi cuenta.", **changes}

    def test_verified_registration_notifies_admin_once_without_secrets(self):
        data,code = self.verify_registration_email()
        self.assertEqual([m[0] for m in self.messages],[data["correo"]])
        self.post("/registro",data,201)
        admin = [m for m in self.messages if m[0]=="admin@example.org"]
        self.assertEqual(len(admin),1)
        self.assertIn("http://127.0.0.1:5173/usuarios",admin[0][2])
        self.assertIn("America/Guayaquil (UTC-05:00)",admin[0][2])
        for secret in (code, data["cedula"], "#token=", "otpauth://", fixtures.PASSWORD):
            self.assertNotIn(secret,admin[0][2])
        self.post("/registro",data,403)
        self.assertEqual(len([m for m in self.messages if m[0]=="admin@example.org"]),1)
        self.assertEqual(len(self.queue()),1)
        self.assertEqual(self.queue()[0].estado,"aceptado")
        self.assertEqual(self.queue()[0].resultado,"buzon_local")
        a = app.state.tables["auth_auditoria"]
        events = self.connection.execute(select(a.c.tipo,a.c.metadatos)).mappings().all()
        self.assertIn("correo_aceptado",[r.tipo for r in events])
        self.assertIn("correo_notificacion_intento",[r.tipo for r in events])
        self.assertNotIn(code,json.dumps([dict(r) for r in events]))

    def test_expired_email_code_does_not_create_registration_or_admin_notice(self):
        data = self.profile()
        self.post("/registro/correo/enviar",{"correo":data["correo"]},202)
        code = re.search(r"es: ([0-9]{6})",self.messages[-1][2])[1]
        t = app.state.tables["auth_token"]
        self.connection.execute(t.update().where(t.c.correo==data["correo"]).values(vence_en=now()-timedelta(seconds=1)))
        self.post("/registro/correo/verificar",{"correo":data["correo"],"codigo":code},400)
        self.assertFalse(self.queue())

    def test_failed_login_threshold_and_rate_limit_share_one_cooldown(self):
        _,data,_ = self.account(approve=True)
        self.messages.clear()
        for index in range(10):
            self.post("/login",{"correo":data["correo"],"password":"incorrecta"},401)
            self.assertEqual(len(self.messages),0 if index<4 else 1)
        self.post("/login",{"correo":data["correo"],"password":"incorrecta"},429)
        self.assertEqual(len(self.messages),1)
        self.assertNotIn(data["correo"],self.messages[0][2])
        self.assertEqual(self.messages[0][0],"admin@example.org")

    def test_successful_login_and_mfa_do_not_generate_admin_alert(self):
        _,data,secret,_ = self.enroll()
        self.post("/logout")
        self.messages.clear()
        self.login(data,"mfa")
        self.advance()
        self.post("/mfa/verificar",{"codigo":self.otp(secret)})
        self.assertFalse(self.messages)

    def test_account_decisions_and_security_changes_notify_users_and_admin(self):
        target,data,_ = self.account(2,approve=True)
        actor,_,secret,_ = self.enroll(99,admin=True)
        self.messages.clear()
        for action in ("suspender","reactivar","bloquear","reactivar"):
            result = self.client.patch(f"/api/auth/admin/usuarios/{target}",json={**self.reauth(secret),
                "rol":"analista","activo":action=="reactivar","accion":action,"motivo":"Revisión de seguridad documentada"})
            self.assertEqual(result.status_code,200,result.text)
        for recipient in (data["correo"],"admin@example.org"):
            self.assertEqual(len([m for m in self.messages if m[0]==recipient]),4)
        self.messages.clear()
        result = self.client.patch(f"/api/auth/admin/usuarios/{target}",json={**self.reauth(secret),"rol":"administrador","activo":True})
        self.assertEqual(result.status_code,200,result.text)
        self.assertIn("Cambio de rol",next(m[2] for m in self.messages if m[0]=="admin@example.org"))
        self.messages.clear()
        self.post(f"/admin/usuarios/{target}/mfa/restablecer",{**self.reauth(secret),
            "referencia_verificacion":"Acta de comprobación presencial de identidad 2026"})
        self.assertEqual({m[0] for m in self.messages},{data["correo"],"admin@example.org"})
        self.assertNotIn("Acta de comprobación",json.dumps(self.messages))

    def test_approval_and_rejection_preserve_existing_user_mail(self):
        first,data,_ = self.account(2)
        second,other,_ = self.account(3)
        _,_,secret,_ = self.enroll(99,admin=True)
        self.messages.clear()
        result = self.client.patch(f"/api/auth/admin/usuarios/{first}",json={"codigo":self.reauth(secret)["codigo"],
            "rol":"analista","activo":True,"aprobar":True})
        self.assertEqual(result.status_code,200,result.text)
        result = self.client.patch(f"/api/auth/admin/usuarios/{second}",json={**self.reauth(secret),"rol":"analista",
            "activo":False,"rechazar":True,"motivo_rechazo":"Solicitud no autorizada tras revisión de identidad"})
        self.assertEqual(result.status_code,200,result.text)
        self.assertIn("autorizada",next(m[1] for m in self.messages if m[0]==data["correo"]))
        self.assertIn("rechazada",next(m[1] for m in self.messages if m[0]==other["correo"]))

    def test_public_support_fixed_recipient_reply_to_dedup_and_safe_markup(self):
        body = self.support_data(descripcion='No puedo entrar. <script>alert("x")</script>\nhttps://untrusted.example.org/reset')
        response = self.post("/soporte",body,202)
        repeated = self.post("/soporte",body,202)
        self.assertEqual(response.json()["id_solicitud"],repeated.json()["id_solicitud"])
        self.assertEqual(len(self.messages),1)
        self.assertEqual(self.messages[0][0],"soporte@example.org")
        self.assertEqual(self.envelopes[0][1]["reply_to"],body["correo"])
        self.assertIn("sin verificación de identidad",self.messages[0][2])
        from backend.auth.email_templates import render_email
        html = render_email(self.messages[0][1],self.messages[0][2])
        self.assertNotIn("<script>",html)
        self.assertNotIn('href="https://untrusted',html)
        self.assertIn("&lt;script&gt;",html)
        self.assertEqual(len(self.queue()),1)
        self.assertEqual(self.client.get("/api/auth/soporte/mis-solicitudes").status_code,401)

    def test_invalid_support_and_arbitrary_destinations_are_rejected(self):
        for changes in ({"correo":"x@example.org\r\nBcc:y@example.org"},{"nombre":"a"},{"categoria":"otra"},
                {"asunto":"Asunto\nBcc:spam"},{"descripcion":"password: NoIncluyaSecretos"},{"destinatario":"spam@example.org"}):
            with self.subTest(changes=changes):
                self.post("/soporte",self.support_data(**changes),422)
        self.assertFalse(self.messages)
        self.assertFalse(self.queue())
        self.client.headers.pop("x-csrf-token")
        self.post("/soporte",self.support_data(),403)

    def test_support_limits_abuse_per_address_and_ip(self):
        for i in range(3):
            self.post("/soporte",self.support_data(asunto=f"Consulta número {i}"),202)
        self.post("/soporte",self.support_data(asunto="Cuarta consulta distinta"),429)
        self.assertEqual(len(self.messages),3)

    def test_support_ip_limit_cannot_be_bypassed_by_changing_reply_address(self):
        for i in range(10):
            self.post("/soporte",self.support_data(correo=f"consulta{i}@example.org"),202)
        self.post("/soporte",self.support_data(correo="undecima@example.org"),429)
        self.assertEqual(len(self.messages),10)

    def test_authenticated_support_confirmation_and_own_history(self):
        _,data,_,_ = self.enroll()
        self.messages.clear()
        self.post("/soporte",self.support_data(correo=data["correo"]),202)
        self.assertEqual({m[0] for m in self.messages},{"soporte@example.org",data["correo"]})
        self.assertEqual(len(self.client.get("/api/auth/soporte/mis-solicitudes").json()),1)
        self.assertEqual(self.client.get("/api/auth/admin/notificaciones").status_code,403)
        self.post("/logout")
        self.enroll(2)
        self.assertEqual(self.client.get("/api/auth/soporte/mis-solicitudes").json(),[])

    def test_public_mfa_support_alerts_admin_without_altering_factors(self):
        self.enroll()
        f = app.state.tables["auth_factor"]
        before = [dict(row) for row in self.connection.execute(select(f)).mappings()]
        self.post("/logout")
        self.messages.clear()
        self.post("/soporte",self.support_data(categoria="mfa"),202)
        self.assertEqual({m[0] for m in self.messages},{"admin@example.org","soporte@example.org"})
        self.assertEqual(before,[dict(row) for row in self.connection.execute(select(f)).mappings()])
        self.assertIn("MFA",next(m[2] for m in self.messages if m[0]=="admin@example.org"))

    def test_transport_failure_is_persisted_sanitized_and_retried_with_same_key(self):
        _,_,secret,_ = self.enroll(99,admin=True)
        attempts = []
        def unavailable(settings,*args,**kwargs):
            attempts.append(kwargs["idempotency_key"])
            raise OSError("private-provider-secret-should-not-escape")
        with patch("backend.auth.mailer.deliver",side_effect=unavailable):
            self.post("/soporte",self.support_data(),202)
        row = next(r for r in self.queue() if r.tipo=="soporte")
        self.assertEqual((row.estado,row.intentos),("fallido",1))
        listed = self.client.get("/api/auth/admin/notificaciones")
        self.assertNotIn("private-provider",listed.text)
        self.post(f"/admin/notificaciones/{row.id_notificacion}/reintentar",{**self.reauth(secret),"motivo":"Verificación del servicio restablecido"},409)
        q = app.state.tables["auth_notificacion"]
        self.connection.execute(q.update().where(q.c.id_notificacion==row.id_notificacion).values(proximo_intento_en=None))
        self.post(f"/admin/notificaciones/{row.id_notificacion}/reintentar",{**self.reauth(secret),"motivo":"Verificación del servicio restablecido"},202)
        current = next(r for r in self.queue() if r.id_notificacion==row.id_notificacion)
        self.assertEqual((current.estado,current.intentos),("aceptado",2))
        self.assertEqual(attempts[0],self.envelopes[-1][1]["idempotency_key"])
        self.post(f"/admin/notificaciones/{row.id_notificacion}/reintentar",{**self.reauth(secret),"motivo":"Duplicado no permitido"},409)

    def test_uncertain_acceptance_and_expired_retry_window_do_not_claim_delivery(self):
        _,_,secret,_ = self.enroll(99,admin=True)
        with patch("backend.auth.mailer.deliver",side_effect=DeliveryUncertain("sanitized")):
            self.post("/soporte",self.support_data(),202)
        row = next(r for r in self.queue() if r.tipo=="soporte")
        self.assertEqual(row.estado,"incierto")
        self.assertIsNone(row.aceptado_en)
        q = app.state.tables["auth_notificacion"]
        self.connection.execute(q.update().where(q.c.id_notificacion==row.id_notificacion).values(
            primer_intento_en=now()-timedelta(hours=24),proximo_intento_en=None))
        count = len(self.messages)
        self.post(f"/admin/notificaciones/{row.id_notificacion}/reintentar",{**self.reauth(secret),"motivo":"Revisión de ventana vencida"},409)
        self.assertEqual(len(self.messages),count)

    def test_retry_cap_and_repeated_dispatch_do_not_send_duplicate_messages(self):
        _,_,secret,_ = self.enroll(99,admin=True)
        self.post("/soporte",self.support_data(),202)
        row = next(r for r in self.queue() if r.tipo=="soporte")
        from backend.auth.notifications import dispatch_one
        from fastapi import Request
        request = Request({"type":"http","app":app,"client":("127.0.0.1",0),"headers":[],"path":"/test","query_string":b""})
        count = len(self.messages)
        dispatch_one(request,row.id_notificacion)
        self.assertEqual(len(self.messages),count)
        q = app.state.tables["auth_notificacion"]
        self.connection.execute(q.update().where(q.c.id_notificacion==row.id_notificacion).values(
            estado="fallido",intentos=3,proximo_intento_en=None))
        self.post(f"/admin/notificaciones/{row.id_notificacion}/reintentar",{**self.reauth(secret),"motivo":"Límite de intentos alcanzado"},409)
        dispatch_one(request,row.id_notificacion)
        self.assertEqual(len(self.messages),count)

    def test_recovery_preserves_secret_link_delivery_without_queuing_its_token(self):
        target,data,_,_ = self.enroll(2)
        self.post("/logout")
        _,_,secret,_ = self.enroll(99,admin=True)
        self.messages.clear()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        q = app.state.tables["auth_solicitud_password"]
        identifier = self.connection.scalar(select(q.c.id_solicitud).where(q.c.id_usuario==target,q.c.estado=="pendiente"))
        self.post(f"/admin/recuperaciones/{identifier}/resolver",{**self.reauth(secret),"decision":"aprobar",
            "motivo":"Solicitud e identidad confirmadas por canal autorizado"})
        personal = [m for m in self.messages if m[0]==data["correo"] and "#token=" in m[2]]
        self.assertEqual(len(personal),1)
        token = re.search(r"#token=([^\s]+)",personal[0][2])[1]
        self.assertNotIn(token," ".join(m[2] for m in self.messages if m[0]=="admin@example.org"))
        self.assertNotIn(token,str([dict(r) for r in self.queue()]))
        self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD})
        self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD},400)
        result = self.post("/login",{"correo":data["correo"],"password":fixtures.NEW_PASSWORD}).json()
        self.assertEqual(result["etapa"],"mfa")

    def test_queue_has_safe_references_only_and_public_config_hides_admin_and_secrets(self):
        config = self.client.get("/api/auth/contacto").json()
        self.assertEqual(config,{"support_email":"soporte@example.org","support_enabled":True})
        columns = set(app.state.tables["auth_notificacion"].c.keys())
        self.assertFalse(columns & {"password","token","contenido","html","codigo","secreto","smtp_password"})


class MailEnvelopeTests(unittest.TestCase):
    def test_resend_ssl_and_header_routing_use_existing_smtp(self):
        from backend.auth.mailer import deliver
        from backend.auth.config import Settings
        with patch.dict("os.environ",{"AUTH_ENV":"development","MAIL_TRANSPORT":"smtp",
                "MAIL_FROM":"TacticLens <no-reply@tacticlens.app>","ADMIN_EMAIL":"admin@example.org",
                "SUPPORT_EMAIL":"soporte@example.org","SMTP_HOST":"smtp.resend.com","SMTP_PORT":"465",
                "SMTP_USER":"resend","SMTP_PASSWORD":"fake-test-key","SMTP_SSL":"true","SMTP_STARTTLS":"false"}), \
                patch("backend.auth.mailer.smtplib.SMTP_SSL") as transport:
            deliver(Settings.load(),"consulta@example.org","Prueba simulada","Sin contenido secreto",idempotency_key="tacticlens/test/1")
            smtp = transport.return_value.__enter__.return_value
            transport.assert_called_once()
            self.assertEqual(transport.call_args.args,("smtp.resend.com",465))
            smtp.starttls.assert_not_called()
            smtp.login.assert_called_once_with("resend","fake-test-key")
            message = smtp.send_message.call_args.args[0]
            self.assertEqual(str(message["Reply-To"]),"soporte@example.org")
            self.assertEqual(str(message["Resend-Idempotency-Key"]),"tacticlens/test/1")
            self.assertNotIn("fake-test-key",message.as_string())
            with self.assertRaises(ValueError):
                deliver(Settings.load(),"consulta@example.org","Seguro","Texto",reply_to="x@example.org\r\nBcc:y@example.org")
            with self.assertRaises(ValueError):
                deliver(Settings.load(),"consulta@example.org","Seguro","Texto",idempotency_key="key\ninvalid")

    def test_starttls_587_still_supported(self):
        from backend.auth.mailer import deliver
        from backend.auth.config import Settings
        with patch.dict("os.environ",{"AUTH_ENV":"development","MAIL_TRANSPORT":"smtp","MAIL_FROM":"TacticLens <no-reply@example.org>",
                "SMTP_HOST":"smtp.example.org","SMTP_PORT":"587","SMTP_SSL":"false","SMTP_STARTTLS":"true"}), \
                patch("backend.auth.mailer.smtplib.SMTP") as transport:
            deliver(Settings.load(),"consulta@example.org","Prueba simulada","Texto")
            transport.return_value.__enter__.return_value.starttls.assert_called_once()
