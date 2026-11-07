"""New administrative flows over real PostgreSQL, with external mail mocked."""
from datetime import datetime, timedelta
import re
from unittest.mock import patch

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
import test_auth as fixtures

from backend.api import app
from backend.auth.security import now


class AdministrationTests(fixtures.AuthFixture):
    def test_security_mail_template_escapes_text_and_builds_personal_link(self):
        from backend.auth.mailer import html_content
        rendered=html_content('<script>alert("x")</script>\nhttps://tacticlens.app/recuperar#token=sample')
        self.assertNotIn("<script>",rendered)
        self.assertIn("&lt;script&gt;",rendered)
        self.assertIn('rel="noreferrer noopener"',rendered)
        self.assertIn('href="https://tacticlens.app/recuperar#token=sample"',rendered)

    def browser(self, cookies=None):
        self.client.cookies.clear()
        if cookies:
            self.client.cookies.update(cookies)
        self.client.headers["x-csrf-token"] = self.client.get("/api/auth/csrf").json()["csrf_token"]

    def managed_pair(self):
        target, data, _, _ = self.enroll(2)
        cookies = dict(self.client.cookies)
        self.browser()
        actor, _, secret, _ = self.enroll(99, admin=True)
        return target, data, cookies, actor, secret

    def request_id(self, user_id):
        q = app.state.tables["auth_solicitud_password"]
        return self.connection.scalar(select(q.c.id_solicitud).where(q.c.id_usuario == user_id).order_by(q.c.estado.in_(["pendiente","aprobada"]).desc(),q.c.creado_en.desc()))

    def resolve(self, request_id, secret, decision="aprobar", expected=200):
        return self.post(f"/admin/recuperaciones/{request_id}/resolver", {
            **self.reauth(secret), "decision": decision, "motivo": "Identidad y solicitud verificadas por canal autorizado"
        }, expected)

    def token(self):
        return re.search(r"#token=([^\s]+)", self.messages[-1][2])[1]

    def test_public_request_is_generic_deduplicated_and_has_no_link(self):
        user_id, data, _, _ = self.enroll()
        self.post("/logout")
        missing = self.post("/password/solicitar", {"correo":"missing@example.org"}, 202)
        existing = self.post("/password/solicitar", {"correo":data["correo"]}, 202)
        self.assertEqual(missing.json(), existing.json())
        self.assertNotIn("#token=", self.messages[-1][2])
        count = len(self.messages)
        self.post("/password/solicitar", {"correo":data["correo"]}, 202)
        self.assertEqual(len(self.messages), count)
        q, t = app.state.tables["auth_solicitud_password"], app.state.tables["auth_token"]
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(q).where(q.c.id_usuario == user_id)), 1)
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(t).where(t.c.id_usuario == user_id, t.c.proposito == "password")), 0)
        with self.assertRaises(IntegrityError), self.connection.begin_nested():
            self.connection.execute(q.insert().values(id_usuario=user_id,vence_en=now()+timedelta(hours=1)))

    def test_recovery_cannot_be_requested_for_pending_rejected_suspended_or_blocked(self):
        user_id, data, _ = self.account()
        u, q = app.state.tables["usuario"], app.state.tables["auth_solicitud_password"]
        for authorization, active, restriction in (("pendiente",True,None),("rechazado",False,None),
                ("aprobado",False,"suspendido"),("aprobado",False,"bloqueado")):
            with self.subTest(estado=restriction or authorization):
                self.connection.execute(u.update().where(u.c.id_usuario==user_id).values(autorizacion=authorization,activo=active,restriccion_acceso=restriction))
                self.post("/password/solicitar",{"correo":data["correo"]},202)
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(q).where(q.c.id_usuario==user_id)),0)

    def test_administrator_approval_link_consumption_and_no_secret_in_admin_views(self):
        target,data,cookies,actor,secret = self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        self.resolve(request_id,secret)
        token=self.token()
        response=self.client.get("/api/auth/admin/recuperaciones").json()
        row=next(r for r in response if r["id_solicitud"]==str(request_id))
        self.assertEqual(row["estado"],"aprobada")
        self.assertEqual(row["resuelto_por"],str(actor))
        self.assertEqual(row["notificacion_estado"],"enviada")
        self.assertNotIn(token,str(response))
        self.assertNotIn(token,self.client.get("/api/auth/admin/auditoria").text)
        t=app.state.tables["auth_token"]
        stored=self.connection.execute(select(t).where(t.c.id_solicitud==request_id,t.c.usado_en.is_(None))).mappings().one()
        self.assertEqual(len(stored.token_hash),64)
        self.assertNotEqual(stored.token_hash,token)
        self.assertAlmostEqual((stored.vence_en-datetime.fromisoformat(row["resuelto_en"])).total_seconds(),900,delta=1)
        self.post("/password/validar",{"token":token})
        self.post("/password/validar",{"token":token})
        self.assertIsNone(self.connection.scalar(select(t.c.usado_en).where(t.c.id_token==stored.id_token)))
        reset=self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD})
        self.assertNotIn("set-cookie",reset.headers)
        self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD},400)
        q=app.state.tables["auth_solicitud_password"]
        self.assertEqual(self.connection.scalar(select(q.c.estado).where(q.c.id_solicitud==request_id)),"completada")
        self.browser(cookies)
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)
        self.post("/login",{"correo":data["correo"],"password":fixtures.PASSWORD},401)
        self.assertEqual(self.post("/login",{"correo":data["correo"],"password":fixtures.NEW_PASSWORD}).json()["etapa"],"mfa")

    def test_rejection_emits_no_link_and_decision_cannot_be_repeated(self):
        target,data,_,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        self.resolve(request_id,secret,"rechazar")
        self.assertNotIn("#token=",self.messages[-1][2])
        self.resolve(request_id,secret,expected=409)
        t=app.state.tables["auth_token"]
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(t).where(t.c.id_solicitud==request_id)),0)

    def test_mail_failure_leaves_request_pending_and_invalidates_attempt_token(self):
        target,data,_,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        with patch("backend.auth.mailer.deliver",side_effect=OSError("private transport detail")):
            response=self.resolve(request_id,secret,expected=503)
        self.assertNotIn("private transport detail",response.text)
        q,t=app.state.tables["auth_solicitud_password"],app.state.tables["auth_token"]
        row=self.connection.execute(select(q).where(q.c.id_solicitud==request_id)).mappings().one()
        self.assertEqual(row.estado,"pendiente")
        self.assertEqual(row.notificacion_estado,"fallida")
        self.assertIsNone(row.resuelto_en)
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(t).where(t.c.id_solicitud==request_id,t.c.usado_en.is_(None))),0)
        self.resolve(request_id,secret)
        self.assertIn("#token=",self.messages[-1][2])

    def test_expired_link_rejected_and_new_request_possible(self):
        target,data,_,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        previous=self.request_id(target)
        self.resolve(previous,secret)
        token=self.token()
        q,t=app.state.tables["auth_solicitud_password"],app.state.tables["auth_token"]
        self.connection.execute(q.update().where(q.c.id_solicitud==previous).values(enlace_vence_en=now()-timedelta(seconds=1)))
        self.connection.execute(t.update().where(t.c.id_solicitud==previous).values(vence_en=now()-timedelta(seconds=1)))
        self.post("/password/validar",{"token":token},400)
        self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD},400)
        listed=self.client.get("/api/auth/admin/recuperaciones?estado=expirada").json()
        self.assertIn(str(previous),[r["id_solicitud"] for r in listed])
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        self.assertNotEqual(previous,self.request_id(target))

    def test_suspension_and_blocking_cancel_links_and_all_sessions_then_reactivation_requires_new_login(self):
        target,data,cookies,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        self.resolve(self.request_id(target),secret)
        token=self.token()
        for action in ("suspender","bloquear","reactivar"):
            response=self.client.patch(f"/api/auth/admin/usuarios/{target}",json={**self.reauth(secret),"rol":"analista","activo":action=="reactivar","accion":action,"motivo":"Restricción administrativa documentada para revisión"})
            self.assertEqual(response.status_code,200,response.text)
            self.assertIn({"suspender":"suspendida","bloquear":"bloqueada","reactivar":"reactivada"}[action],self.messages[-1][1].lower())
        self.post("/password/restablecer",{"token":token,"password":fixtures.NEW_PASSWORD,"confirmacion":fixtures.NEW_PASSWORD},400)
        self.browser(cookies)
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)
        self.assertEqual(self.post("/login",{"correo":data["correo"],"password":fixtures.PASSWORD}).json()["etapa"],"mfa")

    def test_suspension_blocks_login_and_pending_request_cannot_be_approved(self):
        target,data,cookies,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target}",json={**self.reauth(secret),"rol":"analista","activo":False,"accion":"bloquear","motivo":"Acceso bloqueado durante revisión de seguridad"}).status_code,200)
        self.resolve(request_id,secret,expected=409)
        self.browser(cookies)
        self.post("/login",{"correo":data["correo"],"password":fixtures.PASSWORD},401)

    def test_role_state_filters_search_sort_and_activity_are_computed(self):
        target,data,_,_,_=self.managed_pair()
        s=app.state.tables["auth_sesion"]
        self.connection.execute(s.update().where(s.c.id_usuario==target).values(ultima_actividad=self.clock-timedelta(minutes=5)))
        response=self.client.get(f"/api/auth/admin/usuarios?q={data['correo']}&rol=analista&estado=activo&orden=actividad&direccion=asc&limit=1").json()
        self.assertEqual(len(response),1)
        self.assertEqual(response[0]["id_usuario"],str(target))
        self.assertEqual(response[0]["sesiones_activas"],1)
        self.assertEqual(response[0]["conexion"],"inactivo")
        self.assertIsNotNone(response[0]["ultimo_acceso_en"])
        listing=self.client.get(f"/api/auth/admin/sesiones?usuario={target}").json()
        current=next(r for r in listing if r["estado"]=="vigente")
        self.assertEqual(current["actividad"],"inactivo")
        self.assertNotIn("token_hash",str(listing))
        self.assertNotIn("ip_hash",str(listing))

    def test_presence_requires_interaction_endpoint_and_polling_does_not_extend_it(self):
        user_id,_,_,_=self.enroll(admin=True)
        s=app.state.tables["auth_sesion"]
        old=self.clock-timedelta(minutes=5)
        self.connection.execute(s.update().where(s.c.id_usuario==user_id,s.c.etapa=="completa").values(ultima_actividad=old))
        rows=self.client.get(f"/api/auth/admin/sesiones?usuario={user_id}").json()
        self.assertEqual(next(r for r in rows if r["estado"]=="vigente")["actividad"],"inactivo")
        self.assertEqual(self.connection.scalar(select(s.c.ultima_actividad).where(s.c.id_usuario==user_id,s.c.etapa=="completa")),old)
        self.post("/actividad",expected=204)
        rows=self.client.get(f"/api/auth/admin/sesiones?usuario={user_id}&estado=vigente").json()
        self.assertEqual(rows[0]["actividad"],"recientemente_activo")

    def test_specific_and_all_session_revocation_are_effective(self):
        target,_,cookies,_,secret=self.managed_pair()
        rows=self.client.get(f"/api/auth/admin/sesiones?usuario={target}&estado=vigente").json()
        sid=rows[0]["id_sesion"]
        self.post(f"/admin/sesiones/{sid}/revocar",{**self.reauth(secret),"motivo":"Cierre solicitado tras revisión administrativa"})
        self.post(f"/admin/sesiones/{sid}/revocar",{**self.reauth(secret),"motivo":"Segundo intento de cierre documentado"},409)
        self.post(f"/admin/usuarios/{target}/sesiones/revocar",{**self.reauth(secret),"motivo":"Revocar accesos restantes del usuario"})
        self.browser(cookies)
        self.assertEqual(self.client.get("/api/sesiones").status_code,401)

    def test_analyst_cannot_manage_sessions_requests_history_or_states(self):
        target,data,_=self.account(2,approve=True)
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        _,_,secret,_=self.enroll()
        for path in ("/admin/usuarios","/admin/sesiones","/admin/recuperaciones","/admin/auditoria"):
            self.assertEqual(self.client.get("/api/auth"+path).status_code,403)
        self.resolve(request_id,secret,expected=403)
        self.assertEqual(self.client.patch(f"/api/auth/admin/usuarios/{target}",json={**self.reauth(secret),"rol":"administrador","activo":True}).status_code,403)

    def test_admin_cannot_block_self_or_reactivate_a_pending_or_rejected_registration(self):
        target,_,_=self.account(2)
        actor,_,secret,_=self.enroll(admin=True)
        for affected,action,expected in ((actor,"bloquear",403),(target,"reactivar",409)):
            result=self.client.patch(f"/api/auth/admin/usuarios/{affected}",json={**self.reauth(secret),"rol":"administrador","activo":action=="reactivar","accion":action,"motivo":"Operación administrativa para verificar protección"})
            self.assertEqual(result.status_code,expected,result.text)

    def test_decisions_require_reauthentication_and_reasons_and_are_audited(self):
        target,data,_,actor,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        data={**self.reauth(secret),"decision":"aprobar","motivo":"   "}
        self.post(f"/admin/recuperaciones/{request_id}/resolver",data,422)
        self.post(f"/admin/recuperaciones/{request_id}/resolver",{**data,"motivo":"Identidad revisada presencialmente","password":"incorrecta"},400)
        self.resolve(request_id,secret)
        rows=self.client.get(f"/api/auth/admin/auditoria?usuario={target}&tipo=recuperacion_aprobada").json()
        self.assertEqual(rows[0]["actor_id"],str(actor))
        self.assertEqual(rows[0]["metadatos"]["resultado"],"enviada")
        self.assertNotIn(self.token(),str(rows))

    def test_rate_limit_request_and_expired_pending_request(self):
        target,data,_,_,secret=self.managed_pair()
        for _ in range(5):
            self.post("/password/solicitar",{"correo":data["correo"]},202)
        self.post("/password/solicitar",{"correo":data["correo"]},429)
        q=app.state.tables["auth_solicitud_password"]
        request_id=self.request_id(target)
        self.connection.execute(q.update().where(q.c.id_solicitud==request_id).values(vence_en=self.clock-timedelta(seconds=1)))
        self.resolve(request_id,secret,expected=409)

    def test_password_reset_link_uses_trusted_frontend_origin_and_headers(self):
        target,data,_,_,secret=self.managed_pair()
        self.post("/password/solicitar",{"correo":data["correo"]},202)
        request_id=self.request_id(target)
        result=self.resolve(request_id,secret)
        self.assertIn("http://127.0.0.1:5173/recuperar#token=",self.messages[-1][2])
        self.assertEqual(result.headers["referrer-policy"],"no-referrer")
        self.assertIn("no-store",result.headers["cache-control"])
