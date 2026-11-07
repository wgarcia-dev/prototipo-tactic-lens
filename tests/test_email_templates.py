"""Transactional mail rendering and MIME delivery with no network connection."""
from email import policy
from email.parser import BytesParser
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from backend.auth.email_templates import message_parts, presentation, render_email, safe_link
from backend.auth.mailer import deliver


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class EmailTemplateTests(unittest.TestCase):
    def test_verification_code_is_contiguous_unique_and_keeps_expiration(self):
        subject = "Verifique su correo para registrarse"
        content = "Su código de verificación es: 000047\n\nCaduca en 5 minutos y solo puede usarse una vez."
        html = render_email(subject, content)
        self.assertEqual(html.count("000047"), 1)
        self.assertIn("CÓDIGO DE VERIFICACIÓN", html)
        self.assertIn("Caduca en 5 minutos", html)
        self.assertIn("Es diferente del código de Google Authenticator", html)
        self.assertNotIn("000047", presentation(subject).preheader)

    def test_approved_link_is_identical_in_button_and_copyable_fallback(self):
        url = "https://tacticlens.example/recuperar#token=DEMO_TOKEN&source=test"
        content = "Su solicitud fue aprobada.\n" + url + "\n\nEl enlace caduca en 15 minutos y solo puede utilizarse una vez."
        html = render_email("Recuperación aprobada: restablezca su contraseña", content)
        anchors = [attrs for tag, attrs in Elements(html).elements if tag == "a"]
        self.assertEqual([a["href"] for a in anchors], [url, url])
        self.assertTrue(all(a["rel"] == "noreferrer noopener" for a in anchors))
        self.assertIn("Restablecer contraseña", html)
        self.assertIn(escape(url), html)
        self.assertIn("caduca en 15 minutos", html)
        self.assertNotIn("DEMO_TOKEN", presentation("Recuperación aprobada").preheader)

    def test_first_password_and_recovery_have_distinct_action_labels(self):
        content = "Aprobado.\nhttps://tacticlens.example/recuperar#token=demo"
        first = render_email("Cuenta autorizada: defina su contraseña", content)
        recovery = render_email("Recuperación aprobada: restablezca su contraseña", content)
        self.assertIn("Crear mi contraseña", first)
        self.assertIn("Restablecer contraseña", recovery)
        self.assertNotIn("Restablecer contraseña", first)

    def test_informational_mail_does_not_invent_a_link_or_verification_code(self):
        for subject in ("Solicitud de registro recibida", "Solicitud de recuperación recibida",
                        "Contraseña actualizada", "Cuenta suspendida", "Cuenta bloqueada", "Cuenta reactivada"):
            with self.subTest(subject=subject):
                content = "Un administrador actualizó su cuenta. Contacte al administrador si necesita ayuda."
                html = render_email(subject, content)
                self.assertFalse(any(tag == "a" for tag, _ in Elements(html).elements))
                self.assertIn(content, html)

    def test_warning_states_and_generic_subjects_remain_distinguishable(self):
        self.assertEqual(presentation("Cuenta bloqueada").tone, "restricted")
        self.assertEqual(presentation("Cuenta suspendida").tone, "warning")
        self.assertEqual(presentation("Cuenta reactivada").tone, "neutral")
        self.assertEqual(presentation("Solicitud de recuperación rechazada").title, "Solicitud de recuperación rechazada")
        self.assertEqual(presentation("Aviso personalizado").title, "Aviso personalizado")

    def test_untrusted_text_and_subject_cannot_inject_html_or_active_content(self):
        subject = '<script>alert("subject")</script>'
        content = '<img src="https://tracker.invalid/pixel" onerror="alert(1)">\n\njavascript:alert(1)'
        html = render_email(subject, content)
        tags = [tag for tag, _ in Elements(html).elements]
        self.assertNotIn("script", tags)
        self.assertNotIn("img", tags)
        self.assertNotIn("a", tags)
        self.assertIn(escape(subject), html)
        self.assertIn(escape(content.split("\n\n")[0]), html)

    def test_link_attribute_is_escaped_and_unsafe_urls_stay_inert(self):
        content = 'https://example.org/recuperar#token="demo"'
        html = render_email("Restablecimiento de contraseña", content)
        links = [attrs for tag, attrs in Elements(html).elements if tag == "a"]
        self.assertEqual(links[0]["href"], content)
        self.assertTrue(all(set(attrs) <= {"href", "rel", "style"} for attrs in links))
        for url in ("javascript:alert(1)", "data:text/html,example", "http://[", "https://user:secret@example.org/", "https://example.org/\ninjected", "https://example.org/\\path"):
            with self.subTest(url=url):
                self.assertFalse(safe_link(url))

    def test_email_is_self_contained_accessible_and_has_fluid_fallbacks(self):
        html = render_email("Cuenta bloqueada", "Su cuenta fue bloqueada.")
        elements = Elements(html).elements
        self.assertIn(("html", {"lang":"es"}), elements)
        self.assertEqual(sum(tag == "h1" for tag, _ in elements), 1)
        self.assertTrue(all(attrs.get("role") == "presentation" for tag, attrs in elements if tag == "table"))
        self.assertFalse(any(tag in {"img", "script", "link", "iframe", "form", "input"} for tag, _ in elements))
        self.assertIn("max-width:600px", html)
        self.assertIn("@media screen and (max-width:620px)", html)
        self.assertIn("#0b1423", html)
        self.assertIn("#43d7d4", html)

    def test_file_transport_preserves_plain_text_and_produces_html_alternative(self):
        content = "Su código de verificación es: 123456\n\nCaduca en 5 minutos."
        with TemporaryDirectory() as directory, patch.dict("os.environ", {"MAIL_TRANSPORT":"file", "MAIL_DEV_DIRECTORY":directory}), patch("backend.auth.mailer.smtplib.SMTP"), patch("backend.auth.mailer.smtplib.SMTP_SSL") as network:
            deliver(SimpleNamespace(production=False), "person@example.org", "Verifique su correo electrónico", content)
            message = BytesParser(policy=policy.default).parsebytes(next(Path(directory).glob("*.eml")).read_bytes())
            self.assertIn(content, message.get_body(preferencelist=("plain",)).get_content())
            html = message.get_body(preferencelist=("html",)).get_content()
            self.assertIn("CÓDIGO DE VERIFICACIÓN", html)
            self.assertEqual(html.count("123456"), 1)
            network.assert_not_called()

    def test_ssl_smtp_configuration_is_unchanged_and_no_secrets_enter_the_message(self):
        with patch.dict("os.environ", {"MAIL_TRANSPORT":"smtp", "MAIL_FROM":"TacticLens <no-reply@tacticlens.app>",
                "SMTP_HOST":"smtp.resend.com", "SMTP_PORT":"465", "SMTP_USER":"resend",
                "SMTP_PASSWORD":"synthetic-private-key", "SMTP_SSL":"true", "SMTP_STARTTLS":"false"}), patch("backend.auth.mailer.smtplib.SMTP_SSL") as ssl_smtp, patch("backend.auth.mailer.smtplib.SMTP") as plain_smtp:
            deliver(SimpleNamespace(production=True), "person@example.org", "Cuenta reactivada", "Su cuenta fue reactivada.")
            client = ssl_smtp.return_value.__enter__.return_value
            client.login.assert_called_once_with("resend", "synthetic-private-key")
            client.starttls.assert_not_called()
            plain_smtp.assert_not_called()
            context = ssl_smtp.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            message = client.send_message.call_args.args[0]
            self.assertNotIn("synthetic-private-key", message.as_string())
            self.assertEqual(str(message["From"]), "TacticLens <no-reply@tacticlens.app>")

    def test_unrecognized_body_format_is_preserved_instead_of_discarded(self):
        content = "Un aviso nuevo con formato diferente.\nCódigo de soporte: 123456\n\nConserve esta información."
        code, link, paragraphs = message_parts(content, presentation("Aviso nuevo"))
        self.assertIsNone(code)
        self.assertIsNone(link)
        self.assertEqual(len(paragraphs), 2)
        html = render_email("Aviso nuevo", content)
        self.assertIn("Código de soporte: 123456", html)
        self.assertIn("Conserve esta información.", html)
