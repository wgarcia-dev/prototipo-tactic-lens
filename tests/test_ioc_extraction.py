from unittest import TestCase

from backend.intelligence import DOWNLOAD, FAILED_DOWNLOAD, UPLOAD, extract_observables
from backend.routes import Finding, IocProposal, supported_proposals


def command(value, **raw):
    return list(extract_observables({"eventid": "cowrie.command.input", "input": value, **raw}))


class CowrieObservableTests(TestCase):
    def test_ipv4_ipv6_and_connection_context(self):
        for original, canonical, scope in (
            ("192.168.56.1", "192.168.56.1", "privada"),
            ("FD00:0:0::A", "fd00::a", "privada"),
            ("127.0.0.1", "127.0.0.1", "loopback"),
            ("::1", "::1", "loopback"),
            ("FE80::01", "fe80::1", "enlace_local"),
            ("240.0.0.1", "240.0.0.1", "reservada"),
            ("100.64.0.10", "100.64.0.10", "no_enrutable"),
            ("192.0.2.1", "192.0.2.1", "documentacion"),
        ):
            with self.subTest(original=original):
                item, = extract_observables({"eventid": "cowrie.session.connect", "src_ip": original})
                self.assertEqual((item.valor_original, item.valor, item.alcance_ip), (original, canonical, scope))
                self.assertEqual((item.campo, item.comportamiento, item.grado_evidencia),
                                 ("src_ip", "conexion_origen", "resultado_registrado"))
        for invalid in ("300.1.1.1", "192.168.01.2", "2001:db8:::1", "fe80::1%eth0"):
            with self.subTest(invalid=invalid):
                self.assertEqual(command("ping " + invalid, src_ip=invalid), [])
        items = command("ping fd00:0::1; ping 192.168.1.2", src_ip="fd00::1")
        self.assertEqual([(x.valor, x.campo, x.comportamiento) for x in items], [
            ("fd00::1", "src_ip", "origen_sesion"), ("fd00::1", "input", "host_mencionado"),
            ("192.168.1.2", "input", "host_mencionado"),
        ])

    def test_domains_require_a_complete_contextual_argument(self):
        items = command("ping -c 1 BÜCHER.local.; ssh user@Repo.Corp.Local cat backup.zip")
        self.assertEqual([(x.valor_original, x.valor) for x in items], [
            ("BÜCHER.local.", "xn--bcher-kva.local"), ("Repo.Corp.Local", "repo.corp.local"),
        ])
        for line in ("echo hello.network.local 10.0.0.1", "ping bad..local", "host server.local..",
                     "ping -c 1 -invalid.local", "host bad_name.local", "ping /tmp/tool.net",
                     "printf bundles.zip", "ping 192.0.2.5", "ping api.example.org",
                     "wget https://service.test/file", "dig api.invalid"):
            with self.subTest(line=line):
                self.assertEqual(command(line), [])

    def test_urls_preserve_path_query_fragment_and_occurrences(self):
        original = "HTTPS://BÜCHER.local:443/Path%2f?q=%2B&x=2&x=1#Frag"
        value = "https://xn--bcher-kva.local:443/Path%2f?q=%2B&x=2&x=1#Frag"
        items = command(f"""curl -fsSL --url="{original}"; printf '{original}'""")
        self.assertEqual([(x.valor, x.valor_original, x.comportamiento) for x in items], [
            (value, original, "intento_descarga"), (value, original, "url_mencionada"),
        ])
        self.assertNotEqual(items[0].posicion, items[1].posicion)
        ipv6, = command("wget http://[FD00:0::1]:8080/artifact?#")
        self.assertEqual(ipv6.valor, "http://[fd00::1]:8080/artifact?#")
        self.assertEqual(ipv6.alcance_ip, "privada")
        quoted, = command("wget 'https://host.local/a?q=(1)'")
        self.assertEqual((quoted.valor, quoted.comportamiento), ("https://host.local/a?q=(1)", "intento_descarga"))
        for url in ("file:///tmp/foo", "https:///file", "https://bad..local/file",
                    "https://host.local:65536/", "http://[fd00::1]x/a", "http://host.local/%xx",
                    "https://u:pass@host.local/file", "https://[v1.bad]/file", "http://example.org/doc"):
            with self.subTest(url=url):
                self.assertEqual(command(f"wget '{url}'"), [])

    def test_command_context_avoids_claiming_a_transfer(self):
        for line in ("echo wget https://host.local/a", "curl -I https://host.local/a",
                     "curl -o https://host.local/a", "wget --spider https://host.local/a",
                     "curl --header https://host.local/a", "echo $(curl https://host.local/a)"):
            with self.subTest(line=line):
                item, = command(line)
                self.assertEqual((item.comportamiento, item.grado_evidencia), ("url_mencionada", "referencia"))
        self.assertEqual(command("echo marker # ; wget https://host.local/file"), [])
        self.assertEqual(list(extract_observables({"eventid": "cowrie.command.failed",
                         "input": "wget https://host.local/file"})), [])

    def test_transfer_outcomes_and_file_hash_provenance(self):
        sha = "Ab89" * 16
        url = "ftp://10.0.0.2/file"
        success = list(extract_observables({"eventid": DOWNLOAD, "url": url, "shasum": sha}))
        self.assertEqual([(x.tipo, x.campo, x.comportamiento, x.grado_evidencia) for x in success], [
            ("URL", "url", "descarga_registrada", "resultado_registrado"),
            ("Hash", "shasum", "archivo_capturado", "resultado_registrado"),
        ])
        self.assertEqual((success[1].valor, success[1].valor_original, success[1].algoritmo),
                         (sha.lower(), sha, "SHA-256"))
        failed, = extract_observables({"eventid": FAILED_DOWNLOAD, "url": url, "shasum": sha})
        self.assertEqual((failed.comportamiento, failed.grado_evidencia), ("descarga_fallida", "fallo_registrado"))
        uploaded, = extract_observables({"eventid": UPLOAD, "filename": "artifact", "shasum": sha})
        self.assertEqual(uploaded.comportamiento, "archivo_subido")
        local, = extract_observables({"eventid": DOWNLOAD, "outfile": "download/" + sha, "shasum": sha})
        self.assertEqual(local.tipo, "Hash")
        self.assertEqual(command(f"sha256sum {sha}; echo {sha}", shasum=sha), [])
        self.assertEqual(list(extract_observables({"eventid": "cowrie.log.closed", "shasum": sha})), [])
        for unsupported in (sha[:32], sha[:40], "z" * 64):
            self.assertEqual(list(extract_observables({"eventid": DOWNLOAD, "shasum": unsupported})), [])

    def test_model_only_matches_complete_typed_values_or_valid_event_references(self):
        action = Finding(tipo="shell", descripcion="Referencia observada", confianza=0.7, eventos=[10], iocs=[
            IocProposal(tipo="IP", valor="fd00::1", evento=10),
            IocProposal(tipo="URL", referencia=2, evento=10),
            IocProposal(tipo="URL", referencia=99, evento=10),
            IocProposal(tipo="Dominio", valor="host.local", referencia=2, evento=10),
            IocProposal(tipo="URL", valor="https://host.local/path", evento=10),
            IocProposal(tipo="IP", valor="fd00::1", evento=20),
            IocProposal(tipo="Hash", valor="a" * 64, evento=10),
            IocProposal(tipo="IP", valor="fd00::", evento=10),
        ])
        items = command("curl 'https://host.local/path?x=1&y=2'", src_ip="FD00:0::1")
        self.assertEqual([(value, reason) for _, value, reason in supported_proposals(action, {10: items})], [
            ("fd00::1", None), ("https://host.local/path?x=1&y=2", None),
            (None, "referencia_invalida"), (None, "sin_evidencia_determinista"),
            (None, "sin_evidencia_determinista"), (None, "evento_ajeno_a_la_accion"),
            (None, "sin_evidencia_determinista"), (None, "sin_evidencia_determinista"),
        ])
