"""Offline provider contract and credential boundary."""
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
import unittest
import httpx

from backend.enrichment import enrich


def event(number, raw):
    return SimpleNamespace(id_evento=number, fecha_hora=datetime.now(timezone.utc), datos_originales=raw)


class EnrichmentTests(unittest.TestCase):
    def test_private_address_and_missing_providers(self):
        events = [event(1, {"eventid": "cowrie.session.connect", "src_ip": "192.168.56.101"})]
        with patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "fixture", "URLHAUS_AUTH_KEY": "fixture",
                                     "MISP_WARNING_LISTS_DIR": ""}), patch("backend.enrichment.httpx.post") as post:
            result = enrich(events)
        post.assert_not_called()
        self.assertEqual(result["observables"][0]["proveedores"]["threatfox"]["estado"], "omitido")

    def test_local_warning_list_offline(self):
        with TemporaryDirectory() as folder:
            directory = Path(folder) / "known-test"
            directory.mkdir()
            (directory / "list.json").write_text(json.dumps({"name": "Fixture", "version": 2,
                "type": "cidr", "list": ["192.168.0.0/16"]}), encoding="utf-8")
            with patch.dict("os.environ", {"MISP_WARNING_LISTS_DIR": folder,
                                         "THREATFOX_AUTH_KEY": "", "URLHAUS_AUTH_KEY": ""}), patch("backend.enrichment.httpx.post") as post:
                result = enrich([event(2, {"eventid": "cowrie.session.connect", "src_ip": "192.168.56.101"})])
            post.assert_not_called()
        self.assertEqual(result["observables"][0]["proveedores"]["misp_warning_lists"][0]["version"], 2)

    def test_remote_failure_and_quota_are_separate(self):
        events = [event(3, {"eventid": "cowrie.session.connect", "src_ip": "8.8.8.8"})]
        with patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "fixture", "URLHAUS_AUTH_KEY": "",
                                     "MISP_WARNING_LISTS_DIR": ""}):
            with patch("backend.enrichment.httpx.post", side_effect=httpx.ConnectError("offline")):
                offline = enrich(events)
            self.assertEqual(offline["observables"][0]["proveedores"]["threatfox"]["estado"], "error")
            response = Mock(status_code=429)
            with patch("backend.enrichment.httpx.post", return_value=response):
                result = enrich(events)
        self.assertEqual(result["observables"][0]["proveedores"]["threatfox"]["estado"], "cuota")

    def test_captured_password_is_never_sent(self):
        events = [event(4, {"eventid": "cowrie.login.failed", "password": "captured-password",
                            "src_ip": "8.8.4.4"})]
        response = Mock(status_code=200)
        response.json.return_value = {"query_status": "no_result"}
        with patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "fixture", "URLHAUS_AUTH_KEY": "",
                                     "MISP_WARNING_LISTS_DIR": ""}), patch("backend.enrichment.httpx.post", return_value=response) as post:
            enrich(events)
        self.assertNotIn("captured-password", str(post.call_args))


if __name__ == "__main__":
    unittest.main()
