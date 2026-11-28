"""Offline provider contracts, quota, deadline and credential boundary."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Event
from time import monotonic
from types import SimpleNamespace
from unittest.mock import patch
import json
import unittest
import httpx

from backend import enrichment as module

SHA = "ab" * 32


def event(number, raw):
    return SimpleNamespace(id_evento=number, fecha_hora=datetime.now(timezone.utc), datos_originales=raw)


def response(status, body=None, invalid=False):
    return httpx.Response(status, json=body, content=b"{invalid" if invalid else None)


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        with module._LOCK:
            module._CACHE.clear()
            module._REQUESTS.clear()
            module._COOLDOWN.clear()
        self.configuration = patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "synthetic-fixture",
            "URLHAUS_AUTH_KEY": "", "MISP_WARNING_LISTS_DIR": "", "ENRICHMENT_RETRIES": "0",
            "ENRICHMENT_TOTAL_TIMEOUT_SECONDS": "1", "ENRICHMENT_CACHE_TTL_SECONDS": "10",
            "ENRICHMENT_CACHE_MAX_ENTRIES": "16", "THREATFOX_REQUESTS_PER_MINUTE": "30"})
        self.configuration.start()
        self.addCleanup(self.configuration.stop)

    def run_on(self, provider="threatfox", raw=None):
        raw = raw or {"eventid": "cowrie.session.connect", "src_ip": "8.8.8.8"}
        items = module.enrich([event(1, raw)])["observables"]
        return next(item["proveedores"][provider] for item in items if provider in item["proveedores"])

    def test_private_address_and_nested_credentials_are_local(self):
        with patch("backend.enrichment.httpx.post") as post:
            self.assertEqual(self.run_on(raw={"src_ip": "192.168.1.51"})["estado"], "omitido")
            data = {"input": "curl https://user:synthetic-credential@files.example.net/payload?token=hidden-synthetic",
                    "metadata": {"api_key": "8.8.4.4"}, "src_ip": "8.8.4.4"}
            module.enrich([event(2, data)])
        self.assertNotIn("synthetic-credential", str(post.call_args_list))
        self.assertNotIn("hidden-synthetic", str(post.call_args_list))
        self.assertNotIn("8.8.4.4", str(post.call_args_list))

    def test_local_warning_list_offline_and_incompatible(self):
        with TemporaryDirectory() as folder, patch.dict("os.environ", {"MISP_WARNING_LISTS_DIR": folder}), \
             patch("backend.enrichment.httpx.post", return_value=response(503)):
            path = Path(folder, "known-test")
            path.mkdir()
            file = path / "list.json"
            file.write_text(json.dumps({"name": "Fixture", "version": 2, "type": "cidr",
                                         "list": ["192.168.0.0/16"]}), encoding="utf-8")
            result = self.run_on("misp_warning_lists", {"src_ip": "192.168.1.51"})
            self.assertEqual(result["estado"], "coincidencia")
            self.assertEqual(result["coincidencias"][0]["version"], 2)
            self.assertEqual(self.run_on("misp_warning_lists")["estado"], "sin_resultados")
            file.write_text("{}", encoding="utf-8")
            self.assertEqual(self.run_on("misp_warning_lists")["estado"], "respuesta_incompatible")

    def test_offline_timeout_auth_quota_json_and_contract_failures_are_distinct(self):
        failures = [
            (httpx.ConnectError("offline"), "no_disponible"),
            (httpx.ReadTimeout("timeout"), "timeout"),
            (response(500), "no_disponible"),
            (response(403), "error_autenticacion"),
            (response(200, invalid=True), "respuesta_incompatible"),
            (response(200, {"query_status": "ok", "data": {"id": 1}}), "respuesta_incompatible"),
            (response(200, {"query_status": "unexpected", "data": []}), "respuesta_incompatible"),
            (response(429), "cuota"),
        ]
        for reply, expected in failures:
            with self.subTest(expected=expected), patch("backend.enrichment.httpx.post",
                side_effect=reply if isinstance(reply, Exception) else None,
                return_value=reply) as post:
                self.assertEqual(self.run_on()["estado"], expected)
                self.assertEqual(post.call_count, 1)

    def test_valid_and_absent_provider_specific_results_and_partial_continuity(self):
        raw = {"eventid": "cowrie.session.file_download", "shasum": SHA}
        def post(url, **kwargs):
            if "threatfox" in url:
                if kwargs["json"]["hash"] != SHA:
                    return response(200, {"query_status": "no_result"})
                return response(200, {"query_status": "ok", "data": [{"id": 456}]})
            self.assertEqual(kwargs["data"], {"sha256_hash": SHA})
            return response(200, {"query_status": "ok", "sha256_hash": SHA, "urls": []})
        with patch.dict("os.environ", {"URLHAUS_AUTH_KEY": "synthetic-urlhaus"}), \
             patch("backend.enrichment.httpx.post", side_effect=post):
            items = module.enrich([event(1, raw)])["observables"]
            hits = next(item["proveedores"] for item in items if item["valor"] == SHA)
            self.assertEqual(hits["threatfox"]["id"], "456")
            self.assertEqual(hits["urlhaus"]["estado"], "coincidencia")
        def partial(url, **_):
            return response(401) if "threatfox" in url else response(200, {"query_status": "no_results"})
        with patch.dict("os.environ", {"THREATFOX_AUTH_KEY": "another-fixture", "URLHAUS_AUTH_KEY": "another-urlhaus"}), \
             patch("backend.enrichment.httpx.post", side_effect=partial):
            hits = module.enrich([event(1, raw)])["observables"][0]["proveedores"]
            self.assertEqual(hits["threatfox"]["estado"], "error_autenticacion")
            self.assertEqual(hits["urlhaus"]["estado"], "sin_resultados")

    def test_retry_quota_ttl_and_bounded_cache(self):
        ok = response(200, {"query_status": "no_result"})
        with patch.dict("os.environ", {"ENRICHMENT_RETRIES": "1", "THREATFOX_REQUESTS_PER_MINUTE": "2"}), \
             patch("backend.enrichment.httpx.post", side_effect=[response(503), ok]) as post:
            self.assertEqual(self.run_on()["estado"], "sin_resultados")
            self.assertEqual(self.run_on(raw={"src_ip":"1.1.1.1"})["estado"], "cuota")
            self.assertEqual(post.call_count, 2)
        with module._LOCK:
            module._REQUESTS.clear()
            module._CACHE.clear()
        with patch.dict("os.environ", {"ENRICHMENT_CACHE_MAX_ENTRIES": "1"}), \
             patch("backend.enrichment.httpx.post", return_value=ok) as post:
            self.run_on()
            self.assertTrue(self.run_on()["cache"])
            self.run_on(raw={"src_ip": "1.1.1.1"})
            self.assertEqual(len(module._CACHE), 1)
            self.run_on()
            self.assertEqual(post.call_count, 3)
            with module._LOCK:
                for key, (_, value) in list(module._CACHE.items()):
                    module._CACHE[key] = (monotonic() - 100, value)
            self.run_on()
            self.assertEqual(post.call_count, 4)

    def test_concurrent_calls_and_deadline(self):
        two = Barrier(2)
        release = Event()
        launched = Event()
        def blocking(*args, **kwargs):
            two.wait(timeout=1)
            launched.set()
            release.wait(timeout=1)
            return response(200, {"query_status": "no_result"})
        inputs = [event(1, {"src_ip":"8.8.8.8"}), event(2, {"src_ip":"1.1.1.1"})]
        with patch.dict("os.environ", {"ENRICHMENT_TOTAL_TIMEOUT_SECONDS": "0.16"}), \
             patch("backend.enrichment.httpx.post", side_effect=blocking) as send, ThreadPoolExecutor(2) as executor:
            started = monotonic()
            first, second = [executor.submit(module.enrich, inputs) for _ in range(2)]
            try:
                self.assertTrue(launched.wait(0.5))
                outputs = [first.result(0.8), second.result(0.8)]
                elapsed = monotonic() - started
                self.assertLess(elapsed, 0.5)
                self.assertEqual(send.call_count, 2)
                for output in outputs:
                    self.assertEqual([item["proveedores"]["threatfox"]["estado"] for item in output["observables"]],
                                     ["timeout", "timeout"])
                print(f"H08: dos consultas en paralelo, dos consumidores, {elapsed * 1000:.1f} ms con presupuesto de 160 ms.")
            finally:
                release.set()
                for future in list(module._INFLIGHT.values()):
                    future.result(1)


if __name__ == "__main__":
    unittest.main()
