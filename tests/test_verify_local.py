import unittest
from scripts.verify_local import local_url


class ReadOnlyVerifierTests(unittest.TestCase):
    def test_verifier_only_contacts_loopback_and_never_accepts_url_secrets(self):
        self.assertEqual(local_url('http://127.0.0.1:8000/'),'http://127.0.0.1:8000')
        for value in ('http://192.168.0.100:8000','https://example.org',
                      'http://user:secret@localhost','http://localhost/?token=secret',
                      'http://localhost/path','http://localhost/#secret'):
            with self.subTest(value=value),self.assertRaises(ValueError):local_url(value)
