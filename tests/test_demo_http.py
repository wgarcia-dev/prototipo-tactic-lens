"""No network/SMTP: enforce explicit private HTTP and the LAN API boundary."""
import os
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from backend.ingest_transport import IngestTransportMiddleware, validate_demo_settings
from collector.sqlite_sender import validate_endpoint

ENV={'INGEST_TRANSPORT':'demo-http','AUTH_ENV':'development',
     'INGEST_DEMO_LOCAL_IP':'192.168.0.111','INGEST_DEMO_UBUNTU_IP':'192.168.0.110'}
URL='http://192.168.0.111:8000/api/ingesta/eventos'


class DemoHttpTests(unittest.TestCase):
    def test_direct_http_requires_explicit_mode_and_exact_private_api(self):
        validate_endpoint(URL,'test-key','demo-http')
        with self.assertRaises(ValueError):validate_endpoint(URL,'test-key')
        for url in ('http://8.8.8.8:8000/api/ingesta/eventos','http://127.0.0.1:8000/api/ingesta/eventos',
                    'http://192.168.0.111:80/api/ingesta/eventos',URL+'?key=x',
                    'http://user:pass@192.168.0.111:8000/api/ingesta/eventos',
                    'http://[fd00::1]:8000/api/ingesta/eventos','http://192.168.0.111:8000/auxiliar'):
            with self.subTest(url=url),self.assertRaises(ValueError):validate_endpoint(url,'key','demo-http')

    def test_production_and_public_settings_fail_closed(self):
        with patch.dict(os.environ,ENV):
            validate_demo_settings()
            for changes in ({'AUTH_ENV':'production'},{'INGEST_DEMO_LOCAL_IP':'0.0.0.0'},
                            {'INGEST_DEMO_UBUNTU_IP':'8.8.8.8'},{'INGEST_DEMO_LOCAL_IP':'192.168.0.110'}):
                with patch.dict(os.environ,changes),self.assertRaises((ValueError,RuntimeError)):
                    validate_demo_settings()

    def client(self,peer):
        async def ok(request):return JSONResponse({'ok':True})
        app=Starlette(routes=[Route('/{rest:path}',ok,methods=['GET','POST'])])
        app.add_middleware(IngestTransportMiddleware)
        return TestClient(app,client=(peer,45678))

    def test_only_ubuntu_can_reach_health_and_machine_posts_on_lan(self):
        with patch.dict(os.environ,ENV):
            client=self.client('192.168.0.110')
            self.assertEqual(client.get('/api/health').status_code,200)
            self.assertEqual(client.post('/api/ingesta/eventos').status_code,200)
            self.assertEqual(client.post('/api/ingesta/heartbeat').status_code,200)
            for path in ('/api/auth/login','/api/sesiones','/docs'):
                self.assertEqual(client.get(path).status_code,403)
            self.assertEqual(client.get('/api/ingesta/eventos').status_code,403)
            self.assertEqual(self.client('192.168.0.112').get('/api/health').status_code,403)
            self.assertEqual(self.client('127.0.0.1').get('/api/auth/login').status_code,200)

    def test_forged_forwarded_ip_does_not_grant_access(self):
        with patch.dict(os.environ,ENV):
            self.assertEqual(self.client('192.168.0.112').post('/api/ingesta/eventos',
                headers={'X-Forwarded-For':'192.168.0.110'}).status_code,403)

    def test_plaintext_machine_ingestion_is_denied_outside_demo(self):
        with patch.dict(os.environ,{'INGEST_TRANSPORT':''}):
            self.assertEqual(self.client('192.168.0.110').post('/api/ingesta/eventos').status_code,403)
            self.assertEqual(self.client('127.0.0.1').post('/api/ingesta/eventos').status_code,200)
