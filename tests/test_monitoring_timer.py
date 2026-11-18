import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from collector import sqlite_sender
from scripts.ubuntu import configurar_monitoreo as timer


class TimerConfigurationTests(unittest.TestCase):
    def setup_case(self, service_type='oneshot', fail_reload=False):
        temp=TemporaryDirectory();self.addCleanup(temp.cleanup)
        base=Path(temp.name)
        config=base/'etc/tacticlens-cowrie/exportador.env';config.parent.mkdir(parents=True)
        original='TACTICLENS_URL=http://192.168.0.108:8000/api/ingesta/eventos\nTACTICLENS_TRANSPORT=demo-http\nTACTICLENS_TOKEN='+('fixture_'*6)+'\nTACTICLENS_SENSOR_ID=preserved\n'
        config.write_text(original,encoding='utf-8')
        queue=base/'queue.sqlite3';queue.write_bytes(b'unchanged-queue-and-cursor')
        actual_path=Path
        def path(value):
            value=str(value)
            return base/value.lstrip('/') if value.startswith(('/etc/','/etc/systemd','/var/')) else actual_path(value)
        def command(*args):
            if 'Type' in args:return service_type
            if 'RemainAfterExit' in args:return 'no'
            if 'ExecStart' in args:return '/usr/bin/python3 /opt/tacticlens-cowrie/exportar_eventos.py'
            if 'ActiveState' in args and '--value' in args:return 'inactive'
            return 'ActiveState=active\nTimersMonotonic=OnUnitInactiveUSec=30s'
        reloads=[]
        def run(args,check=False):
            if args==['systemctl','daemon-reload']:
                reloads.append(1)
                if fail_reload and len(reloads)==1:raise subprocess.CalledProcessError(1,args)
            return SimpleNamespace(returncode=3 if 'is-active' in args else 0)
        response=MagicMock();response.__enter__.return_value=response;response.status=422
        response.read.return_value=json.dumps({'contrato':'tacticlens.ingesta.v2','rechazados':1}).encode()
        opener=MagicMock();opener.open.return_value=response
        contexts=[patch.object(timer,'Path',side_effect=path),patch.object(timer,'command',side_effect=command),
            patch.object(timer.os,'geteuid',return_value=0,create=True),patch.object(timer.os,'chown',create=True),
            patch.object(timer.subprocess,'run',side_effect=run),patch.object(timer.urllib.request,'build_opener',return_value=opener),
            patch.dict(sys.modules,{'sqlite_sender':sqlite_sender})]
        mocks=[context.start() for context in contexts]
        for context in reversed(contexts):self.addCleanup(context.stop)
        return base,config,queue,original,mocks[4]

    def test_updates_only_url_and_dropin_with_private_backup_preserving_queue(self):
        base,config,queue,original,run=self.setup_case()
        timer.configure('http://192.168.0.107:8000/api/ingesta/eventos')
        self.assertEqual(config.read_text(),original.replace('192.168.0.108','192.168.0.107'))
        self.assertEqual(queue.read_bytes(),b'unchanged-queue-and-cursor')
        dropin=base/'etc/systemd/system/tacticlens-exportador.timer.d/20-monitoreo-local.conf'
        self.assertIn('OnUnitInactiveSec=2s',dropin.read_text())
        self.assertIn('AccuracySec=100ms',dropin.read_text())
        self.assertTrue(list((base/'var/lib/tacticlens-cowrie/backups').glob('*/exportador.env')))
        commands=[call.args[0] for call in run.call_args_list]
        self.assertNotIn(['systemctl','stop','cowrie-tacticlens.service'],commands)
        run.reset_mock()
        timer.configure('http://192.168.0.107:8000/api/ingesta/eventos')
        self.assertFalse(any(call.args[0]==['systemctl','stop',timer.TIMER] for call in run.call_args_list))

    def test_reload_failure_restores_original_configuration_and_timer(self):
        base,config,queue,original,run=self.setup_case(fail_reload=True)
        with self.assertRaises(subprocess.CalledProcessError):timer.configure('http://192.168.0.107:8000/api/ingesta/eventos')
        self.assertEqual(config.read_text(),original)
        self.assertFalse((base/'etc/systemd/system/tacticlens-exportador.timer.d/20-monitoreo-local.conf').exists())
        self.assertEqual(queue.read_bytes(),b'unchanged-queue-and-cursor')
        self.assertTrue(any(call.args[0]==['systemctl','start',timer.TIMER] for call in run.call_args_list))

    def test_non_oneshot_unit_is_never_reconfigured(self):
        _,config,queue,original,run=self.setup_case(service_type='simple')
        with self.assertRaises(RuntimeError):timer.configure('http://192.168.0.107:8000/api/ingesta/eventos')
        self.assertEqual(config.read_text(),original)
        self.assertEqual(queue.read_bytes(),b'unchanged-queue-and-cursor')
        run.assert_not_called()
