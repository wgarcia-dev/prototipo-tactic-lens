import json
from pathlib import Path
import shlex
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock,patch
from scripts import sync_ingest_key as windows
from scripts.ubuntu import sincronizar_clave as ubuntu

KEY='Ab_7'*12
URL='http://192.168.0.111:8000/api/ingesta/eventos'


class KeySyncTests(unittest.TestCase):
    def test_windows_sends_key_only_through_encrypted_stdin_not_argv(self):
        original_read=Path.read_text
        def read(path,*args,**kwargs):
            return KEY if path.name=='ingest.key' else original_read(path,*args,**kwargs)
        with patch('sys.argv',['sync','--host','192.168.0.110','--demo-url',URL]),patch.object(Path,'read_text',read),patch.object(windows.subprocess,'run') as run:
            windows.main()
        self.assertEqual(run.call_count,2)
        payload=json.loads(run.call_args_list[0].kwargs['input'])
        self.assertEqual(payload['key'],KEY)
        self.assertIn('collector/exportar_eventos.py',payload['files'])
        for call in run.call_args_list:
            self.assertNotIn(KEY,' '.join(call.args[0]))
            self.assertIn('StrictHostKeyChecking=yes',call.args[0])
        self.assertEqual(shlex.split(windows.encoded_command('print(1)'))[:2],['python3','-c'])

    def helper(self,http_status):
        temp=TemporaryDirectory();self.addCleanup(temp.cleanup)
        folder=Path(temp.name);config=folder/'exportador.env'
        keyfolder=folder/('.tacticlens-key-'+'a'*32);keyfolder.mkdir();keyfile=keyfolder/'key'
        config.write_text('TACTICLENS_TOKEN=old-test-token\nTACTICLENS_SENSOR_ID=original-sensor\n')
        keyfile.write_text(KEY)
        response=MagicMock();response.__enter__.return_value=response;response.status=http_status
        response.read.return_value=json.dumps({'contrato':'tacticlens.ingesta.v2','rechazados':1} if http_status==422 else {'detail':'invalid'}).encode()
        opener=MagicMock();opener.open.return_value=response
        real_path=Path
        def paths(value):
            return config if str(value).startswith('/etc/') else folder/'backups'
        with patch.object(ubuntu,'Path',side_effect=paths),patch.object(ubuntu.os,'geteuid',return_value=0,create=True),patch.object(ubuntu.os,'chown',create=True),patch.object(ubuntu.urllib.request,'build_opener',return_value=opener),patch.object(ubuntu.subprocess,'run') as run,patch.object(ubuntu.subprocess,'check_output',return_value='inactive\n'):
            if http_status==422:
                ubuntu.main(keyfile,URL)
            else:
                with self.assertRaises(RuntimeError):ubuntu.main(keyfile,URL)
        return config,keyfile,run

    def test_ubuntu_validates_key_before_updating_and_preserves_sensor(self):
        config,keyfile,run=self.helper(422)
        self.assertIn('TACTICLENS_TOKEN='+KEY,config.read_text())
        self.assertIn('TACTICLENS_SENSOR_ID=original-sensor',config.read_text())
        self.assertIn('TACTICLENS_TRANSPORT=demo-http',config.read_text())
        self.assertIn('TACTICLENS_URL='+URL,config.read_text())
        self.assertFalse(keyfile.exists())
        self.assertTrue(any('--retry-now' in call.args[0] for call in run.call_args_list))

    def test_wrong_api_does_not_change_credentials_or_services(self):
        config,keyfile,run=self.helper(401)
        self.assertIn('TACTICLENS_TOKEN=old-test-token',config.read_text())
        self.assertFalse(keyfile.exists())
        run.assert_not_called()

    def test_root_helper_never_consumes_or_deletes_an_arbitrary_file(self):
        with TemporaryDirectory() as folder:
            original=Path(folder)/'exportador.env';original.write_text(KEY)
            with self.assertRaises(RuntimeError):ubuntu.main(original,URL)
            self.assertEqual(original.read_text(),KEY)
