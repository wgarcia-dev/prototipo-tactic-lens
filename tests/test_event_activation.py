import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from collector import sqlite_sender
from scripts.ubuntu import activar_eventos as installer


class ActivationTests(unittest.TestCase):
    def case(self, fail_start=False):
        with TemporaryDirectory() as folder:
            base=Path(folder);root=base/'opt/tacticlens-cowrie';root.mkdir(parents=True)
            kit=base/'kit';kit.mkdir()
            for name in ('event_watch.py','event_status.py','estado.sh','verificar.sh','sincronizar.sh','probar-reconexion.sh'):
                (kit/name).write_text('new '+name,encoding='utf-8')
            (root/'scripts').mkdir()
            (root/'event_watch.py').write_text('old watcher',encoding='utf-8')
            (root/'scripts/estado.sh').write_text('old status',encoding='utf-8')
            expected={}
            for name in ('exportar_eventos.py','sqlite_sender.py'):
                content=('original '+name).encode();(root/name).write_bytes(content)
                expected[name]=hashlib.sha256(content).hexdigest()
            config=base/'etc/exportador.env';config.parent.mkdir()
            original='TACTICLENS_URL=http://192.168.0.107:8000/api/ingesta/eventos\nTACTICLENS_TOKEN=fixture-only\nTACTICLENS_TRANSPORT=demo-http\n'
            config.write_text(original,encoding='utf-8')
            db=base/'var/cola.sqlite3';db.parent.mkdir()
            conn=sqlite3.connect(db);conn.execute('CREATE TABLE retained(value TEXT)');conn.execute("INSERT INTO retained VALUES('historical')");conn.commit();conn.close()
            fake=SimpleNamespace(ENV=config,DB=db,delivery=sqlite_sender,full_status=lambda _: {'pendientes':0})
            actual_path=Path
            def path(value):
                value=str(value)
                return base/value.lstrip('/') if value.startswith(('/opt/','/etc/systemd')) else actual_path(value)
            calls=[];starts=[]
            def command(*args):
                if 'Type' in args:return 'simple' if fail_start else 'oneshot'
                if 'ActiveState' in args:return 'active' if starts else 'inactive'
                return 'original unit'
            def run(args,check=False):
                calls.append(args)
                if args[:2]==['systemctl','start'] and args[2].endswith('.service'):
                    starts.append(1)
                    if fail_start and len(starts)==1:raise subprocess.CalledProcessError(1,args)
                return SimpleNamespace(returncode=3 if 'is-active' in args else 0)
            response=MagicMock();response.__enter__.return_value=response;response.status=422
            response.read.return_value=json.dumps({'contrato':sqlite_sender.CONTRACT}).encode()
            opener=MagicMock();opener.open.return_value=response
            with patch.object(installer,'Path',side_effect=path),patch.object(installer,'__file__',str(kit/'activar_eventos.py')),patch.dict(sys.modules,{'exportar_eventos':fake}),patch.object(sys,'path',[*sys.path]),patch.object(installer,'command',side_effect=command),patch.object(installer.subprocess,'run',side_effect=run),patch.object(installer.urllib.request,'build_opener',return_value=opener),patch.object(installer.os,'geteuid',return_value=0,create=True),patch.object(installer.os,'chown',return_value=None,create=True),patch.object(installer.time,'sleep'):
                if fail_start:
                    with self.assertRaises(subprocess.CalledProcessError):installer.activate('http://192.168.0.111:8000/api/ingesta/eventos',expected['exportar_eventos.py'],expected['sqlite_sender.py'])
                else:
                    installer.activate('http://192.168.0.111:8000/api/ingesta/eventos',expected['exportar_eventos.py'],expected['sqlite_sender.py'])
            conn=sqlite3.connect(db);self.assertEqual(conn.execute('SELECT value FROM retained').fetchone()[0],'historical');conn.close()
            backups=list((db.parent/'backups').glob('eventos-*'))
            self.assertEqual(len(backups),1)
            conn=sqlite3.connect(backups[0]/'cola.sqlite3');self.assertEqual(conn.execute('SELECT value FROM retained').fetchone()[0],'historical');conn.close()
            if fail_start:
                self.assertEqual(config.read_text(encoding='utf-8'),original)
                self.assertEqual((root/'event_watch.py').read_text(encoding='utf-8'),'old watcher')
                self.assertEqual((root/'scripts/estado.sh').read_text(encoding='utf-8'),'old status')
                self.assertEqual(len(starts),2) # restore the previously permanent service
            else:
                self.assertIn('TACTICLENS_TOKEN=fixture-only',config.read_text(encoding='utf-8'))
                self.assertIn(['systemctl','disable','--now','tacticlens-exportador.timer'],calls)
                self.assertIn(['systemctl','add-wants','multi-user.target','tacticlens-exportador.service'],calls)
                self.assertEqual((root/'scripts/estado.sh').read_text(encoding='utf-8'),'new estado.sh')

    def test_activation_preserves_data_key_and_adds_boot_dependency(self):self.case()
    def test_failed_activation_restores_previous_daemon_and_helpers(self):self.case(fail_start=True)
