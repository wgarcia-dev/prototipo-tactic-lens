from contextlib import closing, redirect_stdout
from io import BytesIO, StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import urllib.error

from scripts.ubuntu import sincronizar_exportador_permanente as sync


URL = 'http://192.168.1.120:8000/api/ingesta/eventos'
KEY = 'fixture-key-in-standalone-tests'


class PermanentExporterTests(unittest.TestCase):
    def test_live_preflight_accepts_only_expected_running_cowrie_watcher(self):
        from unittest.mock import Mock
        import stat
        with TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('event_watch.py', 'exportar_eventos.py', 'sqlite_sender.py'):
                (root / name).touch()
            config = root / 'exportador.env'
            config.touch()
            metadata = Mock(st_mode=stat.S_IFREG | 0o640, st_uid=0)
            values = {
                ('tacticlens-cowrie-live.service', 'Type'): 'simple',
                ('tacticlens-cowrie-live.service', 'SubState'): 'running',
                ('tacticlens-cowrie-live.service', 'User'): 'cowrie',
                ('tacticlens-cowrie-live.service', 'MainPID'): '123',
                ('tacticlens-cowrie-live.service', 'ExecStart'): "event_watch LOG=/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json",
            }
            def property_of(unit, field):
                return values.get((unit, field), 'inactive')
            with patch.multiple(sync, UNIT='tacticlens-cowrie-live.service', EXPORTER=root, CONFIG=config), \
                    patch.object(sync, 'property_of', side_effect=property_of), \
                    patch.object(config.__class__, 'lstat', return_value=metadata), \
                    patch.object(config.__class__, 'read_bytes', return_value=b'event_watch'), \
                    patch.object(sync, 'verify_installed_exporter'):
                self.assertEqual(sync.preflight(live=True), metadata)
                values[('tacticlens-exportador.service', 'ActiveState')] = 'active'
                with self.assertRaisesRegex(RuntimeError, 'emisores alternativos'):
                    sync.preflight(live=True)

    def test_configuration_keeps_sensor_content_and_its_original_line_endings(self):
        original = (b'# Configuracion privada\r\nTACTICLENS_SENSOR_ID=sensor-a\r\n'
                    b'TACTICLENS_URL=http://192.168.0.108:8000/api/ingesta/eventos\r\n'
                    b'export TACTICLENS_TOKEN=previous-fixture\r\nCOWRIE_LOG=/some/cowrie.json')
        expected = (b'# Configuracion privada\r\nTACTICLENS_SENSOR_ID=sensor-a\r\n'
                    + f'TACTICLENS_URL={URL}\r\nTACTICLENS_TOKEN={KEY}\r\n'.encode()
                    + b'COWRIE_LOG=/some/cowrie.json\r\nTACTICLENS_TRANSPORT=demo-http\r\n')
        self.assertEqual(sync.update_config(original, URL, KEY), expected)
        self.assertEqual(sync.update_config(expected, URL, KEY), expected)
        with self.assertRaisesRegex(RuntimeError, 'duplicada'):
            sync.update_config(expected + b'TACTICLENS_TOKEN=another\n', URL, KEY)

    def test_authentication_requires_the_non_inserting_contract_receipt(self):
        result = {'contrato': sync.CONTRACT, 'recibidos': 1, 'insertados': 0, 'duplicados': 0, 'rechazados': 1,
                  'confirmaciones': [{'indice': 0, 'source_id': sync.PROBE, 'estado': 'rechazado',
                                      'error': 'evento_invalido_o_identidad_en_conflicto'}]}
        with patch.object(sync.urllib.request, 'build_opener') as builder:
            opener = builder.return_value
            opener.open.side_effect = urllib.error.HTTPError(URL, 422, '', {}, BytesIO(json.dumps(result).encode()))
            self.assertEqual(sync.authentication_probe(URL, KEY)['insertados'], 0)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_header('X-api-key'), KEY)
            self.assertEqual(json.loads(request.data)['eventos'][0]['session'], '')
            for code, detail in ((401, 'clave'), (403, 'origen'), (503, 'no disponible'), (422, 'recibo')):
                with self.subTest(code=code):
                    opener.open.side_effect = urllib.error.HTTPError(URL, code, '', {}, BytesIO(b'{}'))
                    with self.assertRaisesRegex(RuntimeError, detail):
                        sync.authentication_probe(URL, KEY)

    def make_queue(self, path):
        db = sqlite3.connect(path)
        self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
        db.executescript('''CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created_at TEXT);
            CREATE TABLE tacticlens_envio_meta(clave TEXT PRIMARY KEY,valor TEXT);
            CREATE TABLE tacticlens_entregas(origen_pk TEXT PRIMARY KEY,estado TEXT,confirmado_en TEXT);
            CREATE TABLE tacticlens_captura_origen(origen TEXT PRIMARY KEY,event_id TEXT);
            INSERT INTO tacticlens_envio_meta VALUES('queue_uuid','fixture-identity');
            INSERT INTO events VALUES('one','{"original":true}','2026-11-19T00:00:00Z');
            INSERT INTO tacticlens_captura_origen VALUES('fixture-origin','one');''')
        return db

    def test_backup_reads_committed_wal_and_checks_retention(self):
        with TemporaryDirectory() as folder:
            queue, backup = (Path(folder) / name for name in ('queue.sqlite3', 'backup.sqlite3'))
            with closing(self.make_queue(queue)) as db:
                self.assertEqual(sync.backup_queue(queue, backup)['pendientes'], 1)
                db.execute("INSERT INTO tacticlens_entregas VALUES('one','enviado','2026-11-19T00:00:01Z')")
                db.commit()
                self.assertEqual(sync.preserved_rows(queue, backup)[:3], (0, True, 0))
                db.execute("UPDATE events SET payload='changed'")
                db.execute("UPDATE tacticlens_captura_origen SET event_id='another'")
                db.commit()
                self.assertEqual(sync.preserved_rows(queue, backup)[:3], (1, True, 1))

    def test_failed_start_restores_config_with_the_existing_queue_and_timer(self):
        with TemporaryDirectory() as folder:
            base = Path(folder)
            config, queue = base / 'exportador.env', base / 'cola.sqlite3'
            original = b'TACTICLENS_TRANSPORT=demo-http\nTACTICLENS_TOKEN=fixture-old\nSENSOR=fixture\n'
            config.write_bytes(original)
            calls = []

            def system(*args):
                self.assertEqual(args, ('stop', sync.UNIT))
                backup, = base.glob('tacticlens-demo-http-*')
                self.assertEqual((backup / 'exportador.env').read_bytes(), original)
                self.assertTrue((backup / 'cola.sqlite3').is_file())
                calls.append('stop')

            with closing(self.make_queue(queue)), patch.multiple(sync, CONFIG=config, QUEUE=queue, BACKUPS=base), \
                    patch.object(sync, 'preflight', return_value=config.stat()), \
                    patch.object(sync, 'authentication_probe', return_value={'http': 422}), \
                    patch.object(sync, 'system', side_effect=system), \
                    patch.object(sync, 'property_of', return_value='inactive'), \
                    patch.object(sync, 'atomic_config', side_effect=lambda content, _: config.write_bytes(content)), \
                    patch.object(sync, 'start_exporter', side_effect=[RuntimeError('fixture startup failure'), None]), \
                    redirect_stdout(StringIO()) as output:
                with self.assertRaisesRegex(RuntimeError, 'startup failure'):
                    sync.transition(URL, KEY)
                self.assertIn('TACTICLENS_ROLLBACK=', output.getvalue())
                self.assertEqual(config.read_bytes(), original)
                self.assertEqual(calls, ['stop', 'stop'])
