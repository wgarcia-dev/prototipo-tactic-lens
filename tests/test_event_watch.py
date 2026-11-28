from contextlib import closing, nullcontext
from configparser import ConfigParser
import json
from pathlib import Path
import signal
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from collector import event_status, event_watch, exportar_eventos as exporter


class EventWatchTests(unittest.TestCase):
    def test_distributed_service_uses_the_persistent_exporter(self):
        root = Path(__file__).resolve().parents[1]
        unit = ConfigParser(interpolation=None)
        unit.read(root / "deploy/cowrie-ingest.service", encoding="utf-8")
        service = unit["Service"]
        self.assertEqual(service["Type"], "simple")
        self.assertEqual(service["User"], "cowrie")
        self.assertEqual(service["ExecStart"], "/usr/bin/python3 /opt/tacticlens-cowrie/event_watch.py")
        self.assertEqual(service["StateDirectory"], exporter.DB.parent.name)
        self.assertEqual(service["StateDirectoryMode"], "0700")
        self.assertEqual(service["Restart"], "on-failure")
        self.assertIn("tacticlens-exportador.timer", unit["Unit"]["Conflicts"])
        config = exporter.delivery.read_env(root / "deploy/cowrie-ingest.env.example")
        exporter.delivery.validate_endpoint(config["TACTICLENS_URL"], config["TACTICLENS_TOKEN"],
                                             config["TACTICLENS_TRANSPORT"])

    def test_fresh_queue_is_initialized_and_never_replaced(self):
        with TemporaryDirectory() as folder:
            db = Path(folder) / "cola.sqlite3"
            exporter.initialize(db)
            with closing(exporter.delivery.connect(db)) as conn:
                identity = conn.execute("SELECT valor FROM tacticlens_envio_meta WHERE clave = 'queue_uuid'").fetchone()
                self.assertTrue(identity[0])
                self.assertEqual(exporter.full_status(conn)["total_cola"], 0)
            with self.assertRaises(FileExistsError):
                exporter.initialize(db)
            with closing(exporter.delivery.connect(db)) as conn:
                self.assertEqual(conn.execute("SELECT valor FROM tacticlens_envio_meta WHERE clave = 'queue_uuid'").fetchone(),
                                 identity)

    def case(self, offline=False, extra_source=False):
        with TemporaryDirectory() as folder:
            base=Path(folder);db=base/'cola.sqlite3';log=base/'cowrie.json';env=base/'exportador.env'
            with closing(sqlite3.connect(db)) as conn:
                conn.executescript('CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL);CREATE TABLE cursor(name TEXT PRIMARY KEY,inode TEXT NOT NULL,offset INTEGER NOT NULL);')
            raw={'session':'watch-test','eventid':'cowrie.command.input','timestamp':'2026-11-16T12:00:00Z','input':'pwd'}
            line=json.dumps(raw)+'\n';log.write_text(line,encoding='utf-8')
            exporter.prepare(db,base/'backups')
            settings = 'TACTICLENS_URL=http://192.168.0.111:8000/api/ingesta/eventos\nTACTICLENS_TOKEN=fixture-key\nTACTICLENS_TRANSPORT=demo-http\n'
            if extra_source:
                extra = base / 'proxy.json'
                extra.write_text(json.dumps({**raw, 'session': 'extra-proxy', 'dst_port': 2223})+'\n',encoding='utf-8')
                settings += f'TACTICLENS_EXTRA_LOGS={extra}\n'
            env.write_text(settings,encoding='utf-8')
            handlers={};waits=[];posted=[]
            class Watch:
                def __init__(self, paths):
                    expected = [log, extra] if extra_source else [log]
                    if list(paths) != expected:
                        raise AssertionError("Las rutas vigiladas no corresponden a la configuración")
                def wait(self,timeout):
                    waits.append(timeout)
                    if len(waits)==1:
                        with log.open('a',encoding='utf-8') as stream:stream.write(line)
                        return True
                    handlers[signal.SIGTERM]()
                    return False
                def close(self):pass
            def post(url,key,events,**kwargs):
                if offline:raise OSError('offline')
                posted.extend(events)
                return {'contrato':exporter.delivery.CONTRACT,'recibidos':len(events),'insertados':len(events),'duplicados':0,'rechazados':0,
                    'confirmaciones':[{'indice':i,'source_id':e['_collector']['source_id'],'estado':'insertado','id_evento':i+1} for i,e in enumerate(events)]}
            with patch.multiple(exporter,DB=db,LOG=log,ENV=env),patch.object(event_watch,'LogWatch',Watch),patch.object(signal,'signal',side_effect=lambda kind,fn:handlers.update({kind:fn})),patch.object(exporter.delivery,'sender_lock',return_value=nullcontext()),patch.object(exporter.delivery,'post',side_effect=post),patch.object(exporter,'heartbeat',return_value=True):
                event_watch.run()
            with closing(exporter.delivery.connect(db)) as conn:
                status=exporter.full_status(conn)
                if extra_source:
                    cursor, = conn.execute("SELECT inode FROM cursor WHERE name='cowrie_json'").fetchone()
                    self.assertEqual(cursor, f'{log.stat().st_dev}:{log.stat().st_ino}')
            return status,posted,waits

    def test_kernel_wake_captures_identical_new_occurrence_with_distinct_identity(self):
        status,posted,waits=self.case()
        self.assertEqual(status['enviados'],2)
        self.assertEqual(len({e['_collector']['source_id'] for e in posted}),2)
        self.assertEqual(len(waits),2)
        self.assertGreater(waits[0],10) # heartbeat timeout, not periodic file detection

    def test_disconnection_preserves_pending_and_stable_occurrences(self):
        status,posted,_=self.case(offline=True)
        self.assertEqual(status['total_cola'],2)
        self.assertEqual(status['pendientes'],2)
        self.assertEqual(status['enviados'],0)

    def test_legacy_extra_sources_share_durable_watch_and_preserve_primary_cursor(self):
        status,posted,_=self.case(extra_source=True)
        self.assertEqual(status['enviados'],3)
        self.assertEqual(len({event['_collector']['source_id'] for event in posted}),3)
        extra = next(event for event in posted if event["session"] == "extra-proxy")
        self.assertNotIn("instance_id",extra["_collector"])

    def test_status_reads_committed_rows_without_acquiring_writer_lock(self):
        with TemporaryDirectory() as folder:
            db=Path(folder)/'cola.sqlite3'
            with closing(sqlite3.connect(db)) as conn:
                conn.executescript('CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL);')
                conn.execute("INSERT INTO events VALUES('committed','{}','2026-11-16')");conn.commit()
                conn.execute('BEGIN IMMEDIATE')
                conn.execute("INSERT INTO events VALUES('pending','{}','2026-11-16')")
                with patch.object(exporter,'DB',db),patch.object(exporter.delivery,'sender_lock',side_effect=AssertionError('status must not lock sender')):
                    self.assertEqual(event_status.status()['total_cola'],1)
                conn.rollback()
