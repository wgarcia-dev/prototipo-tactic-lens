import gzip
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from collector import exportar_eventos as capture


class ExistingExporterTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'cola.sqlite3';self.log=Path(self.temp.name)/'cowrie.json'
        self.raw={'eventid':'cowrie.command.input','session':'same-session','timestamp':'2026-11-12T12:00:00Z','input':'pwd'}
        self.line=(json.dumps(self.raw)+'\n').encode()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            # EXACT schema inspected in diagnostico_tacticlens.json, not guessed.
            conn.executescript('''CREATE TABLE events (
        id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE cursor (name TEXT PRIMARY KEY,inode TEXT NOT NULL,offset INTEGER NOT NULL);''')
            old_id=hashlib.sha256(json.dumps(self.raw,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
            conn.execute('INSERT INTO events VALUES(?,?,?)',(old_id,json.dumps(self.raw),'2026-11-12T12:00:00Z'))
        self.log.write_bytes(self.line)
        self.backup=capture.prepare(self.path,Path(self.temp.name)/'backups')
        self.conn=capture.delivery.connect(self.path);self.addCleanup(self.conn.close)

    def test_status_works_while_sender_owns_the_lock(self):
        with patch.object(capture, 'DB', self.path), patch('sys.argv', ['exporter', '--status']), \
             patch.object(capture.delivery, 'sender_lock', side_effect=AssertionError('status requested sender lock')), \
             patch('builtins.print') as output:
            capture.main()
        self.assertEqual(json.loads(output.call_args.args[0])['total_cola'], 1)

    def count(self):
        return self.conn.execute('SELECT count(*) FROM events').fetchone()[0]

    def test_legacy_rows_preserved_and_new_identical_occurrences_not_collapsed(self):
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],0)
        with self.log.open('ab') as f:f.write(self.line)
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],1)
        self.assertEqual(self.count(),2)
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],0)
        with closing(sqlite3.connect(self.backup)) as conn, conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM events').fetchone()[0],1)

    def test_multiple_rotations_between_polls_and_compressed_archives(self):
        capture.ingest(self.conn,self.log)
        first=self.log.with_name('cowrie.json.1')
        self.log.rename(first)
        with first.open('ab') as f:f.write(self.line)
        self.log.write_bytes(self.line)
        second=self.log.with_name('cowrie.json.2');self.log.rename(second)
        self.log.write_bytes(self.line)
        with gzip.open(str(first)+'.gz','wb') as zipped:zipped.write(first.read_bytes())
        first.unlink()
        result=capture.ingest(self.conn,self.log)
        self.assertEqual(result['nuevos'],3)
        self.assertEqual(self.count(),4)
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],0)

    def test_bad_json_is_durable_review_and_valid_later_lines_continue(self):
        self.log.write_bytes(self.line+b'not-json\n'+self.line+b'{"partial":')
        result=capture.ingest(self.conn,self.log)
        self.assertEqual((result['nuevos'],result['revision_captura']),(1,1))
        self.assertEqual(self.conn.execute('SELECT raw FROM tacticlens_captura_revision').fetchone()[0],b'not-json\n')
        before=self.conn.execute('SELECT offset FROM cursor').fetchone()[0]
        self.assertEqual(before,len(self.line)*2+len(b'not-json\n'))
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],0)

    def test_cursor_and_event_roll_back_together_on_failed_insert(self):
        capture.ingest(self.conn,self.log)
        with self.log.open('ab') as f:f.write(self.line)
        before=self.conn.execute('SELECT offset FROM cursor').fetchone()[0]
        self.conn.execute("CREATE TRIGGER fail_test BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):capture.ingest(self.conn,self.log)
        self.assertEqual(self.conn.execute('SELECT offset FROM cursor').fetchone()[0],before)
        self.conn.execute('DROP TRIGGER fail_test')
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],1)

    def test_observable_copy_truncation_creates_new_generation(self):
        capture.ingest(self.conn,self.log)
        changed={**self.raw,'input':'whoami'}
        self.log.write_text(json.dumps(changed)+'\n')
        self.assertEqual(capture.ingest(self.conn,self.log)['nuevos'],1)
        self.assertEqual(self.count(),2)
