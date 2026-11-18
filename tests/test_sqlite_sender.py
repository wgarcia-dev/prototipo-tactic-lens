"""Durable delivery using disposable SQLite queues and a mocked transport."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from collector import sqlite_sender as sender


class SQLiteSenderTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'cola.sqlite3'
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute('CREATE TABLE registros(id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL,enviado INTEGER DEFAULT 0)')
            raw=json.dumps({'eventid':'cowrie.command.input','timestamp':'2026-11-12T12:00:00Z','session':'test','input':'pwd'})
            conn.executemany('INSERT INTO registros(payload) VALUES(?)',[(raw,),(raw,)])
            self.mapping={'table':'registros','id_column':'id','json_column':'payload','sent_column':'enviado','sent_value':1,
                'schema_sha256':sender.schema_hash(conn,'registros')}
        self.backup=sender.prepare_queue(self.path,self.mapping,Path(self.temp.name)/'backups')
        self.conn=sender.connect(self.path);self.addCleanup(self.conn.close)

    def ack(self,url,key,events):
        return {'contrato':sender.CONTRACT,'recibidos':len(events),'insertados':len(events),'duplicados':0,'rechazados':0,
            'confirmaciones':[{'indice':i,'source_id':e['_collector']['source_id'],'estado':'insertado','id_evento':i+1} for i,e in enumerate(events)]}

    def send(self):
        return sender.deliver_pending(self.conn,self.mapping,'http://127.0.0.1:18765/api/ingesta/eventos','fake-private-key')

    def test_backup_preserves_original_rows_and_identical_occurrences_are_distinct(self):
        with closing(sqlite3.connect(self.backup)) as conn, conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM registros').fetchone()[0],2)
        with patch.object(sender,'post',side_effect=self.ack) as transport:
            self.assertEqual(self.send(),2)
            events=transport.call_args.args[2]
            self.assertNotEqual(events[0]['_collector']['source_id'],events[1]['_collector']['source_id'])
            self.assertEqual(self.send(),0)
            self.assertEqual(transport.call_count,1)
        self.assertEqual(self.conn.execute('SELECT sum(enviado) FROM registros').fetchone()[0],2)
        self.assertEqual(sender.status(self.conn,self.mapping),{'total_cola':2,'enviados':2,'revision':0,'pendientes':0})

    def test_disconnect_restart_and_retry_preserve_identity_and_pending_data(self):
        with patch.object(sender,'post',side_effect=OSError('private-detail')) as transport:
            self.assertEqual(self.send(),0)
            first=[e['_collector']['source_id'] for e in transport.call_args.args[2]]
        self.assertEqual(sender.status(self.conn,self.mapping)['pendientes'],2)
        self.conn.close();self.conn=sender.connect(self.path);self.addCleanup(self.conn.close)
        self.conn.execute('UPDATE tacticlens_entregas SET proximo_intento=0')
        with patch.object(sender,'post',side_effect=self.ack) as transport:
            self.assertEqual(self.send(),2)
            self.assertEqual(first,[e['_collector']['source_id'] for e in transport.call_args.args[2]])

    def test_plain_200_or_wrong_receipt_never_marks_sent(self):
        for response in ({'ok':True},{'contrato':sender.CONTRACT,'recibidos':2,'confirmaciones':[]}):
            with patch.object(sender,'post',return_value=response):
                self.assertEqual(self.send(),0)
            self.assertEqual(self.conn.execute('SELECT sum(enviado) FROM registros').fetchone()[0],0)
            self.conn.execute('UPDATE tacticlens_entregas SET proximo_intento=0')

    def test_invalid_json_is_retained_for_review_and_later_rows_continue(self):
        self.conn.execute("UPDATE registros SET payload='invalid-json' WHERE id=1")
        with patch.object(sender,'post',side_effect=self.ack):
            self.assertEqual(self.send(),1)
        self.assertEqual(sender.status(self.conn,self.mapping),{'total_cola':2,'enviados':1,'revision':1,'pendientes':0})
        self.assertEqual(self.conn.execute('SELECT count(*) FROM registros').fetchone()[0],2)

    def test_api_rejection_is_recorded_without_marking_original_row_sent(self):
        def ack(url,key,events):
            result=self.ack(url,key,events)
            result['insertados']-=1;result['rechazados']=1
            result['confirmaciones'][0]={'indice':0,'source_id':events[0]['_collector']['source_id'],'estado':'rechazado'}
            return result
        with patch.object(sender,'post',side_effect=ack):
            self.assertEqual(self.send(),2)
        self.assertEqual(self.conn.execute('SELECT enviado FROM registros WHERE id=1').fetchone()[0],0)
        self.assertEqual(sender.status(self.conn,self.mapping)['revision'],1)

    def test_schema_drift_fails_closed_and_no_other_recipient_is_allowed(self):
        self.conn.execute('ALTER TABLE registros ADD COLUMN otra TEXT')
        with self.assertRaises(ValueError):
            self.send()
        for url in ('http://192.168.0.111:8000/api/ingesta/eventos','http://127.0.0.1:18765/auxiliar','http://user:secret@127.0.0.1:18765/api/ingesta/eventos'):
            with self.assertRaises(ValueError):
                sender.post(url,'fake',[])

    def test_changed_pending_row_goes_to_review_without_losing_later_rows(self):
        with patch.object(sender,'post',side_effect=OSError('not logged')):
            self.send()
        self.conn.execute('UPDATE tacticlens_entregas SET proximo_intento=0')
        self.conn.execute("UPDATE registros SET payload=? WHERE id=1",(json.dumps({'session':'changed'}),))
        with patch.object(sender,'post',side_effect=self.ack):
            self.assertEqual(self.send(),1)
        self.assertEqual(sender.status(self.conn,self.mapping)['revision'],1)
        self.assertEqual(self.conn.execute('SELECT enviado FROM registros WHERE id=1').fetchone()[0],0)

    def test_wrong_source_or_boolean_confirmation_is_not_accepted(self):
        def wrong_source(url,key,events):
            result=self.ack(url,key,events)
            result['confirmaciones'][0]['source_id']='not-the-source'
            return result
        with patch.object(sender,'post',side_effect=wrong_source):
            self.assertEqual(self.send(),0)
        self.conn.execute('UPDATE tacticlens_entregas SET proximo_intento=0')
        def boolean_id(url,key,events):
            result=self.ack(url,key,events)
            result['confirmaciones'][0]['id_evento']=True
            return result
        with patch.object(sender,'post',side_effect=boolean_id):
            self.assertEqual(self.send(),0)
        self.assertEqual(sender.status(self.conn,self.mapping)['enviados'],0)
