"""Real PostgreSQL receipts, historical compatibility and concurrent ingestion."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier
import json
import hashlib
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import MetaData,func,select
from sqlalchemy.schema import CreateSchema,DropSchema
import test_auth as fixtures
from backend.api import app


def event(source='fixture:1',**changes):
    return {'session':'ingestion-fixture','eventid':'cowrie.command.input','timestamp':'2026-11-12T12:00:00Z',
            'src_ip':'198.51.100.25','src_port':40000,'dst_port':2222,'input':'pwd',
            '_collector':{'source_id':source},**changes}


class IngestionTests(fixtures.AuthFixture):
    def test_source_identity_routes_shell_and_destination_port_alone_is_insufficient(self):
        self.enroll(96, admin=True)
        shell_id = uuid4()
        self.connection.execute(app.state.tables['honeypot'].insert().values(
            id_honeypot=shell_id, nombre='shell-test', host='loopback'))
        with patch.object(app.state, 'instances', {'cowrie_shell': shell_id}):
            explicit = event('port-routing-explicit', session='port-routing-explicit', dst_port=2223)
            explicit['_collector']['instance_id'] = 'cowrie_shell'
            invalid = event('port-routing-invalid', session='port-routing-invalid')
            invalid['_collector']['instance_id'] = None
            self.ingest([invalid], status=422)
            result = self.ingest([
                event('port-routing-1', session='port-routing-test', dst_port='2222'),
                event('sensor-routing-1', session='sensor-routing-test', sensor='tacticlens-cowrie-01', dst_port=2222),
                explicit,
                event('port-routing-unregistered', session='port-routing-unregistered', dst_port=2223),
            ])
            self.assertEqual(result['insertados'], 4)
            rows = self.client.get('/api/sesiones', params={'q': 'sensor-routing-test',
                'modalidad': 'cowrie_shell'}).json()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['modalidad'], 'cowrie_shell')
            ambiguous = self.client.get('/api/sesiones', params={'q':'port-routing-test', 'modalidad':'desconocido'}).json()
            self.assertEqual(len(ambiguous), 1)
            conflict = self.client.get('/api/sesiones', params={'q':'port-routing-explicit', 'modalidad':'desconocido'}).json()
            self.assertEqual(len(conflict), 1)
            events = self.client.get(f"/api/sesiones/{conflict[0]['id_sesion']}/eventos").json()
            self.assertEqual(events[0]['procedencia']['estado'], 'conflicto')
            fallback = self.client.get('/api/sesiones', params={'q': 'port-routing-unregistered'}).json()
            self.assertEqual(len(fallback), 1)
            self.assertNotEqual(fallback[0]['modalidad'], 'cowrie_proxy')

    def ingest(self,events,status=200):
        response=self.client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key},json={'eventos':events})
        self.assertEqual(response.status_code,status,response.text)
        return response.json()

    def test_instance_receipts_and_session_filters(self):
        self.enroll(95, admin=True)
        mapping = {name: uuid4() for name in ("cowrie_shell", "cowrie_proxy", "cowrie_llm")}
        for name, sensor in mapping.items():
            self.connection.execute(app.state.tables["honeypot"].insert().values(id_honeypot=sensor,nombre=name,host="loopback"))
        raw = event("sqlite:fixture:legacy", session="shared-test-id", sensor="tacticlens", dst_port=None)
        batch = [raw, *[{**raw, "_collector": {"source_id": "sqlite:fixture:" + name, "instance_id": name}} for name in mapping]]
        with patch.object(app.state, "instances", mapping):
            self.assertEqual(self.ingest(batch)["insertados"], 4)
            self.assertEqual(self.ingest(batch)["duplicados"], 4)
            ids = set()
            for name in ("desconocido", *mapping):
                response = self.client.get("/api/sesiones", params={"q":"shared-test-id", "modalidad":name})
                self.assertEqual(response.status_code, 200)
                rows = response.json()
                self.assertEqual([(r["modalidad"],r["eventos"]) for r in rows], [(name,1)])
                ids.add(rows[0]["id_sesion"])
                report = self.client.get(f'/api/sesiones/{rows[0]["id_sesion"]}/informe')
                self.assertEqual(report.status_code, 409, report.text)
            self.assertEqual(len(ids),4)
            groups = self.client.get("/api/dashboard/resumen").json()["por_modalidad"]
            for name in mapping:
                self.assertEqual(groups[name], {"sesiones": 1, "eventos": 1})
            invalid = {**raw, "_collector":{"source_id":"invalid", "instance_id":"unknown"}}
            self.assertEqual(self.ingest([invalid],422)["rechazados"],1)

    def test_retries_and_identical_distinct_occurrences_have_durable_receipts(self):
        result=self.ingest([event('occurrence:1'),event('occurrence:2')])
        self.assertEqual(result['insertados'],2)
        replay=self.ingest([event('occurrence:1'),event('occurrence:2')])
        self.assertEqual(replay['duplicados'],2)
        self.assertEqual([r['id_evento'] for r in result['confirmaciones']],[r['id_evento'] for r in replay['confirmaciones']])
        e=app.state.tables['evento']
        ids=[r['id_evento'] for r in result['confirmaciones']]
        self.assertEqual(self.connection.execute(select(e.c.numero_secuencia).where(e.c.id_evento.in_(ids)).order_by(e.c.numero_secuencia)).scalars().all(),[1,2])

    def test_sqlite_retry_across_instance_activation_keeps_historical_sensor(self):
        sensor=uuid4()
        self.connection.execute(app.state.tables['honeypot'].insert().values(id_honeypot=sensor,nombre='proxy',host='loopback'))
        raw=event('sqlite:fixture:before-cutover')
        original=self.ingest([raw])['confirmaciones'][0]['id_evento']
        attributed={**raw,'_collector':{**raw['_collector'],'instance_id':'cowrie_proxy'}}
        with patch.object(app.state,'instances',{'cowrie_proxy':sensor}):
            response=self.ingest([attributed])
            self.assertEqual(response['duplicados'],1)
            self.assertEqual(response['confirmaciones'][0]['id_evento'],original)
            self.assertEqual(self.ingest([{**attributed,'input':'different'}],422)['rechazados'],1)
        e,s=(app.state.tables[name] for name in ('evento','sesion'))
        self.assertEqual(self.connection.scalar(select(s.c.id_honeypot).join(e).where(e.c.id_evento==original)),
                         app.state.honeypot_id)

    def test_old_31_bit_collision_no_longer_collides(self):
        result=self.ingest([event('auditoria:16451'),event('auditoria:51147')])
        self.assertEqual(result['insertados'],2)
        self.assertNotEqual(result['confirmaciones'][0]['id_evento'],result['confirmaciones'][1]['id_evento'])

    def test_invalid_event_does_not_block_valid_later_events_or_leak_payload(self):
        result=self.ingest([event('bad',src_port=70000,password='captured-secret'),event('good')])
        self.assertEqual((result['insertados'],result['rechazados']),(1,1))
        self.assertEqual([r['estado'] for r in result['confirmaciones']],['rechazado','insertado'])
        self.assertNotIn('captured-secret',json.dumps(result))
        self.assertEqual(self.ingest([event('all-bad',timestamp='sin-zona')],422)['rechazados'],1)

    def test_source_cannot_be_reused_for_another_payload_or_session(self):
        result=self.ingest([event('stable')])
        bad=self.ingest([event('stable',input='whoami')],422)
        self.assertEqual(bad['rechazados'],1)
        self.ingest([event('stable',session='other')],422)
        self.assertEqual(self.ingest([event('stable')])['confirmaciones'][0]['id_evento'],result['confirmaciones'][0]['id_evento'])

    def test_historical_event_is_adopted_once_without_renumbering(self):
        s,e=app.state.tables['sesion'],app.state.tables['evento']
        raw=event();original={k:v for k,v in raw.items() if k!='_collector'}
        from backend.api import timestamp
        sid=self.connection.scalar(s.insert().values(id_honeypot=app.state.honeypot_id,cowrie_session_id=raw['session'],fecha_inicio=timestamp(raw['timestamp'])).returning(s.c.id_sesion))
        historical=int.from_bytes(hashlib.sha256(b'first-claim').digest()[:8],'big') & ((1<<63)-1)
        self.connection.execute(e.insert().values(id_evento=historical,id_sesion=sid,numero_secuencia=2_147_483_647,tipo_evento=raw['eventid'],fecha_hora=timestamp(raw['timestamp']),datos_originales=original))
        result=self.ingest([event('first-claim'),event('second-occurrence')])
        self.assertEqual(result['confirmaciones'][0]['id_evento'],historical)
        self.assertEqual((result['duplicados'],result['insertados']),(1,1))
        sequences=self.connection.execute(select(e.c.numero_secuencia).where(e.c.id_sesion==sid).order_by(e.c.numero_secuencia)).scalars().all()
        self.assertEqual(sequences,[2_147_483_647,2_147_483_648])

    def test_identical_json_never_claims_an_unrelated_historical_occurrence(self):
        s,e=app.state.tables['sesion'],app.state.tables['evento']
        raw=event();original={k:v for k,v in raw.items() if k!='_collector'}
        from backend.api import timestamp
        sid=self.connection.scalar(s.insert().values(id_honeypot=app.state.honeypot_id,cowrie_session_id=raw['session'],fecha_inicio=timestamp(raw['timestamp'])).returning(s.c.id_sesion))
        self.connection.execute(e.insert().values(id_evento=8_000_000_000_000_001,id_sesion=sid,numero_secuencia=123,tipo_evento=raw['eventid'],fecha_hora=timestamp(raw['timestamp']),datos_originales=original))
        self.assertEqual(self.ingest([event('new:1'),event('new:2')])['insertados'],2)
        self.assertEqual(self.connection.scalar(select(func.count()).select_from(e).where(e.c.id_sesion==sid)),3)

    def test_machine_auth_body_limits_health_and_private_queries_stay_protected(self):
        self.assertEqual(self.client.post('/api/ingesta/eventos',json={'eventos':[event()]}).status_code,401)
        self.assertEqual(self.client.get('/api/sesiones').status_code,401)
        large=self.client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key,'Content-Type':'application/json'},content=b' '*2_097_153)
        self.assertEqual(large.status_code,413)
        self.assertEqual(self.client.get('/api/health').json()['contrato_ingesta'],'tacticlens.ingesta.v2')

    def test_real_sqlite_capture_api_postgres_and_queries_survive_lost_ack(self):
        from collector import exportar_eventos as capture
        from collector import sqlite_sender as sender
        with TemporaryDirectory() as folder:
            path=Path(folder)/'cola.sqlite3';log=Path(folder)/'cowrie.json'
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.executescript('CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL); CREATE TABLE cursor(name TEXT PRIMARY KEY,inode TEXT NOT NULL,offset INTEGER NOT NULL);')
            raw=event();raw.pop('_collector')
            log.write_text((json.dumps(raw)+'\n')*2)
            capture.prepare(path,Path(folder)/'backups')
            conn=sender.connect(path)
            try:
                capture.ingest(conn,log)
                seen=[]
                def lost_ack(url,key,events):
                    result=self.ingest(events)
                    seen.extend(r['id_evento'] for r in result['confirmaciones'])
                    raise TimeoutError('simulated lost response after PostgreSQL commit')
                with patch.object(sender,'post',side_effect=lost_ack):
                    self.assertEqual(sender.deliver_pending(conn,capture.mapping(conn),'unused','fake'),0)
                self.assertEqual(sender.status(conn,capture.mapping(conn))['pendientes'],2)
                conn.execute('UPDATE tacticlens_entregas SET proximo_intento=0')
                with patch.object(sender,'post',side_effect=lambda url,key,events:self.ingest(events)):
                    self.assertEqual(sender.deliver_pending(conn,capture.mapping(conn),'unused','fake'),2)
                self.assertEqual(sender.status(conn,capture.mapping(conn))['enviados'],2)
                e=app.state.tables['evento']
                self.assertEqual(self.connection.scalar(select(func.count()).select_from(e).where(e.c.id_evento.in_(seen))),2)
                self.enroll(91)
                sessions=self.client.get('/api/sesiones?q=ingestion-fixture').json()
                row=next(r for r in sessions if r['cowrie_session_id']==raw['session'])
                self.assertEqual(row['eventos'],2)
                self.assertEqual(len(self.client.get('/api/sesiones/'+row['id_sesion']+'/eventos').json()),2)
            finally:
                conn.close()


class ConcurrentIngestionTests(unittest.TestCase):
    def test_two_connections_retry_same_and_distinct_events_without_duplicates(self):
        with patch.dict('os.environ',{'ADMIN_EMAIL':'','SUPPORT_EMAIL':'','MAIL_TRANSPORT':'file'}),TestClient(app,client=('127.0.0.1',51002)) as client:
            engine,original=app.state.engine,app.state.tables
            schema='test_ingestion_'+uuid4().hex
            meta=MetaData()
            names=('rol','usuario','honeypot','sesion','evento','evento_origen','tipo_ioc','ioc','observacion_ioc')
            copied={n:original[n].to_metadata(meta,schema=schema,referred_schema_fn=lambda *args:schema) for n in names}
            created=False
            try:
                with engine.begin() as conn:
                    conn.execute(CreateSchema(schema));meta.create_all(conn)
                    conn.execute(copied['honeypot'].insert().values(id_honeypot=app.state.honeypot_id,nombre='Prueba aislada',host='loopback'))
                    conn.execute(copied['tipo_ioc'].insert().values(id_tipo_ioc=1,nombre='IP'))
                created=True
                app.state.tables={**original,**copied}
                barrier=Barrier(2)
                def submit(source):
                    barrier.wait(timeout=10)
                    return client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key},json={'eventos':[event('shared'),event(source)]})
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures=[pool.submit(submit,'unique:'+str(i)) for i in range(2)]
                    results=[f.result(timeout=30) for f in futures]
                self.assertEqual([r.status_code for r in results],[200,200],[r.text for r in results])
                self.assertEqual(sum(r.json()['insertados'] for r in results),3)
                with engine.connect() as conn:
                    self.assertEqual(conn.scalar(select(func.count()).select_from(copied['evento'])),3)
                    self.assertEqual(conn.execute(select(copied['evento'].c.numero_secuencia).order_by(copied['evento'].c.numero_secuencia)).scalars().all(),[1,2,3])
            finally:
                app.state.tables=original
                if created:
                    assert schema.startswith('test_ingestion_') and len(schema)==47
                    with engine.begin() as conn:
                        conn.execute(DropSchema(schema,cascade=True))
