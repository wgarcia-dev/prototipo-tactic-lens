"""Transactional PostgreSQL checks for the combined Cowrie/intelligence flows."""
import json
from pathlib import Path
from datetime import datetime, timedelta
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import UUID, uuid4

from sqlalchemy import func, select, text

import test_auth as fixtures
from backend.api import app
from backend.session_report import report_snapshot
from backend.intelligence import backfill_detections, persist_observables
from backend.routes import AnalysisResult, Finding, IocProposal, MitreProposal, mitre_catalog
from scripts import migrate
from scripts.seed_catalog import seed_catalog


class CollaborativeIntegrationTests(fixtures.AuthFixture):
    def setUp(self):
        super().setUp()
        seed_catalog(self.connection, app.state.tables)

    def event(self, **changes):
        return {'session':'merged-'+uuid4().hex, 'eventid':'cowrie.command.input',
                'timestamp':self.clock.isoformat(), 'src_ip':'198.51.100.45',
                'input':'wget https://evidence.corp.local/tool.sh',
                '_collector':{'source_id':'merged:'+uuid4().hex}, **changes}

    def ingest(self, events, expected=200):
        response = self.client.post('/api/ingesta/eventos', json={'eventos':events},
            headers={'X-API-Key':app.state.api_key})
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def observable(self, event_id):
        o = app.state.tables['observacion_ioc']
        return self.connection.execute(select(o).where(o.c.id_evento==event_id)).mappings().first()

    def test_receipts_and_observables_are_idempotent_for_distinct_identical_occurrences(self):
        first = self.event()
        second = {**first, '_collector':{'source_id':'merged:'+uuid4().hex}}
        result = self.ingest([first,second])
        ids = [r['id_evento'] for r in result['confirmaciones']]
        obs = app.state.tables['observacion_ioc']
        count = lambda: self.connection.scalar(select(func.count()).select_from(obs).where(obs.c.id_evento.in_(ids)))
        before = count()
        self.assertGreaterEqual(before,4)
        retry = self.ingest([first,second])
        self.assertEqual((retry['insertados'],retry['duplicados']),(0,2))
        self.assertEqual(count(),before)

    def test_recent_commands_survive_a_long_tail_of_other_events(self):
        self.enroll(95, admin=True)
        command = self.event(input='echo --password "private fixture"')
        receipt = self.ingest([command])['confirmaciones'][0]
        events = app.state.tables['evento']
        sid = self.connection.scalar(select(events.c.id_sesion).where(events.c.id_evento == receipt['id_evento']))
        later = self.clock + timedelta(seconds=1)
        self.connection.execute(events.insert(), [
            dict(id_sesion=sid, numero_secuencia=n, tipo_evento='cowrie.client.size',
                 fecha_hora=later, datos_originales={}) for n in range(2, 504)
        ])
        path = f'/api/sesiones/{sid}'
        recent = self.client.get(path + '/eventos?comandos_recientes=true&limit=6')
        self.assertEqual(recent.status_code, 200, recent.text)
        self.assertEqual([row['id_evento_texto'] for row in recent.json()], [str(receipt['id_evento'])])
        self.assertEqual(self.client.get(path + '/informe').status_code, 409)
        from test_analysis import report_data
        from backend.routes import ensure_model
        model_id = ensure_model(self.connection)
        analysis_table = app.state.tables['analisis_llm']
        self.connection.execute(analysis_table.insert().values(id_sesion=sid, id_modelo=model_id,
            estado='completado', fecha_inicio=self.clock, fecha_fin=self.clock, resumen='Análisis de prueba', resultado_estructurado={
                'eventos_analizados':503, 'version_informe':4, 'informe':report_data()}))
        report = report_snapshot(self.connection, app.state.tables, app.state.honeypot_id, sid)
        self.assertNotIn('private fixture', json.dumps(report))
        self.assertIn('[REDACTED]', json.dumps(report))
        with patch.object(app.state, 'honeypot_id', uuid4()):
            self.assertEqual(self.client.get(path + '/eventos').json(), [])
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_failed_observable_transaction_never_acknowledges_or_persists_event(self):
        raw = self.event()
        with patch('backend.ingestion.persist_observables',side_effect=RuntimeError('simulated database failure')):
            self.ingest([raw],503)
        e,s,o = (app.state.tables[n] for n in ('evento','sesion','evento_origen'))
        self.assertIsNone(self.connection.scalar(select(s.c.id_sesion).where(s.c.cowrie_session_id==raw['session'])))
        self.assertIsNone(self.connection.scalar(select(o.c.id_evento).where(o.c.origen_id==raw['_collector']['source_id'])))
        self.assertEqual(self.ingest([raw])['insertados'],1)

    def test_report_is_bound_to_selected_session_analysis_and_current_coverage(self):
        self.enroll(96, admin=True)
        from backend.routes import ensure_model
        from test_analysis import report_data
        model_id = ensure_model(self.connection)
        event_table, analysis = app.state.tables['evento'], app.state.tables['analisis_llm']
        results = []
        for marker in ('SESION-ALFA', 'SESION-BETA'):
            receipt = self.ingest([self.event(input='echo ' + marker)])['confirmaciones'][0]
            sid = self.connection.scalar(select(event_table.c.id_sesion).where(event_table.c.id_evento==receipt['id_evento']))
            aid = self.connection.scalar(analysis.insert().values(id_sesion=sid, id_modelo=model_id,
                estado='completado', fecha_inicio=self.clock, fecha_fin=self.clock, resumen=marker, resultado_estructurado={
                    'eventos_analizados':1, 'version_informe':4, 'informe':report_data()}).returning(analysis.c.id_analisis))
            response = self.client.get(f'/api/sesiones/{sid}/informe?id_analisis={aid}')
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['id_analisis'], str(aid))
            results.append((sid, aid, response.json()))
        self.assertNotIn('SESION-BETA', json.dumps(results[0][2]))
        self.assertNotIn('SESION-ALFA', json.dumps(results[1][2]))
        sid, aid, _ = results[0]
        wrong = results[1][1]
        self.assertEqual(self.client.get(f'/api/sesiones/{sid}/informe?id_analisis={wrong}').status_code,409)
        self.connection.execute(analysis.update().where(analysis.c.id_analisis==aid).values(
            resultado_estructurado={'eventos_analizados':0, 'informe':report_data()}))
        historical = self.client.get(f'/api/sesiones/{sid}/informe?id_analisis={aid}')
        self.assertEqual(historical.status_code,200,historical.text)
        self.assertEqual(historical.json()['status'],'Análisis desactualizado')
        self.connection.execute(analysis.update().where(analysis.c.id_analisis==aid).values(
            resultado_estructurado={'acciones':[]}))
        legacy = self.client.get(f'/api/sesiones/{sid}/informe?id_analisis={aid}')
        self.assertEqual(legacy.status_code,200,legacy.text)
        self.assertEqual(legacy.json()['status'],'Cobertura del análisis sin verificar')
        self.assertNotIn('Formato del análisis conservado',json.dumps(legacy.json(),ensure_ascii=False))

    def test_review_survives_reingestion_and_backfill_with_audit(self):
        self.enroll(91,admin=True)
        raw = self.event()
        event_id = self.ingest([raw])['confirmaciones'][0]['id_evento']
        row = self.observable(event_id)
        endpoint = '/api/inteligencia/ioc/'+str(row['id_ioc'])+'/revision'
        self.assertEqual(self.client.patch(endpoint,json={'estado':'confirmado','motivo':' '*12}).status_code,422)
        response = self.client.patch(endpoint,json={'estado':'confirmado','motivo':'Origen comprobado en esta prueba'})
        self.assertEqual(response.status_code,200,response.text)
        self.ingest([raw])
        persist_observables(self.connection,app.state.tables,raw,event_id,self.clock)
        obs = app.state.tables['observacion_ioc']
        self.assertEqual(self.connection.scalar(select(obs.c.estado_revision).where(
            obs.c.id_observacion==row['id_observacion'])),'confirmado')
        audit = app.state.tables['auth_auditoria']
        self.assertIsNotNone(self.connection.execute(select(audit).where(audit.c.tipo=='inteligencia_revisada')).first())

    def test_analyst_cannot_review_and_anonymous_cannot_read(self):
        raw = self.event()
        event_id = self.ingest([raw])['confirmaciones'][0]['id_evento']
        row = self.observable(event_id)
        self.assertEqual(self.client.get('/api/iocs').status_code,401)
        detail = '/api/iocs/'+str(row['id_ioc'])+'/observaciones'
        self.assertEqual(self.client.get(detail).status_code,401)
        self.enroll(92)
        self.assertEqual(self.client.get(detail).status_code,200)
        self.assertEqual(self.client.get('/api/iocs/'+str(uuid4())+'/observaciones').status_code,404)
        response = self.client.patch('/api/inteligencia/ioc/'+str(row['id_ioc'])+'/revision',
            json={'estado':'descartado','motivo':'Analista no puede decidir este estado'})
        self.assertEqual(response.status_code,403,response.text)
        self.assertEqual(self.client.patch('/api/inteligencia/observacion_ioc/'+str(row['id_observacion'])+'/revision',
            json={'estado':'confirmado','motivo':'Analista no puede confirmar relevancia'}).status_code,403)
        self.assertEqual(self.observable(event_id)['estado_revision'],'pendiente')

    def test_model_findings_and_review_remain_visible_with_supported_mitre_only(self):
        self.enroll(93,admin=True)
        url = 'https://evidence.corp.local/tool.sh?arg=1'
        raw = self.event(input=f"wget -O bundles.zip '{url}'")
        event_id = self.ingest([raw])['confirmaciones'][0]['id_evento']
        e = app.state.tables['evento']
        sid = self.connection.scalar(select(e.c.id_sesion).where(e.c.id_evento==event_id))
        result = AnalysisResult(resumen='Comando literal observado, sin descarga confirmada',acciones=[
            Finding(tipo='comando',descripcion='Comando de shell registrado',confianza=0.8,eventos=[event_id],
                iocs=[IocProposal(tipo='Dominio',valor='bundles.zip',evento=event_id),
                      IocProposal(tipo='URL',valor=url.split('?')[0],evento=event_id),
                      IocProposal(tipo='URL',valor=url,evento=event_id+1000),
                      IocProposal(tipo='URL',referencia=2,evento=event_id)],
                mitre=[MitreProposal(codigo='T1105',codigo_tactica='TA0011',eventos=[event_id],comportamiento_observado='Orden de descarga introducida',justificacion='Comando de descarga escrito en Cowrie, sin prueba de ejecución del archivo',limitaciones=['El registro contiene un intento de descarga sin confirmación.'],confianza=0.8),
                       MitreProposal(codigo='T1078',justificacion='Propuesta no permitida en este laboratorio',confianza=0.5)]),
            Finding(tipo='otra acción',descripcion='Mismo evento asociado',confianza=0.7,eventos=[event_id],
                iocs=[IocProposal(tipo='URL',valor=url,evento=event_id)])])
        with patch('backend.routes.real_result',return_value=result):
            analyzed = self.client.post('/api/sesiones/'+str(sid)+'/analizar')
        self.assertEqual(analyzed.status_code,200,analyzed.text)
        aid = UUID(analyzed.json()['id_analisis'])
        analysis = app.state.tables['analisis_llm']
        saved = self.connection.scalar(select(analysis.c.resultado_estructurado).where(analysis.c.id_analisis==aid))
        self.assertEqual(saved['mapeos_descartados'][0]['codigo'],'T1078')
        self.assertEqual([rejected['motivo'] for rejected in saved['propuestas_ioc_descartadas']], [
            'sin_evidencia_determinista','sin_evidencia_determinista','evento_ajeno_a_la_accion'])
        self.assertEqual(saved['acciones'][0]['iocs'][0]['valor'],url)
        listed = self.client.get('/api/iocs').json()
        self.assertFalse(any(row['valor']=='bundles.zip' for row in listed))
        ioc = next(row for row in listed if row['valor']==url)
        observed, = self.client.get(f"/api/iocs/{ioc['id_ioc']}/observaciones").json()
        self.assertEqual(observed['id_evento'],str(event_id))
        self.assertEqual(observed['estado_revision'],'pendiente')
        self.assertEqual(len(observed['acciones']),2)
        self.assertTrue(all(link['vinculo_determinista'] for link in observed['acciones']))
        m = app.state.tables['mapeo_mitre']
        action = app.state.tables['accion_identificada']
        mid = self.connection.scalar(select(m.c.id_mapeo).join(action,m.c.id_accion==action.c.id_accion).where(action.c.id_analisis==aid))
        response = self.client.patch('/api/inteligencia/mitre/'+str(mid)+'/revision',
            json={'estado':'confirmado','motivo':'Evidencia literal de shell revisada'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(self.connection.scalar(select(m.c.estado_revision).where(m.c.id_mapeo==mid)),'confirmado')
        backfill_detections(self.connection,app.state.tables)
        self.assertFalse(any(row['valor']=='bundles.zip' for row in self.client.get('/api/iocs').json()))

    def test_same_normalized_url_preserves_sessions_outcomes_and_individual_review(self):
        self.enroll(94,admin=True)
        latest = self.clock + timedelta(seconds=2)
        raw = self.event(eventid='cowrie.session.file_download', timestamp=latest.isoformat(),
            url='HTTPS://Artifacts.Corp.Local/file?x=%2F&y=2', shasum='aBcD'*16,
            src_ip='FD00:0::FA', password='private-fixture')
        earlier = self.event(eventid='cowrie.session.file_download.failed',
            url='https://artifacts.corp.local/file?x=%2F&y=2', src_ip='fd00::fa')
        receipts = self.ingest([raw,earlier])['confirmaciones']
        listed = self.client.get('/api/iocs').json()
        row = next(x for x in listed if x['valor']==earlier['url'])
        self.assertEqual((row['evidencias'],row['sesiones'],row['observaciones_verificables']),(2,2,2))
        self.assertEqual(datetime.fromisoformat(row['primera_observacion']),self.clock)
        self.assertEqual(datetime.fromisoformat(row['ultima_observacion']),latest)
        ip = next(x for x in listed if x['valor']=='fd00::fa')
        self.assertEqual((ip['evidencias'],ip['sesiones']),(2,2))
        endpoint = f"/api/iocs/{row['id_ioc']}/observaciones"
        first,second = [self.client.get(endpoint,params={'limit':1,'offset':offset}).json()[0] for offset in (0,1)]
        self.assertEqual([item['id_evento'] for item in (first,second)],
                         [str(receipt['id_evento']) for receipt in receipts])
        self.assertNotEqual(first['id_sesion'],second['id_sesion'])
        self.assertEqual((first['tipo'],first['valor_normalizado']),('URL',earlier['url']))
        self.assertEqual(first['datos_originales']['password'],'[REDACTED]')
        self.assertEqual(first['detalles'][0]['valor_original'],raw['url'])
        self.assertEqual(first['detalles'][0]['comportamiento'],'descarga_registrada')
        self.assertEqual(second['detalles'][0]['comportamiento'],'descarga_fallida')
        event = app.state.tables['evento']
        stored = self.connection.scalar(select(event.c.datos_originales).where(event.c.id_evento==receipts[0]['id_evento']))
        self.assertEqual(stored,{k:v for k,v in raw.items() if k!='_collector'})
        review = self.client.patch(f"/api/inteligencia/observacion_ioc/{first['id_observacion']}/revision",
            json={'estado':'confirmado','motivo':'Resultado relevante para esta sesión'})
        self.assertEqual(review.status_code,200,review.text)
        self.assertEqual(self.client.get(endpoint).json()[1]['estado_revision'],'pendiente')
        self.assertEqual(next(x for x in self.client.get('/api/iocs').json() if x['id_ioc']==row['id_ioc'])['estado_revision'],'mixto')

    def test_legacy_detection_remains_visible_and_cannot_gain_a_new_confirmation(self):
        self.enroll(95,admin=True)
        t = app.state.tables
        raw = self.event(input='printf bundles.zip')
        event_id = self.ingest([raw])['confirmaciones'][0]['id_evento']
        sid = self.connection.scalar(select(t['evento'].c.id_sesion).where(t['evento'].c.id_evento==event_id))
        model_id = self.connection.scalar(select(t['modelo_llm'].c.id_modelo).limit(1))
        aid = self.connection.scalar(t['analisis_llm'].insert().values(
            id_sesion=sid,id_modelo=model_id,estado='en_proceso',fecha_inicio=self.clock)
            .returning(t['analisis_llm'].c.id_analisis))
        kind = self.connection.scalar(select(t['tipo_ioc'].c.id_tipo_ioc).where(t['tipo_ioc'].c.nombre=='Dominio'))
        ioc = self.connection.scalar(t['ioc'].insert().values(
            id_tipo_ioc=kind,valor='bundles.zip',primera_observacion=self.clock,ultima_observacion=self.clock)
            .returning(t['ioc'].c.id_ioc))
        self.connection.execute(t['deteccion_ioc'].insert().values(
            id_ioc=ioc,id_evento=event_id,id_analisis=aid,evidencia='Propuesta histórica sin respaldo'))
        backfill_detections(self.connection,t)
        before, = self.client.get(f'/api/iocs/{ioc}/observaciones').json()
        persist_observables(self.connection,t,raw,event_id,self.clock)
        backfill_detections(self.connection,t)
        self.assertEqual(self.client.get(f'/api/iocs/{ioc}/observaciones').json(),[before])
        self.assertEqual(before['detalles'],[])
        listing = next(row for row in self.client.get('/api/iocs').json() if row['id_ioc']==str(ioc))
        self.assertEqual((listing['estado_revision'],listing['observaciones_historicas']),('historico',1))
        response = self.client.patch(f"/api/inteligencia/observacion_ioc/{before['id_observacion']}/revision",
            json={'estado':'confirmado','motivo':'Esta propuesta carece de evidencia'})
        self.assertEqual(response.status_code,409,response.text)

    def test_seed_preserves_existing_metadata_and_catalog_supplies_allowed_codes(self):
        tech = app.state.tables['tecnica_mitre']
        self.connection.execute(tech.update().where(tech.c.codigo_tecnica=='T1059').values(nombre='Nombre revisado por el equipo'))
        seed_catalog(self.connection,app.state.tables)
        self.assertEqual(self.connection.scalar(select(tech.c.nombre).where(tech.c.codigo_tecnica=='T1059')),'Nombre revisado por el equipo')
        codes = {row['codigo_tecnica'] for row in mitre_catalog()}
        self.assertIn('T1059.004',codes)
        # Full import is independent from whether Cowrie can observe a technique.
        self.assertIn('T1078',codes)
        self.assertGreater(len(codes),10)

    def test_deferred_migration_is_not_executed_or_marked_applied(self):
        name = '999_cleanup_integration_fixture.sql'
        with TemporaryDirectory() as folder:
            Path(folder,name).write_text("DO $$ BEGIN RAISE EXCEPTION 'must not execute'; END $$;",encoding='utf-8')
            with patch.object(migrate,'MIGRATIONS',Path(folder)),patch.object(migrate,'DEFERRED_DATA_MIGRATIONS',{name}):
                result = migrate.migrate(app.state.engine)
        self.assertEqual(result['deferred'],[name])
        self.assertFalse(result['applied'])
        self.assertIsNone(self.connection.scalar(text('SELECT version FROM honeypot.schema_migration WHERE version=:v'),{'v':name}))
