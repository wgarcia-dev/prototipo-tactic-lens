"""Transactional PostgreSQL checks for the combined Cowrie/intelligence flows."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import UUID, uuid4

from sqlalchemy import func, select, text

import test_auth as fixtures
from backend.api import app
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
                'input':'wget https://evidence.example/tool.sh',
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

    def test_failed_observable_transaction_never_acknowledges_or_persists_event(self):
        raw = self.event()
        with patch('backend.ingestion.persist_observables',side_effect=RuntimeError('simulated database failure')):
            self.ingest([raw],503)
        e,s,o = (app.state.tables[n] for n in ('evento','sesion','evento_origen'))
        self.assertIsNone(self.connection.scalar(select(s.c.id_sesion).where(s.c.cowrie_session_id==raw['session'])))
        self.assertIsNone(self.connection.scalar(select(o.c.id_evento).where(o.c.origen_id==raw['_collector']['source_id'])))
        self.assertEqual(self.ingest([raw])['insertados'],1)

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
        self.enroll(92)
        response = self.client.patch('/api/inteligencia/ioc/'+str(row['id_ioc'])+'/revision',
            json={'estado':'descartado','motivo':'Analista no puede decidir este estado'})
        self.assertEqual(response.status_code,403,response.text)
        self.assertEqual(self.observable(event_id)['estado_revision'],'pendiente')

    def test_model_findings_and_review_remain_visible_with_supported_mitre_only(self):
        self.enroll(93,admin=True)
        raw = self.event(input='printf bundles.zip')
        event_id = self.ingest([raw])['confirmaciones'][0]['id_evento']
        e = app.state.tables['evento']
        sid = self.connection.scalar(select(e.c.id_sesion).where(e.c.id_evento==event_id))
        result = AnalysisResult(resumen='Comando literal observado, sin descarga confirmada',acciones=[
            Finding(tipo='comando',descripcion='Comando de shell registrado',confianza=0.8,eventos=[event_id],
                iocs=[IocProposal(tipo='Dominio',valor='bundles.zip',evento=event_id)],
                mitre=[MitreProposal(codigo='T1059.004',justificacion='Comando escrito en la shell emulada',confianza=0.8),
                       MitreProposal(codigo='T1078',justificacion='Propuesta no permitida en este laboratorio',confianza=0.5)])])
        with patch('backend.routes.real_result',return_value=result):
            analyzed = self.client.post('/api/sesiones/'+str(sid)+'/analizar')
        self.assertEqual(analyzed.status_code,200,analyzed.text)
        aid = UUID(analyzed.json()['id_analisis'])
        analysis = app.state.tables['analisis_llm']
        saved = self.connection.scalar(select(analysis.c.resultado_estructurado).where(analysis.c.id_analisis==aid))
        self.assertEqual(saved['mapeos_descartados'][0]['codigo'],'T1078')
        listed = self.client.get('/api/iocs').json()
        self.assertTrue(any(row['valor']=='bundles.zip' for row in listed))
        m = app.state.tables['mapeo_mitre']
        action = app.state.tables['accion_identificada']
        mid = self.connection.scalar(select(m.c.id_mapeo).join(action,m.c.id_accion==action.c.id_accion).where(action.c.id_analisis==aid))
        response = self.client.patch('/api/inteligencia/mitre/'+str(mid)+'/revision',
            json={'estado':'confirmado','motivo':'Evidencia literal de shell revisada'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(self.connection.scalar(select(m.c.estado_revision).where(m.c.id_mapeo==mid)),'confirmado')
        # A historical model detection remains visible after the backfill and
        # an existing human verdict is never overwritten by that operation.
        backfill_detections(self.connection,app.state.tables)
        self.assertTrue(any(row['valor']=='bundles.zip' for row in self.client.get('/api/iocs').json()))

    def test_seed_preserves_existing_metadata_and_catalog_supplies_allowed_codes(self):
        tech = app.state.tables['tecnica_mitre']
        self.connection.execute(tech.update().where(tech.c.codigo_tecnica=='T1059').values(nombre='Nombre revisado por el equipo'))
        seed_catalog(self.connection,app.state.tables)
        self.assertEqual(self.connection.scalar(select(tech.c.nombre).where(tech.c.codigo_tecnica=='T1059')),'Nombre revisado por el equipo')
        codes = {row['codigo_tecnica'] for row in mitre_catalog()}
        self.assertIn('T1059.004',codes)
        self.assertNotIn('T1078',codes)

    def test_deferred_migration_is_not_executed_or_marked_applied(self):
        name = '999_cleanup_integration_fixture.sql'
        with TemporaryDirectory() as folder:
            Path(folder,name).write_text("DO $$ BEGIN RAISE EXCEPTION 'must not execute'; END $$;",encoding='utf-8')
            with patch.object(migrate,'MIGRATIONS',Path(folder)),patch.object(migrate,'DEFERRED_DATA_MIGRATIONS',{name}):
                result = migrate.migrate(app.state.engine)
        self.assertEqual(result['deferred'],[name])
        self.assertFalse(result['applied'])
        self.assertIsNone(self.connection.scalar(text('SELECT version FROM honeypot.schema_migration WHERE version=:v'),{'v':name}))
