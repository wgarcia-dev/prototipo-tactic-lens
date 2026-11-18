from concurrent.futures import ThreadPoolExecutor
from threading import Event
import unittest
from unittest.mock import patch

from backend.monitoring import SnapshotCache
import test_auth as fixtures
from backend.api import app


class SnapshotTests(unittest.TestCase):
    def test_ttl_engine_boundary_and_explicit_invalidation(self):
        at=[10.0];cache=SnapshotCache(clock=lambda:at[0]);calls=[]
        def load():calls.append(1);return len(calls)
        self.assertEqual(cache.get('engine-a',load),1)
        self.assertEqual(cache.get('engine-a',load),1)
        at[0]+=0.76
        self.assertEqual(cache.get('engine-a',load),2)
        self.assertEqual(cache.get('engine-b',load),3)
        cache.invalidate();self.assertEqual(cache.get('engine-b',load),4)

    def test_concurrent_dashboards_share_one_computation(self):
        cache=SnapshotCache();entered=Event();release=Event();calls=[]
        def load():calls.append(1);entered.set();release.wait(3);return {'events':12}
        with ThreadPoolExecutor(max_workers=4) as pool:
            jobs=[pool.submit(cache.get,'engine',load) for _ in range(4)]
            self.assertTrue(entered.wait(3));release.set()
            self.assertEqual([job.result(3) for job in jobs],[{'events':12}]*4)
        self.assertEqual(len(calls),1)

    def test_failed_computations_are_not_cached(self):
        cache=SnapshotCache()
        with self.assertRaises(RuntimeError):cache.get('engine',lambda:(_ for _ in ()).throw(RuntimeError()))
        self.assertEqual(cache.get('engine',lambda:8),8)


class DashboardMonitoringTests(fixtures.AuthFixture):
    def test_ingestion_invalidates_summary_without_repeating_llm_or_changing_auth(self):
        from backend import routes
        self.assertEqual(self.client.get('/api/dashboard/resumen').status_code,401)
        self.enroll(94)
        app.state.dashboard_cache.invalidate()
        with patch.object(routes,'dashboard_snapshot',wraps=routes.dashboard_snapshot) as snapshot,patch.object(routes,'real_result',side_effect=AssertionError('Monitoring must not run the LLM')):
            first=self.client.get('/api/dashboard/resumen').json()
            self.assertEqual(self.client.get('/api/dashboard/resumen').json(),first)
            self.assertEqual(snapshot.call_count,1)
            raw={'session':'monitoring-fixture','eventid':'cowrie.command.input','timestamp':self.clock.isoformat(),
                 'input':'echo monitor','_collector':{'source_id':'monitoring-fixture:1'}}
            result=self.client.post('/api/ingesta/eventos',headers={'X-API-Key':app.state.api_key},json={'eventos':[raw]})
            self.assertEqual(result.status_code,200,result.text)
            latest=self.client.get('/api/dashboard/resumen').json()
            self.assertEqual(latest['eventos'],first['eventos']+1)
            self.assertTrue(any(row['comando']=='echo monitor' for row in latest['ultimos_comandos']))
            self.assertEqual(snapshot.call_count,2)
