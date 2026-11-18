from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from scripts.prepare_deepseek_trial import availability,configuration,estimate,privacy_check
from scripts.compare_deepseek_trials import compare


class TrialPreparationTests(unittest.TestCase):
    def test_official_configuration_only_and_key_is_not_returned(self):
        env={'LLM_PROVIDER':'deepseek','LLM_MODEL':'deepseek-v4-pro','LLM_API_KEY':'fixture-key-only','LLM_BASE_URL':'https://api.deepseek.com'}
        with patch.dict('os.environ',env):
            self.assertNotIn('fixture-key-only',json.dumps(configuration()))
            for url in ('http://api.deepseek.com','https://api.deepseek.com.evil.example','https://user@api.deepseek.com','https://api.deepseek.com/?key=x'):
                with self.subTest(url=url),patch.dict('os.environ',{'LLM_BASE_URL':url}),self.assertRaises(ValueError):configuration()

    def test_availability_uses_get_only(self):
        response=Mock(status_code=200);response.json.return_value={'data':[{'id':'deepseek-v4-pro','owned_by':'deepseek'}]}
        with patch.dict('os.environ',{'LLM_API_KEY':'fixture-key-only'}),patch('scripts.prepare_deepseek_trial.httpx.get',return_value=response) as get,patch('httpx.post',side_effect=AssertionError('No generation')):
            result=availability({'base_url':'https://api.deepseek.com','modelo':'deepseek-v4-pro'})
        self.assertTrue(result['modelo_disponible']);self.assertFalse(result['generacion_comprobada'])
        self.assertEqual(get.call_args.args[0],'https://api.deepseek.com/models')
        self.assertFalse(get.call_args.kwargs['follow_redirects'])

    def test_known_secret_blocks_artifact_without_echoing_it(self):
        events=[SimpleNamespace(datos_originales={'password':'fixture-sensitive-value'})]
        with self.assertRaises(ValueError) as error:privacy_check({'message':'copy fixture-sensitive-value'},events)
        self.assertNotIn('fixture-sensitive-value',str(error.exception))

    def test_estimate_is_not_reported_as_actual_usage(self):
        value=estimate({'messages':[{'role':'user','content':'x'*1000}],'max_tokens':8192},'deepseek-v4-pro')
        self.assertEqual(value['entrada_por_millon_sin_cache_hora_pico'],1.32)
        self.assertGreater(value['escenario_conservador_usd'],value['costo_estimado_usd'][1])
        self.assertIn('no es tope',value['nota'])


class PairedComparisonTests(unittest.TestCase):
    def fixture(self):
        dataset={'metadata':{'independiente':False},'casos':[{'id':'session','etiquetado':True,'snapshot_sha256':'a'*64,'esperados':['T1033']}]}
        meta={'modelo':'deepseek-v4-pro','parametros':{'temperature':0},'prompt_comun_sha256':'b'*64}
        baseline={'metadata':{**meta,'variante':'sin_rag'},'resultados':{'session':{'estado':'completado','snapshot_sha256':'a'*64,'propuestas':['T1105'],'aceptadas':[]}}}
        rag={'metadata':{**meta,'variante':'con_rag'},'resultados':{'session':{'estado':'completado','snapshot_sha256':'a'*64,'propuestas':['T1033'],'aceptadas':['T1033'],'candidatos':['T1033']}}}
        return dataset,baseline,rag

    def test_paired_metrics_do_not_claim_improvement_from_one_case(self):
        result=compare(*self.fixture())
        self.assertEqual(result['con_rag']['propuestas']['f1_micro'],1)
        self.assertEqual(result['sin_rag']['propuestas']['f1_micro'],0)
        self.assertFalse(result['demostracion_mejora'])

    def test_unlabelled_case_different_events_or_model_are_rejected(self):
        for mutation in ('unlabelled','snapshot','model','pending','prompt'):
            data,baseline,rag=self.fixture()
            if mutation=='unlabelled':data['casos'][0]['etiquetado']=False
            elif mutation=='snapshot':rag['resultados']['session']['snapshot_sha256']='c'*64
            elif mutation=='model':rag['metadata']['modelo']='another-model'
            elif mutation=='pending':rag['resultados']['session']['estado']='pendiente'
            else:
                baseline['metadata']['prompt_comun_sha256']='PENDIENTE'
                rag['metadata']['prompt_comun_sha256']='PENDIENTE'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):compare(data,baseline,rag)
