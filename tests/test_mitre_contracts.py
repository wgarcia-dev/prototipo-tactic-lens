import base64
from unittest import TestCase
from unittest.mock import patch

from backend.rag.evaluation import evaluate_independent
from backend.rag.mitre_evidence import CONTRACTS, EvidenceContract, Signal, contract_signature, technique_evidence
from backend.rag.retrieval import select_candidates
from backend.rag.validation import validate
from test_rag import event, local_context, proposal, result


PUBLIC_KEY = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))).decode()
KEY_WRITE = f"echo '{PUBLIC_KEY}' >> ~/.ssh/authorized_keys"
NEW_CONTRACTS = (
    ('T1098.004','TA0003',KEY_WRITE,'cat ~/.ssh/authorized_keys',
     f"echo '{PUBLIC_KEY}' >> '~/.ssh/authorized_keys'",f"echo '{PUBLIC_KEY}' >> /tmp/authorized_keys"),
    ('T1046','TA0007','nmap -sV -p 80 192.0.2.5','nmap -sL 192.0.2.5',
     'nmap -sV -p 80 lab-host','nmap -sV -p 0 192.0.2.5'),
    ('T1018','TA0007','ip neigh show','ip neigh flush all','ip addr show','echo ip neigh show'),
)


class ContractTests(TestCase):
    def classify(self, code, tactic, events, citations=None, grade='intento', modality='cowrie_shell'):
        context=local_context(events,code,code,tactic)
        context['modalidad']=modality
        analysis=result(events,[proposal(code,tactic,eventos=citations if citations is not None else [events[0].id_evento],
                                         grado_evidencia=grade)])
        rejected, provenance=validate(analysis,events,context)
        return analysis.acciones[0].mitre,rejected,provenance

    def test_eleven_original_contracts_still_identify_evidence(self):
        commands={
            'T1105':('TA0011','wget https://example.org/a'),'T1082':('TA0007','uname -a'),
            'T1033':('TA0007','whoami'),'T1083':('TA0007','ls -la /tmp'),
            'T1016':('TA0007','ip route show'),'T1057':('TA0007','ps aux'),
            'T1059.004':('TA0002','sh -c "pwd"'),'T1053.003':('TA0003','crontab /tmp/jobs'),
            'T1136.001':('TA0003','useradd demo'),'T1070.003':('TA0005','history -c'),
        }
        for code,(tactic,command) in commands.items():
            with self.subTest(code=code):
                accepted, rejected, _=self.classify(code,tactic,[event(command=command)])
                self.assertFalse(rejected)
                self.assertEqual(accepted[0].grado_evidencia,'intento')
        attempts=[event(i,kind='cowrie.login.failed',src_ip='192.0.2.5',username='fixture',password=str(i)) for i in (1,2,3)]
        self.assertTrue(self.classify('T1110','TA0006',attempts,[1,2,3])[0])

    def test_new_contracts_require_positive_compatible_cited_input(self):
        for code,tactic,positive,contrary,ambiguous,incomplete in NEW_CONTRACTS:
            with self.subTest(code=code):
                events=[event(command=positive)]
                accepted,rejected,provenance=self.classify(code,tactic,events)
                self.assertFalse(rejected)
                self.assertEqual(accepted[0].eventos,[1])
                self.assertEqual(provenance[(0,code,tactic)]['contrato_evidencia'],code)
                self.assertFalse(self.classify(code,tactic,events,citations=[345])[0])
                self.assertEqual(self.classify(code,tactic,events,grade='resultado_en_honeypot')[1][0]['causa'],
                                 'resultado_no_demostrado')
                for mode in ('cowrie_proxy','cowrie_llm','desconocido'):
                    self.assertEqual(self.classify(code,tactic,events,modality=mode)[1][0]['causa'],'modalidad_incompatible')
                for command in (contrary,ambiguous,incomplete):
                    self.assertFalse(self.classify(code,tactic,[event(command=command)])[0])
                    self.assertFalse(self.classify(code,tactic,[*events,event(2,command)],citations=[1,2])[0])
                self.assertFalse(self.classify(code,tactic,[event(command=positive,kind='cowrie.command.success')])[0])

    def test_transfer_contradictions_and_defensive_ssh_tactics(self):
        for command in ('curl -I https://example.org/a','curl -T file.txt https://example.org/a'):
            self.assertEqual(self.classify('T1105','TA0011',[event(command=command)])[1][0]['causa'],
                             'evidencia_contradictoria')
        self.assertEqual(self.classify('T1098.004','TA0004',[event(command=KEY_WRITE)])[1][0]['causa'],
                         'tactica_sin_respaldo')

    def test_visible_historical_examples_are_not_implicitly_validated(self):
        self.assertFalse(self.classify('T1059.004','TA0002',[event(command='exit')])[0])
        failed = event(kind='cowrie.login.failed', src_ip='192.0.2.4', username='fixture', password='fixture-only')
        self.assertFalse(self.classify('T1110','TA0006',[failed])[0])
        self.assertTrue(self.classify('T1033','TA0007',[event(command='whoami')])[0])

    def test_no_contract_is_diagnostic_and_registry_supports_ordered_grouped_evidence(self):
        records=[event(command='fixture-first'),event(2,'fixture-second')]
        accepted,diagnostics,_=self.classify('T1005','TA0009',records,[1,2])
        self.assertFalse(accepted)
        self.assertEqual(diagnostics[0]['estado'],'candidata_no_validada')

        def synthetic(observation):
            steps={'fixture-first':'first','fixture-second':'second'}
            if observation.command and observation.command.tool in steps:
                return Signal(step=steps[observation.command.tool])

        contract=EvidenceContract('synthetic',synthetic,sequence=('first','second'))
        signature=contract_signature()
        with patch.dict(CONTRACTS,{'T1005':contract}):
            self.assertNotEqual(contract_signature(),signature)
            self.assertIn('T1005',technique_evidence(records,'cowrie_shell'))
            self.assertTrue(self.classify('T1005','TA0009',records,[2,1])[0])
            self.assertFalse(self.classify('T1005','TA0009',records,[1])[0])
            reversed_order=[event(command='fixture-second'),event(2,'fixture-first')]
            self.assertFalse(self.classify('T1005','TA0009',reversed_order,[1,2])[0])

    def test_selection_reserves_diagnostic_candidates_without_losing_supported_leaders(self):
        rows=[{'codigo_tecnica':f'T{i:04}','plataformas':['Linux'],'puntuacion_hibrida':i,
               'observabilidad':'intento_evaluable' if i<3 else 'sin_contrato'} for i in range(49)]
        selected=select_candidates(rows,limit=8)
        self.assertEqual(len(selected),8)
        self.assertEqual({row['codigo_tecnica'] for row in selected[:3]},{'T0000','T0001','T0002'})
        self.assertEqual(selected[-1]['observabilidad'],'sin_contrato')


class IndependentEvaluationTests(TestCase):
    def test_counts_coverage_abstentions_and_technical_failures(self):
        labels={'metadata':{'independiente':True,'origen':'etiquetado manual externo'},'casos':[
            {'id':'a','esperados':['T1018','T1046']},{'id':'b','esperados':[]},{'id':'c','esperados':[]},
            {'id':'d','esperados':['T1046']},
        ]}
        results={'a':{'estado':'completado','identificadas':['T1018','T1082']},
                 'b':{'estado':'completado','identificadas':[]},
                 'c':{'estado':'fallido','identificadas':[]},
                 'd':{'estado':'fallido','identificadas':[]}}
        metrics=evaluate_independent(labels,results)
        self.assertEqual([metrics[key] for key in ('verdaderos_positivos','falsos_positivos','falsos_negativos')],[1,1,2])
        self.assertEqual([metrics[key] for key in ('cobertura_tecnicas_esperadas','abstencion_negativos','abstenciones','fallos_tecnicos')],
                         [0.5,0.5,1,2])
        self.assertAlmostEqual(metrics['f1_micro'],0.4)
        with self.assertRaises(ValueError):evaluate_independent(labels,{'a':results['a']})
        with self.assertRaises(ValueError):evaluate_independent({**labels,'metadata':{'independiente':False}},results)
