from types import SimpleNamespace
from unittest import TestCase
from backend.operational_report import analyst_sections


class OperationalReportTests(TestCase):
    def test_operational_body_uses_case_content_and_moves_evidence_to_appendix(self):
        report = {'id_sesion':'case-a','metadata':[['Sesión Cowrie','case-a']], 'status':'Análisis vigente',
                  'sections':[{'title':'Interpretación del análisis guardado','paragraphs':['Nota','Resumen exclusivo A']},
                              {'title':'Registro de comandos','paragraphs':[], 'columns':[], 'rows':[]}]}
        payload = {'informe':{'fases':[{'fase':'Reconocimiento A','observado':'Comando uname',
            'interpretacion':'Consulta de plataforma','resultado':'Salida emulada','eventos':[123]}],
            'recomendaciones':[{'salvaguarda':'Preservar TTY','activo':'Señuelo','riesgo':'Pérdida de evidencia',
              'objetivo':'Conservar la secuencia','medidas':'Obtener TTY del evento 123',
              'validacion':'Hash y copia verificadas'}]}}
        result = analyst_sections(report,payload,[SimpleNamespace(id_evento=123)])
        self.assertEqual(result['sections'][0]['title'],'Síntesis ejecutiva')
        text = str(result)
        self.assertIn('Resumen exclusivo A',text)
        self.assertIn('H01',text)
        self.assertIn('#123',text)
        self.assertIn('Hash y copia verificadas',text)
        titles = [item['title'] for item in result['sections']]
        self.assertLess(titles.index('Anexos de evidencia'),titles.index('Registro de comandos'))

    def test_legacy_report_identifies_missing_content_without_inventing_findings(self):
        result = analyst_sections({'id_sesion':'legacy','metadata':[],'status':'Cobertura sin verificar','sections':[]},{},[])
        self.assertIn('Reconstrucción técnica pendiente',str(result))
        self.assertFalse(any(s.get('kind')=='finding' for s in result['sections']))
