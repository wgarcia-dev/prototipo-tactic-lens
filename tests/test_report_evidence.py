from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase

from backend.report_evidence import complete_assessment


class EvidenceReportTests(TestCase):
    def event(self, eid, kind, **data):
        return SimpleNamespace(id_evento=eid,tipo_evento=kind,fecha_hora=datetime(2026,1,1,tzinfo=timezone.utc),datos_originales=data)

    def report(self):
        return {'metadata':[], 'sections':[{'title':'Síntesis ejecutiva','paragraphs':['La severidad del incidente es baja.']},
                                          {'title':'Plan de investigación y respuesta'}]}

    def test_profile_scope_guest_and_safeguards_are_tied_to_observations(self):
        events=[self.event(1,'cowrie.session.connect',dst_port=2223,src_port=50557,sensor='proxy-a'),
                self.event(2,'cowrie.client.version',version='SSH-2.0-OpenSSH_for_Windows_9.5'),
                self.event(3,'cowrie.client.kex',hassh='701158e75b508e76f0410d5d22ef9df0'),
                self.event(4,'cowrie.login.success'),self.event(5,'cowrie.command.input',input='whoami')]
        result=complete_assessment(self.report(),events,SimpleNamespace(ip_origen='192.168.56.1'),
            {'informe':{'fases':[{'eventos':[5]}]}},5)
        text=str(result)
        self.assertIn('50557',text)
        self.assertIn('701158e75b508e76f0410d5d22ef9df0',text)
        self.assertIn('Proxy hacia Alpine/QEMU',text)
        self.assertIn('Pendiente de verificación independiente',text)
        self.assertIn('PasswordAuthentication no',text)
        self.assertIn('auditd',text)
        self.assertIn('H01',text)
        self.assertNotIn('La severidad del incidente es baja',text)
        self.assertIn('Por determinar por el analista',text)

    def test_absence_is_qualified_and_transfer_is_not_automatically_exfiltration(self):
        events=[self.event(1,'cowrie.session.file_download',url='http://host/file')]
        text=str(complete_assessment(self.report(),events,SimpleNamespace(ip_origen='10.0.0.2'),{},1))
        self.assertIn('Sin coincidencias en los campos y reglas revisados',text)
        self.assertIn('Una descarga hacia el señuelo indica ingreso',text)

    def test_unknown_port_does_not_assign_a_mode(self):
        result=complete_assessment(self.report(),[],SimpleNamespace(ip_origen='10.0.0.2'),{},0)
        self.assertIn('Modo pendiente de identificar',str(result))
