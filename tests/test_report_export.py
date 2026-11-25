"""Verify renderer input isolation and actual PDF generation without LLM calls."""
from unittest import TestCase
from unittest.mock import patch
import json
from types import SimpleNamespace
from datetime import datetime, timezone
from io import BytesIO

from docx import Document

from backend.report_export import render_docx, render_pdf
from backend.session_report import ecuador_time, stored_time


class ReportExportTests(TestCase):
    def test_ecuador_time_converts_utc_across_midnight(self):
        expected = '2026-11-21 20:07:42 UTC-05:00'
        self.assertEqual(ecuador_time(datetime(2026,11,22,1,7,42,tzinfo=timezone.utc)), expected)
        self.assertEqual(stored_time('2026-11-22T01:07:42Z'), expected)
        self.assertEqual(ecuador_time(None), 'Sin registro')

    def report(self, marker):
        return {'title':marker, 'reference':marker, 'status':'Análisis vigente',
                'metadata':[['Sesión', marker]], 'sections':[{'title':'Hallazgo '+marker,
                'paragraphs':['Evidencia exclusiva '+marker], 'columns':[], 'rows':[]}]}

    def test_every_render_receives_its_own_complete_report(self):
        with patch('backend.report_export.subprocess.run', return_value=SimpleNamespace(stdout=b'%PDF-fixture')) as run:
            render_pdf(self.report('ALFA'))
            render_pdf(self.report('BETA'))
        first, second = [json.loads(call.kwargs['input']) for call in run.call_args_list]
        self.assertNotIn('BETA', json.dumps(first))
        self.assertNotIn('ALFA', json.dumps(second))

    def test_actual_pdf_renderer_generates_distinct_documents(self):
        first = render_pdf(self.report('SESION-ALFA'))
        second = render_pdf(self.report('SESION-BETA'))
        self.assertTrue(first.startswith(b'%PDF-'))
        self.assertTrue(second.startswith(b'%PDF-'))
        self.assertGreater(len(first), 1000)
        self.assertNotEqual(first, second)

    def test_docx_keeps_all_four_columns_of_external_observations(self):
        report = self.report('SESION-ALFA')
        labels = ['Proveedor', 'Observable', 'Evaluación', 'Referencia']
        values = ['URLhaus', 'IP de laboratorio', 'Omitido', 'Evaluación local']
        report['sections'].append({'title': 'Evaluación por fuente externa', 'paragraphs': [],
                                   'columns': labels, 'rows': [values]})

        table = Document(BytesIO(render_docx(report))).tables[-1]
        self.assertEqual([[cell.text for cell in row.cells] for row in table.rows], [labels, values])
