from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from backend.incident_assessment import assess, IncidentDecision, validate_decision


class IncidentTests(unittest.TestCase):
    def event(self, kind, eid=1):
        return SimpleNamespace(id_evento=eid, tipo_evento=kind, fecha_hora=datetime(2026, 1, 1, tzinfo=timezone.utc), datos_originales={})

    def decision(self, **changes):
        data = dict(revision_esperada=0, decision="actividad_sospechosa", severidad="por_determinar",
            justificacion="La sesión requiere corroborar la finalidad y sus efectos.",
            criterio_incidente="Evaluar la política de uso y el alcance autorizado.", impacto="Impacto organizacional pendiente de corroboración.",
            alcance="Sesión SSH del honeypot", responsable="Analista de seguridad", medidas="Correlacionar con telemetría adicional.",
            eventos=[1], estado="en_investigacion")
        return IncidentDecision(**(data | changes))

    def test_shell_does_not_confirm_incident_or_impact(self):
        result = assess([self.event("cowrie.command.input")])
        self.assertEqual(result["estado"], "pendiente_revision")
        self.assertEqual(result["severidad"], "por_determinar")
        self.assertEqual(result["prioridad_triaje"], "media")
        self.assertEqual(result["impacto"]["integridad"], "sin_determinar")

    def test_connections_have_low_priority(self):
        result = assess([self.event("cowrie.session.connect")])
        self.assertEqual(result["clasificacion"], "evento_observado")
        self.assertEqual(result["prioridad_triaje"], "baja")

    def test_snapshot_changes_when_evidence_changes(self):
        self.assertNotEqual(assess([self.event("cowrie.session.connect")])["snapshot_sha256"],
                            assess([self.event("cowrie.command.input")])["snapshot_sha256"])

    def test_foreign_evidence_rejected(self):
        with self.assertRaisesRegex(ValueError, "fuera"):
            validate_decision(self.decision(eventos=[99]), {1})

    def test_confirmation_requires_severity(self):
        with self.assertRaisesRegex(ValueError, "severidad"):
            validate_decision(self.decision(decision="incidente_confirmado"), {1})

    def test_closure_requires_verification(self):
        with self.assertRaisesRegex(ValueError, "cierre"):
            validate_decision(self.decision(estado="cerrado"), {1})

    def test_valid_decision(self):
        validate_decision(self.decision(), {1})


if __name__ == "__main__":
    unittest.main()
