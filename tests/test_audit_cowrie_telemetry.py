from json import dumps
from unittest import TestCase

from scripts.audit_cowrie_telemetry import MODES, Shapes, compare


class TelemetryAuditTests(TestCase):
    def test_report_keeps_shapes_and_excludes_values_and_arbitrary_keys(self):
        shape = Shapes()
        raw = {"session":"fixture-session", "timestamp":"2026-11-26T02:00:00Z",
               "input":"fixture-input", "message":"fixture-message", "password":"fixture-password",
               "arbitraryFieldThatCouldExposeSecret":"ignored", "dst_port":2223}
        shape.add(raw,"cowrie.command.input", receipt=True)
        report = shape.report(anchors=True)
        serialized = dumps(report)
        self.assertNotIn("fixture-",serialized)
        self.assertNotIn("password",serialized)
        self.assertNotIn("arbitraryField",serialized)
        fields = report["campos_y_tipos"]["cowrie.command.input"]
        self.assertEqual(fields["input"],{"str":1})
        self.assertEqual(fields["dst_port"],{"int":1})
        self.assertEqual(report["tipos"]["cowrie.command.input"]["campos_fuera_lista"],2)

    def test_comparison_separates_field_loss_and_ambiguous_anchors(self):
        remote = {"modalidades":{mode:{"anclas_pseudonimas":{}} for mode in MODES}}
        remote["modalidades"]["cowrie_shell"]["anclas_pseudonimas"] = {
            "match":[["input","dst_port"]], "shared":[[" input"]], "missing":[["input"]]}
        remote["modalidades"]["cowrie_proxy"]["anclas_pseudonimas"] = {"shared":[["input"]]}
        stored = {"match":[("desconocido",{"input","uuid"})], "shared":[("desconocido",{"input"})]}
        shell = compare(remote,stored)["cowrie_shell"]
        self.assertEqual(shell["conteos"],{"coincidentes":1,"persistidos_como_desconocido":1,
                                          "ambiguos":1,"sin_par_en_muestra":1})
        self.assertEqual(shell["campos_ausentes_en_postgresql"],{"dst_port":1})
        self.assertEqual(shell["campos_adicionales_en_postgresql"],{"uuid":1})
