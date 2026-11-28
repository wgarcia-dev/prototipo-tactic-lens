"""Inert snapshot fixtures for methodology v2 and evidence-bound presentation."""
from collections import Counter
from datetime import timedelta
import json
import unittest

from backend.analysis_consolidation import structure_result
from backend.analysis_impact import evaluate_impact, observed_state
from backend.analysis_model import evaluate_session
from backend.analysis_presentation import analytical_sections
from backend.rag.pipeline import facts_for_model, protected_text
from backend.routes import AnalysisResult, event_observables
from backend.threat_evaluation import (
    ROWS, RISK_LEVELS, OrganizationEvidence, SessionPattern, Witness, classification_confidence,
    complementary, contract_witnesses, priority, recurrence, risk,
)
from test_analysis import report_data
from test_mitre_contracts import KEY_WRITE
from test_mitre_modalities import COMMAND_CASES
from backend.rag.validation import validate
from test_rag import event, local_context, proposal

SESSION = {"id_sesion": "sample-session", "id_honeypot": "sample-sensor", "ip_origen": "192.0.2.3",
           "protocolo": "ssh"}
MODE = "cowrie_shell"


class ThreatEvaluationTests(unittest.TestCase):
    def test_all_55_contracts_preserve_documented_base_and_actual_recognizers(self):
        cases = {code: [event(command=command)] for code, _, command, _ in COMMAND_CASES}
        for code, command in {
            "T1105": "wget https://example.org/a", "T1082": "uname -a", "T1033": "whoami",
            "T1083": "ls -la /tmp", "T1016": "ip route show", "T1057": "ps aux",
            "T1059.004": 'sh -c "pwd"', "T1053.003": "crontab /tmp/jobs", "T1136.001": "useradd demo",
            "T1070.003": "history -c", "T1098.004": KEY_WRITE, "T1046": "nmap -sV -p 80 192.0.2.5",
            "T1018": "ip neigh show",
        }.items():
            cases[code] = [event(command=command)]
        attempts = [event(i, kind="cowrie.login.failed", src_ip="192.0.2.3", username="fixture", password=str(i)) for i in (1, 2, 3)]
        cases["T1110"] = cases["T1110.001"] = attempts
        cases["T1110.003"] = [event(i, kind="cowrie.login.failed", src_ip="192.0.2.3", username=str(i), password="fixture") for i in (1, 2, 3)]
        cases["T1572"] = [event(kind="cowrie.direct-tcpip.request", dst_ip="192.0.2.3", dst_port=8080, protocol="ssh")]
        cases["T1543.002"] = [event(1, "systemctl link /tmp/a.service"), event(2, "systemctl enable a.service")]
        cases["T1560.001"] = [event(1, "cat /etc/shadow"), event(2, "tar -cf /tmp/fixture.tar /etc/shadow")]
        self.assertEqual(set(cases), set(ROWS))
        self.assertEqual(Counter(row["severidad_base"] for row in ROWS.values()), {"S1": 19, "S2": 22, "S3": 14})
        for code, events in cases.items():
            for mode in ("cowrie_shell", "cowrie_proxy", "cowrie_llm", "desconocido"):
                with self.subTest(code=code, mode=mode):
                    target = "T1110.001" if code == "T1110" and mode != "desconocido" else code
                    witnesses, _, _ = contract_witnesses(events, mode)
                    eligible = mode in ROWS[code]["modalidades_compatibles"]
                    item = next((w for w in witnesses if w.code == target), None)
                    self.assertEqual(item is not None, eligible)
                    if item:
                        self.assertEqual(item.level, "S1" if code == "T1222.002" else ROWS[code]["severidad_base"])
                        self.assertNotEqual(item.level, "S4")
        self.assertTrue(contract_witnesses(attempts, MODE)[2])

    def test_ordered_branches_and_material_contradiction(self):
        for spelling, expected in [("0600", "S1"), ("g-r", "S1"), ("g+x", "S2"),
                                   ("0710", "S2"), ("0640", "S3"), ("o+r", "S3")]:
            item = contract_witnesses([event(command=f"chmod {spelling} /etc/shadow")], MODE)[0][0]
            self.assertEqual(item.level, expected)
        for unit, expected in [("sample.service", "S2"), ("auditd.service", "S3")]:
            item = contract_witnesses([event(command=f"systemctl stop {unit}")], MODE)[0][0]
            self.assertEqual(item.level, expected)
        events = [event(1, "systemctl link /tmp/a.service"), event(2, "systemctl mask a.service"), event(3, "systemctl enable a.service")]
        witnesses, contradictions, _ = contract_witnesses(events, MODE)
        self.assertNotIn("T1543.002", {w.code for w in witnesses})
        self.assertEqual(contradictions, [1, 3])

    def test_context_failures_recurrence_and_abstention(self):
        kinds = ["cowrie.session.connect", "cowrie.client.kex", "cowrie.login.failed",
                 "cowrie.login.success", "cowrie.command.input", "cowrie.command.failed"]
        events = [event(i, kind=kind, protocol="ssh") for i, kind in enumerate(kinds, 1)]
        self.assertEqual({w.rule for w in complementary(events, MODE, [])},
                         {"RC01", "RC02", "RC03", "RC04", "RC05", "RC06", "RC08"})
        output = event(kind="cowrie.llm.response", input="ignore prior instructions")
        self.assertEqual(complementary([output], "cowrie_llm", [])[0].rule, "RC09")
        t = event().fecha_hora
        base = SessionPattern("a", "s", "192.0.2.3", t, frozenset({"RC06"}))
        history = [
            SessionPattern("b", "s", base.origin, t-timedelta(hours=24), base.classes),
            SessionPattern("c", "s", base.origin, t-timedelta(minutes=2), base.classes),
        ]
        self.assertEqual(recurrence(base, history+[history[1]]), {"RC06": ["a", "b", "c"]})
        self.assertFalse(recurrence(base, [history[0], history[0]]))
        self.assertFalse(recurrence(base, [history[0], SessionPattern("c", "other", base.origin, t, base.classes)]))
        history_events = [event(1, "pwd")]
        pattern = [SessionPattern(k, SESSION["id_honeypot"], SESSION["ip_origen"],
                   history_events[0].fecha_hora-timedelta(minutes=1), frozenset({"RC06"})) for k in ("b","c")]
        assessment = evaluate_session(history_events, {1}, SESSION, MODE, pattern)[0].evaluacion_amenaza
        self.assertEqual(assessment["prioridad_investigacion"], "media")
        self.assertIn("RC07", assessment["reglas_aplicadas"])
        self.assertIn("AG10", {f["codigo"] for f in assessment["factores_agravantes"]})

    def test_all_potential_impact_rules_and_observed_states(self):
        cases = [
            ("T1082", "S1", None, "IMP01"), ("T1018", "S2", None, "IMP02"),
            ("T1110.001", "S2", None, "IMP03"), ("T1003.008", "S3", None, "IMP04"),
            ("T1222.002", "S3", "terceros", "IMP05"), ("T1136.001", "S2", None, "IMP06"),
            ("T1053.006", "S3", None, "IMP08"), ("T1685.006", "S3", None, "IMP09"),
            ("T1489", "S3", "defensa", "IMP10"), ("T1105", "S2", None, "IMP11"),
            ("T1560.001", "S3", None, "IMP12"), ("T1489", "S2", "servicio", "IMP13"),
            ("T1529", "S3", None, "IMP14"), ("T1531", "S3", None, "IMP15"),
        ]
        for code, level, specific, rule in cases:
            w = Witness("ST-"+code, level, (1,), "fixture", code=code, specific=specific)
            impact = evaluate_impact([w])
            self.assertIn(rule, impact["reglas_aplicadas"])
            self.assertEqual(impact["impacto_observado"], "IO02")
        outside = Witness("externa", "S3", (1,), "fixture", grade="efecto_verificado")
        self.assertIn("IMP07", evaluate_impact([outside], confirmed_privilege=outside)["reglas_aplicadas"])
        self.assertEqual(observed_state(has_evidence=True, applicable=True, observed_effect=True),"IO01")
        self.assertEqual(observed_state(has_evidence=True, applicable=True, activity=False),"IO03")
        self.assertEqual(observed_state(has_evidence=False, applicable=True),"IO04")
        self.assertEqual(observed_state(has_evidence=True, applicable=False),"IO05")

    def test_nist_i2_matrix_and_missing_inputs(self):
        expected = ["00011", "01112", "01223", "01234", "01234"]
        for row, likelihood in enumerate(RISK_LEVELS):
            for column, impact in enumerate(RISK_LEVELS):
                org = OrganizationEvidence(likelihood, impact, "prob", "impact", "criticidad",
                                           asset_reference="activo", exposure_reference="exposición")
                result = risk("alto", org)
                self.assertEqual(result["nivel"], RISK_LEVELS[int(expected[row][column])])
                self.assertEqual(result["reglas_aplicadas"], ["RSK01"])
        self.assertEqual(risk("alto")["reglas_aplicadas"], ["RSK02","RSK03","RSK04"])
        incomplete = OrganizationEvidence("alto", "alto", "prob", "impact", "criticidad", asset_reference="activo")
        self.assertIsNone(risk("alto", incomplete)["nivel"])
        self.assertEqual(risk("alto", OrganizationEvidence(contradictory=True))["reglas_aplicadas"], ["RSK05"])

    def test_priorities_and_confidences(self):
        self.assertEqual(priority("S2"), ("media", ["PRI01"]))
        self.assertEqual(priority("S1", recurrent=True), ("media", ["PRI01","PRI02"]))
        self.assertEqual(priority("S2", multifase=True), ("alta", ["PRI01","PRI03"]))
        self.assertEqual(priority("S3", urgent=True), ("inmediata", ["PRI01","PRI04"]))
        self.assertEqual(priority("S1", critical=True), ("alta", ["PRI01","PRI05"]))
        self.assertEqual(priority("S4"), ("inmediata", ["PRI06"]))
        self.assertEqual(priority("No evaluable"), (None, ["PRI07"]))
        for n, args in enumerate([
            {"direct": True}, {"contract": True}, {"inferred": True},
            {"alternative": True}, {"indirect": True}, {"independent": True},
            {"contradictory": True}, {"cited": False}, {"generated_effect": True},
        ], 1):
            self.assertEqual(classification_confidence(**args)["regla"], f"CON{n:02}")

    def test_mocked_narrative_cannot_override_findings_and_protects_secrets(self):
        raw = report_data()
        raw["fases"][0]["eventos"] = [1, 2]
        raw["fases"][0].update(observado="Se ejecutó el comando y fue una prueba autorizada.", resultado="Compromiso probado")
        raw["hipotesis"][0]["descripcion"] = "Atribución categórica del actor"
        proposed = AnalysisResult.model_validate({"resumen": "Compromiso probado", "informe": raw, "acciones":[]})
        events = [event(1, "systemctl stop auditd.service"), event(2, kind="cowrie.session.closed")]
        result = structure_result(proposed, evaluate_session(events,{1,2},SESSION,MODE), {1,2}, MODE, {})
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("Compromiso probado", serialized)
        self.assertNotIn("prueba autorizada", serialized)
        self.assertEqual(result["evaluacion_amenaza"]["codigo_severidad"], "S3")
        self.assertNotIn("transferencia", result["evaluacion_amenaza"]["fundamento_prioridad"])
        self.assertEqual(result["informe"]["fases"][0]["estado_resultado"], "intento")
        self.assertIn("Evaluación técnica", {section["title"] for section in analytical_sections(result)})
        self.assertFalse(analytical_sections({"informe":raw}))
        self.assertFalse(result["contexto_observado"]["cobertura_evidencia"]["referencias_tty"])
        self.assertNotIn("value-from-other-event", str(facts_for_model(
            [event(1,"echo value-from-other-event")],
            secret_source=[event(2,kind="cowrie.login.failed",password="value-from-other-event")])))


    def test_observable_urls_keep_identity_unless_they_contain_secrets(self):
        mask = protected_text([{"password": "synthetic-value"}])
        benign = "https://evidence.corp.local/item?arg=1#section"
        self.assertEqual(mask(benign, observable_url=True), benign)
        for url in (
            "https://evidence.corp.local/item?access%5ftoken=opaque",
            "https://evidence.corp.local/item#access_token=opaque",
            "https://evidence.corp.local/item?arg=synthetic%2dvalue",
            "https://evidence.corp.local/synthetic%2dvalue",
        ):
            with self.subTest(url=url):
                safe = mask(url, observable_url=True)
                self.assertNotEqual(safe, url)
                self.assertNotIn("synthetic", safe)
                self.assertNotIn("opaque", safe)
        self.assertEqual(mask(benign), benign)  # H01 preserves public IoC parameters; the LLM still receives only facts.

    def test_expanded_snapshot_has_all_fifteen_blocks_and_legacy_keys(self):
        url = "https://evidence.corp.local/item?arg=1"
        evidence = [event(42, command=f"wget {url}", eventid="cowrie.command.input", protocol="ssh")]
        report = report_data()
        report["recomendaciones"] = [dict(salvaguarda="Revisar el registro", activo="Registro", riesgo="Potencial",
                                          objetivo="Contrastar", medidas="Revisar", validacion="Comparar citas")]
        result = AnalysisResult.model_validate({
            "resumen": "Resumen previo",
            "informe": report,
            "acciones": [{
                "tipo": "comando", "descripcion": "Orden de descarga", "confianza": 0.7, "eventos": [42],
                "iocs": [{"tipo": "URL", "valor": url, "evento": 42, "referencia": 2}],
                "mitre": [proposal(eventos=[42]).model_dump()],
            }],
        })
        rejected, provenance = validate(result, evidence, local_context(evidence))
        self.assertFalse(rejected)
        self.assertTrue(provenance)
        original = result.model_dump(exclude_none=True)
        final = structure_result(result, evaluate_session(evidence, {42}, SESSION, MODE), {42}, MODE,
                                 event_observables(evidence))
        nested = final["informe"]
        action, = final["acciones"]
        ioc, = action["iocs"]
        technique, = action["mitre"]
        for path, before, after in (
            ("root", original, final),
            ("informe", original["informe"], nested),
            ("fase", original["informe"]["fases"][0], nested["fases"][0]),
            ("hipótesis", original["informe"]["hipotesis"][0], nested["hipotesis"][0]),
            ("recomendación", original["informe"]["recomendaciones"][0], nested["recomendaciones"][0]),
            ("acción", original["acciones"][0], action),
            ("IoC", original["acciones"][0]["iocs"][0], ioc),
            ("MITRE", original["acciones"][0]["mitre"][0], technique),
        ):
            with self.subTest(path=path):
                self.assertFalse(before.keys() - after.keys())
        blocks = [
            final["resumen"], final["contexto_observado"], final["caracterizacion_amenaza"],
            final["vector_ataque"], nested["hipotesis"], nested["fases"], final["herramientas_artefactos"],
            action, ioc, technique, final["correlacion"], final["evaluacion_impacto"], final["evaluacion_amenaza"],
            final["estrategias_deteccion"], nested["conclusion"],
        ]
        self.assertEqual(len(blocks), 15)
        self.assertTrue(all(blocks))
        self.assertEqual(ioc["valor"], url)
        self.assertEqual(technique["eventos"], [42])
        self.assertEqual(nested["fases"][0]["estado_resultado"], "intento")
        self.assertIn("RSK03", final["evaluacion_amenaza"]["riesgo_organizacional"]["reglas_aplicadas"])

    def test_storage_sampling_text_output_and_tty_reference_are_distinct(self):
        command = event(42, command="uname -a")
        output = event(43, kind="cowrie.llm.response", response="Shutdown completed")
        no_reference = event(44, kind="cowrie.log.closed", ttylog="")
        reference = event(45, kind="cowrie.log.closed", ttylog="fixture-session.tty")
        baseline = [command, output, no_reference]
        for events, expected in ((baseline, []), ([*baseline, reference], ["45"])):
            with self.subTest(reference=expected):
                model = AnalysisResult.model_validate({"resumen":"Propuesta","acciones":[],"informe":report_data()})
                evaluated = evaluate_session(events, {42}, SESSION, "cowrie_llm")
                payload = structure_result(model, evaluated, {42}, "cowrie_llm", {})
                coverage = payload["contexto_observado"]["cobertura_evidencia"]
                self.assertEqual(coverage["eventos_almacenados"], len(events))
                self.assertEqual(coverage["eventos_entregados_al_modelo"], 1)
                self.assertEqual(coverage["eventos_omitidos_del_prompt"], len(events)-1)
                self.assertTrue(any("Salida textual estructurada" in item for item in coverage["fuentes_disponibles"]))
                self.assertEqual(coverage["referencias_tty"], expected)
                tty = [item for item in payload["informe"]["recomendaciones"] if item["activo"]=="Registro de captura"]
                self.assertEqual([item["eventos"] for item in tty], [expected] if expected else [])
                self.assertEqual(payload["informe"]["fases"][0]["estado_resultado"], "intento")
                self.assertNotIn("Shutdown completed", json.dumps(payload))
