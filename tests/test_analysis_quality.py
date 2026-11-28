"""Regression coverage for the analytical quality corrections."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from uuid import uuid4

from backend.analysis_consolidation import structure_result
from backend.analysis_model import ContextPattern, evaluate_session
from backend.analysis_presentation import analytical_sections
from backend.analysis_semantics import characterize, describe_events
from backend.analysis_trace import DiagnosticTrace
from backend.rag.validation import validate
from backend.routes import AnalysisResult, event_observables
from test_analysis import report_data
from test_rag import event, local_context, proposal

SESSION = {"id_sesion":"fixture", "id_honeypot":"sensor", "ip_origen":"10.0.0.8","protocolo":"ssh"}
MODE = "desconocido"


def consolidate(events, action=None, mapping=None, goal=None, history=(), modality=MODE, relationship=None,
                safeguards=None):
    ids = [e.id_evento for e in events]
    report = report_data()
    report["fases"][0]["eventos"] = ids
    report["hipotesis"][0].update(eventos=ids, objetivo_probable=goal, relacion=relationship)
    if safeguards is not None:
        report["recomendaciones"] = safeguards
    result = AnalysisResult.model_validate({"resumen": action or "Resumen propuesto.", "informe":report,
        "acciones": [{"tipo":"orden","descripcion":action or "Orden propuesta.","confianza":0.7,"eventos":ids,
                      "mitre":[mapping] if mapping else []}]})
    rejected = []
    if mapping:
        ctx=local_context(events,"T1059.004","Unix Shell","TA0002")
        ctx["modalidad"]=modality
        rejected,_=validate(result,events,ctx)
    decisions={}
    data=structure_result(result,evaluate_session(events,ids,SESSION,modality,history),
                          set(ids),modality,event_observables(events),decisions=decisions)
    return data, decisions, rejected


class AnalysisQualityTests(unittest.TestCase):
    def test_terminal_budget_and_contextual_org_risk_keep_formal_abstention(self):
        from backend.rag.pipeline import evidence_sample
        from backend.terminal_evidence import terminal_context
        command = event(25,"cat /etc/os-release",command_id="fixture-command")
        output = event(50,kind="cowrie.command.output",command_id="fixture-command",
                       output="Permission denied\n" + "x" * 9000)
        other = [event(i,kind="cowrie.client.version") for i in range(1,101) if i not in {25,50}]
        for item in [command,output,*other]:
            item.id_sesion = "fixture"
        sample = {item.id_evento for item in evidence_sample([*other,command,output], "cowrie_proxy")}
        self.assertLessEqual(len(sample),80)
        self.assertTrue({25,50} <= sample)
        entries, counts = terminal_context([command,output], sample, "cowrie_proxy")
        self.assertEqual(entries[0]["evento_orden"], "25")
        self.assertTrue(entries[0]["limite_lectura"])
        self.assertEqual(counts["salidas_con_extracto"],1)
        data, _, _ = consolidate([command,output], modality="cowrie_proxy")
        risk = data["evaluacion_amenaza"]["riesgo_organizacional"]
        self.assertEqual(risk["estado"],"no_evaluable")
        self.assertIn("permisos de lectura",risk["escenarios_condicionados"][0])
        sections = analytical_sections(data)
        self.assertTrue(any(item["title"] == "Metadatos técnicos" for item in sections))

    def test_model_diligence_preserves_citations_and_indexes_in_sanitized_trace(self):
        from backend.analysis_trace import minimized
        phrase = "instrucción del modelo sin verificar"
        proposal = {key:phrase for key in ("activo","riesgo","salvaguarda","objetivo","medidas","validacion")}
        events = [event(1,"hostname"), event(2,"orden-no-reconocida"), event(3,"cat /etc/os-release")]
        data, decisions, _ = consolidate(events, relationship="consulta_y_lectura", safeguards=[
            dict(proposal, enfoque="verificar_recurso", eventos=[1,3]),
            dict(proposal, enfoque="aclarar_orden", eventos=[1]),
        ])
        first = data["informe"]["recomendaciones"][0]
        self.assertEqual(first["eventos"], ["1","3"])
        self.assertIn("nombre del sistema",first["activo"])
        self.assertNotIn(phrase, json.dumps(data))
        self.assertEqual(len(data["informe"]["conclusion"].split("\n\n")), 4)
        trace = minimized({"motivos_por_campo":{**decisions, "[credencial]":phrase}})
        paths = trace["motivos_por_campo"]
        self.assertEqual(paths["hipotesis.propuestas[0].relacion"]["aceptadas"], 1)
        self.assertEqual(paths["recomendaciones[1].enfoque"]["rechazadas"], 1)
        self.assertNotIn("[credencial]", paths)

    def test_model_relationship_requires_chronology_and_exact_support(self):
        events = [event(1, "hostname"), event(2, "una-orden-no-reconocida"),
                  event(3, "cat /etc/os-release"), event(4, "exit")]
        data, decisions, _ = consolidate(events, relationship="consulta_y_lectura")
        hypothesis, = [item for item in data["informe"]["hipotesis"] if item.get("relacion")]
        self.assertEqual(hypothesis["eventos"], [1, 3])
        self.assertIn("exploración", data["resumen"])
        self.assertIn("#2", data["resumen"])
        self.assertIn("2", data["evaluacion_impacto"]["integridad"]["eventos"])
        self.assertIn("terminal", data["evaluacion_impacto"]["integridad"]["fundamento"])
        self.assertEqual(decisions["hipotesis.propuestas[0].relacion"]["aceptadas"], 1)
        inverted, decisions, _ = consolidate(
            [event(1, "cat /etc/os-release"), event(2, "hostname")], relationship="consulta_y_lectura")
        self.assertFalse(any(item.get("relacion") for item in inverted["informe"]["hipotesis"]))
        self.assertEqual(decisions["hipotesis.propuestas[0].relacion"]["rechazadas"], 1)

    def test_single_measurements_and_redundant_phrasing(self):
        events = [event(1, "pwd"), event(2, "cat /etc/os-release"),
                  event(3, kind="cowrie.client.size", width=80, height=24)]
        proposal = ("El cliente pidió consultar el directorio de trabajo. "
                    "Se solicitó consultar el directorio de trabajo. Se solicitó leer un archivo.")
        data, decisions, _ = consolidate(events, proposal)
        self.assertEqual(decisions["resumen"]["duplicadas"], 1)
        self.assertEqual(data["resumen"].count("consultar el directorio de trabajo"), 1)
        self.assertIn("Se solicitó leer un archivo", data["resumen"])
        basis = data["caracterizacion_amenaza"]["fundamento_automatizacion"]
        self.assertIn("Se midió un intervalo", basis)
        self.assertIn("Terminal — La captura registra un único tamaño", basis)
        display = next(s for s in analytical_sections(data) if s["title"] == "Herramientas y artefactos")
        row = next(row for row in display["rows"] if row[0] == "pwd")
        self.assertEqual(row[2].count("consultar el directorio de trabajo"), 1)
        self.assertIn("\nRecurso objetivo", row[2])

    def test_replays_keep_only_supported_propositions_and_reject_unfounded_shell_mapping(self):
        path=Path(__file__).with_name("fixtures")/"quality_replay_sanitized.json"
        fixtures=json.loads(path.read_text(encoding="utf8"))
        sentence="La orden pwd solicitó consultar el directorio de trabajo."
        for record in fixtures:
            with self.subTest(record=record["analisis_base"]):
                start=datetime(2026,11,26,tzinfo=timezone.utc)
                events=[SimpleNamespace(id_evento=e["id"],tipo_evento=e["tipo"],fecha_hora=start+timedelta(seconds=e["segundos"]),
                                        datos_originales={"eventid":e["tipo"],**e["forma"]},id_sesion="fixture")
                        for e in record["eventos"]]
                mapped=proposal("T1059.004","TA0002",eventos=record["rechazo_mitre"]).model_dump()
                data, decisions, rejected=consolidate(events,sentence+" Compromiso probado.",mapped)
                self.assertIn(sentence,data["resumen"])
                self.assertIn(sentence,data["acciones"][0]["descripcion"])
                self.assertNotIn("Compromiso probado",json.dumps(data))
                self.assertEqual(decisions["acciones[0].descripcion"]["rechazadas"],1)
                self.assertEqual(rejected[0]["causa"],"evidencia_insuficiente")
                self.assertFalse(data["acciones"][0]["mitre"])
                self.assertEqual(data["evaluacion_amenaza"]["codigo_severidad"],"S1")
                self.assertEqual(data["evaluacion_amenaza"]["riesgo_organizacional"]["estado"],"no_evaluable")
                self.assertIn("pwd",{t["nombre"] for t in data["herramientas_artefactos"]})
                self.assertTrue(any(h["objetivo_inmediato"]=="consultar el directorio de trabajo" for h in data["informe"]["hipotesis"]))
                self.assertTrue(any(s["codigo_mitre"] is None and s["eventos"] for s in data["estrategias_deteccion"]))
                self.assertTrue(any(r["activo"]=="Autenticaciones SSH" for r in data["informe"]["recomendaciones"]))
                self.assertNotIn("Actividad documentada",{f["fase"] for f in data["informe"]["fases"]})
                self.assertNotEqual(data["informe"]["conclusion"],"La evaluación describe los hechos y solicitudes que admiten los eventos citados.")
                projection=analytical_sections(data)
                timeline=next(s for s in projection if s["title"]=="Cronología estructurada")
                self.assertEqual(len(timeline["rows"]),len(data["informe"]["fases"]))
                self.assertTrue(all("UTC-05:00" in row[1] and "#" in row[3] for row in timeline["rows"]))

    def test_operational_objectives_and_inference_with_literal_evidence_and_no_mitre(self):
        d,_,_=consolidate([event(1,"pwd"),event(2,"date")],goal="inventariar_entorno")
        self.assertTrue(any(h["objetivo_probable"]=="inventariar_entorno" for h in d["informe"]["hipotesis"]))
        self.assertEqual(d["caracterizacion_amenaza"]["complejidad_tecnica"],"basica")
        self.assertEqual(d["caracterizacion_amenaza"]["grado_automatizacion"],"indeterminada")
        self.assertEqual(d["evaluacion_amenaza"]["codigo_severidad"],"S1")
        self.assertEqual(d["evaluacion_amenaza"]["prioridad_investigacion"],"baja")

    def test_unknown_and_dynamic_syntax_never_expand_or_expose_values(self):
        events=[event(1,'echo $(id)'),
                event(2,'unknown palabra-secreta'),
                event(3,'cat /etc/os-release'),
                event(4,'cat /tmp/secreto-local'),
                event(5,'hostname --file /tmp/secreto-local')]
        values=describe_events(events,MODE)
        self.assertEqual(values[1].operacion,"orden_sin_semantica")
        self.assertEqual(values[2].operacion,"orden_sin_semantica")
        self.assertEqual(values[3].recurso,"/etc/os-release")
        self.assertEqual(values[4].recurso,"archivo indicado")
        self.assertIsNone(values[5].objetivo)
        self.assertNotIn("secreto",json.dumps([v.public() for v in values.values()]))

    def test_automation_uses_distinct_terminal_changes_and_timing_not_speed(self):
        orders=[event(1,"pwd"),event(2,"date"),event(7,"hostname"),event(8,"exit")]
        first=event(3,kind="cowrie.client.size",width=80,height=24)
        resize=event(5,kind="cowrie.client.size",width=120,height=60)
        for events, expected in ((orders,"indeterminada"),([*orders,first],"indeterminada"),
                                 ([*orders,first,resize],"manual_probable")):
            behaviors=describe_events(events,MODE)
            self.assertEqual(characterize(behaviors,events,[],[])[2],expected)

    def test_associations_are_separate_from_formal_recurrence_and_use_existing_roles(self):
        events=[event(1,"pwd",eventid="cowrie.command.input",src_ip="10.0.0.8"),event(2,"exit")]
        at=events[0].fecha_hora - timedelta(seconds=60)
        other=ContextPattern("otra","otro", "10.0.0.7",at,frozenset({"RC06"}),("directorio_actual",),
                             frozenset({"pwd"}),("44",), referencias=(("operacion:directorio_actual","44"),))
        d,_,_=consolidate(events,history=[other])
        self.assertEqual(d["correlacion"]["asociaciones_contextuales"],[])
        self.assertEqual(d["correlacion"]["frecuencia"],0)
        self.assertNotIn("AG10",{a["codigo"] for a in d["evaluacion_amenaza"]["factores_agravantes"]})
        self.assertTrue(any(o["alcance"]=="transporte" and o["clasificacion"]=="observable"
                            for o in d["observables_contextuales"]))

    def test_differentiated_sequence_cites_both_sessions_without_citing_exit(self):
        events = [event(1,"pwd"),event(2,"hostname"),event(3,"exit")]
        other = ContextPattern("otra","otro","10.0.0.7",events[0].fecha_hora,
            frozenset(),("directorio_actual","nombre_host"),referencias=(
                ("operacion:directorio_actual","44"),("operacion:nombre_host","45")))
        data, _, _ = consolidate(events,history=[other])
        match, = data["correlacion"]["asociaciones_contextuales"]
        self.assertEqual(match["eventos_actuales"],["1","2"])
        self.assertEqual(match["eventos_asociados"],["44","45"])

    def test_cia_and_incident_reuse_evidence_without_new_mitre_or_organizational_score(self):
        from backend.incident_assessment import assess
        events = [event(1,"pwd"),event(2,"exit")]
        data, _, _ = consolidate(events, "El cliente pidió consultar el directorio de trabajo. El cliente modificó archivos.")
        impact = data["evaluacion_impacto"]
        self.assertEqual(impact["confidencialidad"]["eventos"],["1"])
        self.assertIn("reconocimiento posterior",impact["confidencialidad"]["descripcion"])
        self.assertIn("cierre de la interacción",impact["disponibilidad"]["descripcion"])
        self.assertEqual(impact["impacto_potencial"],"no_evaluable")
        self.assertIn("El cliente pidió",data["resumen"])
        self.assertNotIn("modificó archivos",data["resumen"])
        result = assess(events,data["evaluacion_amenaza"],impact)
        self.assertEqual(result["severidad"],"S1")
        self.assertEqual(result["estado"],"pendiente_revision")
        self.assertEqual(result["revisiones"],[])
        result.update(severidad="alta", clasificacion="incidente_confirmado", estado="en_respuesta")
        data["evaluacion_incidente"] = result
        titles = {row["title"] for row in analytical_sections(data)}
        self.assertIn("Evaluación técnica",titles)
        self.assertTrue({"Riesgo técnico","Riesgo organizacional","Evidencia de terminal y límites de cobertura",
                         "Evaluación automática de incidente"}.isdisjoint(titles))
        self.assertEqual(result["automatica"]["severidad"],"S1")

    def test_safeguard_risk_is_individual_and_requires_citations(self):
        from backend.safeguard_risk import assess_safeguard
        data, _, _ = consolidate([event(1,"pwd"),event(2,"history -c")])
        one = {"activo":"directorio de trabajo","medidas":"Validar permisos","eventos":["1"]}
        two = {"activo":"registro de actividad","medidas":"Verificar integridad","eventos":["2"]}
        self.assertEqual(assess_safeguard(one,data)["nivel"],"bajo")
        self.assertEqual(assess_safeguard(two,data)["nivel"],"alto")
        self.assertIsNone(assess_safeguard({**one,"eventos":[]},data)["nivel"])

    def test_connection_context_does_not_create_unnecessary_controls(self):
        d,_,_=consolidate([event(1,kind="cowrie.session.connect",protocol="ssh"),
                           event(2,kind="cowrie.session.closed",protocol="ssh")])
        self.assertEqual(d["evaluacion_amenaza"]["codigo_severidad"],"S0")
        self.assertEqual(d["estrategias_deteccion"],[])
        self.assertEqual(d["informe"]["recomendaciones"],[])

    def test_tty_metadata_and_unsafe_text_are_never_copied_to_trace(self):
        secret="hidden fixture password and terminal path"
        with TemporaryDirectory() as folder:
            path=Path(folder)
            self.assertFalse(DiagnosticTrace().write(uuid4(),path))
            enabled=DiagnosticTrace(True)
            enabled.record("contexto_entregado",{"referencias_tty":[1],"ttylog":secret,"descripcion":secret})
            enabled.record("consolidacion",{"estado":"intento","eventos":[1],"password":secret})
            with patch("backend.analysis_trace.private_directory",return_value=path):
                self.assertTrue(enabled.write(uuid4(),path))
            text=next(path.glob("*.json")).read_text(encoding="utf8")
            self.assertNotIn(secret,text)
            self.assertNotIn("ttylog",text)
            self.assertNotIn("password",text)
            actual=json.loads(text)["etapas"]
            self.assertEqual(actual["contexto_entregado"]["referencias_tty"],[1])
            self.assertEqual(actual["consolidacion"]["estado"],"intento")
