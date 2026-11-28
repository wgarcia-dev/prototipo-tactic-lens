"""Evaluate a frozen, synthetic analytical corpus without touching operational data."""
import argparse
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

from dotenv import load_dotenv
import httpx
from sqlalchemy import text

from backend.analysis_consolidation import structure_result
from backend.analysis_model import evaluate_session, resources
from backend.analysis_semantics import describe_events
from backend.analysis_state import digest, evidence_snapshot, methodology_configuration
from backend.db import database_engine
from backend.rag.evaluation import evaluate_corpus
from backend.rag.pipeline import evidence_sample
from backend.rag.retrieval import active_catalog, context, select_candidates
from backend.rag.validation import validate
from backend.routes import event_observables, real_result, supported_proposals

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "tests/fixtures/h04_corpus_inicial.json"
DIMENSIONS = ("confidencialidad", "integridad", "disponibilidad")


class BudgetExhausted(RuntimeError):
    pass


class BoundedDeepSeek:
    def __init__(self, client, endpoint, token_budget, usd_budget, input_price, output_price):
        self.client = client
        self.endpoint = endpoint + "/chat/completions"
        self.limit = token_budget
        self.money = usd_budget
        self.input_price = input_price
        self.output_price = output_price
        self.tokens = 0
        self.reserved_cost = Decimal(0)
        self.requests = 0

    def cost(self, input_tokens, output_tokens):
        return (input_tokens * self.input_price + output_tokens * self.output_price) / Decimal(1_000_000)

    def __call__(self, url, *, headers, json, timeout):
        if url != self.endpoint or not self.limit:
            raise BudgetExhausted("Destino o presupuesto rechazado")
        # Reserve by UTF-8 byte count plus envelope margin, and bill all input
        # at the operator-supplied cache-miss rate. Unknown usage is not refunded.
        estimated_input = sum(len(m["content"].encode("utf-8")) + 32 for m in json["messages"]) + 256
        max_output = json["max_tokens"]
        reserved_tokens = estimated_input + max_output
        reserved_money = self.cost(estimated_input, max_output)
        if self.tokens + reserved_tokens > self.limit or self.reserved_cost + reserved_money > self.money:
            raise BudgetExhausted("Presupuesto insuficiente para reservar la siguiente solicitud")
        self.tokens += reserved_tokens
        self.reserved_cost += reserved_money
        self.requests += 1
        response = self.client.post(url, headers=headers, json=json, timeout=timeout)
        if response.is_success:
            try:
                usage = response.json().get("usage") or {}
                actual_input, actual_output = usage.get("prompt_tokens"), usage.get("completion_tokens")
                if all(type(value) is int and value >= 0 for value in (actual_input, actual_output)):
                    self.tokens += actual_input + actual_output - reserved_tokens
                    self.reserved_cost += self.cost(actual_input, actual_output) - reserved_money
            except (AttributeError, ValueError, TypeError):
                pass
        return response


def simulated_provider(url, *, headers, json, timeout):
    # Deliberately independent of the answer key. This echo of eligible
    # witnesses exercises response validation and is not a model quality test.
    from json import dumps, loads

    payload = loads(json["messages"][-1]["content"])
    actions = []
    for candidate in payload["tecnicas_mitre_permitidas"]:
        witness = candidate["testigos"][0]
        ids = witness["eventos"]
        actions.append({"tipo": "telemetria", "descripcion": "Propuesta sintética de evaluación",
                        "eventos": ids, "confianza": 0.5, "mitre": [{
                            "codigo": candidate["codigo_tecnica"], "codigo_tactica": candidate["tacticas"][0]["codigo_tactica"],
                            "comportamiento_observado": "Comportamiento registrado en la muestra",
                            "justificacion": "Propuesta sintética asociada a los testigos suministrados por el servidor.",
                            "eventos": ids, "grado_evidencia": witness["grado"],
                            "limitaciones": ["La captura no acredita ejecución ni afectación de un activo real."],
                        }]})
    content = {"resumen": "Salida sintética para comprobar el paso de validación.", "acciones": actions,
               "informe": {"contexto": "Sesión sintética.", "conclusion": "Se conserva el alcance de la evidencia.",
                           "fases": [{"fase": "Observación", "observado": "Se registró un evento del señuelo.",
                                     "interpretacion": "Registro de la captura.", "resultado": "Alcance limitado.",
                                     "eventos": [payload["eventos"][0]["id_evento"]]}],
                           "limitaciones": ["Salida simulada sin atribución a un servicio comercial."]}}
    return httpx.Response(200, json={"model": "simulador-h04-v1", "choices": [{
        "finish_reason": "stop", "message": {"content": dumps(content, ensure_ascii=False)}}]},
        request=httpx.Request("POST", url))


def seconds_ms(start):
    return round((time.perf_counter() - start) * 1000, 2)


def fixture_events(case):
    session_id = uuid5(NAMESPACE_URL, "tacticlens-evaluacion-h04/" + case["id"])
    events = [SimpleNamespace(id_evento=row["id_evento"], tipo_evento=row["eventid"], id_sesion=session_id,
                             fecha_hora=datetime.fromisoformat(row["timestamp"]),
                             datos_originales={key: value for key, value in row.items() if key != "id_evento"})
              for row in case["eventos"]]
    return events, {"id_sesion": session_id, "id_honeypot": uuid5(NAMESPACE_URL, "tacticlens-eval-sensor"),
                    "ip_origen": events[0].datos_originales.get("src_ip")}


def run_case(engine, case, sender=None, max_output_tokens=None):
    started = time.perf_counter()
    result = {"estado": "fallido", "latencia_ms": {}}
    try:
        events, session = fixture_events(case)
        result["eventos_sha256"] = evidence_snapshot(events)["eventos_sha256"]
        mode = case["modalidad"]
        sample = evidence_sample(events, mode)
        delivered = {event.id_evento for event in sample}
        before_retrieval = time.perf_counter()
        rag = context(engine, events, modality=mode, sample=sample)
        result["latencia_ms"]["recuperacion"] = seconds_ms(before_retrieval)
        result["recuperadas"] = [candidate["codigo_tecnica"] for candidate in rag["candidatos"]]
        by_event = event_observables(events)
        evaluated = evaluate_session(events, delivered, session, mode, context_evidence=None)
        block, _, _, _, witnesses, _ = evaluated
        behaviors = describe_events(events, mode, witnesses, resources)
        impact = block.evaluacion_impacto
        threat = block.evaluacion_amenaza
        flags = {"resultado_transferencia_senuelo" for item in behaviors.values()
                 if item.operacion == "descarga_registrada" and item.estado == "resultado_observado"}
        if threat["riesgo_organizacional"]["estado"] == "evaluado":
            flags.add("organizacion_evaluada")
        if impact["impacto_observado"] == "IO01":
            flags.add("impacto_externo_confirmado")
        result.update(estado_local="completado", contratos=sorted({item.code for item in witnesses}),
                      acciones=[f"{item.evento}:{item.estado}" for item in behaviors.values()],
                      iocs=sorted({f"{item.tipo}:{item.valor}" for items in by_event.values() for item in items}),
                      severidad=threat["codigo_severidad"], confianza=threat["confianza_evaluacion"],
                      cia={dimension: {"observado": impact[dimension]["estado_observado"],
                                      "potencial": impact[dimension]["nivel_potencial"]} for dimension in DIMENSIONS},
                      riesgo_tecnico=threat["riesgo_tecnico_potencial"], organizacion=threat["riesgo_organizacional"]["estado"],
                      eventos_entregados=len(delivered), afirmaciones=sorted(flags))
        if sender is not None:
            rag["candidatos"] = select_candidates(rag["candidatos"])
            rag["eventos_entregados"] = sorted(delivered)
            before_provider = time.perf_counter()
            output = real_result(events, rag=rag, send=sender, max_output_tokens=max_output_tokens)
            result["latencia_ms"]["proveedor"] = seconds_ms(before_provider)
            proposals = [item for action in output.acciones for item in action.mitre]
            narrative_ids = [eid for group in (output.informe.fases, output.informe.hipotesis)
                             for claim in group for eid in claim.eventos]
            admissible = sum(eid in delivered and eid in action.eventos for action in output.acciones
                             for item in action.mitre for eid in item.eventos)
            for action in output.acciones:
                action.iocs = [proposal.model_copy(update={"valor": value})
                               for proposal, value, reason in supported_proposals(action, by_event) if not reason]
            _, accepted = validate(output, events, rag)
            cited = defaultdict(set)
            for (_, code, _), evidence in accepted.items():
                cited[code].update(evidence["eventos"])
            consolidated = structure_result(output, evaluated, delivered, mode, by_event)
            if any(item.get("grado_evidencia") == "efecto_verificado" for item in consolidated["acciones"]):
                flags.add("ejecucion_confirmada")
            result.update(identificadas=sorted(cited), propuestas=sorted({item.codigo for item in proposals}),
                          citas_mitre={code: sorted(ids) for code, ids in cited.items()},
                          citas={"propuestas": sum(len(item.eventos) for item in proposals), "admisibles": admissible,
                                 "narrativa": len(narrative_ids),
                                 "narrativa_admisibles": sum(eid in delivered for eid in narrative_ids)},
                          tokens=rag.get("respuesta_proveedor", {}).get("uso") or None,
                          modelo_reportado=rag.get("respuesta_proveedor", {}).get("modelo_reportado"),
                          solicitud_sha256=rag.get("solicitud_sha256"), afirmaciones=sorted(flags))
        result["estado"] = "completado"
    except BudgetExhausted:
        result["error"] = "presupuesto"
    except (AttributeError, httpx.HTTPError, KeyError, RuntimeError, TypeError, ValueError) as error:
        result["error"] = type(error).__name__
    result["latencia_ms"]["total"] = seconds_ms(started)
    return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--salida", type=Path, required=True)
    parser.add_argument("--modo", choices=("local", "simulado", "real"), default="local")
    parser.add_argument("--resultados-guardados", type=Path)
    parser.add_argument("--casos-max", type=int)
    parser.add_argument("--tokens-max", type=int)
    parser.add_argument("--salida-tokens-max", type=int, default=8192)
    parser.add_argument("--presupuesto-usd", type=Decimal)
    parser.add_argument("--precio-entrada-millon", type=Decimal)
    parser.add_argument("--precio-salida-millon", type=Decimal)
    args = parser.parse_args()
    if args.casos_max is not None and args.casos_max <= 0:
        parser.error("--casos-max debe ser positivo")
    if args.modo == "real" and not args.resultados_guardados:
        prices = args.presupuesto_usd, args.precio_entrada_millon, args.precio_salida_millon
        if (not args.casos_max or not args.tokens_max or args.tokens_max <= 0
                or not 0 < args.salida_tokens_max <= 8192
                or not all(value and value.is_finite() and value > 0 for value in prices)):
            parser.error("El modo real requiere topes positivos de casos, tokens y USD, más las dos tarifas vigentes.")
    return args


def main():
    args = arguments()
    load_dotenv(ROOT / ".env")
    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    if corpus["metadata"].get("independiente") is not True:
        raise SystemExit("El corpus requiere etiquetas independientes declaradas")
    cases = corpus["casos"][:args.casos_max]
    metadata = {"corpus": corpus["metadata"], "corpus_sha256": digest(corpus), "modo": args.modo}
    if args.resultados_guardados:
        saved = json.loads(args.resultados_guardados.read_text(encoding="utf-8"))
        if saved["metadata"]["corpus_sha256"] != metadata["corpus_sha256"]:
            raise SystemExit("La referencia independiente pertenece a otro corpus")
        results = {case["id"]: saved["resultados"][case["id"]] for case in cases}
        if any(results[case["id"]].get("eventos_sha256") != evidence_snapshot(fixture_events(case)[0])["eventos_sha256"]
               for case in cases):
            raise SystemExit("Los casos guardados tienen un snapshot distinto o no verificable")
        metadata = {**saved["metadata"], "recalculado_desde_resultados_guardados": True}
    else:
        with httpx.Client(trust_env=False, follow_redirects=False) as client:
            sender = None
            if args.modo == "simulado":
                sender = simulated_provider
            elif args.modo == "real":
                from scripts.prepare_deepseek_trial import configuration
                config = configuration()
                sender = BoundedDeepSeek(client, config["base_url"], args.tokens_max, args.presupuesto_usd,
                                          args.precio_entrada_millon, args.precio_salida_millon)
            fixture = {"LLM_MODEL": "simulador-h04-v1", "LLM_PROVIDER": "simulado", "LLM_API_KEY": "fixture-local",
                       "LLM_BASE_URL": "https://fixture.invalid/v1"}
            engine = database_engine().execution_options(postgresql_readonly=True)
            try:
                with patch.dict("os.environ", fixture if args.modo == "simulado" else {}):
                    with engine.connect() as conn:
                        if conn.scalar(text("SHOW transaction_read_only")) != "on":
                            raise RuntimeError("La evaluación requiere PostgreSQL de solo lectura")
                        methodology = methodology_configuration(active_catalog(conn), {})
                    if args.modo == "local":
                        methodology.update(modelo=None, proveedor=None)
                    else:
                        methodology["parametros"]["max_tokens"] = args.salida_tokens_max
                    metadata["metodologia"] = methodology
                    results = {case["id"]: run_case(engine, case, sender, args.salida_tokens_max) for case in cases}
                if isinstance(sender, BoundedDeepSeek):
                    metadata["consumo_controlado"] = {"solicitudes": sender.requests, "tokens_cargados_o_reservados": sender.tokens,
                                                     "usd_estimados_o_reservados": str(sender.reserved_cost)}
            finally:
                engine.dispose()
    result = {"metadata": metadata, "metricas": evaluate_corpus(cases, results), "resultados": results}
    args.salida.parent.mkdir(parents=True, exist_ok=True)
    args.salida.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"modo": metadata["modo"], "casos": len(cases), "fallos": result["metricas"]["fallos_tecnicos"]}))
    return 1 if result["metricas"]["fallos_tecnicos"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
