"""Generate the Cowrie observability matrix from the pinned Enterprise STIX bundle."""

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path

from backend.rag.catalog import SHA256, VERSION, parse
from backend.rag.mitre_evidence import (
    ATTEMPT, CONTRACTS, KNOWN_MODES, OBSERVED, SOURCE_LIMITATIONS, VALIDATOR_VERSION,
)


NEEDED_BY_TACTIC = {
    "TA0043": "Registros anteriores a la sesión, trazas de reconocimiento externo o telemetría del objetivo.",
    "TA0042": "Evidencia externa de adquisición, despliegue o control de los recursos.",
    "TA0001": "Auditoría de acceso en el servicio objetivo y prueba del mecanismo de entrada.",
    "TA0002": "Identidad del ejecutable o intérprete, contenido ejecutado y contexto verificable de la operación.",
    "TA0003": "Cambio atribuible en cuentas, servicios, tareas o archivos de arranque y contexto previo.",
    "TA0004": "Identidad y privilegios efectivos antes y después, con causa atribuible a la acción.",
    "TA0005": "Artefacto, operación y contexto que distingan ocultamiento o evasión de administración ordinaria.",
    "TA0006": "Origen y tipo de credencial y acceso al almacén específico o patrón de autenticación que identifique el método.",
    "TA0007": "Consulta dirigida a la entidad indicada por la técnica o resultado verificable del inventario.",
    "TA0008": "Identidad y alcance del segundo sistema, registros de conexión o ejecución y relación con el origen.",
    "TA0009": "Origen y contenido de los datos, lectura o captura verificable y finalidad distinguible de una consulta ordinaria.",
    "TA0011": "Flujo o canal, dirección y destino, contenido o patrón que distinga C2 de tráfico normal.",
    "TA0010": "Datos que salieron, destino, dirección, protocolo y correlación con la transferencia.",
    "TA0040": "Estado anterior y posterior de los recursos objetivo y nexo causal con la operación.",
    "TA0112": "Identidad del control, operación atribuible y estado o configuración antes y después.",
}

PARTIAL = {
    "T1005": "Leer o listar un archivo no acredita recopilación para un objetivo posterior.",
    "T1021.004": "Un cliente SSH o un reenvío no demuestra acceso a un segundo sistema en el mismo entorno.",
    "T1041": "La orden de transferencia no demuestra que el canal sea de C2 ni qué datos salieron.",
    "T1070.004": "La eliminación genérica no identifica un artefacto relacionado con eliminación de indicadores.",
    "T1071.001": "Una petición HTTP o descarga no distingue un canal C2.",
    "T1071.004": "Una consulta DNS aislada no distingue señalización, tunelización ni C2.",
    "T1074.001": "Una copia o un movimiento de archivos no demuestra que exista una etapa de preparación de datos.",
    "T1078": "Cowrie puede aceptar credenciales emuladas y no acredita que sean cuentas reales comprometidas.",
    "T1078.001": "No se conoce el origen predeterminado de la cuenta en un servicio real.",
    "T1078.002": "No se acredita autenticación ante un dominio real.",
    "T1078.003": "Aceptar una credencial del señuelo no verifica una cuenta local real.",
    "T1102": "El dominio de un servicio web no demuestra su uso para C2.",
    "T1110.004": "No se puede atribuir el origen de los pares de credenciales a una colección filtrada.",
    "T1140": "Una utilidad de decodificación no acredita que el contenido pertenezca a una carga previamente ofuscada.",
    "T1485": "Una orden de borrado corriente no permite inferir la destrucción deliberada de datos del objetivo.",
    "T1486": "No se acredita cifrado de archivos objetivo ni intención o efecto de impacto.",
    "T1548.003": "Invocar sudo no acredita abuso de la configuración, caché ni elevación efectiva.",
    "T1567.004": "Una URL con forma de webhook no identifica los datos que salieron ni una exfiltración.",
    "T1570": "Los eventos de transferencia no establecen la identidad y relación de dos sistemas internos.",
    "T1611": "Las rutas y texto visible no acreditan cruzar el límite entre un invitado y su anfitrión.",
}

AVAILABLE = {
    "cowrie_shell": "Entrada estructurada del cliente, autenticación y descargas estructuradas. El sistema de archivos es emulado.",
    "cowrie_proxy": "Entrada del cliente y eventos de transporte si llegan al JSON de ingesta. Sin auditoría independiente del invitado.",
    "cowrie_llm": "Entrada del cliente y eventos estructurados independientes si llegan a la ingesta. Las respuestas se generan.",
}


def assess_mode(code, platform, active, tactics, mode):
    contract = CONTRACTS.get(code)
    declared = contract and mode in contract.modes
    extra = {}
    if not active:
        status, reason = "no_aplicable", "Objeto revocado o desaprobado en el catálogo fijado."
    elif set(tactics) and set(tactics) <= {"TA0042", "TA0043"}:
        status, reason = "no_observable", "La actividad ocurre fuera del alcance de una sesión del señuelo."
    elif "Linux" not in platform:
        status, reason = "no_aplicable", "El catálogo no incluye Linux para este objeto y el sensor se evalúa en ese contexto."
    elif declared:
        status = ("identificable_mediante_resultados_observados" if code == "T1105" and mode == "cowrie_shell"
                  else "identificable_mediante_correlacion" if contract.sequence or contract.minimum_distinct > 1
                  else "identificable_como_intento_explicito")
        reason = contract.minimum
        extra = {
            "contrato": code, "version": contract.version, "tipos_evento": sorted(contract.event_types),
            "grados": [ATTEMPT, OBSERVED] if status == "identificable_mediante_resultados_observados" else [ATTEMPT],
            "tacticas_admitidas": sorted(contract.tactics or set(tactics)),
            "correlacion": {"distintos_minimo": contract.minimum_distinct, "secuencia": list(contract.sequence),
                            "ventana_segundos": contract.window_seconds},
            "limitaciones": [contract.limitation, SOURCE_LIMITATIONS[mode]],
            "pruebas": ["tests/test_mitre_contracts.py", "tests/test_mitre_modalities.py"],
        }
        if OBSERVED in extra["grados"]:
            extra["limitaciones"].append(contract.observed_limitation)
    elif code in PARTIAL:
        status, reason = "parcialmente_observable", PARTIAL[code]
    else:
        status = "requiere_telemetria_adicional"
        reason = "El JSON de sesión carece de un discriminador verificado para el comportamiento de esta técnica."
    return {
        "estado": status, "clasificacion_automatica": bool(active and "Linux" in platform and declared),
        "evidencia_disponible": AVAILABLE[mode], "justificacion": reason,
        "evidencia_necesaria": contract.minimum if extra else [
            NEEDED_BY_TACTIC.get(tactic, "Registro verificable que discrimine el mecanismo.") for tactic in tactics
        ],
        **extra,
    }


def detection_sources(bundle):
    """Index official Linux analytics linked to each technique by STIX detects."""
    objects = {obj["id"]: obj for obj in bundle["objects"] if "id" in obj
               and not obj.get("revoked") and not obj.get("x_mitre_deprecated")}
    by_technique = defaultdict(set)
    for relationship in objects.values():
        if relationship.get("relationship_type") != "detects":
            continue
        strategy = objects.get(relationship["source_ref"], {})
        for reference in strategy.get("x_mitre_analytic_refs", ()):
            analytic = objects.get(reference, {})
            if "Linux" not in analytic.get("x_mitre_platforms", ()):
                continue
            analytic_code = next((ref["external_id"] for ref in analytic.get("external_references", ())
                                  if ref.get("source_name") == "mitre-attack"), reference)
            for source in analytic.get("x_mitre_log_source_references", ()):
                component = objects.get(source.get("x_mitre_data_component_ref"), {})
                by_technique[relationship["target_ref"]].add((
                    analytic_code, component.get("name", ""), source.get("name", ""), source.get("channel", "")
                ))
    return {
        technique: [{"analitica": code, "componente": component, "fuente": source, "canal": channel}
                    for code, component, source, channel in sorted(sources)]
        for technique, sources in by_technique.items()
    }


def inventory(path):
    payload = path.read_bytes()
    if sha256(payload).hexdigest() != SHA256:
        raise ValueError("La huella del catálogo local no corresponde con Enterprise 20.1")
    bundle = json.loads(payload)
    tactics, techniques, parents, relationships = parse(bundle)
    sources = detection_sources(bundle)
    by_code = defaultdict(list)
    for code, tactic in sorted(relationships):
        if not tactics[tactic].get("revoked") and not tactics[tactic].get("x_mitre_deprecated"):
            by_code[code].append(tactic)
    modes = sorted(KNOWN_MODES)
    counts = {mode: Counter() for mode in modes}
    tactic_counts = {tactic: Counter() for tactic in tactics}
    rows = []
    for code, obj in sorted(techniques.items()):
        active = not (obj.get("revoked") or obj.get("x_mitre_deprecated"))
        platforms = sorted(obj.get("x_mitre_platforms", ()))
        tactic_ids = by_code[code]
        decisions = {mode: assess_mode(code, platforms, active, tactic_ids, mode) for mode in modes}
        if code in CONTRACTS and (not active or "Linux" not in platforms or not tactic_ids
                                  or not CONTRACTS[code].tactics <= set(tactic_ids)):
            raise ValueError(f"Contrato incompatible con STIX: {code}")
        row = {
            "codigo": code, "nombre": obj["name"], "padre": parents.get(code),
            "tacticas": [{"codigo": tactic, "nombre": tactics[tactic]["name"]} for tactic in tactic_ids],
            "plataformas": platforms, "vigente": active, "revocada": bool(obj.get("revoked")),
            "desaprobada": bool(obj.get("x_mitre_deprecated")),
            "fuentes_linux_oficiales": sources.get(obj["id"], []), "modalidades": decisions,
        }
        rows.append(row)
        for mode, decision in decisions.items():
            if active:
                counts[mode][decision["estado"]] += 1
            if decision["clasificacion_automatica"]:
                for tactic in decision["tacticas_admitidas"]:
                    tactic_counts[tactic][mode] += 1
        if active:
            for tactic in tactic_ids:
                tactic_counts[tactic]["activos_catalogo"] += 1
    if missing := CONTRACTS.keys() - techniques.keys():
        raise ValueError(f"Contratos ausentes del catálogo: {sorted(missing)}")
    coverage = Counter(
        sum(decision["clasificacion_automatica"] for decision in row["modalidades"].values()) for row in rows
    )
    summary = {
        "catalogo": VERSION, "sha256": SHA256, "validador": VALIDATOR_VERSION,
        "objetos_totales": len(rows), "objetos_vigentes": sum(row["vigente"] for row in rows),
        "tecnicas_vigentes": sum(row["vigente"] and not row["padre"] for row in rows),
        "subtecnicas_vigentes": sum(bool(row["vigente"] and row["padre"]) for row in rows),
        "contratos": len(CONTRACTS), "tecnicas_unicas": sum(value for size, value in coverage.items() if size),
        "combinaciones_tecnica_modalidad": sum(size * value for size, value in coverage.items()),
        "compartidos": coverage[2] + coverage[3],
        "exclusivos_por_modalidad": {mode: sum(
            row["modalidades"][mode]["clasificacion_automatica"]
            and sum(d["clasificacion_automatica"] for d in row["modalidades"].values()) == 1 for row in rows
        ) for mode in modes},
        "modalidades_objetos_vigentes": counts,
        "tacticas": {code: {"nombre": tactics[code]["name"], **{k: counter[k] for k in ("activos_catalogo", *modes)}}
                    for code, counter in sorted(tactic_counts.items())},
    }
    return summary, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogo", type=Path, default=Path(".local/rag/enterprise-attack-20.1.json"))
    parser.add_argument("--salida", type=Path, required=True)
    args = parser.parse_args()
    summary, rows = inventory(args.catalogo)
    with args.salida.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write('{\n"resumen":' + json.dumps(summary, ensure_ascii=False) + ',\n"tecnicas":[\n')
        stream.write(",\n".join(json.dumps(row, ensure_ascii=False) for row in rows))
        stream.write("\n]}\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
