"""Build a versioned, evidence-bound representation from the saved session snapshot."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Literal

import json
from itertools import combinations
from typing_extensions import NotRequired, TypedDict

from pydantic import BaseModel, Field

from .analysis_impact import evaluate_impact, organizational_context
from .analysis_report import observation_context
from .analysis_controls import complement_strategies
from .analysis_semantics import characterize, describe_events
from .intelligence import extract_observables
from .rag.mitre_evidence import ATTEMPT, COMMAND_INPUT, OBSERVED, SOURCE_LIMITATIONS, VALIDATOR_VERSION
from .terminal_evidence import terminal_context, tty_references
from .threat_evaluation import (
    AUTH, CONFIG_SIGNATURE, LABELS, LEVELS, MATRIX, METHODOLOGY,
    ROWS, SCHEMA_VERSION, VERSION, SessionPattern, classification_confidence, complementary,
    contract_witnesses, normalized_origin, priority, recurrence, risk,
)

_OFFICIAL = Path(__file__).with_name("rag") / "analysis_catalog_20_1.json"
_OFFICIAL_BYTES = _OFFICIAL.read_bytes()
OFFICIAL = json.loads(_OFFICIAL_BYTES)
NARRATIVE_VERSION = "evidence_semantics_v7"
SIGNATURE = (*CONFIG_SIGNATURE, sha256(_OFFICIAL_BYTES).hexdigest(), NARRATIVE_VERSION)


class Assertion(BaseModel):
    id: str
    eventos: list[str]
    grado_evidencia: Literal["contexto", "intento", "resultado_en_honeypot", "efecto_verificado"]
    fundamento: str
    alcance: str
    modalidad: str
    reglas_validacion: list[str]
    estado_validacion: Literal["validado", "abstencion"]
    limitaciones: list[str]
    confianza_analitica: dict[str, str]
    codigo_mitre: str | None = None
    codigo_severidad: str


class AnalyticalConfidence(TypedDict):
    codigo: Literal["CF0", "CF1", "CF2", "CF3"]
    nivel: Literal["insuficiente", "baja", "moderada", "alta"]
    regla: str
    fundamento: str


class Characterization(TypedDict):
    tipo_actividad: str
    naturaleza_amenaza: str
    patron_comportamiento: list[str]
    grado_automatizacion: Literal["manual_probable", "automatizada_probable", "mixta_probable", "indeterminada"]
    complejidad_tecnica: Literal["basica", "intermedia", "avanzada", "no_evaluable"]
    nivel_interaccion: Literal["conexion", "autenticacion", "comandos", "multifase"]
    capacidades_observadas: list[str]
    fundamento: str
    eventos: list[str]
    confianza_analitica: AnalyticalConfidence
    fundamento_complejidad: NotRequired[str]
    fundamento_automatizacion: NotRequired[str]
    confianza_automatizacion: NotRequired[AnalyticalConfidence]


class AttackVector(TypedDict):
    vector: str | None
    servicio: str | None
    protocolo: str | None
    metodo_acceso: str
    mecanismo_autenticacion: str | None
    estado_acceso: str
    debilidad_potencial: str | None
    vulnerabilidad_identificada: str | None
    fundamento: str
    eventos: list[str]


class Artifact(TypedDict):
    id: str
    nombre: str
    tipo: str
    categoria: str
    valor: str
    forma_utilizacion: str
    estado_utilizacion: Literal["mencionado", "solicitado", "transferido", "utilizacion_acreditada"]
    finalidad_probable: str | None
    observables_relacionados: list[dict[str, str]]
    eventos: list[str]
    confianza_analitica: AnalyticalConfidence
    recurso_objetivo: NotRequired[str | None]
    implicacion_seguridad: NotRequired[str]


class ContextCorrelation(TypedDict):
    sesiones_relacionadas: list[str]
    observables_compartidos: list[dict[str, str]]
    ttps_recurrentes: list[str]
    patron_comun: list[str]
    frecuencia: int
    primera_observacion: str | None
    ultima_observacion: str | None
    tipo_relacion: str | None
    fundamento_correlacion: str
    confianza_relacion: AnalyticalConfidence
    asociaciones_contextuales: NotRequired[list[dict]]


ImpactLevel = Literal["bajo", "moderado", "alto", "no_evaluable"]
ObservedState = Literal["IO01", "IO02", "IO03", "IO04", "IO05"]


class Dimension(TypedDict):
    estado_observado: ObservedState
    nivel_potencial: ImpactLevel
    descripcion: str
    fundamento: str
    condiciones: list[str]
    eventos: list[str]
    reglas_aplicadas: list[str]
    recursos: NotRequired[list[str]]
    recomendacion: NotRequired[str]


class ImpactEvaluation(TypedDict):
    confidencialidad: Dimension
    integridad: Dimension
    disponibilidad: Dimension
    impacto_observado: ObservedState
    impacto_potencial: ImpactLevel
    recursos_afectados: list[str]
    recursos_en_riesgo: list[str]
    alcance: str
    fundamento: str
    eventos: list[str]
    reglas_aplicadas: list[str]


class EvidenceFactor(TypedDict):
    codigo: str
    descripcion: str
    eventos: list[str]


class ThreatEvaluation(TypedDict):
    severidad_preliminar: str
    codigo_severidad: Literal["S0", "S1", "S2", "S3", "S4", "No evaluable"]
    nivel_impacto_potencial: ImpactLevel
    prioridad_investigacion: Literal["baja", "media", "alta", "inmediata"] | None
    fundamento_severidad: str
    fundamento_prioridad: str
    factores_agravantes: list[EvidenceFactor]
    factores_limitantes: list[EvidenceFactor]
    confianza_evaluacion: AnalyticalConfidence
    riesgo_tecnico_potencial: dict[str, str | None]
    riesgo_organizacional: dict[str, str | list[str] | None]
    reglas_aplicadas: list[str]
    eventos: list[str]
    version_metodologia: str
    fecha_evaluacion: str


class DetectionStrategy(TypedDict):
    nombre: str
    descripcion: str
    codigo_mitre: str | None
    recurso_objetivo: NotRequired[str]
    medidas_propuestas: NotRequired[str]
    comportamiento_objetivo: str
    fuentes_datos: list[dict[str, str | None]]
    criterio_deteccion: str
    prioridad: str | None
    justificacion: str
    criterio_validacion: str
    eventos: list[str]
    referencias: list[dict[str, str]]
    origen: Literal["TacticLens"]


class AnalysisBlocks(BaseModel):
    version_esquema: int = SCHEMA_VERSION
    version_metodologia: str = METHODOLOGY
    version_matriz: str = VERSION
    version_contratos: str = VALIDATOR_VERSION
    version_narrativa: str = NARRATIVE_VERSION
    hallazgos_principales: list[str]
    clasificacion_actividad: Literal["conexion", "sospechosa", "intento_intrusion_compatible", "comportamiento_hostil_sustentado", "indeterminada"]
    valoracion_amenaza: str
    caracterizacion_amenaza: Characterization
    vector_ataque: AttackVector
    herramientas_artefactos: list[Artifact]
    correlacion: ContextCorrelation
    evaluacion_impacto: ImpactEvaluation
    evaluacion_amenaza: ThreatEvaluation
    estrategias_deteccion: list[DetectionStrategy]
    hallazgos_confirmados: list[str]
    inferencias_principales: list[str]
    confianza_analitica: dict[str, str]
    fundamento_confianza: str
    evidencia_adicional_requerida: list[str]
    alcance_conclusion: str
    evidencias_analiticas: list[Assertion] = Field(default_factory=list)


def event_ids(events):
    return [str(event.id_evento) for event in events]


@dataclass(frozen=True)
class ContextPattern(SessionPattern):
    secuencia: tuple[str, ...] = ()
    herramientas: frozenset[str] = frozenset()
    testigos_semanticos: tuple[str, ...] = ()
    observables: frozenset[str] = frozenset()
    referencias: tuple[tuple[str, str], ...] = ()


def observable_identity(item):
    return sha256((item.tipo + ":" + item.valor).encode()).hexdigest()


def session_pattern(session, witnesses, events, behaviors=None):
    behaviors = behaviors if behaviors is not None else describe_events(
        events, session.get("modalidad", "desconocido"), [w for w in witnesses if w.code], resources)
    operations = [b for b in behaviors.values() if b.objetivo]
    signals = [(f"operacion:{b.operacion}", str(b.evento)) for b in operations
               if b.categoria in {"descubrimiento", "recursos", "red", "modificacion", "transferencia"}]
    signals += [(f"mitre:{w.code}", str(eid)) for w in witnesses if w.code for eid in w.ids]
    signals += [(f"observable:{observable_identity(item)}", str(e.id_evento)) for e in events
                for item in extract_observables(e.datos_originales) if item.campo not in {"src_ip", "dst_ip"}]
    return ContextPattern(
        str(session["id_sesion"]), str(session["id_honeypot"]), normalized_origin(session.get("ip_origen")) or "",
        max(event.fecha_hora for event in events), frozenset(witness.behavior for witness in witnesses if witness.ids),
        tuple(b.operacion for b in operations), frozenset(b.herramienta for b in operations if b.herramienta),
        tuple(str(b.evento) for b in operations),
        frozenset(observable_identity(item) for e in events for item in extract_observables(e.datos_originales)
                  if item.campo not in {"src_ip","dst_ip"}), tuple(dict.fromkeys(signals)),
    )


def contextual_matches(pattern, history):
    matches = []
    for other in history:
        if not isinstance(other, ContextPattern) or other.session == pattern.session:
            continue
        common = {key for key, _ in pattern.referencias} & {key for key, _ in other.referencias}
        techniques = sorted(key.removeprefix("mitre:") for key in common if key.startswith("mitre:"))
        shared_observables = sum(key.startswith("observable:") for key in common)
        operations = sorted(key.removeprefix("operacion:") for key in common if key.startswith("operacion:"))
        left = tuple(code for code in pattern.secuencia if code in operations)
        right = tuple(code for code in other.secuencia if code in operations)
        similarly_ordered = len(set(left)) >= 2 and left == right
        if techniques or shared_observables or similarly_ordered:
            rank = 3 if shared_observables and (techniques or similarly_ordered) else 2 if shared_observables or similarly_ordered else 1
            matches.append({
                "id_sesion":other.session,"herramientas":[],"tecnicas":techniques,
                "operaciones_comunes":operations,"secuencia_coincidente":similarly_ordered,
                "total_observables_no_transporte":shared_observables,
                "eventos_actuales":list(dict.fromkeys(eid for key, eid in pattern.referencias if key in common)),
                "eventos_asociados":list(dict.fromkeys(eid for key, eid in other.referencias if key in common)),
                "ventana":[stamp.isoformat() for stamp in sorted((pattern.at, other.at))],
                "relevancia":rank,
                "alcance":"Contrastar el recurso, la secuencia o el testigo compartido en ambas capturas. La coincidencia no identifica al operador.",
            })
    return sorted(matches,key=lambda row: (-row["relevancia"], row["id_sesion"]))[:25]


def coverage(events, delivered, modality):
    recorded = tty_references(events)
    terminal, counts = terminal_context(events, set(delivered), modality)
    limits = []
    if not counts["salidas_con_texto"]:
        limits.append("Los eventos almacenados carecen de cuerpos de salida textual. Los fallos estructurados conservan su valor como registro del sensor.")
    else:
        limits.append(f"Hay {counts['salidas_con_texto']} cuerpos de salida almacenados. "
                      f"El contexto lleva extractos diagnósticos de {counts['salidas_con_extracto']} registros. "
                      "El texto libre queda reservado para proteger datos del terminal.")
    if counts["evidencias_no_enviadas"]:
        limits.append(f"El muestreo o el presupuesto omitió {counts['evidencias_no_enviadas']} registros de terminal del contexto del modelo.")
    if recorded:
        limits.append("La captura conserva referencias TTY. Se requiere el archivo de grabación del sensor para revisar contenido o resultado.")
    if any(record["limite_lectura"] for record in terminal):
        limits.append("El extractor limitó la lectura de al menos un cuerpo de salida a sus primeros 8192 caracteres.")
    result = {
        "eventos_almacenados": len(events), "eventos_entregados_al_modelo": len(delivered),
        "eventos_omitidos_del_prompt": len(events) - len(delivered),
        "fuentes_disponibles": ["Eventos JSON estructurados"] +
        (["Salida textual estructurada en los registros almacenados"] if counts["salidas_con_texto"] else []) +
        (["Fallos estructurados de Cowrie"] if counts["fallos_registrados"] else []) +
        (["Referencia registrada a una grabación TTY"] if recorded else []),
        "referencias_tty": recorded, "terminal":counts, "evidencia_terminal":terminal,
        "limitaciones": [*limits, SOURCE_LIMITATIONS[modality]],
    }
    if len(delivered) < len(events):
        result["limitaciones"].insert(0, f"El modelo recibió {len(delivered)} de {len(events)} eventos. La evaluación determinista usa el conjunto almacenado.")
    return result


def resources(witness):
    """Expose resource categories, keeping raw literals and captured values in their original events."""
    code = witness.code
    if code == "T1489":
        return "control defensivo" if witness.specific == "defensa" else "servicio"
    if code in {"T1552.004", "T1098.004"}:
        return "material de autenticación SSH"
    if code in {"T1003.008", "T1222.002", "T1552.003", "T1560.001"}:
        return "material sensible"
    if code in {"T1685.006", "T1690", "T1070.003"}:
        return "registro de actividad"
    if code in {"T1110", "T1110.001", "T1110.003", "T1136.001", "T1098.007", "T1531"}:
        return "cuentas y acceso"
    if code == "T1105":
        return "archivo de transferencia entrante"
    if code in {"T1046", "T1572"}:
        return "destino de red indicado en el evento"
    return None


def scoped_witnesses(events, modality):
    mitre, contradictory, duplicates = contract_witnesses(events, modality)
    return mitre, complementary(events, modality, mitre), contradictory, duplicates


def evaluate_session(events, delivered, session, modality, history=(), context_evidence=None):
    ordered = sorted(events, key=lambda e: (e.fecha_hora, e.id_evento))
    by_id = {event.id_evento: event for event in ordered}
    mitre, extra, conflicts, duplicates = scoped_witnesses(ordered, modality)
    witnesses = mitre + extra
    valid = [witness for witness in witnesses if witness.level in LEVELS]
    best = max((w.level for w in valid), key=LEVELS.index, default="No evaluable")
    best_rows = [w for w in valid if w.level == best]
    base_families = defaultdict(set)
    for witness in mitre:
        base_families[ROWS[witness.code]["tacticas_admitidas"][0]["codigo"]].update(witness.ids)
    # Both tactical meanings must have independent evidence, not labels for the same events.
    multifase = any(left - right and right - left for left, right in combinations(base_families.values(), 2))
    behaviors = describe_events(ordered, modality, mitre, resources)
    pattern = session_pattern(session, witnesses, ordered, behaviors)
    repeated = recurrence(pattern, list(history))
    investigate, priority_rules = priority(best, recurrent=bool(repeated), multifase=multifase)
    observed = {eid for w in mitre if w.grade == OBSERVED for eid in w.ids}
    impact = evaluate_impact(witnesses, behaviors=tuple(behaviors.values()))
    impact["recursos_en_riesgo"] = sorted({resource for w in mitre if (resource := resources(w))}
        | {resource for name in ("confidencialidad", "integridad", "disponibilidad")
           for resource in impact[name].get("recursos", [])})
    organization = risk(impact["impacto_potencial"], context_evidence)
    organization["escenarios_condicionados"] = organizational_context(behaviors.values())
    visibility = coverage(ordered, delivered, modality)
    factor_support = defaultdict(set)
    limits = defaultdict(set)
    for w in witnesses:
        ids = set(w.ids)
        rule, code = w.rule, w.code
        if code in {"T1110", "T1110.001", "T1110.003"}:
            factor_support["AG01"].update(ids)
        if rule == "RC05":
            factor_support["AG02"].update(ids)
        if rule == "RC06":
            limits["LI07"].update(ids)
        if code in {"T1003.008", "T1552.003", "T1552.004", "T1560.001", "T1222.002"}:
            factor_support["AG03"].update(ids)
        if code in {"T1053.003", "T1053.006", "T1098.004", "T1098.007", "T1543.002"}:
            factor_support["AG05"].update(ids)
        if code in {"T1685.006", "T1690", "T1070.003"} or w.specific == "defensa":
            factor_support["AG06"].update(ids)
        if code and w.grade == ATTEMPT:
            factor_support["AG13"].update(ids)
        if code and len(ids) > 1:
            factor_support["AG14"].update(ids)
        if code in {"T1046", "T1572", "T1105"}:
            factor_support["AG15"].update(ids)
        if code == "T1098.007":
            factor_support["AG16"].update(ids)
        if w.grade == OBSERVED:
            factor_support["AG17"].update(ids)
        if w.grade == ATTEMPT:
            limits["LI01"].update(ids)
            if any(by_id[eid].tipo_evento == COMMAND_INPUT for eid in ids):
                limits["LI04"].update(ids)
    if multifase:
        factor_support["AG09"].update(eid for w in mitre for eid in w.ids)
    if repeated:
        factor_support["AG10"].update(eid for w in witnesses if w.behavior in repeated for eid in w.ids)
    if modality == "desconocido":
        limits["LI02"]
    if visibility["eventos_omitidos_del_prompt"]:
        limits["LI05"]
    if any(w.grade in {ATTEMPT, OBSERVED} for w in valid):
        limits["LI06"]
    if conflicts:
        limits["LI03"].update(conflicts)
    if duplicates:
        limits["LI12"]
    if not valid:
        limits["LI09"]
    incomplete_inputs = [e.id_evento for e in ordered if e.tipo_evento == COMMAND_INPUT and
                         e.datos_originales.get("realm") is None and not isinstance(e.datos_originales.get("input"), str)]
    if incomplete_inputs:
        limits["LI11"].update(incomplete_inputs)
    if organization["estado"] == "no_evaluable" and "RSK04" in organization["reglas_aplicadas"]:
        limits["LI08"]
    if any(w.level in {"S2", "S3"} for w in valid):
        limits["LI14"]
    simulated = [e.id_evento for e in ordered if e.tipo_evento in {"cowrie.command.output", "cowrie.llm.response"}]
    if simulated:
        limits["LI10"].update(simulated)
    def factors(values, name):
        labels = MATRIX["reglas_operativas"][name]
        return [{"codigo": code, "descripcion": labels[code], "eventos": [str(eid) for eid in sorted(ids)]}
                for code, ids in sorted(values.items())]
    scope = SOURCE_LIMITATIONS[modality]
    assertions = []
    for witness in witnesses:
        ids = [str(eid) for eid in witness.ids]
        digest = sha256((witness.rule + ":" + ",".join(ids)).encode()).hexdigest()[:16]
        assertions.append(Assertion(
            id="E-" + digest, eventos=ids, grado_evidencia=witness.grade, fundamento=witness.summary,
            alcance=scope, modalidad=modality, reglas_validacion=[witness.rule],
            estado_validacion="validado" if witness.level != "No evaluable" else "abstencion",
            limitaciones=[scope], confianza_analitica=classification_confidence(
                direct=bool(ids), contract=bool(witness.code), cited=bool(ids) and witness.level in LEVELS),
            codigo_mitre=witness.code, codigo_severidad=witness.level,
        ))
    context = observation_context(ordered)
    transport = next((e.datos_originales for e in ordered if e.tipo_evento == "cowrie.session.connect"), {})
    protocol = session.get("protocolo")
    context.update({
        "id_sesion": str(session["id_sesion"]), "id_sensor": str(session["id_honeypot"]),
        "ip_origen": normalized_origin(session.get("ip_origen")), "ip_destino": normalized_origin(transport.get("dst_ip")),
        "puerto_origen": session.get("puerto_origen"), "puerto_destino": session.get("puerto_destino"), "protocolo": protocol,
        "servicio_objetivo": protocol if protocol in {"ssh", "telnet"} else None, "modalidad": modality,
        "total_eventos": len(ordered), "total_comandos": context["comandos"], "cobertura_evidencia": visibility,
    })
    top_summaries = list(dict.fromkeys(
        "Se registró una orden cuya finalidad requiere corroboración" if w.rule == "RC06" else w.summary.rstrip(".")
        for w in best_rows))
    severity_reason = ". ".join(top_summaries[:6]) + "." if top_summaries else (
        "La captura carece de un evento que satisfaga los criterios actuales de severidad.")
    priority_reason = ("Reglas aplicadas " + ", ".join(priority_rules) + ". " + severity_reason
                       if investigate else "Revisión de calidad y procedencia de la evidencia.")
    label = LABELS.get(best, "No evaluable")
    assessment = {
        "severidad_preliminar": label, "codigo_severidad": best, "nivel_impacto_potencial": impact["impacto_potencial"],
        "prioridad_investigacion": investigate, "fundamento_severidad": severity_reason, "fundamento_prioridad": priority_reason,
        "factores_agravantes": factors(factor_support, "agravantes"), "factores_limitantes": factors(limits, "limitantes"),
        "confianza_evaluacion": classification_confidence(direct=bool(best_rows), contract=any(w.code for w in best_rows), cited=bool(best_rows)),
        "riesgo_tecnico_potencial": {"nivel": impact["impacto_potencial"], "fundamento": impact["fundamento"], "regla": "RSK02" if impact["reglas_aplicadas"] else None},
        "riesgo_organizacional": organization, "reglas_aplicadas": sorted({w.rule for w in best_rows} | set(priority_rules) | ({"RC07"} if repeated else set())),
        "eventos": [str(eid) for eid in sorted({eid for w in best_rows for eid in w.ids})],
        "version_metodologia": METHODOLOGY, "fecha_evaluacion": datetime.now(timezone.utc).isoformat(),
    }
    activity = {"S0": "conexion", "S1": "sospechosa", "S2": "intento_intrusion_compatible",
                "S3": "comportamiento_hostil_sustentado"}.get(best, "indeterminada")
    if best == "S2" and not any(w.code in {"T1110", "T1110.001", "T1110.003", "T1572", "T1046"} for w in best_rows):
        activity = "sospechosa"
    if len(top_summaries) > 6:
        summary_tail = " Consulte los hallazgos principales para ver todos los testigos."
    else:
        summary_tail = ""
    accepted = context["autenticaciones_exitosas"]
    rejected = context["autenticaciones_fallidas"]
    summary = f"Se examinaron {len(ordered)} eventos, con {context['comandos']} órdenes registradas, {accepted} autenticaciones aceptadas y {rejected} rechazadas. Severidad técnica {label}. {severity_reason}{summary_tail}"
    classes = sorted({w.code for w in mitre})
    interaction = "multifase" if multifase else "comandos" if context["comandos"] else "autenticacion" if accepted or rejected else "conexion"
    confidence = assessment["confianza_evaluacion"]
    confidence_refs = ", ".join("#" + eid for eid in assessment["eventos"][:8])
    confidence_basis = (f"La valoración {best} se apoya en {severity_reason} Evidencia {confidence_refs}. "
                        "La confianza se refiere a lo que registran esas citas. El resultado fuera del sensor requiere evidencia independiente."
                        if confidence_refs else "La captura carece de citas suficientes para sostener una valoración de severidad.")
    if conflicts:
        confidence_basis += " Revisar la contradicción en los eventos " + ", ".join(
            f"#{eid}" for eid in sorted(conflicts)[:8]) + " antes de sostener la acción discutida."
    categories, complexity, automation, complexity_basis, automation_basis, semantic_ids = characterize(
        behaviors, ordered, mitre, history)
    objective_limits = ["Una auditoría independiente del activo debe confirmar los efectos y su relación con los eventos citados."]
    if visibility["referencias_tty"]:
        objective_limits.append("Verificar la referencia TTY registrada en los eventos " + ", ".join("#" + eid for eid in visibility["referencias_tty"]) + " para contextualizar la interacción, si el archivo está disponible.")
    main_ids = [a.id for a in assertions if a.codigo_severidad == best and a.estado_validacion == "validado"]
    confirmed = [a.id for a in assertions if a.estado_validacion == "validado"]
    available_related = sorted({item for group in repeated.values() for item in group if item != pattern.session})
    block = AnalysisBlocks(
        hallazgos_principales=main_ids, clasificacion_actividad=activity, valoracion_amenaza=label,
        caracterizacion_amenaza={
            "tipo_actividad": activity, "naturaleza_amenaza": " · ".join(categories) or "Interacción sin mecanismo acreditado",
            "patron_comportamiento": list(dict.fromkeys([*classes,*categories])), "grado_automatizacion": automation,
            "complejidad_tecnica": complexity, "fundamento_complejidad": complexity_basis,
            "fundamento_automatizacion": automation_basis,
            "confianza_automatizacion": classification_confidence(inferred=automation!="indeterminada", cited=automation!="indeterminada"),
            "nivel_interaccion": interaction,
            "capacidades_observadas": list(dict.fromkeys([b.descripcion for b in behaviors.values()
                if b.objetivo and b.categoria != "finalizacion"] + [w.summary for w in mitre])),
            "fundamento": severity_reason, "eventos": list(dict.fromkeys(assessment["eventos"] + list(map(str,semantic_ids)))),
            "confianza_analitica": confidence,
        },
        vector_ataque={
            "vector": "servicio remoto" if protocol in {"ssh", "telnet"} else None, "servicio": context["servicio_objetivo"],
            "protocolo": protocol, "metodo_acceso": "autenticacion" if accepted or rejected else "conexion",
            "mecanismo_autenticacion": "contraseña registrada" if any(e.tipo_evento in AUTH and "password" in e.datos_originales for e in ordered) else None,
            "estado_acceso": "aceptado_por_sensor" if accepted else "rechazado" if rejected else "sin_autenticacion_acreditada",
            "debilidad_potencial": None, "vulnerabilidad_identificada": None,
            "fundamento": "El estado de acceso se obtiene de los eventos de autenticación dentro de la sesión.",
            "eventos": event_ids([e for e in ordered if e.tipo_evento in AUTH or e.tipo_evento == "cowrie.session.connect"]),
        },
        herramientas_artefactos=artifacts(behaviors, by_id),
        correlacion={
            "sesiones_relacionadas": available_related, "observables_compartidos": [{"tipo": "IP", "valor": pattern.origin}] if available_related else [],
            "ttps_recurrentes": sorted(set(repeated) & set(ROWS)), "patron_comun": sorted(repeated),
            "frecuencia": max(map(len, repeated.values()), default=0),
            "primera_observacion": min((h.at.isoformat() for h in history if h.session in available_related), default=None),
            "ultima_observacion": pattern.at.isoformat() if repeated else None,
            "tipo_relacion": "recurrencia_de_comportamiento" if repeated else None,
            "fundamento_correlacion": "Coinciden sensor, origen, clase y ventana. La identidad de la persona permanece indeterminada." if repeated else "No se acreditó el umbral de recurrencia en los registros evaluados.",
            "confianza_relacion": classification_confidence(inferred=bool(repeated), cited=bool(repeated)),
            "asociaciones_contextuales":contextual_matches(pattern, history),
        },
        evaluacion_impacto=impact, evaluacion_amenaza=assessment, estrategias_deteccion=strategies(mitre) + complement_strategies(behaviors, witnesses, investigate),
        hallazgos_confirmados=confirmed, inferencias_principales=[], confianza_analitica=confidence,
        fundamento_confianza=confidence_basis, evidencia_adicional_requerida=objective_limits,
        alcance_conclusion=scope, evidencias_analiticas=assertions,
    )
    return block, context, summary, observed, mitre, by_id


def artifacts(behaviors, by_id):
    result = {}
    for b in behaviors.values():
        if not (b.herramienta or b.objetivo or b.estado == "resultado_observado"):
            continue
        by_kind = []
        if b.herramienta:
            by_kind.append((b.herramienta,"herramienta","solicitado"))
        if b.recurso and (b.categoria in {"recursos","modificacion","red"} or b.estado=="resultado_observado"):
            by_kind.append((b.recurso,"artefacto" if b.estado=="resultado_observado" else "recurso",
                            "transferido" if b.estado=="resultado_observado" else "mencionado"))
        event = by_id[b.evento]
        links = [{"evento":str(b.evento),"referencia":str(i),"tipo":item.tipo,"rol":item.comportamiento}
                 for i,item in enumerate(extract_observables(event.datos_originales),1)
                 if item.campo not in {"src_ip","dst_ip"}]
        for name, kind, state in by_kind:
            item = result.setdefault((name,state), {
                "id": f"H-{len(result)+1}","nombre":name,"tipo":kind,"categoria":b.categoria,"valor":name,
                "forma_utilizacion":b.descripcion,"estado_utilizacion":state,
                "finalidad_probable":b.objetivo,"observables_relacionados":[],"eventos":[],
                "recurso_objetivo":b.recurso,
                "implicacion_seguridad":{
                    "descubrimiento":"La respuesta podría revelar características del entorno si la consulta se materializara.",
                    "modificacion":"La solicitud podría cambiar el estado del recurso si se ejecutara con permisos suficientes.",
                    "recursos":"Corroborar acceso y sensibilidad del recurso antes de valorar la exposición.",
                    "red":"Corroborar en registros de red el destino y si llegó a establecerse comunicación.",
                    "finalizacion":"La solicitud se refiere al cierre de la interacción.",
                    "transferencia":"Corroborar el origen, integridad y alcance del artefacto registrado.",
                }.get(b.categoria, "El registro permite atribuir la solicitud al terminal de la sesión."),
                "confianza_analitica":classification_confidence(direct=True),
            })
            if str(b.evento) not in item["eventos"]:
                item["eventos"].append(str(b.evento))
                item["observables_relacionados"].extend(links)
    return list(result.values())


def strategies(witnesses):
    result = {}
    for witness in witnesses:
        code = witness.code
        catalog = OFFICIAL["tecnicas"][code]
        if code not in result:
            result[code] = {
                "nombre": "Comprobación defensiva de " + ROWS[code]["nombre_oficial"],
                "descripcion": "Estrategia propia de TacticLens. Verificar el comportamiento en fuentes autorizadas.",
                "codigo_mitre": code, "comportamiento_objetivo": witness.summary,
                "fuentes_datos": catalog["fuentes_linux"], "criterio_deteccion": witness.summary,
                "prioridad": priority(witness.level)[0],
                "justificacion": "El comportamiento se sustenta mediante el contrato y los eventos citados.",
                "criterio_validacion": "Correlacionar las citas con auditoría independiente del recurso y documentar discrepancias.",
                "eventos": [], "referencias": catalog["estrategias"], "origen": "TacticLens",
            }
        result[code]["eventos"] = list(dict.fromkeys([*result[code]["eventos"], *(str(eid) for eid in witness.ids)]))
    return list(result.values())
