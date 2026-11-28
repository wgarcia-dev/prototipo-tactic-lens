"""Deterministic assessment of Cowrie evidence and separately documented risk."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Literal, Protocol
import json
import re

from .intelligence import normalize_ip
from .rag.mitre_command_rules import SECURITY_UNITS
from .rag.mitre_evidence import (
    ATTEMPT, COMMAND_INPUT, CONTRACTS, OBSERVED, VALIDATOR_VERSION, collect_evidence, telemetry,
)

_MATRIX_BYTES = (Path(__file__).resolve().parents[1] / "docs/MATRIZ_SEVERIDAD_MITRE_V2.json").read_bytes()
MATRIX = json.loads(_MATRIX_BYTES)
ROWS = {row["codigo_mitre"]: row for row in MATRIX["contratos"]}
RULES = {row[0]: row for row in MATRIX["reglas_operativas"]["reglas_complementarias"]}
METHODOLOGY = MATRIX["version_metodologia"]
VERSION = MATRIX["version_matriz"]
SCHEMA_VERSION = 1
NARRATIVE_VERSION = "evidence_bound_v1"
CONFIG_SIGNATURE = (SCHEMA_VERSION, METHODOLOGY, VERSION, sha256(_MATRIX_BYTES).hexdigest(), NARRATIVE_VERSION)
RECURRENCE = MATRIX["reglas_operativas"]["recurrencia"]
LEVELS = ("S0", "S1", "S2", "S3", "S4")
LABELS = dict(zip(LEVELS, ("Informativa", "Baja", "Media", "Alta", "Crítica")))
PRIORITIES = ("baja", "media", "alta", "inmediata")
CIA = ("confidencialidad", "integridad", "disponibilidad")
IMPACT = ("no_evaluable", "bajo", "moderado", "alto")
AUTH = {"cowrie.login.failed", "cowrie.login.success"}
FAILURES = {"cowrie.command.failed", "cowrie.session.file_download.failed", "cowrie.direct-tcpip.failed"}
SSH_CONTEXT = {"cowrie.session.connect", "cowrie.session.closed", "cowrie.client.version", "cowrie.client.kex"}
if len(MATRIX["contratos"]) != 55 or set(ROWS) != set(CONTRACTS) or MATRIX["motor"] != VALIDATOR_VERSION:
    raise RuntimeError("La matriz de severidad no coincide con el registro MITRE")

# Likelihood rows and impact columns both in ascending order. NIST SP 800-30r1, table I-2.
RISK_LEVELS = ("muy_bajo", "bajo", "moderado", "alto", "muy_alto")
NIST_I2 = (
    (0, 0, 0, 1, 1),
    (0, 1, 1, 1, 2),
    (0, 1, 2, 2, 3),
    (0, 1, 2, 3, 4),
    (0, 1, 2, 3, 4),
)


class Event(Protocol):
    id_evento: int
    tipo_evento: str
    fecha_hora: datetime
    datos_originales: dict


EvidenceGrade = Literal["contexto", "intento", "resultado_en_honeypot", "efecto_verificado"]


@dataclass(frozen=True)
class Witness:
    rule: str
    level: str
    ids: tuple[int, ...]
    summary: str
    grade: EvidenceGrade = ATTEMPT
    code: str | None = None
    specific: str | None = None

    @property
    def behavior(self):
        return self.code or self.rule


@dataclass(frozen=True)
class OrganizationEvidence:
    likelihood: str | None = None
    impact: str | None = None
    likelihood_reference: str | None = None
    impact_reference: str | None = None
    criticality_reference: str | None = None
    contradictory: bool = False
    asset_reference: str | None = None
    exposure_reference: str | None = None


@dataclass(frozen=True)
class SessionPattern:
    session: str
    sensor: str
    origin: str
    at: datetime
    classes: frozenset[str]


def normalized_origin(value):
    try:
        return str(normalize_ip(str(value))) if value is not None else None
    except ValueError:
        return None


def classification_confidence(
    *, direct=False, contract=False, inferred=False, alternative=False, discriminates=False,
    indirect=False, independent=False, contradictory=False, cited=True, generated_effect=False,
):
    if contradictory:
        code, rule, reason = "CF0", "CON07", "Contradicción material sin resolver."
    elif generated_effect:
        code, rule, reason = "CF0", "CON09", "La respuesta generada carece de corroboración independiente."
    elif not cited:
        code, rule, reason = "CF0", "CON08", "La hipótesis carece de un testigo verificable."
    elif independent:
        code, rule, reason = "CF3", "CON06", "Fuentes independientes corroboran la misma proposición."
    elif contract:
        code, rule, reason = "CF3", "CON02", "El contrato sustenta la proposición y su grado indicado."
    elif direct:
        code, rule, reason = "CF3", "CON01", "El evento estructurado registra directamente el hecho acotado."
    elif alternative:
        code, rule, reason = ("CF2" if discriminates else "CF1"), "CON04", "La inferencia conserva explicaciones alternativas."
    elif inferred:
        code, rule, reason = "CF2", "CON03", "Los eventos sustentan una inferencia acotada."
    elif indirect:
        code, rule, reason = "CF1", "CON05", "El sustento indirecto es limitado."
    else:
        code, rule, reason = "CF0", "CON08", "Evidencia insuficiente para evaluar la proposición."
    return {"codigo": code, "nivel": {"CF0": "insuficiente", "CF1": "baja", "CF2": "moderada", "CF3": "alta"}[code],
            "regla": rule, "fundamento": reason}


def selected_level(code: str, event: Event, modality: str):
    row = ROWS[code]
    selector = row["selector_severidad"]
    if selector == "base":
        return row["severidad_base"], None
    command = telemetry(event, modality).command
    if selector == "unidad_defensiva":
        defense = command.args[-1] in SECURITY_UNITS
        return ("S3", "defensa") if defense else ("S2", "servicio")
    mode = command.args[0]
    if mode.isdecimal():
        number = int(mode, 8)
        return ("S3", "terceros") if number & 0o066 else ("S2", "otros_permisos") if number & 0o077 else ("S1", "restrictivo")
    subjects, operator, bits = re.fullmatch(r"([ugo]+)([+=-])([rwx]+)", mode).groups()
    if operator in "+=" and set(subjects) & {"g", "o"} and set(bits) & {"r", "w"}:
        return "S3", "terceros"
    return ("S1", "restrictivo") if operator == "-" else ("S2", "otros_permisos")


def contract_witnesses(events: list[Event], modality: str):
    """Reuse v5 recognizers, distinct groups and sequence witnesses for the full snapshot."""
    by_id = {event.id_evento: event for event in events}
    matches = collect_evidence(events, modality)
    witnesses = []
    contradictory = set()
    for code, signals in matches.items():
        contract = CONTRACTS[code]
        groups = contract.groups(signals)
        if contract.sequence and any(signal.step == "contradiccion" for signal in signals.values()):
            without = {eid: signal for eid, signal in signals.items() if signal.step != "contradiccion"}
            preserved = {tuple(contract.sequence_witness(group)) for group in groups}
            contradictory.update(eid for group in contract.groups(without)
                                 if (candidate := tuple(contract.sequence_witness(group))) not in preserved
                                 for eid in candidate if candidate)
        for group in groups:
            if contract.sequence:
                parts = [contract.sequence_witness(group)]
            elif contract.minimum_distinct > 1:
                parts = [contract.sample_ids(group)]
            else:
                parts = [(eid,) for eid in group]
            for ids in parts:
                if contract.contradicts and any(contract.contradicts(telemetry(by_id[eid], modality)) for eid in ids):
                    contradictory.update(ids)
                    continue
                grade = OBSERVED if all(signals[eid].grade == OBSERVED for eid in ids) else ATTEMPT
                level, specific = selected_level(code, by_id[ids[0]], modality)
                witnesses.append(Witness("ST-" + code, level, ids, contract.minimum, grade, code, specific))
    children = defaultdict(list)
    for witness in witnesses:
        if parent := ROWS[witness.code]["padre_oficial"]:
            children[parent].append(set(witness.ids))
    kept = [witness for witness in witnesses
            if not any(set(witness.ids) <= ids for ids in children.get(witness.code, []))]
    return kept, sorted(contradictory), len(kept) != len(witnesses)


def is_ssh(events: list[Event]):
    return any(event.datos_originales.get("protocol") == "ssh" or event.tipo_evento == "cowrie.client.kex"
               for event in events)


def complementary(events: list[Event], modality: str, contracts: list[Witness]):
    ssh = is_ssh(events)
    mapped = {eid for witness in contracts for eid in witness.ids}
    witnesses = []
    logged_in = None
    for event in events:
        kind, eid = event.tipo_evento, event.id_evento
        command = telemetry(event, modality).command if kind == COMMAND_INPUT else None
        # Keep transport context even when a different behavior cannot be evaluated.
        applicable = []
        if kind in SSH_CONTEXT and ssh:
            applicable.append(("RC02" if kind in {"cowrie.client.version", "cowrie.client.kex"} else "RC01", "S0", "contexto", (eid,)))
        if kind in AUTH:
            applicable.append(("RC04" if kind == "cowrie.login.success" else "RC03", "S1", "contexto", (eid,)))
            if kind == "cowrie.login.success":
                logged_in = event
        if logged_in and (logged_in.fecha_hora, logged_in.id_evento) < (event.fecha_hora, eid) and (command or kind == "cowrie.direct-tcpip.request" and eid in mapped):
            applicable.append(("RC05", "S1", "intento", (logged_in.id_evento, eid)))
        if command and eid not in mapped:
            applicable.append(("RC06", "S1", "intento", (eid,)))
        if kind in FAILURES:
            applicable.append(("RC08", "S0" if ssh else "No evaluable", "contexto", (eid,)))
        witnesses.extend(Witness(rule, level, ids, RULES[rule][1], grade) for rule, level, grade, ids in applicable)
    if not any(witness.level in LEVELS for witness in witnesses + contracts):
        witnesses.append(Witness("RC09", "No evaluable", (), RULES["RC09"][1], "contexto"))
    return witnesses


def recurrence(pattern: SessionPattern, history: list[SessionPattern]):
    low = pattern.at - timedelta(hours=RECURRENCE["ventana_horas"])
    by_behavior = defaultdict(set)
    if not pattern.origin or not pattern.sensor:
        return {}
    for item in [*history, pattern]:
        if item.sensor != pattern.sensor or item.origin != pattern.origin or not low <= item.at <= pattern.at:
            continue
        for key in pattern.classes & item.classes:
            by_behavior[key].add(item.session)
    return {key: sorted(ids) for key, ids in by_behavior.items() if len(ids) >= RECURRENCE["minimo_sesiones"]}


def priority(level, *, recurrent=False, multifase=False, urgent=False, critical=False):
    if level not in LEVELS:
        return None, ["PRI07"]
    if level == "S4":
        return "inmediata", ["PRI06"]
    ordinary = dict(zip(LEVELS, ("baja", "baja", "media", "alta", "inmediata")))[level]
    options = [("PRI01", ordinary)]
    if recurrent:
        options.append(("PRI02", dict(zip(LEVELS, ("baja", "media", "alta", "alta", "inmediata")))[level]))
    if multifase:
        options.append(("PRI03", {"baja": "media", "media": "alta", "alta": "alta"}[ordinary]))
    if urgent and level in {"S2", "S3"}:
        options.append(("PRI04", "alta" if level == "S2" else "inmediata"))
    if critical:
        options.append(("PRI05", "alta"))
    return max((value for _, value in options), key=PRIORITIES.index), [rule for rule, _ in options]


def risk(potential, organization: OrganizationEvidence | None = None):
    organization = organization or OrganizationEvidence()
    likelihood_ok = organization.likelihood_reference and organization.likelihood in RISK_LEVELS
    impact_ok = organization.impact_reference and organization.impact in RISK_LEVELS
    context_ok = all(reference and reference.strip() for reference in (
        organization.asset_reference, organization.exposure_reference, organization.criticality_reference))
    if organization.contradictory:
        return {"estado": "no_evaluable", "nivel": None, "reglas_aplicadas": ["RSK05"],
                "fundamento": "Los insumos organizacionales presentan una contradicción material."}
    if likelihood_ok and impact_ok and context_ok:
        output = NIST_I2[RISK_LEVELS.index(organization.likelihood)][RISK_LEVELS.index(organization.impact)]
        return {"estado": "evaluado", "nivel": RISK_LEVELS[output], "reglas_aplicadas": ["RSK01"],
                "fundamento": "Probabilidad e impacto organizacional documentados conforme a la tabla I-2.",
                "referencias": [organization.likelihood_reference, organization.impact_reference,
                                organization.criticality_reference, organization.asset_reference, organization.exposure_reference]}
    rules = ["RSK02"] if potential != "no_evaluable" else []
    if not likelihood_ok:
        rules.append("RSK03")
    if not impact_ok or not context_ok:
        rules.append("RSK04")
    return {"estado": "no_evaluable", "nivel": None, "reglas_aplicadas": rules,
            "fundamento": "Riesgo organizacional no evaluado. Se requieren activo, exposición, criticidad, probabilidad e impacto documentados."}

