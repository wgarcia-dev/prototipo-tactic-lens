"""Source attribution uses configured identities, never a port by itself."""
from sqlalchemy import and_, case, func, literal, or_, select

SOURCES = {
    "cowrie_shell": ("tacticlens-cowrie-01", "shell", "2222"),
    "cowrie_proxy": ("tacticlens-cowrie-proxy", "proxy", "2223"),
    "cowrie_llm": ("tacticlens-cowrie-llm", "llm", "2224"),
}
UNKNOWN = "desconocido"
BY_LABEL = {label: mode for mode, (label, _, _) in SOURCES.items()}
BY_TYPE = {alias: mode for mode, (_, alias, _) in SOURCES.items()} | {mode: mode for mode in SOURCES}
BY_PORT = {port: mode for mode, (_, _, port) in SOURCES.items()}


def capture(raw, instances, fallback):
    metadata = raw.get("_collector") or {}
    explicit = metadata.get("instance_id")
    label = raw.get("sensor")
    subtype = raw.get("instance_type")
    if "instance_id" in metadata and (not isinstance(explicit, str) or explicit not in SOURCES):
        raise ValueError("instancia_invalida")
    declared = BY_LABEL.get(label) if isinstance(label, str) else None
    proposal = explicit or declared
    qualifiers = [
        BY_TYPE.get(subtype) if isinstance(subtype, str) else None,
        BY_PORT.get(str(raw.get("dst_port"))),
        declared,
    ]
    conflict = proposal and any(value and value != proposal for value in qualifiers)
    if conflict:
        state, mode = "conflicto", UNKNOWN
    elif proposal in instances:
        state, mode = "verificada", proposal
    else:
        state, mode = ("sin_registro" if proposal else "insuficiente"), UNKNOWN
    return instances.get(mode, fallback), {
        "estado": state, "modalidad": mode,
        "sensor": SOURCES[mode][0] if mode != UNKNOWN else None,
        "fuentes": [source for source, present in (("identidad_colector", explicit), ("sensor_json", declared)) if present],
    }


def event_mode(event, session, instances):
    """Legacy rows qualify only with a verifiable JSON sensor and consistent metadata."""
    raw = event.c.datos_originales
    options = []
    for mode, (label, alias, port) in SOURCES.items():
        if mode not in instances:
            continue
        storage_compatible = or_(session.c.id_honeypot == instances[mode], session.c.id_honeypot.not_in(instances.values()))
        native = and_(storage_compatible, raw["sensor"].astext == label,
                      or_(raw["instance_type"].astext.not_in(BY_TYPE), raw["instance_type"].astext.is_(None),
                          raw["instance_type"].astext.in_((alias, mode))),
                      or_(raw["dst_port"].astext.not_in(BY_PORT), raw["dst_port"].astext.is_(None),
                          raw["dst_port"].astext == port))
        if "procedencia_cowrie" in event.c:
            stored = event.c.procedencia_cowrie
            native = or_(and_(stored["estado"].astext == "verificada", stored["modalidad"].astext == mode,
                              session.c.id_honeypot == instances[mode]), and_(stored.is_(None), native))
        options.append((native, mode))
    return case(*options, else_=UNKNOWN) if options else literal(UNKNOWN)


def session_mode(session, event, instances):
    value = event_mode(event, session, instances)
    return func.coalesce(select(case((func.min(value) == func.max(value), func.min(value)), else_=UNKNOWN))
                         .where(event.c.id_sesion == session.c.id_sesion).correlate(session).scalar_subquery(), UNKNOWN)


def public_provenance(mode, stored=None):
    if mode in SOURCES:
        return {"modalidad": mode, "sensor": SOURCES[mode][0], "estado": "verificada",
                "fuentes": (stored or {}).get("fuentes", ["sensor_json_historico"])}
    return {"modalidad": UNKNOWN, "sensor": None, "estado": (stored or {}).get("estado", "insuficiente")
            if (stored or {}).get("estado") != "verificada" else "sin_registro"}
