"""Bound and minimize terminal evidence before any external transmission."""
import re

COMMAND = "cowrie.command.input"
OUTPUT_FIELDS = {
    "cowrie.command.output": ("output", "stdout", "stderr"),
    "cowrie.llm.response": ("response", "output"),
}
ERRORS = {
    "cowrie.command.failed": "Cowrie registró un fallo de orden.",
    "cowrie.proxy.backend_connect_error": "Cowrie registró un error de conexión con el entorno Proxy.",
}
PROVENANCE = {
    "cowrie_shell": "respuesta_emulada_por_shell",
    "cowrie_proxy": "respuesta_capturada_del_entorno_proxy",
    "cowrie_llm": "respuesta_generada_en_cowrie_llm",
}
SAFE_DIAGNOSTICS = (
    "command not found", "permission denied", "no such file or directory",
    "operation not permitted", "connection refused", "connection timed out",
    "read-only file system", "is a directory", "not a directory",
)
MAX_ITEMS = 20
MAX_BODY = 8192
DIAGNOSTIC_PATTERNS = {phrase:re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])", re.I)
                       for phrase in SAFE_DIAGNOSTICS}


def diagnostic_phrases(bodies):
    return [phrase for phrase, pattern in DIAGNOSTIC_PATTERNS.items()
            if any(pattern.search(body[:MAX_BODY]) for body in bodies)]


def terminal_event(event):
    return event.tipo_evento in OUTPUT_FIELDS or event.tipo_evento in ERRORS


def tty_references(events):
    return [str(event.id_evento) for event in events if event.tipo_evento == "cowrie.log.closed"
            and isinstance(event.datos_originales.get("ttylog"), str) and event.datos_originales["ttylog"].strip()]


def command_index(events):
    index = {}
    for event in events:
        raw = event.datos_originales
        value = raw.get("command_id")
        session = getattr(event, "id_sesion", None)
        if (event.tipo_evento == COMMAND and session is not None and raw.get("realm") is None
                and isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)):
            key = (session, value)
            index[key] = None if key in index else event
    return index


def referenced_command(event, by_id, by_command):
    raw = event.datos_originales
    reference = raw.get("command_event_id")
    if isinstance(reference, str) and re.fullmatch(r"[0-9]{1,19}", reference):
        reference = int(reference)
    session = getattr(event, "id_sesion", None)
    upstream = raw.get("command_id")
    explicit = by_id.get(reference) if type(reference) is int else None
    indexed = by_command.get((session, upstream)) if isinstance(upstream, str) and len(upstream) <= 128 else None
    if "command_event_id" in raw and "command_id" in raw and explicit != indexed:
        return None
    original = explicit if "command_event_id" in raw else indexed
    if (original is not None and session is not None and getattr(original, "id_sesion", None) == session
            and original.tipo_evento == COMMAND and original.datos_originales.get("realm") is None
            and (original.fecha_hora, original.id_evento) < (event.fecha_hora, event.id_evento)):
        return original
    return None


def terminal_context(events, delivered, modality):
    """Return safe records and coverage counts. Raw terminal text never leaves the backend."""
    by_id = {event.id_evento:event for event in events}
    by_command = command_index(events)
    candidates = [event for event in events if terminal_event(event)]
    candidates.sort(key=lambda event:(referenced_command(event, by_id, by_command) is None, event.fecha_hora, event.id_evento))
    records = []
    counters = {"salidas_estructuradas":0, "salidas_con_texto":0, "fallos_registrados":0,
                "salidas_enviadas":0, "salidas_con_extracto":0, "fallos_enviados":0,
                "salidas_reducidas":0, "evidencias_no_enviadas":0}
    for event in candidates:
        kind = event.tipo_evento
        error = ERRORS.get(kind)
        raw = event.datos_originales
        fields = OUTPUT_FIELDS.get(kind, ())
        bodies = [raw[name] for name in fields if isinstance(raw.get(name), str) and raw[name].strip()]
        counters["fallos_registrados" if error else "salidas_estructuradas"] += 1
        counters["salidas_con_texto"] += bool(bodies)
        if event.id_evento not in delivered or len(records) >= MAX_ITEMS:
            counters["evidencias_no_enviadas"] += 1
            continue
        # Closed vocabulary. Emit only the registered diagnostic phrase, omitting
        # arbitrary text, filenames, escape sequences and values around the match.
        findings = diagnostic_phrases(bodies)
        reference = referenced_command(event, by_id, by_command)
        linked = str(reference.id_evento) if reference and reference.id_evento in delivered else None
        source = ("respuesta_generada_en_cowrie_llm" if kind == "cowrie.llm.response" else
                  "fallo_reportado_por_cowrie" if error else PROVENANCE.get(modality, "origen_terminal_no_identificado"))
        counters["fallos_enviados" if error else "salidas_enviadas"] += 1
        counters["salidas_con_extracto"] += bool(findings)
        counters["salidas_reducidas"] += bool(bodies)
        records.append({
            "evento":str(event.id_evento), "fecha":event.fecha_hora.isoformat(), "tipo":kind,
            "modalidad":modality, "procedencia":source, "evento_orden":linked,
            "estado":"fallo_registrado" if error else "salida_contextual", "diagnosticos":findings,
            "resultado_observado":error or ("El registro contiene texto del terminal." if bodies else
                                            "El evento de salida carece de cuerpo textual."),
            "limite_lectura":any(len(body)>MAX_BODY for body in bodies),
            "limitacion":("Se omite el cuerpo libre. Las frases registradas no acreditan ejecución ni efectos."
                          if bodies else "El evento no aporta una transcripción de la operación."),
        })
    return records, counters
