from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json

MODES = {"shell": "shell", "proxy": "proxy", "llm": "llm",
         "cowrie_shell": "shell", "cowrie_proxy": "proxy", "cowrie_llm": "llm"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def parse_time(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Timestamp requires timezone")
    return dt.astimezone(timezone.utc)


def normalize(records):
    events, seen, duplicates, rejected = [], {}, 0, []
    for index, original in enumerate(records):
        raw = deepcopy(original)
        nested = raw.get("datos_originales", {})
        if isinstance(nested, str):
            try:
                nested = json.loads(nested)
            except json.JSONDecodeError:
                nested = None
        if not isinstance(nested, dict):
            rejected.append({"index": index, "reason": "invalid datos_originales"})
            continue
        row = {**nested, **{k: v for k, v in raw.items() if k != "datos_originales"}}
        try:
            identity = row.get("id_evento")
            if isinstance(identity, bool) or not isinstance(identity, (str, int)) or not str(identity).strip():
                raise ValueError("missing id_evento")
            timestamp = parse_time(row.get("timestamp"))
            if not isinstance(row.get("eventid"), str) or not row["eventid"]:
                raise ValueError("missing eventid")
            for key in ("id_sesion", "id_honeypot", "src_ip", "instance_type", "input"):
                if row.get(key) is not None and not isinstance(row[key], (str, int)):
                    raise ValueError("invalid scalar field")
        except (ValueError, TypeError, OverflowError):
            rejected.append({"index": index, "reason": "invalid identity, timestamp or field type"})
            continue
        identity = str(identity)
        fingerprint = hashlib.sha256(canonical(original).encode()).hexdigest()
        if identity in seen:
            if seen[identity] != fingerprint:
                raise ValueError(f"Conflicting duplicate at record {index}")
            duplicates += 1
            continue
        seen[identity] = fingerprint
        row.update(id_evento=identity, timestamp=timestamp.isoformat(timespec="microseconds"),
                   instance_type=MODES.get(str(row.get("instance_type", "")).lower(), "unknown"),
                   input=str(row.get("input") or "").strip())
        for key in ("id_sesion", "id_honeypot"):
            row[key] = str(row[key]) if row.get(key) is not None else None
        # Derived security fields cannot be asserted by an untrusted input record.
        row["verified_malware"] = False
        row["_original"] = raw
        row["_fingerprint"] = fingerprint
        events.append(row)
    events.sort(key=lambda e: (e["timestamp"], e["id_evento"]))
    keys = [set(e["_original"]) for e in events]
    by_mode = {}
    for mode in sorted({e["instance_type"] for e in events}):
        subset = [set(e["_original"]) for e in events if e["instance_type"] == mode]
        by_mode[mode] = sorted(set.union(*subset))
    uuids = Counter(e.get("uuid") for e in events if e.get("uuid") is not None)
    sequence_decreases, last_sequence = 0, {}
    for event in events:
        group = (event.get("id_sesion"), event.get("id_honeypot"), event["instance_type"])
        sequence = event.get("numero_secuencia")
        if isinstance(sequence, int):
            if group in last_sequence and sequence < last_sequence[group]:
                sequence_decreases += 1
            last_sequence[group] = sequence
    return events, {
        "input_records": len(records), "processed_events": len(events),
        "duplicates": duplicates, "rejected": rejected,
        "events_by_mode": dict(Counter(e["instance_type"] for e in events)),
        "event_types": dict(Counter(e["eventid"] for e in events)),
        "common_fields": sorted(set.intersection(*keys)) if keys else [],
        "optional_fields": sorted(set.union(*keys) - set.intersection(*keys)) if keys else [],
        "fields_by_mode": by_mode,
        "empty_commands": sum(e["eventid"] == "cowrie.command.input" and not e["input"] for e in events),
        "distinct_uuids": len(uuids), "repeated_uuid_values": sum(n > 1 for n in uuids.values()),
        "sequence_decreases_in_chronological_order": sequence_decreases,
        "correlation_missing_context_events": sum(any(e.get(k) is None for k in ("src_ip", "id_sesion", "id_honeypot")) for e in events),
    }
