from .correlator import related_ids
from .database import EventStore
from .normalizer import canonical
import hashlib


def detect(store: EventStore, compiled, events):
    indexed = {e["id_evento"]: e for e in events}
    detections = {}
    for rule in compiled:
        for query in rule["rule"]:
            for result in store.query(query):
                ids = related_ids(result) if rule["result_type"] == "correlation" else [str(result["id_evento"])]
                evidence = sorted((indexed[i] for i in set(ids)), key=lambda e: (e["timestamp"], e["id_evento"]))
                if not evidence:
                    continue
                key = hashlib.sha256(canonical([rule["id"], sorted(ids)]).encode()).hexdigest()
                def unique(field):
                    return sorted({e[field] for e in evidence if e.get(field) is not None})
                detections[key] = {
                    "detection_id": key, "rule_id": rule["id"], "title": rule["title"],
                    "severity": rule["level"], "event_ids": [e["id_evento"] for e in evidence],
                    "session_ids": unique("id_sesion"), "honeypot_ids": unique("id_honeypot"),
                    "modalities": unique("instance_type"), "timestamp": evidence[-1]["timestamp"],
                    "kind": rule["result_type"], "confidence": "heuristic",
                    "verified_impact": False, "risk_score": None,
                    "mitre": [t for t in rule["tags"] if t.startswith("attack.t")],
                    # Do not export commands, messages, credentials or raw records.
                    "evidence": [{"id_evento": e["id_evento"], "eventid": e["eventid"],
                                  "timestamp": e["timestamp"], "original_sha256": e["_fingerprint"]}
                                 for e in evidence],
                }
                if rule["result_type"] == "correlation":
                    detections[key]["correlation"] = {k: result[k] for k in ("window_start", "window_end", "metric_name", "metric_value")}
    return sorted(detections.values(), key=lambda d: (d["timestamp"], d["rule_id"], d["detection_id"]))
