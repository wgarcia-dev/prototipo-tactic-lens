import hashlib
from .config import Config, LEVELS
from .normalizer import canonical, parse_time


def generate_alerts(detections, config=Config()):
    alerts, active, seen = [], {}, set()
    for detection in sorted(detections, key=lambda d: (d["timestamp"], d["detection_id"])):
        if detection["detection_id"] in seen:
            continue
        seen.add(detection["detection_id"])
        if LEVELS.index(detection["severity"]) < LEVELS.index(config.alert_threshold):
            continue
        group = canonical([detection["rule_id"], detection["session_ids"], detection["honeypot_ids"], detection["modalities"]])
        # Missing session/honeypot identity must not join unrelated detections.
        if not detection["session_ids"] or not detection["honeypot_ids"]:
            group += detection["detection_id"]
        prior = active.get(group)
        if prior and (parse_time(detection["timestamp"]) - parse_time(prior["first_seen"])).total_seconds() <= config.grouping_seconds:
            prior["detection_ids"].append(detection["detection_id"])
            prior["event_ids"] = sorted(set(prior["event_ids"]) | set(detection["event_ids"]))
            prior["last_seen"] = detection["timestamp"]
            if detection["risk_score"] is not None:
                prior["risk_score"] = max(prior["risk_score"] or 0, detection["risk_score"])
        else:
            prior = {"alert_id": hashlib.sha256((group + detection["detection_id"]).encode()).hexdigest(),
                     "rule_id": detection["rule_id"], "severity": detection["severity"],
                     "first_seen": detection["timestamp"], "last_seen": detection["timestamp"],
                     "detection_ids": [detection["detection_id"]], "event_ids": list(detection["event_ids"]),
                     "confidence": detection["confidence"], "verified_impact": False, "risk_score": detection["risk_score"]}
            active[group] = prior
            alerts.append(prior)
    return alerts
