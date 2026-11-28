from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5


def rule_id(name):
    return str(uuid5(NAMESPACE_URL, "tacticlens-sigma-lab/" + name))


def build_replay(plans):
    """Produce labelled synthetic observations, never shell execution."""
    events, labels, expectations = [], {}, []
    epoch = datetime(2026, 11, 27, tzinfo=timezone.utc)
    for case_number, plan in enumerate(plans):
        marker, mode, case = plan["marcador"], plan["modalidad"], plan["case"]
        def add(seconds, eventid, attack, expected=(), **fields):
            identity = f"synthetic:{marker}:{len(events)}"
            row = {"id_evento": identity, "id_sesion": "synthetic-session:" + marker,
                   "id_honeypot": "synthetic-honeypot:" + mode, "instance_type": mode,
                   "timestamp": (epoch + timedelta(seconds=case_number * 600 + seconds)).isoformat(),
                   "eventid": eventid, "src_ip": "192.0.2.10", "protocol": "ssh", **fields}
            events.append(row)
            labels[identity] = attack
            expectations.append({"id_evento": identity, "marker": marker, "scenario": case.id,
                                 "attack_intent": attack, "expected_rule_ids": [rule_id(n) for n in expected]})
        if case.transport == "auth":
            for i in range(5):
                add(i, "cowrie.login.failed", True, username=marker)
        else:
            # A successful root login is detectable but alone is not malicious.
            add(0, "cowrie.login.success", False, ("root_login",), username="root")
            for i, step in enumerate(case.steps, 1):
                add(i, "cowrie.command.input", step.attack, step.expected_rules, input=step.command)
    return events, labels, expectations


def compare_expectations(detections, expectations, plans):
    """Compare rule matches separately from attack-intent classification."""
    actual = {e["id_evento"]: set() for e in expectations}
    actual_correlations = {}
    for detection in detections:
        if detection["kind"] == "event":
            for identity in detection["event_ids"]:
                actual[identity].add(detection["rule_id"])
        else:
            for session in detection["session_ids"]:
                actual_correlations.setdefault(session, set()).add(detection["rule_id"])
    differences = []
    for item in expectations:
        expected, found = set(item["expected_rule_ids"]), actual[item["id_evento"]]
        if expected != found:
            differences.append({"id_evento": item["id_evento"], "missing": sorted(expected - found),
                                "unexpected": sorted(found - expected)})
    correlation_differences = []
    for plan in plans:
        case, marker = plan["case"], plan["marcador"]
        expected = {rule_id(n) for n in case.expected_correlations}
        if case.transport == "auth":
            expected.add(rule_id("ssh_bruteforce"))
        found = actual_correlations.get("synthetic-session:" + marker, set())
        if expected != found:
            correlation_differences.append({"marker": marker, "missing": sorted(expected - found),
                                            "unexpected": sorted(found - expected)})
    return {"event_rule_differences": differences, "correlation_differences": correlation_differences,
            "matched_expectations": not differences and not correlation_differences}
