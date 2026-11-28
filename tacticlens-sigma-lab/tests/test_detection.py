from collections import Counter
import json
import os
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5
import pytest
import yaml
from src.pipeline import analyze
from src.loader import load_events
from src.rule_loader import compile_rules, RuleError


def rid(name):
    return str(uuid5(NAMESPACE_URL, "tacticlens-sigma-lab/" + name))


def test_real_corpus(rules):
    default = rules.parent / "data/cowrie_events.json"
    path = Path(os.environ.get("COWRIE_REAL_EVENTS", str(default)))
    if not path.exists():
        pytest.skip("Private real corpus absent; set COWRIE_REAL_EVENTS")
    result = analyze(load_events(path), rules)
    metrics = result["metrics"]
    assert metrics["processed_events"] == 50
    assert metrics["events_by_mode"] == {"shell":17, "proxy":15, "llm":18}
    assert len(metrics["event_types"]) == 12
    assert len(metrics["common_fields"]) == 16
    assert metrics["detections"] == 10
    assert metrics["detections_by_mode"] == {"shell":4, "proxy":2, "llm":4}
    assert metrics["detections_by_rule"] == {rid("root_login"):3, rid("basic_discovery"):4,
                                            rid("prompt_injection"):2, rid("unknown_command"):1}
    assert result["alerts"] == []
    assert metrics["rejected"] == []


@pytest.mark.parametrize("mode", ["shell", "proxy", "llm"])
@pytest.mark.parametrize("command,name", [
    ("cat /etc/shadow", "sensitive_files"), ("curl https://example.invalid/file", "file_transfer"),
    ("sudo id", "privilege_escalation"), ("echo key >> ~/.ssh/authorized_keys", "persistence"),
    ("iptables -F", "disable_security"), ("rm -rf /", "destructive_command"),
    ("crontab -e", "cron_persistence"), ("cat /root/.ssh/id_rsa", "private_key"),
    ("systemctl stop auditd", "stop_controls")])
def test_severe_synthetic_commands(event, rules, mode, command, name):
    result = analyze([event(input=command, instance_type=mode)], rules)
    assert rid(name) in {d["rule_id"] for d in result["detections"]}
    assert result["alerts"]
    assert all(d["verified_impact"] is False for d in result["detections"])


@pytest.mark.parametrize("command", ["", "echo safe", "lswhatever", "curling", "cat /tmp/missing", "echo whoami"])
def test_negative_commands(event, rules, command):
    assert not analyze([event(input=command)], rules)["detections"]


def test_verified_hash_never_terminal_log(event, rules):
    catalog = [{"sha256":"a"*64, "verified":True, "source":"synthetic-test-only",
                "reference":"fixture://not-real-malware", "verified_at":"2026-11-27T00:00:00Z"}]
    records = [event(1,eventid="cowrie.log.closed",shasum="a"*64),
               event(2,eventid="cowrie.session.file_download",shasum="a"*64),
               event(3,eventid="cowrie.session.file_upload",shasum="b"*64,verified_malware=True)]
    result = analyze(records, rules, catalog=catalog)
    assert [d["event_ids"] for d in result["detections"]] == [["2"]]
    assert not analyze(records, rules)["detections"]


def test_invalid_intelligence(event, rules):
    with pytest.raises(ValueError):
        analyze([event()], rules, catalog=[{"sha256":"a"*64,"verified":True}])


def test_new_rule_missing_optional_column(event, rules, tmp_path):
    sample = yaml.safe_load((rules / "authentication/root_login.yml").read_text())
    sample["detection"] = {"selection":{"missing_field|contains":"value"}, "condition":"selection"}
    (tmp_path / "new.yaml").write_text(yaml.safe_dump(sample))
    assert not analyze([event()], tmp_path)["detections"]
    assert len(analyze([event(missing_field="a value")], tmp_path)["detections"]) == 1


def test_invalid_rules_fail_explicitly(tmp_path):
    (tmp_path / "bad.yml").write_text("title: invalid\ndetection: []")
    with pytest.raises(RuleError):
        compile_rules(tmp_path)


def test_no_events(rules):
    result = analyze([], rules)
    assert result["detections"] == result["alerts"] == []
