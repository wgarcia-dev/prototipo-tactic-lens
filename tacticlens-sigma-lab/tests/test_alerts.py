import json
import pytest
from src.alerts import generate_alerts
from src.config import Config
from src.evaluation import classification_metrics
from src.pipeline import analyze
from main import main


def test_threshold_and_dedup(event, rules):
    result = analyze([event(input="ls")], rules)
    assert not result["alerts"]
    detections = result["detections"]
    assert len(generate_alerts(detections * 2, Config("low"))) == 1
    assert not generate_alerts(detections, Config("critical"))


def test_grouping_window(event, rules):
    result = analyze([event(1,input="rm -rf /"),event(2,seconds=1,input="rm -rf /"),
                      event(3,seconds=301,input="rm -rf /")], rules)
    assert len(result["alerts"]) == 2
    assert result["alerts"][0]["event_ids"] == ["1","2"]


def test_no_credentials_in_outputs(event, rules, tmp_path, capsys):
    secret = "DO_NOT_EXPORT_PASSWORD_OR_TOKEN"
    records = [event(input="cat /etc/shadow " + secret, password=secret, message=secret, token=secret)]
    path = tmp_path / "input.json"
    path.write_text(json.dumps(records))
    output = tmp_path / "output"
    assert main(["--input",str(path),"--rules",str(rules),"--output",str(output)]) == 0
    assert secret not in capsys.readouterr().out
    for path in output.glob("*.json"):
        assert secret not in path.read_text()
    assert {p.name for p in output.iterdir()} == {"detections.json", "alerts.json", "metrics.json"}


def test_classification_is_measured(event, rules):
    records = [event(1,input="ls"),event(2,input="echo harmless"),event(3,input="whoami"),event(4,input="custom missed")]
    result = analyze(records, rules, labels={"1":True,"2":False,"3":False,"4":True})
    metrics = result["metrics"]["classification"]
    assert metrics["precision"] == metrics["recall"] == 0.5
    assert metrics["false_positives"] == metrics["false_negatives"] == 1
    assert metrics["true_positives"] == metrics["true_negatives"] == 1
    with pytest.raises(ValueError):
        classification_metrics([], {"1":True}, ["1","2"])


def test_cli_invalid_input_returns_failure(tmp_path, capsys):
    assert main(["--input",str(tmp_path / "missing.json")]) == 1
    assert "failed" in capsys.readouterr().err


def test_injected_risk_policy(event, rules):
    class Scorer:
        def score(self, detection):
            return 80
    result = analyze([event(input="rm -rf /")], rules, scorer=Scorer())
    assert result["detections"][0]["risk_score"] == 80
    assert result["alerts"][0]["risk_score"] == 80
    class InvalidScorer:
        def score(self, detection):
            return 101
    with pytest.raises(ValueError):
        analyze([event(input="rm -rf /")], rules, scorer=InvalidScorer())


def test_offline_labelled_fixture(rules, monkeypatch):
    import socket
    from src.loader import load_events
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access is forbidden")
    monkeypatch.setattr(socket, "socket", forbidden)
    fixtures = rules.parent / "tests/fixtures"
    result = analyze(load_events(fixtures / "synthetic_events.json"), rules,
                     labels=json.loads((fixtures / "synthetic_labels.json").read_text()))
    assert result["metrics"]["classification"] == {
        "unit":"event_with_any_detection", "true_positives":7, "true_negatives":2,
        "false_positives":0, "false_negatives":0, "precision":1.0, "recall":1.0}
    assert result["metrics"]["alerts"] == 6
