import json
import pytest
from src.loader import load_events
from src.normalizer import normalize


def test_json_and_jsonl(tmp_path, event):
    path = tmp_path / "events.json"
    for content in (json.dumps([event(), event(2)]), json.dumps(event()) + "\n" + json.dumps(event(2))):
        path.write_text(content, encoding="utf-8-sig")
        assert len(load_events(path)) == 2


@pytest.mark.parametrize("content", ['{}', '[1]', 'broken', '{"x": "SECRET"}'])
def test_invalid_input_does_not_echo_data(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(ValueError) as exc:
        load_events(path)
    assert "SECRET" not in str(exc.value)


def test_order_duplicate_original_and_empty(event):
    a = event(1, seconds=2, numero_secuencia=0, uuid="shared", input=None)
    b = event(2, seconds=1, numero_secuencia=9, uuid="shared")
    events, metrics = normalize([a, b, a])
    assert [e["id_evento"] for e in events] == ["2", "1"]
    assert events[1]["input"] == ""
    assert events[1]["_original"] == a
    assert a["input"] is None
    assert metrics["duplicates"] == 1


def test_conflicting_duplicate(event):
    with pytest.raises(ValueError, match="Conflicting"):
        normalize([event(), event(input="different")])


@pytest.mark.parametrize("fields", [{"id_evento":None}, {"timestamp":"bad"},
    {"timestamp":"2026-01-01T00:00:00"}, {"eventid":None}, {"input":[]}])
def test_invalid_records_are_quarantined(event, fields):
    events, metrics = normalize([event(**fields)])
    assert events == []
    assert len(metrics["rejected"]) == 1


def test_metadata_and_timezone(event):
    original = event(timestamp="2026-11-26T19:00:00-05:00", instance_type="cowrie_llm", dst_port=2222)
    events, _ = normalize([original])
    assert events[0]["timestamp"] == "2026-11-27T00:00:00.000000+00:00"
    assert events[0]["instance_type"] == "llm"


def test_nested_export(event):
    raw = event()
    nested = {k:raw.pop(k) for k in ("input", "eventid", "timestamp")}
    raw["datos_originales"] = nested
    events, _ = normalize([raw])
    assert events[0]["eventid"] == nested["eventid"]
