from src.pipeline import analyze


def correlations(result):
    return [d for d in result["detections"] if d["kind"] == "correlation"]


def test_bruteforce_threshold_and_window(event, rules):
    rows = [event(i, seconds=i, eventid="cowrie.login.failed") for i in range(5)]
    assert not correlations(analyze(rows[:4], rules))
    detected = correlations(analyze(rows, rules))
    assert len(detected) == 1
    assert set(detected[0]["event_ids"]) == {"0","1","2","3","4"}
    rows[-1] = event(4, seconds=301, eventid="cowrie.login.failed")
    assert not correlations(analyze(rows, rules))


def test_inclusive_boundary(event, rules):
    rows = [event(i, seconds=0, eventid="cowrie.login.failed") for i in range(4)]
    rows.append(event(4, seconds=300, eventid="cowrie.login.failed"))
    assert len(correlations(analyze(rows, rules))) == 1


def test_instances_and_ips_are_separate(event, rules):
    for key in ("instance_type", "id_honeypot", "src_ip"):
        rows = [event(i,eventid="cowrie.login.failed") for i in range(5)]
        rows[-1][key] = "proxy" if key == "instance_type" else "different"
        assert not correlations(analyze(rows, rules))


def test_missing_group_does_not_correlate(event, rules):
    rows = [event(i,eventid="cowrie.login.failed", id_honeypot=None) for i in range(5)]
    assert not correlations(analyze(rows, rules))


def test_burst_alert_grouping_and_duplicates(event, rules):
    rows = [event(i,seconds=i,eventid="cowrie.login.failed") for i in range(6)]
    result = analyze(rows + rows, rules)
    assert len(correlations(result)) == 2
    assert len(result["alerts"]) == 1
    assert len(result["alerts"][0]["event_ids"]) == 6


def test_ordered_session_correlation(event, rules):
    login = event(1,eventid="cowrie.login.success",username="root")
    access = event(2,seconds=1,input="cat /etc/shadow")
    assert len(correlations(analyze([access, login], rules))) == 1
    for changes in ({"id_sesion":"other"},{"id_honeypot":"other"},{"instance_type":"llm"},
                    {"timestamp":login["timestamp"]}):
        assert not correlations(analyze([login, {**access, **changes}], rules))
    login["timestamp"], access["timestamp"] = access["timestamp"], login["timestamp"]
    assert not correlations(analyze([login, access], rules))
