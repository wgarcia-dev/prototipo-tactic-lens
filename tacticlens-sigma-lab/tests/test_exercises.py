from dataclasses import replace
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest
from exercises.catalog import catalog, select_cases
from exercises.replay import build_replay, compare_expectations
from exercises.ssh_runner import execute_step, run_case, validate_host
from run_exercises import create_plans, main
from src.pipeline import analyze

MARKER = "TL-" + "a" * 20


@pytest.mark.parametrize("host", ["127.0.0.1", "8.8.8.8", "169.254.1.1", "192.0.2.1", "::1", "lab.example", "100.64.0.1"])
def test_reject_non_lab_addresses(host):
    with pytest.raises(ValueError):
        validate_host(host)


@pytest.mark.parametrize("host", ["192.168.56.101", "10.0.0.2", "172.16.0.2"])
def test_accept_rfc1918(host):
    assert validate_host(host) == host


def test_distinct_markers_across_modes_and_cases():
    plans = create_plans(["shell", "proxy", "llm"], "critico", [])
    assert len(plans) == 30
    assert len({p["marcador"] for p in plans}) == 30
    assert {p["puerto"] for p in plans} == {2222, 2223, 2224}


def test_catalog_restricts_severity_and_marker():
    with pytest.raises(ValueError):
        select_cases(MARKER, "bajo", ["destruccion"])
    with pytest.raises(ValueError):
        select_cases(MARKER, "critico", ["typo"])
    with pytest.raises(ValueError):
        catalog("TL-;touch /tmp/injected")


def test_dangerous_commands_only_exist_in_replay():
    for case in catalog(MARKER):
        if case.transport == "ssh":
            assert not any(re.match(r"(sudo|su |rm |ufw |systemctl |wget |curl )", s.command) for s in case.steps)
            for step in case.steps:
                if ">" in step.command:
                    assert f"/tmp/{MARKER}/" in step.command


def test_full_replay_expected_rules_and_intent_false_positives(rules):
    plans = create_plans(["shell", "proxy", "llm"], "critico", [])
    events, labels, expected = build_replay(plans)
    result = analyze(events, rules, labels=labels)
    comparison = compare_expectations(result["detections"], expected, plans)
    assert comparison["matched_expectations"], comparison
    assert result["metrics"]["classification"]["false_positives"] > 0
    assert result["metrics"]["classification"]["false_negatives"] == 0
    assert {m for d in result["detections"] for m in d["modalities"]} == {"shell", "proxy", "llm"}
    assert len([d for d in result["detections"] if d["kind"] == "correlation"]) >= 6


class Channel:
    closed = False

    def __init__(self, behavior="success", status=0):
        self.behavior, self.status, self.parts, self.sent = behavior, status, [], []

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)
        token = re.search(rb"TL_DONE_[0-9a-f]+", data).group()
        if self.behavior == "success":
            self.parts = [data, b"\r\n" + token + f":{self.status}\r\n".encode()]
        elif self.behavior == "echo":
            self.parts = [data]
        elif self.behavior == "split":
            self.parts = [b"\n" + token + b":1", b"27\n"]
        elif self.behavior == "flood":
            self.parts = [b"x" * 256]

    def recv_ready(self):
        return bool(self.parts)

    def recv(self, size):
        return self.parts.pop(0)


def test_terminal_echo_is_not_completion():
    channel = Channel("echo")
    with pytest.raises(TimeoutError):
        execute_step(channel, "echo SAFE", 0.01)


def test_fragmented_exit_code_waits_for_newline():
    assert execute_step(Channel("split"), "echo SAFE", 1)["reported_exit_code"] == 127


def test_output_bound_and_no_raw_response():
    with pytest.raises(ValueError):
        execute_step(Channel("flood"), "echo SAFE", 1, max_bytes=100)
    result = execute_step(Channel(), "echo SAFE", 1)
    assert result["reported_exit_code"] == 0
    assert "response" not in result
    assert len(result["response_sha256"]) == 64


def fake_paramiko(channel=None, reject_auth=False):
    class AuthenticationException(Exception):
        pass
    class Client:
        instances = []
        def __init__(self):
            self.closed, self.kwargs = False, None
            self.instances.append(self)
        def load_host_keys(self, path):
            self.host_keys = path
        def set_missing_host_key_policy(self, policy):
            self.policy = policy
        def connect(self, *args, **kwargs):
            self.kwargs = kwargs
            if reject_auth:
                raise AuthenticationException("DO_NOT_EXPORT")
        def invoke_shell(self, **kwargs):
            return channel
        def close(self):
            self.closed = True
    return SimpleNamespace(SSHClient=Client, RejectPolicy=lambda: "reject", AuthenticationException=AuthenticationException)


def test_ssh_only_approved_catalog_and_stops_after_failure(monkeypatch):
    monkeypatch.setattr("exercises.ssh_runner.time.sleep", lambda _: None)
    plan = create_plans(["proxy"], "alto", ["cadena_controlada"])[0]
    channel = Channel(status=1)
    paramiko = fake_paramiko(channel)
    result = run_case(paramiko, plan, "192.168.56.101", "root", "SECRET", Path("known_hosts"))
    assert result["estado"] == "reported_command_failure"
    assert len(channel.sent) == 1
    assert paramiko.SSHClient.instances[0].closed
    assert "SECRET" not in json.dumps(result)
    assert paramiko.SSHClient.instances[0].policy == "reject"
    assert paramiko.SSHClient.instances[0].kwargs["allow_agent"] is False
    plan["case"] = replace(plan["case"], steps=())
    with pytest.raises(ValueError):
        run_case(paramiko, plan, "192.168.56.101", "root", "SECRET", Path("known_hosts"))


def test_replay_case_cannot_be_sent_to_ssh():
    plan = create_plans(["proxy"], "critico", ["destruccion"])[0]
    with pytest.raises(ValueError):
        run_case(None, plan, "192.168.56.101", "root", "SECRET", Path("known_hosts"))


def test_successful_transport_records_each_step_without_claiming_impact(monkeypatch):
    monkeypatch.setattr("exercises.ssh_runner.time.sleep", lambda _: None)
    plan = create_plans(["llm"], "bajo", ["reconocimiento"])[0]
    channel = Channel()
    paramiko = fake_paramiko(channel)
    result = run_case(paramiko, plan, "192.168.56.101", "root", "SECRET", Path("known_hosts"))
    assert result["codigo_ssh"] == 0
    assert result["estado"] == "commands_acknowledged"
    assert len(result["steps"]) == len(plan["case"].steps) + 2
    assert result["impacto_verificado"] is False
    assert paramiko.SSHClient.instances[0].closed


def test_existing_fixture_directory_stops_before_any_file_write(monkeypatch):
    monkeypatch.setattr("exercises.ssh_runner.time.sleep", lambda _: None)
    plan = create_plans(["proxy"], "alto", ["cadena_controlada"])[0]
    class ExistingDirectory(Channel):
        def sendall(self, data):
            self.status = 1 if b"mkdir -m 700" in data else 0
            super().sendall(data)
    channel = ExistingDirectory()
    result = run_case(fake_paramiko(channel), plan, "192.168.56.101", "root", "SECRET", Path("known_hosts"))
    assert result["codigo_ssh"] != 0
    assert len(channel.sent) == 2
    assert all(b">" not in wire for wire in channel.sent)


def test_exactly_five_auth_rejections_and_no_guesses_saved(monkeypatch):
    monkeypatch.setattr("exercises.ssh_runner.time.sleep", lambda _: None)
    plan = create_plans(["shell"], "alto", ["fuerza_bruta"])[0]
    paramiko = fake_paramiko(reject_auth=True)
    result = run_case(paramiko, plan, "192.168.56.101", "root", None, Path("known_hosts"))
    assert result["codigo_ssh"] == 0
    assert len(result["attempts"]) == 5
    assert all(c.closed for c in paramiko.SSHClient.instances)
    for client in paramiko.SSHClient.instances:
        assert client.kwargs["password"] not in json.dumps(result)
        assert client.kwargs["username"] == plan["marcador"]


def test_unexpected_auth_acceptance_stops_immediately():
    plan = create_plans(["llm"], "alto", ["fuerza_bruta"])[0]
    paramiko = fake_paramiko()
    result = run_case(paramiko, plan, "192.168.56.101", "root", None, Path("known_hosts"))
    assert result["estado"] == "inconclusive_auth_accepted"
    assert result["codigo_ssh"] != 0
    assert len(paramiko.SSHClient.instances) == 1


def test_plan_and_replay_do_not_open_network(tmp_path, monkeypatch):
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError("Network is forbidden")
    monkeypatch.setattr(socket, "socket", forbidden)
    assert main(["--output", str(tmp_path), "--nivel", "critico"]) == 0
    assert main(["--output", str(tmp_path), "--modo", "replay", "--nivel", "critico"]) == 0
    reports = list(tmp_path.glob("TL-*/comparison.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text())["matched_expectations"]


def test_live_replay_rejected_before_password_or_connection(tmp_path, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda _: pytest.fail("Must not prompt"))
    assert main(["--modo", "ssh", "--nivel", "critico", "--escenarios", "destruccion", "--output", str(tmp_path)]) == 1
    assert not list(tmp_path.iterdir())
