"""Bounded SSH transport. Only compiled, approved catalog entries are sent."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import secrets
import time
from uuid import uuid4
from .catalog import PORTS, catalog

PRIVATE_RANGES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate_host(host):
    address = ipaddress.ip_address(host)
    if address.version != 4 or not any(address in network for network in PRIVATE_RANGES):
        raise ValueError("Use a literal RFC1918 IPv4 address of your Cowrie laboratory")
    return str(address)


def now():
    return datetime.now(timezone.utc).isoformat()


def client_for(paramiko, known_hosts):
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client
    except BaseException:
        client.close()
        raise


def connect(client, host, mode, username, password):
    client.connect(validate_host(host), port=PORTS[mode], username=username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=12,
                   banner_timeout=12, channel_timeout=12)


def execute_step(channel, command, timeout, max_bytes=131072):
    token = "TL_DONE_" + uuid4().hex
    # A terminal echo of this command cannot match the complete result line.
    wire = command + f"; printf '\\n%s:%s\\n' '{token}' \"$?\""
    channel.settimeout(min(timeout, 10))
    channel.sendall((wire + "\n").encode())
    deadline, output = time.monotonic() + timeout, bytearray()
    pattern = re.compile(rb"(?:^|\n)" + token.encode() + rb":([0-9]{1,3})\r?\n")
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(8192)
            if not chunk:
                raise EOFError("Channel ended before acknowledgement")
            output.extend(chunk)
            if len(output) > max_bytes:
                raise ValueError("Response exceeds byte limit")
            match = pattern.search(output)
            if match:
                return {"reported_exit_code": int(match.group(1)), "bytes_received": len(output),
                        "response_sha256": hashlib.sha256(output).hexdigest(),
                        "wire_command": wire}
        elif channel.closed:
            raise EOFError("Channel closed before acknowledgement")
        else:
            time.sleep(0.05)
    raise TimeoutError("No complete acknowledgement before deadline")


def run_case(paramiko, plan, host, username, password, known_hosts, pause=1.0):
    mode, marker, case = plan["modalidad"], plan["marcador"], plan["case"]
    # Defense in depth: never trust a modified plan or replay command for live SSH.
    approved = next((c for c in catalog(marker) if c.id == case.id), None)
    if approved != case or case.transport not in {"ssh", "auth"}:
        raise ValueError("Scenario is not approved for live SSH")
    if pause < 1:
        raise ValueError("Minimum interval is one second")
    validate_host(host)
    result = {"marcador": marker, "modalidad": mode, "escenario": case.id,
              "objetivo": case.objective, "inicio_utc": now(), "destino": host,
              "puerto": PORTS[mode], "codigo_ssh": 1, "error": None,
              "comandos": [s.command for s in case.steps], "steps": [], "attempts": [],
              "estado": "incomplete", "impacto_verificado": False,
              "verificacion": "Pendiente de contrastar con eventos Cowrie; respuestas no prueban impacto"}
    try:
        if case.transport == "auth":
            result["usuario_prueba"] = marker
            for attempt in range(5):
                client = client_for(paramiko, known_hosts)
                try:
                    connect(client, host, mode, marker, secrets.token_urlsafe(32))
                    result["attempts"].append({"at": now(), "outcome": "unexpected_acceptance"})
                    result["estado"] = "inconclusive_auth_accepted"
                    break
                except paramiko.AuthenticationException:
                    result["attempts"].append({"at": now(), "outcome": "rejected"})
                finally:
                    client.close()
                if attempt < 4:
                    time.sleep(pause)
            else:
                result.update(estado="five_auth_rejections_observed", codigo_ssh=0)
        else:
            client = client_for(paramiko, known_hosts)
            try:
                connect(client, host, mode, username, password)
                channel = client.invoke_shell(width=240, height=40)
                commands = [("marker", f"echo INICIO_{marker}")]
                commands += [(s.phase, s.command) for s in case.steps]
                commands += [("marker", f"echo FIN_{marker}")]
                for phase, command in commands:
                    evidence = execute_step(channel, command, 35 if mode == "llm" else 12)
                    result["steps"].append({"phase": phase, "command": command, "at": now(), **evidence})
                    if evidence["reported_exit_code"] != 0:
                        result["estado"] = "reported_command_failure"
                        break
                    time.sleep(pause)
                else:
                    result.update(estado="commands_acknowledged", codigo_ssh=0)
            finally:
                client.close()
    except Exception as exc:
        # Do not persist SSH responses, passwords or exception payloads.
        result["error"] = type(exc).__name__
    finally:
        result["fin_utc"] = now()
    return result
