"""Conservative, versioned evidence rules for automatic ATT&CK mappings."""

import base64
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
import re
import shlex
from urllib.parse import urlsplit

from ..intelligence import DOWNLOAD, SHA256, SHELL_TOKEN, download_positions, normalize_ip

VALIDATOR_VERSION = "cowrie_contracts_v2"
AUTO_CLASSIFICATION = "identificada_automaticamente"
SUPPORTED_MODES = frozenset({"cowrie_shell", "desconocido"})
SHELL_ONLY = frozenset({"cowrie_shell"})
ATTEMPT = "intento"
OBSERVED = "resultado_en_honeypot"

@dataclass(frozen=True)
class Command:
    tool: str
    args: tuple[str, ...]
    append_target: str | None = None


@dataclass(frozen=True)
class Telemetry:
    kind: str
    raw: dict
    command: Command | None
    modality: str


@dataclass(frozen=True)
class Signal:
    grade: str = ATTEMPT
    group: tuple[str, str] | None = None
    distinct: str | None = None
    step: str | None = None


@dataclass(frozen=True)
class EvidenceContract:
    tag: str
    recognize: Callable[[Telemetry], Signal | None]
    modes: frozenset[str] = SUPPORTED_MODES
    tactics: frozenset[str] = frozenset()
    minimum_distinct: int = 1
    sequence: tuple[str, ...] = ()
    contradicts: Callable[[Telemetry], bool] | None = None
    limitation: str = "La evidencia respalda un intento; el resultado y el impacto no están confirmados."
    observed_limitation: str = "El sensor registró un resultado. Su alcance fuera del señuelo no está confirmado."
    version: str = "1"

    def groups(self, matches):
        groups = defaultdict(dict)
        for eid, signal in matches.items():
            groups[signal.group][eid] = signal
        return [group for group in groups.values()
                if len({signal.distinct for signal in group.values()}) >= self.minimum_distinct
                and (not self.sequence or self.sequence_witness(group))]

    def sequence_witness(self, matches):
        witness = []
        for eid, signal in matches.items():
            if signal.step == self.sequence[len(witness)]:
                witness.append(eid)
                if len(witness) == len(self.sequence):
                    return tuple(witness)
        return ()

    def sample_ids(self, matches):
        if self.sequence:
            groups = self.groups(matches)
            return self.sequence_witness(groups[0]) if groups else ()
        if self.minimum_distinct == 1:
            grades = {}
            for eid, signal in matches.items():
                grades.setdefault(signal.grade, eid)
            return tuple(grades.values())
        groups = self.groups(matches)
        if not groups:
            return ()
        distinct = {}
        for eid, signal in groups[0].items():
            distinct.setdefault(signal.distinct, eid)
        return tuple(distinct.values())[:self.minimum_distinct]


def http_url(value):
    if not isinstance(value, str) or re.search(r"[\s\x00-\x1f]", value):
        return False
    try:
        url = urlsplit(value)
        return url.scheme in {"http", "https"} and bool(url.hostname) and url.port != 0
    except ValueError:
        return False


def parse_command(command):
    if not isinstance(command, str) or len(command) > 8192 or re.search(r"[`$\\\x00-\x08\x0a-\x1f]", command):
        return None
    end = 0
    tokens = []
    redirects = []
    last_word = None
    for match in SHELL_TOKEN.finditer(command):
        if command[end:match.start()].strip() or match.lastgroup not in {"word", "comment", "redirect"}:
            return None
        end = match.end()
        if match.lastgroup == "comment":
            break
        if match.lastgroup == "redirect":
            redirects.append((len(tokens), match.group()))
        else:
            last_word = match.group()
            tokens.extend(shlex.split(last_word))
    if command[end:].strip() or not tokens or redirects and redirects != [(len(tokens)-1, ">>")]:
        return None
    prefix, separator, name = tokens[0].rpartition("/")
    if separator and prefix not in {"/usr/bin", "/bin", "/usr/sbin", "/sbin"}:
        return None
    if redirects:
        if tokens[-1].startswith("~/") and last_word != tokens[-1]:
            return None
        return Command(name, tuple(tokens[1:-1]), tokens[-1])
    return Command(name, tuple(tokens[1:]))


def inbound_download(tool, args):
    if tool not in {"wget", "curl"}:
        return False
    if tool == 'curl' and any(arg in {'-H','--header'} or arg.startswith('--header=') for arg in args):
        return False
    positions = download_positions(tool, [(arg, 0, False) for arg in args])
    if len(positions) != 1:
        return False
    target = args[next(iter(positions))].removeprefix("--url=")
    if not http_url(target):
        return False
    # curl without a file destination is ambiguous. Ignore options supplied as values.
    file_output = False
    valued = {"-o", "--output", "-O", "--output-document"} if tool == "wget" else {"-o", "--output"}
    other_values = ({"--output-file", "--timeout", "--tries", "--user-agent", "-T", "-t", "-U"}
                    if tool == "wget" else {"--connect-timeout", "-m", "--max-time", "--retry", "--url"})
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        switch, inline, value = arg.partition("=")
        if switch in valued and (not inline or switch.startswith("--")):
            if not inline:
                index += 1
                value = args[index] if index < len(args) else ""
            if not value or value in {"-", "/dev/null", "/dev/stdout", "/dev/stderr"}:
                return False
            file_output = True
        elif arg in other_values:
            index += 1
        elif tool == "curl" and (arg == "--remote-name" or re.fullmatch(r"-[sSfLkOv46]*O[sSfLkOv46]*", arg)):
            file_output = True
        index += 1
    return tool == "wget" or file_output


def from_command(predicate):
    """Recognize an attempt only on a literal, non-redirected Cowrie input."""
    def recognize(observation):
        command = observation.command
        if command and command.append_target is None and predicate(command.tool, command.args):
            return Signal()
        return None
    return recognize


def system_discovery(tool, args):
    return (tool == "uname" and all(re.fullmatch(r"-[asnrvmpio]+", arg) for arg in args)
            or tool == "cat" and args in (("/etc/os-release",), ("/proc/version",), ("/proc/cpuinfo",)))


def file_discovery(tool, args):
    return tool == "ls" and all(
        re.fullmatch(r"-[aAlhRtdF1]+" if arg.startswith("-") else r"[./\w][./\w-]*", arg)
        for arg in args
    )


def network_discovery(tool, args):
    return (tool == "ifconfig" and not args or tool == "ip"
            and args in (("addr", "show"), ("address", "show"), ("route", "show")))


def inbound_transfer(observation):
    command = observation.command
    if command and command.append_target is None and inbound_download(command.tool, command.args):
        return Signal()
    if observation.kind == DOWNLOAD and observation.modality == "cowrie_shell" and http_url(observation.raw.get("url")):
        digest, size = observation.raw.get("shasum"), observation.raw.get("size")
        if (isinstance(digest, str) and SHA256.fullmatch(digest)) or (type(size) is int and size > 0):
            return Signal(OBSERVED)
    return None


def opposite_transfer(observation):
    command = observation.command
    return (observation.kind == "cowrie.session.file_upload"
            or bool(command and command.tool == "curl" and any(
                arg in {"-I", "--head"} or arg.startswith(("-T", "--upload-file"))
                for arg in command.args
            )))


def authentication_guess(observation):
    user, password, address = (observation.raw.get(key) for key in ("username", "password", "src_ip"))
    if observation.kind != "cowrie.login.failed" or not all(isinstance(v, str) and v for v in (user, password, address)):
        return None
    try:
        return Signal(group=(str(normalize_ip(address)), user), distinct=password)
    except ValueError:
        return None


def authorized_key_append(observation):
    command = observation.command
    if not command or command.tool != "echo" or len(command.args) != 1 or not command.append_target:
        return None
    if not re.fullmatch(r"(?:~|/root|/home/[a-z_][a-z0-9_-]*)/\.ssh/authorized_keys", command.append_target):
        return None
    # A literal Ed25519 public-key record. This recognition performs no file operation.
    fields = command.args[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519" or not re.fullmatch(r"[A-Za-z0-9+/]{68}", fields[1]):
        return None
    blob = base64.b64decode(fields[1])
    header = b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
    return Signal() if len(blob) == len(header) + 32 and blob.startswith(header) else None


def service_discovery(tool, args):
    if tool != "nmap" or len(args) != 4 or args[:2] != ("-sV", "-p"):
        return False
    if not re.fullmatch(r"[0-9]{1,5}(?:,[0-9]{1,5})*", args[2]):
        return False
    try:
        address = normalize_ip(args[3])
    except ValueError:
        return False
    return (not (address.is_loopback or address.is_unspecified or address.is_multicast)
            and all(1 <= int(port) <= 65535 for port in args[2].split(",")))


def remote_discovery(tool, args):
    return (tool == "ip" and args == ("neigh", "show")
            or tool == "arp" and args in (("-a",), ("-an",), ("-n",)))


# Registering a policy here requires no change to retrieval, validation or persistence.
CONTRACTS = {
    "T1105": EvidenceContract("transfer", inbound_transfer, contradicts=opposite_transfer,
        observed_limitation="Cowrie registró la descarga. El evento no acredita ejecución del archivo ni compromiso del sistema."),
    "T1110": EvidenceContract("auth_repeated", authentication_guess, minimum_distinct=3),
    "T1082": EvidenceContract("system_discovery", from_command(system_discovery)),
    "T1033": EvidenceContract("user_discovery", from_command(lambda tool, args: tool in {"whoami", "id"} and not args)),
    "T1083": EvidenceContract("file_discovery", from_command(file_discovery)),
    "T1016": EvidenceContract("network_discovery", from_command(network_discovery)),
    "T1057": EvidenceContract("process_discovery", from_command(
        lambda tool, args: tool == "ps" and all(re.fullmatch(r"-?[auxeflA]+", arg) for arg in args))),
    "T1059.004": EvidenceContract("shell", from_command(
        lambda tool, args: tool in {"sh", "bash", "dash", "zsh"} and len(args) == 2 and args[0] == "-c" and bool(args[1].strip()))),
    "T1053.003": EvidenceContract("cron", from_command(
        lambda tool, args: tool == "crontab" and len(args) == 1 and bool(re.fullmatch(r"(?:/|\./)[\w./-]+", args[0]))),
        tactics=frozenset({"TA0003"})),
    "T1136.001": EvidenceContract("account_create", from_command(
        lambda tool, args: tool == "useradd" and len(args) == 1 and bool(re.fullmatch(r"[a-z_][a-z0-9_-]*", args[0])))),
    "T1070.003": EvidenceContract("history", from_command(lambda tool, args: tool == "history" and args == ("-c",))),
    "T1098.004": EvidenceContract("ssh_keys", authorized_key_append, modes=SHELL_ONLY, tactics=frozenset({"TA0003"}),
        limitation="La orden intenta añadir una clave pública. Cowrie no acredita escritura efectiva ni acceso posterior."),
    "T1046": EvidenceContract("network_scan", from_command(service_discovery), modes=SHELL_ONLY,
        limitation="Se observó una orden de identificación de servicios. No hay resultados de escaneo confirmados."),
    "T1018": EvidenceContract("remote_discovery", from_command(remote_discovery), modes=SHELL_ONLY,
        limitation="La orden consulta vecinos o la caché ARP. No acredita que se hayan descubierto otros sistemas."),
}


def contract_signature():
    return [(code, contract.version, contract.tag, sorted(contract.modes), sorted(contract.tactics),
             contract.minimum_distinct, contract.sequence) for code, contract in sorted(CONTRACTS.items())]


def telemetry(event, modality):
    command = parse_command(event.datos_originales.get("input")) if event.tipo_evento == "cowrie.command.input" else None
    return Telemetry(event.tipo_evento, event.datos_originales, command, modality)


def command_technique(command):
    observation = Telemetry("cowrie.command.input", {}, parse_command(command), "cowrie_shell")
    return next((code for code, contract in CONTRACTS.items() if contract.recognize(observation)), None)


def collect_evidence(events, modality):
    """Return local signals, including groups that may lack enough matching events."""
    matches = defaultdict(dict)
    contracts = [(code, contract) for code, contract in CONTRACTS.items() if modality in contract.modes]
    for event in sorted(events,key=lambda item:(item.fecha_hora,item.id_evento)):
        observation = telemetry(event, modality)
        for code, contract in contracts:
            if signal := contract.recognize(observation):
                matches[code][event.id_evento] = signal
    return matches


def technique_evidence(events, modality):
    """Only IDs and grades may leave the server's evidence evaluator."""
    qualified = {}
    for code, matches in collect_evidence(events, modality).items():
        grades = {eid: signal.grade for group in CONTRACTS[code].groups(matches) for eid, signal in group.items()}
        if grades:
            qualified[code] = grades
    return qualified
