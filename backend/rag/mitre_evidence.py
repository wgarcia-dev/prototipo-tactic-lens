"""Conservative, versioned evidence rules for automatic ATT&CK mappings."""

import base64
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
from pathlib import PurePosixPath
import re
import shlex
from urllib.parse import urlsplit

from ..intelligence import DOWNLOAD, SHA256, SHELL_TOKEN, download_positions, normalize_ip
from .mitre_command_rules import COMMAND_RULES, KEY_PATH, PATH

VALIDATOR_VERSION = "cowrie_contracts_v5"
AUTO_CLASSIFICATION = "identificada_automaticamente"
KNOWN_MODES = frozenset({"cowrie_shell", "cowrie_proxy", "cowrie_llm"})
SUPPORTED_MODES = KNOWN_MODES | {"desconocido"}
ATTEMPT = "intento"
OBSERVED = "resultado_en_honeypot"
COMMAND_INPUT = "cowrie.command.input"
SOURCE_LIMITATIONS = {
    "cowrie_shell": "Entrada del cliente o registro del señuelo Shell. Sin atribución de efectos al anfitrión.",
    "cowrie_proxy": "Entrada del cliente en una sesión Proxy. Sin verificación independiente de cambios en el entorno aislado o el anfitrión.",
    "cowrie_llm": "Entrada del cliente o evento estructurado independiente. La respuesta generada no acredita ejecución ni efectos.",
    "desconocido": "La modalidad histórica no está registrada.",
}

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
    session: str | None = None
    timestamp: datetime | None = None


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
    event_types: frozenset[str] = frozenset({COMMAND_INPUT})
    minimum: str = "Una entrada estructurada que cumple el predicado literal del contrato."
    window_seconds: int | None = None

    def groups(self, matches):
        groups = defaultdict(dict)
        for eid, signal in matches.items():
            groups[(signal.session, signal.group)][eid] = signal
        return [group for group in groups.values()
                if len({signal.distinct for signal in group.values()}) >= self.minimum_distinct
                and (not self.sequence or self.sequence_witness(group))]

    def sequence_witness(self, matches):
        # Keep the most recent prefix so an expired first occurrence does not
        # mask a later valid sequence. Iterate backwards to consume each row once.
        prefixes = {0: ()}
        for eid, signal in matches.items():
            if signal.step == "contradiccion":
                prefixes = {0: ()}
                continue
            for length in range(len(self.sequence) - 1, -1, -1):
                if signal.step != self.sequence[length] or length not in prefixes:
                    continue
                prefix = prefixes[length]
                if prefix and self.window_seconds is not None:
                    start = matches[prefix[0]].timestamp
                    if (signal.timestamp - start).total_seconds() > self.window_seconds:
                        continue
                witness = (*prefix, eid)
                if len(witness) == len(self.sequence):
                    return witness
                prefixes[length + 1] = witness
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
            or tool in {"hostname", "uptime"} and not args
            or tool == "cat" and args in (("/etc/os-release",), ("/proc/version",), ("/proc/cpuinfo",)))


def process_discovery(tool, args):
    return (tool == "ps" and all(re.fullmatch(r"-?[auxeflA]+", arg) for arg in args)
            or tool == "top" and args == ("-b", "-n", "1"))


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
        return Signal(group=(str(normalize_ip(address)), user), distinct=sha256(password.encode("utf-8")).hexdigest())
    except ValueError:
        return None


def authentication_spray(observation):
    guess = authentication_guess(observation)
    if guess is None:
        return None
    address, account = guess.group
    return Signal(group=(address, guess.distinct), distinct=account)


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


def ssh_forward_request(observation):
    raw = observation.raw
    if raw.get("protocol") != "ssh" or type(raw.get("dst_port")) is not int or not 1 <= raw["dst_port"] <= 65535:
        return None
    if not isinstance(raw.get("dst_ip"), str):
        return None
    try:
        address = normalize_ip(raw["dst_ip"])
    except ValueError:
        return None
    return Signal() if not (address.is_unspecified or address.is_multicast) else None


def archive_after_read(observation):
    command = observation.command
    if not command or command.append_target is not None:
        return None
    tool, args = command.tool, command.args
    if tool == "cat" and len(args) == 1 and re.fullmatch(r"/etc/shadow|" + KEY_PATH, args[0]):
        return Signal(group=("archive", args[0]), step="lectura")
    if (tool == "tar" and len(args) == 3 and args[0] in {"-cf", "-czf", "-cjf"}
            and re.fullmatch(r"/(?:var/)?tmp/" + PATH.removeprefix(r"(?:/|\./)") + r"\.(?:tar|tgz|tar\.gz|tar\.bz2)", args[1])
            and ".." not in PurePosixPath(args[1]).parts
            and re.fullmatch(r"/etc/shadow|" + KEY_PATH, args[2])):
        return Signal(group=("archive", args[2]), step="archivo")
    return None


def systemd_service_registration(observation):
    command = observation.command
    if not command or command.append_target is not None or command.tool != "systemctl":
        return None
    args = command.args
    if len(args) == 2 and args[0] == "link" and re.fullmatch(PATH + r"\.service", args[1]) and args[1].startswith("/"):
        unit = args[1].rsplit("/", 1)[-1]
        return Signal(group=("systemd", unit), step="enlace")
    if (len(args) == 2 and args[0] == "enable" or len(args) == 3 and args[:2] == ("enable", "--now")) and re.fullmatch(r"[A-Za-z0-9_@-][A-Za-z0-9_.@-]*\.service", args[-1]):
        return Signal(group=("systemd", args[-1]), step="habilitacion")
    if len(args) == 2 and args[0] in {"disable", "mask"}:
        return Signal(group=("systemd", args[1]), step="contradiccion")
    return None


# Registering a policy here requires no change to retrieval, validation or persistence.
CONTRACTS = {
    "T1105": EvidenceContract("transfer", inbound_transfer, contradicts=opposite_transfer,
        version="2",
        event_types=frozenset({COMMAND_INPUT, DOWNLOAD}),
        minimum="Orden de descarga con destino a archivo o descarga HTTP estructurada de Shell con SHA-256 o tamaño positivo.",
        observed_limitation="Cowrie registró la descarga. El evento no acredita ejecución del archivo ni compromiso del sistema."),
    "T1110": EvidenceContract("auth_repeated", authentication_guess, minimum_distinct=3,
        version="2",
        event_types=frozenset({"cowrie.login.failed"}),
        minimum="Tres contraseñas distintas rechazadas para la misma cuenta y origen en la misma sesión."),
    "T1082": EvidenceContract("system_discovery", from_command(system_discovery), version="3",
        minimum="Consulta de información del sistema con uname, hostname o uptime, o lectura de metadatos conocidos."),
    "T1033": EvidenceContract("user_discovery", from_command(lambda tool, args: tool in {"whoami", "id"} and not args),
        version="2", minimum="Invocación de whoami o id sin argumentos para identificar la cuenta actual."),
    "T1083": EvidenceContract("file_discovery", from_command(file_discovery), version="2",
        minimum="Listado con ls, opciones admitidas y operandos de ruta literales."),
    "T1016": EvidenceContract("network_discovery", from_command(network_discovery), version="2",
        minimum="Consulta explícita de configuración de interfaces o rutas locales."),
    "T1057": EvidenceContract("process_discovery", from_command(process_discovery),
        version="3", minimum="Listado de procesos con ps y opciones de consulta admitidas o top en lote de una iteración."),
    "T1059.004": EvidenceContract("shell", from_command(
        lambda tool, args: tool in {"sh", "bash", "dash", "zsh"} and len(args) == 2 and args[0] == "-c" and bool(args[1].strip())),
        version="2", minimum="Invocación explícita de shell Unix con un argumento de código no vacío."),
    "T1053.003": EvidenceContract("cron", from_command(
        lambda tool, args: tool == "crontab" and len(args) == 1 and bool(re.fullmatch(r"(?:/|\./)[\w./-]+", args[0]))),
        tactics=frozenset({"TA0003"}), version="2", minimum="Solicitud de instalar un crontab desde archivo literal."),
    "T1136.001": EvidenceContract("account_create", from_command(
        lambda tool, args: tool == "useradd" and len(args) == 1 and bool(re.fullmatch(r"[a-z_][a-z0-9_-]*", args[0]))),
        version="2", minimum="Solicitud explícita de crear una cuenta local nombrada."),
    "T1070.003": EvidenceContract("history", from_command(lambda tool, args: tool == "history" and args == ("-c",)),
        version="2", minimum="Solicitud explícita de vaciar el historial de comandos."),
    "T1098.004": EvidenceContract("ssh_keys", authorized_key_append, modes=KNOWN_MODES, tactics=frozenset({"TA0003"}),
        version="2", minimum="Escritura por anexado de un registro Ed25519 válido a una ruta estándar authorized_keys.",
        limitation="La orden intenta añadir una clave pública. Cowrie no acredita escritura efectiva ni acceso posterior."),
    "T1046": EvidenceContract("network_scan", from_command(service_discovery), modes=KNOWN_MODES,
        version="2", minimum="Sondeo de servicios con destino IP explícito y puertos válidos.",
        limitation="Se observó una orden de identificación de servicios. No hay resultados de escaneo confirmados."),
    "T1018": EvidenceContract("remote_discovery", from_command(remote_discovery), modes=KNOWN_MODES,
        version="2", minimum="Consulta literal de vecinos o lectura de la caché ARP.",
        limitation="La orden consulta vecinos o la caché ARP. No acredita que se hayan descubierto otros sistemas."),
    "T1110.001": EvidenceContract("password_guessing", authentication_guess, modes=KNOWN_MODES,
        tactics=frozenset({"TA0006"}), minimum_distinct=3, event_types=frozenset({"cowrie.login.failed"}),
        minimum="Tres contraseñas distintas rechazadas para la misma cuenta y origen en la misma sesión.",
        limitation="Patrón de intentos de contraseña; sin confirmación de credenciales válidas ni de compromiso."),
    "T1110.003": EvidenceContract("password_spraying", authentication_spray, modes=KNOWN_MODES,
        tactics=frozenset({"TA0006"}), minimum_distinct=3, event_types=frozenset({"cowrie.login.failed"}),
        minimum="La misma contraseña rechazada para tres cuentas distintas desde el mismo origen y sesión.",
        limitation="Patrón de reutilización de un intento de contraseña entre cuentas del señuelo. No identifica una campaña ni su alcance."),
    "T1572": EvidenceContract("protocol_tunnel_request", ssh_forward_request, modes=KNOWN_MODES,
        tactics=frozenset({"TA0011"}), event_types=frozenset({"cowrie.direct-tcpip.request"}),
        minimum="Petición SSH direct-tcpip estructurada con dirección de destino y puerto válidos.",
        limitation="Se solicitó un reenvío SSH. La solicitud no acredita conexión, tráfico transferido ni canal de C2."),
    "T1560.001": EvidenceContract("archive_after_read", archive_after_read, modes=KNOWN_MODES,
        tactics=frozenset({"TA0009"}), sequence=("lectura", "archivo"), window_seconds=300,
        minimum="Lectura explícita de material sensible seguida de solicitud de archivado del mismo archivo en destino temporal.",
        limitation="La secuencia acredita dos solicitudes relacionadas. No confirma lectura, creación del archivo ni exfiltración."),
    "T1543.002": EvidenceContract("systemd_service_registration", systemd_service_registration, modes=KNOWN_MODES,
        tactics=frozenset({"TA0003"}), sequence=("enlace", "habilitacion"), window_seconds=300,
        minimum="Enlace de un archivo de unidad absoluto seguido de habilitación de la misma unidad en la sesión.",
        limitation="Se solicitó registrar y habilitar una unidad. Su instalación, arranque y privilegios no están acreditados."),
    **{
        code: EvidenceContract(tag, from_command(predicate), modes=KNOWN_MODES,
                               tactics=frozenset({tactic}), minimum=minimum,
                               version="2" if code == "T1069.001" else "1")
        for code, tactic, tag, minimum, predicate in COMMAND_RULES
    },
}


def contract_signature():
    return [(code, contract.version, contract.tag, sorted(contract.modes), sorted(contract.tactics),
             contract.minimum_distinct, contract.sequence, contract.window_seconds, sorted(contract.event_types))
            for code, contract in sorted(CONTRACTS.items())]


def telemetry(event, modality):
    raw = event.datos_originales
    command = parse_command(raw.get("input")) if event.tipo_evento == COMMAND_INPUT and raw.get("realm") is None else None
    return Telemetry(event.tipo_evento, raw, command, modality)


def command_technique(command):
    observation = Telemetry(COMMAND_INPUT, {}, parse_command(command), "cowrie_shell")
    return next((code for code, contract in CONTRACTS.items()
                 if COMMAND_INPUT in contract.event_types and contract.recognize(observation) and not contract.sequence), None)


def collect_evidence(events, modality):
    """Return local signals, including groups that may lack enough matching events."""
    matches = defaultdict(dict)
    contracts = defaultdict(list)
    for code, contract in CONTRACTS.items():
        if modality in contract.modes:
            for kind in contract.event_types:
                contracts[kind].append((code, contract))
    for event in sorted(events,key=lambda item:(item.fecha_hora,item.id_evento)):
        if not contracts[event.tipo_evento]:
            continue
        observation = telemetry(event, modality)
        session = getattr(event, "id_sesion", None) or observation.raw.get("session")
        session = str(session) if session is not None else None
        for code, contract in contracts[event.tipo_evento]:
            if signal := contract.recognize(observation):
                matches[code][event.id_evento] = replace(signal, session=session, timestamp=event.fecha_hora)
    return matches


def technique_evidence(events, modality):
    """Only IDs and grades may leave the server's evidence evaluator."""
    qualified = {}
    for code, matches in collect_evidence(events, modality).items():
        contract = CONTRACTS[code]
        grades = {
            eid: group[eid].grade for group in contract.groups(matches)
            for eid in (contract.sequence_witness(group) if contract.sequence else group)
        }
        if grades:
            qualified[code] = grades
    return qualified
