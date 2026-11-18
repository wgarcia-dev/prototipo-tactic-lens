"""Deterministic observables from Cowrie fields and shell input."""
import ipaddress
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

import idna
from sqlalchemy import func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert


DOWNLOAD = "cowrie.session.file_download"
FAILED_DOWNLOAD = "cowrie.session.file_download.failed"
UPLOAD = "cowrie.session.file_upload"
URL_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*://", re.I | re.ASCII)
URL_SCHEMES = {"http", "https", "ftp", "tftp"}
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
SHA256 = re.compile(r"[0-9a-f]{64}", re.I | re.ASCII)
DOC_IPS = tuple(map(ipaddress.ip_network, (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20",
)))
DOC_NAMES = ("example.com", "example.org", "example.net", "example", "test", "invalid", "localhost", "localdomain")
LOCAL_IPS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
# Keep token boundaries and positions without executing or expanding shell input.
SHELL_TOKEN = re.compile(r"""(?P<comment>\#[^\n]*)|(?P<separator>[;&|]+|[()\n])|(?P<redirect>[<>]+)|(?P<word>(?:'[^']*'|"[^"\\]*(?:\\.[^"\\]*)*"|\\.|[^\s;&|()<>\\'"])+)""")
HOST_COMMANDS = {"ping", "ping6", "host", "nslookup", "dig", "traceroute", "tracepath", "ssh", "telnet", "nc", "netcat"}
HOST_OPTION_VALUES = {
    "ping": {"-c", "-i", "-s", "-W", "-w", "-I", "-t"},
    "ping6": {"-c", "-i", "-s", "-W", "-w", "-I", "-t"},
    "ssh": {"-p", "-l", "-i", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-W"},
    "nc": {"-p", "-s", "-w", "-q"}, "netcat": {"-p", "-s", "-w", "-q"},
    "dig": {"-p", "-b", "-c", "-f", "-k", "-q", "-t"}, "host": {"-c", "-N", "-R", "-t", "-W"},
    "traceroute": {"-m", "-p", "-q", "-s", "-w"},
}
DOWNLOAD_FLAGS = {
    "curl": ({"--silent", "--show-error", "--fail", "--location", "--insecure", "--remote-name",
              "--verbose", "--ipv4", "--ipv6"}, "sSfLkOv46",
             {"--output", "--connect-timeout", "--max-time", "--retry", "--header"}, {"-o", "-H", "-m"}),
    "wget": ({"--quiet", "--no-verbose", "--no-check-certificate", "--continue", "--background",
              "--inet4-only", "--inet6-only"}, "qvcb46",
             {"--output-document", "--output-file", "--timeout", "--tries", "--user-agent"}, {"-O", "-o", "-T", "-t", "-U"}),
}


@dataclass(frozen=True)
class Observable:
    tipo: str
    valor: str
    valor_original: str
    campo: str
    metodo: str
    comportamiento: str
    grado_evidencia: str
    limitacion: str
    alcance_ip: str | None = None
    algoritmo: str | None = None
    posicion: int | None = None

    def detalle(self):
        fields = asdict(self)
        del fields["tipo"], fields["valor"]
        return fields


def normalize_ip(value):
    if "%" in value:
        raise ValueError("IPv6 con identificador de zona")
    return ipaddress.ip_address(value)


def ip_scope(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return "no_especificada"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "enlace_local"
    if address.is_multicast:
        return "multicast"
    if any(address in network for network in DOC_IPS):
        return "documentacion"
    if any(address in network for network in LOCAL_IPS):
        return "privada"
    if address.is_reserved:
        return "reservada"
    return "global" if address.is_global else "no_enrutable"


def normalize_domain(value):
    name = idna.encode(value, uts46=True, std3_rules=True, transitional=False).decode("ascii").removesuffix(".")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(map(DOMAIN_LABEL.fullmatch, labels)):
        raise ValueError("Nombre DNS incompleto o inválido")
    if not re.fullmatch(r"(?:[a-z]{2,63}|xn--[a-z0-9-]+)", labels[-1]):
        raise ValueError("Sufijo DNS inválido")
    return name


def documentation_domain(domain):
    return any(domain == name or domain.endswith("." + name) for name in DOC_NAMES)


def normalize_url(value):
    # urlsplit alone silently strips control characters and accepts malformed hosts.
    if (len(value) > 2048 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            or re.search(r"[\\<>\"`{}^]", value) or re.search(r"%(?![0-9a-fA-F]{2})", value)):
        raise ValueError("URL inválida")
    scheme_match = URL_SCHEME.match(value)
    parts = urlsplit(value)
    if not scheme_match or parts.scheme not in URL_SCHEMES or not parts.hostname or parts.username is not None:
        raise ValueError("Esquema o autoridad URL no admitidos")
    authority = re.fullmatch(r"(\[[^\[\]]+\]|[^:\[\]]+)(:[0-9]+)?", parts.netloc)
    if not authority or parts.port == 0:
        raise ValueError("Puerto o autoridad URL inválidos")
    host, port_suffix = authority.groups()
    ip_address = None
    if host.startswith("["):
        ip_address = normalize_ip(host[1:-1])
        if ip_address.version != 6:
            raise ValueError("Solo IPv6 admite corchetes")
        host = f"[{ip_address}]"
    else:
        try:
            ip_address = normalize_ip(host)
            host = str(ip_address)
        except ValueError:
            host = normalize_domain(host)
            if documentation_domain(host):
                raise ValueError("URL de documentación o prueba")
    scope = ip_scope(ip_address) if ip_address else None
    if scope == "documentacion":
        raise ValueError("URL de documentación")
    # Preserve the entire suffix, including empty delimiters, case and percent encoding.
    tail = value[scheme_match.end() + len(parts.netloc):]
    return parts.scheme + "://" + host + (port_suffix or "") + tail, scope


def normalized_value(kind, value):
    """Use the same normalization for observed values and model proposals."""
    if kind == "IP":
        return str(normalize_ip(value))
    if kind == "Dominio":
        return normalize_domain(value)
    if kind == "URL":
        return normalize_url(value)[0]
    if kind == "Hash" and SHA256.fullmatch(value):
        return value.lower()
    raise ValueError("Tipo o valor no admitido")


def url_observation(value, field, method, behavior, grade, limitation, position=None):
    try:
        canonical, scope = normalize_url(value)
    except ValueError:
        return None
    return Observable("URL", canonical, value, field, method, behavior, grade, limitation,
                      alcance_ip=scope, posicion=position)


def shell_segments(command):
    segment = []
    end = 0
    for match in SHELL_TOKEN.finditer(command):
        if command[end:match.start()].strip():
            # Unbalanced quotes or unrecognized syntax. Earlier complete segments remain valid.
            return
        end = match.end()
        if match.lastgroup == "comment":
            continue
        if match.lastgroup == "separator":
            yield segment
            segment = []
        else:
            segment.append((match.group(), match.start(), match.lastgroup == "redirect"))
    if not command[end:].strip():
        yield segment


def shell_literal(token, position):
    if len(token) >= 2 and token[0] in "\"'" and token[-1] == token[0]:
        return token[1:-1], position + 1
    return token, position


def download_positions(tool, args):
    if tool not in DOWNLOAD_FLAGS:
        return set()
    flags, short_flags, valued, short_valued = DOWNLOAD_FLAGS[tool]
    positions = set()
    options = True
    skip = False
    for index, (value, _, redirect) in enumerate(args):
        if redirect:
            skip = True
        elif skip:
            skip = False
        elif options and value == "--":
            options = False
        elif options and tool == "curl" and value.startswith("--url="):
            positions.add(index)
        elif options and (value in valued or value in short_valued or (tool == "curl" and value == "--url")):
            if value == "--url" and index + 1 < len(args) and not args[index + 1][2]:
                positions.add(index + 1)
            skip = True
        elif options and value.startswith("-"):
            name, eq, _ = value.partition("=")
            if (value in flags or (eq and name in valued)
                    or (len(value) > 1 and all(flag in short_flags for flag in value[1:]))):
                continue
            return set()
        else:
            positions.add(index)
    return positions


def host_positions(tool, args):
    if tool not in HOST_COMMANDS:
        return set()
    positions = set()
    valued = HOST_OPTION_VALUES.get(tool, ())
    options = True
    skip = False
    for index, (value, _, redirect) in enumerate(args):
        if redirect or skip:
            skip = redirect
        elif options and value == "--":
            options = False
        elif options and value.startswith("-"):
            skip = value in valued
        elif tool == "dig" and value.startswith("@"):
            positions.add(index)
        else:
            positions.add(index)
            if tool != "nslookup" or len(positions) == 2:
                break
    return positions


def command_observations(command):
    if not isinstance(command, str) or len(command) > 8192:
        return
    # Shell substitutions and control structures can contain references that look
    # like standalone commands. Classify their literals conservatively.
    complex_shell = "`" in command or "\\\n" in command or any(
        token.lastgroup == "separator" and token.group() in {"(", ")"}
        for token in SHELL_TOKEN.finditer(command)
    )
    for segment in shell_segments(command):
        if not segment:
            continue
        decoded = [(*shell_literal(token, position), redirect) for token, position, redirect in segment]
        tool = decoded[0][0].rsplit("/", 1)[-1]
        args = decoded[1:]
        attempted = download_positions(tool, args) if not complex_shell else set()
        hosts = host_positions(tool, args) if not complex_shell else set()
        for index, (value, position, redirect) in enumerate(args):
            if redirect:
                continue
            if value.startswith("--url="):
                value, position = shell_literal(value[6:], position + 6)
            if URL_SCHEME.match(value):
                attempt = index in attempted and "$" not in value
                item = url_observation(value, "input", "argumento_shell",
                    "intento_descarga" if attempt else "url_mencionada", "intento" if attempt else "referencia",
                    "Comando registrado; descarga no confirmada." if attempt else
                    "URL escrita en un comando; descarga no confirmada.", position)
                if item:
                    yield item
                continue
            if index not in hosts:
                continue
            # Only admit an entire network-tool argument, never a fragment of a path or email.
            candidate = value
            if tool in {"ssh", "dig"} and "@" in value:
                user, _, candidate = value.rpartition("@")
                if (tool == "ssh" and not re.fullmatch(r"[\w.-]+", user)) or (tool == "dig" and user):
                    continue
                position += len(user) + 1
            try:
                address = normalize_ip(candidate)
                canonical, scope, kind = str(address), ip_scope(address), "IP"
                if scope == "documentacion":
                    continue
            except ValueError:
                try:
                    canonical = normalize_domain(candidate)
                except ValueError:
                    continue
                if documentation_domain(canonical):
                    continue
                scope, kind = None, "Dominio"
            yield Observable(kind, canonical, candidate, "input", "argumento_shell", "host_mencionado", "referencia",
                             "Argumento de una herramienta de red; contacto y resolución sin verificar.",
                             alcance_ip=scope, posicion=position)


def extract_observables(raw):
    event_type = raw.get("eventid")
    original_ip = raw.get("src_ip")
    if isinstance(original_ip, str):
        try:
            address = normalize_ip(original_ip)
        except ValueError:
            pass
        else:
            yield Observable("IP", str(address), original_ip, "src_ip", "campo_cowrie",
                             "conexion_origen" if event_type == "cowrie.session.connect" else "origen_sesion",
                             "resultado_registrado" if event_type == "cowrie.session.connect" else "referencia",
                             "Identifica el origen registrado de la sesión; por sí sola no acredita malicia.",
                             alcance_ip=ip_scope(address))

    if event_type == "cowrie.command.input":
        yield from command_observations(raw.get("input"))
    elif event_type in {DOWNLOAD, FAILED_DOWNLOAD, UPLOAD}:
        url = raw.get("url")
        if event_type != UPLOAD and isinstance(url, str):
            failed = event_type == FAILED_DOWNLOAD
            item = url_observation(url, "url", "campo_cowrie", "descarga_fallida" if failed else "descarga_registrada",
                "fallo_registrado" if failed else "resultado_registrado",
                "Cowrie registró el fallo; el evento no acredita recepción del archivo." if failed else
                "Cowrie registró la transferencia al honeypot; ejecución y contenido fuera de la captura sin verificar.")
            if item:
                yield item
        digest = raw.get("shasum")
        if event_type != FAILED_DOWNLOAD and isinstance(digest, str) and SHA256.fullmatch(digest):
            yield Observable("Hash", digest.lower(), digest, "shasum", "campo_cowrie",
                             "archivo_subido" if event_type == UPLOAD else "archivo_capturado", "resultado_registrado",
                             "SHA-256 informado por Cowrie para un archivo capturado; sin recálculo del contenido.",
                             algoritmo="SHA-256")


def observables(raw):
    """Compatibility projection for callers that only need type, value and evidence."""
    return sorted({(item.tipo, item.valor,
                    "IP de origen registrada por Cowrie" if item.campo == "src_ip" else item.limitacion)
                   for item in extract_observables(raw)})


def persist_observables(conn, tables, raw, event_id, when, *, extracted=None):
    ioc, types, observation = (tables[name] for name in ("ioc", "tipo_ioc", "observacion_ioc"))
    grouped = defaultdict(list)
    for item in extract_observables(raw) if extracted is None else extracted:
        grouped[item.tipo, item.valor].append(item.detalle())
    if not grouped:
        return {}
    type_ids = dict(conn.execute(select(types.c.nombre, types.c.id_tipo_ioc)
                                .where(types.c.nombre.in_({kind for kind, _ in grouped}))).all())
    observed = {}
    for (kind, value), details in sorted(grouped.items()):
        type_id = type_ids.get(kind)
        if type_id is None:
            continue
        record = insert(ioc).values(id_tipo_ioc=type_id, valor=value,
                                    primera_observacion=when, ultima_observacion=when)
        ioc_id = conn.scalar(record.on_conflict_do_update(index_elements=["id_tipo_ioc", "valor"],
            set_={"primera_observacion": func.least(ioc.c.primera_observacion, when),
                  "ultima_observacion": func.greatest(ioc.c.ultima_observacion, when)},
            where=or_(when < ioc.c.primera_observacion, when > ioc.c.ultima_observacion)).returning(ioc.c.id_ioc))
        if ioc_id is None:
            ioc_id = conn.scalar(select(ioc.c.id_ioc).where(ioc.c.id_tipo_ioc == type_id, ioc.c.valor == value))
        record = insert(observation).values(id_ioc=ioc_id, id_evento=event_id,
                                            evidencia=details[0]["limitacion"], detalles=details)
        observation_id = conn.scalar(record.on_conflict_do_update(index_elements=["id_ioc", "id_evento"],
            set_={"detalles": record.excluded.detalles},
            where=observation.c.detalles.is_distinct_from(record.excluded.detalles)).returning(observation.c.id_observacion))
        if observation_id is None:
            observation_id = conn.scalar(select(observation.c.id_observacion)
                .where(observation.c.id_ioc == ioc_id, observation.c.id_evento == event_id))
        observed[kind, value] = (ioc_id, observation_id)
    return observed


def backfill_detections(conn, tables):
    """Expose legacy detections without upgrading them to deterministic evidence."""
    detection, observation = tables["deteccion_ioc"], tables["observacion_ioc"]
    rows = select(detection.c.id_ioc, detection.c.id_evento,
        literal("Detección histórica del LLM; respaldo determinista pendiente de verificar")).distinct().where(
        detection.c.id_evento.is_not(None))
    result = conn.execute(insert(observation).from_select(["id_ioc", "id_evento", "evidencia"], rows)
        .on_conflict_do_nothing(index_elements=["id_ioc", "id_evento"]))
    return result.rowcount
