"""Deterministic observables from Cowrie data; no network lookups or verdicts."""
import ipaddress
import re
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert


URL = re.compile(r"https?://[^\s'\"<>]+", re.I)
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", re.I)
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", re.I)
FILE_SUFFIXES = {"txt", "py", "service", "json", "jsonl", "log", "sh", "bash", "conf", "cfg", "ini", "yaml", "yml", "xml", "csv", "db", "sql", "md", "exe", "dll", "so", "zip", "tar", "gz"}


def observables(raw):
    """Return (type, value, evidence) tuples directly supported by one event."""
    found = set()
    source = raw.get("src_ip")
    if isinstance(source, str):
        try:
            found.add(("IP", str(ipaddress.ip_address(source)), "IP de origen registrada por Cowrie"))
        except ValueError:
            pass
    command = raw.get("input") if raw.get("eventid") == "cowrie.command.input" else None
    if not isinstance(command, str):
        return sorted(found)
    command = command[:8192]
    urls = set()
    for match in URL.finditer(command):
        value = match.group().rstrip(".,;)")
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        if host and len(value) <= 2048:
            urls.add(value)
            found.add(("URL", value, "URL escrita en un comando; descarga no confirmada"))
    without_urls = command
    for value in urls:
        without_urls = without_urls.replace(value, " ")
    for match in DOMAIN.finditer(without_urls):
        value = match.group().lower().rstrip(".")
        if value.rsplit(".", 1)[-1] not in FILE_SUFFIXES:
            found.add(("Dominio", value, "Dominio escrito en un comando"))
    for match in IP.finditer(without_urls):
        try:
            found.add(("IP", str(ipaddress.ip_address(match.group())), "IP escrita en un comando"))
        except ValueError:
            pass
    for match in HASH.finditer(command):
        found.add(("Hash", match.group().lower(), "Hash escrito en un comando; archivo no verificado"))
    return sorted(found)


def persist_observables(conn, tables, raw, event_id, when):
    ioc, types, observation = (tables[name] for name in ("ioc", "tipo_ioc", "observacion_ioc"))
    for kind, value, evidence in observables(raw):
        type_id = conn.scalar(select(types.c.id_tipo_ioc).where(types.c.nombre == kind))
        if type_id is None:
            continue
        conn.execute(insert(ioc).values(id_tipo_ioc=type_id, valor=value,
            primera_observacion=when, ultima_observacion=when).on_conflict_do_update(
            index_elements=["id_tipo_ioc", "valor"],
            set_={"primera_observacion": func.least(ioc.c.primera_observacion, when),
                  "ultima_observacion": func.greatest(ioc.c.ultima_observacion, when)}))
        ioc_id = conn.scalar(select(ioc.c.id_ioc).where(ioc.c.id_tipo_ioc == type_id, ioc.c.valor == value))
        conn.execute(insert(observation).values(id_ioc=ioc_id, id_evento=event_id,
            evidencia=evidence).on_conflict_do_nothing(index_elements=["id_ioc", "id_evento"]))
