"""Bounded enrichment of redacted indicators through independent provider contracts."""

from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from math import isfinite
import os
from pathlib import Path
import re
from threading import BoundedSemaphore, RLock
import time

import httpx

from .intelligence import extract_observables
from .sensitive import Redactor, captured_strings

_CACHE = OrderedDict()
_INFLIGHT = {}
_REQUESTS = defaultdict(deque)
_COOLDOWN = {}
_LOCK = RLock()
_POOL = ThreadPoolExecutor(max_workers=6, thread_name_prefix="tacticlens-enrichment")
_MISP_SLOTS = BoundedSemaphore(2)
_MAX_PENDING = 60
_MAX_INDICATORS = 30
_ENDPOINTS = {"threatfox": "https://threatfox-api.abuse.ch/api/v1/",
              "urlhaus": "https://urlhaus-api.abuse.ch/v1/payload/",
              "misp_warning_lists": "https://github.com/MISP/misp-warninglists/tree/main/lists/"}


def _setting(name, default, minimum, maximum, parse=float):
    try:
        value = parse(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if isfinite(value) and minimum <= value <= maximum else default


def _now():
    return datetime.now(timezone.utc).isoformat()


def _status(provider, state, **details):
    return {"estado": state, "consultado_en": _now(), "url": _ENDPOINTS[provider], **details}


def _indicators(events):
    sources = [event.datos_originales or {} for event in events]
    captured = set()
    for raw in sources:
        captured_strings(raw, captured)
    captured = {value.casefold() for value in captured if len(value) >= 5}
    redactor = Redactor(sources)
    found = {}
    for event, raw in zip(events, sources):
        for item in extract_observables(raw):
            if (redactor.text(item.valor, observable_url=True) != item.valor or
                    any(secret in item.valor.casefold() for secret in captured)):
                continue
            key = (item.tipo, item.valor)
            if key not in found:
                found[key] = {"tipo": item.tipo, "valor": item.valor,
                              "alcance_ip": item.alcance_ip, "eventos": []}
            if event.id_evento not in found[key]["eventos"]:
                found[key]["eventos"].append(event.id_evento)
    return list(found.values())[:_MAX_INDICATORS]


def _warning_lists(indicators, root, deadline):
    provider = "misp_warning_lists"
    folder = Path(root)
    try:
        if not folder.is_dir():
            return [_status(provider, "no_disponible") for _ in indicators]
        paths = sorted(folder.glob("*/list.json"))
    except OSError:
        return [_status(provider, "no_disponible") for _ in indicators]
    if not paths:
        return [_status(provider, "respuesta_incompatible") for _ in indicators]
    results = [[] for _ in indicators]
    partial = len(paths) > 512
    for path in paths[:512]:
        if time.monotonic() >= deadline:
            return [_status(provider, "timeout", coincidencias=hits, parcial=True) for hits in results]
        try:
            if path.stat().st_size > 2_000_000:
                partial = True
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            mode, entries = data.get("type", "string"), data.get("list")
            if mode not in {"string", "hostname", "cidr", "regex", "substring"} or not isinstance(entries, list):
                partial = True
                continue
            if not all(isinstance(entry, str) for entry in entries):
                partial = True
                continue
            if mode == "cidr":
                networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
            elif mode in {"string", "hostname"}:
                values = {entry.casefold().rstrip(".") if mode == "hostname" else entry.casefold() for entry in entries}
            elif mode == "regex":
                # Warning-list regexes may be expensive and are outside the supported local contract.
                partial = True
                continue
            for index, indicator in enumerate(indicators):
                if len(results[index]) >= 10:
                    continue
                value, kind = indicator["valor"].casefold(), indicator["tipo"]
                if mode == "cidr":
                    hit = kind == "IP" and any(ipaddress.ip_address(value) in network for network in networks)
                elif mode == "hostname":
                    labels = value.rstrip(".").split(".")
                    hit = kind == "Dominio" and any(".".join(labels[i:]) in values for i in range(len(labels)))
                elif mode == "substring":
                    hit = any(entry and entry.casefold() in value for entry in entries)
                else:
                    hit = value in values
                if hit:
                    results[index].append(_status(provider, "coincidencia", id=path.parent.name,
                        nombre=data.get("name", path.parent.name), version=data.get("version"),
                        categoria=data.get("category", "false_positive"),
                        url=_ENDPOINTS[provider] + path.parent.name))
        except (AttributeError, OSError, ValueError, TypeError):
            partial = True
    return [_status(provider, "coincidencia" if hits else "respuesta_incompatible" if partial else "sin_resultados",
                    coincidencias=hits, parcial=partial) for hits in results]


def _parse_response(provider, value, body):
    if not isinstance(body, dict):
        return _status(provider, "respuesta_incompatible")
    status = body.get("query_status")
    if status in ("unauthorized", "invalid_auth_key", "no_auth_key", "auth_key_invalid"):
        return _status(provider, "error_autenticacion")
    if status in ("rate_limit", "rate_limited"):
        return _status(provider, "cuota")
    if status in ("no_result", "no_results", "not_found"):
        return _status(provider, "sin_resultados")
    if status != "ok":
        return _status(provider, "respuesta_incompatible")
    if provider == "threatfox":
        hits = body.get("data")
        if not isinstance(hits, list) or not hits or not all(
                isinstance(hit, dict) and re.fullmatch(r"[0-9]{1,20}", str(hit.get("id"))) for hit in hits):
            return _status(provider, "respuesta_incompatible")
        identifier = str(hits[0]["id"])
        return _status(provider, "coincidencia", id=identifier, url="https://threatfox.abuse.ch/ioc/" + identifier)
    fingerprint = body.get("sha256_hash", body.get("sha256"))
    if not isinstance(fingerprint, str) or fingerprint.casefold() != value or (
            "urls" in body and not isinstance(body["urls"], list)):
        return _status(provider, "respuesta_incompatible")
    return _status(provider, "coincidencia", id=value, url="https://urlhaus.abuse.ch/")


def _request_slot(provider):
    limit = _setting(provider.upper() + "_REQUESTS_PER_MINUTE", 30, 1, 1000, int)
    now = time.monotonic()
    with _LOCK:
        history = _REQUESTS[provider]
        while history and now - history[0] >= 60:
            history.popleft()
        if _COOLDOWN.get(provider, 0) > now or len(history) >= limit:
            return False
        history.append(now)
        return True


def _cooldown(provider, response=None):
    try:
        seconds = float(response.headers.get("Retry-After", "60")) if response is not None else 60
        seconds = max(1, min(seconds, 3600)) if isfinite(seconds) else 60
    except (AttributeError, TypeError, ValueError):
        seconds = 60
    with _LOCK:
        _COOLDOWN[provider] = max(_COOLDOWN.get(provider, 0), time.monotonic() + seconds)


def _remote(provider, kind, value, key, deadline):
    if provider == "threatfox":
        payload = ({"query": "search_hash", "hash": value} if kind == "Hash" else
                   {"query": "search_ioc", "search_term": value, "exact_match": True})
        arguments = {"json": payload}
    else:
        arguments = {"data": {"sha256_hash": value}}
    timeout = _setting(provider.upper() + "_TIMEOUT_SECONDS", 2, 0.01, 30)
    retries = _setting("ENRICHMENT_RETRIES", 1, 0, 2, int)
    for attempt in range(retries + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _status(provider, "timeout")
        if not _request_slot(provider):
            return _status(provider, "cuota")
        try:
            response = httpx.post(_ENDPOINTS[provider], headers={"Auth-Key": key},
                                  timeout=min(timeout, remaining), **arguments)
        except httpx.TimeoutException:
            state = "timeout"
        except httpx.RequestError:
            state = "no_disponible"
        else:
            status = response.status_code
            if status in (401, 403):
                return _status(provider, "error_autenticacion")
            if status == 429:
                _cooldown(provider, response)
                return _status(provider, "cuota")
            if status == 408 or 500 <= status <= 599:
                state = "timeout" if status == 408 else "no_disponible"
            elif 200 <= status < 300:
                try:
                    parsed = _parse_response(provider, value, response.json())
                except (ValueError, TypeError):
                    return _status(provider, "respuesta_incompatible")
                if parsed["estado"] == "cuota":
                    _cooldown(provider)
                return parsed
            else:
                return _status(provider, "respuesta_incompatible")
        pause = 0.05 * 2**attempt
        if attempt == retries or deadline - time.monotonic() <= pause:
            return _status(provider, state)
        time.sleep(pause)


def _query(provider, kind, value, key, deadline):
    cache_key = provider, kind, value, hashlib.sha256(key.encode()).digest()
    ttl = _setting("ENRICHMENT_CACHE_TTL_SECONDS", 3600, 0, 86400)
    capacity = _setting("ENRICHMENT_CACHE_MAX_ENTRIES", 512, 1, 10000, int)
    with _LOCK:
        for expired in [item for item, (created, _) in _CACHE.items() if time.monotonic() - created >= ttl]:
            _CACHE.pop(expired, None)
        while len(_CACHE) > capacity:
            _CACHE.popitem(last=False)
        if cached := _CACHE.get(cache_key):
            _CACHE.move_to_end(cache_key)
            return {**cached[1], "cache": True}
        if active := _INFLIGHT.get(cache_key):
            return active
        if len(_INFLIGHT) >= _MAX_PENDING:
            return _status(provider, "no_disponible", motivo="capacidad_local")
        future = _POOL.submit(_remote, provider, kind, value, key, deadline)
        _INFLIGHT[cache_key] = future

        def completed(work):
            with _LOCK:
                _INFLIGHT.pop(cache_key, None)
                if not work.cancelled() and work.exception() is None:
                    result = work.result()
                    if result["estado"] in {"coincidencia", "sin_resultados"} and ttl:
                        _CACHE[cache_key] = (time.monotonic(), result)
                        while len(_CACHE) > capacity:
                            _CACHE.popitem(last=False)

        future.add_done_callback(completed)
        return future


def enrich(events):
    """Return a complete status per configured provider within the shared time budget."""
    started = time.monotonic()
    deadline = started + _setting("ENRICHMENT_TOTAL_TIMEOUT_SECONDS", 4, 0.01, 60)
    root = os.getenv("MISP_WARNING_LISTS_DIR", "")
    keys = {"threatfox": os.getenv("THREATFOX_AUTH_KEY", ""), "urlhaus": os.getenv("URLHAUS_AUTH_KEY", "")}
    indicators = _indicators(events)
    output = [{**indicator, "proveedores": {}} for indicator in indicators]
    pending = defaultdict(list)
    if root and indicators and _MISP_SLOTS.acquire(blocking=False):
        # Local MISP parsing is bounded by the same wall clock and worker pool.
        future = _POOL.submit(_warning_lists, indicators, root, deadline)
        future.add_done_callback(lambda _: _MISP_SLOTS.release())
        pending[future].append(("misp_warning_lists", None))
    elif root:
        for indicator in output:
            indicator["proveedores"]["misp_warning_lists"] = _status("misp_warning_lists", "no_disponible", motivo="capacidad_local")
    for index, indicator in enumerate(indicators):
        kind, value = indicator["tipo"], indicator["valor"].lower()
        for provider, key in keys.items():
            if not key or kind not in {"IP", "Dominio", "Hash"}:
                continue
            if provider == "urlhaus" and (kind != "Hash" or not re.fullmatch(r"[a-f0-9]{64}", value)):
                continue
            if provider == "threatfox" and kind == "Hash" and len(value) not in (32, 64):
                continue
            if kind == "IP" and indicator["alcance_ip"] != "global":
                result = _status(provider, "omitido", motivo="IP no pública")
            else:
                result = _query(provider, kind, value, key, deadline)
            if isinstance(result, dict):
                output[index]["proveedores"][provider] = result
            else:
                pending[result].append((provider, index))
    done, _ = wait(pending, timeout=max(0, deadline - time.monotonic()))
    for future, destinations in pending.items():
        for provider, index in destinations:
            try:
                value = future.result() if future in done else _status(provider, "timeout")
            except Exception:
                value = _status(provider, "no_disponible")
            if index is None:
                matches = value if isinstance(value, list) else [value] * len(output)
                for indicator, result in zip(output, matches, strict=True):
                    indicator["proveedores"][provider] = result
            else:
                output[index]["proveedores"][provider] = value
    return {"version": 2, "generado_en": _now(), "duracion_ms": round((time.monotonic() - started) * 1000, 2),
            "observables": output, "fuentes": {"misp_warning_lists": bool(root),
                                               **{provider: bool(key) for provider, key in keys.items()}}}
