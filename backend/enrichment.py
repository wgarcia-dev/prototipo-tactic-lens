"""Bounded, provider-separated context for observed Cowrie indicators.

Remote lookups are opt-in. No captured command, credential or URL query is sent.
"""
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import httpx

from .intelligence import extract_observables

_CACHE = {}
_LOCK = Lock()
_TTL = 3600
_MAX_INDICATORS = 30


def _now():
    return datetime.now(timezone.utc).isoformat()


def _public(item):
    return item["tipo"] != "IP" or item["alcance_ip"] == "global"


def _indicators(events):
    captured = set()
    for event in events:
        raw = event.datos_originales or {}
        for name, value in raw.items():
            if isinstance(value, str) and value and any(mark in name.lower() for mark in
                ("password", "passwd", "passphrase", "secret", "token", "credential", "api_key")):
                captured.add(value.lower())
    found = {}
    for event in events:
        for item in extract_observables(event.datos_originales or {}):
            if any(secret in item.valor.lower() for secret in captured):
                continue
            key = (item.tipo, item.valor)
            if key not in found:
                found[key] = {"tipo": item.tipo, "valor": item.valor,
                              "alcance_ip": item.alcance_ip, "eventos": []}
            found[key]["eventos"].append(event.id_evento)
    return list(found.values())[:_MAX_INDICATORS]


def _warning_lists(indicator, root):
    if not root:
        return []
    folder = Path(root)
    if not folder.is_dir():
        return []
    matches = []
    for path in sorted(folder.glob("*/list.json")):
        try:
            if path.stat().st_size > 2_000_000:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data.get("list"), list):
                continue
            mode = data.get("type", "string")
            value = indicator["valor"].lower()
            entries = data["list"]
            hit = False
            if mode == "string":
                hit = value in {str(x).lower() for x in entries}
            elif mode == "hostname" and indicator["tipo"] == "Dominio":
                hit = any(value == str(x).lower() or value.endswith("." + str(x).lower()) for x in entries)
            elif mode == "cidr" and indicator["tipo"] == "IP":
                address = ipaddress.ip_address(value)
                hit = any(address in ipaddress.ip_network(str(x), strict=False) for x in entries)
            if hit:
                matches.append({"id": path.parent.name, "nombre": data.get("name", path.parent.name),
                                "version": data.get("version"), "categoria": data.get("category", "false_positive"),
                                "url": "https://github.com/MISP/misp-warninglists/tree/main/lists/" + path.parent.name,
                                "consultado_en": _now(), "resultado": "coincidencia"})
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return matches[:10]


def _remote(provider, indicator, key):
    kind, value = indicator["tipo"], indicator["valor"]
    if not _public(indicator):
        return {"estado": "omitido", "motivo": "IP no pública", "consultado_en": _now()}
    if provider == "threatfox":
        if kind not in {"IP", "Dominio", "Hash"}:
            return None
        endpoint = "https://threatfox-api.abuse.ch/api/v1/"
        payload = ({"query": "search_hash", "hash": value} if kind == "Hash" else
                   {"query": "search_ioc", "search_term": value, "exact_match": True})
    else:
        # Full Cowrie URLs may contain secrets in paths or query parameters.
        # Only the SHA-256 lookup is used by this provider.
        if kind != "Hash":
            return None
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
        payload = {"sha256_hash": value}
    cache_key = (provider, kind, value)
    with _LOCK:
        cached = _CACHE.get(cache_key)
        if cached and time.monotonic() - cached[0] < _TTL:
            return {**cached[1], "cache": True}
    try:
        if provider == "threatfox":
            response = httpx.post(endpoint, json=payload, headers={"Auth-Key": key}, timeout=5)
        else:
            response = httpx.post(endpoint, data=payload, headers={"Auth-Key": key}, timeout=5)
        if response.status_code == 429:
            result = {"estado": "cuota", "consultado_en": _now()}
        else:
            response.raise_for_status()
            body = response.json()
            status = body.get("query_status")
            hits = body.get("data")
            result = {"estado": "coincidencia" if status == "ok" and hits else "sin_resultados",
                      "consultado_en": _now(), "id": str((hits or [{}])[0].get("id", ""))[:100] if isinstance(hits, list) else None,
                      "resultado": status, "url": ("https://threatfox.abuse.ch/ioc/" + str(hits[0]["id"])
                          if provider == "threatfox" and isinstance(hits, list) and hits and str(hits[0].get("id", "")).isdigit()
                          else "https://threatfox.abuse.ch/" if provider == "threatfox" else "https://urlhaus.abuse.ch/")}
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        result = {"estado": "error", "consultado_en": _now()}
    if result["estado"] not in {"error", "cuota"}:
        with _LOCK:
            _CACHE[cache_key] = (time.monotonic(), result)
    return result


def enrich(events):
    """Return only server-owned references; provider errors never stop analysis."""
    root = os.getenv("MISP_WARNING_LISTS_DIR", "")
    keys = {"threatfox": os.getenv("THREATFOX_AUTH_KEY", ""),
            "urlhaus": os.getenv("URLHAUS_AUTH_KEY", "")}
    output = []
    for indicator in _indicators(events):
        providers = {"misp_warning_lists": _warning_lists(indicator, root)}
        for provider, key in keys.items():
            if key:
                result = _remote(provider, indicator, key)
                if result is not None:
                    providers[provider] = result
        output.append({**indicator, "proveedores": providers})
    return {"version": 1, "generado_en": _now(), "observables": output,
            "fuentes": {"misp_warning_lists": bool(root and Path(root).is_dir()),
                        "threatfox": bool(keys["threatfox"]), "urlhaus": bool(keys["urlhaus"])}}
