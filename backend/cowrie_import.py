"""Bounded JSON/JSONL ingestion shared by the web and command line."""
from collections import Counter
import hashlib
import json
import os

from fastapi import HTTPException

from .ingestion import prepare


def limits():
    def bounded(name, default, ceiling):
        try:
            return min(ceiling, max(1, int(os.getenv(name, default))))
        except ValueError:
            return default
    return (bounded("COWRIE_IMPORT_MAX_BYTES", 10_000_000, 50_000_000),
            bounded("COWRIE_IMPORT_MAX_RECORDS", 20_000, 100_000),
            bounded("COWRIE_IMPORT_BATCH_SIZE", 100, 500))


def records(content):
    try:
        source = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(422, "El archivo debe estar codificado en UTF-8") from None
    if not source.strip():
        raise HTTPException(422, "Archivo vacío")
    try:
        document = json.loads(source)
    except (ValueError, RecursionError):
        if source.lstrip().startswith("["):
            raise HTTPException(422, "El array JSON está incompleto o tiene sintaxis inválida") from None
        for number, line in enumerate(source.splitlines(), 1):
            if not line.strip():
                continue
            position = {"linea": number}
            try:
                value = json.loads(line)
            except (ValueError, RecursionError):
                yield position, None, None, "json_invalido"
            else:
                yield position, value, line.strip(), None
    else:
        if isinstance(document, list):
            for index, value in enumerate(document, 1):
                yield {"posicion": index}, value, None, None
        else:
            yield {"linea": 1}, document, source.strip(), None


def import_events(stream, persist):
    maximum, record_limit, batch_size = limits()
    content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise HTTPException(413, f"Máximo {maximum} bytes por archivo")
    parsed = []
    for item in records(content):
        if len(parsed) == record_limit:
            raise HTTPException(413, f"Máximo {record_limit} registros por archivo")
        parsed.append(item)

    inserted = duplicates = rejected = 0
    pending, positions, errors, aliases = [], [], [], {}
    seen, old_seen = Counter(), Counter()

    def reject(position, reason):
        nonlocal rejected
        rejected += 1
        if len(errors) < 100:
            errors.append({**position, "error": reason})

    def flush():
        nonlocal inserted, duplicates
        if not pending:
            return
        outcome = persist(pending, partial=True, legacy_manual_aliases=aliases)
        inserted += outcome["insertados"]
        duplicates += outcome["duplicados"]
        for receipt in outcome["confirmaciones"]:
            if receipt["estado"] == "rechazado":
                reject(positions[receipt["indice"]], receipt["error"])
        pending.clear()
        positions.clear()
        aliases.clear()

    for position, value, original, problem in parsed:
        if problem or not isinstance(value, dict):
            reject(position, problem or "se_esperaba_un_objeto")
            continue
        event = {**value, "_collector": {"source_id": "manual:v2:pendiente"}}
        try:
            _, _, _, digest = prepare(event)
        except (ValueError, TypeError, OverflowError, RecursionError) as error:
            known = {"estructura_invalida", "fecha_invalida", "fecha_sin_zona", "puerto_invalido", "evento_demasiado_grande"}
            reject(position, str(error) if str(error) in known else "contenido_invalido")
            continue
        seen[digest] += 1
        identity = f"manual:v2:{digest}:{seen[digest]}"
        event["_collector"]["source_id"] = identity
        if original is not None:
            key = hashlib.sha256(original.encode()).hexdigest()
            old_seen[key] += 1
            aliases[identity] = f"manual:{key}:{old_seen[key]}"
        pending.append(event)
        positions.append(position)
        if len(pending) == batch_size:
            flush()
    flush()
    return {"procesados": len(parsed), "aceptados": inserted + duplicates, "insertados": inserted,
            "duplicados": duplicates, "rechazados": rejected,
            "errores": errors, "errores_omitidos": rejected - len(errors)}
