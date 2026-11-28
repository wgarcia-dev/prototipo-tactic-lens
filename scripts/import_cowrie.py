"""Import Cowrie JSON and JSONL with the same rules as the web interface."""
import argparse
import asyncio
import json
from pathlib import Path

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from backend.api import app, lifespan, persist_events
from backend.cowrie_import import import_events


def import_file(path):
    with Path(path).open("rb") as source:
        return import_events(source, persist_events)


async def main(path):
    try:
        async with lifespan(app):
            result = await run_in_threadpool(import_file, path)
    except HTTPException as error:
        print(json.dumps({"estado": "error", "mensaje": error.detail}, ensure_ascii=False))
        return 1
    except OSError:
        print(json.dumps({"estado": "error", "mensaje": "No se pudo leer el archivo"}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archivo")
    raise SystemExit(asyncio.run(main(parser.parse_args().archivo)))
