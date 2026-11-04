"""CLI import of a Cowrie JSONL file. Usage: python import_cowrie.py path/to/cowrie.json"""
import argparse
import asyncio
import json
from pathlib import Path

from backend import app, lifespan, persist_events
from platform_api import parse_jsonl


async def main(path):
    content = Path(path).read_bytes()
    valid, errors = parse_jsonl(content)
    inserted = duplicates = 0
    async with lifespan(app):
        for event in valid:
            try:
                result = persist_events([event])
                inserted += result["insertados"]
                duplicates += result["duplicados"]
            except Exception as exc:
                errors.append({"linea": "evento", "error": type(exc).__name__})
    print(json.dumps({"procesados": len(content.splitlines()), "insertados": inserted, "duplicados": duplicates, "errores": errors[:100]}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archivo")
    asyncio.run(main(parser.parse_args().archivo))
