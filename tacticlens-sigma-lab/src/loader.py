import json
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    """Read JSON array or JSONL; never execute event contents."""
    text = path.read_text(encoding="utf-8-sig")
    try:
        records = json.loads(text)
    except json.JSONDecodeError:
        try:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON/JSONL input") from None
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise ValueError("Input must contain an array of event objects")
    return records
