"""Filesystem/terminal adapter only. Run with this laboratory's Python environment."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
from src.config import Config, LEVELS
from src.loader import load_events
from src.pipeline import analyze

ROOT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description="TacticLens offline Sigma laboratory")
    parser.add_argument("--input", type=Path, default=ROOT / "data/cowrie_events.json")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules")
    parser.add_argument("--output", type=Path, default=ROOT / "output")
    parser.add_argument("--alert-threshold", choices=LEVELS, default="high")
    parser.add_argument("--grouping-seconds", type=int, default=300)
    parser.add_argument("--hash-catalog", type=Path)
    parser.add_argument("--labels", type=Path)
    args = parser.parse_args(argv)
    try:
        config = Config(args.alert_threshold, args.grouping_seconds)
        catalog = load_events(args.hash_catalog) if args.hash_catalog else []
        labels = json.loads(args.labels.read_text(encoding="utf-8-sig")) if args.labels else None
        result = analyze(load_events(args.input), args.rules, config, catalog, labels)
        args.output.mkdir(parents=True, exist_ok=True)
        for name, content in result.items():
            target = args.output / f"{name}.json"
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(target)
    except (OSError, ValueError, sqlite3.Error) as exc:
        # Exception text may contain event data or file content. Keep terminal safe.
        print(f"Analysis failed ({type(exc).__name__}); check input, rules and configuration.", file=sys.stderr)
        return 1
    metrics = result["metrics"]
    print(f"Processed: {metrics['processed_events']} | Detections: {metrics['detections']} | Alerts: {metrics['alerts']}")
    print(f"By modality: {metrics['detections_by_mode']} | Duplicates: {metrics['duplicates']} | Rejected: {len(metrics['rejected'])}")
    print(f"Processing: {metrics['processing_seconds']:.4f}s")
    return 2 if metrics["rejected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
