"""Plan, replay or execute bounded Cowrie exercises; plan is the safe default."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import getpass
import json
from pathlib import Path
import re
from uuid import uuid4
from exercises.catalog import PORTS, LEVELS, select_cases
from exercises.replay import build_replay, compare_expectations
from exercises.ssh_runner import run_case, validate_host

ROOT = Path(__file__).resolve().parent


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def create_plans(modes, level, selected):
    plans = []
    for mode in modes:
        template = "TL-" + uuid4().hex[:20]
        for case in select_cases(template, level, selected):
            marker = "TL-" + uuid4().hex[:20]
            actual = next(c for c in select_cases(marker, level, [case.id]))
            plans.append({"modalidad": mode, "puerto": PORTS[mode], "marcador": marker, "case": actual})
    return plans


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modo", choices=("plan", "replay", "ssh"), default="plan")
    parser.add_argument("--nivel", choices=LEVELS, default="bajo")
    parser.add_argument("--modalidades", nargs="+", choices=PORTS, default=list(PORTS))
    parser.add_argument("--escenarios", nargs="+", default=[])
    parser.add_argument("--host", default="192.168.56.101")
    parser.add_argument("--usuario", default="root")
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh/known_hosts")
    parser.add_argument("--output", type=Path, default=ROOT / "output/exercises")
    args = parser.parse_args(argv)
    try:
        if len(args.modalidades) != len(set(args.modalidades)):
            raise ValueError("Repeated modalities are not allowed")
        plans = create_plans(args.modalidades, args.nivel, args.escenarios)
        if args.modo == "ssh":
            validate_host(args.host)
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.usuario):
                raise ValueError("Invalid SSH user")
            if any(p["case"].transport == "replay" for p in plans):
                raise ValueError("Selection contains replay-only scenarios: select live scenarios explicitly")
            if not args.known_hosts.is_file():
                raise ValueError("Provide a known_hosts file with verified laboratory host keys")
            llm_commands = sum(len(p["case"].steps) + 2 for p in plans if p["modalidad"] == "llm" and p["case"].transport == "ssh")
            if llm_commands > 50:
                raise ValueError("LLM command budget exceeded (50)")
        run_id = datetime.now(timezone.utc).strftime("TL-%Y%m%dT%H%M%SZ-") + uuid4().hex[:8]
        output = args.output / run_id
        output.mkdir(parents=True, exist_ok=False)
        serializable = [{**p, "case": asdict(p["case"])} for p in plans]
        write_json(output / "plan.json", {"mode": args.modo, "host": args.host, "cases": serializable})
        if args.modo == "replay":
            events, labels, expectations = build_replay(plans)
            write_json(output / "synthetic_events.json", events)
            write_json(output / "intent_labels.json", labels)
            write_json(output / "expectations.json", expectations)
            from src.pipeline import analyze
            result = analyze(events, ROOT / "rules", labels=labels)
            for key, value in result.items():
                write_json(output / f"{key}.json", value)
            comparison = compare_expectations(result["detections"], expectations, plans)
            write_json(output / "comparison.json", comparison)
            print(f"Replay SYNTHETIC: {len(events)} events, {len(result['detections'])} detections, {len(result['alerts'])} alerts")
            print(f"Rule expectations match: {comparison['matched_expectations']}; intent metrics: {result['metrics']['classification']}")
            if not comparison["matched_expectations"]:
                print(f"Review differences: {output}")
                return 2
        elif args.modo == "ssh":
            import paramiko
            password = getpass.getpass("Contrasena Cowrie (solo memoria): ") if any(p["case"].transport == "ssh" for p in plans) else None
            results = []
            write_json(output / "resultados.json", results)
            for plan in plans:
                # Write a pending entry first, preserving evidence even on Ctrl+C.
                results.append({"marcador": plan["marcador"], "modalidad": plan["modalidad"],
                                "puerto": plan["puerto"], "escenario": plan["case"].id,
                                "estado": "started", "codigo_ssh": 1, "comandos": []})
                write_json(output / "resultados.json", results)
                results[-1] = run_case(paramiko, plan, args.host, args.usuario, password, args.known_hosts)
                write_json(output / "resultados.json", results)
                print(f"{plan['modalidad']} / {plan['case'].id}: {results[-1]['estado']}")
                if results[-1]["codigo_ssh"] != 0:
                    print(f"Stopped; review manifest: {output}")
                    return 2
        else:
            for p in plans:
                print(f"{p['modalidad']}:{p['puerto']} {p['case'].id} [{p['case'].severity}; {p['case'].transport}]")
        print(f"Artifacts: {output}")
        return 0
    except (ValueError, OSError, ImportError) as exc:
        # Only local validation messages; remote exception payloads are never printed.
        print(f"Exercise failed: {type(exc).__name__}")
        if isinstance(exc, ValueError):
            print(str(exc))
        return 1
    except KeyboardInterrupt:
        print("Interrupted; started entries remain pending in resultados.json")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
