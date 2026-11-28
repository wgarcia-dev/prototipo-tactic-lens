"""Compare independent session labels with saved, automatically accepted MITRE codes."""
import argparse
import json
from pathlib import Path

from backend.rag.evaluation import evaluate_independent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--etiquetas', type=Path, required=True,
                        help='JSON: metadata {independiente, origen}, casos [{id, esperados}]')
    parser.add_argument('--resultados', type=Path, required=True,
                        help='JSON por ID con estado, identificadas y opcionalmente recuperadas y propuestas')
    parser.add_argument('--inventario', type=Path, help='Matriz oficial generada por scripts.inventory_mitre')
    args = parser.parse_args()
    try:
        catalog = json.loads(args.inventario.read_text(encoding='utf-8'))['tecnicas'] if args.inventario else ()
        metrics = evaluate_independent(json.loads(args.etiquetas.read_text(encoding='utf-8')),
                                       json.loads(args.resultados.read_text(encoding='utf-8')),catalog)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
