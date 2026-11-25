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
                        help='JSON por ID: {estado: completado|fallido, identificadas: [códigos aceptados]}')
    args = parser.parse_args()
    try:
        metrics = evaluate_independent(json.loads(args.etiquetas.read_text(encoding='utf-8')),
                                       json.loads(args.resultados.read_text(encoding='utf-8')))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
