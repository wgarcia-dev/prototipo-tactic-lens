"""Inspect an operator-supplied Cowrie UML recording offline. Never replay its contents."""
import argparse
import json
from pathlib import Path
from struct import Struct

from backend.terminal_evidence import MAX_BODY, diagnostic_phrases

TTY_HEADER = Struct("<iLiiLL")
MAX_RECORDING = 10 * 1024 * 1024


def inspect_recording(stream):
    total = 0
    output_frames = 0
    reduced = 0
    diagnostics = set()
    while header := stream.read(TTY_HEADER.size):
        if len(header) != TTY_HEADER.size:
            raise ValueError("Cabecera TTY incompleta")
        operation, _, length, direction, _, microseconds = TTY_HEADER.unpack(header)
        if operation not in {1, 2, 3, 4} or length < 0 or microseconds >= 1_000_000:
            raise ValueError("Formato TTY no reconocido")
        total += TTY_HEADER.size + length
        if total > MAX_RECORDING:
            raise ValueError("Grabación fuera del límite de inspección de 10 MiB")
        payload = stream.read(length)
        if len(payload) != length:
            raise ValueError("Registro TTY incompleto")
        if operation == 3 and direction == 2:
            output_frames += 1
            reduced += length > MAX_BODY
            diagnostics.update(diagnostic_phrases([payload[:MAX_BODY].decode("utf-8", errors="replace")]))
    if not total:
        raise ValueError("Grabación vacía")
    return {"registros_de_salida":output_frames, "registros_reducidos":reduced,
            "diagnosticos":sorted(diagnostics), "enlace_a_orden":"no_acreditado"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archivo", type=Path, help="Copia local autorizada de la grabación")
    path = parser.parse_args().archivo
    if not path.is_file() or path.is_symlink():
        parser.error("Se requiere un archivo regular local seleccionado por el operador")
    try:
        with path.open("rb") as stream:
            print(json.dumps(inspect_recording(stream), ensure_ascii=False))
    except (OSError, ValueError) as error:
        if isinstance(error, OSError):
            parser.error("No se pudo leer la copia local")
        parser.error(str(error))


if __name__ == "__main__":
    main()
