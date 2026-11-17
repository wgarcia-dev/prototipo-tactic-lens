#!/usr/bin/env python3
"""Read-only SQLite status, also usable while the daemon holds its writer lock."""
from contextlib import closing
import json
import sqlite3
from urllib.parse import quote
try:
    from . import exportar_eventos as exporter
except ImportError:
    import exportar_eventos as exporter


def status():
    with closing(sqlite3.connect('file:'+quote(str(exporter.DB.resolve()),safe='/')+'?mode=ro',uri=True,timeout=5)) as conn:
        return exporter.full_status(conn)


if __name__=='__main__':
    try:print(json.dumps(status()))
    except Exception as exc:raise SystemExit('Estado no disponible: '+type(exc).__name__) from None
