"""Compare historical values to a private pre-update dump using temporary tables."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from dotenv import dotenv_values
from psycopg import sql
from scripts.historical_database import ROOT, connect

TABLES = {'sesion', 'evento', 'ioc', 'observacion_ioc', 'analisis_llm',
          'accion_identificada', 'accion_evento', 'mapeo_mitre', 'usuario',
          'auth_factor', 'auth_recuperacion'}


def verify(archive, output):
    decoded = output.with_suffix('.private.sql')
    subprocess.run([r'C:\Program Files\PostgreSQL\18\bin\pg_restore.exe', '-f', str(decoded), str(archive)],
                   check=True, capture_output=True)
    blocks = {}
    current = None
    for line in decoded.read_text(encoding='utf-8').splitlines(keepends=True):
        if current:
            if line.rstrip('\r\n') == r'\.':
                current = None
            else:
                blocks[current][1].append(line)
            continue
        match = re.match(r'COPY honeypot\.([a-z_]+) \(([^)]+)\) FROM stdin;', line)
        if match and match[1] in TABLES:
            current = match[1]
            fields = match[2].split(', ')
            if not all(re.fullmatch('[a-z_]+', field) for field in fields):
                raise ValueError('Columna no admitida')
            blocks[current] = (fields, [])
    if set(blocks) != TABLES:
        raise ValueError('Respaldo incompleto para comparar históricos')
    report = {}
    with connect(dotenv_values(ROOT/'.env')) as conn:
        # Only connection-local temporary tables are written. Permanent tables
        # are selected using the exact columns that existed before the update.
        conn.execute("SET LOCAL TIME ZONE 'UTC'")
        for name, (fields, data) in blocks.items():
            columns = sql.SQL(',').join(map(sql.Identifier, fields))
            conn.execute('DROP TABLE IF EXISTS pg_temp.history_baseline')
            conn.execute(sql.SQL('CREATE TEMP TABLE history_baseline ON COMMIT DROP AS SELECT {} FROM honeypot.{} WITH NO DATA').format(columns, sql.Identifier(name)))
            with conn.cursor().copy(sql.SQL('COPY history_baseline ({}) FROM STDIN').format(columns)) as copy:
                for line in data:
                    copy.write(line)
            def fingerprint(query):
                return conn.execute(sql.SQL("SELECT count(*),md5(coalesce(string_agg(h,'' ORDER BY h),'')) FROM (SELECT md5(row_to_json(r)::text) h FROM ({}) r) s").format(query)).fetchone()
            baseline = fingerprint(sql.SQL('SELECT {} FROM history_baseline').format(columns))
            actual = fingerprint(sql.SQL('SELECT {} FROM honeypot.{}').format(columns, sql.Identifier(name)))
            report[name] = {'filas_originales': baseline[0], 'filas_actuales': actual[0], 'valores_conservados': baseline == actual}
        conn.rollback()
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return all(row['valores_conservados'] for row in report.values())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(not verify(args.archive, args.output))
