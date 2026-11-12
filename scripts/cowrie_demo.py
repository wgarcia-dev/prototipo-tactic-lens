"""Generate a harmless Cowrie marker or verify its actual durable receipt."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
import time
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine
from backend.ingest_transport import private_ipv4


def probe(host):
    marker = 'TacticLensDemo_' + uuid4().hex[:12]
    with socket.create_connection((host, 2222), timeout=8) as client:
        banner = client.recv(1024).decode('ascii', errors='replace').strip()
        if not banner.startswith('SSH-'):
            raise RuntimeError('Cowrie no devolvió una identificación SSH')
        client.sendall(('SSH-2.0-' + marker + '\r\n').encode('ascii'))
        time.sleep(1)
    # No credentials or commands are sent. This proves capture only after the
    # marker later appears with a SQLite origin receipt in PostgreSQL.
    result = {'marker': marker, 'ubuntu': host, 'fecha_utc': datetime.now(timezone.utc).isoformat(),
              'server_banner': banner}
    path = Path('.local/demo-http/ultima-prueba.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result), encoding='utf-8')
    print(json.dumps(result))


def verify(marker):
    if not re.fullmatch(r'TacticLensDemo_[a-f0-9]{12}', marker):
        raise ValueError('Marcador no válido')
    load_dotenv()
    engine = database_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            rows = conn.execute(text('''SELECT s.id_sesion,s.cowrie_session_id,e.id_evento,
                e.tipo_evento,e.numero_secuencia,e.fecha_hora,o.origen_id,o.registrado_en
                FROM honeypot.evento e JOIN honeypot.sesion s USING(id_sesion)
                LEFT JOIN honeypot.evento_origen o USING(id_evento)
                WHERE e.datos_originales::text LIKE :marker ORDER BY e.id_evento'''),
                {'marker': '%' + marker + '%'}).mappings().all()
            sessions = [r['id_sesion'] for r in rows]
            result = {'marker': marker, 'coincidencias': len(rows), 'eventos': [dict(r) for r in rows],
                      'origen_sqlite_confirmado': bool(rows) and all((r['origen_id'] or '').startswith('sqlite:') for r in rows)}
            if sessions:
                result['eventos_en_sesiones'] = conn.scalar(text('SELECT count(*) FROM honeypot.evento WHERE id_sesion=ANY(:ids)'), {'ids': sessions})
                result['secuencias_duplicadas'] = conn.scalar(text('''SELECT count(*) FROM (
                    SELECT id_sesion,numero_secuencia FROM honeypot.evento WHERE id_sesion=ANY(:ids)
                    GROUP BY id_sesion,numero_secuencia HAVING count(*)>1) d'''), {'ids': sessions})
            print(json.dumps(result, default=str))
            return result['origen_sqlite_confirmado']
    finally:
        engine.dispose()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    create = sub.add_parser('generar'); create.add_argument('--ubuntu', required=True, type=private_ipv4)
    check = sub.add_parser('verificar'); check.add_argument('--marker', required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'generar': probe(args.ubuntu)
        elif not verify(args.marker): raise SystemExit(2)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('Prueba no confirmada: ' + type(exc).__name__) from None
