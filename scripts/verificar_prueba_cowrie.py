"""Summarize captured sessions for a test-run marker without exposing event bodies."""
import argparse
import os
from dotenv import load_dotenv
from sqlalchemy import text
from backend.db import database_engine

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('marcador')
    args = parser.parse_args()
    load_dotenv()
    query = text('''SELECT s.cowrie_session_id, s.id_honeypot, s.puerto_destino,
        (SELECT count(*) FROM honeypot.evento all_events WHERE all_events.id_sesion=s.id_sesion) AS eventos_sesion,
        count(*) AS eventos_con_marcador, min(e.fecha_hora) AS primera_evidencia
        FROM honeypot.sesion s JOIN honeypot.evento e ON e.id_sesion=s.id_sesion
        WHERE e.datos_originales::text LIKE :marker
        GROUP BY s.id_sesion ORDER BY primera_evidencia''')
    with database_engine().connect() as conn:
        for row in conn.execute(query, {'marker': '%' + args.marcador + '%'}):
            modes = {os.getenv('HONEYPOT_ID_COWRIE_' + name): name.lower() for name in ('SHELL', 'PROXY', 'LLM')}
            label = modes.get(str(row.id_honeypot), 'desconocido')
            print(row.cowrie_session_id, label, row.puerto_destino,
                  row.eventos_sesion, row.eventos_con_marcador, row.primera_evidencia, sep=' | ')

if __name__ == '__main__':
    main()
