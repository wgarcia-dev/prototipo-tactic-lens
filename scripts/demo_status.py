"""Local prerequisite checks and safe sensor metadata; never sends email."""
import argparse
from dotenv import load_dotenv
from sqlalchemy import inspect, select, text
from backend.db import database_engine


def main():
    load_dotenv()
    engine=database_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            missing=[name for name in ('evento_origen','observacion_ioc') if not inspect(conn).has_table(name,schema='honeypot')]
            if missing:
                raise RuntimeError('Faltan tablas de migraciones 007: '+', '.join(missing)+'; respalde y ejecute python -m scripts.migrate')
            result=conn.execute(text('SELECT nombre,host,version FROM honeypot.honeypot WHERE id_honeypot=CAST(:sensor AS uuid)'),
                {'sensor':__import__('os').environ['HONEYPOT_ID']}).mappings().first()
            if not result:
                raise RuntimeError('HONEYPOT_ID no corresponde a un sensor registrado')
            print('PostgreSQL disponible; migraciones de ingesta y observables presentes; sensor:',result['nombre'])
            print('Metadatos del sensor:',result['host'],result['version'])
    finally:
        engine.dispose()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',action='store_true')
    parser.parse_args()
    try:
        main()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit('Comprobacion no disponible: '+type(exc).__name__) from None
