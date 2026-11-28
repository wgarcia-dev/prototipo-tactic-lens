"""Update descriptive metadata of the existing logical sensor; keep its UUID/history."""
import argparse
import os
from dotenv import load_dotenv
from sqlalchemy import text
from backend.db import migration_engine


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True)
    parser.add_argument('--version',required=True)
    args=parser.parse_args()
    if not 1<=len(args.host)<=255 or not 1<=len(args.version)<=30:
        raise SystemExit('Metadatos fuera de rango')
    load_dotenv();engine=migration_engine()
    try:
        with engine.begin() as conn:
            name=conn.scalar(text('UPDATE honeypot.honeypot SET host=:host,version=:version,actualizado_en=now() WHERE id_honeypot=CAST(:sensor AS uuid) RETURNING nombre'),
                {'host':args.host,'version':args.version,'sensor':os.environ['HONEYPOT_ID']})
            if not name:raise RuntimeError('El sensor configurado no existe')
            print('Sensor conservado:',name,'; se actualizaron solo host/version, sin cambiar sesiones ni eventos.')
    finally:
        engine.dispose()


if __name__=='__main__':
    try:main()
    except Exception as exc:raise SystemExit('Actualizacion no disponible: '+type(exc).__name__) from None
