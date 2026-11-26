"""Register the three lab sensors and print the environment assignments."""
import os
from uuid import uuid4

from dotenv import find_dotenv, load_dotenv, set_key
from sqlalchemy import MetaData, Table, select

from backend.db import database_engine


def main():
    env_path = find_dotenv(usecwd=True)
    if not env_path:
        raise SystemExit('No se encontro .env del proyecto')
    load_dotenv(env_path)
    base_id = os.environ['HONEYPOT_ID']
    engine = database_engine()
    honeypot = Table('honeypot', MetaData(), schema='honeypot', autoload_with=engine)
    modes = {'COWRIE_SHELL': 2222, 'COWRIE_PROXY': 2223, 'COWRIE_LLM': 2224}
    assignments = {}
    with engine.begin() as conn:
        base = conn.execute(select(honeypot).where(honeypot.c.id_honeypot == base_id)).mappings().one()
        for mode, port in modes.items():
            name = 'TacticLens ' + mode.replace('_', ' ').title() + ' ' + str(port)
            existing = conn.scalar(select(honeypot.c.id_honeypot).where(honeypot.c.nombre == name))
            if existing is None:
                existing = uuid4()
                conn.execute(honeypot.insert().values(id_honeypot=existing, nombre=name,
                    software=base['software'], version=base['version'], host=base['host'],
                    estado='activo', id_usuario=base['id_usuario']))
            assignments[mode] = existing
    for mode, identifier in assignments.items():
        set_key(env_path, 'HONEYPOT_ID_' + mode, str(identifier))
        print(f'HONEYPOT_ID_{mode}={identifier}')
    print('Sensores registrados en PostgreSQL y .env. Reinicie el backend antes de enrutar nuevos eventos.')


if __name__ == '__main__':
    main()
