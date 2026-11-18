"""Custom-format backup and additive restore into a uniquely named database."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid

import psycopg
from psycopg import sql
from dotenv import dotenv_values

from scripts.portability import sha256

ROOT = Path(__file__).resolve().parents[1]


def run(args, values, **kwargs):
    env = dict(os.environ, PGPASSWORD=values['DATABASE_PASSWORD'])
    base = ['-h', values.get('DATABASE_HOST', '127.0.0.1'), '-p', values.get('DATABASE_PORT', '5432'),
            '-U', values['DATABASE_USER']]
    return subprocess.run([str(args[0]), *base, *args[1:]], env=env, check=True, **kwargs)


def connect(values, **kwargs):
    return psycopg.connect(host=values.get('DATABASE_HOST', '127.0.0.1'), port=values.get('DATABASE_PORT', '5432'),
                          user=values['DATABASE_USER'], password=values['DATABASE_PASSWORD'],
                          dbname=values['DATABASE_NAME'], **kwargs)


def inspect(conn):
    version = int(conn.execute('SHOW server_version_num').fetchone()[0])
    extensions = dict(conn.execute('SELECT extname,extversion FROM pg_extension').fetchall())
    tables = conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='honeypot' ORDER BY tablename").fetchall()
    counts = {name: conn.execute(sql.SQL('SELECT count(*) FROM honeypot.{}').format(sql.Identifier(name))).fetchone()[0]
              for (name,) in tables}
    return dict(server_version_num=version, extensions=extensions, counts=counts)


def backup(args):
    values = dotenv_values(args.config)
    output = Path(args.dump).resolve()
    if output.exists() or Path(str(output)+'.json').exists():
        raise RuntimeError('El respaldo ya existe; use otro nombre')
    output.parent.mkdir(parents=True, exist_ok=True)
    with connect(values) as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        manifest = inspect(conn)
        client_version = subprocess.run([str(Path(args.bin)/'pg_dump.exe'), '--version'], check=True, capture_output=True, text=True).stdout
        if int(re.search(r'\b(\d+)\.', client_version)[1]) < manifest['server_version_num']//10000:
            raise RuntimeError('pg_dump es anterior al servidor; utilice el bin de la versión original')
        snapshot = conn.execute('SELECT pg_export_snapshot()').fetchone()[0]
        run([Path(args.bin)/'pg_dump.exe', '-Fc', '--no-owner', '--no-privileges', '--snapshot', snapshot,
             '-f', str(output), values['DATABASE_NAME']], values)
    manifest['sha256'] = sha256(output)
    Path(str(output)+'.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    from dotenv import set_key
    transfer = Path(str(output)+'.auth.env')
    if transfer.exists():
        raise RuntimeError('Ya existe el archivo privado de transferencia')
    transfer.touch(exist_ok=False)
    for key in ('AUTH_SECRET_KEY', 'AUTH_TOTP_KEYS', 'HONEYPOT_ID'):
        if not values.get(key):
            raise RuntimeError('Falta clave original: '+key)
        set_key(transfer, key, values[key])
    print('Respaldo completo y manifiesto guardados. Contienen datos sensibles: transporte privado, nunca GitHub.')


def restore(args):
    if (ROOT/'.env').exists():
        raise RuntimeError('Existe .env: se conserva; revise antes de restaurar')
    source = dotenv_values(args.config)
    for key in ('AUTH_SECRET_KEY', 'AUTH_TOTP_KEYS', 'HONEYPOT_ID'):
        if not source.get(key):
            raise RuntimeError('Falta configuración privada original: '+key)
    dump = Path(args.dump).resolve()
    manifest = json.loads(Path(str(dump)+'.json').read_text(encoding='utf-8-sig'))
    if sha256(dump) != manifest['sha256']:
        raise RuntimeError('El checksum del respaldo no coincide')
    admin = dict(DATABASE_NAME='postgres', DATABASE_USER='postgres', DATABASE_HOST='127.0.0.1', DATABASE_PORT='5432',
                 DATABASE_PASSWORD=os.environ.pop('TACTICLENS_PG_ADMIN_PASSWORD'))
    db = 'tacticlens_historico_'+uuid.uuid4().hex[:8]
    role = db+'_app'
    password = secrets.token_urlsafe(36)
    private = ROOT/'.local/restauracion'
    private.mkdir(parents=True, exist_ok=True)
    # The entire archive TOC is reviewed before creating anything.
    toc = subprocess.run([str(Path(args.bin)/'pg_restore.exe'), '-l', str(dump)], check=True, capture_output=True, text=True).stdout
    with connect(admin, autocommit=True) as conn:
        target = inspect(conn)
        if manifest['server_version_num']//10000 > target['server_version_num']//10000:
            raise RuntimeError('No se admite restaurar hacia una versión mayor anterior')
        available = {row[0] for row in conn.execute('SELECT name FROM pg_available_extensions')}
        for name in manifest['extensions']:
            if name not in available:
                raise RuntimeError('Extensión no instalada: '+name)
        versions = set(conn.execute('SELECT name,version FROM pg_available_extension_versions').fetchall())
        for name, version in manifest['extensions'].items():
            if (name, version) not in versions:
                raise RuntimeError('Versión de extensión no disponible: '+name+' '+version)
        conn.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role), sql.Literal(password)))
        conn.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING {}').format(sql.Identifier(db), sql.Identifier(role), sql.Literal('UTF8')))
    admin['DATABASE_NAME'] = db
    with connect(admin, autocommit=True) as conn:
        for name, version in manifest['extensions'].items():
            if name != 'plpgsql':
                conn.execute(sql.SQL('CREATE EXTENSION {} VERSION {}').format(sql.Identifier(name), sql.Literal(version)))
    # Extensions are installed by administrator, remaining objects by dedicated owner.
    filtered = '\n'.join(';'+line if re.search(r'\b(?:EXTENSION|COMMENT - EXTENSION)\b', line) else line for line in toc.splitlines())
    listing = private/(db+'.list')
    listing.write_text(filtered, encoding='utf-8')
    local = dict(DATABASE_NAME=db, DATABASE_USER=role, DATABASE_PASSWORD=password, DATABASE_HOST='127.0.0.1', DATABASE_PORT='5432')
    with (private/(db+'.log')).open('w', encoding='utf-8') as log:
        run([Path(args.bin)/'pg_restore.exe', '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges',
             '-L', str(listing), '-d', db, str(dump)], local, stdout=log, stderr=log)
    with connect(local) as conn:
        restored = inspect(conn)
        if restored['counts'] != manifest['counts']:
            raise RuntimeError('Conteos distintos: revise el respaldo; no se habilita .env')
        if not conn.execute('SELECT 1 FROM honeypot.honeypot WHERE id_honeypot=%s', (source['HONEYPOT_ID'],)).fetchone():
            raise RuntimeError('Sensor original no encontrado')
    values = dict(source)
    values.update(local)
    values.update(AUTH_ENV='development', AUTH_COOKIE_SECURE='false', AUTH_PUBLIC_URL='http://127.0.0.1:5173',
                  AUTH_ALLOWED_ORIGINS='http://127.0.0.1:5173,http://localhost:5173', MAIL_TRANSPORT='file',
                  MAIL_DEV_DIRECTORY='.local/mail', INGEST_TRANSPORT='', INGEST_API_KEY=secrets.token_urlsafe(32),
                  SMTP_PASSWORD='', LLM_MODE='real')
    from dotenv import set_key
    (ROOT/'.env').touch(exist_ok=False)
    import getpass
    subprocess.run(['icacls.exe', str(ROOT/'.env'), '/inheritance:r', '/grant:r',
                    getpass.getuser()+':F', '*S-1-5-18:F', '*S-1-5-32-544:F'],
                   stdout=subprocess.DEVNULL, check=True)
    for key, value in values.items():
        if value is not None:
            set_key(ROOT/'.env', key, value)
    (private/(db+'.verified.json')).write_text(json.dumps(restored, indent=2), encoding='utf-8')
    print('Restauración validada: todas las tablas honeypot conservan sus conteos. Ejecutar migraciones compatibles.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--dump', required=True)
    parser.add_argument('--bin', default=r'C:\Program Files\PostgreSQL\18\bin')
    args = parser.parse_args()
    try:
        (backup if args.operation == 'backup' else restore)(args)
    except Exception as exc:
        # Never include database URLs, credentials or row values in console errors.
        raise SystemExit('Operación detenida: '+type(exc).__name__+'. '+(str(exc) if isinstance(exc, RuntimeError) else 'Revise el registro privado. No se eliminó ninguna base.')) from None
