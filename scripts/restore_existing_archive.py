"""Inspect a standalone pg_dump custom archive and restore into a new database."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid

from dotenv import set_key
from psycopg import sql
from scripts.historical_database import ROOT, connect, inspect, run
from scripts.portability import sha256

PRIVATE = ROOT / '.local/restauracion'
PG = Path(r'C:\Program Files\PostgreSQL\18\bin')


def preflight(archive):
    PRIVATE.mkdir(parents=True, exist_ok=True)
    with archive.open('rb') as stream:
        if stream.read(5) != b'PGDMP':
            raise RuntimeError('El archivo no es un respaldo custom de PostgreSQL')
    digest = sha256(archive)
    toc = subprocess.run([str(PG/'pg_restore.exe'), '-l', str(archive)], check=True,
                         capture_output=True, text=True).stdout
    major = int(re.search(r'Dumped from database version: (\d+)', toc)[1])
    client = subprocess.run([str(PG/'pg_restore.exe'), '--version'], check=True,
                            capture_output=True, text=True).stdout
    if major > int(re.search(r'\b(\d+)\.', client)[1]):
        raise RuntimeError('Se necesita una versión más reciente de PostgreSQL/pg_restore')
    decoded = PRIVATE/'archive-inspection.sql'
    subprocess.run([str(PG/'pg_restore.exe'), '-f', str(decoded), str(archive)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    counts, extensions, migrations = {}, [], {}
    current, columns = None, []
    with decoded.open(encoding='utf-8') as stream:
        for raw in stream:
            line = raw.rstrip('\r\n')
            if current:
                if line == r'\.':
                    current = None
                    continue
                counts[current] += 1
                if current == 'schema_migration':
                    values = dict(zip(columns, line.split('\t')))
                    migrations[values['version']] = values['checksum']
                continue
            match = re.match(r'COPY honeypot\.([a-z_]+) \(([^)]+)\) FROM stdin;', line)
            if match:
                current, fields = match.groups()
                columns = fields.split(', ')
                counts[current] = 0
            match = re.match(r'CREATE EXTENSION IF NOT EXISTS ([a-z_]+) WITH SCHEMA ([a-z_]+);', line)
            if match:
                extensions.append(match.groups())
    if current:
        raise RuntimeError('COPY incompleto en el respaldo')
    required = {'sesion', 'evento', 'ioc', 'mapeo_mitre', 'usuario', 'auth_factor', 'observacion_ioc'}
    if not required <= counts.keys():
        raise RuntimeError('El respaldo no contiene todas las tablas integradas requeridas')
    for name, checksum in migrations.items():
        path = ROOT/'database/migrations'/name
        if not path.is_file() or hashlib.sha256(path.read_text(encoding='utf-8').encode()).hexdigest() != checksum:
            raise RuntimeError('Migración distinta del repositorio integrado: '+name)
    result = dict(sha256=digest, source_major=major, counts=counts, extensions=extensions,
                  migrations=list(migrations), full_archive_read=True)
    (PRIVATE/'archive-preflight.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result, toc


def restore(archive):
    result, toc = preflight(archive)
    config_path = PRIVATE/'restored-db.env'
    if config_path.exists() or (ROOT/'.env').exists():
        raise RuntimeError('Ya existe configuración de una restauración. Se conserva sin reemplazarla')
    admin = dict(DATABASE_NAME='postgres', DATABASE_USER='postgres', DATABASE_HOST='127.0.0.1',
                 DATABASE_PORT='5432', DATABASE_PASSWORD=os.environ.pop('TACTICLENS_PG_ADMIN_PASSWORD'))
    db = 'tacticlens_historico_'+uuid.uuid4().hex[:8]
    role = db+'_app'
    password = secrets.token_urlsafe(36)
    with connect(admin, autocommit=True) as conn:
        target_version = int(conn.execute('SHOW server_version_num').fetchone()[0])
        if result['source_major'] > target_version//10000:
            raise RuntimeError('El servidor local es de una versión mayor anterior al origen')
        available = dict(conn.execute('SELECT name,default_version FROM pg_available_extensions'))
        for name, schema in result['extensions']:
            if name not in available or schema != 'public':
                raise RuntimeError('Extensión no disponible o esquema no revisado: '+name)
        result['target_version_num'] = target_version
        result['target_extensions'] = {name: available[name] for name, _ in result['extensions']}
        # UUID-generated identifiers and plain CREATE deliberately refuse replacement.
        conn.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role), sql.Literal(password)))
        conn.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING {}').format(
            sql.Identifier(db), sql.Identifier(role), sql.Literal('UTF8')))
    admin['DATABASE_NAME'] = db
    with connect(admin, autocommit=True) as conn:
        for name, schema in result['extensions']:
            conn.execute(sql.SQL('CREATE EXTENSION {} WITH SCHEMA {}').format(sql.Identifier(name), sql.Identifier(schema)))
    # Avoid extension ownership operations while preserving all application objects.
    filtered = '\n'.join(';'+line if re.search(r'\bEXTENSION\b', line) else line for line in toc.splitlines())
    listing = PRIVATE/(db+'.list')
    listing.write_text(filtered, encoding='utf-8')
    local = dict(DATABASE_NAME=db, DATABASE_USER=role, DATABASE_PASSWORD=password,
                 DATABASE_HOST='127.0.0.1', DATABASE_PORT='5432')
    with (PRIVATE/(db+'.log')).open('w', encoding='utf-8') as log:
        run([PG/'pg_restore.exe', '--single-transaction', '--exit-on-error', '--no-owner', '--no-privileges',
             '-L', str(listing), '-d', db, str(archive)], local, stdout=log, stderr=log)
    with connect(local) as conn:
        restored = inspect(conn)
        if restored['counts'] != result['counts']:
            raise RuntimeError('Los conteos restaurados no coinciden con el archivo')
        sensors = conn.execute('SELECT id_honeypot FROM honeypot.honeypot').fetchall()
        if len(sensors) == 1:
            local['HONEYPOT_ID'] = str(sensors[0][0])
        result['unvalidated_constraints'] = conn.execute("SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='honeypot' AND NOT convalidated").fetchone()[0]
        result['encrypted_mfa_factors'] = conn.execute('SELECT count(*) FROM honeypot.auth_factor').fetchone()[0]
    # Only the new application role credential is persisted, never postgres password.
    config_path.touch(exist_ok=False)
    for key, value in local.items():
        set_key(config_path, key, value)
    result.update(database=db, counts_restored=restored['counts'], restore_complete=True)
    (PRIVATE/'restore-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print('Restauración completa en base nueva. Conteos y restricciones comprobados.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    try:
        if args.restore:
            restore(args.archive.resolve())
        else:
            result, _ = preflight(args.archive.resolve())
            print(json.dumps(result, indent=2))
    except Exception as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else 'Revise los registros privados; no se eliminó ninguna base.'
        if 'password authentication failed' in str(exc):
            detail = 'PostgreSQL rechazó la contraseña local de postgres.'
        import traceback
        location = traceback.extract_tb(exc.__traceback__)[-1]
        detail += ' Ubicación: '+Path(location.filename).name+':'+str(location.lineno)
        raise SystemExit(type(exc).__name__+': '+detail) from None
