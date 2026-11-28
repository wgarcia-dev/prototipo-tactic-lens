"""PostgreSQL portability checks, consistent dumps and empty-database restores.

No migrations, seeding, SMTP or LLM requests are executed by this tool.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from backend.db import migration_credentials

ROOT = Path(__file__).resolve().parents[1]
DEFERRED = {'008_limpieza_dominios.sql'}


def engine_for(database=None, *, autocommit=False, administrative=False):
    user, password = migration_credentials() if administrative else (os.environ['DATABASE_USER'], os.environ['DATABASE_PASSWORD'])
    return create_engine(URL.create('postgresql+psycopg', username=user,
        password=password, host=os.environ['DATABASE_HOST'],
        port=int(os.getenv('DATABASE_PORT','5432')), database=database or os.environ['DATABASE_NAME']),
        hide_parameters=True, isolation_level='AUTOCOMMIT' if autocommit else 'READ COMMITTED')


def sha256(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):result.update(chunk)
    return result.hexdigest()


def canonical_constraint(value):
    # PostgreSQL can reparse ARRAY[varchar literals]::text[] as one cast per
    # literal during restore. Normalize only that known equivalent form; other
    # expression, FK, uniqueness and validation differences still fail.
    literal=r"'(?:[^']|'')*'::character varying"
    pattern=r'\(ARRAY\[('+literal+r'(?:,\s*'+literal+r')*)\]\)::text\[\]'
    def expand(match):
        items=re.findall(literal,match.group(1))
        return 'ARRAY['+', '.join('('+item+')::text' for item in items)+']'
    return re.sub(pattern,expand,value)


def constraints_equal(expected,current):
    def normalize(rows):
        return [{**row,'definicion':canonical_constraint(row['definicion'])} for row in rows]
    return normalize(expected)==normalize(current)


def pg_tool(name):
    configured=os.getenv('PG_BIN_DIRECTORY')
    candidates=([Path(configured)/f'{name}.exe'] if configured else [])
    found=shutil.which(name)
    if found:candidates.append(Path(found))
    candidates += [Path(os.getenv('ProgramFiles','C:/Program Files'))/'PostgreSQL'/'18'/'bin'/f'{name}.exe']
    for path in candidates:
        if path.is_file():return str(path.resolve())
    raise RuntimeError(f'No se encontro {name}; configure PG_BIN_DIRECTORY o PATH')


def run_pg(name,arguments,database=None,stdout=None,*,administrative=False):
    user, password = migration_credentials() if administrative else (os.environ['DATABASE_USER'], os.environ['DATABASE_PASSWORD'])
    environment=os.environ.copy()
    environment.update(PGPASSWORD=password,PGHOST=os.environ['DATABASE_HOST'],
        PGPORT=os.getenv('DATABASE_PORT','5432'),PGUSER=user,
        PGDATABASE=database or os.environ['DATABASE_NAME'],PGCONNECT_TIMEOUT='10')
    result=subprocess.run([pg_tool(name),*arguments],env=environment,stdout=stdout or subprocess.PIPE,
        stderr=subprocess.PIPE,check=False)
    if result.returncode:
        # Driver stderr can contain row data. Preserve it privately, never echo it.
        error_dir=ROOT/'.local/migration/errors';error_dir.mkdir(parents=True,exist_ok=True)
        path=error_dir/(name+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')+'.log')
        path.write_bytes(result.stderr)
        raise RuntimeError(f'{name} fallo (codigo {result.returncode}); detalle privado: {path}')
    return result.stdout


def snapshot(conn):
    conn.execute(text("SET LOCAL TIME ZONE 'UTC'"))
    names=conn.execute(text("""SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
        ORDER BY 1,2""")).all()
    quote=conn.dialect.identifier_preparer.quote
    tables={}
    for schema,name in names:
        qualified=quote(schema)+'.'+quote(name)
        row=conn.execute(text('SELECT count(*) filas,md5(coalesce(string_agg(h,\'\' ORDER BY h),\'\')) contenido_md5 '
            +'FROM (SELECT md5(row_to_json(r)::text) h FROM '+qualified+' r) s')).mappings().one()
        tables[schema+'.'+name]=dict(row)
    constraints=[dict(r) for r in conn.execute(text("""SELECT n.nspname esquema,t.relname tabla,c.conname nombre,
        c.contype tipo,c.convalidated validada,pg_get_constraintdef(c.oid) definicion
        FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname='honeypot' ORDER BY t.relname,c.conname""")).mappings()]
    return {'tables':tables,'constraints':constraints}


def migration_status(conn):
    rows=dict(conn.execute(text('SELECT version,checksum FROM honeypot.schema_migration')).all())
    errors=[];missing=[]
    for path in sorted((ROOT/'database/migrations').glob('*.sql')):
        if path.name in rows:
            value=hashlib.sha256(path.read_text(encoding='utf-8').encode()).hexdigest()
            if value!=rows[path.name]:errors.append(path.name)
        elif path.name not in DEFERRED:missing.append(path.name)
    return {'aplicadas':sorted(rows),'faltantes_no_diferidas':missing,'checksums_distintos':errors,
            '008_diferida_sin_ejecutar':'008_limpieza_dominios.sql' not in rows}


def check(database=None,model=False):
    engine=engine_for(database)
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            info={'base':conn.scalar(text('SELECT current_database()')),'postgresql':conn.scalar(text('SHOW server_version')),
                  'puerto':conn.scalar(text('SHOW port'))}
            available=conn.execute(text("SELECT default_version,installed_version FROM pg_available_extensions WHERE name='vector'")).mappings().first()
            info['vector']=dict(available) if available else None
            if not available or not available['installed_version']:raise RuntimeError('pgvector no disponible/habilitado; revise la guia de migracion')
            info['coseno_ortogonales']=conn.scalar(text("SELECT '[1,0,0]'::vector <=> '[0,1,0]'::vector"))
            info['migraciones']=migration_status(conn)
            info['conteos']={name:conn.scalar(text('SELECT count(*) FROM honeypot.'+name)) for name in
                ('sesion','evento','ioc','observacion_ioc','analisis_llm','mapeo_mitre','usuario','rol','tecnica_mitre','catalogo_mitre')}
            info['catalogo']=[dict(r) for r in conn.execute(text('SELECT version,sha256,conteos FROM honeypot.catalogo_mitre WHERE activo')).mappings()]
            info['embeddings']=dict(conn.execute(text('SELECT count(*) FILTER(WHERE NOT revocada AND NOT deprecada) vigentes,count(*) FILTER(WHERE embedding_rag IS NOT NULL) vectores,min(vector_dims(embedding_rag)) dimension FROM honeypot.tecnica_mitre')).mappings().one())
            exists=conn.scalar(text('SELECT count(*) FROM honeypot.honeypot WHERE id_honeypot=CAST(:id AS uuid)'),{'id':os.environ['HONEYPOT_ID']})
            if not exists:raise RuntimeError('HONEYPOT_ID no corresponde a la base restaurada')
            from backend.auth.config import Settings
            settings=Settings.load()
            encrypted=conn.scalars(text('SELECT secreto_cifrado FROM honeypot.auth_factor WHERE secreto_cifrado IS NOT NULL')).all()
            for value in encrypted:settings.cipher.decrypt(value.encode())
            info['mfa_factores_descifrables']=len(encrypted)
        if info['migraciones']['faltantes_no_diferidas'] or info['migraciones']['checksums_distintos']:
            raise RuntimeError('Historial de migraciones incompatible; no ejecutar migraciones automaticamente')
        if model:
            from backend.rag.embeddings import encoder
            vector=encoder().encode(['system information discovery'])[0]
            info['modelo_cpu_dimension']=len(vector)
        return info
    finally:engine.dispose()


def backup(directory):
    directory=Path(directory).resolve()
    if not directory.is_relative_to((ROOT/'.local').resolve()):raise ValueError('El respaldo debe quedar en .local/ privado')
    directory.mkdir(parents=True,exist_ok=True)
    archive=directory/'TacticLens_Completo.backup'
    if archive.exists():raise ValueError('El respaldo ya existe; no sobrescribir')
    engine=engine_for(administrative=True)
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
            exported=conn.scalar(text('SELECT pg_export_snapshot()'))
            manifest={'creado_en_utc':datetime.now(timezone.utc).isoformat(),
                'database':conn.scalar(text('SELECT current_database()')),'postgresql':conn.scalar(text('SHOW server_version')),
                'port':conn.scalar(text('SHOW port')),'vector':conn.scalar(text("SELECT extversion FROM pg_extension WHERE extname='vector'")),
                'snapshot':snapshot(conn),'migrations':migration_status(conn)}
            run_pg('pg_dump',['--format=custom','--snapshot='+exported,'--file='+str(archive)],administrative=True)
        toc=run_pg('pg_restore',['--list',str(archive)]).decode('utf-8',errors='replace')
        (directory/'TacticLens_Completo.toc.txt').write_text(toc,encoding='utf-8')
        run_pg('pg_restore',['--file='+os.devnull,str(archive)])
        manifest.update(archivo=archive.name,bytes=archive.stat().st_size,sha256=sha256(archive),
            pg_restore_list=True,decodificacion_completa=True,toc_entradas=sum(bool(line and not line.startswith(';')) for line in toc.splitlines()))
        (directory/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
        return {k:v for k,v in manifest.items() if k not in ('snapshot','migrations')}
    finally:engine.dispose()


def verify_database(database,manifest_path):
    manifest=json.loads(Path(manifest_path).read_text(encoding='utf-8'));engine=engine_for(database,administrative=True)
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
            current=snapshot(conn)
        expected=manifest['snapshot']
        different=[name for name in set(expected['tables'])|set(current['tables']) if expected['tables'].get(name)!=current['tables'].get(name)]
        result={'base':database,'tablas_comprobadas':len(current['tables']),'tablas_distintas':sorted(different),
            'restricciones_iguales':constraints_equal(expected['constraints'],current['constraints']),
            'normalizaciones_sintacticas':sum(a!=b for a,b in zip(expected['constraints'],current['constraints']))}
        result['correcto']=not different and result['restricciones_iguales']
        return result
    finally:engine.dispose()


def restore(archive,manifest_path,database):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,62}',database) or database in {'postgres','template0','template1'}:raise ValueError('Nombre de destino no permitido')
    if os.environ['DATABASE_HOST'] not in {'localhost','127.0.0.1','::1'}:raise ValueError('Restauracion automatica solo en PostgreSQL local')
    archive=Path(archive).resolve();manifest=json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    if sha256(archive)!=manifest['sha256']:raise ValueError('SHA-256 del respaldo no coincide')
    maintenance=engine_for('postgres',autocommit=True,administrative=True)
    try:
        with maintenance.connect() as conn:
            exists=conn.scalar(text('SELECT 1 FROM pg_database WHERE datname=:name'),{'name':database})
            if not exists:
                conn.execute(text('CREATE DATABASE '+conn.dialect.identifier_preparer.quote(database)+" TEMPLATE template0 ENCODING 'UTF8'"))
    finally:maintenance.dispose()
    target=engine_for(database,administrative=True)
    try:
        with target.connect() as conn:
            count=conn.scalar(text("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f')"))
            if count:raise ValueError('Destino contiene objetos; se rechaza sobrescribir. Use una base nueva y vacia')
    finally:target.dispose()
    run_pg('pg_restore',['--no-owner','--no-privileges','--exit-on-error','--single-transaction','--dbname='+database,str(archive)],
           database,administrative=True)
    return verify_database(database,manifest_path)


def prerequisites():
    engine=engine_for('postgres')
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            version=int(conn.scalar(text('SHOW server_version_num')))
            vector=conn.execute(text("SELECT default_version FROM pg_available_extensions WHERE name='vector'")).first()
            if not 180000<=version<190000:raise RuntimeError('Esta transferencia requiere PostgreSQL 18')
            if not vector:raise RuntimeError('Faltan binarios pgvector compatibles con PostgreSQL 18')
            return {'postgresql':conn.scalar(text('SHOW server_version')),'vector_disponible':vector[0],
                    'base_mantenimiento':'postgres','sin_migraciones':True}
    finally:engine.dispose()


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    check_p=sub.add_parser('check');check_p.add_argument('--database');check_p.add_argument('--model',action='store_true')
    sub.add_parser('prerequisites')
    backup_p=sub.add_parser('backup');backup_p.add_argument('--directory',type=Path,required=True)
    restore_p=sub.add_parser('restore');restore_p.add_argument('--archive',type=Path,required=True);restore_p.add_argument('--manifest',type=Path,required=True);restore_p.add_argument('--database',required=True)
    verify_p=sub.add_parser('verify');verify_p.add_argument('--manifest',type=Path,required=True);verify_p.add_argument('--database',required=True)
    args=p.parse_args();load_dotenv(ROOT/'.env')
    try:
        if args.action=='check':result=check(args.database,args.model)
        elif args.action=='prerequisites':result=prerequisites()
        elif args.action=='backup':result=backup(args.directory)
        elif args.action=='restore':result=restore(args.archive,args.manifest,args.database)
        else:result=verify_database(args.database,args.manifest)
        print(json.dumps(result,ensure_ascii=False,indent=2,default=str))
        if result.get('correcto') is False:raise SystemExit(1)
    except Exception as exc:
        # Do not print DB driver errors, connection URLs or data from failed COPY.
        if type(exc) in (ValueError,RuntimeError):print(str(exc))
        else:print('Operacion no completada ('+type(exc).__name__+'); revise servicio, permisos y .env privado')
        raise SystemExit(1)


if __name__=='__main__':main()
