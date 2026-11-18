"""Compare pre-existing rows against the private pre-migration hash manifest."""
import argparse,json,re
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import text
from backend.db import database_engine


def verify(engine,manifest):
    def q(value):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',value):raise ValueError('Identificador de manifiesto invalido')
        return '"'+value+'"'
    result={}
    with engine.connect() as conn:
        conn.execute(text('SET TRANSACTION READ ONLY'))
        for name,snapshot in manifest['manifest'].items():
            sql='SELECT jsonb_build_array('+','.join(q(k) for k in snapshot['pk'])+')::text k,md5(row_to_json(r)::text) f FROM (SELECT '+','.join(q(c) for c in snapshot['columns'])+' FROM honeypot.'+q(name)+') r'
            current=dict(conn.execute(text(sql)).all());original=snapshot['rows']
            result[name]={'originales':len(original),'nuevos':len(set(current)-set(original)),
                'faltantes':len(set(original)-set(current)),'modificados':sum(current.get(k)!=v for k,v in original.items() if k in current)}
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path)
    args=parser.parse_args();load_dotenv()
    path=args.manifest or Path(json.loads(Path('.local/rag/backup-pointer.json').read_text())['manifest'])
    engine=database_engine()
    try:result=verify(engine,json.loads(path.read_text(encoding='utf-8')))
    finally:engine.dispose()
    print(json.dumps(result,ensure_ascii=False))
    if any(row['faltantes'] or row['modificados'] for row in result.values()):raise SystemExit(1)


if __name__=='__main__':main()
