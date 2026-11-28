"""Import the checksum-pinned official Enterprise STIX bundle; no LLM calls."""
import argparse,json
from pathlib import Path
from dotenv import load_dotenv
from backend.db import migration_engine
from backend.rag.catalog import download,import_catalog

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archivo',type=Path,default=Path('.local/rag/enterprise-attack-20.1.json'))
    parser.add_argument('--descargar',action='store_true')
    args=parser.parse_args();load_dotenv()
    if args.descargar:download(args.archivo)
    engine=migration_engine()
    try:print(json.dumps(import_catalog(engine,args.archivo),ensure_ascii=False))
    finally:engine.dispose()

if __name__=='__main__':main()
