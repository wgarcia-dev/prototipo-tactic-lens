"""Small native-argument helper: no nested Python -c quoting in PowerShell 5.1."""
import argparse
import os
from pathlib import Path
import secrets
from dotenv import load_dotenv


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-environment',action='store_true')
    parser.add_argument('--create-key',type=Path)
    args=parser.parse_args()
    load_dotenv()
    if os.getenv('AUTH_ENV')!='development':
        raise SystemExit('Demo HTTP prohibida en produccion')
    if args.create_key:
        # Exclusive creation; credentials already configured are never overwritten.
        with args.create_key.open('x',encoding='ascii') as stream:
            stream.write(secrets.token_urlsafe(32))


if __name__=='__main__':main()
