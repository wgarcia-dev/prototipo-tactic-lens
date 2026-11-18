"""Restrict private files to the current OS user and system administrators."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def protect(path):
    path=Path(path).resolve()
    if os.name!='nt':
        path.chmod(0o700 if path.is_dir() else 0o600);return
    result=subprocess.run(['whoami.exe','/user','/fo','csv','/nh'],capture_output=True,check=True)
    found=re.findall(rb'S-1-[0-9-]+',result.stdout)
    if len(found)!=1:raise RuntimeError('No se pudo identificar el propietario de archivos privados')
    sid=found[0].decode('ascii');rights='(OI)(CI)F' if path.is_dir() else 'F'
    command=['icacls.exe',str(path),'/inheritance:r','/grant:r',f'*{sid}:{rights}',f'*S-1-5-18:{rights}',f'*S-1-5-32-544:{rights}',
             '/remove:g','*S-1-1-0','*S-1-5-11','*S-1-5-32-545']
    result=subprocess.run(command,capture_output=True,check=False)
    if result.returncode:raise RuntimeError('No se pudieron restringir permisos privados; no continuar la transferencia')


def prepare(root):
    root=Path(root).resolve();private=root/'.local';private.mkdir(parents=True,exist_ok=True);protect(private)
    for path in (root/'.env',root/'frontend/.env',root/'frontend/.env.local'):
        if path.is_file():protect(path)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);args=parser.parse_args()
    prepare(args.root);print('Permisos privados restringidos; no se imprimieron secretos.')
