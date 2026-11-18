"""Scan current release files and outgoing commits without printing secret values."""
import argparse,json,re,subprocess
from pathlib import Path
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]


def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)


def audit(base):
    secrets=[]
    for file in (ROOT/'.env',ROOT/'frontend/.env',ROOT/'frontend/.env.local'):
        if not file.is_file():continue
        for name,value in dotenv_values(file).items():
            if value and any(part in name.upper() for part in ('PASSWORD','SECRET','API_KEY','TOTP_KEYS')):
                for part in value.split(','):
                    if len(part.strip())>=8:secrets.append(part.strip().encode())
    issues=[];checked=0
    def inspect(path,data,location):
        nonlocal checked
        checked+=1
        private=path.startswith('.local/') or (Path(path).name.startswith('.env') and not path.endswith('.env.example')) or Path(path).suffix.lower() in {'.backup','.dump','.fernet','.sqlite3','.key'}
        if private:issues.append({'archivo':path,'origen':location,'riesgo':'Archivo privado'})
        if any(value in data for value in secrets):issues.append({'archivo':path,'origen':location,'riesgo':'Coincide con un secreto privado configurado'})
        if re.search(rb'\b(?:sk-|re_)[A-Za-z0-9_-]{32,}',data) or re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',data):
            issues.append({'archivo':path,'origen':location,'riesgo':'Patron de credencial o clave privada'})
    paths=git('ls-files','-z').split(b'\0')+git('ls-files','--others','--exclude-standard','-z').split(b'\0')
    for raw in sorted(set(paths)):
        if not raw:continue
        path=raw.decode();file=ROOT/path
        if file.is_file():inspect(path,file.read_bytes(),'arbol_actual')
    commits=git('rev-list',base+'..HEAD').decode().splitlines()
    for commit in commits:
        paths=git('diff-tree','--root','--no-commit-id','--name-only','--diff-filter=ACM','-r',commit).decode().splitlines()
        for path in paths:inspect(path,git('show',commit+':'+path),commit[:12])
    return {'archivos_revisados':checked,'commits_salientes':len(commits),'incidencias':issues,
            'nota':'Revision de secretos conocidos y patrones; complementar con revision humana. Nunca muestra valores.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',default='origin/codex/integracion-colaborativa-http');args=parser.parse_args()
    result=audit(args.base);print(json.dumps(result,ensure_ascii=False,indent=2))
    if result['incidencias']:raise SystemExit(1)
