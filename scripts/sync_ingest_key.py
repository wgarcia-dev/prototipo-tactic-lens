"""Copy the existing Windows ingestion key through SSH stdin, never chat/argv."""
import argparse
import base64
from pathlib import Path
import re
import shlex
import subprocess
from uuid import uuid4
from dotenv import dotenv_values


def encoded_command(code):
    encoded=base64.b64encode(code.encode()).decode()
    return 'python3 -c '+shlex.quote("import base64;exec(compile(base64.b64decode('"+encoded+"'),'<tacticlens-sync>','exec'))")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--user',default='tacticadmin')
    args=parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]*',args.host) or not re.fullmatch('[a-z_][a-z0-9_-]*',args.user):
        raise SystemExit('Destino SSH no válido')
    root=Path(__file__).resolve().parents[1]
    key=dotenv_values(root/'.env').get('INGEST_API_KEY','')
    if not re.fullmatch('[A-Za-z0-9_-]{32,}',key):raise SystemExit('Revise INGEST_API_KEY en el .env privado')
    folder='.tacticlens-key-'+uuid4().hex
    receive="""import os,sys,re
from pathlib import Path
os.umask(0o077)
key=sys.stdin.buffer.read(513)
if not re.fullmatch(rb'[A-Za-z0-9_-]{32,512}',key):raise SystemExit('Entrada privada no valida')
folder=Path.home()/FOLDER
folder.mkdir(mode=0o700)
fd=os.open(folder/'key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(key)
print('Entrada temporal recibida por SSH cifrado, sin mostrarla.')
""".replace('FOLDER',repr(folder))
    common=['ssh.exe','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=tacticlens-cowrie','-o','ConnectTimeout=8']
    target=args.user+'@'+args.host
    print('SSH puede solicitar su contraseña en esta terminal. La clave de ingesta se transmite por stdin cifrado, no se imprime.',flush=True)
    subprocess.run([*common,'-T',target,encoded_command(receive)],input=key.encode(),check=True)
    print('Fase 2/2: vuelva a introducir la contraseña SSH y despues sudo si lo solicita. El proceso aun no ha terminado.',flush=True)
    helper=(root/'scripts/ubuntu/sincronizar_clave.py').read_text(encoding='utf-8')
    command='sudo '+encoded_command(helper)+' --key-file "$HOME/'+folder+'/key"'
    try:
        subprocess.run([*common,'-tt',target,command],check=True)
        print('Sincronizacion completada. Compruebe los contadores enviados y la interfaz de TacticLens.',flush=True)
    except subprocess.CalledProcessError:
        # Root helper removes the private input on every executed path. If sudo
        # was cancelled before Python ran, clean it using the same SSH identity.
        cleanup="from pathlib import Path; p=Path.home()/"+repr(folder)+"; (p/'key').unlink(missing_ok=True); p.rmdir() if p.exists() else None"
        subprocess.run([*common,'-T',target,encoded_command(cleanup)],check=False)
        raise


if __name__=='__main__':
    try:main()
    except subprocess.CalledProcessError:raise SystemExit('Sincronización SSH incompleta; conserve pendientes y revise el mensaje anterior') from None
