"""Install the HTTP demo exporter using administrative SSH, without a tunnel."""
import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import subprocess
from uuid import uuid4


def encoded_command(code):
    encoded=base64.b64encode(code.encode()).decode()
    return 'python3 -c '+shlex.quote("import base64;exec(compile(base64.b64decode('"+encoded+"'),'<tacticlens-sync>','exec'))")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--user',default='tacticadmin')
    parser.add_argument('--demo-url',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]*',args.host) or not re.fullmatch('[a-z_][a-z0-9_-]*',args.user):
        raise SystemExit('Destino SSH no válido')
    root=Path(__file__).resolve().parents[1]
    from collector.sqlite_sender import validate_endpoint
    key=(root/'.local/demo-http/ingest.key').read_text().strip()
    validate_endpoint(args.demo_url,key,'demo-http')
    if not re.fullmatch('[A-Za-z0-9_-]{43,128}',key):raise SystemExit('Revise la clave exclusiva de demo; ejecute Iniciar-DemoHTTP.ps1')
    members=('collector/exportar_eventos.py','collector/sqlite_sender.py','scripts/ubuntu/configurar.sh',
             'scripts/ubuntu/configurar-http.sh','scripts/ubuntu/verificar.sh','scripts/ubuntu/sincronizar.sh',
             'scripts/ubuntu/estado.sh','scripts/ubuntu/probar-reconexion.sh')
    payload=json.dumps({'key':key,'files':{name:(root/name).read_text(encoding='utf-8').replace('\r\n','\n') for name in members}}).encode()
    folder='.tacticlens-key-'+uuid4().hex
    receive="""import os,sys,re,json
from pathlib import Path
os.umask(0o077)
payload=json.loads(sys.stdin.buffer.read(1048577))
key=payload['key'].encode()
if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}',key) or set(payload['files'])!=set(MEMBERS):raise SystemExit('Entrada privada no valida')
folder=Path.home()/FOLDER
folder.mkdir(mode=0o700)
fd=os.open(folder/'key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(key)
for name,content in payload['files'].items():
    target=folder/'kit'/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(content,encoding='utf-8')
print('Kit HTTP y entrada temporal recibidos por SSH administrativo, sin tunel y sin mostrar secretos.')
""".replace('FOLDER',repr(folder)).replace('MEMBERS',repr(members))
    common=['ssh.exe','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=tacticlens-cowrie','-o','ConnectTimeout=8']
    target=args.user+'@'+args.host
    print('SSH puede solicitar su contraseña en esta terminal. La clave de ingesta se transmite por stdin cifrado, no se imprime.',flush=True)
    subprocess.run([*common,'-T',target,encoded_command(receive)],input=payload,check=True)
    print('Fase 2/2: vuelva a introducir la contraseña SSH y despues sudo si lo solicita. El proceso aun no ha terminado.',flush=True)
    helper=(root/'scripts/ubuntu/sincronizar_clave.py').read_text(encoding='utf-8')
    command='sudo '+encoded_command(helper)+' --key-file "$HOME/'+folder+'/key" --kit "$HOME/'+folder+'/kit" --url '+shlex.quote(args.demo_url)
    try:
        subprocess.run([*common,'-tt',target,command],check=True)
        print('Configuracion HTTP completada. Los eventos viajan directamente, sin tunel. Compruebe los contadores y TacticLens.',flush=True)
    except subprocess.CalledProcessError:
        # Root helper removes the private input on every executed path. If sudo
        # was cancelled before Python ran, clean it using the same SSH identity.
        cleanup="from pathlib import Path; p=Path.home()/"+repr(folder)+"; (p/'key').unlink(missing_ok=True)"
        subprocess.run([*common,'-T',target,encoded_command(cleanup)],check=False)
        raise


if __name__=='__main__':
    try:main()
    except subprocess.CalledProcessError:raise SystemExit('Sincronización SSH incompleta; conserve pendientes y revise el mensaje anterior') from None
