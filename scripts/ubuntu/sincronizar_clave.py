#!/usr/bin/env python3
"""Privileged key alignment; invoked by the Windows helper over verified SSH."""
import argparse
from datetime import datetime,timezone
import json
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def main(path,url,kit=None):
    # Only consume the dedicated temporary input created by the SSH receiver;
    # never unlink an arbitrary file supplied accidentally to a root command.
    if (path.name!='key' or not re.fullmatch(r'\.tacticlens-key-[a-f0-9]{32}',path.parent.name)
        or path.is_symlink() or path.parent.is_symlink() or not path.is_file()):
        raise RuntimeError('Se requiere la entrada temporal privada creada por el instalador')
    try:
        key=path.read_text().strip()
        if os.geteuid()!=0 or not re.fullmatch(r'[A-Za-z0-9_-]{32,}',key):
            raise RuntimeError('La entrada privada o el usuario no son válidos')
        parsed=urlsplit(url)
        ip=ipaddress.ip_address(parsed.hostname or '')
        if (parsed.scheme!='http' or parsed.port!=8000 or parsed.path!='/api/ingesta/eventos'
            or parsed.username or parsed.password or parsed.query or parsed.fragment or ip.version!=4
            or not any(ip in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))):
            raise RuntimeError('La modalidad demo requiere IPv4 privada y API real en puerto 8000')
        # Prove this key against the actual direct API without inserting data.
        body=json.dumps({'eventos':[{'session':'','eventid':'','_collector':{'source_id':'comprobacion-clave-sin-persistencia'}}]}).encode()
        request=urllib.request.Request(url,data=body,
            headers={'Content-Type':'application/json','X-API-Key':key})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        try:
            response=opener.open(request,timeout=8)
        except urllib.error.HTTPError as exc:
            response=exc
        with response:
            result=json.load(response)
            if response.status!=422 or result.get('contrato')!='tacticlens.ingesta.v2' or result.get('rechazados')!=1:
                raise RuntimeError('La API HTTP no reconoce la clave de demostración; no se modificó configuración')
        if kit:
            subprocess.run(['bash',str(kit/'scripts/ubuntu/configurar-http.sh'),str(kit),str(ip),str(path)],check=True)
            return
        subprocess.run(['systemctl','stop','tacticlens-exportador.timer'],check=True)
        try:
            for _ in range(60):
                state=subprocess.check_output(['systemctl','show','tacticlens-exportador.service','-p','ActiveState','--value'],text=True).strip()
                if state not in {'active','activating','deactivating'}:break
                time.sleep(1)
            else:raise RuntimeError('La captura sigue activa; no modificar mientras se ejecuta')
            config=Path('/etc/tacticlens-cowrie/exportador.env')
            backup=Path('/var/lib/tacticlens-cowrie/backups')/('clave-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.env')
            backup.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            shutil.copy2(config,backup);os.chmod(backup,0o600)
            value=config.read_text()
            for name,new in {'TACTICLENS_TOKEN':key,'TACTICLENS_URL':url,'TACTICLENS_TRANSPORT':'demo-http'}.items():
                pattern=r'(?m)^(?:export\s+)?'+name+r'\s*=.*$'
                line=name+'='+new
                value=re.sub(pattern,lambda _:line,value) if re.search(pattern,value) else value.rstrip()+'\n'+line+'\n'
            temp=config.with_suffix('.sync.tmp');temp.write_text(value)
            os.chmod(temp,0o600);os.chown(temp,config.stat().st_uid,config.stat().st_gid);os.replace(temp,config)
            environment={**os.environ,'TACTICLENS_TOKEN':key,'TACTICLENS_URL':url,'TACTICLENS_TRANSPORT':'demo-http'}
            print('Clave validada en la API real y alineada sin mostrarla. Se conserva respaldo privado.',flush=True)
            subprocess.run(['python3','/opt/tacticlens-cowrie/exportar_eventos.py','--retry-now'],env=environment,check=True)
        finally:
            subprocess.run(['systemctl','start','tacticlens-exportador.timer'],check=True)
    finally:
        path.unlink(missing_ok=True)
        try:path.parent.rmdir()
        except OSError:pass


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file',type=Path,required=True)
    parser.add_argument('--url',required=True)
    parser.add_argument('--kit',type=Path)
    args=parser.parse_args()
    try:main(args.key_file,args.url,args.kit)
    except RuntimeError as exc:raise SystemExit(str(exc)) from None
    except Exception as exc:raise SystemExit('Alineación incompleta: '+type(exc).__name__+'; no publique secretos') from None
