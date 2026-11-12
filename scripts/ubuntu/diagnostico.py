#!/usr/bin/env python3
"""Read-only technical inventory. Never imports/executes the installed exporter."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
from urllib.parse import quote

EXPORTER=Path('/opt/tacticlens-cowrie/exportar_eventos.py')
ENV=Path('/etc/tacticlens-cowrie/exportador.env')
QUEUE=Path('/var/lib/tacticlens-cowrie/cola.sqlite3')


def environment(path):
    values={}
    if path.exists():
        for line in path.read_text().splitlines():
            match=re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$',line.strip())
            if match:
                values[match[1]]=match[2].strip().strip('\"\'')
    return values


def redact(value,config):
    for key,secret in config.items():
        if re.search(r'(?i)key|password|secret|token|credential',key) and len(secret)>=4:
            value=value.replace(secret,'[SECRETO OMITIDO]')
    value=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----','[CLAVE PRIVADA OMITIDA]',value,flags=re.S)
    value=re.sub(r'(?i)((?:api[_-]?key|password|secret|token)\s*[:=]\s*)[\"\'][^\"\'\n]+[\"\']',r'\1"[SECRETO OMITIDO]"',value)
    value=re.sub(r'\b(?:re_|sk-)[A-Za-z0-9_-]{20,}','[CLAVE OMITIDA]',value)
    value=re.sub(r'(https?://)[^/\s:@]+:[^/\s@]+@',r'\1[CREDENCIALES]@',value)
    return value


def command(args,config):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=10)
        return {'codigo':result.returncode,'salida':redact(result.stdout[:24000],config)}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {'error':type(exc).__name__}


def inventory(exporter=EXPORTER,env=ENV,queue=QUEUE):
    config=environment(env)
    result={'version_diagnostico':1,'variables_presentes':sorted(config),
        'configuracion_publica':{k:v for k,v in config.items() if k in {'COWRIE_LOG','INGEST_URL','SQLITE_PATH','SQLITE_DB','QUEUE_DB','DB_PATH','BATCH_SIZE'}},
        'rutas':{'exportador':str(exporter),'configuracion':str(env),'cola':str(queue)}}
    if exporter.exists():
        data=exporter.read_bytes()
        result['exportador_sha256']=hashlib.sha256(data).hexdigest()
        result['codigo_exportador_revisar_antes_de_compartir']=redact(data.decode(),config)
    if queue.exists():
        with sqlite3.connect('file:'+quote(str(queue.resolve()),safe='/')+'?mode=ro',uri=True,timeout=3) as conn:
            result['sqlite']={'version':sqlite3.sqlite_version,'objetos':[]}
            for name,sql in conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                quoted='"'+name.replace('"','""')+'"'
                indexes=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? ORDER BY name",(name,)).fetchall()
                fingerprint=hashlib.sha256(json.dumps([sql,indexes],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
                result['sqlite']['objetos'].append({'tabla':name,'sql':sql,'indices':indexes,'schema_sha256':fingerprint,
                    'registros':conn.execute('SELECT count(*) FROM '+quoted).fetchone()[0]})
    for label,args in {
        'red':['ip','-br','address'],'rutas_red':['ip','route'],'hora':['timedatectl','status'],
        'servicios':['systemctl','list-units','--all','--type=service','--no-pager','--no-legend'],
        'cowrie':['systemctl','show','cowrie-tacticlens.service','-p','User','-p','WorkingDirectory','-p','ExecStart'],
        'exportador':['systemctl','show','tacticlens-exportador.service','-p','User','-p','WorkingDirectory','-p','ExecStart','-p','FragmentPath'],
        'timer':['systemctl','cat','tacticlens-exportador.timer'],'firewall':['ufw','status','verbose'],
        'sshd':['sshd','-T'],'puertos':['ss','-lnt']}.items():
        result[label]=command(args,config)
    result['servicios']['salida']='\n'.join(line for line in result['servicios'].get('salida','').splitlines() if re.search('cowrie|tacticlens|ingest|export',line,re.I))
    result['sshd']['salida']='\n'.join(line for line in result['sshd'].get('salida','').splitlines() if line.split(' ')[0] in {'port','gatewayports','allowtcpforwarding','disableforwarding','permitlisten','pubkeyauthentication','passwordauthentication'})
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exporter',type=Path,default=EXPORTER)
    parser.add_argument('--env',type=Path,default=ENV)
    parser.add_argument('--queue',type=Path,default=QUEUE)
    args=parser.parse_args()
    try:
        print(json.dumps(inventory(args.exporter,args.env,args.queue),ensure_ascii=False,indent=2))
    except Exception as exc:
        raise SystemExit('Diagnóstico incompleto: '+type(exc).__name__) from None
