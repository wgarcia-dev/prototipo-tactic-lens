"""Deterministic, bounded behavioral representation. Never embeds raw secrets."""
from collections import Counter, defaultdict
import re
import shlex
from ..sensitive import redact
from .mitre_evidence import CONTRACTS, OBSERVED, inbound_download, technique_evidence

LABELS={
 'system_discovery':'system information discovery operating system hostname hardware uname',
 'user_discovery':'system owner user discovery current user identity id whoami',
 'group_discovery':'permission groups discovery group membership',
 'file_discovery':'file and directory discovery enumeration listing filesystem',
 'network_discovery':'system network configuration discovery interfaces route IP address',
 'network_scan':'network service discovery port scanning nmap',
 'remote_discovery':'remote system discovery network peers neighbor table arp cache',
 'process_discovery':'process discovery process list running processes',
 'transfer':'ingress tool transfer download remote files using wget curl scp',
 'collection':'data from local system read collect local file content',
 'auth_repeated':'brute force repeated failed SSH authentication password guessing attempts',
 'shell':'Unix shell command and scripting interpreter command submitted to emulated shell',
 'file_delete':'file deletion remove local files',
 'account_create':'create local account useradd adduser',
 'ssh_keys':'account manipulation SSH authorized keys write persistence attempt',
 'cron':'scheduled task job cron crontab persistence attempt',
 'archive':'archive collected data compression tar zip',
 'permissions':'file and directory permissions ownership access control chmod chown',
 'file_movement':'local file copy move data staging',
 'history':'command history clearing disable shell history',
 'unknown':'unknown command; insufficient behavioral evidence; emulated honeypot only',
}


def command_features(command,depth=0):
    if not isinstance(command,str) or len(command)>16000 or depth>2:return {'unknown'}
    try:
        lexer=shlex.shlex(command,posix=True,punctuation_chars=';&|()')
        lexer.whitespace_split=True;tokens=list(lexer)
    except ValueError:return {'unknown'}
    groups=[[]]
    for token in tokens:
        if token and all(c in ';&|()' for c in token):groups.append([])
        else:groups[-1].append(token)
    features=set()
    for args in groups:
        if not args:continue
        # Assignment values, output and arbitrary literals are never embedded.
        while args and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=',args[0]):args=args[1:]
        if not args:continue
        name=args[0].rsplit('/',1)[-1].lower()
        if name in {'sudo','env','command','nohup'} and len(args)>1:
            features|=command_features(shlex.join(args[1:]),depth+1);continue
        if name in {'sh','bash','dash','zsh'}:
            features.add('shell')
            if '-c' in args and args.index('-c')+1<len(args):features|=command_features(args[args.index('-c')+1],depth+1)
        elif name in {'uname','hostname','hostnamectl','lscpu','lsb_release','uptime'}:features.add('system_discovery')
        elif name in {'whoami','id','who','w','users'}:features.add('user_discovery')
        elif name=='groups' or (name=='getent' and 'group' in args):features.add('group_discovery')
        elif name in {'ls','find','locate','tree','stat'}:features.add('file_discovery')
        elif name in {'ip','ifconfig','route','netstat','ss'}:features.add('network_discovery')
        elif name in {'nmap','masscan'}:features.add('network_scan')
        elif name in {'ps','top','pgrep','pstree'}:features.add('process_discovery')
        elif name in {'wget','curl'} and inbound_download(name, args[1:]):features.add('transfer')
        elif name=='cat':
            if any(a in {'/etc/os-release','/proc/version','/proc/cpuinfo'} for a in args[1:]):features.add('system_discovery')
            elif any(a.startswith('/') or a.startswith('./') for a in args[1:] if not a.startswith('-')):features.add('collection')
        elif name in {'rm','unlink','shred'}:features.add('file_delete')
        elif name in {'useradd','adduser'}:features.add('account_create')
        elif name=='crontab':
            features.add('cron' if '-e' in args or any(not a.startswith('-') for a in args[1:]) else 'unknown')
        elif name in {'tar','zip','gzip','7z'}:features.add('archive')
        elif name in {'chmod','chown','setfacl'} and len(args)>2:features.add('permissions')
        elif name in {'cp','mv'} and len(args)>2:features.add('file_movement')
        elif name=='history' and '-c' in args:features.add('history')
        elif name in {'echo','printf','tee'}:
            features.add('shell')
            # Inspect only known target path shapes; never the written content.
            if any(a.endswith('/.ssh/authorized_keys') or a=='~/.ssh/authorized_keys' for a in args):features.add('ssh_keys')
            elif any('/cron.' in a or a=='/etc/crontab' for a in args):features.add('cron')
            else:features.add('unknown')
        elif name in {'pwd','cd','true','false','exit'}:features.add('shell')
        else:features.add('unknown')
        if features-{'unknown'}:features.add('shell')
    return features or {'unknown'}


def represent(events, modality='desconocido'):
    ordered=sorted(events,key=lambda e:(e.fecha_hora,e.id_evento))
    counts=Counter(e.tipo_evento for e in ordered)
    eligible=technique_evidence(ordered,modality)
    transfers=eligible.get('T1105',{})
    guesses=eligible.get('T1110',{})
    supported_tags=defaultdict(set)
    for code, grades in eligible.items():
        for eid in grades:
            supported_tags[eid].add(CONTRACTS[code].tag)
    sequence=[];features={};confirmed=[]
    for event in ordered:
        data=event.datos_originales
        if event.tipo_evento=='cowrie.command.input' and data.get('realm') is None:
            tags=command_features(data.get('input',''))-{'transfer'}
            if event.id_evento in transfers:tags.add('transfer')
        elif event.tipo_evento=='cowrie.login.failed':tags={'auth_repeated'} if event.id_evento in guesses else {'unknown'}
        elif event.tipo_evento=='cowrie.session.file_download':
            tags={'transfer'} if event.id_evento in transfers else set()
            if transfers.get(event.id_evento)==OBSERVED:confirmed.append(event.id_evento)
        else:tags=set()
        tags.update(supported_tags[event.id_evento])
        features[event.id_evento]=sorted(tags)
        meaningful=sorted(tags-{'shell','unknown'})
        if meaningful and len(sequence)<48:sequence.append({'evento':event.id_evento,'segundos_desde_inicio':(event.fecha_hora-ordered[0].fecha_hora).total_seconds(),'acciones':meaningful,'resultado':'transferencia registrada por Cowrie' if event.id_evento in confirmed else 'intento registrado; resultado no confirmado'})
    actions=sorted({tag for values in features.values() for tag in values}-{'shell','unknown'})
    # This is the ONLY event-derived text that can reach the embedding model.
    has_shell=any('shell' in values for values in features.values())
    query='; '.join(behavior_label(tag) for tag in actions) or (LABELS['shell'] if has_shell else LABELS['unknown'])
    query+='; Cowrie SSH telemetry; assess only recorded evidence.'
    return {'version':1,'acciones':actions,'secuencia':sequence,'conteos':dict(counts),
            'consulta_segura':query,'rasgos_por_evento':features,'resultados_confirmados':confirmed,
            'modalidad':modality,
            'limites':['Las entradas son intentos; una respuesta del señuelo no demuestra ejecución en el sistema real.',
                       'No se incluyen contrasenas, salidas ni textos arbitrarios en embeddings']}


def behavior_label(tag):
    return LABELS.get(tag,tag.replace('_',' '))


def technique_profiles(name):
    # Semantic coverage derives from official names, not a fixed list of codes.
    value=name.lower()
    patterns={
        'system_discovery':r'system information discovery', 'user_discovery':r'system owner/user discovery',
        'group_discovery':r'permission groups discovery|local groups', 'file_discovery':r'file and directory discovery',
        'network_discovery':r'system network configuration discovery', 'network_scan':r'network service discovery',
        'process_discovery':r'process discovery', 'transfer':r'ingress tool transfer',
        'collection':r'data from local system', 'auth_repeated':r'brute force|password guessing',
        'shell':r'^unix shell$|^command and scripting interpreter$', 'file_delete':r'^file deletion$',
        'account_create':r'^create account$|^local account$', 'ssh_keys':r'^ssh authorized keys$',
        'cron':r'^cron$', 'archive':r'archive collected data|^archive via utility$',
        'history':r'clear command history',
    }
    return {tag for tag,pattern in patterns.items() if re.search(pattern,value)}
