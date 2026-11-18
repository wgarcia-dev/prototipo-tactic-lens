"""Version-pinned official STIX import, preserving relational IDs and history."""
import hashlib
import json
from pathlib import Path
import re
import urllib.request

from sqlalchemy import MetaData, Table, select, text, update
from sqlalchemy.dialects.postgresql import insert
from pgvector.sqlalchemy import VECTOR  # noqa: F401 register existing types

VERSION='20.1'
SOURCE='https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/enterprise-attack/enterprise-attack.json'
SHA256='539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5'


def tables(engine):
    meta=MetaData()
    return {name:Table(name,meta,schema='honeypot',autoload_with=engine) for name in
            ('catalogo_mitre','tactica_mitre','tecnica_mitre','tecnica_tactica','modelo_embedding')}


def download(path):
    path=Path(path)
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==SHA256:return path
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.part')
    try:
        digest=hashlib.sha256();total=0
        with urllib.request.urlopen(SOURCE,timeout=45) as response,temporary.open('wb') as stream:
            while chunk:=response.read(1048576):
                total+=len(chunk)
                if total>100_000_000:raise ValueError('Bundle demasiado grande')
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=SHA256:raise ValueError('La huella del STIX oficial no coincide con la version fijada')
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)
    return path


def parse(bundle):
    if bundle.get('type')!='bundle' or not isinstance(bundle.get('objects'),list):raise ValueError('STIX bundle requerido')
    tactics={};techniques={};ids={}
    for obj in bundle['objects']:
        kind=obj.get('type')
        if kind not in {'attack-pattern','x-mitre-tactic'}:continue
        refs=[r.get('external_id') for r in obj.get('external_references',[]) if r.get('source_name')=='mitre-attack']
        pattern=r'T\d{4}(?:\.\d{3})?' if kind=='attack-pattern' else r'TA\d{4}'
        codes=[c for c in refs if isinstance(c,str) and re.fullmatch(pattern,c)]
        if len(codes)!=1:raise ValueError('Objeto sin codigo ATT&CK unico')
        code=codes[0];target=techniques if kind=='attack-pattern' else tactics
        if code in target and target[code]['id']!=obj['id']:raise ValueError('Codigo ATT&CK ambiguo')
        target[code]=obj;ids[obj['id']]=code
    phases={o['x_mitre_shortname']:code for code,o in tactics.items()}
    parents={}
    for obj in bundle['objects']:
        if obj.get('type')=='relationship' and obj.get('relationship_type')=='subtechnique-of':
            child,parent=ids.get(obj.get('source_ref')),ids.get(obj.get('target_ref'))
            if child and parent:
                if child in parents and parents[child]!=parent:raise ValueError('Jerarquia ambigua')
                parents[child]=parent
    pairs=set()
    for code,obj in techniques.items():
        if obj.get('x_mitre_is_subtechnique') and code not in parents:
            # STIX 20.1 omits subtechnique-of links for 16 revoked objects.
            # Preserve their numbered parent explicitly marked as a legacy
            # derivation, never pretend that an absent STIX relationship exists.
            parent=code.split('.')[0]
            if obj.get('revoked') and '.' in code and parent in techniques:parents[code]=parent
            else:raise ValueError('Subtecnica vigente sin padre STIX')
        for phase in obj.get('kill_chain_phases',[]):
            if phase.get('kill_chain_name')=='mitre-attack':
                if phase.get('phase_name') not in phases:raise ValueError('Tactica desconocida en STIX')
                pairs.add((code,phases[phase['phase_name']]))
    if not techniques or not tactics:raise ValueError('Catalogo vacio')
    return tactics,techniques,parents,pairs


def import_catalog(engine,path,expected_sha=SHA256):
    raw=Path(path).read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=expected_sha:raise ValueError('Checksum STIX incorrecto')
    bundle=json.loads(raw)
    tactics,techniques,parents,pairs=parse(bundle)
    direct_children={o['source_ref'] for o in bundle['objects'] if o.get('type')=='relationship' and o.get('relationship_type')=='subtechnique-of'}
    t=tables(engine);cat,ta,te,tt=(t[n] for n in ('catalogo_mitre','tactica_mitre','tecnica_mitre','tecnica_tactica'))
    counts={'tacticas':len(tactics),'tecnicas_y_subtecnicas':len(techniques),'subtecnicas':len(parents),
            'relaciones_tacticas':len(pairs),'revocadas':sum(bool(o.get('revoked')) for o in techniques.values()),
            'deprecadas':sum(bool(o.get('x_mitre_deprecated')) for o in techniques.values()),
            'jerarquias_revocadas_derivadas':sum(techniques[c]['id'] not in direct_children for c in parents)}
    with engine.begin() as conn:
        conn.execute(text('SELECT pg_advisory_xact_lock(724610902)'))
        old=conn.execute(select(cat).where(cat.c.dominio=='enterprise-attack',cat.c.version==VERSION)).mappings().first()
        if old and old.sha256!=digest:raise ValueError('La version ya tiene otra procedencia; revise antes de reemplazar')
        conn.execute(cat.update().values(activo=False))
        if old:
            catalog_id=old.id_catalogo
            conn.execute(cat.update().where(cat.c.id_catalogo==catalog_id).values(activo=True))
        else:
            catalog_id=conn.scalar(insert(cat).values(dominio='enterprise-attack',version=VERSION,fuente=SOURCE,sha256=digest,activo=True,conteos=counts).returning(cat.c.id_catalogo))
        for code,obj in tactics.items():
            values={'codigo_tactica':code,'stix_id':obj['id'],'nombre':obj['name'],'descripcion':obj.get('description',''),
                    'version_attack':VERSION,'version_objeto':obj.get('x_mitre_version'),'id_catalogo':catalog_id,
                    'revocada':bool(obj.get('revoked')),'deprecada':bool(obj.get('x_mitre_deprecated'))}
            base=insert(ta).values(**values)
            conn.execute(base.on_conflict_do_update(index_elements=['codigo_tactica'],set_={k:v for k,v in values.items() if k!='codigo_tactica'}))
        # Parents first; IDs/relations from earlier analyses are never removed.
        for code in sorted(techniques,key=lambda c:('.' in c,c)):
            obj=techniques[code]
            object_hash=hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
            values={'codigo_tecnica':code,'tecnica_padre_id':parents.get(code),'stix_id':obj['id'],'nombre':obj['name'],
                    'descripcion':obj.get('description',''),'version_attack':VERSION,'version_objeto':obj.get('x_mitre_version'),
                    'plataformas':obj.get('x_mitre_platforms',[]),'revocada':bool(obj.get('revoked')),
                    'es_subtecnica':bool(obj.get('x_mitre_is_subtechnique')),
                    'jerarquia_fuente':('stix' if obj['id'] in direct_children else 'codigo_revocado') if code in parents else None,
                    'deprecada':bool(obj.get('x_mitre_deprecated')),'id_catalogo':catalog_id,'objeto_sha256':object_hash}
            previous=conn.execute(select(te.c.objeto_sha256).where(te.c.codigo_tecnica==code)).first()
            if previous and previous[0]!=object_hash:
                values.update(embedding_rag=None,id_modelo_rag=None,embedding_rag_sha256=None)
            base=insert(te).values(**values)
            conn.execute(base.on_conflict_do_update(index_elements=['codigo_tecnica'],set_={k:v for k,v in values.items() if k!='codigo_tecnica'}))
        conn.execute(tt.update().values(activa_en_catalogo=False))
        for code,tactic in sorted(pairs):
            base=insert(tt).values(codigo_tecnica=code,codigo_tactica=tactic,id_catalogo=catalog_id,activa_en_catalogo=True)
            conn.execute(base.on_conflict_do_update(index_elements=['codigo_tecnica','codigo_tactica'],
                set_={'id_catalogo':catalog_id,'activa_en_catalogo':True}))
    return {'id_catalogo':str(catalog_id),'version':VERSION,'sha256':digest,**counts}
