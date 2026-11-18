"""Read-only trial preparation. Never calls chat/completions or writes PostgreSQL."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
import os
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine
from backend.rag.pipeline import evidence_sample
from backend.rag.retrieval import context
from backend.routes import real_result

SESSION='b100f403-1495-486b-88ee-26f9357681ab'
ROOT=Path(__file__).resolve().parents[1]
TABLES=('sesion','evento','analisis_llm','accion_identificada','accion_evento','mapeo_mitre')
PRICING_SOURCE='https://api-docs.deepseek.com/quick_start/pricing/'


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()


def configuration():
    provider=os.getenv('LLM_PROVIDER','');model=os.getenv('LLM_MODEL','')
    base=(os.getenv('LLM_BASE_URL') or '').rstrip('/');url=urlsplit(base)
    if provider.lower()!='deepseek' or url.scheme!='https' or url.hostname!='api.deepseek.com' or url.port not in (None,443) or url.username or url.password or url.query or url.fragment or url.path not in ('','/v1'):
        raise ValueError('Proveedor/origen no corresponde al HTTPS oficial de DeepSeek')
    if not model or not os.getenv('LLM_API_KEY'):raise ValueError('Falta modelo o clave configurada')
    return {'proveedor':provider,'modelo':model,'base_url':base}


def availability(config):
    # Metadata request only. No prompts, events, generation, retries or balance lookup.
    try:
        response=httpx.get(config['base_url']+'/models',headers={'Authorization':'Bearer '+os.environ['LLM_API_KEY']},
                           timeout=20,follow_redirects=False)
        found=response.json().get('data',[]) if response.status_code==200 else []
        available=any(row.get('id')==config['modelo'] and row.get('owned_by')=='deepseek' for row in found)
        return {'http':response.status_code,'modelo_disponible':available,'tipo_peticion':'GET /models',
                'generacion_comprobada':False}
    except (httpx.HTTPError,ValueError) as exc:
        return {'modelo_disponible':False,'error_seguro':type(exc).__name__,'generacion_comprobada':False}


def capture_payload(events,rag):
    class Captured(Exception):pass
    captured={}
    def intercept(*args,**kwargs):
        captured.update(kwargs['json'])  # Never retain Authorization or the API key.
        raise Captured()
    with patch('backend.routes.httpx.post',side_effect=intercept):
        try:real_result(events,rag)
        except Captured:pass
    if not captured:raise RuntimeError('No se pudo preparar el payload')
    return captured


def privacy_check(payload,events):
    secrets=set()
    def collect(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if isinstance(item,str) and len(item)>=4 and any(part in key.lower() for part in
                    ('password','passwd','passphrase','token','secret','credential','authorization','api_key')):
                    secrets.add(item)
                else:collect(item)
        elif isinstance(value,list):
            for item in value:collect(item)
    for event in events:collect(event.datos_originales)
    for key,value in os.environ.items():
        if len(value)>=8 and any(part in key for part in ('PASSWORD','SECRET','API_KEY','TOTP_KEYS')):secrets.add(value)
    serialized=json.dumps(payload,ensure_ascii=False,default=str)
    if any(secret in serialized for secret in secrets):raise ValueError('El contexto contiene un secreto conocido; no guardar ni transmitir')
    return {'secretos_conocidos_detectados':0,'campos_credencial_redactados':True,
            'alcance':'Campos sensibles, sus copias conocidas y patrones de redaccion; no es garantia universal frente a secretos desconocidos'}


def estimate(payload,model):
    # Pricing snapshot verified in official docs on 2026-11-16. Peak/cache-miss
    # scenarios intentionally ignore cache discounts and off-peak savings.
    rates={'deepseek-v4-pro':(1.32,3.96),'deepseek-flash':(0.30,1.20)}
    if model not in rates:raise ValueError('Revisar manualmente la tarifa del modelo antes de estimar')
    messages=json.dumps(payload['messages'],ensure_ascii=False)
    chars=len(messages);size=len(messages.encode());input_rate,output_rate=rates[model]
    low=math.ceil(chars*0.3)+256;high=math.ceil(chars*0.5)+256
    byte_scenario=size+1024
    return {'moneda':'USD','fuente':PRICING_SOURCE,'tarifa_verificada':'2026-11-16',
            'entrada_por_millon_sin_cache_hora_pico':input_rate,'salida_por_millon_hora_pico':output_rate,
            'caracteres_messages':chars,'bytes_messages':size,'tokens_entrada_aproximados':[low,high],
            'tokens_salida_escenario':[2000,4000],'max_tokens_configurado':payload['max_tokens'],
            'costo_estimado_usd':[round((low*input_rate+2000*output_rate)/1e6,5),round((high*input_rate+4000*output_rate)/1e6,5)],
            'escenario_conservador_usd':round((byte_scenario*input_rate+payload['max_tokens']*output_rate)/1e6,5),
            'nota':'Estimacion sin tokenizador exacto del modelo; no es tope contractual. El costo real requiere usage del proveedor.'}


def snapshot(conn,session):
    # Full original row hashes, not original content or historical summaries.
    tables={}
    for name in TABLES:
        rows=conn.execute(text('SELECT md5(row_to_json(r)::text) h FROM honeypot.'+name+' r ORDER BY 1')).scalars().all()
        tables[name]={'filas':len(rows),'hashes':rows}
    analyses=[dict(row) for row in conn.execute(text('SELECT id_analisis,estado,resultado_estructurado->\'rag\'->>\'metodo\' metodo FROM honeypot.analisis_llm WHERE id_sesion=CAST(:sid AS uuid) ORDER BY creado_en'),{'sid':session}).mappings()]
    duplicates=conn.scalar(text('SELECT count(*) FROM (SELECT id_accion,id_vinculo FROM honeypot.mapeo_mitre GROUP BY id_accion,id_vinculo HAVING count(*)>1) d'))
    return {'tablas':tables,'analisis_sesion':analyses,'parejas_mapeo_duplicadas':duplicates}


def prepare(engine,session,directory,check_provider=False):
    directory=Path(directory).resolve()
    if not directory.is_relative_to((ROOT/'.local').resolve()):raise ValueError('Guardar artefactos exclusivamente dentro de .local/ ignorada')
    if any((directory/name).exists() for name in ('payload.json','preflight.json')):raise ValueError('Ya existe el ensayo; verificarlo o utilizar otro directorio privado sin reemplazar el original')
    config=configuration()
    with engine.connect() as conn:
        conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        exists=conn.scalar(text('SELECT id_sesion FROM honeypot.sesion WHERE id_sesion=CAST(:sid AS uuid) AND id_honeypot=CAST(:hp AS uuid)'),{'sid':session,'hp':os.environ['HONEYPOT_ID']})
        if not exists:raise ValueError('Sesion no pertenece al sensor configurado')
        events=conn.execute(text('SELECT id_evento,tipo_evento,fecha_hora,datos_originales FROM honeypot.evento WHERE id_sesion=CAST(:sid AS uuid) ORDER BY fecha_hora,id_evento'),{'sid':session}).all()
        before=snapshot(conn,session)
        events_sha=digest([dict(row._mapping) for row in events])
    if not events:raise ValueError('Sesion sin eventos')
    rag=context(engine,events);rag['candidatos']=rag['candidatos'][:24]
    rag.update(modelo_llm={'proveedor':config['proveedor'],'modelo':config['modelo']},
               eventos_entregados=[event.id_evento for event in evidence_sample(events)],eventos_snapshot=len(events))
    payload=capture_payload(events,rag);privacy=privacy_check(payload,events)
    report={'creado_en':datetime.now(timezone.utc).isoformat(),'sesion':session,'eventos':len(events),
            'eventos_sha256':events_sha,'eventos_entregados':rag['eventos_entregados'],
            'configuracion':config,'catalogo':rag['catalogo'],'candidatos':len(rag['candidatos']),
            'codigos_candidatos':[row['codigo_tecnica'] for row in rag['candidatos']],
            'privacidad':privacy,'costo':estimate(payload,config['modelo']),'payload_sha256':digest(payload),
            'proveedor':availability(config) if check_provider else {'comprobacion':'No solicitada'},
            'chat_completions_ejecutado':False,'baseline':before}
    directory.mkdir(parents=True,exist_ok=True)
    # Exclusive creation: never replace the approval snapshot with another trial.
    for name,value in (('payload.json',payload),('preflight.json',report)):
        with (directory/name).open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2,default=str)
    return {key:value for key,value in report.items() if key!='baseline'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session',type=UUID,default=UUID(SESSION))
    p.add_argument('--directory',type=Path,default=ROOT/'.local/rag/ensayo-controlado')
    p.add_argument('--check-provider',action='store_true')
    args=p.parse_args();load_dotenv(ROOT/'.env');engine=database_engine()
    try:report=prepare(engine,str(args.session),args.directory,args.check_provider)
    finally:engine.dispose()
    print(json.dumps(report,ensure_ascii=False,indent=2,default=str))


if __name__=='__main__':main()
