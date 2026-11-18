"""Read-only verification before/after the explicitly authorized single UI analysis."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import json
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine
from scripts.prepare_deepseek_trial import ROOT,digest,privacy_check,snapshot


def verify(engine,directory):
    directory=Path(directory).resolve()
    if not directory.is_relative_to((ROOT/'.local').resolve()):raise ValueError('Utilice el manifiesto privado de .local/')
    original=json.loads((directory/'preflight.json').read_text(encoding='utf-8'))
    session=original['sesion']
    with engine.connect() as conn:
        conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        current=snapshot(conn,session);preserved={}
        for name,before in original['baseline']['tablas'].items():
            missing=Counter(before['hashes'])-Counter(current['tablas'][name]['hashes'])
            preserved[name]={'originales':before['filas'],'faltantes_o_modificados':sum(missing.values()),
                'filas_actuales':current['tablas'][name]['filas']}
        events=conn.execute(text('SELECT id_evento,tipo_evento,fecha_hora,datos_originales FROM honeypot.evento WHERE id_sesion=CAST(:sid AS uuid) ORDER BY fecha_hora,id_evento'),{'sid':session}).all()
        events_equal=digest([dict(row._mapping) for row in events])==original['eventos_sha256']
        old_ids={row['id_analisis'] for row in original['baseline']['analisis_sesion']}
        added=[row for row in current['analisis_sesion'] if str(row['id_analisis']) not in old_ids]
        result={'fecha':datetime.now(timezone.utc).isoformat(),'sesion':session,'historia':preserved,
                'snapshot_eventos_sin_cambios':events_equal,'analisis_nuevos_sesion':len(added),
                'parejas_mapeo_duplicadas':current['parejas_mapeo_duplicadas'],'chat_completions_ejecutado_por_verificador':False}
        if not added:result['estado_ensayo']='Sin ejecutar; no se ha creado otro analisis de esta sesion'
        elif len(added)==1:
            row=conn.execute(text('SELECT id_analisis,estado,resumen,resultado_estructurado FROM honeypot.analisis_llm WHERE id_analisis=:id'),{'id':added[0]['id_analisis']}).mappings().one()
            payload=row['resultado_estructurado'] or {};rag=payload.get('rag') or {}
            mappings=[dict(r) for r in conn.execute(text('''SELECT m.id_mapeo,tt.codigo_tecnica,tt.codigo_tactica,m.evidencia,
                m.justificacion,m.estado_revision,m.grado_evidencia,m.rag_procedencia
                FROM honeypot.mapeo_mitre m JOIN honeypot.accion_identificada a USING(id_accion)
                JOIN honeypot.tecnica_tactica tt USING(id_vinculo) WHERE a.id_analisis=:id ORDER BY m.id_mapeo'''),{'id':row['id_analisis']}).mappings()]
            details={'id_analisis':str(row['id_analisis']),'estado':row['estado'],'resumen':row['resumen'],
                'acciones':payload.get('acciones',[]),'informe':payload.get('informe'),
                'mapeos':mappings,'descartes':payload.get('mapeos_descartados',[]),'respuesta_proveedor':rag.get('respuesta_proveedor')}
            privacy_check(details,events)
            result.update(estado_ensayo=row['estado'],id_analisis=str(row['id_analisis']),
                metodo=rag.get('metodo'),mapeos=len(mappings),
                todos_mapeos_pendientes=all(m['estado_revision']=='pendiente' for m in mappings),
                mismo_catalogo=rag.get('catalogo',{}).get('sha256')==original['catalogo']['sha256'],
                mismo_modelo=rag.get('modelo_llm',{}).get('modelo')==original['configuracion']['modelo'],
                misma_solicitud=rag.get('solicitud_sha256')==original['payload_sha256'],
                respuesta_proveedor=rag.get('respuesta_proveedor'))
            with (directory/'resultado-revisable.json').open('w',encoding='utf-8') as stream:json.dump(details,stream,ensure_ascii=False,indent=2,default=str)
        else:result['estado_ensayo']='Revisar: hay mas de un analisis nuevo; no ejecutar mas llamadas'
    result['integridad_correcta']=events_equal and not any(r['faltantes_o_modificados'] for r in preserved.values()) and current['parejas_mapeo_duplicadas']==0 and len(added)<=1
    if added:result['integridad_correcta']=result['integridad_correcta'] and result.get('estado_ensayo')=='completado' and result.get('metodo')=='deepseek_rag_mitre_v1' and result.get('todos_mapeos_pendientes') and result.get('mismo_catalogo') and result.get('mismo_modelo') and result.get('misma_solicitud')
    with (directory/'verificacion.json').open('w',encoding='utf-8') as stream:json.dump(result,stream,ensure_ascii=False,indent=2,default=str)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=ROOT/'.local/rag/ensayo-controlado')
    args=parser.parse_args();load_dotenv(ROOT/'.env');engine=database_engine()
    try:result=verify(engine,args.directory)
    finally:engine.dispose()
    print(json.dumps(result,ensure_ascii=False,indent=2,default=str))
    if not result['integridad_correcta']:raise SystemExit(1)


if __name__=='__main__':main()
