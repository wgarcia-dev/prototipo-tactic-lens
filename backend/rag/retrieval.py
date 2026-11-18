"""Cosine pgvector + English FTS with rank fusion, never attack probabilities."""
import json
import re
from functools import lru_cache
from sqlalchemy import text
from .behavior import LABELS,represent,technique_profiles
from .embeddings import MODEL,REVISION,encoder


def active_catalog(conn):
    row=conn.execute(text('SELECT id_catalogo,version,fuente,sha256 FROM honeypot.catalogo_mitre WHERE activo')).mappings().first()
    if not row:raise RuntimeError('Importe primero el catalogo MITRE oficial')
    return {**dict(row),'id_catalogo':str(row.id_catalogo)}


@lru_cache(maxsize=128)
def query_vector(query):return tuple(encoder().encode([query])[0])


def search(engine,query,k=12,encode=None):
    k=max(1,min(int(k),40))
    vector=encode([query])[0] if encode else query_vector(query)
    if len(vector)!=384:raise ValueError('Dimension vectorial incorrecta')
    lexical_query=' OR '.join(dict.fromkeys(re.findall(r'[A-Za-z]{3,}',query)[:60]))
    params={'vector':json.dumps(vector),'query':lexical_query,'limit':max(40,k*3),'model':MODEL+'@'+REVISION[:12]}
    with engine.connect() as conn:
        catalog=active_catalog(conn);params['catalog']=catalog['id_catalogo']
        model_id=conn.scalar(text("SELECT id_modelo_embedding FROM honeypot.modelo_embedding WHERE proveedor='local-onnx-cpu' AND nombre_modelo=:model AND dimension=384"),params)
        if model_id is None:raise RuntimeError('Genere primero los embeddings del catalogo')
        params['model_id']=str(model_id)
        availability=conn.execute(text('SELECT count(*) total,count(*) FILTER(WHERE id_modelo_rag=CAST(:model_id AS uuid) AND embedding_rag IS NOT NULL) listos FROM honeypot.tecnica_mitre WHERE id_catalogo=CAST(:catalog AS uuid) AND NOT revocada AND NOT deprecada'),params).mappings().one()
        if availability.total!=availability.listos:raise RuntimeError('Embeddings incompletos; finalice su generacion antes de analizar')
        base="FROM honeypot.tecnica_mitre WHERE id_catalogo=CAST(:catalog AS uuid) AND NOT revocada AND NOT deprecada"
        dense=conn.execute(text('SELECT codigo_tecnica,1-(embedding_rag <=> CAST(:vector AS vector)) similitud '+base+
            ' AND id_modelo_rag=CAST(:model_id AS uuid) AND embedding_rag IS NOT NULL ORDER BY embedding_rag <=> CAST(:vector AS vector),codigo_tecnica LIMIT :limit'),params).mappings().all()
        lexical=conn.execute(text("SELECT codigo_tecnica,ts_rank_cd(documento_busqueda,websearch_to_tsquery('english',:query)) relevancia "+base+
            " AND documento_busqueda @@ websearch_to_tsquery('english',:query) ORDER BY relevancia DESC,codigo_tecnica LIMIT :limit"),params).mappings().all()
        if not dense:raise RuntimeError('No hay embeddings vigentes para el modelo configurado')
        scores={}
        for channel,rows in (('vectorial',dense),('lexico',lexical)):
            for rank,row in enumerate(rows,1):
                value=scores.setdefault(row.codigo_tecnica,{'codigo_tecnica':row.codigo_tecnica,'puntuacion_hibrida':0,'similitud_vectorial':None,'rangos':{}})
                value['puntuacion_hibrida']+=1/(60+rank);value['rangos'][channel]=rank
                if channel=='vectorial':value['similitud_vectorial']=float(row.similitud)
        selected=sorted(scores.values(),key=lambda r:(-r['puntuacion_hibrida'],r['codigo_tecnica']))[:k]
        rows=conn.execute(text('SELECT codigo_tecnica,stix_id,nombre,descripcion,plataformas,version_attack,version_objeto,objeto_sha256 FROM honeypot.tecnica_mitre WHERE codigo_tecnica=ANY(:codes)'),{'codes':[r['codigo_tecnica'] for r in selected]}).mappings().all()
        definitions={r.codigo_tecnica:dict(r) for r in rows}
        for item in selected:
            item.update(definitions[item['codigo_tecnica']]);item['definicion']=item.pop('descripcion')[:7000]
            item['puntuacion_hibrida']=round(item['puntuacion_hibrida'],7)
            item['rasgos_compatibles']=sorted(technique_profiles(item['nombre']))
            item['observabilidad']='intento_evaluable' if item['rasgos_compatibles'] and ('Linux' in item['plataformas'] or 'Network Devices' in item['plataformas']) else 'no_evaluable_con_cobertura_actual'
            item['tacticas']=[dict(r) for r in conn.execute(text('SELECT tt.codigo_tactica,ta.nombre FROM honeypot.tecnica_tactica tt JOIN honeypot.tactica_mitre ta USING(codigo_tactica) WHERE tt.codigo_tecnica=:code AND tt.activa_en_catalogo AND tt.id_catalogo=CAST(:catalog AS uuid) ORDER BY tt.codigo_tactica'),{'code':item['codigo_tecnica'],'catalog':catalog['id_catalogo']}).mappings()]
    return {'catalogo':catalog,'modelo':{'nombre':MODEL,'revision':REVISION,'dimension':384,'id_modelo':str(model_id)},'resultados':selected}


def context(engine,events,k=16):
    behavior=represent(events)
    # Per-behavior retrieval prevents one strong action hiding other session actions.
    queries=[behavior['consulta_segura']]+[LABELS[tag] for tag in behavior['acciones'][:12]]
    if any('shell' in tags for tags in behavior['rasgos_por_evento'].values()):queries.append(LABELS['shell'])
    found={};reference=None
    for index,query in enumerate(queries):
        result=search(engine,query,k=k if index==0 else 4);reference=result
        for candidate in result['resultados']:
            previous=found.get(candidate['codigo_tecnica'])
            if previous is None or candidate['puntuacion_hibrida']>previous['puntuacion_hibrida']:found[candidate['codigo_tecnica']]=candidate
    ordered=sorted(found.values(),key=lambda r:(-r['puntuacion_hibrida'],r['codigo_tecnica']))[:40]
    return {'metodo':'deepseek_rag_mitre_v1','catalogo':reference['catalogo'],'modelo_embeddings':reference['modelo'],
            'representacion':behavior,'candidatos':ordered,'nota_puntuaciones':'Relevancia de recuperacion; no probabilidad ni confirmacion de ataque'}
