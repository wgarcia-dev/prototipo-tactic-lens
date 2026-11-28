"""Cosine pgvector + English FTS with rank fusion, never attack probabilities."""
import json
import re
from collections import defaultdict
from functools import lru_cache
from sqlalchemy import text
from .behavior import behavior_label,represent,technique_profiles
from .embeddings import MODEL,REVISION,encoder
from .mitre_evidence import CONTRACTS, technique_evidence
from .pipeline import evidence_sample


def active_catalog(conn):
    row=conn.execute(text('SELECT id_catalogo,version,fuente,sha256 FROM honeypot.catalogo_mitre WHERE activo')).mappings().first()
    if not row:raise RuntimeError('Importe primero el catalogo MITRE oficial')
    return {**dict(row),'id_catalogo':str(row.id_catalogo)}


@lru_cache(maxsize=128)
def query_vector(query):return tuple(encoder().encode([query])[0])


def ready_embeddings(conn, catalog_id):
    params = {"model": MODEL + '@' + REVISION[:12], "catalog": str(catalog_id)}
    model_id = conn.scalar(text("SELECT id_modelo_embedding FROM honeypot.modelo_embedding WHERE proveedor='local-onnx-cpu' AND nombre_modelo=:model AND dimension=384"), params)
    if model_id is None:
        raise RuntimeError('Genere primero los embeddings del catalogo')
    availability = conn.execute(text('''SELECT count(*) total,
        count(*) FILTER(WHERE id_modelo_rag=CAST(:model_id AS uuid) AND embedding_rag IS NOT NULL) listos
        FROM honeypot.tecnica_mitre WHERE id_catalogo=CAST(:catalog AS uuid) AND NOT revocada AND NOT deprecada'''),
        {**params, "model_id": str(model_id)}).mappings().one()
    if not availability.total or availability.total != availability.listos:
        raise RuntimeError('Embeddings incompletos; finalice su generacion antes de analizar')
    return str(model_id)


def search(engine,query,k=12,encode=None,priority=()):
    k=max(1,min(int(k),40))
    vector=encode([query])[0] if encode else query_vector(query)
    if len(vector)!=384:raise ValueError('Dimension vectorial incorrecta')
    lexical_query=' OR '.join(dict.fromkeys(re.findall(r'[A-Za-z]{3,}',query)[:60]))
    params={'vector':json.dumps(vector),'query':lexical_query,'limit':max(40,k*3)}
    with engine.connect() as conn:
        catalog=active_catalog(conn);params['catalog']=catalog['id_catalogo']
        model_id=params['model_id']=ready_embeddings(conn, catalog['id_catalogo'])
        base="FROM honeypot.tecnica_mitre WHERE id_catalogo=CAST(:catalog AS uuid) AND NOT revocada AND NOT deprecada"
        dense=conn.execute(text('SELECT codigo_tecnica,1-(embedding_rag <=> CAST(:vector AS vector)) similitud '+base+
            ' AND id_modelo_rag=CAST(:model_id AS uuid) AND embedding_rag IS NOT NULL ORDER BY embedding_rag <=> CAST(:vector AS vector),codigo_tecnica LIMIT :limit'),params).mappings().all()
        lexical=conn.execute(text("""
            WITH q AS (SELECT websearch_to_tsquery('english',:query) AS terms),
            tactics AS (
                SELECT tt.codigo_tecnica, max(ts_rank_cd(to_tsvector('english',ta.nombre),q.terms)) AS relevancia
                FROM honeypot.tecnica_tactica tt JOIN honeypot.tactica_mitre ta USING(codigo_tactica) CROSS JOIN q
                WHERE tt.id_catalogo=CAST(:catalog AS uuid) AND tt.activa_en_catalogo
                  AND ta.id_catalogo=tt.id_catalogo AND NOT ta.revocada AND NOT ta.deprecada
                  AND to_tsvector('english',ta.nombre) @@ q.terms
                GROUP BY tt.codigo_tecnica
            )
            SELECT te.codigo_tecnica, ts_rank_cd(te.documento_busqueda,q.terms) +
                   coalesce(tactics.relevancia,0)*0.2 AS relevancia
            FROM honeypot.tecnica_mitre te LEFT JOIN tactics USING(codigo_tecnica) CROSS JOIN q
            WHERE te.id_catalogo=CAST(:catalog AS uuid) AND NOT te.revocada AND NOT te.deprecada
              AND (te.documento_busqueda @@ q.terms OR tactics.codigo_tecnica IS NOT NULL)
            ORDER BY relevancia DESC,te.codigo_tecnica LIMIT :limit
        """),params).mappings().all()
        if not dense:raise RuntimeError('No hay embeddings vigentes para el modelo configurado')
        scores={}
        for channel,rows in (('vectorial',dense),('lexico',lexical)):
            for rank,row in enumerate(rows,1):
                value=scores.setdefault(row.codigo_tecnica,{'codigo_tecnica':row.codigo_tecnica,'puntuacion_hibrida':0,'similitud_vectorial':None,'rangos':{}})
                value['puntuacion_hibrida']+=1/(60+rank);value['rangos'][channel]=rank
                if channel=='vectorial':value['similitud_vectorial']=float(row.similitud)
        selected=sorted(scores.values(),key=lambda r:(-r['puntuacion_hibrida'],r['codigo_tecnica']))[:k]
        selected_codes={item['codigo_tecnica'] for item in selected}
        # Preserve real evidence even when generic catalog descriptions dominate both open rankings.
        if remaining:=set(priority)-selected_codes:
            prioritized=conn.execute(text('SELECT codigo_tecnica,1-(embedding_rag <=> CAST(:vector AS vector)) similitud '+base+
                " AND codigo_tecnica=ANY(:priority) AND plataformas ? 'Linux' AND id_modelo_rag=CAST(:model_id AS uuid)"),
                {**params,'priority':sorted(remaining)}).mappings()
            for row in prioritized:
                selected.append(scores.get(row.codigo_tecnica,{
                    'codigo_tecnica':row.codigo_tecnica,'puntuacion_hibrida':0,
                    'similitud_vectorial':float(row.similitud),'rangos':{},
                }))
        selection={'codes':[r['codigo_tecnica'] for r in selected],'catalog':catalog['id_catalogo']}
        rows=conn.execute(text('SELECT codigo_tecnica,stix_id,nombre,descripcion,plataformas,version_attack,version_objeto,objeto_sha256,revocada,deprecada,es_subtecnica,tecnica_padre_id '+base+' AND codigo_tecnica=ANY(:codes)'),selection).mappings().all()
        definitions={r.codigo_tecnica:dict(r) for r in rows}
        tactics=defaultdict(list)
        for row in conn.execute(text('SELECT tt.codigo_tecnica,tt.codigo_tactica,ta.nombre FROM honeypot.tecnica_tactica tt JOIN honeypot.tactica_mitre ta USING(codigo_tactica) WHERE tt.codigo_tecnica=ANY(:codes) AND tt.activa_en_catalogo AND tt.id_catalogo=CAST(:catalog AS uuid) AND ta.id_catalogo=tt.id_catalogo AND NOT ta.revocada AND NOT ta.deprecada ORDER BY tt.codigo_tactica'),selection).mappings():
            tactics[row.codigo_tecnica].append({'codigo_tactica':row.codigo_tactica,'nombre':row.nombre})
        for item in selected:
            item.update(definitions[item['codigo_tecnica']]);item['definicion']=item.pop('descripcion')[:7000]
            item['puntuacion_hibrida']=round(item['puntuacion_hibrida'],7)
            item['tacticas']=tactics[item['codigo_tecnica']]
    return {'catalogo':catalog,'modelo':{'nombre':MODEL,'revision':REVISION,'dimension':384,'id_modelo':str(model_id)},'resultados':selected}


def select_candidates(candidates,limit=24):
    def rank(row):
        return ('Linux' not in row.get('plataformas',()), -row['puntuacion_hibrida'], row['codigo_tecnica'])

    ranked=sorted(candidates,key=rank)
    supported=[row for row in ranked if row.get('observabilidad')=='intento_evaluable']
    exploratory=[row for row in ranked if row.get('observabilidad')!='intento_evaluable']
    return supported+exploratory[:max(0,limit-len(supported))]


def context(engine,events,k=16,modality='desconocido',sample=None):
    behavior=represent(events,modality)
    delivered={event.id_evento for event in (evidence_sample(events,modality) if sample is None else sample)}
    evidence={code: {eid: grade for eid,grade in grades.items() if eid in delivered}
              for code,grades in technique_evidence(events,modality).items()}
    evidence={code: grades for code,grades in evidence.items() if grades}
    # Per-behavior retrieval prevents one strong action hiding other session actions.
    tags=list(dict.fromkeys([*(CONTRACTS[code].tag for code in evidence),*behavior['acciones']]))
    queries=[behavior['consulta_segura']]+[behavior_label(tag) for tag in tags[:12]]
    found={};reference=None
    for index,query in enumerate(queries):
        result=search(engine,query,k=k if index==0 else 4,priority=evidence if index==0 else ())
        if reference and result['catalogo'] != reference['catalogo']:
            raise RuntimeError('El catálogo cambió durante la recuperación')
        reference=result
        for candidate in result['resultados']:
            previous=found.get(candidate['codigo_tecnica'])
            if previous is None or candidate['puntuacion_hibrida']>previous['puntuacion_hibrida']:found[candidate['codigo_tecnica']]=candidate
    for code,candidate in found.items():
        contract=CONTRACTS.get(code)
        candidate['rasgos_compatibles']=[contract.tag] if contract else sorted(technique_profiles(candidate['nombre']))
        tactics=[t['codigo_tactica'] for t in candidate['tacticas']]
        candidate['tacticas_contrato']=[t for t in tactics if contract and (not contract.tactics or t in contract.tactics)]
        if not contract:
            candidate['observabilidad']='sin_contrato'
        elif modality not in contract.modes:
            candidate['observabilidad']='modalidad_incompatible'
        elif code in evidence and candidate['tacticas_contrato'] and 'Linux' in candidate['plataformas']:
            candidate['observabilidad']='intento_evaluable'
        else:
            candidate['observabilidad']='sin_evidencia_compatible'
    ordered=select_candidates(found.values(),limit=40)
    return {'metodo':'deepseek_rag_mitre_v1','catalogo':reference['catalogo'],'modelo_embeddings':reference['modelo'],
            'modalidad':modality,'representacion':behavior,'candidatos':ordered,'evidencia_mitre':evidence,
            'nota_puntuaciones':'Relevancia de recuperacion; no probabilidad ni confirmacion de ataque'}
