"""Generate reproducible local CPU embeddings; never reads captured events."""
import argparse,hashlib,json,time
from dotenv import load_dotenv
from sqlalchemy import select,text
from sqlalchemy.dialects.postgresql import insert
from backend.db import database_engine
from backend.rag.catalog import tables
from backend.rag.embeddings import MODEL,REVISION,encoder,prepare_model,catalog_text


def generate(engine):
    started=time.monotonic();model=encoder();t=tables(engine);te=t['tecnica_mitre'];mt=t['modelo_embedding']
    name=MODEL+'@'+REVISION[:12]
    with engine.begin() as conn:
        conn.execute(insert(mt).values(proveedor='local-onnx-cpu',nombre_modelo=name,dimension=384,configuracion=model.manifest)
            .on_conflict_do_nothing(index_elements=['proveedor','nombre_modelo']))
        registered=conn.execute(select(mt).where(mt.c.proveedor=='local-onnx-cpu',mt.c.nombre_modelo==name)).mappings().one()
        if registered.dimension!=384 or registered.configuracion!=model.manifest:raise RuntimeError('Registro del modelo incompatible con los artefactos verificados')
        mid=registered.id_modelo_embedding
        rows=conn.execute(select(te.c.codigo_tecnica,te.c.nombre,te.c.descripcion,te.c.embedding_rag_sha256,te.c.id_modelo_rag,te.c.objeto_sha256,te.c.id_catalogo,te.c.embedding_rag.is_(None).label('sin_vector'))
            .where(~te.c.revocada,~te.c.deprecada,te.c.id_catalogo==select(t['catalogo_mitre'].c.id_catalogo).where(t['catalogo_mitre'].c.activo).scalar_subquery())).mappings().all()
    pending=[]
    for row in rows:
        value=catalog_text(row.nombre,row.descripcion)
        digest=hashlib.sha256(value.encode()).hexdigest()
        if row.sin_vector or row.embedding_rag_sha256!=digest or row.id_modelo_rag!=mid:pending.append((row.codigo_tecnica,value,digest,row.objeto_sha256,row.id_catalogo))
    done=0
    for offset in range(0,len(pending),16):
        batch=pending[offset:offset+16];vectors=model.encode([r[1] for r in batch])
        with engine.begin() as conn:
            for (code,_,digest,source_hash,catalog_id),vector in zip(batch,vectors):
                changed=conn.execute(te.update().where(te.c.codigo_tecnica==code,te.c.objeto_sha256==source_hash,te.c.id_catalogo==catalog_id).values(embedding_rag=vector,id_modelo_rag=mid,embedding_rag_sha256=digest))
                if changed.rowcount!=1:raise RuntimeError('El catalogo cambio durante la generacion; vuelva a ejecutarla')
        done+=len(batch)
        if done%128==0:print(json.dumps({'embeddings_generados':done,'pendientes':len(pending)-done}),flush=True)
    with engine.begin() as conn:conn.execute(text('ANALYZE honeypot.tecnica_mitre'))
    return {'modelo':MODEL,'revision':REVISION,'dimension':384,'generados':done,'vigentes':len(rows),'segundos':round(time.monotonic()-started,2)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparar-modelo',action='store_true');args=parser.parse_args();load_dotenv()
    if args.preparar_modelo:print(json.dumps(prepare_model(),ensure_ascii=False),flush=True)
    engine=database_engine()
    try:print(json.dumps(generate(engine),ensure_ascii=False))
    finally:engine.dispose()

if __name__=='__main__':main()
