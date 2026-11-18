"""Measure Recall@K with local retrieval. No DeepSeek calls or credits consumed."""
import argparse,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
from dotenv import load_dotenv
from backend.db import database_engine
from backend.rag.retrieval import context
from backend.rag.evaluation import comparison,summarize


def evaluate(engine,dataset):
    predictions={};details=[]
    for case in dataset['casos']:
        events=[];start=datetime(2026,11,16,tzinfo=timezone.utc)
        rows=[('cowrie.login.failed',{}) for _ in range(case.get('fallos_auth',0))]
        rows += [('cowrie.command.input',{'input':cmd}) for cmd in case.get('comandos',[])]
        for index,(kind,raw) in enumerate(rows,1):events.append(SimpleNamespace(id_evento=index,tipo_evento=kind,datos_originales=raw,fecha_hora=start+timedelta(seconds=index)))
        result=context(engine,events);codes=[c['codigo_tecnica'] for c in result['candidatos']]
        predictions[case['id']]=codes
        details.append({'id':case['id'],'esperados':case['esperados'],'recuperados':codes[:20]})
    return {'metadata':dataset['metadata'],'casos':len(dataset['casos']),'casos_con_relevantes':sum(bool(c['esperados']) for c in dataset['casos']),
            'metricas_desarrollo':summarize(dataset['casos'],predictions),'comparacion':comparison(dataset,{},{}),
            'resultados':details,'nota':'Recall mide recuperacion, no exactitud de clasificacion ni probabilidad de ataque.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset',type=Path,default=Path('tests/fixtures/rag_retrieval_dev.json'))
    p.add_argument('--salida',type=Path,default=Path('.local/rag/evaluacion_desarrollo.json'))
    p.add_argument('--predicciones-anterior',type=Path);p.add_argument('--predicciones-rag',type=Path)
    args=p.parse_args();load_dotenv();dataset=json.loads(args.dataset.read_text(encoding='utf-8'))
    engine=database_engine()
    try:result=evaluate(engine,dataset)
    finally:engine.dispose()
    if args.predicciones_anterior and args.predicciones_rag:
        result['comparacion']=comparison(dataset,json.loads(args.predicciones_anterior.read_text(encoding='utf-8')),json.loads(args.predicciones_rag.read_text(encoding='utf-8')))
    args.salida.parent.mkdir(parents=True,exist_ok=True);args.salida.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='resultados'},ensure_ascii=False))

if __name__=='__main__':main()
