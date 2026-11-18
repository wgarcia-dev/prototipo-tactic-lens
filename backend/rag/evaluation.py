"""Retrieval metrics and offline model-comparison support; never calls an LLM."""
def recall_at_k(expected,retrieved,k):
    relevant=set(expected)
    return len(relevant.intersection(retrieved[:k]))/len(relevant) if relevant else None


def summarize(cases,predictions,ks=(5,10,20)):
    result={}
    for k in ks:
        values=[recall_at_k(case['esperados'],predictions.get(case['id'],[]),k) for case in cases]
        values=[v for v in values if v is not None]
        result[f'Recall@{k}']=round(sum(values)/len(values),4) if values else None
    return result


def comparison(dataset,baseline,rag):
    cases=dataset['casos']
    if not dataset.get('metadata',{}).get('independiente') or len(cases)<20 or sum(bool(c['esperados']) for c in cases)<10:
        return {'demostracion_mejora':False,'motivo':'Etiquetado independiente insuficiente; no se demuestra mejora DeepSeek frente a DeepSeek+RAG.'}
    if not baseline or not rag:
        return {'demostracion_mejora':False,'motivo':'Faltan predicciones de ambos pipelines para los mismos casos; no se consumen creditos automaticamente.'}
    if set(c['id'] for c in cases)-set(baseline) or set(c['id'] for c in cases)-set(rag):
        raise ValueError('Se requieren predicciones de ambos pipelines para todos los mismos casos')
    return {'demostracion_mejora':False,'anterior':{'recuperacion':summarize(cases,baseline),'clasificacion':classification_metrics(cases,baseline)},'rag':{'recuperacion':summarize(cases,rag),'clasificacion':classification_metrics(cases,rag)},
            'motivo':'Comparacion descriptiva; requiere revision de independencia y analisis estadistico antes de concluir mejora.'}


def classification_metrics(cases,predictions):
    tp=fp=fn=0;negatives=[]
    for case in cases:
        expected=set(case['esperados']);found=set(predictions.get(case['id'],[]))
        tp+=len(expected&found);fp+=len(found-expected);fn+=len(expected-found)
        if not expected:negatives.append(not found)
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    return {'precision_micro':precision,'recall_micro':recall,'f1_micro':2*precision*recall/(precision+recall) if precision+recall else 0,
            'abstencion_negativos':sum(negatives)/len(negatives) if negatives else None}
