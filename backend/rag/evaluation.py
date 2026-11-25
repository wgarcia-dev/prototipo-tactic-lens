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
    expected_codes, correct_codes = set(), set()
    for case in cases:
        expected=set(case['esperados']);found=set(predictions.get(case['id'],[]))
        expected_codes.update(expected)
        correct_codes.update(expected & found)
        tp+=len(expected&found);fp+=len(found-expected);fn+=len(expected-found)
        if not expected:negatives.append(not found)
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    return {'verdaderos_positivos':tp,'falsos_positivos':fp,'falsos_negativos':fn,
            'tecnicas_esperadas_distintas':len(expected_codes),'tecnicas_detectadas_distintas':len(correct_codes),
            'cobertura_tecnicas_esperadas':len(correct_codes)/len(expected_codes) if expected_codes else None,
            'precision_micro':precision,'recall_micro':recall,'f1_micro':2*precision*recall/(precision+recall) if precision+recall else 0,
            'abstencion_negativos':sum(negatives)/len(negatives) if negatives else None}


def evaluate_independent(dataset, results):
    """Evaluate final accepted codes by case. Technical failures never count as abstentions."""
    metadata = dataset.get('metadata', {})
    if metadata.get('independiente') is not True or not str(metadata.get('origen') or '').strip():
        raise ValueError('Se requiere etiquetado independiente con procedencia declarada')
    cases = dataset['casos']
    ids = {case['id'] for case in cases}
    if not cases or len(ids) != len(cases) or ids != results.keys():
        raise ValueError('Las predicciones deben cubrir exactamente los casos únicos del conjunto')
    predictions, failed, abstained = {}, set(), set()
    for case in cases:
        case_id = case['id']
        row = results[case_id]
        codes = row['identificadas']
        state = row['estado']
        if not isinstance(codes,list) or not isinstance(case['esperados'],list):
            raise ValueError(f'Los códigos deben proporcionarse como listas en {case_id}')
        if state not in {'completado','fallido'} or state == 'fallido' and codes:
            raise ValueError(f'Estado o identificaciones incompatibles en {case_id}')
        predictions[case_id] = codes
        if state == 'fallido':
            failed.add(case_id)
        elif not codes:
            abstained.add(case_id)
    metrics = classification_metrics(cases,predictions)
    negatives = {case['id'] for case in cases if not case['esperados']}
    metrics['abstencion_negativos'] = len(negatives & abstained)/len(negatives) if negatives else None
    return {**metrics, 'sesiones':len(cases),'abstenciones':len(abstained),'fallos_tecnicos':len(failed),
            'origen_etiquetas':metadata['origen']}
