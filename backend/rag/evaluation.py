"""Retrieval metrics and offline model-comparison support; never calls an LLM."""

from collections import Counter, defaultdict


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


def evaluate_independent(dataset, results, techniques=()):
    """Evaluate final accepted codes by case. Technical failures never count as abstentions."""
    metadata = dataset.get('metadata', {})
    if metadata.get('independiente') is not True or not str(metadata.get('origen') or '').strip():
        raise ValueError('Se requiere etiquetado independiente con procedencia declarada')
    cases = dataset['casos']
    ids = {case['id'] for case in cases}
    if not cases or len(ids) != len(cases) or ids != results.keys():
        raise ValueError('Las predicciones deben cubrir exactamente los casos únicos del conjunto')
    predictions, failed, abstained = {}, set(), set()
    per_mode = defaultdict(list)
    per_code = defaultdict(Counter)
    per_tactic = defaultdict(Counter)
    catalog = {row['codigo']: row for row in techniques}
    hierarchy_duplicates = 0
    retrieval_cases = validation_cases = retrieval_errors = validation_errors = 0
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
        per_mode[case.get('modalidad', 'desconocido')].append(case)
        expected, identified = set(case['esperados']), set(codes)
        for code in expected | identified:
            outcome = ('tp' if code in expected and code in identified else 'fn' if code in expected else 'fp')
            per_code[code][outcome] += 1
            for tactic in catalog.get(code, {}).get('tacticas', ()):
                per_tactic[tactic['codigo']][outcome] += 1
        hierarchy_duplicates += sum(catalog.get(code, {}).get('padre') in identified for code in identified)
        if state == 'completado' and 'recuperadas' in row:
            if not isinstance(row['recuperadas'], list):
                raise ValueError(f'La recuperación debe proporcionarse como lista en {case_id}')
            retrieval_cases += 1
            retrieval_errors += len(expected - set(row['recuperadas']))
        if state == 'completado' and 'propuestas' in row:
            if not isinstance(row['propuestas'], list):
                raise ValueError(f'Las propuestas deben proporcionarse como lista en {case_id}')
            validation_cases += 1
            validation_errors += len((expected & set(row['propuestas'])) - identified)
        if state == 'fallido':
            failed.add(case_id)
        elif not codes:
            abstained.add(case_id)
    metrics = classification_metrics(cases,predictions)
    negatives = {case['id'] for case in cases if not case['esperados']}
    metrics['abstencion_negativos'] = len(negatives & abstained)/len(negatives) if negatives else None
    return {**metrics, 'sesiones':len(cases),'abstenciones':len(abstained),'fallos_tecnicos':len(failed),
            'origen_etiquetas':metadata['origen'],
            'por_modalidad': {mode: {**classification_metrics(group, predictions),
                'abstenciones': sum(case['id'] in abstained for case in group),
                'fallos_tecnicos': sum(case['id'] in failed for case in group)} for mode, group in per_mode.items()},
            'por_tecnica': {code: counts for code,counts in sorted(per_code.items())},
            'por_tactica_catalogo': {code: counts for code,counts in sorted(per_tactic.items())} if catalog else None,
            'duplicaciones_padre_subtecnica_por_sesion': hierarchy_duplicates if catalog else None,
            'casos_con_recuperacion': retrieval_cases, 'errores_recuperacion': retrieval_errors if retrieval_cases else None,
            'casos_con_propuestas': validation_cases, 'omisiones_en_validacion': validation_errors if validation_cases else None}


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def evaluate_corpus(cases, results):
    """Compute metrics for each stage over matching case IDs and frozen labels."""
    if not cases or len(cases) != len({case["id"] for case in cases}) or {case["id"] for case in cases} != results.keys():
        raise ValueError("Se requieren filas de resultado para los mismos casos únicos del corpus")
    successful = [case for case in cases if results[case["id"]]["estado"] == "completado"]
    local = [case for case in cases if results[case["id"]].get("estado_local", results[case["id"]]["estado"]) == "completado"]
    total = len(cases)

    def set_stage(field, expected):
        selected = [case for case in (successful if field == "identificadas" else local)
                    if results[case["id"]].get(field) is not None]
        if not selected:
            return None
        labels = [{"id": case["id"], "esperados": expected(case)} for case in selected]
        predictions = {case["id"]: results[case["id"]][field] for case in selected}
        metrics = classification_metrics(labels, predictions)
        metrics["etiquetas_esperadas_distintas"] = metrics.pop("tecnicas_esperadas_distintas")
        metrics["etiquetas_detectadas_distintas"] = metrics.pop("tecnicas_detectadas_distintas")
        metrics["cobertura_etiquetas_esperadas"] = metrics.pop("cobertura_tecnicas_esperadas")
        exact = sum(set(row["esperados"]) == set(predictions[row["id"]]) for row in labels)
        return {**metrics, "casos": len(selected), "accuracy_conjunto_exacto": ratio(exact, len(selected))}

    wanted_mitre = lambda case: [item["codigo"] for item in case["mitre_esperadas"]]
    retrieval_cases = [case for case in local if results[case["id"]].get("recuperadas") is not None]
    retrieval_labels = [{"id": case["id"], "esperados": wanted_mitre(case)} for case in retrieval_cases]
    retrieved = {case["id"]: results[case["id"]]["recuperadas"] for case in retrieval_cases}
    predicted_mitre = [case for case in successful if results[case["id"]].get("identificadas") is not None]
    abstentions = sum(not results[case["id"]]["identificadas"] for case in predicted_mitre)
    severity = defaultdict(Counter)
    for case in cases:
        result = results[case["id"]]
        severity[case["severidad_esperada"]["nivel"]][result.get("severidad") or "sin_resultado"] += 1
    cia = {}
    for dimension in ("confidencialidad", "integridad", "disponibilidad"):
        cia[dimension] = {}
        for field in ("observado", "potencial"):
            matches = sum(case["cia_esperado"][dimension][field] == results[case["id"]]["cia"][dimension][field]
                          for case in local)
            cia[dimension][field] = {"aciertos": matches, "casos": len(local),
                                     "accuracy": ratio(matches, len(local))}
    citation_counts = Counter()
    for case in successful:
        row = results[case["id"]]
        if "citas" not in row:
            continue
        citation_counts.update(row.get("citas", {}))
        accepted = row.get("citas_mitre", {})
        for item in case["mitre_esperadas"]:
            citation_counts["tecnicas_referencia"] += 1
            citation_counts["tecnicas_con_cita_suficiente"] += set(item["eventos"]) <= set(accepted.get(item["codigo"], []))
    all_events = sum(len(case["eventos"]) for case in cases)
    delivered = sum(results[case["id"]]["eventos_entregados"] for case in local)
    measured = [row for row in results.values() if isinstance(row.get("tokens"), dict) and row["tokens"]]
    limits = [{"id": case["id"], "afirmaciones": sorted(set(case["no_afirmar"]) & set(results[case["id"]]["afirmaciones"]))}
              for case in local]
    return {
        "casos": total, "completados": len(successful), "fallos_tecnicos": total - len(successful),
        "recuperacion": {"casos": len(retrieval_cases), "positivos": sum(bool(row["esperados"]) for row in retrieval_labels),
                         **summarize(retrieval_labels, retrieved)},
        "mitre_contratos": set_stage("contratos", wanted_mitre),
        "mitre_seleccion": set_stage("identificadas", wanted_mitre),
        "abstencion_mitre": {"casos_sin_tecnica": abstentions, "casos_evaluados": len(predicted_mitre),
                           "tasa": ratio(abstentions, len(predicted_mitre))},
        "iocs": set_stage("iocs", lambda case: [f"{item['tipo']}:{item['valor']}" for item in case["iocs_esperados"]]),
        "acciones_por_estado": set_stage("acciones", lambda case: [
            f"{item['evento']}:{item['estado']}" for item in case["acciones_esperadas"]]),
        "severidad": {"accuracy": ratio(sum(counts[level] for level, counts in severity.items()), total),
                      "matriz_confusion": {level: dict(row) for level, row in sorted(severity.items())}},
        "cia": cia,
        "evidencia": {**citation_counts, "validez_citas_mitre_en_muestra":
                      ratio(citation_counts["admisibles"], citation_counts["propuestas"]),
                      "validez_citas_narrativa": ratio(citation_counts["narrativa_admisibles"], citation_counts["narrativa"]),
                      "afirmaciones_no_permitidas": [row for row in limits if row["afirmaciones"]]},
        "cobertura": {"eventos": all_events, "eventos_en_muestra": delivered,
                      "proporcion_eventos": ratio(delivered, all_events), "proporcion_casos": ratio(len(local), total)},
        "latencia_ms": {field: {"casos": len(values), "promedio": round(sum(values) / len(values), 2),
                               "maximo": max(values)} for field in ("total", "recuperacion", "proveedor")
                       if (values := [row["latencia_ms"][field] for row in results.values() if field in row["latencia_ms"]])},
        "tokens": {"casos_con_medicion": len(measured),
                   "total": sum(row["tokens"].get("total_tokens", 0) for row in measured) if measured else None},
    }
