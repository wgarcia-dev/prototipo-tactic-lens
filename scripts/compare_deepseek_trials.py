"""Compare frozen, independently labelled session predictions offline; no API calls."""
import argparse,json,re
from pathlib import Path
from backend.rag.evaluation import classification_metrics,summarize


def compare(dataset,baseline,rag):
    cases=dataset['casos'];ids=[case['id'] for case in cases]
    if not cases or len(set(ids))!=len(ids):raise ValueError('Casos vacios o repetidos')
    for case in cases:
        if case.get('etiquetado') is not True:raise ValueError('Complete el etiquetado humano antes de evaluar; vacio pendiente no es negativo')
        if not re.fullmatch('[a-f0-9]{64}',case.get('snapshot_sha256','')):raise ValueError('Falta snapshot congelado de eventos')
        if not isinstance(case.get('esperados'),list) or any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?',code) for code in case['esperados']):raise ValueError('Etiquetas ATT&CK invalidas')
    for key in ('modelo','parametros','prompt_comun_sha256'):
        if not baseline.get('metadata',{}).get(key) or baseline['metadata'][key]!=rag.get('metadata',{}).get(key):raise ValueError('Modelo, parametros o prompt comun diferentes')
    if not re.fullmatch('[a-f0-9]{64}',baseline['metadata']['prompt_comun_sha256']):raise ValueError('Congele la huella del prompt comun antes de comparar')
    if baseline['metadata'].get('variante')!='sin_rag' or rag['metadata'].get('variante')!='con_rag':raise ValueError('Identifique ambas variantes')
    result={'casos':len(cases),'independiente':bool(dataset.get('metadata',{}).get('independiente')),
            'demostracion_mejora':False,'nota':'Comparacion descriptiva pareada; requiere revisar independencia y suficiencia del corpus. No se ejecuta DeepSeek.'}
    for label,run in (('sin_rag',baseline),('con_rag',rag)):
        rows=run.get('resultados',{})
        if set(rows)!=set(ids):raise ValueError('Se necesitan exactamente las mismas sesiones en ambas variantes')
        for case in cases:
            item=rows[case['id']]
            if item.get('estado')!='completado':raise ValueError('No evaluar predicciones pendientes o fallidas como abstenciones')
            if item.get('snapshot_sha256')!=case['snapshot_sha256']:raise ValueError('Los eventos evaluados no son el mismo snapshot')
            if any(not isinstance(item.get(field),list) or any(not isinstance(code,str) for code in item[field]) for field in ('propuestas','aceptadas')):raise ValueError('Faltan listas de propuestas y aceptadas')
            for field in ('propuestas','aceptadas'):
                if not isinstance(item.get(field),list) or any(not isinstance(code,str) for code in item[field]):raise ValueError('Faltan propuestas y aceptadas, incluso si hubo abstencion')
        result[label]={field:classification_metrics(cases,{key:row[field] for key,row in rows.items()}) for field in ('propuestas','aceptadas')}
        if label=='con_rag' and all(isinstance(row.get('candidatos'),list) for row in rows.values()):
            result[label]['recuperacion']=summarize(cases,{key:row['candidatos'] for key,row in rows.items()})
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset',type=Path,required=True);p.add_argument('--sin-rag',type=Path,required=True)
    p.add_argument('--con-rag',type=Path,required=True);args=p.parse_args()
    files=[json.loads(path.read_text(encoding='utf-8')) for path in (args.dataset,args.sin_rag,args.con_rag)]
    print(json.dumps(compare(*files),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
