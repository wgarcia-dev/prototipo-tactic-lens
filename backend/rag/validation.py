"""Ground proposals in retrieved official definitions AND compatible observations."""
from .behavior import technique_profiles

GENERIC={'propuesta para revision','propuesta para revisión','comando en shell','mitre','tecnica detectada','técnica detectada'}


def validate(result,events,context):
    candidates={r['codigo_tecnica']:r for r in context['candidatos']}
    representation=context['representacion'];discarded=[];provenance={}
    valid_ids={e.id_evento for e in events}
    for action_index,action in enumerate(result.acciones):
        if not set(action.eventos)<=valid_ids:raise ValueError('Evidencia ajena a la sesion')
        action.eventos=list(dict.fromkeys(action.eventos))
        accepted=[];seen=set()
        for proposal in action.mitre:
            definition=candidates.get(proposal.codigo);reason=None
            evidence=list(dict.fromkeys(proposal.eventos or action.eventos))
            justification=proposal.justificacion.strip()
            if not definition:reason='Tecnica no recuperada del catalogo oficial vigente'
            elif not evidence or not set(evidence)<=set(action.eventos):reason='Eventos ajenos a la accion o sesion'
            elif len(justification)<30 or justification.lower() in GENERIC:reason='Justificacion insuficiente o predeterminada'
            elif proposal.codigo_tactica not in {t['codigo_tactica'] for t in definition['tacticas']}:reason='Tactica ausente o no relacionada oficialmente'
            else:
                profiles=technique_profiles(definition['nombre'])
                observed={tag for eid in evidence for tag in representation['rasgos_por_evento'].get(eid,representation['rasgos_por_evento'].get(str(eid),[]))}
                if definition['observabilidad']!='intento_evaluable' or not profiles.intersection(observed):
                    reason='La evidencia no sustenta esta tecnica con la cobertura actual de Cowrie'
                elif proposal.grado_evidencia=='resultado_en_honeypot' and not (profiles=={'transfer'} and set(evidence).intersection(representation['resultados_confirmados'])):
                    reason='No hay telemetria de resultado confirmado para esa propuesta'
                elif not proposal.limitaciones or not any(len(s.strip())>=15 for s in proposal.limitaciones):
                    reason='Declare limitaciones concretas del entorno emulado'
            pair=(proposal.codigo,proposal.codigo_tactica)
            if not reason and pair in seen:reason='Propuesta duplicada; se conserva una sola asociacion'
            if reason:
                discarded.append({'codigo':proposal.codigo,'motivo':reason,'eventos':evidence})
                continue
            seen.add(pair);proposal.eventos=evidence;accepted.append(proposal)
            provenance[(action_index,*pair)]={'metodo':context['metodo'],'catalogo':context['catalogo'],'modelo_embeddings':context['modelo_embeddings'],
                'stix_id':definition['stix_id'],'version_objeto':definition.get('version_objeto'),
                'definicion_sha256':definition['objeto_sha256'],'nombre_oficial':definition['nombre'],
                'puntuacion_hibrida':definition['puntuacion_hibrida'],'similitud_vectorial':definition['similitud_vectorial'],
                'eventos':evidence,'limitaciones':proposal.limitaciones,
                'advertencia':'Propuesta pendiente de revision humana; similitud no es probabilidad de ataque'}
        action.mitre=accepted
    return discarded,provenance
