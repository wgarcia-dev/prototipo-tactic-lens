"""Ground proposals in retrieved official definitions and deterministic evidence."""
from .mitre_evidence import (
    ATTEMPT, AUTO_CLASSIFICATION, CONTRACTS, OBSERVED, VALIDATOR_VERSION,
    collect_evidence, telemetry,
)

GENERIC = {'propuesta para revision', 'propuesta para revisión', 'comando en shell', 'mitre',
           'tecnica detectada', 'técnica detectada'}


def _validate_proposal(proposal, candidate, cited, action_events, events, matches, modality):
    if not candidate or candidate.get('revocada') or candidate.get('deprecada'):
        return 'catalogo_no_vigente', 'Técnica ausente de los candidatos oficiales vigentes'
    if not cited:
        return 'sin_citas', 'Se requieren citas MITRE explícitas'
    if not set(cited) <= action_events:
        return 'eventos_ajenos', 'Eventos ajenos a la acción, a la sesión o al muestreo'
    if len(proposal.justificacion.strip()) < 30 or proposal.justificacion.strip().lower() in GENERIC:
        return 'justificacion_insuficiente', 'Justificación insuficiente o predeterminada'
    if not (proposal.comportamiento_observado or '').strip():
        return 'sin_comportamiento', 'La propuesta carece de una descripción del comportamiento citado'
    if not any(len(value.strip()) >= 15 for value in proposal.limitaciones):
        return 'sin_limitaciones', 'Declare limitaciones concretas de la evidencia'
    if proposal.codigo_tactica not in {t['codigo_tactica'] for t in candidate['tacticas']}:
        return 'tactica_invalida', 'Táctica ausente o no relacionada oficialmente'
    if 'Linux' not in candidate.get('plataformas', []):
        return 'plataforma_incompatible', 'La plataforma del catálogo no es compatible con el entorno Linux'
    contract = CONTRACTS.get(proposal.codigo)
    if contract is None:
        return 'sin_contrato', 'Técnica candidata sin contrato de evidencia suficiente'
    if modality not in contract.modes:
        return 'modalidad_incompatible', 'El contrato carece de validación para esta modalidad'
    if contract.tactics and proposal.codigo_tactica not in contract.tactics:
        return 'tactica_sin_respaldo', 'La táctica oficial no está respaldada por este contrato'
    if contract.contradicts and any(contract.contradicts(telemetry(events[eid], modality)) for eid in cited):
        return 'evidencia_contradictoria', 'La telemetría citada contradice el comportamiento propuesto'
    if any(eid not in matches for eid in cited):
        return 'evidencia_insuficiente', 'Los eventos citados no sustentan la técnica'
    cited_ids = set(cited)
    selected = {eid: signal for eid, signal in matches.items() if eid in cited_ids}
    if not any(group.keys() == selected.keys() for group in contract.groups(selected)):
        return 'evidencia_ambigua', 'Las citas no componen un grupo de observaciones suficiente'
    grade = OBSERVED if all(signal.grade == OBSERVED for signal in selected.values()) else ATTEMPT
    if proposal.grado_evidencia == OBSERVED and grade != OBSERVED:
        return 'resultado_no_demostrado', 'Las citas no acreditan el resultado solicitado'
    return None, grade


def validate(result, events, context):
    candidates = {row['codigo_tecnica']: row for row in context['candidatos']}
    rejected, provenance = [], {}
    by_id = {event.id_evento: event for event in events}
    delivered = set(context.get('eventos_entregados', by_id)) & by_id.keys()
    modality = context.get('modalidad', 'desconocido')
    matches = collect_evidence((event for eid, event in by_id.items() if eid in delivered), modality)
    for index, action in enumerate(result.acciones):
        action_events = set(action.eventos)
        if not action_events <= delivered:
            raise ValueError('Evidencia ajena a la sesión o al muestreo')
        action.eventos = list(dict.fromkeys(action.eventos))
        accepted, seen = [], set()
        for proposal in action.mitre:
            candidate = candidates.get(proposal.codigo)
            cited = list(dict.fromkeys(proposal.eventos))
            pair = (proposal.codigo, proposal.codigo_tactica)
            failure, detail = _validate_proposal(proposal, candidate, cited, action_events, by_id,
                                                matches.get(proposal.codigo, {}), modality)
            if failure is None and pair in seen:
                failure, detail = 'duplicada', 'Propuesta duplicada; se conserva una sola asociación'
            if failure:
                rejected.append({
                    'codigo': proposal.codigo, 'codigo_tactica': proposal.codigo_tactica,
                    'estado': 'candidata_no_validada' if failure == 'sin_contrato' else 'descartada',
                    'causa': failure, 'motivo': detail, 'eventos': cited,
                })
                continue
            seen.add(pair)
            contract = CONTRACTS[proposal.codigo]
            proposal.eventos = cited
            proposal.grado_evidencia = detail
            limitation = contract.observed_limitation if detail == OBSERVED else contract.limitation
            if modality == 'desconocido':
                limitation += ' La modalidad histórica no está registrada.'
            proposal.limitaciones = [*proposal.limitaciones, limitation]
            accepted.append(proposal)
            provenance[(index, *pair)] = {
                'metodo': context['metodo'], 'catalogo': context['catalogo'], 'modelo_embeddings': context['modelo_embeddings'],
                'stix_id': candidate['stix_id'], 'version_objeto': candidate.get('version_objeto'),
                'definicion_sha256': candidate['objeto_sha256'], 'nombre_oficial': candidate['nombre'],
                'puntuacion_hibrida': candidate['puntuacion_hibrida'], 'similitud_vectorial': candidate['similitud_vectorial'],
                'eventos': cited, 'citas_explicitas': True, 'limitaciones': proposal.limitaciones,
                'clasificacion': AUTO_CLASSIFICATION, 'version_validador': VALIDATOR_VERSION, 'modalidad': modality,
                'contrato_evidencia': proposal.codigo, 'version_contrato': contract.version, 'rasgo_validado': contract.tag,
                'comportamiento_observado': proposal.comportamiento_observado,
                'advertencia': 'Identificación automática; confianza y similitud no son probabilidades de ataque',
            }
        action.mitre = accepted
    return rejected, provenance
