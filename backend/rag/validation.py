"""Ground proposals in retrieved official definitions and deterministic evidence."""
from .mitre_evidence import (
    ATTEMPT, AUTO_CLASSIFICATION, CONTRACTS, OBSERVED, SOURCE_LIMITATIONS, VALIDATOR_VERSION,
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
    if contract.sequence:
        bounded = {eid: signal for eid, signal in matches.items()
                   if eid in cited_ids or signal.step == 'contradiccion'}
        supported = any(set(contract.sequence_witness(group)) == cited_ids for group in contract.groups(bounded))
        if not supported and any(set(contract.sequence_witness(group)) == cited_ids for group in contract.groups(selected)):
            return 'evidencia_contradictoria', 'Otro evento de la sesión contradice la secuencia citada'
    else:
        supported = any(group.keys() == selected.keys() for group in contract.groups(selected))
    if not supported:
        return 'evidencia_ambigua', 'Las citas no componen un grupo de observaciones suficiente'
    grade = OBSERVED if all(signal.grade == OBSERVED for signal in selected.values()) else ATTEMPT
    if proposal.grado_evidencia == OBSERVED and grade != OBSERVED:
        return 'resultado_no_demostrado', 'Las citas no acreditan el resultado solicitado'
    return None, grade


def validate(result, events, context):
    candidates = {row['codigo_tecnica']: row for row in context['candidatos']}
    children_by_parent = {}
    for code, candidate in candidates.items():
        if parent := candidate.get('tecnica_padre_id'):
            children_by_parent.setdefault(parent, []).append(code)
    rejected, provenance = [], {}
    by_id = {event.id_evento: event for event in events}
    delivered = set(context.get('eventos_entregados', by_id)) & by_id.keys()
    modality = context.get('modalidad', 'desconocido')
    matches = collect_evidence(events, modality)
    for index, action in enumerate(result.acciones):
        action_events = set(action.eventos)
        if not action_events <= delivered:
            raise ValueError('Evidencia ajena a la sesión o al muestreo')
        action.eventos = list(dict.fromkeys(action.eventos))
        accepted, seen = [], set()
        proposed_codes = {proposal.codigo for proposal in action.mitre}
        for proposal in action.mitre:
            candidate = candidates.get(proposal.codigo)
            cited = list(dict.fromkeys(proposal.eventos))
            failure, detail = _validate_proposal(proposal, candidate, cited, action_events, by_id,
                                                matches.get(proposal.codigo, {}), modality)
            children = children_by_parent.get(proposal.codigo, ())
            if failure is None and set(children).isdisjoint(proposed_codes):
                eligible = []
                for child in children:
                    refined = proposal.model_copy(update={'codigo': child})
                    child_failure, child_grade = _validate_proposal(
                        refined, candidates[child], cited, action_events, by_id, matches.get(child, {}), modality
                    )
                    if child_failure is None:
                        eligible.append((refined, child_grade))
                if len(eligible) == 1:
                    proposal, detail = eligible[0]
                    candidate = candidates[proposal.codigo]
            pair = (proposal.codigo, proposal.codigo_tactica)
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
            if contract.sequence:
                cited_ids = set(cited)
                proposal.eventos = [eid for eid in matches[proposal.codigo] if eid in cited_ids]
            else:
                proposal.eventos = cited
            proposal.grado_evidencia = detail
            limitation = contract.observed_limitation if detail == OBSERVED else contract.limitation
            scope = SOURCE_LIMITATIONS[modality]
            status = 'Resultado registrado por Cowrie' if detail == OBSERVED else 'Intento sustentado por los eventos'
            proposal.comportamiento_observado = contract.minimum
            proposal.justificacion = f'{status}. {contract.minimum}'
            proposal.limitaciones = [limitation, scope]
            accepted.append(proposal)
            provenance[(index, *pair)] = {
                'metodo': context['metodo'], 'catalogo': context['catalogo'], 'modelo_embeddings': context['modelo_embeddings'],
                'stix_id': candidate['stix_id'], 'version_objeto': candidate.get('version_objeto'),
                'definicion_sha256': candidate['objeto_sha256'], 'nombre_oficial': candidate['nombre'],
                'puntuacion_hibrida': candidate['puntuacion_hibrida'], 'similitud_vectorial': candidate['similitud_vectorial'],
                'eventos': proposal.eventos, 'citas_explicitas': True, 'limitaciones': proposal.limitaciones,
                'clasificacion': AUTO_CLASSIFICATION, 'version_validador': VALIDATOR_VERSION, 'modalidad': modality,
                'alcance_sensor': scope, 'grado_evidencia': detail,
                'contrato_evidencia': proposal.codigo, 'version_contrato': contract.version, 'rasgo_validado': contract.tag,
                'comportamiento_observado': proposal.comportamiento_observado,
                'advertencia': 'Identificación automática; confianza y similitud no son probabilidades de ataque',
            }
        action.mitre = accepted
    children = {}
    for (_, code, _), entry in provenance.items():
        if parent := candidates[code].get('tecnica_padre_id'):
            children.setdefault(parent, []).append(set(entry['eventos']))
    for index, action in enumerate(result.acciones):
        retained = []
        for proposal in action.mitre:
            if any(set(proposal.eventos) <= evidence for evidence in children.get(proposal.codigo, ())):
                del provenance[(index, proposal.codigo, proposal.codigo_tactica)]
                rejected.append({'codigo': proposal.codigo, 'codigo_tactica': proposal.codigo_tactica,
                                 'estado': 'descartada', 'causa': 'padre_redundante', 'eventos': proposal.eventos,
                                 'motivo': 'Las mismas citas sustentan una subtécnica oficial más específica'})
            else:
                retained.append(proposal)
        action.mitre = retained
    return rejected, provenance
