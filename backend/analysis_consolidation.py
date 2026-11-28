"""Accept the model's grouping proposals while deriving claims from cited evidence."""
from hashlib import sha256

from .analysis_model import OFFICIAL, resources
from .analysis_controls import cited_safeguard, strategy_safeguard
from .analysis_semantics import PHASE_NAMES, chronological_groups, describe_events, describe_group, validated_sentences
from .rag.mitre_evidence import COMMAND_INPUT
from .rag.pipeline import protected_text
from .threat_evaluation import FAILURES, MATRIX, ROWS, classification_confidence, priority

GOAL_BY_TACTIC = {
    "TA0007": "inventariar_entorno", "TA0003": "mantener_acceso", "TA0005": "reducir_trazabilidad",
    "TA0112": "reducir_trazabilidad", "TA0009": "obtener_material_sensible",
}
GOAL_BY_CODE = {
    "T1110": "evaluar_acceso", "T1110.001": "evaluar_acceso", "T1110.003": "evaluar_acceso",
    "T1003.008": "obtener_material_sensible", "T1552.003": "obtener_material_sensible",
    "T1552.004": "obtener_material_sensible", "T1489": "afectar_disponibilidad", "T1529": "afectar_disponibilidad",
    "T1531": "afectar_disponibilidad",
}
PHASE_STATES = {
    "resultado_observado": "El resultado se limita al evento estructurado del sensor.",
    "intento": "La captura acredita la solicitud. El efecto no queda establecido.",
    "fallido": "El evento registra que falló la operación indicada.",
    "registrado": "Se documentó el estado del sensor sin atribuir causas ni efectos externos.",
    "no_determinable": "La cita no acredita el resultado solicitado."
}


def proposition_state(events, downloaded):
    if events and all(e.id_evento in downloaded for e in events):
        return "resultado_observado", "resultado_en_honeypot"
    if any(e.tipo_evento in {COMMAND_INPUT, "cowrie.direct-tcpip.request"} for e in events):
        return "intento", "intento"
    if events and all(e.tipo_evento in FAILURES for e in events):
        return "fallido", "contexto"
    if events and all(e.tipo_evento in {
        "cowrie.session.connect", "cowrie.session.closed", "cowrie.client.kex", "cowrie.client.version",
        "cowrie.login.success", "cowrie.login.failed",
    } for e in events):
        return "registrado", "contexto"
    return "no_determinable", "contexto"


def related_witnesses(mitre, ids):
    known = set(ids)
    return [w for w in mitre if set(w.ids) <= known]


def supported_relation(kind, claims, terminal=()):
    """Match a proposed relationship against the cited events in capture order."""
    discoveries = [b for b in claims if b.categoria == "descubrimiento" and b.objetivo]
    if kind == "consultas_complementarias" and len({b.operacion for b in discoveries}) >= 2:
        return discoveries, "Las solicitudes consultan aspectos distintos del entorno. Juntas son compatibles con un reconocimiento inicial.", "inventariar_entorno"
    if kind == "consulta_y_lectura":
        for index, left in enumerate(claims):
            if left not in discoveries:
                continue
            right = next((b for b in claims[index+1:] if b.operacion == "leer" and b.objetivo), None)
            if right:
                return [left, right], "Tras una solicitud de consulta sobre el sistema, se registró una solicitud de lectura. La secuencia es compatible con una exploración del entorno.", "inventariar_entorno"
    if kind == "actividad_posterior_al_acceso":
        for index, left in enumerate(claims):
            if left.operacion != "cowrie.login.success":
                continue
            right = next((b for b in claims[index+1:] if b.objetivo and b.categoria != "finalizacion"), None)
            if right:
                return [left, right], "El sensor registró una orden interpretable después de aceptar la autenticación. Corresponde revisar qué acceso estaba autorizado y qué resultado registró el recurso.", None
    if kind == "orden_y_fallo":
        by_id = {str(item.evento):item for item in claims}
        for record in terminal:
            if (record["tipo"] == "cowrie.command.failed" and record["evento_orden"] in by_id
                    and record["evento"] in by_id):
                return ([by_id[record["evento_orden"]], by_id[record["evento"]]],
                        "Cowrie registró un fallo vinculado explícitamente a la orden citada. La captura no establece el efecto fuera del sensor.", None)
    return None


def summarize_observables(by_event, enrichment):
    profiles = {(item["tipo"],item["valor"]):item["proveedores"]
                for item in (enrichment or {}).get("observables", [])}
    records = {}
    for eid, entries in by_event.items():
        for idx, item in enumerate(entries, 1):
            # One entry per normalized identity and role, referencing the existing extractor.
            transport = item.campo in {"src_ip","dst_ip"}
            identity = (item.tipo,item.valor)
            record = records.setdefault((*identity,transport),{
                "tipo":item.tipo, "alcance":"transporte" if transport else "recurso_referenciado",
                "clasificacion": "indicador_sospechoso" if not transport and
                    (profiles.get(identity,{}).get("threatfox") or {}).get("estado")=="coincidencia" else "observable",
                "eventos":[],"referencias":[],
            })
            if str(eid) not in record["eventos"]:
                record["eventos"].append(str(eid))
            record["referencias"].append({"evento":str(eid),"referencia":idx,"rol":item.comportamiento})
    return list(records.values())


def structure_result(result, evaluated, delivered, modality, by_event, enrichment=None, decisions=None):
    block, context, _, downloaded, mitre, by_id = evaluated
    behaviors = describe_events(by_id.values(), modality, mitre, resources)
    decisions = decisions if decisions is not None else {}
    def checked(text, cited, path):
        accepted, decision = validated_sentences(text, cited)
        decisions[path] = decision
        return accepted

    # Add uncovered operations without changing the indices of model actions or MITRE provenance.
    from .routes import Finding
    cited_actions = {eid for action in result.acciones for eid in action.eventos}
    uncovered = {}
    for b in behaviors.values():
        if (b.objetivo or b.operacion == "orden_sin_semantica") and b.evento not in cited_actions:
            uncovered.setdefault(b.operacion, []).append(b.evento)
    for operation, ids in uncovered.items():
        result.acciones.append(Finding(tipo="operacion_del_sensor", descripcion=describe_group([behaviors[eid] for eid in ids]),
                                       confianza=0.5, eventos=ids))
    structured = result.model_dump(exclude_none=True)
    structured.update(block.model_dump())
    structured["contexto_observado"] = context
    structured["comportamientos_semanticos"] = [b.public() for b in behaviors.values()]
    structured["observables_contextuales"] = summarize_observables(by_event, enrichment)
    terminal = context["cobertura_evidencia"].get("evidencia_terminal", [])
    validated_summary = checked(result.resumen, [behaviors[eid] for eid in delivered if eid in behaviors], "resumen")
    commands = [b for b in behaviors.values() if by_id[b.evento].tipo_evento == COMMAND_INPUT]
    material = [b for b in commands if b.objetivo and b.categoria != "finalizacion"]
    unresolved = [b for b in commands if b.operacion == "orden_sin_semantica"]
    gap = ""
    if unresolved:
        refs = ", ".join(f"#{b.evento}" for b in unresolved[:6])
        gap = (f"Quedó una orden sin interpretación fiable (evento {refs})." if len(unresolved) == 1 else
               f"Quedaron {len(unresolved)} órdenes sin interpretación fiable (eventos {refs}).")
    failures = [e.id_evento for e in by_id.values() if e.tipo_evento in FAILURES]
    recorded_failure = (f"El sensor también registró un fallo (evento #{failures[0]})." if failures else "")
    executions = context["autenticaciones_exitosas"]
    rejected = context["autenticaciones_fallidas"]
    accepted_label = "autenticación aceptada" if executions == 1 else "autenticaciones aceptadas"
    requested_label = "orden registrada" if context["comandos"] == 1 else "órdenes registradas"
    excerpt = " ".join(validated_summary) or describe_group(material[:8])
    if not excerpt:
        excerpt = describe_group([b for b in behaviors.values() if b.categoria != "contexto"][:4])
    severity = block.evaluacion_amenaza
    confidentiality = block.evaluacion_impacto["confidencialidad"]
    consequence = (confidentiality["descripcion"].split(". ")[-1]
                   if confidentiality.get("recursos") else "")
    control = next((strategy for strategy in block.estrategias_deteccion
                    if strategy["codigo_mitre"] or set(strategy["eventos"]) & {str(b.evento) for b in material}), None)
    control = control or next(iter(block.estrategias_deteccion), None)
    summary = " ".join(filter(None, [
        excerpt, consequence, gap, recorded_failure,
        f"La captura reúne {context['total_eventos']} eventos con {context['comandos']} {requested_label}, "
        f"{executions} {accepted_label} y {rejected} rechazos.",
        f"Severidad técnica {severity['severidad_preliminar']}." +
        (f" Prioridad de investigación {severity['prioridad_investigacion']}." if severity["prioridad_investigacion"] else ""),
        "Comprobación inicial: contrastar las órdenes citadas y su resultado con el registro de terminal o la auditoría del servicio."
        if unresolved and not material else f"Comprobación inicial: {control['criterio_validacion']}" if control else "",
    ]))
    structured["resumen"] = result.resumen = summary
    offsets = {}
    mask = protected_text(e.datos_originales for e in by_id.values())
    profiles = {(item["tipo"], item["valor"]): index for index, item in enumerate((enrichment or {}).get("observables", []))}
    for index, action in enumerate(result.acciones):
        event_ids = sorted(set(action.eventos), key=lambda eid: (by_id[eid].fecha_hora, eid))
        evidence = [by_id[eid] for eid in event_ids]
        witnesses = related_witnesses(mitre, event_ids)
        state, grade = proposition_state(evidence, downloaded)
        described = [behaviors[eid] for eid in event_ids]
        accepted = checked(action.descripcion, described, f"acciones[{index}].descripcion")
        procedure = " ".join(accepted) or describe_group(described)
        identifier = "A-" + sha256((str(index) + ":" + ",".join(map(str, event_ids))).encode()).hexdigest()[:16]
        offsets[identifier] = set(event_ids)
        action.tipo = mask(action.tipo).strip()[:80] or "actividad_registrada"
        action.descripcion = procedure
        data = structured["acciones"][index]
        data.update(tipo=action.tipo, descripcion=procedure, id_accion=identifier, estado=state,
                    grado_evidencia=grade, resultado=PHASE_STATES[state],
                    recurso_objetivo=next((category for w in witnesses if (category := resources(w))),
                                         next((b.recurso for b in described if b.recurso), None)),
                    operaciones=list(dict.fromkeys(b.operacion for b in described)),
                    limitaciones=list(dict.fromkeys(b.limitacion for b in described if b.limitacion)),
                    confianza_analitica=classification_confidence(direct=state!="no_determinable", cited=bool(evidence)))
        linked = [record for record in terminal if record["evento_orden"] in {str(eid) for eid in event_ids}]
        if linked:
            data["resultado"] += " " + " ".join(
                f"Terminal #{record['evento']}. {record['resultado_observado']}" for record in linked[:4])
        for ioc, model_ioc in zip(data["iocs"], action.iocs, strict=True):
            item = next((item for item in by_event[model_ioc.evento] if item.tipo == model_ioc.tipo and item.valor == model_ioc.valor), None)
            description = "Observable registrado en la fuente y el evento citados."
            model_ioc.evidencia = description
            identity = (model_ioc.tipo, model_ioc.valor)
            profile_offset = profiles.get(identity)
            profile = enrichment["observables"][profile_offset] if profile_offset is not None else None
            providers = profile["proveedores"] if profile else {}
            signal = (providers.get("threatfox") or {}).get("estado") == "coincidencia"
            ioc.update(valor=mask(model_ioc.valor, observable_url=model_ioc.tipo == "URL"), evidencia=description,
                       rol=item.comportamiento if item else None, contexto=item.campo if item else None,
                       clasificacion="indicador_sospechoso" if signal else "observable",
                       reputacion={"perfil_enriquecimiento":profile_offset} if profile else None,
                       recurrencia=len(set(profile["eventos"])) if profile else None,
                       acciones_relacionadas=[identifier], confianza_analitica=classification_confidence(direct=bool(item), cited=bool(item)))
        for mapping in data["mitre"]:
            cited_procedure = [behaviors[eid] for eid in mapping["eventos"] if eid in behaviors
                               and behaviors[eid].operacion != "orden_sin_semantica" and
                               (behaviors[eid].objetivo or behaviors[eid].estado == "resultado_observado")]
            mapping.update(procedimiento_observado=describe_group(cited_procedure) or mapping["comportamiento_observado"],
                           confianza_analitica=classification_confidence(contract=True))
    if not result.informe:
        return structured
    report = structured["informe"]
    phases = []
    phase_proposals = result.informe.fases
    for category, evidence in chronological_groups(by_id.values(), behaviors):
        ids = {e.id_evento for e in evidence}
        descriptions = [behaviors[e.id_evento] for e in evidence]
        state, _ = proposition_state(evidence, downloaded)
        if all(b.estado == "registrado" for b in descriptions):
            state = "registrado"
        witnesses = related_witnesses(mitre, ids)
        available = [p for p in phase_proposals if set(p.eventos) & ids & set(delivered)]
        fragments = {}
        for field in ("observado","interpretacion","resultado"):
            kept = []
            for i, p in enumerate(available):
                scoped = [b for b in descriptions if b.evento in p.eventos and b.evento in delivered]
                # The result field cannot promote a request to execution.
                if field == "resultado":
                    scoped = [b for b in scoped if b.estado in {"resultado_observado","registrado","fallido"}]
                kept.extend(checked(getattr(p, field), scoped, f"fases[{len(phases)}].{field}.{i}"))
            fragments[field] = " ".join(dict.fromkeys(kept))
        phase_purpose = list(dict.fromkeys(b.objetivo for b in descriptions if b.objetivo))
        explanation = " ".join(dict.fromkeys(w.summary for w in witnesses))
        if not explanation and phase_purpose:
            explanation = "Propósito inmediato de la solicitud: " + "; ".join(phase_purpose) + "."
        if not explanation and any(b.operacion == "orden_sin_semantica" for b in descriptions):
            explanation = "Las entradas citadas requieren el registro del terminal para establecer qué operación se solicitó."
        if not explanation and category == "fallo":
            explanation = "La captura documenta un fallo. Correlacionar hora e identificador antes de asociarlo a una orden."
        if not explanation and category == "autenticacion":
            explanation = "La decisión de autenticación delimita el acceso registrado por el sensor. Compruebe la autorización en el servicio protegido."
        phases.append({
            "fase": PHASE_NAMES[category], "observado": fragments["observado"] or describe_group(descriptions),
            "interpretacion": fragments["interpretacion"] or explanation or PHASE_STATES[state],
            "resultado": fragments["resultado"] if state != "intento" and fragments["resultado"] else PHASE_STATES[state],
            "eventos": [e.id_evento for e in evidence],
            "inicio_fase": evidence[0].fecha_hora.isoformat(), "fin_fase": evidence[-1].fecha_hora.isoformat(),
            "estado_resultado": state, "acciones_relacionadas": [key for key, citations in offsets.items() if citations & ids],
        })
    phases.sort(key=lambda phase: (phase["inicio_fase"], phase["eventos"][0]))
    report["fases"] = [dict(phase, orden=index) for index, phase in enumerate(phases, 1)]
    hypotheses = []
    hypothesis_codes = set()
    relationship_keys = set()
    unsupported_hypotheses = set()
    operational = {}
    for b in behaviors.values():
        if b.objetivo and b.categoria != "finalizacion":
            operational.setdefault((b.operacion, b.recurso), []).append(b)
    for group in operational.values():
        first = group[0]
        hypotheses.append({
            "descripcion": f"Objetivo operativo sustentado: {first.objetivo}.",
            "confianza": 0.5, "eventos": [b.evento for b in group],
            "objetivo_inmediato": first.objetivo, "objetivo_probable": None,
            "recursos_interes": [first.recurso] if first.recurso else [], "hipotesis_alternativas": [],
            "fundamento": "La entrada citada expresa esta solicitud. El resultado requiere corroboración.",
            "confianza_analitica": classification_confidence(direct=True),
        })
    for index, proposal in enumerate(result.informe.hipotesis):
        citations = set(proposal.eventos) & delivered
        if proposal.relacion:
            claimed = [b for b in behaviors.values() if b.evento in citations]
            relation = supported_relation(proposal.relacion, claimed, terminal) if citations == set(proposal.eventos) else None
            decisions[f"hipotesis.propuestas[{index}].relacion"] = {
                "aceptadas":int(bool(relation)), "rechazadas":int(not relation),
                "motivo_codigo":"relacion_sustentada" if relation else "citas_no_sustentadas",
            }
            if not relation:
                unsupported_hypotheses.update(citations)
                continue
            support, interpretation, goal = relation
            ids = tuple(b.evento for b in support)
            key = (proposal.relacion, ids)
            if key in relationship_keys:
                continue
            relationship_keys.add(key)
            targets = list(dict.fromkeys(b.recurso for b in support if b.recurso))
            hypotheses.append({
                "descripcion":interpretation, "relacion":proposal.relacion,
                "objetivo_inmediato":"; ".join(b.objetivo for b in support if b.objetivo),
                "objetivo_probable":goal, "confianza":proposal.confianza, "eventos":list(ids),
                "recursos_interes":targets, "hipotesis_alternativas":[
                    "Una tarea de administración autorizada también podría explicar las solicitudes. Contrastar con el registro de acceso."],
                "fundamento":"Secuencia verificada de los eventos citados. El orden no acredita causalidad ni resultados.",
                "confianza_analitica":classification_confidence(inferred=True),
            })
            continue
        witnessed = related_witnesses(mitre, citations)
        supported = next((w for w in witnessed if w.code not in hypothesis_codes), None)
        if not supported:
            matched = [behaviors[eid] for eid in citations if behaviors[eid].objetivo]
            accepted = checked(proposal.descripcion, matched, f"hipotesis.propuesta.{len(decisions)}")
            discoveries = [b for b in matched if b.categoria=="descubrimiento"]
            if (proposal.objetivo_probable=="inventariar_entorno"
                and len({b.operacion for b in discoveries})>=2):
                hypotheses.append({
                    "descripcion":"Las consultas diferenciadas permiten inferir un posible inventario del entorno.",
                    "confianza":proposal.confianza,"eventos":sorted(b.evento for b in discoveries),
                    "objetivo_inmediato":"Consultar propiedades diferenciadas del entorno.",
                    "objetivo_probable":"inventariar_entorno",
                    "recursos_interes":list(dict.fromkeys(b.recurso for b in discoveries if b.recurso)),
                    "hipotesis_alternativas":["Consulta operativa autorizada de propiedades del entorno."],
                    "fundamento":"Al menos dos operaciones de descubrimiento distintas con citas, sin atribuir motivación.",
                    "confianza_analitica":classification_confidence(inferred=True),
                })
                continue
            if not witnessed and (not accepted or proposal.objetivo_probable is not None):
                unsupported_hypotheses.update(citations)
            if accepted and proposal.objetivo_probable is None:
                for objective in hypotheses:
                    if set(objective["eventos"]) == citations:
                        objective["descripcion"] = " ".join(accepted)
                        objective["confianza"] = proposal.confianza
                        break
            continue
        hypothesis_codes.add(supported.code)
        resource = resources(supported)
        inference = f"El objetivo inmediato es compatible con {ROWS[supported.code]['nombre_oficial']}. La finalidad posterior sigue abierta."
        tactic = ROWS[supported.code]["tacticas_admitidas"][0]["codigo"]
        eligible_goal = GOAL_BY_CODE.get(supported.code, GOAL_BY_TACTIC.get(tactic))
        goal = proposal.objetivo_probable if proposal.objetivo_probable == eligible_goal else None
        hypotheses.append({
            "descripcion": inference, "confianza": proposal.confianza, "eventos": list(supported.ids),
            "objetivo_inmediato": supported.summary, "objetivo_probable": goal,
            "recursos_interes": [resource] if resource else [],
            "hipotesis_alternativas": ["Actividad administrativa o exploratoria; la autorización requiere corroboración."],
            "fundamento": "Coincidencia del comportamiento y sus citas con un contrato; sin inferencia de motivación.",
            "confianza_analitica": classification_confidence(alternative=True, discriminates=bool(goal and len(supported.ids) > 1)),
        })
    if unsupported_hypotheses:
        structured["evaluacion_amenaza"]["factores_limitantes"].append({
            "codigo":"LI13", "descripcion":MATRIX["reglas_operativas"]["limitantes"]["LI13"],
            "eventos":list(map(str, sorted(unsupported_hypotheses))),
        })
    report["hipotesis"] = hypotheses
    structured["inferencias_principales"] = [h["descripcion"] for h in hypotheses if h["objetivo_probable"] or h.get("relacion")]
    visibility = context["cobertura_evidencia"]
    scope = []
    if material:
        targets = list(dict.fromkeys(b.recurso for b in material if b.recurso))
        if targets:
            scope.append("Las solicitudes interpretadas se refieren a " + ", ".join(targets) + ".")
    if unresolved:
        scope.append(gap)
    report["contexto"] = " ".join(part for part in (
        f"Se revisó la ventana de {context['duracion_observada_segundos']:g} segundos cubierta por los eventos almacenados. "
        f"Modalidad registrada: {modality}.", *scope
    ) if part)
    report["limitaciones"] = list(dict.fromkeys(block.evidencia_adicional_requerida))
    priorities = block.evaluacion_amenaza["codigo_severidad"]
    provider_safeguards = []
    selected_focus = set()
    for index, proposal in enumerate(result.informe.recomendaciones):
        focus = getattr(proposal, "enfoque", None)
        if not focus:
            continue
        ids = set(proposal.eventos)
        scoped = [b for b in behaviors.values() if b.evento in ids]
        accepted = cited_safeguard(focus, scoped, severity["prioridad_investigacion"]) if ids <= delivered else None
        key = (focus, tuple(b.evento for b in scoped))
        decisions[f"recomendaciones[{index}].enfoque"] = {
            "aceptadas":int(bool(accepted) and key not in selected_focus),
            "rechazadas":int(not accepted), "duplicadas":int(bool(accepted) and key in selected_focus),
            "motivo_codigo":"diligencia_sustentada" if accepted else "citas_no_sustentadas",
        }
        if accepted and key not in selected_focus:
            provider_safeguards.append(accepted)
            selected_focus.add(key)
    recommendations = [*provider_safeguards,
                       *(strategy_safeguard(strategy, OFFICIAL) for strategy in block.estrategias_deteccion)]
    priority_safeguard = next(iter(provider_safeguards), None)
    if priority_safeguard is None:
        actionable = [b for b in material if b.recurso and b.categoria in
                      {"descubrimiento", "recursos", "modificacion", "red", "transferencia"}]
        focus, support = ("verificar_recurso", actionable[:6]) if actionable else ("aclarar_orden", unresolved[:6])
        priority_safeguard = cited_safeguard(focus, support, severity["prioridad_investigacion"], provider_selected=False)
        if priority_safeguard:
            recommendations.insert(0, priority_safeguard)
    if visibility["referencias_tty"]:
        recommendations.append({
            "salvaguarda": "Comprobar la referencia de grabación registrada", "activo": "Registro de captura",
            "riesgo": "Cobertura parcial de la interacción", "objetivo": "Corroborar la secuencia del terminal",
            "medidas": "Verificar disponibilidad y procedencia del archivo referenciado por el evento.",
            "validacion": "Relacionar la grabación con la sesión y las fechas de las citas.",
            "prioridad_recomendada": priority(priorities)[0], "justificacion": "Existe un evento con referencia TTY.",
            "tecnicas_relacionadas": [], "mitigaciones_mitre": [], "eventos": visibility["referencias_tty"],
        })
    report["recomendaciones"] = recommendations
    conclusion = checked(result.informe.conclusion, [behaviors[eid] for eid in delivered if eid in behaviors], "informe.conclusion")
    primary = next((h for h in hypotheses if h.get("relacion")), None) or next(
        (h for h in hypotheses if h["objetivo_probable"]), None)
    interpretation = primary["descripcion"] if primary else ""
    if primary:
        interpretation += " Evidencia " + ", ".join(f"#{eid}" for eid in primary["eventos"][:6]) + "."
    outcome = (interpretation or " ".join(conclusion) or describe_group(material[:6])
               or describe_group([b for b in behaviors.values() if b.categoria != "contexto"][:4]))
    impact = block.evaluacion_impacto["impacto_potencial"]
    priority_value = block.evaluacion_amenaza["prioridad_investigacion"]
    follow_up = priority_safeguard or next((row for row in recommendations if row["activo"] not in
                      {"Autenticaciones SSH", "Registro de captura", "control de acceso"}), None)
    follow_up = follow_up or next(iter(recommendations), None)
    relevant = material or unresolved
    if relevant:
        access = ("El sensor aceptó la autenticación." if executions else
                  "El sensor registró rechazos de autenticación." if rejected else "La captura no acredita una autenticación aceptada.")
        protocol = context.get("protocolo")
        channel = f"Interacción por {protocol.upper()}." if protocol in {"ssh", "telnet"} else "Interacción registrada por el sensor."
        lead = interpretation or (" ".join(validated_summary) if validated_summary else describe_group(material[:8]))
        triage = (f"Severidad {severity['codigo_severidad']}. Prioridad {priority_value}." if priority_value
                  else f"Severidad {severity['codigo_severidad']}. Compruebe la cobertura antes de priorizar.")
        result.resumen = structured["resumen"] = " ".join(part for part in (
            channel, access, lead, gap, recorded_failure, triage,
            f"Diligencia inicial — {follow_up['medidas']}" if follow_up else "",
        ) if part)
    observed_scope = " ".join(part for part in (gap, recorded_failure) if part)
    if visibility.get("terminal", {}).get("salidas_con_texto"):
        observed_scope += " Las salidas son contexto del terminal. Para verificar efectos, cotejar las citas con la auditoría del recurso."
    technical = " ".join(filter(None, [
        f"Valoración técnica {severity['codigo_severidad']}.",
        f"Prioridad de investigación {priority_value}." if priority_value else "",
        ("Recursos que requieren corroboración: " + ", ".join(block.evaluacion_impacto["recursos_en_riesgo"]) + ".")
        if block.evaluacion_impacto["recursos_en_riesgo"] else "",
        f"Impacto técnico potencial: {impact}, sujeto a las condiciones del bloque CIA." if impact != "no_evaluable" else "",
    ]))
    investigation = ""
    if follow_up:
        citations = ", ".join(f"#{eid}" for eid in follow_up.get("eventos", [])[:6])
        investigation = (f"Diligencia sobre {follow_up['activo']}. {follow_up['medidas']} {follow_up['validacion']}"
                         + (f" Evidencia {citations}." if citations else ""))
    report["conclusion"] = "\n\n".join(filter(None, [outcome, technical, investigation, observed_scope]))
    return structured

