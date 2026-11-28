"""Common display projection for React, report JSON, PDF and DOCX."""
from .operational_report import section
from .session_report import stored_time

OBSERVED = {
    "IO01": "Afectación acreditada", "IO02": "Afectación sin acreditar",
    "IO03": "Sin afectación registrada en la evidencia examinada",
    "IO04": "Evidencia insuficiente", "IO05": "Dimensión no aplicable a la evidencia",
}


def refs(items):
    return ", ".join("#" + str(item) for item in items)


def label(value):
    return str(value).replace("_", " ") if value is not None else ""


LABELS = {
    "id_sensor": "Identificador del sensor", "modalidad": "Modalidad", "servicio_objetivo": "Servicio objetivo",
    "ip_origen": "IP de origen", "ip_destino": "IP de destino", "puerto_origen": "Puerto de origen",
    "puerto_destino": "Puerto de destino", "naturaleza_amenaza": "Naturaleza de la amenaza",
    "tipo_actividad": "Tipo de actividad", "grado_automatizacion": "Grado de automatización",
    "complejidad_tecnica": "Complejidad técnica", "nivel_interaccion": "Nivel de interacción",
    "protocolo": "Protocolo", "vector": "Vector", "metodo_acceso": "Método de acceso",
    "mecanismo_autenticacion": "Mecanismo de autenticación", "estado_acceso": "Estado de acceso",
}


def analytical_sections(payload):
    if not payload.get("version_esquema"):
        return []
    threat = payload["evaluacion_amenaza"]
    impact = payload["evaluacion_impacto"]
    organization = threat["riesgo_organizacional"]
    context = payload["contexto_observado"]
    coverage = context["cobertura_evidencia"]
    confidence = threat["confianza_evaluacion"]
    assessment = " · ".join(item for item in (
        threat["codigo_severidad"], threat["severidad_preliminar"],
        label(threat["prioridad_investigacion"]), confidence["nivel"],
    ) if item)
    output = [
        section("Evaluación técnica", [assessment, threat["fundamento_severidad"], threat["fundamento_prioridad"]],
                ["Factor", "Descripción", "Evidencia"], [
                    [factor["codigo"], factor["descripcion"], refs(factor["eventos"])]
                    for factor in threat["factores_agravantes"] + threat["factores_limitantes"]
                ]),
        section("Riesgo técnico potencial y riesgo organizacional", [], ["Ámbito", "Estado", "Fundamento"], [
            ["Técnico potencial", label(threat.get("riesgo_tecnico_potencial", {}).get("nivel")),
             threat.get("riesgo_tecnico_potencial", {}).get("fundamento", "")],
            ["Organizacional", label(organization.get("nivel")) if organization.get("estado") == "evaluado" else "No evaluado",
             organization.get("fundamento", "")],
        ]),
        section("Contexto y cobertura", [f"Eventos almacenados {coverage['eventos_almacenados']}. "
            f"Entregados al modelo {coverage['eventos_entregados_al_modelo']}. "
            f"Omitidos del prompt {coverage['eventos_omitidos_del_prompt']}.", *coverage["fuentes_disponibles"],
            *([] if "terminal" in coverage else [note for note in coverage["limitaciones"] if "salidas de terminal quedan fuera" not in note])],
            ["Atributo", "Valor"], [[LABELS[key], label(context[key])] for key in
                          ("id_sensor", "modalidad", "servicio_objetivo", "ip_origen", "ip_destino", "puerto_origen", "puerto_destino")
                          if context.get(key) is not None]),
        section("Impacto CIA", [OBSERVED[impact["impacto_observado"]], impact["fundamento"]],
            ["Dimensión", "Observado", "Nivel metodológico", "Escenario, condiciones y evidencia"], [
                [dimension.capitalize(), OBSERVED[record["estado_observado"]],
                 ("Escenario cualitativo" if record.get("recursos") and record["nivel_potencial"] == "no_evaluable"
                  else label(record["nivel_potencial"]).capitalize()),
                 " ".join(part for part in [record["descripcion"], record["fundamento"],
                    *record["condiciones"], ("Recursos: " + ", ".join(record["recursos"]) + ".") if record.get("recursos") else "",
                    record.get("recomendacion"), refs(record["eventos"])] if part)]
                for dimension in ("confidencialidad", "integridad", "disponibilidad") for record in (impact[dimension],)
            ]),
    ]
    character = payload["caracterizacion_amenaza"]
    output.append(section("Caracterización de la amenaza", [character["fundamento"],
        *character.get("capacidades_observadas", [])], ["Aspecto", "Valor y fundamento"], [
        [LABELS[key], " ".join(filter(None, [label(character.get(key)).capitalize(), character.get(basis)]))]
        for key, basis in (("naturaleza_amenaza", ""), ("tipo_actividad", ""), ("grado_automatizacion", "fundamento_automatizacion"),
                           ("complejidad_tecnica", "fundamento_complejidad"), ("nivel_interaccion", ""))
    ]))
    vector = payload["vector_ataque"]
    output.append(section("Vector y mecanismo", [vector["fundamento"], refs(vector["eventos"])],
        ["Aspecto", "Valor"], [[LABELS[key], label(vector[key])] for key in
                              ("protocolo", "vector", "metodo_acceso", "mecanismo_autenticacion", "estado_acceso") if vector[key] is not None]))
    if payload["herramientas_artefactos"]:
        output.append(section("Herramientas y artefactos", [], ["Elemento", "Tipo y estado", "Interpretación técnica", "Confianza y evidencia"],
            [[item["nombre"], " · ".join(label(item.get(key)) for key in ("tipo", "categoria", "estado_utilizacion")),
              "\n".join(text for text in (
                  (item.get("forma_utilizacion") or item.get("finalidad_probable") or "").rstrip("."),
                  "Recurso objetivo — " + item["recurso_objetivo"] if item.get("recurso_objetivo") else "",
                  "Implicación — " + item["implicacion_seguridad"] if item.get("implicacion_seguridad") else "",
              ) if text),
              " · ".join(filter(None, [label(item.get("confianza_analitica", {}).get("nivel")), refs(item["eventos"])]))]
             for item in payload["herramientas_artefactos"]]))
    if payload["correlacion"]["sesiones_relacionadas"]:
        correlation = payload["correlacion"]
        output.append(section("Correlación contextual", [correlation["fundamento_correlacion"],
            f"Sesiones en el patrón {correlation['frecuencia']}."], ["Sesión", "Relación"], [[item, label(correlation["tipo_relacion"])] for item in correlation["sesiones_relacionadas"]]))
    associations = payload["correlacion"].get("asociaciones_contextuales") or []
    if associations:
        output.append(section("Asociaciones contextuales", ["Las coincidencias no prueban identidad ni cambian la severidad."],
            ["Sesión asociada","Coincidencias","Evidencia actual","Eventos de sesión asociada"], [
                [item["id_sesion"], ", ".join(item["herramientas"]+item["operaciones_comunes"]+item["tecnicas"])
                 + f". Recursos no de transporte compartidos {item['total_observables_no_transporte']}. "
                 + ("Ventana: " + " a ".join(stored_time(t) for t in item["ventana"]) + ". " if item.get("ventana") else "")
                 + item["alcance"], refs(item["eventos_actuales"]), refs(item["eventos_asociados"])]
                for item in associations]))
    observables = payload.get("observables_contextuales") or []
    if observables:
        output.append(section("Observables por función", [],
            ["Tipo y alcance","Clasificación y uso investigativo","Evidencia"],
            [[label(item["tipo"]) + " · " + label(item["alcance"]),
              label(item["clasificacion"]).capitalize() + ". " + (
                  "Cotejar origen y destino con la auditoría del servicio en la ventana de la sesión."
                  if item["alcance"] == "transporte" else
                  "Correlacionar el observable con las acciones citadas antes de atribuirle un efecto."),
              refs(item["eventos"])]
             for item in observables]))
    assertions = {item["id"]: item for item in payload["evidencias_analiticas"]}
    principal = [assertions[key] for key in payload["hallazgos_principales"] if key in assertions]
    if principal:
        output.append(section("Hallazgos que sustentan la severidad", [], ["Comportamiento", "Grado", "Evidencia"],
            [[item["fundamento"], label(item["grado_evidencia"]), refs(item["eventos"])] for item in principal]))
    actions = payload.get("acciones") or []
    detail = payload.get("informe") or {}
    if payload.get("comportamientos_semanticos"):
        actions_by_id = {item.get("id_accion"):item for item in actions}
        phases = detail.get("fases") or []
        if phases:
            output.append(section("Cronología estructurada", ["La sucesión temporal no establece causalidad."],
                ["Orden y fase","Ventana (Ecuador)","Estado","Acciones y citas"], [
                  [f'{phase["orden"]}. {phase["fase"]}',f'{stored_time(phase["inicio_fase"])} a {stored_time(phase["fin_fase"])}',
                   label(phase["estado_resultado"]), " ".join(actions_by_id[key]["descripcion"] for key in phase["acciones_relacionadas"]
                       if key in actions_by_id) + " " + refs(phase["eventos"])] for phase in phases]))
        objectives = detail.get("hipotesis") or []
        if objectives:
            output.append(section("Objetivos operativos e hipótesis", [], ["Objetivo","Alcance y confianza","Evidencia"], [
                [" ".join(filter(None, [item["descripcion"], item.get("fundamento"),
                  "Alternativas: " + " ".join(item["hipotesis_alternativas"]) if item.get("hipotesis_alternativas") else "",
                  "Recursos: " + ", ".join(item["recursos_interes"]) if item.get("recursos_interes") else ""])),
                 ("Inferencia " + label(item["objetivo_probable"]) if item.get("objetivo_probable") else
                  "Relación temporal verificada" if item.get("relacion") else "Objetivo inmediato sustentado")
                 + " · " + label((item.get("confianza_analitica") or {}).get("nivel")), refs(item["eventos"])]
                for item in objectives]))
        if detail.get("conclusion"):
            output.append(section("Conclusiones del análisis", detail["conclusion"].split("\n\n")))
    if actions:
        output.append(section("Acciones evaluadas", [], ["Acción", "Resultado y alcance", "Evidencia"],
            [[item["descripcion"], "\n".join(filter(None, [
                item["resultado"], "Recurso — " + item["recurso_objetivo"] if item.get("recurso_objetivo") else "",
                *item.get("limitaciones", [])])), refs(item["eventos"])] for item in actions]))
    procedures = list(dict.fromkeys((mapping["codigo"], mapping.get("codigo_tactica") or "",
        mapping["procedimiento_observado"], refs(mapping["eventos"])) for action in actions
        for mapping in action.get("mitre", []) if mapping.get("procedimiento_observado")))
    if procedures:
        output.append(section("Procedimientos ATT&CK acreditados", [],
            ["Técnica", "Táctica", "Procedimiento", "Evidencia"], procedures))
    strategies = payload["estrategias_deteccion"]
    if strategies:
        output.append(section("Estrategias de detección y mitigación", [], ["Estrategia", "Criterio y fundamento", "Validación y referencias", "Evidencia"],
            [[item["nombre"], " ".join(filter(None, [item.get("descripcion"), item.get("criterio_deteccion"), item.get("fundamento")])),
                item["criterio_validacion"] + " " +
                " · ".join(ref["codigo"] + " " + (ref.get("url") or ref.get("nombre") or "") for ref in item["referencias"]),
                refs(item["eventos"])] for item in strategies]))
    confidence_rows = [[item["fundamento"], label(item["grado_evidencia"]),
                        item["confianza_analitica"]["nivel"], refs(item["eventos"])] for item in principal[:8]]
    confidence_rows.extend([item["descripcion"], "Inferencia", label(item.get("confianza_analitica", {}).get("nivel")),
                            refs(item["eventos"])] for item in detail.get("hipotesis", [])
                           if item.get("relacion") or item.get("objetivo_probable"))
    output.append(section("Confianza y alcance", [payload["fundamento_confianza"], payload["alcance_conclusion"],
        *payload["evidencia_adicional_requerida"]], ["Proposición", "Alcance", "Confianza", "Evidencia"], confidence_rows))
    output.append(section("Metadatos técnicos", [
        f"Esquema {payload['version_esquema']} · metodología {payload['version_metodologia']} · matriz {payload['version_matriz']} · contratos {payload['version_contratos']} · narrativa {payload['version_narrativa']}"]))
    return output

