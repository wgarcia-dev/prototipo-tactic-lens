"""Analyst-facing report assembled from the selected analysis and cited evidence."""


def section(title, paragraphs=(), columns=(), rows=(), kind="analysis"):
    return dict(title=title, paragraphs=list(paragraphs), columns=list(columns), rows=list(rows), kind=kind)


def analyst_sections(report, payload, commands):
    detail = payload.get("informe") or {}
    assessment = payload.get("evaluacion_incidente") or {}
    revisions = assessment.get("revisiones") or []
    decision = revisions[-1] if revisions else {}
    old = report["sections"]
    summary = next((item for item in old if item["title"] == "Interpretación del análisis guardado"), None)
    executive = summary["paragraphs"][1:] if summary else ["El resultado histórico carece de síntesis narrativa. Se requiere revisión del analista para completar la valoración."]
    executive += [detail["conclusion"]] if detail.get("conclusion") else []
    executive.append("Decisión registrada por el analista. " + decision["justificacion"] if decision else
                     "La decisión sobre el incidente está pendiente de revisión humana.")
    sections = [section("Síntesis ejecutiva", executive, kind="executive")]
    sections.append(section("Alcance, estado y calidad de la evaluación", [
        detail.get("contexto") or "El alcance disponible corresponde a los registros de esta sesión del honeypot.",
        "Estado de cobertura del resultado seleccionado. " + report["status"],
        "Las fechas de este documento se presentan en America/Guayaquil (UTC-05:00)."
    ], ["Dimensión", "Valoración"], [
        ["Clasificación", decision.get("decision", assessment.get("clasificacion", "Pendiente de evaluación"))],
        ["Severidad", decision.get("severidad", "Por determinar por el analista")],
        ["Impacto documentado", decision.get("impacto", "Pendiente de corroborar con el propietario del activo y telemetría independiente")],
        ["Alcance documentado", decision.get("alcance", "Una sesión SSH del señuelo Cowrie")],
        ["Responsable", decision.get("responsable", "Pendiente de asignación")]
    ]))
    findings = []
    for index, phase in enumerate(detail.get("fases") or [], 1):
        references = ", ".join("#" + str(eid) for eid in phase.get("eventos", []))
        findings.append(section(f"H{index:02d} · {phase.get('fase', 'Actividad observada')}", [
            phase.get("observado", ""),
            "Interpretación técnica del modelo. " + phase.get("interpretacion", "Sin interpretación guardada"),
            "Resultado sustentado y alcance. " + phase.get("resultado", "Pendiente de verificar"),
            "Eventos que permiten contrastar el hallazgo. " + references
        ], kind="finding"))
    sections += findings or [section("Reconstrucción técnica pendiente", [
        "El resultado disponible carece de fases estructuradas. El anexo conserva los comandos y eventos para completar la reconstrucción durante la revisión del caso."
    ])]
    mitre = next((item for item in old if item["title"] == "Mapeos MITRE ATT&CK"), None)
    if mitre is not None:
        sections.append(mitre)
    questions = []
    for hypothesis in detail.get("hipotesis") or []:
        questions.append([hypothesis["descripcion"], ", ".join("#"+str(eid) for eid in hypothesis.get("eventos", [])),
                          "Correlacionar los eventos citados con la grabación TTY y comprobar autorización y alcance con el responsable del activo."])
    sections.append(section("Hipótesis y diligencias de investigación", detail.get("limitaciones") or [
        "La cobertura adicional debe establecerse durante la revisión del caso."
    ], ["Hipótesis pendiente", "Evidencia", "Diligencia propuesta"], questions))
    from .analysis_report import safeguard_cards
    actions = [
        section(f"{card['rows'][0][1]} · {card['title']}", [], ["Campo", "Detalle"],
                card["rows"], kind="response")
        for card in safeguard_cards(detail.get("recomendaciones") or [], payload.get("seguimiento_salvaguardas"))
    ]
    sections.append(section("Plan de investigación y respuesta", [
        "Las intervenciones siguientes proceden del análisis seleccionado y requieren aprobación del responsable. Conserve los registros originales antes de introducir cambios en el entorno."
    ]))
    sections += actions
    tracking = payload.get("seguimiento_salvaguardas") or {}
    for card in safeguard_cards(detail.get("recomendaciones") or [], payload.get("seguimiento_salvaguardas")):
        code = card["rows"][0][1]
        revisions = tracking.get(code) or []
        if revisions:
            from .session_report import stored_time
            sections.append(section("Historial de " + code, [], [
                "Fecha Ecuador / revisor", "Estado / responsable", "Motivo y verificación"
            ], [[stored_time(review.get("revisado_en")) + "\n" + review.get("revisado_por", ""),
                 review["estado"] + "\n" + review["responsable"],
                 review["motivo"] + "\n" + review.get("verificacion", "")]
                for review in revisions]))
    if not actions:
        sections.append(section("Acciones por concretar", ["El análisis histórico carece de medidas estructuradas. El analista debe definir intervención, responsable y criterio de eficacia a partir de los hallazgos documentados."]))
    # These tasks are explicitly investigative and conditioned on observed events.
    command_ids = ", ".join("#"+str(row.id_evento) for row in commands[:8])
    sections.append(section("Preservación, escalamiento y criterio de cierre", [
        "Conservar JSON original, grabación TTY disponible y artefactos capturados con hashes y acceso restringido. Registrar quién obtuvo cada evidencia y cuándo.",
        "Para revisar la interacción de shell, contrastar las entradas con la grabación y los resultados del sensor. Referencias de comandos de esta sesión. " + (command_ids or "Sin comandos registrados."),
        "Escalar al responsable de respuesta cuando se corrobore afectación o amenaza sobre activos reales, aportando la evidencia y el alcance confirmado.",
        "Cierre registrado. " + decision["criterio_cierre"] if decision.get("criterio_cierre") else
        "El cierre requiere resolver la autorización de la actividad, documentar su alcance e impacto y verificar las medidas aprobadas. La revisión humana debe registrar las cuestiones que permanezcan abiertas."
    ]))
    retained = {"Cobertura del análisis", "Decisión documentada del analista",
                "Observables", "Evaluación por fuente externa"}
    for item in old:
        if item["title"] in retained:
            sections.append(item)
    sections.append(section("Anexos de evidencia", ["Los registros siguientes permiten reproducir las comprobaciones. La interpretación del cuerpo principal corresponde al análisis seleccionado."], kind="appendix"))
    for item in old:
        if item["title"] in {"Registro de comandos", "Distribución de actividad", "Cronología de evidencia"}:
            sections.append(item)
    report["sections"] = sections
    report["title"] = "Evaluación técnica y respuesta a actividad SSH"
    report["subtitle"] = "Sesión " + dict(report["metadata"]).get("Sesión Cowrie", report["id_sesion"])
    return report
