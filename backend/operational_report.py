"""Analyst-facing report assembled from the selected analysis and cited evidence."""


def section(title, paragraphs=(), columns=(), rows=(), kind="analysis"):
    return dict(title=title, paragraphs=list(paragraphs), columns=list(columns), rows=list(rows), kind=kind)


def analyst_sections(report, payload, commands, safeguard_links=None):
    detail = payload.get("informe") or {}
    assessment = payload.get("evaluacion_incidente") or {}
    revisions = assessment.get("revisiones") or []
    decision = revisions[-1] if revisions else {}
    old = report["sections"]
    summary = next((item for item in old if item["title"] == "Interpretación del análisis guardado"), None)
    executive = summary["paragraphs"][1:] if summary else ["El resultado histórico carece de síntesis narrativa. Se requiere revisión del analista para completar la valoración."]
    sections = [section("Síntesis ejecutiva", executive, kind="executive")]
    sections.append(section("Alcance, estado y calidad de la evaluación", [
        detail.get("contexto") or "El alcance disponible corresponde a los registros de esta sesión del honeypot.",
        "Estado de cobertura del resultado seleccionado. " + report["status"],
        "Las fechas de este documento se presentan en America/Guayaquil (UTC-05:00)."
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
    tty = ((payload.get("contexto_observado") or {}).get("cobertura_evidencia") or {}).get("referencias_tty") or []
    for hypothesis in detail.get("hipotesis") or []:
        questions.append([hypothesis["descripcion"], ", ".join("#"+str(eid) for eid in hypothesis.get("eventos", [])),
                          ("Comprobar la referencia registrada a la grabación en " + ", ".join("#" + str(eid) for eid in tty)
                           if tty else "Contrastar los eventos citados con auditoría independiente del recurso y verificar alcance y autorización.")])
    sections.append(section("Hipótesis y diligencias de investigación", detail.get("limitaciones") or [
        "La cobertura adicional debe establecerse durante la revisión del caso."
    ], ["Hipótesis pendiente", "Evidencia", "Diligencia propuesta"], questions))
    if detail.get("conclusion") and not payload.get("comportamientos_semanticos"):
        sections.append(section("Conclusión del análisis", detail["conclusion"].split("\n\n")))
    from .analysis_report import safeguard_cards
    actions = [
        section(f"{card['rows'][0][1]} · {card['title']}", [], ["Campo", "Detalle"],
                card["rows"], kind="response")
        for card in safeguard_cards(detail.get("recomendaciones") or [], payload, safeguard_links)
    ]
    sections.append(section("Plan de investigación y respuesta", [
        "Las intervenciones siguientes proceden del análisis seleccionado y requieren aprobación del responsable. Conserve los registros originales antes de introducir cambios en el entorno."
    ]))
    sections += actions
    tracking = payload.get("seguimiento_salvaguardas") or {}
    if tracking:
        from .session_report import stored_time
        for index in range(1, len(actions) + 1):
            code = f"SG-{index:03d}"
            if not (reviews := tracking.get(code)):
                continue
            sections.append(section(f"Historial de {code}", [], [
                "Fecha Ecuador / revisor", "Estado / responsable", "Motivo y verificación"
            ], [[stored_time(review.get("revisado_en")) + "\n" + review.get("revisado_por", ""),
                 review["estado"] + "\n" + review["responsable"],
                 review["motivo"] + "\n" + review.get("verificacion", "")]
                for review in reviews], kind="response"))
    if not actions:
        sections.append(section("Acciones por concretar", ["El análisis histórico carece de medidas estructuradas. El analista debe definir intervención, responsable y criterio de eficacia a partir de los hallazgos documentados."]))
    # These tasks are explicitly investigative and conditioned on observed events.
    command_ids = ", ".join("#"+str(row.id_evento) for row in commands[:8])
    sections.append(section("Preservación, escalamiento y criterio de cierre", [
        "Conservar los registros originales y los artefactos acreditados con acceso restringido. Registrar la cadena de custodia.",
        "Contrastar cada orden con eventos de resultado independientes. Referencias de comandos de esta sesión. " + (command_ids or "Sin comandos registrados."),
        "Escalar al responsable de respuesta cuando se corrobore afectación o amenaza sobre activos reales, aportando la evidencia y el alcance confirmado.",
        "Cierre registrado. " + decision["criterio_cierre"] if decision.get("criterio_cierre") else
        "El cierre requiere resolver la autorización de la actividad, documentar su alcance e impacto y verificar las medidas aprobadas. La revisión humana debe registrar las cuestiones que permanezcan abiertas."
    ]))
    retained = {"Cobertura del análisis", "Cobertura por sección", "Vigencia y cobertura del análisis",
                "Indicadores del alcance", "Conjunto de evidencia del triaje", "Decisión documentada del analista",
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
