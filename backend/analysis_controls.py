"""Defensive detections and safeguards derived from the captured behavior."""
from collections import defaultdict

from .threat_evaluation import ROWS

CONTROLS = {
    "autenticacion": (
        "Revisar autenticaciones del servicio",
        "Autenticaciones SSH",
        "Acceso fuera de la política autorizada o intentos de acceso no previstos.",
        "Comparar aceptación y rechazo con la política y los registros del servicio protegido. Verificar el origen por un canal independiente.",
        "Comprobar estado, hora y cita del evento frente al registro independiente y a una prueba autorizada.",
    ),
    "interaccion": (
        "Verificar auditoría de órdenes de terminal",
        "Registro de interacción",
        "Pérdida de visibilidad sobre las operaciones solicitadas tras el acceso.",
        "Conservar las entradas citadas. Contrastar el alcance y la autorización con el registro de acceso y la auditoría del terminal.",
        "Confirmar que la prueba de auditoría registra la solicitud, su resultado y la referencia de sesión por separado.",
    ),
    "descubrimiento": (
        "Supervisar consultas de reconocimiento",
        "Inventario y metadatos del sistema",
        "Exposición de información operativa mediante consultas del entorno.",
        "Revisar quién tiene permiso de consulta y comprobar que los registros distinguen solicitud y lectura efectiva.",
        "Contrastar las consultas citadas con una auditoría autorizada del inventario y registrar si hubo acceso efectivo.",
    ),
    "recursos": (
        "Comprobar acceso a recursos referenciados",
        "Recursos citados en las operaciones",
        "Lectura o manipulación de recursos que excedan los permisos definidos.",
        "Revisar permisos efectivos y auditoría de acceso sobre el recurso indicado. Preservar las citas.",
        "Confirmar que una prueba autorizada registra la decisión de acceso y su resultado.",
    ),
    "modificacion": (
        "Verificar integridad y privilegios",
        "Configuraciones, controles o servicios solicitados",
        "Cambio de configuración o privilegios fuera de la política aprobada.",
        "Contrastar las solicitudes con auditoría de cambios y con una referencia de configuración aprobada.",
        "Comparar el estado anterior y posterior del recurso y exigir trazabilidad de la operación efectiva.",
    ),
    "red": (
        "Correlacionar solicitudes de red",
        "Flujos y destinos referenciados",
        "Pérdida de trazabilidad entre la solicitud y una conexión efectiva.",
        "Contrastar las solicitudes con flujos autorizados, dirección de transferencia y registros del destino.",
        "Verificar si existe un flujo independiente con tiempo y recurso compatibles.",
    ),
    "transferencia": (
        "Revisar el artefacto registrado",
        "Registro de transferencia",
        "Ingreso de un artefacto cuya procedencia o utilización requiere corroboración.",
        "Conservar los metadatos de transferencia y contrastar procedencia e integridad por un proceso autorizado.",
        "Verificar dirección, identificador de artefacto y registros del origen sin ejecutar el archivo.",
    ),
}


def complement_strategies(behaviors, witnesses, priority):
    groups = defaultdict(list)
    complementary = {eid for witness in witnesses if witness.rule in {"RC03","RC04","RC05","RC06"}
                     for eid in witness.ids}
    for b in behaviors.values():
        if b.categoria == "autenticacion":
            groups["autenticacion"].append(b)
        elif b.evento in complementary and b.categoria in CONTROLS and b.estado == "intento":
            groups[b.categoria].append(b)
    strategies = []
    for category, group in groups.items():
        title, target, risk, measures, validation = CONTROLS[category]
        rules = sorted({w.rule for w in witnesses if w.rule.startswith("RC") and w.ids
                        and any(b.evento in w.ids for b in group)})
        operations = list(dict.fromkeys(b.descripcion for b in group))
        resources = list(dict.fromkeys(b.recurso for b in group if b.recurso))
        specific_target = ", ".join(resources[:5]) if resources and category != "autenticacion" else target
        strategies.append({
            "nombre":title,"descripcion":risk,"codigo_mitre":None,"comportamiento_objetivo":". ".join(operations[:5]) + ".",
            "fuentes_datos":[{"fuente":"Cowrie JSON", "componente":target}],
            "criterio_deteccion":f"Buscar las operaciones descritas en la misma sesión y contrastar su alcance sobre {specific_target}.",
            "prioridad":priority,"justificacion":f"Evidencia de {target.lower()} con reglas de contexto {', '.join(rules) or 'aplicables'}.",
            "criterio_validacion":validation,"eventos":[str(b.evento) for b in group],
            "referencias":[{"codigo":rule,"nombre":"Regla complementaria TacticLens"} for rule in rules],
            "origen":"TacticLens","recurso_objetivo":specific_target,"medidas_propuestas":measures,
        })
    return strategies


def strategy_safeguard(strategy, official):
    code = strategy["codigo_mitre"]
    target = strategy.get("recurso_objetivo") or (ROWS[code]["nombre_oficial"] if code else "Registro citado")
    return {
        "salvaguarda":strategy["nombre"],"activo":target,
        "riesgo":strategy["descripcion"],"objetivo":strategy["comportamiento_objetivo"],
        "medidas":strategy.get("medidas_propuestas") or "Preservar las citas y contrastar la operación con auditoría del recurso identificado.",
        "validacion":strategy["criterio_validacion"],"prioridad_recomendada":strategy["prioridad"],
        "justificacion":strategy["justificacion"],"tecnicas_relacionadas":[code] if code else [],
        "mitigaciones_mitre":official["tecnicas"][code]["mitigaciones"] if code else [],
        "eventos":strategy["eventos"],
    }


def cited_safeguard(focus, behaviors, priority, *, provider_selected=True):
    """Render a provider-selected investigation only when every cited event supports it."""
    if not behaviors:
        return None
    if focus == "verificar_recurso" and all(b.objetivo and b.recurso and b.categoria in
            {"descubrimiento","recursos","modificacion","red","transferencia"} for b in behaviors):
        resources = ", ".join(dict.fromkeys(b.recurso for b in behaviors))
        operation = "; ".join(dict.fromkeys(b.objetivo.rstrip(".") for b in behaviors))
        details = ("Corroborar operaciones sobre el recurso", resources,
            "Confundir la orden capturada con acceso efectivo o un cambio del recurso.",
            f"Determinar el resultado de la solicitud de {operation}.",
            "Buscar en la auditoría del recurso operaciones compatibles con la hora y la cuenta de la captura.",
            "Documentar si la auditoría registra acceso, rechazo o cambio y si coincide con las citas.")
    elif focus == "aclarar_orden" and all(b.operacion == "orden_sin_semantica" for b in behaviors):
        details = ("Aclarar las órdenes citadas", "Registro de terminal",
            "Clasificar una entrada ambigua sin conocer la operación efectiva.",
            "Determinar la operación y su resultado, si la evidencia disponible lo permite.",
            "Consultar el registro de terminal por sesión y hora. Comparar la entrada citada con la respuesta y el estado de salida disponibles.",
            "Registrar qué orden se pudo resolver y qué evidencia respalda el resultado.")
    elif focus == "verificar_fallo" and all(b.estado == "fallido" for b in behaviors):
        details = ("Corroborar el fallo registrado", "Registro del terminal y del servicio",
            "Atribuir el fallo a una orden concreta sin un vínculo en la captura.",
            "Identificar qué operación generó el fallo.",
            "Buscar registros de error en la misma sesión y ventana. Verificar si contienen un identificador de operación o correlación con el evento.",
            "Conservar el código de error y el vínculo verificable con la operación. Mantener abierta la atribución si falta ese vínculo.")
    elif focus == "corroborar_acceso" and all(b.categoria == "autenticacion" for b in behaviors):
        details = ("Corroborar la autenticación observada", "Registros de acceso SSH",
            "Interpretar la aceptación del sensor como autorización o acceso efectivo a un sistema protegido.",
            "Determinar si existe un acceso correspondiente en el servicio protegido.",
            "Cotejar hora, origen y decisión de autenticación de las citas con la auditoría SSH y la política de acceso.",
            "Registrar si se encontró un acceso coincidente y si estaba autorizado.")
    else:
        return None
    title, resource, risk, objective, measures, validation = details
    return {"salvaguarda":title, "activo":resource, "riesgo":risk, "objetivo":objective,
            "medidas":measures, "validacion":validation, "prioridad_recomendada":priority,
            "justificacion":("Diligencia propuesta por el modelo y verificada con los eventos citados." if provider_selected
                             else "Diligencia priorizada por la evidencia de los eventos citados."),
            "tecnicas_relacionadas":[], "mitigaciones_mitre":[], "eventos":[str(b.evento) for b in behaviors]}
