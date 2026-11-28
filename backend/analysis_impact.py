"""Evaluate potential CIA consequences without claiming changes to real assets."""
from collections import defaultdict

from .threat_evaluation import CIA, IMPACT, LEVELS, ROWS, Witness

DISCOVERY = {r["codigo_mitre"] for r in ROWS.values()
             if any(t["codigo"] == "TA0007" for t in r["tacticas_admitidas"])}

# All entries require the corresponding v5 witness, including its exact predicate.
IMPACTS = {
    "IMP03": ({"T1110", "T1110.001", "T1110.003"}, {"confidencialidad": "moderado"}, "Acceso efectivo a una cuenta del servicio objetivo."),
    "IMP04": ({"T1003.008", "T1552.004"}, {"confidencialidad": "alto"}, "Lectura efectiva del material protegido."),
    "IMP06": ({"T1136.001"}, {"integridad": "moderado"}, "Creación efectiva de la cuenta en el activo."),
    "IMP08": ({"T1053.003", "T1053.006", "T1098.004", "T1098.007", "T1543.002"}, {"integridad": "alto"}, "Cambio persistente confirmado en la configuración."),
    "IMP09": ({"T1070.003", "T1685.006"}, {"integridad": "alto"}, "Eliminación efectiva de los registros objetivo."),
    "IMP10": ({"T1690", "T1685.006"}, {"integridad": "alto"}, "Alteración efectiva del registro de actividad."),
    "IMP11": ({"T1105"}, {"integridad": "moderado"}, "Incorporación o utilización posterior del archivo transferido."),
    "IMP12": ({"T1552.003", "T1560.001"}, {"confidencialidad": "alto"}, "Obtención efectiva del contenido sensible."),
    "IMP13": ({"T1489"}, {"disponibilidad": "moderado"}, "Interrupción efectiva del servicio solicitado."),
    "IMP14": ({"T1529"}, {"disponibilidad": "alto"}, "Apagado o reinicio efectivo del sistema."),
    "IMP15": ({"T1531"}, {"integridad": "moderado", "disponibilidad": "moderado"}, "Pérdida efectiva del acceso asociado a la cuenta."),
}


def observed_state(*, has_evidence, applicable, observed_effect=False, verified_exclusion=False, activity=False):
    if not has_evidence:
        return "IO04"
    if not applicable:
        return "IO05"
    if observed_effect:
        return "IO01"
    if verified_exclusion or not activity:
        return "IO03"
    return "IO02"


def evaluate_impact(witnesses: list[Witness], *, confirmed_privilege: Witness | None = None, behaviors=()):
    effects = defaultdict(list)

    def add(rule, dimensions, condition, witness):
        for dimension, level in dimensions.items():
            effects[dimension].append((rule, level, condition, witness))

    for witness in witnesses:
        code = witness.code
        if code in DISCOVERY:
            specific = witness.level == "S2"
            add("IMP02" if specific else "IMP01", {"confidencialidad": "moderado" if specific else "bajo"},
                "Obtención efectiva de los datos del objetivo consultado.", witness)
        for rule, (codes, dimensions, condition) in IMPACTS.items():
            if code in codes:
                add(rule, dimensions, condition, witness)
        if code == "T1222.002":
            dimensions = {"integridad": "moderado"}
            if witness.specific == "terceros":
                dimensions["confidencialidad"] = "alto"  # v5 solo admite shadow y rutas de clave privada.
            add("IMP05", dimensions, "Aplicación efectiva de los permisos solicitados sobre el recurso protegido.", witness)
        if code == "T1489" and witness.specific == "defensa":
            add("IMP10", {"integridad": "alto", "disponibilidad": "moderado"},
                "Interrupción efectiva del control defensivo identificado.", witness)
    if confirmed_privilege and confirmed_privilege.grade == "efecto_verificado":
        add("IMP07", {"confidencialidad": "alto", "integridad": "alto"},
            "Aumento de privilegios efectivos sustentado por auditoría independiente.", confirmed_privilege)

    output = {}
    all_ids = set()
    all_rules = set()
    context = any(witness.ids and witness.level in LEVELS for witness in witnesses)
    for dimension in CIA:
        matches = effects[dimension]
        ids = {eid for _, _, _, witness in matches for eid in witness.ids}
        rules = {rule for rule, *_ in matches}
        all_ids.update(ids)
        all_rules.update(rules)
        state = observed_state(has_evidence=context, applicable=bool(matches), activity=bool(matches))
        level = max((value for _, value, _, _ in matches), key=IMPACT.index, default="no_evaluable")
        output[dimension] = {
            "estado_observado": state, "nivel_potencial": level,
            "descripcion": ("Escenario condicionado por conductas documentadas." if matches
                            else "Los eventos examinados no sustentan un escenario para esta dimensión."),
            "fundamento": "La captura de la sesión carece de telemetría independiente de un activo real.",
            "condiciones": list(dict.fromkeys(condition for _, _, condition, _ in matches)),
            "eventos": [str(eid) for eid in sorted(ids)], "reglas_aplicadas": sorted(rules),
        }
    # Interpret observed operations separately from the approved IMP and NIST levels.
    requested = [b for b in behaviors if b.objetivo]
    unresolved = [b for b in behaviors if b.operacion == "orden_sin_semantica"]
    availability_operations = {"T1489", "T1529", "T1531"}
    contextual = {
        "confidencialidad": [b for b in requested if b.categoria in {"descubrimiento", "recursos"}],
        "integridad": [b for b in requested if b.categoria == "modificacion" and b.operacion not in availability_operations],
        "disponibilidad": [b for b in requested if b.operacion in availability_operations],
    }

    absent = {
        "confidencialidad": "La captura no contiene una consulta identificable de información o recursos.",
        "integridad": "Las operaciones interpretadas no describen un mecanismo de modificación de archivos, cuentas o configuraciones.",
        "disponibilidad": "Las operaciones interpretadas no solicitan interrumpir el servicio o el sistema.",
    }
    scenarios = {
        "confidencialidad": ("Si la consulta se respondiera en un activo real, los datos devueltos podrían orientar el reconocimiento posterior.",
                            "Contrastar la respuesta del terminal con auditoría del recurso consultado y verificar qué información puede revelar la cuenta."),
        "integridad": ("El cambio podría alterar el estado del recurso si la orden se ejecutara con permisos suficientes.",
                       "Contrastar solicitudes con la auditoría y el estado del recurso antes y después."),
        "disponibilidad": ("El acceso al recurso podría interrumpirse si la operación se aplicara al objetivo.",
                           "Verificar disponibilidad y eventos de servicio en la telemetría del activo."),
    }
    for dimension, record in output.items():
        support = contextual[dimension]
        if support:
            consequence, recommendation = scenarios[dimension]
            record["descripcion"] = ". ".join(dict.fromkeys(b.descripcion.rstrip(".") for b in support)) + ". " + consequence
            record["fundamento"] = ("La entrada acredita la solicitud. La respuesta del sensor por sí sola no acredita un efecto en el activo.")
            record["condiciones"] = list(dict.fromkeys([*record["condiciones"],
                "Operación ejecutada sobre el recurso objetivo y resultado corroborado mediante registros independientes."]))
            record["eventos"] = sorted(set(record["eventos"]) | {str(b.evento) for b in support}, key=int)
            record["recursos"] = list(dict.fromkeys(b.recurso for b in support if b.recurso))
            record["recomendacion"] = recommendation
            if record["estado_observado"] in {"IO04", "IO05"}:
                record["estado_observado"] = "IO02"
        elif not record["eventos"] and behaviors:
            record["descripcion"] = absent[dimension] if requested else (
                "La captura carece de una operación con semántica suficiente para valorar esta dimensión.")
            if dimension == "disponibilidad" and any(b.categoria == "finalizacion" for b in behaviors):
                record["descripcion"] += " El cierre de la interacción solo delimita la sesión."
            record["fundamento"] = "La valoración se limita a los eventos capturados y a las operaciones interpretables."
            if unresolved:
                record["estado_observado"] = "IO04"
                record["descripcion"] += " Hay órdenes cuya finalidad no pudo establecerse; las operaciones interpretadas no permiten descartar un mecanismo en esas entradas."
                record["fundamento"] = "Revisar las entradas citadas y contrastar su resultado con la telemetría del recurso o del terminal."
            relevant = [*unresolved, *requested] or [b for b in behaviors if b.categoria in {"conexion", "autenticacion", "finalizacion"}]
            record["eventos"] = [str(b.evento) for b in relevant[:8]]
        all_ids.update(int(eid) for eid in record["eventos"])
    observed = (observed_state(has_evidence=bool(context or behaviors), applicable=bool(context or requested),
                               activity=bool(all_rules or any(contextual.values())))
                if any(row["estado_observado"] != "IO04" for row in output.values()) else "IO04")
    return {
        **output,
        "impacto_observado": observed,
        "impacto_potencial": max((row["nivel_potencial"] for row in output.values()), key=IMPACT.index),
        "recursos_afectados": [], "recursos_en_riesgo": [],
        "alcance": "Eventos examinados de la sesión registrada.",
        "fundamento": "Los escenarios potenciales dependen de que se materialicen las condiciones indicadas.",
        "eventos": [str(eid) for eid in sorted(all_ids)], "reglas_aplicadas": sorted(all_rules),
    }

def organizational_context(behaviors):
    """Describe hypothetical asset exposure while keeping formal risk inputs separate."""
    inquiries = {
        "identidad": ("cuentas de un servicio remoto","Las respuestas podrían orientar la enumeración de cuentas.",
                      "Comprobar permisos de consulta de identidad y revisar la auditoría SSH por cuenta y sesión."),
        "leer": ("un servicio con acceso a archivos","Una lectura efectiva podría revelar el contenido que la cuenta pueda consultar.",
                 "Verificar permisos de lectura y cotejar la ruta con auditoría de acceso a archivos."),
        "descubrimiento": ("un sistema administrado por SSH","Una consulta exitosa podría revelar información que facilite orientar el reconocimiento.",
                           "Restringir permisos sobre datos de inventario y comprobar trazas de consulta de los recursos citados."),
        "modificacion": ("un activo con configuración modificable","Una operación aplicable con permisos suficientes podría alterar la configuración.",
                         "Contrastar privilegios, controles de cambio y eventos de auditoría con la configuración aprobada."),
        "disponibilidad": ("un servicio que dependa del recurso objetivo","Un cambio efectivo podría interrumpir el acceso de sus consumidores.",
                            "Revisar permisos de administración, alertas de estado y eventos del servicio."),
    }
    groups = defaultdict(list)
    for behavior in behaviors:
        if not behavior.objetivo or not behavior.recurso:
            continue
        key = ("disponibilidad" if behavior.operacion in {"T1489","T1529","T1531"} else
               behavior.operacion if behavior.operacion in {"identidad","leer"} else behavior.categoria)
        if key in inquiries:
            groups[key].append(behavior)
    scenarios = []
    for key, items in groups.items():
        asset, consequence, control = inquiries[key]
        resources = ", ".join(dict.fromkeys(item.recurso for item in items))
        evidence = ", ".join(f"#{item.evento}" for item in items[:6])
        scenarios.append(f"Exposición condicionada en {asset}. Recursos: {resources}. {consequence} "
                         f"{control} Evidencia {evidence}.")
    if scenarios:
        return [*scenarios, "Antes de estimar un nivel NIST, verificar qué activo sería equivalente, qué exposición tiene "
                "y qué impacto operativo y probabilidad documenta su responsable."]
    if any(b.operacion == "orden_sin_semantica" for b in behaviors):
        return ["Primero identifique las operaciones no interpretadas en los registros de terminal o del servicio. "
                "El tipo de recurso y su exposición siguen sin poder establecerse."]
    return ["La evidencia de esta sesión no identifica un recurso expuesto por una operación interpretable. "
            "Valorar exposición y controles del servicio si aparecen registros de actividad adicionales."] if behaviors else []

