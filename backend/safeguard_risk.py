"""Per-control technical assessment from the saved evidence. It is separate from NIST risk."""
import re

LEVELS = ("no_valorado", "bajo", "medio", "alto", "critico")
IMPACT = {"bajo":1, "moderado":2, "alto":3}
SEVERITY = {"S0":0, "S1":1, "S2":2, "S3":3, "S4":4}


def evidence_ids(values):
    return sorted({str(value) for value in (values if isinstance(values, (tuple, list)) else [])
                   if type(value) in (int, str) and re.fullmatch(r"[1-9][0-9]{0,18}", str(value))
                   and int(value) <= 9223372036854775807}, key=int)


def recommendation_references(payload):
    report = payload.get("informe") if isinstance(payload, dict) else None
    suggestions = report.get("recomendaciones") if isinstance(report, dict) else None
    if isinstance(suggestions, list):
        for position, recommendation in enumerate(suggestions, 1):
            if isinstance(recommendation, dict):
                events = recommendation.get("eventos")
                yield position, recommendation, [str(value) for value in events] if isinstance(events, list) else []


def assess_safeguard(item, payload):
    ids = evidence_ids(item.get("eventos"))
    unsupported = {"nivel":None,"eventos":ids,"confianza":"insuficiente","condiciones":[],
                   "fundamento":"La recomendación guardada carece de citas y recursos verificables para una valoración individual."}
    if not ids or not all(isinstance(item.get(key), str) and item[key].strip() for key in ("activo","medidas")):
        return unsupported
    cites = set(ids)
    assertions = [row for row in (payload.get("evidencias_analiticas") or [])
                  if isinstance(row, dict) and row.get("estado_validacion")=="validado"
                  and set(evidence_ids(row.get("eventos"))) & cites]
    behavior_ids = {str(row["evento"]) for row in (payload.get("comportamientos_semanticos") or [])
                    if isinstance(row, dict) and "evento" in row}
    validated_ids = {eid for row in assertions for eid in evidence_ids(row.get("eventos"))}
    if not cites <= (behavior_ids | validated_ids):
        return {**unsupported,"fundamento":"Las citas de esta recomendación no se vinculan con un comportamiento de la versión guardada."}
    matched = {dimension:row for dimension,row in (payload.get("evaluacion_impacto") or {}).items()
               if dimension in {"confidencialidad","integridad","disponibilidad"} and isinstance(row,dict)
               and row.get("nivel_potencial") in IMPACT and set(evidence_ids(row.get("eventos"))) & cites}
    supporting_level = max((SEVERITY.get(row.get("codigo_severidad"),0) for row in assertions), default=0)
    session_level = SEVERITY.get((payload.get("evaluacion_amenaza") or {}).get("codigo_severidad"),0)
    # A dimension summarizes potentially heterogeneous events. Its session maximum
    # applies only when this control cites the entire supporting set.
    impact_level = max((IMPACT[row["nivel_potencial"]] for row in matched.values()
                        if set(evidence_ids(row.get("eventos"))) <= cites), default=0)
    verified_critical = session_level == 4 and any(
        row.get("codigo_severidad") == "S4" and row.get("grado_evidencia") == "efecto_verificado"
        and set(evidence_ids(row.get("eventos"))) <= cites for row in assertions
    ) and any(row.get("estado_observado") == "IO01" and set(evidence_ids(row.get("eventos"))) <= cites
              for row in matched.values())
    rank = 4 if verified_critical else max(1, min(3, max(supporting_level, impact_level)))
    conditions = list(dict.fromkeys(condition for row in matched.values() for condition in row.get("condiciones", [])))
    if not conditions:
        conditions = ["Verificar que el comportamiento se aplique al recurso protegido y comprobar su exposición efectiva."]
    factors = [row.get("fundamento","").strip().rstrip(".") for row in assertions if row.get("fundamento")]
    scope = "; ".join(dict.fromkeys(factors[:3])) or "Comportamiento documentado en las citas de la propuesta"
    dimensions = ", ".join(matched) or "sin dimensión CIA con nivel aplicable a estas citas"
    return {"nivel":LEVELS[rank], "eventos":ids, "condiciones":conditions,
            "confianza":"alta" if verified_critical else "moderada" if assertions else "baja",
            "fundamento":f"{scope}. Recurso protegido: {item['activo']}. "
            f"Dimensiones: {dimensions}. La severidad de la sesión aporta contexto; se valoran las citas de esta medida."}
