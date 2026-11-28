from datetime import datetime, timezone
import hmac
import subprocess

from fastapi import HTTPException, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select

from .analysis_state import digest
from .operational_report import section
from .report_export import PDF_TYPE, WORD_TYPE, render_docx, render_pdf
from .report_snapshot import snapshot_ttl
from .session_report import ecuador_time

LIMIT = 200


def limited(conn, query, order):
    total = conn.scalar(select(func.count()).select_from(query.subquery()))
    return conn.execute(query.order_by(order).limit(LIMIT)).mappings().all(), total


def assemble(ctx):
    ctx.has_plan()
    plan = ctx.plan
    evaluation = ctx.read_evaluation(plan.revision_plan) if ctx.revision != plan.revision_plan else ctx.evaluation
    action, evidence, history, users = (ctx.tables[name] for name in (
        "incidente_accion", "incidente_accion_evidencia", "incidente_respuesta_historial", "usuario"))
    actions, action_count = limited(ctx.conn, select(action).where(action.c.id_respuesta == plan.id_respuesta), action.c.orden)
    citations, citation_count = limited(ctx.conn, select(evidence).where(
        evidence.c.id_respuesta == plan.id_respuesta), evidence.c.id_evidencia)
    changes, history_count = limited(ctx.conn, select(history).where(
        history.c.id_respuesta == plan.id_respuesta), history.c.id_cambio.desc())
    actor_ids = {c.id_actor for c in changes} | {c.id_responsable for c in actions if c.id_responsable}
    if plan.id_responsable:
        actor_ids.add(plan.id_responsable)
    names = dict(ctx.conn.execute(select(users.c.id_usuario, users.c.nombre_usuario)
                                  .where(users.c.id_usuario.in_(actor_ids))).all())
    coverage = [(label, str(total), str(len(items)), str(total - len(items))) for label, total, items in (
        ("Acciones", action_count, actions), ("Evidencias de acciones", citation_count, citations),
        ("Historial", history_count, changes), ("Citas de evaluación", len(evaluation.evidencias), evaluation.evidencias[:LIMIT]))]
    included = [
        section("Evaluación de origen", [evaluation.resumen, f"Decisión: {evaluation.decision}",
                f"Severidad: {evaluation.severidad or 'Por determinar'}. Prioridad: {evaluation.prioridad or 'Por determinar'}",
                f"Impacto corroborado: {evaluation.detalle.get('impacto_confirmado') or 'Sin corroboración independiente'}",
                f"Huella de evidencia: {evaluation.evidencia_sha256}"],
                ("Sesión", "Evento", "Análisis", "Procedencia y grado"), [
                    (str(c.id_sesion), "#" + c.id_evento, str(c.id_analisis or ""),
                     f"{c.procedencia.get('sensor') or 'Origen sin verificar'} · {c.grado}")
                    for c in evaluation.evidencias[:LIMIT]]),
        section("Plan y criterio de cierre",
                [plan.objetivo, plan.alcance, plan.criterio_cierre, f"Responsable: {names.get(plan.id_responsable, 'Sin asignar')}"],
                ("Fase no aplicable", "Motivo"), sorted(plan.fases_no_aplicables.items())),
        section("Acciones", [] if actions else ["No hay acciones registradas."],
                ("Acción", "Fase y estado", "Responsable", "Criterio de verificación"),
                [(f"{a.medida}\n{a.id_accion}\n{a.justificacion}", f"{a.fase} · {a.estado}",
                  names.get(a.id_responsable, "Sin asignar"), a.criterio_verificacion) for a in actions]),
        section("Evidencia y resultados", [] if citations else ["No hay evidencia de actuaciones."],
                ("Acción", "Tipo", "Cita o referencia", "Revisión"),
                [(str(c.id_accion), c.tipo,
                  f"#{c.id_evento} · sesión {c.id_sesion} · análisis {c.id_analisis or '—'}" if c.id_evento else c.referencia,
                  str(c.revision_evaluacion)) for c in citations]),
        section("Historial", [], ("Fecha y actor", "Operación", "Motivo", "Resultado y evidencia"),
                [(f"{ecuador_time(c.creado_en)} · {names.get(c.id_actor, str(c.id_actor))}",
                  f"{c.operacion} · {c.id_accion or 'plan'}", c.motivo,
                  "\n".join(str(c.detalle[key]) for key in ("resultado", "referencia", "estado")
                            if c.detalle.get(key))) for c in changes]),
        section("Resolución y cierre", ["No hay resolución vigente."] if not plan.resolucion else
                [f"{label}: {plan.resolucion[key]}" for key, label in (
                    ("resultado", "Comprobación"), ("referencia", "Referencia"),
                    ("riesgos_pendientes", "Riesgos pendientes"), ("sin_acciones", "Justificación"))
                 if plan.resolucion.get(key)]),
        section("Cobertura del informe", ["El historial se presenta del más reciente al más antiguo."],
                ("Sección", "Disponible", "Incluido", "Omitido"), coverage),
    ]
    return ctx.safe({"id_incidente": str(ctx.id_incidente), "revision_respuesta": plan.revision_respuesta,
        "revision_plan": plan.revision_plan, "revision_evaluacion_actual": ctx.revision,
        "title": "Respuesta a incidente · " + evaluation.titulo, "reference": str(ctx.id_incidente),
        "status": plan.estado + (" · Plan desactualizado" if ctx.header()["desactualizada"] else ""),
        "metadata": [("Incidente", str(ctx.id_incidente)), ("Respuesta", str(plan.id_respuesta)),
                     ("Respuesta / evaluación vinculada / evaluación actual",
                      f"{plan.revision_respuesta} / {plan.revision_plan} / {ctx.revision}")],
        "sections": included})


def finalize(settings, report, actor, token):
    signer = URLSafeTimedSerializer(settings.secret, salt="tacticlens-informe-incidente-v1")
    checksum = digest(report)
    if token:
        try:
            data = signer.loads(token, max_age=snapshot_ttl())
            if (data["incidente"] != report["id_incidente"] or data["actor"] != str(actor)
                    or not hmac.compare_digest(data["huella"], checksum)):
                raise ValueError
            generated = datetime.fromisoformat(data["generado_en"])
        except SignatureExpired:
            raise HTTPException(410, "La vista previa venció. Abra un informe nuevo.") from None
        except (BadSignature, TypeError, ValueError, KeyError):
            raise HTTPException(409, "El informe cambió o no está disponible. Abra una vista previa nueva.") from None
    else:
        generated = datetime.now(timezone.utc)
        token = signer.dumps({"incidente": report["id_incidente"], "actor": str(actor),
                              "huella": checksum, "generado_en": generated.isoformat()})
    report["metadata"] += [("Versión del informe", checksum[:16]), ("Generado (Ecuador)", ecuador_time(generated))]
    return {**report, "snapshot_id": checksum[:16], "generado_en": generated.isoformat()}, token


def export(report, format):
    try:
        content, media_type = (render_pdf(report), PDF_TYPE) if format == "pdf" else (render_docx(report), WORD_TYPE)
    except (OSError, subprocess.SubprocessError):
        raise HTTPException(503, "No se pudo generar el archivo. Vuelva a intentarlo.") from None
    return Response(content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="TacticLens-{report["id_incidente"]}.{format}"',
        "X-TacticLens-Snapshot": report["snapshot_id"], "Cache-Control": "no-store, private"})
