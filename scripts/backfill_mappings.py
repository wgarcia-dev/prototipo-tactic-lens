"""Restore supported ATT&CK proposals from completed saved analyses, without LLM calls."""
import asyncio

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from backend.api import app, lifespan
from backend.routes import COWRIE_TECHNIQUES


async def main():
    added = skipped = 0
    async with lifespan(app):
        t = app.state.tables
        a, action, links, relation, mapping = (t[name] for name in
            ("analisis_llm", "accion_identificada", "accion_evento", "tecnica_tactica", "mapeo_mitre"))
        with app.state.engine.begin() as conn:
            analyses = conn.execute(select(a.c.id_analisis, a.c.resultado_estructurado)
                .where(a.c.estado == "completado")).all()
            for analysis in analyses:
                payload = analysis.resultado_estructurado or {}
                for proposal in payload.get("acciones", []):
                    description = proposal.get("descripcion")
                    candidates = conn.execute(select(action.c.id_accion)
                        .where(action.c.id_analisis == analysis.id_analisis,
                               action.c.descripcion == description)).scalars().all()
                    if len(candidates) != 1:
                        skipped += len(proposal.get("mitre", []))
                        continue
                    action_id = candidates[0]
                    evidence = set(conn.scalars(select(links.c.id_evento)
                        .where(links.c.id_accion == action_id)).all())
                    if not evidence or evidence != set(proposal.get("eventos", [])):
                        skipped += len(proposal.get("mitre", []))
                        continue
                    for suggestion in proposal.get("mitre", []):
                        code = suggestion.get("codigo")
                        reason = suggestion.get("justificacion", "").strip()
                        if code not in COWRIE_TECHNIQUES or not reason:
                            skipped += 1
                            continue
                        relation_id = conn.scalar(select(relation.c.id_vinculo)
                            .where(relation.c.codigo_tecnica == code).limit(1))
                        if relation_id is None:
                            skipped += 1
                            continue
                        result = conn.execute(insert(mapping).values(id_accion=action_id,
                            id_vinculo=relation_id,
                            evidencia="Eventos Cowrie: " + ", ".join(map(str, sorted(evidence))),
                            justificacion=reason, confianza=suggestion.get("confianza", 0.5))
                            .on_conflict_do_nothing(index_elements=["id_accion", "id_vinculo"])
                            .returning(mapping.c.id_mapeo))
                        added += result.scalar_one_or_none() is not None
    print(f"Mapeos históricos recuperados: {added}; propuestas omitidas: {skipped}.")


if __name__ == "__main__":
    asyncio.run(main())
