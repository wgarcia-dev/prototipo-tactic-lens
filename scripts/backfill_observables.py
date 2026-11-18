"""Idempotently derive direct Cowrie observables from already stored events."""
import asyncio

from sqlalchemy import select

from backend.api import app, lifespan
from backend.intelligence import persist_observables, backfill_detections


def backfill_observables(engine, tables):
    total = 0
    event = tables["evento"]
    last_id = None
    while True:
        with engine.begin() as conn:
            query = select(event.c.id_evento, event.c.fecha_hora, event.c.datos_originales)
            if last_id is not None:
                query = query.where(event.c.id_evento > last_id)
            rows = conn.execute(query.order_by(event.c.id_evento).limit(500)).all()
            if not rows:
                break
            for row in rows:
                persist_observables(conn, tables, row.datos_originales or {}, row.id_evento, row.fecha_hora)
            total += len(rows)
            last_id = rows[-1].id_evento
    with engine.begin() as conn:
        backfill_detections(conn, tables)
    return total


async def main():
    async with lifespan(app):
        total = backfill_observables(app.state.engine, app.state.tables)
    print(f"Eventos revisados: {total}. Se conservaron las observaciones y revisiones históricas.")


if __name__ == "__main__":
    asyncio.run(main())
