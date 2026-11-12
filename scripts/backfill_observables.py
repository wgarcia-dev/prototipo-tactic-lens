"""Idempotently derive direct Cowrie observables from already stored events."""
import asyncio

from sqlalchemy import select

from backend.api import app, lifespan
from backend.intelligence import persist_observables


async def main():
    total = 0
    async with lifespan(app):
        event = app.state.tables["evento"]
        last_id = -1
        while True:
            with app.state.engine.begin() as conn:
                rows = conn.execute(select(event.c.id_evento, event.c.fecha_hora,
                    event.c.datos_originales).where(event.c.id_evento > last_id)
                    .order_by(event.c.id_evento).limit(500)).all()
                for row in rows:
                    persist_observables(conn, app.state.tables, row.datos_originales,
                                        row.id_evento, row.fecha_hora)
                total += len(rows)
                if rows:
                    last_id = rows[-1].id_evento
            if not rows:
                break
    print(f"Eventos revisados: {total}. Las observaciones existentes se reutilizaron.")


if __name__ == "__main__":
    asyncio.run(main())
