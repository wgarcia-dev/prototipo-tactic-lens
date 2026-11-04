"""Seed a small verified ATT&CK subset and IoC types without changing the schema."""
import asyncio
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from backend import app, lifespan


async def main():
    async with lifespan(app):
        t = app.state.tables
        with app.state.engine.begin() as conn:
            for number, name in ((1, "IP"), (2, "Dominio"), (3, "URL"), (4, "Hash")):
                conn.execute(insert(t["tipo_ioc"]).values(id_tipo_ioc=number, nombre=name).on_conflict_do_nothing(index_elements=["id_tipo_ioc"]))
            conn.execute(insert(t["tactica_mitre"]).values(codigo_tactica="TA0002", nombre="Execution", descripcion="https://attack.mitre.org/tactics/TA0002/").on_conflict_do_nothing(index_elements=["codigo_tactica"]))
            for code, parent, name, source in (("T1059", None, "Command and Scripting Interpreter", "https://attack.mitre.org/techniques/T1059/"), ("T1059.004", "T1059", "Command and Scripting Interpreter: Unix Shell", "https://attack.mitre.org/techniques/T1059/004/")):
                conn.execute(insert(t["tecnica_mitre"]).values(codigo_tecnica=code, tecnica_padre_id=parent, nombre=name, descripcion=source).on_conflict_do_nothing(index_elements=["codigo_tecnica"]))
            conn.execute(insert(t["tecnica_tactica"]).values(codigo_tecnica="T1059.004", codigo_tactica="TA0002").on_conflict_do_nothing(index_elements=["codigo_tecnica", "codigo_tactica"]))
    print("Catálogo mínimo disponible")


if __name__ == "__main__":
    asyncio.run(main())
