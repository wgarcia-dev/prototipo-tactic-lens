"""Apply reviewed, versioned SQL migrations without recreating the schema."""
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine

MIGRATIONS = Path(__file__).resolve().parents[1] / "database" / "migrations"


def migrate(engine):
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(724610901)"))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS honeypot.schema_migration (
            version varchar(100) PRIMARY KEY, checksum varchar(64) NOT NULL,
            aplicado_en timestamptz NOT NULL DEFAULT now())"""))
        for path in sorted(MIGRATIONS.glob("*.sql")):
            sql = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(sql.encode()).hexdigest()
            previous = conn.scalar(text("SELECT checksum FROM honeypot.schema_migration WHERE version=:v"), {"v": path.name})
            if previous:
                if previous != digest:
                    raise RuntimeError("Migración aplicada modificada: " + path.name)
                continue
            collision = conn.scalar(text("""SELECT count(*) FROM
                (SELECT lower(btrim(correo)) FROM honeypot.usuario
                 GROUP BY lower(btrim(correo)) HAVING count(*)>1) c"""))
            if collision:
                raise RuntimeError("Hay correos duplicados normalizados; resuélvalos antes de migrar")
            # psycopg's simple-query protocol supports the reviewed multi-statement SQL.
            conn.connection.driver_connection.execute(sql, prepare=False)
            conn.execute(text("INSERT INTO honeypot.schema_migration(version,checksum) VALUES(:v,:c)"), {"v": path.name, "c": digest})


if __name__ == "__main__":
    load_dotenv()
    engine = database_engine()
    try:
        migrate(engine)
        print("Migraciones aplicadas. Los datos existentes se conservan.")
    finally:
        engine.dispose()
