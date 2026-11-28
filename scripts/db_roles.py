"""Check the effective permissions using the actual backend login."""
from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine
from backend.db_access import verify_runtime_access


def main():
    load_dotenv()
    engine = database_engine()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")
            verify_runtime_access(conn, conn.scalar(text("SELECT current_user")))
    finally:
        engine.dispose()
    print("Rol operativo y protección de auditoría verificados.")


if __name__ == "__main__":
    main()
