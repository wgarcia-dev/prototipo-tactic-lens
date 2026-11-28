"""Shared connection factory; keep SQLAlchemy Core and the existing schema."""
import os

from sqlalchemy import create_engine
from sqlalchemy.engine import URL


def _engine(user_key, password_key):
    return create_engine(URL.create(
        "postgresql+psycopg", username=os.environ[user_key],
        password=os.environ[password_key], host=os.environ["DATABASE_HOST"],
        port=int(os.getenv("DATABASE_PORT", "5432")), database=os.environ["DATABASE_NAME"],
    ), pool_pre_ping=True, hide_parameters=True, connect_args={"options": "-c search_path=public"})


def database_engine():
    return _engine("DATABASE_USER", "DATABASE_PASSWORD")


def migration_credentials():
    if not all(os.getenv(key) for key in ("DATABASE_MIGRATION_USER", "DATABASE_MIGRATION_PASSWORD")):
        raise RuntimeError("Configure las credenciales administrativas DATABASE_MIGRATION_USER y DATABASE_MIGRATION_PASSWORD")
    user = os.environ["DATABASE_MIGRATION_USER"]
    if user == os.getenv("DATABASE_USER"):
        raise RuntimeError("Las credenciales administrativas y operativas deben corresponder a roles diferentes")
    return user, os.environ["DATABASE_MIGRATION_PASSWORD"]


def migration_engine():
    migration_credentials()
    return _engine("DATABASE_MIGRATION_USER", "DATABASE_MIGRATION_PASSWORD")
