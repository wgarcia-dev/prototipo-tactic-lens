"""Shared connection factory; keep SQLAlchemy Core and the existing schema."""
import os

from sqlalchemy import create_engine
from sqlalchemy.engine import URL


def database_engine():
    return create_engine(URL.create(
        "postgresql+psycopg", username=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"], host=os.environ["DATABASE_HOST"],
        port=int(os.getenv("DATABASE_PORT", "5432")), database=os.environ["DATABASE_NAME"],
    ), pool_pre_ping=True, hide_parameters=True)
