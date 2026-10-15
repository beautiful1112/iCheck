"""Serialize AI catalog mutation within a namespace; no external I/O authority."""
from sqlalchemy import text
from ..database import session_namespace


def catalog_lock(db):
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": "icheck.ai-catalog:" + ":".join(session_namespace(db))})
