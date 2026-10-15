"""Internal scoped authority, never an input field for generic Alert callers."""
from contextlib import contextmanager
from contextvars import ContextVar

PREFIX = "collector.condition:"
_source_writer = ContextVar("collector_condition_writer", default=None)


def assert_collector_condition_writer(db, key: str) -> None:
    if key.startswith(PREFIX) and _source_writer.get() != (db, key):
        raise ValueError("Collector condition keys require sealed envelope provenance")
    if key.startswith(PREFIX):
        from sqlalchemy import select
        from ..models import CollectorConditionSource
        from ..database import session_namespace, DEFAULT_TENANT_ID, DEFAULT_REGION_ID
        from .source_retirements import retirement_for_source
        namespace = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        source = db.scalar(select(CollectorConditionSource).where(CollectorConditionSource.tenant_id == namespace[0],
            CollectorConditionSource.region_id == namespace[1], CollectorConditionSource.dedup_key == key).with_for_update())
        if source and retirement_for_source(db, source.id, namespace=namespace):
            raise ValueError("Retired Collector source cannot change its measured history")


@contextmanager
def collector_condition_writer(db, key: str):
    token = _source_writer.set((db, key))
    try:
        yield
    finally:
        _source_writer.reset(token)
