"""Serialize registry state with admission, heartbeats and capacity draining."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import AgentWorker, CollectorWorker


def lock_worker_registry(
    db: Session, worker: AgentWorker | CollectorWorker,
) -> AgentWorker | CollectorWorker:
    require_locking_transaction(db, purpose="Worker registry state and admission")
    model = type(worker)
    if model not in {AgentWorker, CollectorWorker}:
        raise TypeError("Unsupported Worker registry")
    current = db.scalar(select(model).where(model.id == worker.id)
        .with_for_update().execution_options(populate_existing=True))
    if current is None:
        raise LookupError("Worker registry entry not found")
    return current
