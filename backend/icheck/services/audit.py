from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditEvent


def record_audit_event(
    db: Session,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        outcome=outcome,
        details=details or {},
    )
    db.add(event)
    return event
