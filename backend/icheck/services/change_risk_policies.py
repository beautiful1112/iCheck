from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import ChangeRiskPolicyUpdate
from ..models import ChangeRiskPolicy, utcnow
from .audit import record_audit_event


CHANGE_RISK_POLICY_CONTRACT = "icheck.change-risk-policy/v1"
RISK_CLASSES = ("low", "medium", "high", "critical")
DEFAULT_CHANGE_RISK_POLICIES: dict[str, dict[str, Any]] = {
    "low": {
        "execution_enabled": True,
        "maintenance_window_required": False,
        "max_window_minutes": 480,
        "require_evidence_summary": False,
        "require_authorization_binding": False,
    },
    "medium": {
        "execution_enabled": True,
        "maintenance_window_required": True,
        "max_window_minutes": 240,
        "require_evidence_summary": False,
        "require_authorization_binding": False,
    },
    "high": {
        "execution_enabled": True,
        "maintenance_window_required": True,
        "max_window_minutes": 120,
        "require_evidence_summary": False,
        "require_authorization_binding": False,
    },
    "critical": {
        "execution_enabled": True,
        "maintenance_window_required": True,
        "max_window_minutes": 60,
        "require_evidence_summary": True,
        "require_authorization_binding": True,
    },
}


def ensure_change_risk_policies(db: Session, *, commit: bool = True) -> None:
    existing = {
        item.risk_class
        for item in db.scalars(select(ChangeRiskPolicy)).all()
    }
    changed = False
    for risk_class in RISK_CLASSES:
        if risk_class in existing:
            continue
        db.add(
            ChangeRiskPolicy(
                risk_class=risk_class,
                **DEFAULT_CHANGE_RISK_POLICIES[risk_class],
                revision=1,
                updated_by="system.bootstrap",
                update_reason="Built-in governed change risk policy.",
            )
        )
        changed = True
    if changed and commit:
        db.commit()


def list_change_risk_policies(db: Session) -> list[ChangeRiskPolicy]:
    policies = list(
        db.scalars(
            select(ChangeRiskPolicy).order_by(ChangeRiskPolicy.risk_class)
        ).all()
    )
    order = {name: index for index, name in enumerate(RISK_CLASSES)}
    return sorted(policies, key=lambda item: order[item.risk_class])


def get_change_risk_policy(
    db: Session,
    risk_class: str,
    *,
    lock: bool = False,
) -> ChangeRiskPolicy:
    query = select(ChangeRiskPolicy).where(
        ChangeRiskPolicy.risk_class == risk_class
    )
    if lock:
        query = query.with_for_update()
    policy = db.scalar(query)
    if policy is None:
        raise LookupError(f"Change risk policy {risk_class!r} is unavailable")
    return policy


def change_risk_policy_snapshot(policy: ChangeRiskPolicy) -> dict[str, Any]:
    return {
        "contract": CHANGE_RISK_POLICY_CONTRACT,
        "policy_id": policy.id,
        "risk_class": policy.risk_class,
        "revision": policy.revision,
        "execution_enabled": policy.execution_enabled,
        "maintenance_window_required": policy.maintenance_window_required,
        "max_window_minutes": policy.max_window_minutes,
        "require_evidence_summary": policy.require_evidence_summary,
        "require_authorization_binding": policy.require_authorization_binding,
    }


def assert_change_risk_policy_current(
    db: Session,
    snapshot: dict[str, Any],
) -> ChangeRiskPolicy:
    policy_id = snapshot.get("policy_id")
    policy = db.get(ChangeRiskPolicy, policy_id) if policy_id else None
    if policy is None or change_risk_policy_snapshot(policy) != snapshot:
        raise ValueError("Governed change risk policy has drifted")
    if not policy.execution_enabled:
        raise ValueError("Governed change risk policy disables execution")
    return policy


def update_change_risk_policy(
    db: Session,
    policy: ChangeRiskPolicy,
    payload: ChangeRiskPolicyUpdate,
    *,
    actor: str,
) -> ChangeRiskPolicy:
    if policy.revision != payload.expected_revision:
        raise ValueError("Change risk policy revision is stale")
    previous = change_risk_policy_snapshot(policy)
    policy.execution_enabled = payload.execution_enabled
    policy.maintenance_window_required = payload.maintenance_window_required
    policy.max_window_minutes = payload.max_window_minutes
    policy.require_evidence_summary = payload.require_evidence_summary
    policy.require_authorization_binding = payload.require_authorization_binding
    policy.revision += 1
    policy.updated_by = actor
    policy.update_reason = payload.reason
    policy.updated_at = utcnow()
    db.flush()
    record_audit_event(
        db,
        event_type="change.risk_policy.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="change_risk_policy",
        entity_id=policy.id,
        details={
            "risk_class": policy.risk_class,
            "previous": previous,
            "current": change_risk_policy_snapshot(policy),
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(policy)
    return policy
