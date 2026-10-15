"""Namespace-local, row-locked accounting for retained report snapshots."""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..database import NamespaceViolation, require_locking_transaction, session_namespace
from ..models import ReportStoragePolicy, new_id, utcnow
from ..report_schemas import ReportStoragePolicyUpdate
from .audit import record_audit_event
from .control_plane_auth import PrincipalContext


class ReportStorageQuotaExceeded(ValueError):
    """A bounded snapshot would exceed the configured namespace limit."""


def _assert_namespace(db: Session, principal: PrincipalContext) -> None:
    selected = session_namespace(db)
    expected = (principal.tenant_id, principal.region_id)
    if selected != expected and (selected is not None or db.info.get("namespace_enforced")):
        raise NamespaceViolation("Report storage namespace does not match the principal")


def _query(principal: PrincipalContext):
    return select(ReportStoragePolicy).where(
        ReportStoragePolicy.tenant_id == principal.tenant_id,
        ReportStoragePolicy.region_id == principal.region_id,
    )


def read_report_storage_policy(db: Session, principal: PrincipalContext) -> dict:
    _assert_namespace(db, principal)
    policy = db.scalar(_query(principal))
    if policy is None:
        return {
            "tenant_id": principal.tenant_id, "region_id": principal.region_id,
            "max_instances": None, "max_bytes": None,
            "used_instances": 0, "used_bytes": 0, "revision": 1,
            "max_attachment_bytes": None, "used_attachment_bytes": 0,
        }
    return {
        "tenant_id": policy.tenant_id, "region_id": policy.region_id,
        "max_instances": policy.max_instances, "max_bytes": policy.max_bytes,
        "used_instances": policy.used_instances, "used_bytes": policy.used_bytes,
        "revision": policy.revision,
        "max_attachment_bytes": policy.max_attachment_bytes,
        "used_attachment_bytes": policy.used_attachment_bytes,
    }


def locked_report_storage_policy(
    db: Session, principal: PrincipalContext, *, actor: str,
) -> ReportStoragePolicy:
    """Create the accounting row atomically, then serialize writers on it."""
    _assert_namespace(db, principal)
    require_locking_transaction(db, purpose="Report storage mutations")
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgresql_insert(ReportStoragePolicy)
    elif dialect == "sqlite":
        insert = sqlite_insert(ReportStoragePolicy)
    else:
        raise RuntimeError("Report storage policy requires PostgreSQL or SQLite")
    now = utcnow()
    db.execute(insert.values(
        id=new_id(), tenant_id=principal.tenant_id, region_id=principal.region_id,
        max_instances=None, max_bytes=None, used_instances=0, used_bytes=0,
        max_attachment_bytes=None, used_attachment_bytes=0,
        revision=1, created_by=actor, updated_by=actor,
        created_at=now, updated_at=now,
    ).on_conflict_do_nothing(index_elements=["tenant_id", "region_id"]))
    # A long-lived session may already cache the policy. Refresh its counters,
    # limits and revision from the locked row, not a pre-wait identity map.
    policy = db.scalar(_query(principal).with_for_update().execution_options(populate_existing=True))
    if policy is None:
        raise RuntimeError("Report storage policy could not be initialized")
    return policy


def assert_report_storage_capacity(policy: ReportStoragePolicy, size_bytes: int) -> None:
    if size_bytes < 1:
        raise ValueError("Report snapshot size must be positive")
    if policy.max_instances is not None and policy.used_instances + 1 > policy.max_instances:
        raise ReportStorageQuotaExceeded("Report storage instance quota exceeded")
    if policy.max_bytes is not None and policy.used_bytes + size_bytes > policy.max_bytes:
        raise ReportStorageQuotaExceeded("Report storage byte quota exceeded")


def configure_report_storage_policy(
    db: Session, principal: PrincipalContext, payload: ReportStoragePolicyUpdate,
) -> dict:
    policy = locked_report_storage_policy(db, principal, actor=principal.subject)
    if policy.revision != payload.expected_revision:
        raise ValueError("Report storage policy revision has changed")
    policy.max_instances = payload.max_instances
    policy.max_bytes = payload.max_bytes
    if "max_attachment_bytes" in payload.model_fields_set:
        policy.max_attachment_bytes = payload.max_attachment_bytes
    policy.revision += 1
    policy.updated_by = principal.subject
    policy.updated_at = utcnow()
    record_audit_event(
        db, event_type="report.storage_policy.updated",
        actor_type=principal.principal_type, actor_id=principal.subject,
        entity_type="report_storage_policy", entity_id=policy.id,
        details={
            "max_instances": policy.max_instances, "max_bytes": policy.max_bytes,
            "max_attachment_bytes": policy.max_attachment_bytes,
            "revision": policy.revision,
            "reason_sha256": hashlib.sha256(payload.reason.encode("utf-8")).hexdigest(),
        },
    )
    db.commit()
    return read_report_storage_policy(db, principal)
