"""Durable UTC-day admission accounting for every structured authoring route.

The quota reserves a route's whole token budget before provider I/O. Reported
unused tokens are released only when the external outcome is known; unknown
charges retain the reservation. This is an admission control, not a bill.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..database import NamespaceViolation, require_locking_transaction, session_namespace
from ..models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaBucket,
    AIAuthoringQuotaPolicy,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSettlementConflict,
    new_id,
)
from .audit import record_audit_event


NAMESPACE_SCOPE_KEY = "*"


class AuthoringQuotaExceeded(RuntimeError):
    """The next model call cannot fit the configured admission quota."""


class AuthoringQuotaConflict(RuntimeError):
    """An exact authoring intent already owns a model-call reservation."""


def _namespace(db: Session) -> tuple[str, str]:
    selected = session_namespace(db)
    if selected is None:
        raise NamespaceViolation("AI authoring quota requires a bound tenant and region")
    return selected


def _utc_now(db: Session) -> datetime:
    if db.get_bind().dialect.name == "postgresql":
        value = db.scalar(select(func.clock_timestamp()))
    else:
        value = db.scalar(select(func.now()))
    if value is None:
        raise RuntimeError("Database clock is unavailable")
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _insert_for(db: Session, model):
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        return postgresql_insert(model)
    if dialect == "sqlite":
        return sqlite_insert(model)
    raise RuntimeError("AI authoring quota requires PostgreSQL or SQLite")


def _policy(db: Session, *, lock: bool, actor: str = "system") -> AIAuthoringQuotaPolicy:
    tenant_id, region_id = _namespace(db)
    query = select(AIAuthoringQuotaPolicy).where(
        AIAuthoringQuotaPolicy.tenant_id == tenant_id,
        AIAuthoringQuotaPolicy.region_id == region_id,
    )
    if lock:
        now = _utc_now(db)
        db.execute(_insert_for(db, AIAuthoringQuotaPolicy).values(
            id=new_id(), tenant_id=tenant_id, region_id=region_id,
            daily_token_limit=None, actor_daily_token_limit=None,
            revision=1, updated_by=actor, updated_at=now,
        ).on_conflict_do_nothing(index_elements=["tenant_id", "region_id"]))
        query = query.with_for_update().execution_options(populate_existing=True)
    policy = db.scalar(query)
    if policy is None:
        raise RuntimeError("AI authoring quota policy could not be initialized")
    return policy


def _bucket(
    db: Session, *, period_start: date, scope_kind: str, scope_key: str,
    lock: bool,
) -> AIAuthoringQuotaBucket | None:
    tenant_id, region_id = _namespace(db)
    query = select(AIAuthoringQuotaBucket).where(
        AIAuthoringQuotaBucket.tenant_id == tenant_id,
        AIAuthoringQuotaBucket.region_id == region_id,
        AIAuthoringQuotaBucket.period_start == period_start,
        AIAuthoringQuotaBucket.scope_kind == scope_kind,
        AIAuthoringQuotaBucket.scope_key == scope_key,
    )
    if lock:
        db.execute(_insert_for(db, AIAuthoringQuotaBucket).values(
            id=new_id(), tenant_id=tenant_id, region_id=region_id,
            period_start=period_start, scope_kind=scope_kind,
            scope_key=scope_key, used_tokens=0,
        ).on_conflict_do_nothing(index_elements=[
            "tenant_id", "region_id", "period_start", "scope_kind", "scope_key",
        ]))
        query = query.with_for_update().execution_options(populate_existing=True)
    return db.scalar(query)


def reserve_authoring_tokens(
    db: Session, *, actor: str, entity_type: str, entity_id: str,
    token_budget: int,
    source_entity_type: str | None = None,
    source_entity_id: str | None = None,
    source_step: int | None = None,
) -> str:
    """Atomically reserve capacity before chargeable I/O; return receipt ID."""
    if (
        not actor or len(actor) > 255 or not entity_type or len(entity_type) > 64
        or not entity_id or len(entity_id) > 36 or token_budget < 1
        or token_budget > 10_000_000
    ):
        raise ValueError("Invalid AI authoring quota admission identity or budget")
    source_entity_type = source_entity_type or entity_type
    source_entity_id = source_entity_id or entity_id
    if (
        len(source_entity_type) > 64 or len(source_entity_id) > 36
        or (source_step is not None and (
            isinstance(source_step, bool) or not isinstance(source_step, int)
            or source_step < 0
        ))
    ):
        raise ValueError("Invalid AI quota source identity")
    require_locking_transaction(db, purpose="AI authoring quota admission")
    tenant_id, region_id = _namespace(db)
    policy = _policy(db, lock=True)
    existing = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
        AIAuthoringQuotaReservation.entity_type == entity_type,
        AIAuthoringQuotaReservation.entity_id == entity_id,
    ).with_for_update())
    if existing is not None:
        db.rollback()
        raise AuthoringQuotaConflict("This authoring intent already has a quota reservation")
    now = _utc_now(db)
    period_start = now.date()
    namespace_bucket = _bucket(
        db, period_start=period_start, scope_kind="namespace",
        scope_key=NAMESPACE_SCOPE_KEY, lock=True,
    )
    actor_bucket = _bucket(
        db, period_start=period_start, scope_kind="actor",
        scope_key=actor, lock=True,
    )
    if namespace_bucket is None or actor_bucket is None:
        db.rollback()
        raise RuntimeError("AI authoring quota buckets could not be initialized")
    if (
        policy.daily_token_limit is not None
        and namespace_bucket.used_tokens + token_budget > policy.daily_token_limit
    ):
        used = namespace_bucket.used_tokens
        limit = policy.daily_token_limit
        revision = policy.revision
        db.rollback()
        record_audit_event(
            db, event_type="ai.authoring_quota.denied", actor_type="user",
            actor_id=actor, entity_type=entity_type, entity_id=entity_id,
            outcome="denied", details={
                "scope": "namespace", "period_start": period_start.isoformat(),
                "used_tokens": used, "requested_tokens": token_budget,
                "limit": limit, "policy_revision": revision,
            },
        )
        db.commit()
        raise AuthoringQuotaExceeded("Namespace authoring quota is exhausted")
    if (
        policy.actor_daily_token_limit is not None
        and actor_bucket.used_tokens + token_budget > policy.actor_daily_token_limit
    ):
        used = actor_bucket.used_tokens
        limit = policy.actor_daily_token_limit
        revision = policy.revision
        db.rollback()
        record_audit_event(
            db, event_type="ai.authoring_quota.denied", actor_type="user",
            actor_id=actor, entity_type=entity_type, entity_id=entity_id,
            outcome="denied", details={
                "scope": "actor", "period_start": period_start.isoformat(),
                "used_tokens": used, "requested_tokens": token_budget,
                "limit": limit, "policy_revision": revision,
            },
        )
        db.commit()
        raise AuthoringQuotaExceeded("Your authoring quota is exhausted")
    namespace_bucket.used_tokens += token_budget
    actor_bucket.used_tokens += token_budget
    receipt = AIAuthoringQuotaReservation(
        tenant_id=tenant_id, region_id=region_id,
        entity_type=entity_type, entity_id=entity_id, actor=actor,
        source_entity_type=source_entity_type,
        source_entity_id=source_entity_id, source_step=source_step,
        period_start=period_start, reserved_tokens=token_budget,
        known_tokens=0, charged_tokens=token_budget, status="reserved",
        external_charge_unknown=True, created_at=now,
    )
    db.add(receipt)
    db.flush()
    record_audit_event(
        db, event_type="ai.authoring_quota.reserved", actor_type="user",
        actor_id=actor, entity_type=entity_type, entity_id=entity_id,
        details={
            "reservation_id": receipt.id, "period_start": period_start.isoformat(),
            "reserved_tokens": token_budget, "policy_revision": policy.revision,
            "source_entity_type": source_entity_type,
            "source_entity_id": source_entity_id,
            "source_step": source_step,
        },
    )
    db.commit()  # Capacity is durable before any provider request can start.
    return receipt.id


def settle_authoring_tokens(
    db: Session, reservation_id: str, *, known_tokens: int,
    external_charge_unknown: bool,
) -> None:
    """Settle once; unresolved external charge keeps the whole reservation."""
    if isinstance(known_tokens, bool) or not isinstance(known_tokens, int) or known_tokens < 0:
        raise ValueError("Known authoring token usage must be non-negative")
    require_locking_transaction(db, purpose="AI authoring quota settlement")
    tenant_id, region_id = _namespace(db)
    row = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise RuntimeError("AI authoring quota reservation disappeared")
    if row.status == "settled":
        if row.known_tokens != known_tokens or row.external_charge_unknown != external_charge_unknown:
            existing = db.scalar(select(AIAuthoringQuotaSettlementConflict.id).where(
                AIAuthoringQuotaSettlementConflict.tenant_id == tenant_id,
                AIAuthoringQuotaSettlementConflict.region_id == region_id,
                AIAuthoringQuotaSettlementConflict.reservation_id == row.id,
                AIAuthoringQuotaSettlementConflict.reported_known_tokens == known_tokens,
                AIAuthoringQuotaSettlementConflict.reported_external_charge_unknown == external_charge_unknown,
            ))
            if existing is None:
                conflict = AIAuthoringQuotaSettlementConflict(
                    tenant_id=tenant_id, region_id=region_id,
                    reservation_id=row.id,
                    reported_known_tokens=known_tokens,
                    reported_external_charge_unknown=external_charge_unknown,
                    settled_known_tokens_snapshot=row.known_tokens,
                    settled_external_charge_unknown_snapshot=row.external_charge_unknown,
                    settled_charged_tokens_snapshot=row.charged_tokens,
                    recorded_at=_utc_now(db),
                )
                db.add(conflict)
                db.flush()
                record_audit_event(
                    db, event_type="ai.authoring_quota.settlement_conflict",
                    actor_type="system", actor_id="structured_model",
                    entity_type=row.entity_type, entity_id=row.entity_id,
                    outcome="failure", details={
                        "reservation_id": row.id, "conflict_id": conflict.id,
                        "reported_known_tokens": known_tokens,
                        "reported_external_charge_unknown": external_charge_unknown,
                        "settled_known_tokens": row.known_tokens,
                        "settled_external_charge_unknown": row.external_charge_unknown,
                    },
                )
            db.commit()  # Preserve contradictory usage even when the caller raises.
            raise AuthoringQuotaConflict("AI authoring quota settlement changed")
        db.commit()
        return
    if row.status != "reserved":
        raise AuthoringQuotaConflict("AI authoring quota reservation has invalid state")
    charged_tokens = (
        max(row.reserved_tokens, known_tokens)
        if external_charge_unknown else known_tokens
    )
    namespace_bucket = _bucket(
        db, period_start=row.period_start, scope_kind="namespace",
        scope_key=NAMESPACE_SCOPE_KEY, lock=True,
    )
    actor_bucket = _bucket(
        db, period_start=row.period_start, scope_kind="actor",
        scope_key=row.actor, lock=True,
    )
    if namespace_bucket is None or actor_bucket is None:
        raise RuntimeError("AI authoring quota bucket disappeared")
    delta = charged_tokens - row.reserved_tokens
    if namespace_bucket.used_tokens + delta < 0 or actor_bucket.used_tokens + delta < 0:
        raise RuntimeError("AI authoring quota counter is inconsistent")
    namespace_bucket.used_tokens += delta
    actor_bucket.used_tokens += delta
    row.known_tokens = known_tokens
    row.charged_tokens = charged_tokens
    row.external_charge_unknown = external_charge_unknown
    row.status = "settled"
    row.settled_at = _utc_now(db)
    record_audit_event(
        db, event_type="ai.authoring_quota.settled", actor_type="system",
        actor_id="structured_model", entity_type=row.entity_type,
        entity_id=row.entity_id, details={
            "reservation_id": row.id, "reserved_tokens": row.reserved_tokens,
            "known_tokens": known_tokens, "charged_tokens": charged_tokens,
            "external_charge_unknown": external_charge_unknown,
            "period_start": row.period_start.isoformat(),
        },
    )
    db.commit()


def authoring_quota_snapshot(db: Session, *, actor: str) -> dict:
    """Show current actor and namespace admission headroom, never other actors."""
    tenant_id, region_id = _namespace(db)
    now = _utc_now(db)
    period_start = now.date()
    policy = db.scalar(select(AIAuthoringQuotaPolicy).where(
        AIAuthoringQuotaPolicy.tenant_id == tenant_id,
        AIAuthoringQuotaPolicy.region_id == region_id,
    ))
    namespace_bucket = _bucket(
        db, period_start=period_start, scope_kind="namespace",
        scope_key=NAMESPACE_SCOPE_KEY, lock=False,
    )
    actor_bucket = _bucket(
        db, period_start=period_start, scope_kind="actor",
        scope_key=actor, lock=False,
    )
    pending = db.scalar(select(func.count()).select_from(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
        AIAuthoringQuotaReservation.period_start == period_start,
        AIAuthoringQuotaReservation.actor == actor,
        AIAuthoringQuotaReservation.status == "reserved",
    )) or 0
    unknown = db.scalar(select(func.count()).select_from(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
        AIAuthoringQuotaReservation.period_start == period_start,
        AIAuthoringQuotaReservation.actor == actor,
        AIAuthoringQuotaReservation.status == "settled",
        AIAuthoringQuotaReservation.external_charge_unknown.is_(True),
        ~select(AIAuthoringQuotaAdjustment.id).where(
            AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
            AIAuthoringQuotaAdjustment.region_id == region_id,
            AIAuthoringQuotaAdjustment.reservation_id == AIAuthoringQuotaReservation.id,
        ).exists(),
    )) or 0
    namespace_used = namespace_bucket.used_tokens if namespace_bucket else 0
    actor_used = actor_bucket.used_tokens if actor_bucket else 0
    namespace_limit = policy.daily_token_limit if policy else None
    actor_limit = policy.actor_daily_token_limit if policy else None
    return {
        "period_start": period_start, "actor": actor,
        "namespace_limit": namespace_limit, "namespace_used": namespace_used,
        "namespace_available": (
            max(0, namespace_limit - namespace_used)
            if namespace_limit is not None else None
        ),
        "actor_limit": actor_limit, "actor_used": actor_used,
        "actor_available": (
            max(0, actor_limit - actor_used)
            if actor_limit is not None else None
        ),
        "pending_requests": pending, "unknown_charge_requests": unknown,
        "policy_revision": policy.revision if policy else 1,
    }


def list_authoring_reservations(
    db: Session, *, actor: str | None, state: str,
    limit: int, cursor: str | None = None,
    source_entity_id: str | None = None,
    older_than_minutes: int | None = None,
) -> tuple[list[AIAuthoringQuotaReservation], str | None]:
    """Keyset-page actionable receipts within one namespace and actor scope."""
    if state not in {"attention", "pending", "uncertain", "all"}:
        raise ValueError("Invalid AI quota reservation state")
    if limit < 1 or limit > 100:
        raise ValueError("Invalid AI quota reservation page size")
    tenant_id, region_id = _namespace(db)
    base = [
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ]
    if actor is not None:
        base.append(AIAuthoringQuotaReservation.actor == actor)
    unresolved = ~select(AIAuthoringQuotaAdjustment.id).where(
        AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
        AIAuthoringQuotaAdjustment.region_id == region_id,
        AIAuthoringQuotaAdjustment.reservation_id == AIAuthoringQuotaReservation.id,
    ).exists()
    if state == "attention":
        base.append(or_(
            AIAuthoringQuotaReservation.status == "reserved",
            and_(
                AIAuthoringQuotaReservation.status == "settled",
                AIAuthoringQuotaReservation.external_charge_unknown.is_(True),
                unresolved,
            ),
        ))
    elif state == "pending":
        base.append(AIAuthoringQuotaReservation.status == "reserved")
    elif state == "uncertain":
        base.extend([
            AIAuthoringQuotaReservation.status == "settled",
            AIAuthoringQuotaReservation.external_charge_unknown.is_(True),
            unresolved,
        ])
    if source_entity_id is not None:
        base.append(AIAuthoringQuotaReservation.source_entity_id == source_entity_id)
    if older_than_minutes is not None:
        if older_than_minutes < 1 or older_than_minutes > 525_600:
            raise ValueError("Invalid AI quota reservation age filter")
        base.append(
            AIAuthoringQuotaReservation.created_at <=
            _utc_now(db) - timedelta(minutes=older_than_minutes)
        )
    if cursor is not None:
        # Resolve the cursor only under the same actor/namespace boundary; a
        # foreign cursor must not reveal the existence of another receipt.
        cursor_row = db.scalar(select(AIAuthoringQuotaReservation).where(
            AIAuthoringQuotaReservation.id == cursor,
            AIAuthoringQuotaReservation.tenant_id == tenant_id,
            AIAuthoringQuotaReservation.region_id == region_id,
            *(
                [AIAuthoringQuotaReservation.actor == actor]
                if actor is not None else []
            ),
        ))
        if cursor_row is None:
            raise ValueError("AI quota reservation cursor is unavailable")
        base.append(or_(
            AIAuthoringQuotaReservation.created_at < cursor_row.created_at,
            and_(
                AIAuthoringQuotaReservation.created_at == cursor_row.created_at,
                AIAuthoringQuotaReservation.id < cursor_row.id,
            ),
        ))
    rows = list(db.scalars(
        select(AIAuthoringQuotaReservation)
        .where(*base)
        .order_by(
            AIAuthoringQuotaReservation.created_at.desc(),
            AIAuthoringQuotaReservation.id.desc(),
        )
        .limit(limit + 1)
    ).all())
    has_more = len(rows) > limit
    page = rows[:limit]
    return page, page[-1].id if has_more else None


def list_authoring_settlement_conflicts(
    db: Session, *, limit: int, cursor: str | None = None,
) -> tuple[list[tuple[AIAuthoringQuotaSettlementConflict, AIAuthoringQuotaReservation]], str | None]:
    """Page immutable contradictory reports for global AI administrators."""
    if limit < 1 or limit > 100:
        raise ValueError("Invalid AI quota settlement conflict page size")
    tenant_id, region_id = _namespace(db)
    criteria = [
        AIAuthoringQuotaSettlementConflict.tenant_id == tenant_id,
        AIAuthoringQuotaSettlementConflict.region_id == region_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ]
    if cursor is not None:
        marker = db.scalar(select(AIAuthoringQuotaSettlementConflict).where(
            AIAuthoringQuotaSettlementConflict.id == cursor,
            AIAuthoringQuotaSettlementConflict.tenant_id == tenant_id,
            AIAuthoringQuotaSettlementConflict.region_id == region_id,
        ))
        if marker is None:
            raise ValueError("AI quota settlement conflict cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaSettlementConflict.recorded_at < marker.recorded_at,
            and_(
                AIAuthoringQuotaSettlementConflict.recorded_at == marker.recorded_at,
                AIAuthoringQuotaSettlementConflict.id < marker.id,
            ),
        ))
    rows = list(db.execute(
        select(AIAuthoringQuotaSettlementConflict, AIAuthoringQuotaReservation)
        .join(
            AIAuthoringQuotaReservation,
            AIAuthoringQuotaReservation.id == AIAuthoringQuotaSettlementConflict.reservation_id,
        )
        .where(*criteria)
        .order_by(
            AIAuthoringQuotaSettlementConflict.recorded_at.desc(),
            AIAuthoringQuotaSettlementConflict.id.desc(),
        )
        .limit(limit + 1)
    ).all())
    page = rows[:limit]
    return page, page[-1][0].id if len(rows) > limit else None


def configure_authoring_quota(
    db: Session, *, actor: str, expected_revision: int,
    daily_token_limit: int | None, actor_daily_token_limit: int | None,
    reason: str,
) -> dict:
    require_locking_transaction(db, purpose="AI authoring quota configuration")
    policy = _policy(db, lock=True, actor=actor)
    if policy.revision != expected_revision:
        db.rollback()
        raise AuthoringQuotaConflict("AI authoring quota policy revision changed")
    policy.daily_token_limit = daily_token_limit
    policy.actor_daily_token_limit = actor_daily_token_limit
    policy.revision += 1
    policy.updated_by = actor
    policy.updated_at = _utc_now(db)
    record_audit_event(
        db, event_type="ai.authoring_quota.policy_updated", actor_type="user",
        actor_id=actor, entity_type="ai_authoring_quota_policy",
        entity_id=policy.id, details={
            "revision": policy.revision,
            "daily_token_limit": daily_token_limit,
            "actor_daily_token_limit": actor_daily_token_limit,
            "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
        },
    )
    db.commit()
    return authoring_quota_snapshot(db, actor=actor)
