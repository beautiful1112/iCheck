"""Governed append-only corrections after the first AI billing attestation.

Every case binds the exact current ledger head and previous total. Receipt
locking serializes proposals, reviews and late model reports; reviewers apply
only the signed difference, never replace earlier sealed decisions.
"""

from __future__ import annotations

import re

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSupplementAdjustment,
    AIAuthoringQuotaSupplementCase,
)
from .ai_authoring_quota import AuthoringQuotaConflict, _namespace, _utc_now
from .ai_quota_reconciliation import (
    NAMESPACE_SCOPE_KEY,
    _lock_existing_bucket,
    _reported_known_floor,
    _require_global_ai_admin,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


def _case_query(db: Session, case_id: str):
    tenant_id, region_id = _namespace(db)
    return select(AIAuthoringQuotaSupplementCase).where(
        AIAuthoringQuotaSupplementCase.id == case_id,
        AIAuthoringQuotaSupplementCase.tenant_id == tenant_id,
        AIAuthoringQuotaSupplementCase.region_id == region_id,
    )


def _current_charge(db: Session, reservation_id: str) -> tuple[str, int, int]:
    """Return (head adjustment ID, sequence for next entry, effective total)."""
    tenant_id, region_id = _namespace(db)
    first = db.scalar(select(AIAuthoringQuotaAdjustment).where(
        AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
        AIAuthoringQuotaAdjustment.region_id == region_id,
        AIAuthoringQuotaAdjustment.reservation_id == reservation_id,
    ))
    if first is None:
        raise AuthoringQuotaConflict("An independently approved first adjustment is required")
    entries = list(db.scalars(select(AIAuthoringQuotaSupplementAdjustment).where(
        AIAuthoringQuotaSupplementAdjustment.tenant_id == tenant_id,
        AIAuthoringQuotaSupplementAdjustment.region_id == region_id,
        AIAuthoringQuotaSupplementAdjustment.reservation_id == reservation_id,
    ).order_by(AIAuthoringQuotaSupplementAdjustment.sequence)).all())
    head_id, total = first.id, first.confirmed_total_tokens
    for expected_sequence, entry in enumerate(entries, start=1):
        if (
            entry.sequence != expected_sequence
            or entry.base_adjustment_id != head_id
            or entry.previous_total_tokens != total
            or entry.delta_tokens != entry.confirmed_total_tokens - total
            or entry.actor != first.actor
            or entry.period_start != first.period_start
        ):
            raise RuntimeError("AI quota supplemental ledger chain is inconsistent")
        head_id, total = entry.id, entry.confirmed_total_tokens
    return head_id, len(entries) + 1, total


def list_supplement_candidates(
    db: Session, *, limit: int, cursor: str | None,
    actor: PrincipalContext,
) -> tuple[list[AIAuthoringQuotaReservation], str | None]:
    _require_global_ai_admin(actor)
    if not 1 <= limit <= 100:
        raise ValueError("Invalid AI quota supplement candidate page size")
    tenant_id, region_id = _namespace(db)
    criteria = [
        AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
        AIAuthoringQuotaAdjustment.region_id == region_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
        ~select(AIAuthoringQuotaSupplementCase.id).where(
            AIAuthoringQuotaSupplementCase.tenant_id == tenant_id,
            AIAuthoringQuotaSupplementCase.region_id == region_id,
            AIAuthoringQuotaSupplementCase.reservation_id == AIAuthoringQuotaReservation.id,
            AIAuthoringQuotaSupplementCase.status == "proposed",
        ).exists(),
    ]
    if cursor is not None:
        marker = db.scalar(select(AIAuthoringQuotaAdjustment).where(
            AIAuthoringQuotaAdjustment.id == cursor,
            AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
            AIAuthoringQuotaAdjustment.region_id == region_id,
        ))
        if marker is None:
            raise ValueError("AI quota supplement candidate cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaAdjustment.applied_at < marker.applied_at,
            and_(
                AIAuthoringQuotaAdjustment.applied_at == marker.applied_at,
                AIAuthoringQuotaAdjustment.id < marker.id,
            ),
        ))
    rows = list(db.execute(select(AIAuthoringQuotaAdjustment, AIAuthoringQuotaReservation)
        .join(
            AIAuthoringQuotaReservation,
            AIAuthoringQuotaReservation.id == AIAuthoringQuotaAdjustment.reservation_id,
        )
        .where(*criteria)
        .order_by(
            AIAuthoringQuotaAdjustment.applied_at.desc(),
            AIAuthoringQuotaAdjustment.id.desc(),
        ).limit(limit + 1)).all())
    page = rows[:limit]
    return [receipt for _, receipt in page], page[-1][0].id if len(rows) > limit else None


def propose_supplement(
    db: Session, *, reservation_id: str, confirmed_total_tokens: int,
    evidence_sha256: str, evidence_reference: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaSupplementCase:
    proposer_id = _require_global_ai_admin(actor)
    if (
        isinstance(confirmed_total_tokens, bool)
        or not isinstance(confirmed_total_tokens, int)
        or confirmed_total_tokens < 0
        or confirmed_total_tokens > 1_000_000_000
    ):
        raise ValueError("Confirmed provider total must be a supported non-negative token count")
    if not re.fullmatch(r"[0-9a-f]{64}", evidence_sha256):
        raise ValueError("A lowercase SHA-256 evidence digest is required")
    if not 10 <= len(evidence_reference.strip()) <= 255 or not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Evidence reference and reason must each contain 10-1000 characters")
    assert_no_inline_secrets(
        {"evidence_reference": evidence_reference, "reason": reason},
        "AI quota supplemental billing attestation",
    )
    require_locking_transaction(db, purpose="AI quota supplemental attestation")
    tenant_id, region_id = _namespace(db)
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise LookupError("AI quota receipt not found")
    if receipt.status != "settled" or not receipt.external_charge_unknown:
        raise AuthoringQuotaConflict("Only settled uncertain charges can be corrected")
    if confirmed_total_tokens < max(receipt.known_tokens, _reported_known_floor(db, receipt.id)):
        raise ValueError("Confirmed total cannot be below provider-reported known usage")
    base_id, sequence, previous_total = _current_charge(db, receipt.id)
    if db.scalar(select(AIAuthoringQuotaSupplementCase.id).where(
        AIAuthoringQuotaSupplementCase.tenant_id == tenant_id,
        AIAuthoringQuotaSupplementCase.region_id == region_id,
        AIAuthoringQuotaSupplementCase.reservation_id == receipt.id,
        AIAuthoringQuotaSupplementCase.status == "proposed",
    )) is not None:
        raise AuthoringQuotaConflict("A supplemental correction is already awaiting review")
    case = AIAuthoringQuotaSupplementCase(
        tenant_id=tenant_id, region_id=region_id,
        reservation_id=receipt.id, base_adjustment_id=base_id,
        sequence=sequence, actor=receipt.actor,
        period_start=receipt.period_start,
        source_entity_type=receipt.source_entity_type,
        source_entity_id=receipt.source_entity_id,
        source_step=receipt.source_step,
        previous_total_tokens=previous_total,
        confirmed_total_tokens=confirmed_total_tokens,
        delta_tokens=confirmed_total_tokens - previous_total,
        evidence_sha256=evidence_sha256,
        evidence_reference=evidence_reference.strip(), reason=reason.strip(),
        proposed_by_principal_id=proposer_id, proposed_by=actor.subject,
        proposed_at=_utc_now(db), status="proposed",
    )
    db.add(case)
    db.flush()
    record_audit_event(
        db, event_type="ai.quota.supplement.proposed",
        actor_type="user", actor_id=actor.subject,
        entity_type="ai_quota_supplement_case", entity_id=case.id,
        details={
            "reservation_id": receipt.id,
            "base_adjustment_id": base_id,
            "sequence": sequence,
            "previous_total_tokens": previous_total,
            "confirmed_total_tokens": confirmed_total_tokens,
            "delta_tokens": case.delta_tokens,
            "evidence_sha256": evidence_sha256,
            "manually_attested": True,
        },
    )
    db.commit()
    return case


def review_supplement(
    db: Session, *, case_id: str, decision: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaSupplementCase:
    reviewer_id = _require_global_ai_admin(actor)
    if decision not in {"approve", "reject"}:
        raise ValueError("Review decision must be approve or reject")
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Review reason must contain 10-1000 characters")
    assert_no_inline_secrets({"reason": reason}, "AI quota supplement review reason")
    require_locking_transaction(db, purpose="AI quota supplement review")
    tenant_id, region_id = _namespace(db)
    initial = db.scalar(_case_query(db, case_id))
    if initial is None:
        raise LookupError("AI quota supplemental proposal not found")
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == initial.reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise RuntimeError("AI quota receipt disappeared")
    case = db.scalar(_case_query(db, case_id).with_for_update().execution_options(populate_existing=True))
    if case is None:
        raise RuntimeError("AI quota supplemental proposal disappeared")
    if reviewer_id == case.proposed_by_principal_id or actor.subject == receipt.actor:
        raise PermissionError("Reviewer must be independent of proposer and model-call actor")
    requested_status = "applied" if decision == "approve" else "rejected"
    if case.status != "proposed":
        if (
            case.status == requested_status
            and case.reviewed_by_principal_id == reviewer_id
            and case.review_reason == reason.strip()
        ):
            db.commit()
            return case
        raise AuthoringQuotaConflict("AI quota supplemental proposal is already terminal")
    now = _utc_now(db)
    if decision == "approve":
        if (
            receipt.status != "settled" or not receipt.external_charge_unknown
            or case.actor != receipt.actor
            or case.period_start != receipt.period_start
            or case.source_entity_type != receipt.source_entity_type
            or case.source_entity_id != receipt.source_entity_id
            or case.source_step != receipt.source_step
        ):
            raise AuthoringQuotaConflict("AI quota receipt no longer matches its proposal")
        base_id, sequence, previous_total = _current_charge(db, receipt.id)
        if (
            case.base_adjustment_id != base_id
            or case.sequence != sequence
            or case.previous_total_tokens != previous_total
        ):
            raise AuthoringQuotaConflict("Charge head changed; reject and repropose")
        if case.confirmed_total_tokens < max(receipt.known_tokens, _reported_known_floor(db, receipt.id)):
            raise AuthoringQuotaConflict("A late model report exceeds the proposed total; reject and repropose")
        namespace_bucket = _lock_existing_bucket(
            db, period_start=receipt.period_start,
            scope_kind="namespace", scope_key=NAMESPACE_SCOPE_KEY,
        )
        actor_bucket = _lock_existing_bucket(
            db, period_start=receipt.period_start,
            scope_kind="actor", scope_key=receipt.actor,
        )
        if namespace_bucket is None or actor_bucket is None:
            raise RuntimeError("AI quota bucket disappeared")
        if (
            namespace_bucket.used_tokens < previous_total
            or actor_bucket.used_tokens < previous_total
            or namespace_bucket.used_tokens + case.delta_tokens < 0
            or actor_bucket.used_tokens + case.delta_tokens < 0
        ):
            raise RuntimeError("AI quota counter is inconsistent")
        namespace_bucket.used_tokens += case.delta_tokens
        actor_bucket.used_tokens += case.delta_tokens
        db.add(AIAuthoringQuotaSupplementAdjustment(
            tenant_id=tenant_id, region_id=region_id,
            reservation_id=receipt.id, supplement_case_id=case.id,
            base_adjustment_id=base_id, sequence=sequence,
            actor=receipt.actor, period_start=receipt.period_start,
            previous_total_tokens=previous_total,
            confirmed_total_tokens=case.confirmed_total_tokens,
            delta_tokens=case.delta_tokens,
            applied_by_principal_id=reviewer_id, applied_at=now,
        ))
    case.status = requested_status
    case.reviewed_by_principal_id = reviewer_id
    case.reviewed_by = actor.subject
    case.review_reason = reason.strip()
    case.reviewed_at = now
    record_audit_event(
        db, event_type=f"ai.quota.supplement.{requested_status}",
        actor_type="user", actor_id=actor.subject,
        entity_type="ai_quota_supplement_case", entity_id=case.id,
        details={
            "reservation_id": receipt.id,
            "base_adjustment_id": case.base_adjustment_id,
            "sequence": case.sequence,
            "delta_tokens": case.delta_tokens if decision == "approve" else 0,
            "confirmed_total_tokens": case.confirmed_total_tokens,
            "evidence_sha256": case.evidence_sha256,
            "manually_attested": True,
        },
    )
    db.commit()
    return case


def list_supplement_cases(
    db: Session, *, status: str, limit: int, cursor: str | None,
    actor: PrincipalContext,
) -> tuple[list[AIAuthoringQuotaSupplementCase], str | None]:
    _require_global_ai_admin(actor)
    if status not in {"proposed", "applied", "rejected", "all"} or not 1 <= limit <= 100:
        raise ValueError("Invalid AI quota supplement listing filter")
    tenant_id, region_id = _namespace(db)
    criteria = [
        AIAuthoringQuotaSupplementCase.tenant_id == tenant_id,
        AIAuthoringQuotaSupplementCase.region_id == region_id,
    ]
    if status != "all":
        criteria.append(AIAuthoringQuotaSupplementCase.status == status)
    if cursor is not None:
        marker = db.scalar(_case_query(db, cursor))
        if marker is None:
            raise ValueError("AI quota supplement cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaSupplementCase.proposed_at < marker.proposed_at,
            and_(
                AIAuthoringQuotaSupplementCase.proposed_at == marker.proposed_at,
                AIAuthoringQuotaSupplementCase.id < marker.id,
            ),
        ))
    rows = list(db.scalars(select(AIAuthoringQuotaSupplementCase).where(*criteria)
        .order_by(
            AIAuthoringQuotaSupplementCase.proposed_at.desc(),
            AIAuthoringQuotaSupplementCase.id.desc(),
        ).limit(limit + 1)).all())
    page = rows[:limit]
    return page, page[-1].id if len(rows) > limit else None
