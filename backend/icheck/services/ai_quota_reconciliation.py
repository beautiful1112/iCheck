"""Two-person, evidence-referenced manual correction of uncertain AI charges.

This is an audited human attestation, not an automatic provider-bill verifier.
The original model-call receipt remains sealed; a distinct append-only ledger
entry adjusts both daily counters only after independent review.
"""

from __future__ import annotations

import re

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import (
    AIAuthoringQuotaAdjustment,
    AIAuthoringQuotaBucket,
    AIAuthoringQuotaReconciliationCase,
    AIAuthoringQuotaReservation,
    AIAuthoringQuotaSettlementConflict,
)
from .ai_authoring_quota import (
    NAMESPACE_SCOPE_KEY,
    AuthoringQuotaConflict,
    _namespace,
    _utc_now,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


def _require_global_ai_admin(actor: PrincipalContext) -> str:
    if (
        actor.principal_id is None
        or actor.principal_type != "user"
        or not actor.permits("ai.manage")
        or actor.authorization_scope.get("all") is not True
    ):
        raise PermissionError("Authenticated global AI administration is required")
    return actor.principal_id


def _case_query(db: Session, case_id: str):
    tenant_id, region_id = _namespace(db)
    return select(AIAuthoringQuotaReconciliationCase).where(
        AIAuthoringQuotaReconciliationCase.id == case_id,
        AIAuthoringQuotaReconciliationCase.tenant_id == tenant_id,
        AIAuthoringQuotaReconciliationCase.region_id == region_id,
    )


def _lock_existing_bucket(db: Session, *, period_start, scope_kind: str, scope_key: str):
    tenant_id, region_id = _namespace(db)
    return db.scalar(select(AIAuthoringQuotaBucket).where(
        AIAuthoringQuotaBucket.tenant_id == tenant_id,
        AIAuthoringQuotaBucket.region_id == region_id,
        AIAuthoringQuotaBucket.period_start == period_start,
        AIAuthoringQuotaBucket.scope_kind == scope_kind,
        AIAuthoringQuotaBucket.scope_key == scope_key,
    ).with_for_update().execution_options(populate_existing=True))


def _reported_known_floor(db: Session, reservation_id: str) -> int:
    tenant_id, region_id = _namespace(db)
    return db.scalar(select(func.max(AIAuthoringQuotaSettlementConflict.reported_known_tokens)).where(
        AIAuthoringQuotaSettlementConflict.tenant_id == tenant_id,
        AIAuthoringQuotaSettlementConflict.region_id == region_id,
        AIAuthoringQuotaSettlementConflict.reservation_id == reservation_id,
    )) or 0


def propose_quota_reconciliation(
    db: Session, *, reservation_id: str, confirmed_total_tokens: int,
    evidence_sha256: str, evidence_reference: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaReconciliationCase:
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
        "AI quota billing attestation",
    )
    require_locking_transaction(db, purpose="AI quota billing attestation")
    tenant_id, region_id = _namespace(db)
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise LookupError("AI quota receipt not found")
    if receipt.status != "settled" or not receipt.external_charge_unknown:
        raise AuthoringQuotaConflict("Only settled uncertain charges can be attested")
    if confirmed_total_tokens < max(receipt.known_tokens, _reported_known_floor(db, receipt.id)):
        raise ValueError("Confirmed total cannot be below provider-reported known usage")
    if db.scalar(select(AIAuthoringQuotaAdjustment.id).where(
        AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
        AIAuthoringQuotaAdjustment.region_id == region_id,
        AIAuthoringQuotaAdjustment.reservation_id == reservation_id,
    )) is not None:
        raise AuthoringQuotaConflict("This charge has already been manually adjusted")
    if db.scalar(select(AIAuthoringQuotaReconciliationCase.id).where(
        AIAuthoringQuotaReconciliationCase.tenant_id == tenant_id,
        AIAuthoringQuotaReconciliationCase.region_id == region_id,
        AIAuthoringQuotaReconciliationCase.reservation_id == reservation_id,
        AIAuthoringQuotaReconciliationCase.status == "proposed",
    )) is not None:
        raise AuthoringQuotaConflict("An adjustment proposal is already awaiting review")
    case = AIAuthoringQuotaReconciliationCase(
        tenant_id=tenant_id, region_id=region_id,
        reservation_id=reservation_id, actor=receipt.actor,
        period_start=receipt.period_start,
        source_entity_type=receipt.source_entity_type,
        source_entity_id=receipt.source_entity_id,
        source_step=receipt.source_step,
        known_tokens_snapshot=receipt.known_tokens,
        original_charged_tokens=receipt.charged_tokens,
        confirmed_total_tokens=confirmed_total_tokens,
        delta_tokens=confirmed_total_tokens - receipt.charged_tokens,
        evidence_sha256=evidence_sha256,
        evidence_reference=evidence_reference.strip(), reason=reason.strip(),
        proposed_by_principal_id=proposer_id, proposed_by=actor.subject,
        proposed_at=_utc_now(db), status="proposed",
    )
    db.add(case)
    db.flush()
    record_audit_event(
        db, event_type="ai.quota.reconciliation.proposed",
        actor_type=actor.principal_type, actor_id=actor.subject,
        entity_type="ai_quota_reconciliation_case", entity_id=case.id,
        details={
            "reservation_id": reservation_id,
            "known_tokens": receipt.known_tokens,
            "held_tokens": receipt.charged_tokens,
            "confirmed_total_tokens": confirmed_total_tokens,
            "delta_tokens": case.delta_tokens,
            "evidence_sha256": evidence_sha256,
            "manually_attested": True,
        },
    )
    db.commit()
    return case


def review_quota_reconciliation(
    db: Session, *, case_id: str, decision: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaReconciliationCase:
    reviewer_id = _require_global_ai_admin(actor)
    if decision not in {"approve", "reject"}:
        raise ValueError("Review decision must be approve or reject")
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Review reason must contain 10-1000 characters")
    assert_no_inline_secrets({"reason": reason}, "AI quota review reason")
    require_locking_transaction(db, purpose="AI quota adjustment review")
    tenant_id, region_id = _namespace(db)
    initial = db.scalar(_case_query(db, case_id))
    if initial is None:
        raise LookupError("AI quota adjustment proposal not found")
    # All proposal and review paths lock the receipt before the case so one
    # charge can produce at most one committed ledger adjustment.
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == initial.reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise RuntimeError("AI quota receipt disappeared")
    case = db.scalar(_case_query(db, case_id).with_for_update().execution_options(populate_existing=True))
    if case is None:
        raise RuntimeError("AI quota adjustment proposal disappeared")
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
        raise AuthoringQuotaConflict("AI quota adjustment proposal is already terminal")
    if (
        receipt.status != "settled" or not receipt.external_charge_unknown
        or case.actor != receipt.actor
        or case.period_start != receipt.period_start
        or case.source_entity_type != receipt.source_entity_type
        or case.source_entity_id != receipt.source_entity_id
        or case.source_step != receipt.source_step
        or case.known_tokens_snapshot != receipt.known_tokens
        or case.original_charged_tokens != receipt.charged_tokens
    ):
        raise AuthoringQuotaConflict("AI quota receipt no longer matches its proposal")
    if decision == "approve" and case.confirmed_total_tokens < _reported_known_floor(db, receipt.id):
        raise AuthoringQuotaConflict(
            "A contradictory late settlement exceeds the proposed total; reject and repropose"
        )
    now = _utc_now(db)
    if decision == "approve":
        if db.scalar(select(AIAuthoringQuotaAdjustment.id).where(
            AIAuthoringQuotaAdjustment.tenant_id == tenant_id,
            AIAuthoringQuotaAdjustment.region_id == region_id,
            AIAuthoringQuotaAdjustment.reservation_id == receipt.id,
        )) is not None:
            raise AuthoringQuotaConflict("This charge already has an adjustment")
        namespace_bucket = _lock_existing_bucket(
            db, period_start=receipt.period_start, scope_kind="namespace",
            scope_key=NAMESPACE_SCOPE_KEY,
        )
        actor_bucket = _lock_existing_bucket(
            db, period_start=receipt.period_start, scope_kind="actor",
            scope_key=receipt.actor,
        )
        if namespace_bucket is None or actor_bucket is None:
            raise RuntimeError("AI quota bucket disappeared")
        if (
            namespace_bucket.used_tokens < receipt.charged_tokens
            or actor_bucket.used_tokens < receipt.charged_tokens
            or
            namespace_bucket.used_tokens + case.delta_tokens < 0
            or actor_bucket.used_tokens + case.delta_tokens < 0
        ):
            raise RuntimeError("AI quota counter is inconsistent")
        namespace_bucket.used_tokens += case.delta_tokens
        actor_bucket.used_tokens += case.delta_tokens
        db.add(AIAuthoringQuotaAdjustment(
            tenant_id=tenant_id, region_id=region_id,
            reservation_id=receipt.id, reconciliation_case_id=case.id,
            actor=receipt.actor, period_start=receipt.period_start,
            original_charged_tokens=receipt.charged_tokens,
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
        db, event_type=f"ai.quota.reconciliation.{requested_status}",
        actor_type=actor.principal_type, actor_id=actor.subject,
        entity_type="ai_quota_reconciliation_case", entity_id=case.id,
        details={
            "reservation_id": receipt.id,
            "delta_tokens": case.delta_tokens if decision == "approve" else 0,
            "confirmed_total_tokens": case.confirmed_total_tokens,
            "evidence_sha256": case.evidence_sha256,
            "manually_attested": True,
        },
    )
    db.commit()
    return case


def list_quota_reconciliations(
    db: Session, *, status: str, limit: int, cursor: str | None = None,
    actor: PrincipalContext,
) -> tuple[list[AIAuthoringQuotaReconciliationCase], str | None]:
    _require_global_ai_admin(actor)
    if status not in {"proposed", "applied", "rejected", "all"} or not 1 <= limit <= 100:
        raise ValueError("Invalid AI quota adjustment listing filter")
    tenant_id, region_id = _namespace(db)
    criteria = [
        AIAuthoringQuotaReconciliationCase.tenant_id == tenant_id,
        AIAuthoringQuotaReconciliationCase.region_id == region_id,
    ]
    if status != "all":
        criteria.append(AIAuthoringQuotaReconciliationCase.status == status)
    if cursor is not None:
        marker = db.scalar(_case_query(db, cursor))
        if marker is None:
            raise ValueError("AI quota adjustment cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaReconciliationCase.proposed_at < marker.proposed_at,
            and_(
                AIAuthoringQuotaReconciliationCase.proposed_at == marker.proposed_at,
                AIAuthoringQuotaReconciliationCase.id < marker.id,
            ),
        ))
    rows = list(db.scalars(
        select(AIAuthoringQuotaReconciliationCase).where(*criteria)
        .order_by(
            AIAuthoringQuotaReconciliationCase.proposed_at.desc(),
            AIAuthoringQuotaReconciliationCase.id.desc(),
        )
        .limit(limit + 1)
    ).all())
    page = rows[:limit]
    return page, page[-1].id if len(rows) > limit else None
