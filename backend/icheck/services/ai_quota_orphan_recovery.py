"""Two-person, hold-preserving recovery for abandoned model-call reservations.

An old timestamp alone never proves a model call is dead. Only exact Studio,
Activation Policy proposal, or Investigation source identities with durable
terminal execution state qualify.
Closing changes reserved -> settled-unknown and preserves every charged token.
Verified audit usage above the original hold adds only a positive overrun; this
does not inspect a provider bill or authorize any credit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import (
    AIAuthoringQuotaOrphanCase,
    AIAuthoringQuotaOrphanAuditEvidence,
    AIAuthoringQuotaOrphanClosure,
    AIAuthoringQuotaReservation,
    ActivationPolicyProposal,
    AgentExecution,
    AgentExecutionStatus,
    AuditEvent,
    CapabilityStudioGenerationAttempt,
    Investigation,
)
from .ai_authoring_quota import (
    AuthoringQuotaConflict,
    _namespace,
    _utc_now,
)
from .ai_quota_reconciliation import (
    NAMESPACE_SCOPE_KEY,
    _lock_existing_bucket,
    _require_global_ai_admin,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


MIN_AGE = timedelta(hours=24)
TERMINAL_STUDIO = {"failed", "interrupted", "validated"}
STRUCTURED_MODEL_SOURCES = {
    "capability_studio_generation_attempt",
    "device_activation_policy_proposal",
}
TERMINAL_INVESTIGATION_EXECUTION = {
    "completed": AgentExecutionStatus.SUCCEEDED,
    "failed": AgentExecutionStatus.FAILED,
    "escalated": AgentExecutionStatus.FAILED,
    "cancelled": AgentExecutionStatus.CANCELLED,
}


@dataclass(frozen=True)
class SourceTerminalEvidence:
    status: str
    terminal_at: datetime
    audited_known_tokens: int
    audit_event_count: int
    audit_sha256: str


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _model_audit_evidence(
    db: Session, *, source_type: str, source_id: str,
    source_step: int | None, actor: str,
    expected_route_id: str | None = None,
    expected_model_id: str | None = None,
) -> tuple[int, int, str]:
    """Validate an exact, bounded candidate chain and fingerprint its audit rows."""
    tenant_id, region_id = _namespace(db)
    structured_source = source_type in STRUCTURED_MODEL_SOURCES
    if structured_source:
        events = ("capability.model.completed", "capability.model.failed",
                  "capability.model.budget_exceeded")
        entity_type = source_type
    else:
        events = ("investigation.model.completed", "investigation.model.failed")
        entity_type = "investigation"
    rows = list(db.scalars(select(AuditEvent).where(
        AuditEvent.tenant_id == tenant_id,
        AuditEvent.region_id == region_id,
        AuditEvent.entity_type == entity_type,
        AuditEvent.entity_id == source_id,
        AuditEvent.event_type.in_(events),
    ).limit(501)).all())
    if len(rows) > 500:
        raise AuthoringQuotaConflict("Model audit known usage history exceeds the bounded verifier")
    matching = []
    for event in rows:
        details = event.details or {}
        if not isinstance(details, dict):
            raise AuthoringQuotaConflict("Model audit known usage details are invalid")
        if source_type == "investigation":
            if source_step is None:
                raise AuthoringQuotaConflict("Model audit has no exact Investigation step")
            iteration = details.get("iteration")
            if isinstance(iteration, bool) or not isinstance(iteration, int):
                raise AuthoringQuotaConflict("Model audit known usage iteration is invalid")
            if iteration != source_step + 1:
                continue
        matching.append(event)
    indexed = []
    studio_route: str | None = None
    studio_prompt: str | None = None
    for event in matching:
        details = event.details
        index = details.get("candidate_index")
        usage = details.get("token_usage")
        if (
            event.actor_type != "agent"
            or event.actor_id != (actor if structured_source
                                  else "agent.langgraph")
            or not isinstance(details.get("model_id"), str)
            or not details["model_id"]
            or isinstance(index, bool) or not isinstance(index, int) or index < 0
            or isinstance(usage, bool) or not isinstance(usage, int)
            or usage < 0 or usage > 1_000_000_000
            or details.get("fallback_used") is not (index > 0)
        ):
            raise AuthoringQuotaConflict("Model audit known usage provenance is invalid")
        if structured_source and (
            not isinstance(details.get("route_id"), str) or not details["route_id"]
            or not isinstance(details.get("prompt_sha256"), str)
            or len(details["prompt_sha256"]) != 64
            or not isinstance(details.get("external_charge_unknown"), bool)
        ):
            raise AuthoringQuotaConflict("Structured model audit provenance is incomplete")
        if structured_source:
            if studio_route is None:
                studio_route = details["route_id"]
                studio_prompt = details["prompt_sha256"]
            elif details["route_id"] != studio_route or details["prompt_sha256"] != studio_prompt:
                raise AuthoringQuotaConflict("Structured model audit route or prompt changed within the candidate chain")
        indexed.append((index, event))
    indexed.sort(key=lambda item: item[0])
    total = 0
    for expected_index, (index, event) in enumerate(indexed):
        if index != expected_index:
            raise AuthoringQuotaConflict("Model audit candidate chain is incomplete or duplicated")
        details = event.details
        last = expected_index == len(indexed) - 1
        if event.event_type.endswith(".completed"):
            if event.outcome != "success" or not last:
                raise AuthoringQuotaConflict("Model audit completion is not terminal")
            candidate = details.get("candidate_token_usage") if structured_source else details["token_usage"]
            cumulative = details["token_usage"] if structured_source else details.get("cumulative_token_usage")
            if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0 or cumulative != total + candidate:
                raise AuthoringQuotaConflict("Model audit completed usage is inconsistent")
            total = cumulative
        else:
            if event.outcome != "failure" or (event.event_type.endswith(".budget_exceeded") and not last):
                raise AuthoringQuotaConflict("Model audit failure chain is inconsistent")
            total += details["token_usage"]
            if structured_source and details.get("cumulative_token_usage") != total:
                raise AuthoringQuotaConflict("Structured model audit cumulative usage is inconsistent")
        if total > 1_000_000_000:
            raise AuthoringQuotaConflict("Model audit known usage exceeds the supported bound")
    if expected_route_id is not None or expected_model_id is not None:
        if not indexed or indexed[-1][1].event_type != "capability.model.completed":
            raise AuthoringQuotaConflict("Terminal model audit completion is missing")
        completed = indexed[-1][1].details
        if (completed.get("route_id") != expected_route_id
            or completed.get("model_id") != expected_model_id):
            raise AuthoringQuotaConflict("Terminal model audit route or model differs from the proposal")
    fingerprint = [{
        "id": event.id, "event_type": event.event_type,
        "occurred_at": _as_utc(event.occurred_at).isoformat(),
        "actor_type": event.actor_type, "actor_id": event.actor_id,
        "outcome": event.outcome, "details": event.details,
    } for _, event in indexed]
    digest = hashlib.sha256(json.dumps(
        fingerprint, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return total, len(indexed), digest


def source_terminal_evidence(
    db: Session, receipt: AIAuthoringQuotaReservation,
    *, now: datetime | None = None,
) -> SourceTerminalEvidence:
    """Return exact terminal source proof or refuse; never infer it from age."""
    if receipt.status != "reserved" or receipt.known_tokens != 0 or (
        receipt.charged_tokens != receipt.reserved_tokens
        or not receipt.external_charge_unknown
    ):
        raise AuthoringQuotaConflict("Receipt is not an unchanged pending hold")
    checked_at = now or _utc_now(db)
    cutoff = checked_at - MIN_AGE
    if _as_utc(receipt.created_at) > cutoff:
        raise AuthoringQuotaConflict("Pending hold has not completed its 24-hour cooling period")
    tenant_id, region_id = _namespace(db)
    if receipt.source_entity_type == "capability_studio_generation_attempt":
        if (
            receipt.entity_type != "capability_studio_generation_attempt"
            or receipt.source_entity_id != receipt.entity_id
            or receipt.source_step is not None
        ):
            raise AuthoringQuotaConflict("Studio receipt is not bound to an exact generation attempt")
        attempt = db.scalar(select(CapabilityStudioGenerationAttempt).where(
            CapabilityStudioGenerationAttempt.id == receipt.entity_id,
            CapabilityStudioGenerationAttempt.tenant_id == tenant_id,
            CapabilityStudioGenerationAttempt.region_id == region_id,
        ))
        if attempt is None or attempt.actor != receipt.actor or attempt.status not in TERMINAL_STUDIO:
            raise AuthoringQuotaConflict("Studio generation has no matching terminal attempt")
        terminal_at = _as_utc(attempt.updated_at)
        if terminal_at > cutoff or _as_utc(attempt.lease_expires_at) > cutoff:
            raise AuthoringQuotaConflict("Studio attempt or ownership lease is still within the cooling period")
        source_status = attempt.status
    elif receipt.source_entity_type == "device_activation_policy_proposal":
        if (
            receipt.entity_type != "device_activation_policy_proposal"
            or receipt.source_entity_id != receipt.entity_id
            or receipt.source_step is not None
        ):
            raise AuthoringQuotaConflict("Activation proposal receipt is not bound to an exact request")
        proposal = db.scalar(select(ActivationPolicyProposal).where(
            ActivationPolicyProposal.id == receipt.entity_id,
            ActivationPolicyProposal.tenant_id == tenant_id,
            ActivationPolicyProposal.region_id == region_id,
        ))
        if (
            proposal is None or proposal.actor != receipt.actor
            or proposal.status not in {"succeeded", "failed"}
            or (proposal.status == "failed" and proposal.failure_code == "Interrupted")
        ):
            # An administrative interruption cannot prove the external model
            # call stopped; a late result may still be discarded by the API.
            raise AuthoringQuotaConflict("Activation proposal has no matching terminal model result")
        terminal_at = _as_utc(proposal.updated_at)
        if terminal_at > cutoff:
            raise AuthoringQuotaConflict("Activation proposal is still within the cooling period")
        if proposal.status == "succeeded":
            result_hash = hashlib.sha256(json.dumps(
                proposal.result_snapshot, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            if (
                proposal.result_sha256 != result_hash
                or not proposal.route_id or not proposal.model_id
                or proposal.failure_code is not None
            ):
                raise AuthoringQuotaConflict("Activation proposal result provenance is invalid")
            source_status = "succeeded"
        else:
            if not proposal.failure_code or proposal.result_sha256 is not None:
                raise AuthoringQuotaConflict("Activation proposal failure provenance is invalid")
            source_status = "failed"
    elif receipt.source_entity_type == "investigation":
        if (
            receipt.entity_type != "investigation_step"
            or receipt.source_entity_id is None
            or receipt.source_step is None
            or receipt.source_step < 0
            or receipt.entity_id != str(uuid5(
                NAMESPACE_URL,
                f"icheck:investigation:{receipt.source_entity_id}:iteration:{receipt.source_step}",
            ))
        ):
            raise AuthoringQuotaConflict("Agent receipt is not bound to an exact Investigation step")
        investigation = db.scalar(select(Investigation).where(
            Investigation.id == receipt.source_entity_id,
            Investigation.tenant_id == tenant_id,
            Investigation.region_id == region_id,
        ))
        execution = db.scalar(select(AgentExecution).where(
            AgentExecution.investigation_id == receipt.source_entity_id,
            AgentExecution.tenant_id == tenant_id,
            AgentExecution.region_id == region_id,
        ))
        if (
            investigation is None or execution is None
            or investigation.created_by != receipt.actor
            or investigation.status not in TERMINAL_INVESTIGATION_EXECUTION
            or execution.status != TERMINAL_INVESTIGATION_EXECUTION.get(investigation.status)
            or execution.worker_id is not None
            or execution.lease_token_hash is not None
            or execution.lease_expires_at is not None
            or investigation.finished_at is None
            or execution.finished_at is None
        ):
            raise AuthoringQuotaConflict("Investigation has no matching terminal unowned execution")
        terminal_at = max(
            _as_utc(investigation.finished_at), _as_utc(execution.finished_at),
        )
        if terminal_at > cutoff:
            raise AuthoringQuotaConflict("Investigation execution is still within the cooling period")
        source_status = f"{investigation.status}:{execution.status.value}"
    else:
        raise AuthoringQuotaConflict("This source type has no terminality verifier")
    audited_known_tokens, audit_event_count, audit_sha256 = _model_audit_evidence(
        db, source_type=receipt.source_entity_type,
        source_id=receipt.source_entity_id,
        source_step=receipt.source_step, actor=receipt.actor,
        expected_route_id=(proposal.route_id if receipt.source_entity_type == "device_activation_policy_proposal" else None),
        expected_model_id=(proposal.model_id if receipt.source_entity_type == "device_activation_policy_proposal" else None),
    )
    if receipt.source_entity_type == "device_activation_policy_proposal":
        if proposal.tokens_used != audited_known_tokens or (
            proposal.status == "succeeded" and audit_event_count == 0
        ):
            raise AuthoringQuotaConflict("Activation proposal model usage audit does not match its terminal result")
        # The case's status snapshot is VARCHAR(32). Seal the full proposal
        # identity and outcome into its existing append-only evidence digest,
        # including failures with zero model-audit rows. Review recomputes it.
        source_material = {
            "contract": "icheck.activation-proposal-orphan-source/v1",
            "id": proposal.id,
            "parent_id": proposal.parent_id,
            "device_id": proposal.device_id,
            "artifact_version_id": proposal.artifact_version_id,
            "protocol": proposal.protocol,
            "actor": proposal.actor,
            "request_key": proposal.request_key,
            "request_sha256": proposal.request_sha256,
            "brief_sha256": hashlib.sha256(proposal.brief.encode("utf-8")).hexdigest(),
            "status": proposal.status,
            "result_sha256": proposal.result_sha256,
            "failure_code": proposal.failure_code,
            "route_id": proposal.route_id,
            "model_id": proposal.model_id,
            "tokens_used": proposal.tokens_used,
            "external_charge_unknown": proposal.external_charge_unknown,
            "created_at": _as_utc(proposal.created_at).isoformat(),
            "updated_at": terminal_at.isoformat(),
            "model_audit_sha256": audit_sha256,
        }
        audit_sha256 = hashlib.sha256(json.dumps(
            source_material, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
    return SourceTerminalEvidence(
        status=source_status, terminal_at=terminal_at,
        audited_known_tokens=audited_known_tokens,
        audit_event_count=audit_event_count, audit_sha256=audit_sha256,
    )


def list_orphan_candidates(
    db: Session, *, limit: int, cursor: str | None,
    actor: PrincipalContext,
) -> tuple[list[tuple[AIAuthoringQuotaReservation, bool, str, SourceTerminalEvidence | None]], str | None]:
    _require_global_ai_admin(actor)
    if not 1 <= limit <= 100:
        raise ValueError("Invalid AI quota orphan candidate page size")
    tenant_id, region_id = _namespace(db)
    now = _utc_now(db)
    criteria = [
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
        AIAuthoringQuotaReservation.status == "reserved",
        AIAuthoringQuotaReservation.created_at <= now - MIN_AGE,
    ]
    if cursor is not None:
        marker = db.scalar(select(AIAuthoringQuotaReservation).where(
            AIAuthoringQuotaReservation.id == cursor,
            AIAuthoringQuotaReservation.tenant_id == tenant_id,
            AIAuthoringQuotaReservation.region_id == region_id,
        ))
        if marker is None:
            raise ValueError("AI quota orphan candidate cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaReservation.created_at < marker.created_at,
            and_(
                AIAuthoringQuotaReservation.created_at == marker.created_at,
                AIAuthoringQuotaReservation.id < marker.id,
            ),
        ))
    rows = list(db.scalars(select(AIAuthoringQuotaReservation).where(*criteria)
        .order_by(
            AIAuthoringQuotaReservation.created_at.desc(),
            AIAuthoringQuotaReservation.id.desc(),
        ).limit(limit + 1)).all())
    page = rows[:limit]
    next_cursor = page[-1].id if len(rows) > limit else None
    result = []
    for receipt in page:
        try:
            evidence = source_terminal_evidence(db, receipt, now=now)
            pending = db.scalar(select(AIAuthoringQuotaOrphanCase.id).where(
                AIAuthoringQuotaOrphanCase.tenant_id == tenant_id,
                AIAuthoringQuotaOrphanCase.region_id == region_id,
                AIAuthoringQuotaOrphanCase.reservation_id == receipt.id,
                AIAuthoringQuotaOrphanCase.status == "proposed",
            ))
            if pending is not None:
                result.append((receipt, False, "Already awaiting independent review", evidence))
            else:
                result.append((receipt, True, "Terminal source verified", evidence))
        except AuthoringQuotaConflict as exc:
            result.append((receipt, False, str(exc), None))
    return result, next_cursor


def _case_query(db: Session, case_id: str):
    tenant_id, region_id = _namespace(db)
    return select(AIAuthoringQuotaOrphanCase).where(
        AIAuthoringQuotaOrphanCase.id == case_id,
        AIAuthoringQuotaOrphanCase.tenant_id == tenant_id,
        AIAuthoringQuotaOrphanCase.region_id == region_id,
    )


def propose_orphan_closure(
    db: Session, *, reservation_id: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaOrphanCase:
    proposer_id = _require_global_ai_admin(actor)
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Recovery reason must contain 10-1000 characters")
    assert_no_inline_secrets({"reason": reason}, "AI orphan quota recovery reason")
    require_locking_transaction(db, purpose="AI quota orphan recovery proposal")
    tenant_id, region_id = _namespace(db)
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise LookupError("AI quota receipt not found")
    evidence = source_terminal_evidence(db, receipt)
    if db.scalar(select(AIAuthoringQuotaOrphanClosure.id).where(
        AIAuthoringQuotaOrphanClosure.tenant_id == tenant_id,
        AIAuthoringQuotaOrphanClosure.region_id == region_id,
        AIAuthoringQuotaOrphanClosure.reservation_id == reservation_id,
    )) is not None:
        raise AuthoringQuotaConflict("Pending hold was already closed")
    if db.scalar(select(AIAuthoringQuotaOrphanCase.id).where(
        AIAuthoringQuotaOrphanCase.tenant_id == tenant_id,
        AIAuthoringQuotaOrphanCase.region_id == region_id,
        AIAuthoringQuotaOrphanCase.reservation_id == reservation_id,
        AIAuthoringQuotaOrphanCase.status == "proposed",
    )) is not None:
        raise AuthoringQuotaConflict("An orphan closure is already awaiting review")
    case = AIAuthoringQuotaOrphanCase(
        tenant_id=tenant_id, region_id=region_id,
        reservation_id=receipt.id, actor=receipt.actor,
        period_start=receipt.period_start,
        source_entity_type=receipt.source_entity_type,
        source_entity_id=receipt.source_entity_id,
        source_step=receipt.source_step,
        source_status_snapshot=evidence.status,
        source_terminal_at=evidence.terminal_at,
        reserved_tokens_snapshot=receipt.reserved_tokens,
        reason=reason.strip(), proposed_by_principal_id=proposer_id,
        proposed_by=actor.subject, proposed_at=_utc_now(db), status="proposed",
    )
    db.add(case)
    db.flush()
    db.add(AIAuthoringQuotaOrphanAuditEvidence(
        tenant_id=tenant_id, region_id=region_id,
        reservation_id=receipt.id, orphan_case_id=case.id,
        known_tokens=evidence.audited_known_tokens,
        event_count=evidence.audit_event_count,
        audit_sha256=evidence.audit_sha256,
        captured_at=case.proposed_at,
    ))
    record_audit_event(
        db, event_type="ai.quota.orphan_closure.proposed",
        actor_type="user", actor_id=actor.subject,
        entity_type="ai_quota_orphan_case", entity_id=case.id,
        details={
            "reservation_id": receipt.id,
            "source_status": evidence.status,
            "reserved_tokens": receipt.reserved_tokens,
            "audited_known_tokens": evidence.audited_known_tokens,
            "audit_event_count": evidence.audit_event_count,
            "audit_sha256": evidence.audit_sha256,
            "counter_delta": 0,
        },
    )
    db.commit()
    return case


def review_orphan_closure(
    db: Session, *, case_id: str, decision: str, reason: str,
    actor: PrincipalContext,
) -> AIAuthoringQuotaOrphanCase:
    reviewer_id = _require_global_ai_admin(actor)
    if decision not in {"close", "reject"}:
        raise ValueError("Review decision must be close or reject")
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Review reason must contain 10-1000 characters")
    assert_no_inline_secrets({"reason": reason}, "AI orphan quota review reason")
    require_locking_transaction(db, purpose="AI quota orphan recovery review")
    tenant_id, region_id = _namespace(db)
    initial = db.scalar(_case_query(db, case_id))
    if initial is None:
        raise LookupError("AI quota orphan closure proposal not found")
    receipt = db.scalar(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.id == initial.reservation_id,
        AIAuthoringQuotaReservation.tenant_id == tenant_id,
        AIAuthoringQuotaReservation.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if receipt is None:
        raise RuntimeError("AI quota receipt disappeared")
    case = db.scalar(_case_query(db, case_id).with_for_update().execution_options(populate_existing=True))
    if case is None:
        raise RuntimeError("AI quota orphan case disappeared")
    if reviewer_id == case.proposed_by_principal_id or actor.subject == receipt.actor:
        raise PermissionError("Reviewer must be independent of proposer and model-call actor")
    requested_status = "closed" if decision == "close" else "rejected"
    if case.status != "proposed":
        if (
            case.status == requested_status
            and case.reviewed_by_principal_id == reviewer_id
            and case.review_reason == reason.strip()
        ):
            db.commit()
            return case
        raise AuthoringQuotaConflict("AI quota orphan case is already terminal")
    now = _utc_now(db)
    counter_delta = 0
    if decision == "close":
        if (
            receipt.actor != case.actor
            or receipt.period_start != case.period_start
            or receipt.source_entity_type != case.source_entity_type
            or receipt.source_entity_id != case.source_entity_id
            or receipt.source_step != case.source_step
            or receipt.reserved_tokens != case.reserved_tokens_snapshot
        ):
            raise AuthoringQuotaConflict("Pending receipt no longer matches its proposal")
        evidence = source_terminal_evidence(db, receipt, now=now)
        if (
            evidence.status != case.source_status_snapshot
            or evidence.terminal_at != _as_utc(case.source_terminal_at)
        ):
            raise AuthoringQuotaConflict("Source terminal evidence changed; reject and repropose")
        audit_snapshot = db.scalar(select(AIAuthoringQuotaOrphanAuditEvidence).where(
            AIAuthoringQuotaOrphanAuditEvidence.tenant_id == tenant_id,
            AIAuthoringQuotaOrphanAuditEvidence.region_id == region_id,
            AIAuthoringQuotaOrphanAuditEvidence.orphan_case_id == case.id,
            AIAuthoringQuotaOrphanAuditEvidence.reservation_id == receipt.id,
        ))
        if audit_snapshot is None:
            # Cases proposed before the audit-snapshot migration could only
            # represent zero known usage. Never retrofit a new audit onto one.
            if evidence.audit_event_count:
                raise AuthoringQuotaConflict("Model audit evidence changed; reject and repropose")
            known_tokens = 0
        else:
            if (
                audit_snapshot.known_tokens != evidence.audited_known_tokens
                or audit_snapshot.event_count != evidence.audit_event_count
                or audit_snapshot.audit_sha256 != evidence.audit_sha256
            ):
                raise AuthoringQuotaConflict("Model audit evidence changed; reject and repropose")
            known_tokens = audit_snapshot.known_tokens
        if db.scalar(select(AIAuthoringQuotaOrphanClosure.id).where(
            AIAuthoringQuotaOrphanClosure.tenant_id == tenant_id,
            AIAuthoringQuotaOrphanClosure.region_id == region_id,
            AIAuthoringQuotaOrphanClosure.reservation_id == receipt.id,
        )) is not None:
            raise AuthoringQuotaConflict("Pending hold was already closed")
        charged_tokens = max(receipt.reserved_tokens, known_tokens)
        counter_delta = charged_tokens - receipt.reserved_tokens
        if counter_delta:
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
            if (namespace_bucket.used_tokens < receipt.reserved_tokens
                    or actor_bucket.used_tokens < receipt.reserved_tokens):
                raise RuntimeError("AI quota counter is inconsistent")
            namespace_bucket.used_tokens += counter_delta
            actor_bucket.used_tokens += counter_delta
        receipt.status = "settled"
        receipt.known_tokens = known_tokens
        receipt.charged_tokens = charged_tokens
        receipt.external_charge_unknown = True
        receipt.settled_at = now
    case.status = requested_status
    case.reviewed_by_principal_id = reviewer_id
    case.reviewed_by = actor.subject
    case.review_reason = reason.strip()
    case.reviewed_at = now
    db.flush()
    if decision == "close":
        db.add(AIAuthoringQuotaOrphanClosure(
            tenant_id=tenant_id, region_id=region_id,
            reservation_id=receipt.id, orphan_case_id=case.id,
            actor=receipt.actor, period_start=receipt.period_start,
            reserved_tokens=receipt.reserved_tokens,
            closed_by_principal_id=reviewer_id, closed_at=now,
        ))
    record_audit_event(
        db, event_type=f"ai.quota.orphan_closure.{requested_status}",
        actor_type="user", actor_id=actor.subject,
        entity_type="ai_quota_orphan_case", entity_id=case.id,
        details={
            "reservation_id": receipt.id,
            "reserved_tokens": receipt.reserved_tokens,
            "audited_known_tokens": receipt.known_tokens if decision == "close" else None,
            "audit_sha256": audit_snapshot.audit_sha256 if decision == "close" and audit_snapshot is not None else None,
            "counter_delta": counter_delta,
            "external_charge_unknown": True if decision == "close" else None,
        },
    )
    db.commit()
    return case


def list_orphan_cases(
    db: Session, *, status: str, limit: int, cursor: str | None,
    actor: PrincipalContext,
) -> tuple[list[AIAuthoringQuotaOrphanCase], str | None]:
    _require_global_ai_admin(actor)
    if status not in {"proposed", "closed", "rejected", "all"} or not 1 <= limit <= 100:
        raise ValueError("Invalid AI quota orphan-case listing filter")
    tenant_id, region_id = _namespace(db)
    criteria = [
        AIAuthoringQuotaOrphanCase.tenant_id == tenant_id,
        AIAuthoringQuotaOrphanCase.region_id == region_id,
    ]
    if status != "all":
        criteria.append(AIAuthoringQuotaOrphanCase.status == status)
    if cursor is not None:
        marker = db.scalar(_case_query(db, cursor))
        if marker is None:
            raise ValueError("AI quota orphan-case cursor is unavailable")
        criteria.append(or_(
            AIAuthoringQuotaOrphanCase.proposed_at < marker.proposed_at,
            and_(
                AIAuthoringQuotaOrphanCase.proposed_at == marker.proposed_at,
                AIAuthoringQuotaOrphanCase.id < marker.id,
            ),
        ))
    rows = list(db.scalars(select(AIAuthoringQuotaOrphanCase).where(*criteria)
        .order_by(
            AIAuthoringQuotaOrphanCase.proposed_at.desc(),
            AIAuthoringQuotaOrphanCase.id.desc(),
        ).limit(limit + 1)).all())
    page = rows[:limit]
    return page, page[-1].id if len(rows) > limit else None
