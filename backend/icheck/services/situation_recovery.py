"""Exhaustive Situation recovery checks and reusable peer-reviewed criteria.

All deployments are locked in sorted order BEFORE any origin chain/Worker.
Locking sources one at a time without that prefix deadlocks with a producer
sharing a Worker. Situation is always last; no reverse Alert lock is taken.
This is a recovery evidence transaction, not an incident closure operation.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import or_, select

from ..models import (Alert, AlertConditionState, AlertStatus, CollectorConditionReceipt,
    CollectorConditionSource, CollectorDeployment, CollectorWorker, CollectorSourceQualificationRequest,
    CollectorSourceQualificationReview, CollectorSourceQualificationRevocation, Situation, SituationAlert,
    SituationRecoveryPolicyRequest, SituationRecoveryPolicyReview, SituationRecoveryPolicyRevocation, utcnow)
from ..situation_recovery_schemas import (RecoverySourceBinding, SituationRecoveryEvidenceRead,
    SituationRecoveryPolicyCreate)
from ..config import get_settings
from .alert_conditions import as_utc
from .audit import record_audit_event
from .authorization_scope import require_alert_access, require_situation_access
from .collector_conditions import canonical
from .collectors import assert_no_inline_secrets
from .source_qualifications import (_actor, _human, _lock_origin, _origin, _row, _start,
    MANAGE, QUALIFY, require_source_access, source_quiet_evidence)
from .replacement_recovery import (replacement_references, reference_sources,
    require_replacement_scope, current_replacement)

REVIEW = "situations.recovery.qualify"
MAX_MEMBERS = 512
MAX_QUIET_RECEIPTS = 256


def _bindings(request):
    values = [RecoverySourceBinding.model_validate(value) for value in request.source_bindings]
    if not 1 <= len(values) <= 64 or len({item.source_id for item in values}) != len(values):
        raise ValueError("Recovery policy source bindings are invalid")
    return sorted(values, key=lambda item: item.source_id)


def _prelock(db, bindings, *, replacements=()):
    """Acquire the complete producer mutex prefix, including unused policy sources."""
    result = []
    for binding in bindings:
        source = _row(db, CollectorConditionSource, binding.source_id)
        review = _row(db, CollectorSourceQualificationReview, binding.qualification_review_id)
        request = _row(db, CollectorSourceQualificationRequest, review.request_id)
        if request.source_id != source.id:
            raise LookupError("Recovery policy source qualification not found")
        result.append((source, request, review))
    complete = reference_sources([source for source, _, _ in result], replacements)
    for deployment_id in sorted({source.deployment_id for source in complete}):
        _row(db, CollectorDeployment, deployment_id, lock=True)
    return result


def _policy_actor(db, requested, permission, *, material=False, mapped=False):
    if (not requested.permits(permission) or (material and not requested.permits("capabilities.read"))
        or (mapped and not requested.permits("alerts.read"))):
        raise PermissionError("Recovery policy requires initiating and current authority")
    actor = _actor(db, requested, permission, material_access_required=material, nowait=mapped)
    if mapped and not actor.permits("alerts.read"):
        raise PermissionError("Replacement recovery requires initiating and current alerts.read")
    return actor


def policy_reference_scope(db, policy, *actors):
    references = replacement_references(db, policy)
    current = [_row(db, CollectorConditionSource, item.source_id) for item in _bindings(policy)]
    for source in reference_sources(current, references):
        for actor in actors:
            require_source_access(db, source, actor)
    require_replacement_scope(db, references, *actors)


def _accepted_source(db, source, request, review, actor, policy, *, nonblocking_authority=False):
    require_source_access(db, source, actor)
    # A policy may span unrelated producers sharing lower-level Device,
    # version or credential locks. Never wait on those while retaining an
    # earlier origin chain: abort the transaction and let the caller retry.
    source, snapshot, definition = _lock_origin(db, source.id, request.baseline_receipt_id, nowait=True)
    if canonical(snapshot) != canonical(request.snapshot):
        raise ValueError("Recovery policy qualified source origin changed")
    if as_utc(request.expires_at) <= utcnow() or db.scalar(select(CollectorSourceQualificationRevocation.id)
        .where(CollectorSourceQualificationRevocation.review_id == review.id)):
        raise ValueError("Recovery policy source acceptance expired or was revoked")
    if request.evidence_environment != policy.evidence_environment:
        raise ValueError("Recovery policy evidence environment must match every exact source acceptance")
    if as_utc(policy.expires_at) > as_utc(request.expires_at):
        raise ValueError("Recovery policy may not outlive any source acceptance")
    if max(policy.max_age_seconds, policy.max_sample_gap_seconds) > definition.max_age_seconds:
        raise ValueError("Recovery policy age and sample gap may not weaken the source freshness bound")
    for person_id, subject, permission in (
        (request.author_principal_id, request.author_subject, MANAGE),
        (review.reviewer_principal_id, review.reviewer_subject, QUALIFY)):
        peer = _human(db, person_id, subject, permission, material_access_required=True, nowait=nonblocking_authority)
        require_source_access(db, source, peer)
    return source, snapshot, definition


def _audit(db, event, actor, row):
    record_audit_event(db, event_type=event, actor_type="user", actor_id=actor.subject,
        entity_type="situation_recovery_policy", entity_id=row.id,
        details={"authorizes_incident_closure": False, "remediation_causality_proven": False})


def propose_recovery_policy(db, payload: SituationRecoveryPolicyCreate, actor):
    _start(db)
    if payload.proof_version == 2 and not get_settings().enable_replacement_recovery:
        raise PermissionError("Replacement-aware recovery is disabled pending compatible rollout")
    references = replacement_references(db, payload)
    sources = _prelock(db, payload.source_bindings, replacements=references)
    requested = actor
    actor = _policy_actor(db, actor, MANAGE, material=True, mapped=bool(references))
    for source in reference_sources([source for source, _, _ in sources], references):
        for principal in (requested, actor): require_source_access(db, source, principal)
    require_replacement_scope(db, references, requested, actor)
    now = utcnow()
    if not now < as_utc(payload.expires_at) <= now + timedelta(days=30):
        raise ValueError("Recovery policy expiry must be future and within thirty days")
    for source, request, review in sources:
        _accepted_source(db, source, request, review, actor, payload, nonblocking_authority=bool(references))
    for reference in references:
        current_replacement(db, reference, payload)
    assert_no_inline_secrets(payload.model_dump(mode="json"))
    values = payload.model_dump(exclude={"expires_at"})
    existing = db.scalar(select(SituationRecoveryPolicyRequest).where(
        SituationRecoveryPolicyRequest.request_key == payload.request_key))
    if existing:
        if (existing.author_principal_id != actor.principal_id or existing.author_subject != actor.subject
            or as_utc(existing.expires_at) != as_utc(payload.expires_at)
            or any(canonical(getattr(existing, key)) != canonical(value) for key, value in values.items())):
            raise ValueError("Recovery policy request key was reused with different criteria or author")
        return existing
    row = SituationRecoveryPolicyRequest(**values, expires_at=as_utc(payload.expires_at),
        author_principal_id=actor.principal_id, author_subject=actor.subject)
    db.add(row); db.flush()
    _audit(db, "situation.recovery.policy.proposed", actor, row); db.flush()
    return row


def review_recovery_policy(db, request_id, payload, actor):
    _start(db)
    request = _row(db, SituationRecoveryPolicyRequest, request_id)
    if request.proof_version == 2 and not get_settings().enable_replacement_recovery:
        raise PermissionError("Replacement-aware recovery is disabled pending compatible rollout")
    references = replacement_references(db, request)
    sources = _prelock(db, _bindings(request), replacements=references)
    requested = actor
    actor = _policy_actor(db, actor, REVIEW, material=True, mapped=bool(references))
    author = _human(db, request.author_principal_id, request.author_subject, MANAGE, material_access_required=True, nowait=bool(references))
    if actor.principal_id == author.principal_id or actor.subject == author.subject:
        raise PermissionError("Recovery criteria require an independent human peer")
    for source, source_request, source_review in sources:
        _accepted_source(db, source, source_request, source_review, actor, request, nonblocking_authority=bool(references))
        require_source_access(db, source, author)
        require_source_access(db, source, requested)
    for source in reference_sources([], references):
        for principal in (requested, actor, author): require_source_access(db, source, principal)
    require_replacement_scope(db, references, requested, actor, author)
    for reference in references:
        current_replacement(db, reference, request)
    request = _row(db, SituationRecoveryPolicyRequest, request.id, lock=True)
    if as_utc(request.expires_at) <= utcnow():
        raise ValueError("Recovery policy proposal expired")
    assert_no_inline_secrets({"acceptance_reference": payload.acceptance_reference, "reason": payload.reason})
    existing = db.scalar(select(SituationRecoveryPolicyReview).where(
        SituationRecoveryPolicyReview.request_id == request.id))
    if existing:
        if db.scalar(select(SituationRecoveryPolicyRevocation.id).where(
            SituationRecoveryPolicyRevocation.review_id == existing.id)):
            raise ValueError("Revoked recovery policy cannot be reactivated by retry")
        if (existing.reviewer_principal_id != actor.principal_id or existing.reviewer_subject != actor.subject
            or existing.acceptance_reference != payload.acceptance_reference or existing.reason != payload.reason):
            raise ValueError("Recovery policy review retry differs from immutable history")
        return existing
    row = SituationRecoveryPolicyReview(request_id=request.id, reviewer_principal_id=actor.principal_id,
        reviewer_subject=actor.subject, acceptance_reference=payload.acceptance_reference, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "situation.recovery.policy.accepted", actor, row); db.flush()
    return row


def revoke_recovery_policy(db, review_id, payload, actor):
    _start(db)
    review = _row(db, SituationRecoveryPolicyReview, review_id)
    request = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    references = replacement_references(db, request)
    sources = _prelock(db, _bindings(request), replacements=references)
    requested = actor
    actor = _policy_actor(db, actor, REVIEW)
    for source in reference_sources([source for source, _, _ in sources], references):
        for principal in (requested, actor): require_source_access(db, source, principal)
    # Do not require origin freshness, the original peers or material-read
    # permission: emergency revocation remains possible after their loss.
    _row(db, SituationRecoveryPolicyRequest, request.id, lock=True)
    assert_no_inline_secrets({"reason": payload.reason})
    existing = db.scalar(select(SituationRecoveryPolicyRevocation).where(
        SituationRecoveryPolicyRevocation.review_id == review.id))
    if existing:
        if existing.principal_id != actor.principal_id or existing.subject != actor.subject or existing.reason != payload.reason:
            raise ValueError("Recovery policy revocation retry differs from immutable history")
        return existing
    row = SituationRecoveryPolicyRevocation(review_id=review.id, principal_id=actor.principal_id,
        subject=actor.subject, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "situation.recovery.policy.revoked", actor, row); db.flush()
    return row


def recovery_policy_detail(db, request_id, actor):
    request = _row(db, SituationRecoveryPolicyRequest, request_id)
    if not actor.permits("alerts.read"):
        raise PermissionError("Recovery policy history requires initiating alerts.read")
    current = _actor(db, actor, "alerts.read", human_only=False)
    policy_reference_scope(db, request, actor, current)
    review = db.scalar(select(SituationRecoveryPolicyReview).where(SituationRecoveryPolicyReview.request_id == request.id))
    revocation = db.scalar(select(SituationRecoveryPolicyRevocation).where(
        SituationRecoveryPolicyRevocation.review_id == review.id)) if review else None
    return {"request": request, "review": review, "revocation": revocation}


def _members(db, situation, actor):
    rows = list(db.execute(select(SituationAlert, Alert).outerjoin(Alert, Alert.id == SituationAlert.alert_id)
        .where(SituationAlert.situation_id == situation.id).order_by(SituationAlert.id)
        .limit(MAX_MEMBERS + 1).execution_options(populate_existing=True)).all())
    if not rows or len(rows) > MAX_MEMBERS or any(alert is None for _, alert in rows):
        raise ValueError("Recovery evidence requires a complete available bounded Situation membership set")
    require_situation_access(db, actor, situation.id)
    for _, alert in rows:
        require_alert_access(db, actor, alert.id)
    return rows


def _member_pins(rows, *, proof_version=1):
    values = [{"membership_id": membership.id, "alert_id": alert.id, "dedup_key": alert.dedup_key,
        "event_type": alert.event_type, "entity_type": alert.entity_type, "entity_id": alert.entity_id,
        "status": alert.status.value, "first_seen": as_utc(alert.first_seen).isoformat(),
        "last_seen": as_utc(alert.last_seen).isoformat(), "occurrence_count": alert.occurrence_count}
        for membership, alert in rows]
    if proof_version == 2:
        for item, (_, alert) in zip(values, rows, strict=True):
            item["source_retirement_id"] = alert.source_retirement_id
    return values


def _stable_quiet(db, source, source_request, state, policy, *, after=None):
    """No duplicate counting or bridging active/unknown/conflicting evidence.

Typed provenance is rechecked for every counted sample, not only the latest.
The evidence establishes observed recovery, not continuous physical truth.
"""
    reset = db.scalar(select(CollectorConditionReceipt.observed_at).where(
        CollectorConditionReceipt.source_id == source.id,
        CollectorConditionReceipt.observed_at <= state.observed_at,
        or_(CollectorConditionReceipt.disposition == "conflict",
            (CollectorConditionReceipt.disposition == "accepted") & (CollectorConditionReceipt.verdict != "quiet")))
        .order_by(CollectorConditionReceipt.observed_at.desc()).limit(1))
    query = select(CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id,
        CollectorConditionReceipt.disposition == "accepted", CollectorConditionReceipt.verdict == "quiet",
        CollectorConditionReceipt.observed_at <= state.observed_at)
    if reset is not None:
        query = query.where(CollectorConditionReceipt.observed_at > reset)
    if after is not None:
        query = query.where(CollectorConditionReceipt.observed_at > after)
    receipts = list(db.scalars(query.order_by(CollectorConditionReceipt.observed_at.desc(), CollectorConditionReceipt.id)
        .limit(MAX_QUIET_RECEIPTS + 1)).all())
    if len(receipts) > MAX_QUIET_RECEIPTS:
        raise ValueError("Recovery quiet window exceeds exhaustive receipt bound")
    if len(receipts) < policy.min_quiet_samples:
        raise ValueError("Recovery quiet window has insufficient distinct accepted samples")
    # A large polling gap resets the observed stable segment. Historical
    # samples before the gap cannot manufacture a sustained quiet duration.
    segment = [receipts[0]]
    for receipt in receipts[1:]:
        gap = (as_utc(segment[-1].observed_at) - as_utc(receipt.observed_at)).total_seconds()
        if gap > policy.max_sample_gap_seconds:
            break
        if gap <= 0:
            raise ValueError("Recovery quiet samples must have strictly ordered distinct clocks")
        segment.append(receipt)
    if len(segment) < policy.min_quiet_samples or (
        as_utc(segment[0].observed_at) - as_utc(segment[-1].observed_at)).total_seconds() < policy.min_quiet_seconds:
        raise ValueError("Recovery quiet window does not meet reviewed duration and gap criteria")
    for receipt in segment:
        snapshot, _ = _origin(db, source, receipt, nowait=True)
        if canonical(snapshot) != canonical(source_request.snapshot):
            raise ValueError("Recovery quiet window contains an unqualified source origin")
    return segment


def situation_recovery_evidence(db, situation_id, policy_review_id, actor, *, _before_parent=None, _action_floor=None):
    _start(db)
    review = _row(db, SituationRecoveryPolicyReview, policy_review_id)
    policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    if policy.proof_version == 2:
        from .replacement_recovery_evidence import replacement_recovery_evidence
        return replacement_recovery_evidence(db, situation_id, policy, review, actor,
            _before_parent=_before_parent, _action_floor=_action_floor)
    if _action_floor is not None:
        raise ValueError("Action-relative sampling requires explicit replacement recovery v2")
    situation = _row(db, Situation, situation_id)
    situation_identity = (situation.correlation_key, situation.correlation_version,
        situation.primary_entity_type, situation.primary_entity_id)
    sources = _prelock(db, _bindings(policy))
    requested_actor = actor
    if not requested_actor.permits("alerts.read"):
        raise PermissionError("Recovery evidence requires the caller's alerts.read authority")
    actor = _actor(db, actor, "alerts.read", human_only=False)
    _members(db, situation, requested_actor)
    rows = _members(db, situation, actor)
    initial = _member_pins(rows)
    blockers = []
    if as_utc(policy.expires_at) <= utcnow():
        blockers.append("recovery_policy_expired")
    if db.scalar(select(SituationRecoveryPolicyRevocation.id).where(
        SituationRecoveryPolicyRevocation.review_id == review.id)):
        blockers.append("recovery_policy_revoked")
    for person_id, subject, permission in (
        (policy.author_principal_id, policy.author_subject, MANAGE),
        (review.reviewer_principal_id, review.reviewer_subject, REVIEW)):
        try:
            peer = _human(db, person_id, subject, permission, material_access_required=True)
            for source, _, _ in sources:
                require_source_access(db, source, peer)
        except (LookupError, PermissionError, HTTPException):
            blockers.append("recovery_policy_peer_authority_unavailable")
    by_key = {source.dedup_key: (source, request, accepted) for source, request, accepted in sources}
    coverage = True
    grouped = {}
    for membership, alert in rows:
        bound = by_key.get(alert.dedup_key)
        if bound is None:
            coverage = False
            blockers.append("uncovered_or_unsupported_alert_source")
            continue
        source, request, accepted = bound
        definition = source.context["definition"]
        if (alert.event_type, alert.entity_type, alert.entity_id) != (
            definition["event_type"], source.entity_type, source.entity_id):
            coverage = False
            blockers.append("alert_source_identity_mismatch")
            continue
        if alert.status != AlertStatus.RESOLVED:
            blockers.append("correlated_alert_not_resolved")
        grouped.setdefault(source.id, []).append(alert)
    evidence = []
    deadline = as_utc(policy.expires_at)
    for source, request, accepted in sources:
        # Validate unused bindings too: a reusable policy must not conceal a
        # revoked required source simply because this incident omits it.
        require_source_access(db, source, actor)
        require_source_access(db, source, requested_actor)
        try:
            source, snapshot, _ = _accepted_source(db, source, request, accepted, actor, policy)
            deadline = min(deadline, as_utc(request.expires_at))
            if snapshot["worker_auth_method"] == "bearer+verified_proxy_mtls":
                worker = _row(db, CollectorWorker, snapshot["pins"]["worker"]["id"])
                deadline = min(deadline, as_utc(worker.mtls_not_after))
            if source.id not in grouped:
                continue
            state = db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == source.dedup_key)
                .execution_options(populate_existing=True))
            if state is None or state.latest_alert_id is None:
                raise ValueError("Recovery source has no current Alert episode")
            quiet = source_quiet_evidence(db, source.id, accepted.id, state.latest_alert_id, actor, nonblocking_origin=True)
            if not quiet.qualified_quiet:
                blockers.extend(quiet.blockers)
                continue
            segment = _stable_quiet(db, source, request, state, policy)
            at = as_utc(segment[0].observed_at)
            deadline = min(deadline, at + timedelta(seconds=policy.max_age_seconds))
            member_evidence = []
            for member in grouped[source.id]:
                active = db.scalar(select(CollectorConditionReceipt).where(
                    CollectorConditionReceipt.source_id == source.id, CollectorConditionReceipt.alert_id == member.id,
                    CollectorConditionReceipt.disposition == "accepted", CollectorConditionReceipt.verdict == "active")
                    .order_by(CollectorConditionReceipt.observed_at.desc()).limit(1))
                if active is None or as_utc(active.observed_at) >= at or as_utc(member.last_seen) >= at:
                    raise ValueError("Every historical Alert member requires an earlier accepted active episode")
                active_snapshot, _ = _origin(db, source, active, nowait=True)
                if canonical(active_snapshot) != canonical(request.snapshot):
                    raise ValueError("Historical Alert active evidence is not qualified for this exact origin")
                member_evidence.append({"alert_id": member.id, "active_receipt_id": active.id})
            evidence.append({"source_id": source.id, "qualification_review_id": accepted.id,
                "qualification_request_id": request.id, "condition_revision": state.revision,
                "current_alert_id": state.latest_alert_id, "quiet_receipt_id": quiet.receipt_id,
                "quiet_admission_id": segment[0].admission_id, "quiet_observed_at": at.isoformat(),
                "quiet_window_start": as_utc(segment[-1].observed_at).isoformat(),
                "quiet_sample_receipt_ids": [receipt.id for receipt in segment], "members": member_evidence})
        except (LookupError, PermissionError, ValueError, HTTPException):
            # Never return Collector implementation or hidden resource details
            # through the ordinary alert-reader evidence endpoint.
            blockers.append("source_recovery_evidence_unavailable")
    # A reviewed closure may lock/check its related governed actions here,
    # using NOWAIT, before the final parent mutex. Ordinary reads do not.
    if _before_parent is not None:
        _before_parent()
    # Parent LAST. New members, counters or access can change during its wait.
    # Never acquire a newly discovered source chain while holding this lock.
    situation = _row(db, Situation, situation.id, lock=True)
    final = _member_pins(_members(db, situation, actor))
    _members(db, situation, requested_actor)
    if (canonical(initial) != canonical(final) or situation.alert_count != len(final)
        or situation_identity != (situation.correlation_key, situation.correlation_version,
            situation.primary_entity_type, situation.primary_entity_id)):
        coverage = False
        blockers.append("situation_membership_or_alert_state_changed")
    now = utcnow()
    if now >= deadline:
        blockers.append("recovery_evidence_expired_during_transaction")
    if len(evidence) != len(grouped):
        blockers.append("incomplete_source_recovery_evidence")
    qualified = coverage and not blockers
    return SituationRecoveryEvidenceRead(situation_id=situation.id, policy_review_id=review.id,
        evaluated_at=now, evidence_environment=policy.evidence_environment,
        qualified_recovery=qualified, production_qualified=qualified and policy.evidence_environment == "production",
        covers_situation=coverage, member_count=len(final), blockers=sorted(set(blockers)), membership=final,
        source_evidence=evidence, valid_until=deadline if qualified else None)
