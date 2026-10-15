"""Version 2 recovery: actual new quiet samples cover explicitly retired history."""
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select

from ..config import get_settings
from ..models import (Alert, AlertConditionState, AlertStatus, CollectorConditionReceipt,
    CollectorSourceQualificationRequest, CollectorSourceQualificationReview,
    CollectorWorker, Situation, SituationRecoveryPolicyRevocation, utcnow)
from ..situation_recovery_schemas import SituationRecoveryEvidenceRead
from .alert_conditions import as_utc
from .authorization_scope import require_alert_access
from .collector_conditions import canonical
from .replacement_recovery import (replacement_references, reference_sources, require_replacement_scope, current_replacement)
from .source_qualifications import _actor, _human, _origin, _row, require_source_access, MANAGE
from .source_replacements import historical_source_receipt
from .source_retirements import admitted_source_clock


def _quiet_state(db, source, request, policy, *actors):
    state = db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == source.dedup_key)
        .with_for_update(nowait=True).execution_options(populate_existing=True))
    identity = source.context["definition"]["event_type"], source.entity_type, source.entity_id, None
    if (state is None or state.state != "quiet" or state.observed_at is None
        or (state.event_type, state.entity_type, state.entity_id, state.source_rule_id) != identity):
        raise ValueError("Replacement recovery requires exact current known quiet state")
    at = as_utc(state.observed_at)
    age = min(policy.max_age_seconds, source.context["definition"]["max_age_seconds"])
    if at > utcnow() or utcnow()-at > timedelta(seconds=age) or at < admitted_source_clock(db, source):
        raise ValueError("Replacement recovery current quiet watermark is stale, future or behind accepted ingress")
    if state.latest_alert_id is not None:
        alert = _row(db, Alert, state.latest_alert_id)
        for actor in actors: require_alert_access(db, actor, alert.id)
        if alert.dedup_key != source.dedup_key or alert.status != AlertStatus.RESOLVED or alert.source_retirement_id:
            raise ValueError("Replacement recovery current Alert does not agree with known quiet")
    receipt = db.scalar(select(CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id,
        CollectorConditionReceipt.condition_state_id == state.id, CollectorConditionReceipt.observed_at == state.observed_at,
        CollectorConditionReceipt.alert_id == state.latest_alert_id if state.latest_alert_id else CollectorConditionReceipt.alert_id.is_(None),
        CollectorConditionReceipt.disposition == "accepted", CollectorConditionReceipt.verdict == "quiet")
        .order_by(CollectorConditionReceipt.id).limit(1))
    if receipt is None:
        raise ValueError("Replacement recovery has no exact accepted current quiet receipt")
    snapshot, _ = _origin(db, source, receipt, nowait=True)
    if canonical(snapshot) != canonical(request.snapshot):
        raise ValueError("Replacement recovery current quiet provenance is not qualified")
    return state, receipt


def _active_member(db, source, request, accepted, member, *, replacement=None):
    receipt = db.scalar(select(CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id,
        CollectorConditionReceipt.alert_id == member.id, CollectorConditionReceipt.disposition == "accepted",
        CollectorConditionReceipt.verdict == "active").order_by(CollectorConditionReceipt.observed_at.desc()).limit(1))
    if receipt is None:
        raise ValueError("Recovery member has no retained exact accepted active receipt")
    if replacement is None:
        if member.status != AlertStatus.RESOLVED or member.source_retirement_id:
            raise ValueError("Direct recovery member is not measured resolved")
        snapshot, _ = _origin(db, source, receipt, nowait=True)
        if canonical(snapshot) != canonical(request.snapshot):
            raise ValueError("Direct recovery member active origin is unqualified")
    else:
        retirement = replacement.retirement
        if member.status == AlertStatus.RESOLVED:
            if member.source_retirement_id is not None:
                raise ValueError("Measured resolved member cannot manufacture supersession")
        elif member.id != retirement.superseded_alert_id or member.source_retirement_id != retirement.id:
            raise ValueError("Active retired member lacks exact permanent supersession provenance")
        historical_source_receipt(db, source, request, receipt)
        cutoff = as_utc(datetime.fromisoformat(retirement.old_state_snapshot["admitted_through_at"]))
        if max(as_utc(receipt.observed_at), as_utc(member.last_seen)) > cutoff:
            raise ValueError("Historical active member exceeds its permanent retirement watermark")
    return receipt, {"alert_id": member.id, "active_receipt_id": receipt.id, "active_source_id": source.id,
        "qualification_request_id": request.id, "qualification_review_id": accepted.id,
        "retirement_id": replacement.retirement.id if replacement else None,
        "replacement_request_id": replacement.request.id if replacement else None,
        "replacement_review_id": replacement.review.id if replacement else None}


def replacement_recovery_evidence(db, situation_id, policy, review, requested, *, _before_parent=None, _action_floor=None):
    from .situation_recovery import REVIEW, _bindings, _prelock, _accepted_source, _members, _member_pins, _stable_quiet
    if not get_settings().enable_replacement_recovery:
        raise PermissionError("Replacement-aware recovery is disabled pending compatible rollout")
    if not requested.permits("alerts.read"):
        raise PermissionError("Replacement recovery requires initiating alerts.read")
    references = replacement_references(db, policy)
    sources = _prelock(db, _bindings(policy), replacements=references)
    actor = _actor(db, requested, "alerts.read", human_only=False, nowait=True)
    all_sources = reference_sources([source for source, _, _ in sources], references)
    for source in all_sources:
        for principal in (requested, actor): require_source_access(db, source, principal)
    require_replacement_scope(db, references, requested, actor)
    situation = _row(db, Situation, situation_id)
    identity = (situation.correlation_key, situation.correlation_version, situation.primary_entity_type, situation.primary_entity_id)
    _members(db, situation, requested)
    rows = _members(db, situation, actor)
    initial = _member_pins(rows, proof_version=2)
    blockers, coverage = [], True
    deadline = as_utc(policy.expires_at)
    if deadline <= utcnow(): blockers.append("recovery_policy_expired")
    if db.scalar(select(SituationRecoveryPolicyRevocation.id).where(SituationRecoveryPolicyRevocation.review_id == review.id)):
        blockers.append("recovery_policy_revoked")
    for person_id, subject, permission in ((policy.author_principal_id, policy.author_subject, MANAGE),
        (review.reviewer_principal_id, review.reviewer_subject, REVIEW)):
        try:
            peer = _human(db, person_id, subject, permission, material_access_required=True, nowait=True)
            if not peer.permits("alerts.read"):
                raise PermissionError("Replacement recovery peer lost current read authority")
            for source in all_sources: require_source_access(db, source, peer)
            require_replacement_scope(db, references, peer)
        except (PermissionError, LookupError, HTTPException):
            blockers.append("recovery_policy_peer_authority_unavailable")
    valid_mappings = {}
    for item in references:
        try:
            deadline = min(deadline, current_replacement(db, item, policy))
            valid_mappings[item.old.id] = item
        except (PermissionError, LookupError, ValueError, HTTPException):
            blockers.append("replacement_mapping_unavailable")
    by_key = {source.dedup_key: (source, request, accepted, None) for source, request, accepted in sources}
    for item in references:
        accepted = _row(db, CollectorSourceQualificationReview, item.request.old_qualification_review_id)
        request = _row(db, CollectorSourceQualificationRequest, accepted.request_id)
        by_key[item.old.dedup_key] = item.old, request, accepted, item
    grouped = {}
    for _membership, member in rows:
        binding = by_key.get(member.dedup_key)
        if binding is None:
            coverage = False; blockers.append("uncovered_or_unsupported_alert_source"); continue
        source, request, accepted, replacement = binding
        if (member.event_type, member.entity_type, member.entity_id) != (
            source.context["definition"]["event_type"], source.entity_type, source.entity_id):
            coverage = False; blockers.append("alert_source_identity_mismatch"); continue
        target_id = replacement.target.id if replacement else source.id
        grouped.setdefault(target_id, []).append((member, source, request, accepted, replacement))
    prepared = []
    for source, request, accepted in sources:
        try:
            _, snapshot, _ = _accepted_source(db, source, request, accepted, actor, policy, nonblocking_authority=True)
            deadline = min(deadline, as_utc(request.expires_at))
            if snapshot["worker_auth_method"] == "bearer+verified_proxy_mtls":
                deadline = min(deadline, as_utc(_row(db, CollectorWorker, snapshot["pins"]["worker"]["id"]).mtls_not_after))
            if source.id not in grouped: continue
            state, quiet = _quiet_state(db, source, request, policy, requested, actor)
            prepared.append((source, request, accepted, state, quiet))
        except (PermissionError, LookupError, ValueError, HTTPException):
            blockers.append("source_recovery_evidence_unavailable")
    # All current origin/state chains precede related-action locks; parent is
    # still last. The owned closure callback can only strengthen this floor.
    action_floor = _action_floor() if _action_floor is not None else None
    evidence = []
    for source, request, accepted, state, quiet in prepared:
        try:
            floor, members = as_utc(action_floor) if action_floor is not None else None, []
            for member, active_source, active_request, active_review, replacement in grouped[source.id]:
                if replacement is not None and replacement.old.id not in valid_mappings:
                    raise ValueError("Recovery member mapping is unavailable")
                if replacement is None and state.latest_alert_id is None:
                    raise ValueError("Direct member requires an actual current Alert episode")
                active, pin = _active_member(db, active_source, active_request, active_review, member, replacement=replacement)
                at = max(as_utc(active.observed_at), as_utc(member.last_seen))
                if replacement is not None:
                    at = max(at, as_utc(datetime.fromisoformat(replacement.retirement.old_state_snapshot["admitted_through_at"])))
                floor = max(floor, at) if floor else at
                members.append(pin)
            segment = _stable_quiet(db, source, request, state, policy, after=floor)
            latest = as_utc(segment[0].observed_at)
            deadline = min(deadline, latest+timedelta(seconds=policy.max_age_seconds))
            evidence.append({"source_id": source.id, "qualification_review_id": accepted.id,
                "qualification_request_id": request.id, "condition_revision": state.revision,
                "current_alert_id": state.latest_alert_id, "quiet_receipt_id": quiet.id,
                "quiet_admission_id": quiet.admission_id, "quiet_observed_at": latest.isoformat(),
                "quiet_window_start": as_utc(segment[-1].observed_at).isoformat(),
                "quiet_after": floor.isoformat(),
                "quiet_sample_receipt_ids": [item.id for item in segment], "members": members})
        except (PermissionError, LookupError, ValueError, HTTPException):
            blockers.append("source_recovery_evidence_unavailable")
    if _before_parent is not None: _before_parent()
    situation = _row(db, Situation, situation.id, lock=True)
    final = _member_pins(_members(db, situation, actor), proof_version=2)
    _members(db, situation, requested)
    if (canonical(initial) != canonical(final) or situation.alert_count != len(final)
        or identity != (situation.correlation_key, situation.correlation_version, situation.primary_entity_type, situation.primary_entity_id)):
        coverage = False; blockers.append("situation_membership_or_alert_state_changed")
    now = utcnow()
    if now >= deadline: blockers.append("recovery_evidence_expired_during_transaction")
    if len(evidence) != len(grouped): blockers.append("incomplete_source_recovery_evidence")
    qualified = coverage and not blockers
    return SituationRecoveryEvidenceRead(situation_id=situation.id, policy_review_id=review.id, evaluated_at=now,
        evidence_environment=policy.evidence_environment, qualified_recovery=qualified,
        production_qualified=qualified and policy.evidence_environment == "production", covers_situation=coverage,
        member_count=len(final), blockers=sorted(set(blockers)), membership=final, source_evidence=evidence,
        valid_until=deadline if qualified else None, verification_basis="peer_reviewed_source_recovery/v2")
