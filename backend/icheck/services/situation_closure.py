"""Reviewed, leased closure with atomic historical receipts, not physical truth.

PostgreSQL's namespace advisory fence serializes short closure transactions
against proposal writers (including the native trigger). It is never retained
for a lease's lifetime. Source origin locks precede NOWAIT action locks and
the Situation parent; ownership is last. No external operation is performed.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy import cast, func, select, text

from ..agent_schemas import AgentChangeContract
from ..config import get_settings
from ..database import session_namespace
from ..models import (AgentActionProposal, AgentToolRegistration, AlertStatus, ArtifactVersion,
    ArtifactVersionStatus, CollectorConditionSource, GovernedChangeEvidence, GovernedChangePlan,
    Investigation, InvestigationToolCall, Situation, SituationClosureAttempt, SituationClosureGrant,
    SituationClosureOwnership, SituationClosureReceipt, SituationClosureRequest, SituationClosureRevocation,
    SituationRecoveryPolicyRequest, SituationRecoveryPolicyReview, SituationRecoveryPolicyRevocation, utcnow)
from ..situation_closure_schemas import SituationClosureClaimRead, SituationClosureReceiptRead
from .alert_conditions import as_utc
from .audit import record_audit_event
from .collector_conditions import canonical
from .collectors import assert_no_inline_secrets
from .situation_recovery import (_accepted_source, _bindings, _members, _prelock, MANAGE, REVIEW,
    situation_recovery_evidence)
from .source_qualifications import _actor, _human, _row, _start, require_source_access
from .situation_closure_reads import historical_identity_scope, historical_action_scope, read_receipt
from .situations import append_situation_event

QUALIFY = "situations.closure.qualify"
EXECUTE = "situations.close"
MAX_ACTIONS = 256
MAX_PROOF_BYTES = 2 * 1024 * 1024


class ClosureLeasePending(ValueError):
    """The owned call may retry, but cannot recover or replace a live token."""

    def __init__(self, call_id, lease):
        from ..agent_schemas import AgentRuntimeOwnedClosureWait
        super().__init__("Closure call retains an unexpired lease whose response was lost; resume after expiry or explicit release")
        self.wait = AgentRuntimeOwnedClosureWait(tool_call_id=call_id, request_id=lease.request_id,
            attempt_id=lease.attempt_id, epoch=lease.epoch)


def closure_action_barrier(db, *, writer=False):
    """Try, never wait behind a writer holding a lower-level Plan/Device lock."""
    if db.get_bind().dialect.name == "postgresql":
        namespace = session_namespace(db)
        if namespace is None:
            raise ValueError("Situation closure/action fence requires a selected namespace")
        tenant, region = namespace
        function = "pg_try_advisory_xact_lock_shared" if writer else "pg_try_advisory_xact_lock"
        if not db.scalar(text(f"SELECT {function}(hashtextextended(:key,0))"),
            {"key": f"icheck.closure/v1/{tenant}/{region}"}):
            raise ValueError("Situation closure/action fence is busy; retry the full transaction")


def _start_closure(db):
    _start(db)
    closure_action_barrier(db)


def _authority(db, requested, permission, *, material=False, human=False, nowait=False):
    if not requested.permits(permission) or not requested.permits("alerts.read"):
        raise PermissionError("Closure requires both the caller's and current persisted authority")
    current = _actor(db, requested, permission, human_only=human, material_access_required=material, nowait=nowait)
    if not current.permits("alerts.read") or (material and not requested.permits("capabilities.read")):
        raise PermissionError("Closure requires current alerts.read and reviewed material access")
    return current


def _policy_scope(db, policy, *actors):
    from .situation_recovery import policy_reference_scope
    policy_reference_scope(db, policy, *actors)


def _compatible_policy(policy, proof_version=1):
    if (proof_version != policy.proof_version or proof_version not in {1, 2}
        or (proof_version == 2) != bool(policy.replacement_bindings)):
        raise ValueError("Replacement recovery proof cannot authorize v1 closure before compatible proof and runtime rollout")
    if proof_version == 2 and (not get_settings().enable_replacement_recovery
        or not get_settings().enable_replacement_situation_closure):
        raise PermissionError("Replacement-aware Situation closure is disabled pending compatible rollout")


def _policy_prefix(db, policy):
    from .replacement_recovery import replacement_references
    references = replacement_references(db, policy)
    return _prelock(db, _bindings(policy), replacements=references), references


def _version_snapshot(db, version_id):
    version = _row(db, ArtifactVersion, version_id, lock=True, nowait=True)
    spec = version.definition.get("spec", {})
    if version.status != ArtifactVersionStatus.PUBLISHED or spec.get("read_only") is not False or not version.content_hash:
        raise ValueError("Closure remediation basis requires an exact published change Tool")
    contract = AgentChangeContract.model_validate(spec.get("change_contract"))
    if not contract.semantic_expectations or not contract.authorization_target_paths:
        raise ValueError("Closure remediation requires structured state expectations and explicit targets")
    # Full material, not a digest that could conceal mutable implementation.
    return {"id": version.id, "content_hash": version.content_hash, "definition": version.definition,
        "implementation": version.implementation, "tests": version.tests,
        "validation_report": version.validation_report, "created_by": version.created_by,
        "published_by": version.published_by}


def _audit(db, event, actor, row, **details):
    record_audit_event(db, event_type=event, actor_type="user", actor_id=actor.subject,
        entity_type="situation_closure", entity_id=row.id,
        details={**details, "remediation_causality_proven": False, "physical_truth_automatically_verified": False})


def qualify_closure(db, payload, requested):
    _start_closure(db)
    review = _row(db, SituationRecoveryPolicyReview, payload.policy_review_id)
    policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    _compatible_policy(policy, payload.proof_version)
    sources, references = _policy_prefix(db, policy)
    actor = _authority(db, requested, QUALIFY, material=True, human=True, nowait=bool(references))
    _policy_scope(db, policy, actor, requested)
    author = _human(db, policy.author_principal_id, policy.author_subject, MANAGE, material_access_required=True, nowait=bool(references))
    policy_peer = _human(db, review.reviewer_principal_id, review.reviewer_subject, REVIEW, material_access_required=True, nowait=bool(references))
    _policy_scope(db, policy, author, policy_peer)
    if policy.proof_version == 2 and not all(person.permits("alerts.read") for person in (author, policy_peer)):
        raise PermissionError("Replacement closure policy peers require current read authority")
    if actor.principal_id == author.principal_id or actor.subject == author.subject:
        raise PermissionError("Closure authority requires a human independent of the recovery-policy author")
    for source, proposal, accepted in sources:
        _accepted_source(db, source, proposal, accepted, actor, policy, nonblocking_authority=bool(references))
        for peer in (author, policy_peer):
            require_source_access(db, source, peer)
    from .replacement_recovery import current_replacement
    for reference in references:
        current_replacement(db, reference, policy)
    _row(db, SituationRecoveryPolicyRequest, policy.id, lock=True, nowait=True)
    if db.scalar(select(SituationRecoveryPolicyRevocation.id).where(SituationRecoveryPolicyRevocation.review_id == review.id)):
        raise ValueError("Revoked recovery policy cannot receive closure authority")
    if not utcnow() < as_utc(payload.expires_at) <= as_utc(policy.expires_at):
        raise ValueError("Closure authority must be future and may not outlive reviewed recovery criteria")
    snapshot = _version_snapshot(db, payload.remediation_version_id) if payload.remediation_version_id else None
    if snapshot and actor.subject in {snapshot["created_by"], snapshot["published_by"]}:
        raise PermissionError("Remediation semantics require an independent human closure reviewer")
    assert_no_inline_secrets({"reason": payload.reason, "acceptance_reference": payload.acceptance_reference})
    values = payload.model_dump(exclude={"independent_closure_authority_validated", "expires_at"})
    values.update(reviewer_principal_id=actor.principal_id, reviewer_subject=actor.subject,
        remediation_snapshot=snapshot)
    existing = db.scalar(select(SituationClosureGrant).where(SituationClosureGrant.request_key == payload.request_key))
    if existing:
        if (as_utc(existing.expires_at) != as_utc(payload.expires_at)
            or any(canonical(getattr(existing, key)) != canonical(value) for key, value in values.items())):
            raise ValueError("Closure grant request key differs from immutable authority history")
        if db.scalar(select(SituationClosureRevocation.id).where(SituationClosureRevocation.grant_id == existing.id)):
            raise ValueError("Revoked closure authority cannot be reactivated by retry")
        return existing
    row = SituationClosureGrant(**values, expires_at=as_utc(payload.expires_at))
    db.add(row); db.flush()
    _audit(db, "situation.closure.authority.qualified", actor, row); db.flush()
    return row


def revoke_closure(db, grant_id, payload, requested):
    _start_closure(db)
    grant = _row(db, SituationClosureGrant, grant_id)
    review = _row(db, SituationRecoveryPolicyReview, grant.policy_review_id)
    policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    actor = _authority(db, requested, QUALIFY, human=True)
    _policy_scope(db, policy, actor, requested)
    _row(db, SituationClosureGrant, grant.id, lock=True, nowait=True)
    assert_no_inline_secrets({"reason": payload.reason})
    existing = db.scalar(select(SituationClosureRevocation).where(SituationClosureRevocation.grant_id == grant.id))
    if existing:
        if (existing.principal_id, existing.subject, existing.reason) != (actor.principal_id, actor.subject, payload.reason):
            raise ValueError("Closure revocation retry differs from immutable history")
        return existing
    row = SituationClosureRevocation(grant_id=grant.id, principal_id=actor.principal_id,
        subject=actor.subject, reason=payload.reason)
    db.add(row); db.flush()
    _audit(db, "situation.closure.authority.revoked", actor, row); db.flush()
    return row


def _identity(situation, members):
    return {"situation_id": situation.id, "correlation_key": situation.correlation_key,
        "correlation_version": situation.correlation_version, "primary_entity_type": situation.primary_entity_type,
        "primary_entity_id": situation.primary_entity_id,
        "members": [{key: member[key] for key in ("membership_id", "alert_id", "dedup_key", "event_type",
            "entity_type", "entity_id", "first_seen")} for member in members]}


def _current_identity(db, situation, actor):
    from .situation_recovery import _member_pins
    return _identity(situation, _member_pins(_members(db, situation, actor)))


def _grant(db, grant_id, requested):
    grant = _row(db, SituationClosureGrant, grant_id, lock=True, nowait=True)
    review = _row(db, SituationRecoveryPolicyReview, grant.policy_review_id)
    policy = _row(db, SituationRecoveryPolicyRequest, review.request_id)
    if grant.proof_version == 2:
        _policy_prefix(db, policy)
    actor = _authority(db, requested, EXECUTE, nowait=grant.proof_version == 2)
    if actor.principal_id == grant.reviewer_principal_id or actor.subject == grant.reviewer_subject:
        raise PermissionError("Closure executor must be independent of its authority reviewer")
    if not get_settings().enable_reviewed_situation_closure:
        raise PermissionError("Reviewed Situation closure is disabled on this host")
    if as_utc(grant.expires_at) <= utcnow() or db.scalar(select(SituationClosureRevocation.id).where(
        SituationClosureRevocation.grant_id == grant.id)):
        raise ValueError("Closure authority expired or was revoked")
    _compatible_policy(policy, grant.proof_version)
    _policy_prefix(db, policy)
    if get_settings().environment.strip().lower() == "production" and policy.evidence_environment != "production":
        raise PermissionError("Controlled or lab evidence cannot authorize production closure")
    peer = _human(db, grant.reviewer_principal_id, grant.reviewer_subject, QUALIFY, material_access_required=True, nowait=grant.proof_version == 2)
    _policy_scope(db, policy, actor, requested, peer)
    if grant.remediation_version_id and canonical(_version_snapshot(db, grant.remediation_version_id)) != canonical(grant.remediation_snapshot):
        raise ValueError("Closure remediation Tool material changed after independent qualification")
    return grant, policy, actor


def _related_actions(db, situation_id, policy):
    """Exhaustive bounded indexed lookup; unknown targets are conservatively related.

The advisory fence prevents insertion/status races. NOWAIT row locks prevent
the exact structured proof being edited while we inspect it. No Plan lock is
ever acquired after the Situation parent. Unlinked, same-target actions count.
"""
    from .action_targets import assert_action_target_pins, related_action_ids
    from .remediation_quality import outcome_evidence
    from .replacement_recovery import replacement_references, reference_sources
    sources = reference_sources([_row(db, CollectorConditionSource, b.source_id) for b in _bindings(policy)],
        replacement_references(db, policy))
    devices = {s.context["deployment"].get("scope_device_id") for s in sources}
    devices |= {s.entity_id for s in sources if s.entity_type == "device"}
    devices.discard(None)
    sites = {s.context["deployment"].get("scope_site") for s in sources}; sites.discard(None)
    proposal_ids = related_action_ids(db, situation_id, devices, sites, limit=MAX_ACTIONS + 1)
    if len(proposal_ids) > MAX_ACTIONS:
        raise ValueError("Closure related-action proof exceeds its exhaustive related/unknown action bound")
    result = []; budget = {"remaining": MAX_PROOF_BYTES}; related_rollbacks = set()
    for proposal_id in proposal_ids:
        candidate = _row(db, AgentActionProposal, proposal_id)
        investigation = _row(db, Investigation, candidate.investigation_id)
        plan = db.scalar(select(GovernedChangePlan).where(GovernedChangePlan.action_proposal_id == candidate.id)
            .execution_options(populate_existing=True))
        tool = _row(db, AgentToolRegistration, candidate.tool_id)
        frozen = plan.tool_contract_snapshot if plan else tool.change_contract or {}
        bindings = frozen.get("authorization_target_paths", {})
        targets = [(kind, plan.target_snapshot.get(path) if plan else None)
            for path, kind in bindings.items()]
        assert_action_target_pins(db, candidate, investigation, plan)
        proposal = _row(db, AgentActionProposal, candidate.id, lock=True, nowait=True)
        _row(db, Investigation, investigation.id, lock=True, nowait=True)
        _row(db, AgentToolRegistration, tool.id, lock=True, nowait=True)
        if proposal.status == "rejected" and proposal.execution_started_at is None and proposal.tool_call_id is None:
            result.append({"proposal_id": proposal.id, "outcome": "rejected_without_execution"}); continue
        if proposal.rollback_of_change_plan_id:
            # The primary outcome below must include this exact separately
            # approved rollback and restoration; an orphan is never terminal.
            parent = _row(db, GovernedChangePlan, proposal.rollback_of_change_plan_id, lock=True, nowait=True)
            if not db.scalar(select(AgentActionProposal.id).where(AgentActionProposal.id == parent.action_proposal_id)):
                raise ValueError("Closure has an orphaned rollback action")
            if proposal.status not in {"succeeded", "failed"} or proposal.tool_call_id is None:
                raise ValueError("Closure has an unfinished or ambiguous related rollback")
            parent_bindings = parent.tool_contract_snapshot.get("authorization_target_paths", {})
            _action_peer_authority(db, proposal, investigation, parent_bindings,
                [(kind, parent.target_snapshot.get(path)) for path, kind in parent_bindings.items()])
            related_rollbacks.add(proposal.tool_call_id)
            continue
        if proposal.status not in {"succeeded", "failed"} or proposal.tool_call_id is None or plan is None:
            raise ValueError("Closure has an unfinished or ambiguous related action")
        _action_peer_authority(db, proposal, investigation, bindings, targets, nowait=policy.proof_version == 2)
        plan = _row(db, GovernedChangePlan, plan.id, lock=True, nowait=True)
        evidence = list(db.scalars(select(GovernedChangeEvidence).where(GovernedChangeEvidence.change_plan_id == plan.id)
            .order_by(GovernedChangeEvidence.id).limit(6).with_for_update(nowait=True)).all())
        if len(evidence) > 5:
            raise ValueError("Closure action proof exceeds its governed stage bound")
        call_ids = {proposal.tool_call_id, *(item.tool_call_id for item in evidence)}
        for call_id in sorted(call_ids):
            _row(db, InvestigationToolCall, call_id, lock=True, nowait=True)
        call = _row(db, InvestigationToolCall, proposal.tool_call_id)
        _row(db, ArtifactVersion, call.artifact_version_id, lock=True, nowait=True)
        proof = outcome_evidence(db, call, version_id=call.artifact_version_id,
            content_hash=call.artifact_content_hash, now=utcnow(), budget=budget)
        terminal = proof["outcome"] == "verified" and proof["verification_basis"] == "structured_state_transition"
        restored = proof["outcome"] == "rolled_back" and proof.get("rollback_verification", {}).get("passed") is True
        if not terminal and not restored:
            raise ValueError("Closure requires structured verified execution or structured restoration, not status labels")
        result.append({"proposal_id": proposal.id, "investigation_id": investigation.id,
            "situation_id": investigation.situation_id, "version_id": call.artifact_version_id, **proof})
    proven_rollbacks = {stage["tool_call_id"] for proof in result for stage in proof.get("stages", [])
        if stage["stage"] == "rollback"}
    if not related_rollbacks.issubset(proven_rollbacks):
        raise ValueError("Closure related rollback lacks its primary structured restoration proof")
    return result


def _action_peer_authority(db, proposal, investigation, bindings, targets, *, nowait=False):
    from ..models import (ChangePreapprovalAuthorization, ChangePreapprovalExecutionGrant,
        ChangeRollbackAuthorization, ChangeRollbackExecutionGrant)
    from .authorization_scope import has_global_scope, require_device_access, require_site_access
    if (not proposal.approved_by_principal_id or not proposal.requested_by_principal_id
        or proposal.requested_by_principal_id != investigation.requested_by_principal_id
        or proposal.requested_by != investigation.created_by):
        raise ValueError("Closure related action lacks exact persisted requester and independent approval identities")
    authorization_model = ChangeRollbackAuthorization if proposal.rollback_of_change_plan_id else ChangePreapprovalAuthorization
    proposal_column = authorization_model.rollback_proposal_id if proposal.rollback_of_change_plan_id else authorization_model.action_proposal_id
    authorization = db.scalar(select(authorization_model).where(proposal_column == proposal.id))
    if authorization:
        grant_model = ChangeRollbackExecutionGrant if proposal.rollback_of_change_plan_id else ChangePreapprovalExecutionGrant
        grant = _row(db, grant_model, authorization.grant_id, lock=True, nowait=True)
        subject = grant.granted_by
    else:
        subject = proposal.approved_by
    peer = _human(db, proposal.approved_by_principal_id, subject, "changes.approve", nowait=nowait)
    if authorization and not peer.permits("changes.policy.manage"):
        raise PermissionError("Closure reviewed-execution peer no longer has policy review authority")
    requester = _human(db, proposal.requested_by_principal_id, proposal.requested_by, "alerts.read", human_only=False, nowait=nowait)
    if peer.principal_id == requester.principal_id or peer.subject == requester.subject:
        raise ValueError("Closure related action was not independently reviewed")
    if not bindings and not all(has_global_scope(person) for person in (peer, requester)):
        raise PermissionError("Closure related action has unbounded current approval scope")
    for person in (peer, requester):
        for kind, value in targets:
            if kind == "device_id": require_device_access(db, person, value)
            elif kind == "site": require_site_access(person, value)
            else: raise ValueError("Closure related action has an unsupported target binding")


def _proof(db, situation_id, grant, policy, requested):
    _compatible_policy(policy, grant.proof_version)
    actions = []
    def action_floor():
        actions.extend(_related_actions(db, situation_id, policy))
        clocks = [as_utc(datetime.fromisoformat(action["finished_at"])) for action in actions if action.get("finished_at")]
        return max(clocks) if clocks else None
    report = situation_recovery_evidence(db, situation_id, grant.policy_review_id, requested,
        **({"_action_floor": action_floor} if grant.proof_version == 2 else
            {"_before_parent": lambda: actions.extend(_related_actions(db, situation_id, policy))}))
    if not report.qualified_recovery:
        raise ValueError("Closure recovery evidence is not qualified: " + ", ".join(report.blockers))
    actor = _authority(db, requested, EXECUTE, nowait=grant.proof_version == 2)
    for action in actions:
        historical_action_scope(db, action, actor, requested)
    quiet_start = min(as_utc(datetime.fromisoformat(item["quiet_window_start"]))
        for item in report.source_evidence)
    for action in actions:
        if action.get("finished_at") and as_utc(datetime.fromisoformat(action["finished_at"])) >= quiet_start:
            raise ValueError("Reviewed quiet window must begin strictly after every related action's terminal verification")
    if grant.proof_basis == "verified_remediation" and not any(
        action.get("version_id") == grant.remediation_version_id and action.get("situation_id") == situation_id
        and action.get("outcome") == "verified" and action.get("semantic_verification", {}).get("passed") is True
        for action in actions):
        raise ValueError("Closure requires an exact Situation-bound, independently reviewed structured remediation outcome")
    return report, actions


def _owned_request(db, request_id, requested):
    request = _row(db, SituationClosureRequest, request_id)
    grant = _row(db, SituationClosureGrant, request.grant_id)
    if grant.proof_version == 2 and _receipt(db, request.id) is None:
        review = _row(db, SituationRecoveryPolicyReview, grant.policy_review_id)
        _policy_prefix(db, _row(db, SituationRecoveryPolicyRequest, review.request_id))
    actor = _authority(db, requested, "alerts.read", nowait=grant.proof_version == 2)
    if (request.owner_principal_id, request.owner_subject) != (actor.principal_id, actor.subject):
        raise PermissionError("Only the exact closure request owner can use its lease")
    situation = _row(db, Situation, request.situation_id)
    _members(db, situation, actor); _members(db, situation, requested)
    historical_identity_scope(db, request.membership_identity, request.situation_id, actor, requested)
    return request, actor


def _receipt(db, request_id):
    return db.scalar(select(SituationClosureReceipt).where(SituationClosureReceipt.request_id == request_id))


def claim_closure(db, situation_id, payload, requested):
    _start_closure(db)
    # Recover a committed response before re-evaluating revoked/expired
    # execution authority. This is a historical read, not a new mutation.
    existing = db.scalar(select(SituationClosureRequest).where(SituationClosureRequest.situation_id == situation_id,
        SituationClosureRequest.request_key == payload.request_key))
    if existing:
        _owned_request(db, existing.id, requested)
        if payload.proof_version != _row(db, SituationClosureGrant, existing.grant_id).proof_version:
            raise ValueError("Closure request proof version differs from immutable intent")
        if (existing.grant_id, existing.reason, existing.lease_seconds) != (payload.grant_id, payload.reason, payload.lease_seconds):
            raise ValueError("Closure request key was reused with different immutable intent")
        receipt = _receipt(db, existing.id)
        if receipt:
            return SituationClosureClaimRead(request_id=existing.id, epoch=receipt.epoch,
                state="committed", receipt=read_receipt(db, receipt, requested))
    grant, policy, actor = _grant(db, payload.grant_id, requested)
    if payload.proof_version != grant.proof_version:
        raise ValueError("Closure claim requires the exact explicit grant proof version")
    if payload.lease_seconds > grant.max_lease_seconds:
        raise ValueError("Closure lease exceeds independent authority")
    report, _ = _proof(db, situation_id, grant, policy, requested)
    situation = _row(db, Situation, situation_id)
    identity = _identity(situation, report.membership)
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == situation_id)
        .with_for_update().execution_options(populate_existing=True))
    epoch = ownership.epoch if ownership else 0
    if ownership and ownership.state == "claimed" and as_utc(ownership.lease_expires_at) > utcnow():
        if existing and ownership.request_id == existing.id:
            attempt = db.scalar(select(SituationClosureAttempt).where(SituationClosureAttempt.ownership_id == ownership.id,
                SituationClosureAttempt.epoch == epoch))
            return SituationClosureClaimRead(request_id=existing.id, attempt_id=attempt.id, epoch=epoch,
                state="claimed", lease_expires_at=as_utc(ownership.lease_expires_at))
        raise ValueError("Situation closure has an unexpired owner")
    if payload.expected_epoch != epoch:
        raise ValueError("Closure ownership epoch changed; reload before claiming")
    receipts = list(db.scalars(select(SituationClosureReceipt).where(SituationClosureReceipt.situation_id == situation_id)
        .order_by(SituationClosureReceipt.committed_at.desc()).limit(257)).all())
    if len(receipts) > 256 or any(canonical(row.proof["membership_identity"]) == canonical(identity) for row in receipts):
        raise ValueError("This exact Situation membership is already independently closed or history exceeds its bound")
    if existing and canonical(existing.membership_identity) != canonical(identity):
        raise ValueError("Closure request cannot migrate to a changed Situation membership")
    deadline = min(as_utc(grant.expires_at), as_utc(report.valid_until), utcnow() + timedelta(seconds=payload.lease_seconds))
    if deadline <= utcnow() + timedelta(seconds=4):
        raise ValueError("Recovery proof is too close to expiry for a closure lease")
    if existing is None:
        existing = SituationClosureRequest(situation_id=situation_id, grant_id=grant.id,
            request_key=payload.request_key, owner_principal_id=actor.principal_id, owner_subject=actor.subject,
            reason=payload.reason, lease_seconds=payload.lease_seconds, membership_identity=identity)
        assert_no_inline_secrets({"reason": payload.reason})
        db.add(existing); db.flush()
    if ownership is None:
        ownership = SituationClosureOwnership(situation_id=situation_id, request_id=existing.id,
            epoch=1, state="claimed", lease_expires_at=deadline, updated_at=utcnow())
        db.add(ownership)
    else:
        ownership.request_id = existing.id; ownership.epoch += 1
        ownership.state = "claimed"; ownership.lease_expires_at = deadline; ownership.updated_at = utcnow()
    db.flush()
    token = secrets.token_urlsafe(32)
    attempt = SituationClosureAttempt(request_id=existing.id, ownership_id=ownership.id, epoch=ownership.epoch,
        token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=deadline, created_at=utcnow())
    db.add(attempt); db.flush()
    _audit(db, "situation.closure.claimed", actor, attempt, situation_id=situation_id, epoch=attempt.epoch); db.flush()
    return SituationClosureClaimRead(request_id=existing.id, attempt_id=attempt.id, epoch=attempt.epoch,
        state="claimed", lease_expires_at=deadline, lease_token=token)


def _attempt(db, request, payload):
    attempt = _row(db, SituationClosureAttempt, payload.attempt_id)
    if attempt.request_id != request.id or not secrets.compare_digest(attempt.token_hash,
        hashlib.sha256(payload.lease_token.encode()).hexdigest()):
        raise PermissionError("Closure lease proof is invalid")
    return attempt


def finalize_closure(db, request_id, payload, requested):
    _start_closure(db)
    request, _ = _owned_request(db, request_id, requested)
    attempt = _attempt(db, request, payload)
    receipt = _receipt(db, request.id)
    if receipt:
        if receipt.attempt_id != attempt.id:
            raise ValueError("Only the committed attempt can recover its exact closure receipt")
        return read_receipt(db, receipt, requested)
    grant, policy, actor = _grant(db, request.grant_id, requested)
    report, actions = _proof(db, request.situation_id, grant, policy, requested)
    situation = _row(db, Situation, request.situation_id)
    if canonical(request.membership_identity) != canonical(_identity(situation, report.membership)):
        raise ValueError("Closure request membership changed after its claim")
    ownership = _row(db, SituationClosureOwnership, attempt.ownership_id, lock=True)
    now = utcnow()
    if (ownership.situation_id != request.situation_id or ownership.request_id != request.id
        or ownership.state != "claimed" or ownership.epoch != attempt.epoch
        or as_utc(ownership.lease_expires_at) != as_utc(attempt.expires_at)
        or now >= min(as_utc(attempt.expires_at), as_utc(grant.expires_at), as_utc(report.valid_until))):
        raise ValueError("Closure lease expired, was released or lost its ownership epoch")
    proof = {"contract": f"icheck.reviewed-situation-closure/v{grant.proof_version}", "proof_basis": grant.proof_basis,
        "membership_identity": request.membership_identity, "recovery": report.model_dump(mode="json"),
        "related_actions": actions, "owner_principal_id": actor.principal_id, "owner_subject": actor.subject,
        "reviewer_principal_id": grant.reviewer_principal_id, "reviewer_subject": grant.reviewer_subject,
        "acceptance_reference": grant.acceptance_reference, "evidence_environment": policy.evidence_environment,
        "remediation_causality_proven": False, "physical_truth_automatically_verified": False}
    if len(canonical(proof).encode()) > MAX_PROOF_BYTES:
        raise ValueError("Closure proof exceeds its durable receipt byte bound")
    # No physical action and no Alert/status-clock forgery. Qualified closure
    # gets its own event, atomically with the durable ledger and ownership.
    situation.status = "resolved"; situation.resolved_at = now; situation.resolved_by = actor.subject; situation.updated_at = now
    event = append_situation_event(db, situation, event_type="situation.closure.reviewed", actor=actor.subject,
        details={"request_id": request.id, "attempt_id": attempt.id, "grant_id": grant.id,
            "epoch": attempt.epoch, "proof_basis": grant.proof_basis, "independent_closure": True,
            "remediation_causality_proven": False, "physical_truth_automatically_verified": False})
    receipt = SituationClosureReceipt(situation_id=situation.id, grant_id=grant.id, request_id=request.id,
        attempt_id=attempt.id, ownership_id=ownership.id, epoch=attempt.epoch,
        event_id=event.id, event_sequence=event.sequence, proof=proof, committed_at=now)
    db.add(receipt); db.flush()
    ownership.state = "committed"; ownership.updated_at = now
    _audit(db, "situation.closure.committed", actor, receipt, situation_id=situation.id, epoch=attempt.epoch)
    db.flush()
    return read_receipt(db, receipt, requested)


def release_closure(db, request_id, payload, requested):
    _start_closure(db)
    request, actor = _owned_request(db, request_id, requested)
    attempt = _attempt(db, request, payload)
    # Parent before ownership, even on release. No source proof is needed to
    # give up authority after expiry/revocation or host-gate disablement.
    _row(db, Situation, request.situation_id, lock=True)
    ownership = _row(db, SituationClosureOwnership, attempt.ownership_id, lock=True)
    if (ownership.request_id, ownership.epoch) != (request.id, attempt.epoch) or ownership.state == "committed":
        raise ValueError("Cannot release a committed or superseded closure attempt")
    if ownership.state == "claimed":
        ownership.state = "released"; ownership.updated_at = utcnow()
        _audit(db, "situation.closure.released", actor, attempt, epoch=attempt.epoch); db.flush()
    return SituationClosureClaimRead(request_id=request.id, attempt_id=attempt.id, epoch=attempt.epoch, state="released")


def closure_history(db, situation_id, requested, *, limit=50):
    actor = _authority(db, requested, "alerts.read")
    situation = _row(db, Situation, situation_id)
    _members(db, situation, actor); _members(db, situation, requested)
    rows = list(db.scalars(select(SituationClosureReceipt).where(SituationClosureReceipt.situation_id == situation_id)
        .order_by(SituationClosureReceipt.committed_at.desc(), SituationClosureReceipt.id).limit(limit + 1)).all())
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == situation_id))
    return {"situation_id": situation_id, "receipts": [read_receipt(db, r, requested) for r in rows[:limit]],
        "truncated": len(rows) > limit, "ownership_epoch": ownership.epoch if ownership else 0,
        "ownership_state": ownership.state if ownership else None, "grants_future_authority": False}


def closure_request_detail(db, request_id, requested):
    """Historical read/recovery only. Never finalizes or regenerates a token."""
    request, actor = _owned_request(db, request_id, requested)
    receipt = _receipt(db, request.id)
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == request.situation_id))
    attempt = db.scalar(select(SituationClosureAttempt).where(SituationClosureAttempt.request_id == request.id)
        .order_by(SituationClosureAttempt.epoch.desc()).limit(1))
    state = "committed" if receipt else (ownership.state if ownership and ownership.request_id == request.id else "superseded")
    return {"request_id": request.id, "situation_id": request.situation_id, "grant_id": request.grant_id,
        "reason": request.reason, "lease_seconds": request.lease_seconds, "state": state,
        "attempt_id": attempt.id if attempt else None, "epoch": attempt.epoch if attempt else 0,
        "lease_expires_at": as_utc(attempt.expires_at) if attempt else None,
        "receipt": read_receipt(db, receipt, requested) if receipt else None,
        "historical_read_only": True, "grants_future_authority": False}


def closure_workspace(db, situation_id, requested, *, limit=50, grant_id=None, policy_request_id=None):
    """Scoped bounded discovery, not current authority or a qualifying proof."""
    from fastapi import HTTPException
    from ..situation_closure_schemas import SituationClosureGrantRead
    actor = _authority(db, requested, "alerts.read")
    situation = _row(db, Situation, situation_id)
    members = _members(db, situation, actor); _members(db, situation, requested)
    dedup_keys = {alert.dedup_key for _, alert in members}
    exact_grant = _row(db, SituationClosureGrant, grant_id) if grant_id else None
    if exact_grant:
        exact_review = _row(db, SituationRecoveryPolicyReview, exact_grant.policy_review_id)
        if policy_request_id and policy_request_id != exact_review.request_id:
            raise ValueError("Exact grant and policy request do not match")
        policy_request_id = exact_review.request_id
    candidates = [_row(db, SituationRecoveryPolicyRequest, policy_request_id)] if policy_request_id else list(db.scalars(
        select(SituationRecoveryPolicyRequest).order_by(SituationRecoveryPolicyRequest.created_at.desc(), SituationRecoveryPolicyRequest.id)
        .limit(201)).all())
    policies = []; review_ids = []; scan_truncated = len(candidates) > 200
    now = utcnow()
    for policy in candidates[:200]:
        try:
            _policy_scope(db, policy, actor, requested)
            sources = [_row(db, CollectorConditionSource, binding.source_id) for binding in _bindings(policy)]
            from .replacement_recovery import replacement_references
            historical_sources = [ref.old for ref in replacement_references(db, policy)] if policy.proof_version == 2 else []
            if not dedup_keys.issubset({source.dedup_key for source in sources + historical_sources}):
                continue
        except (LookupError, ValueError, PermissionError, HTTPException):
            continue
        review = db.scalar(select(SituationRecoveryPolicyReview).where(SituationRecoveryPolicyReview.request_id == policy.id))
        revoked = db.scalar(select(SituationRecoveryPolicyRevocation).where(SituationRecoveryPolicyRevocation.review_id == review.id)) if review else None
        policies.append({"id": policy.id, "name": policy.name, "review_id": review.id if review else None,
            "author_principal_id": policy.author_principal_id, "author_subject": policy.author_subject,
            "evidence_environment": policy.evidence_environment, "source_count": len(sources),
            "proof_version": policy.proof_version, "replacement_count": len(historical_sources),
            "expires_at": as_utc(policy.expires_at), "revoked": bool(revoked),
            "record_state": "revoked" if revoked else "expired" if as_utc(policy.expires_at) <= now else "accepted" if review else "pending",
            "candidate_only": True, "current_authority_validated": False})
        if review: review_ids.append(review.id)
    if policy_request_id and not policies:
        raise LookupError("Exact recovery policy is unavailable for this Situation and caller scope")
    grant_query = select(SituationClosureGrant).where(SituationClosureGrant.policy_review_id.in_(review_ids))
    if grant_id: grant_query = grant_query.where(SituationClosureGrant.id == grant_id)
    grant_rows = list(db.scalars(grant_query
        .order_by(SituationClosureGrant.created_at.desc(), SituationClosureGrant.id).limit(limit + 1)).all()) if review_ids else []
    policies_by_review = {policy["review_id"]: policy for policy in policies if policy["review_id"]}
    grants = []
    for grant in grant_rows[:limit]:
        revoked = db.scalar(select(SituationClosureRevocation).where(SituationClosureRevocation.grant_id == grant.id))
        policy = policies_by_review[grant.policy_review_id]
        grants.append({"grant": SituationClosureGrantRead.model_validate(grant), "policy_request_id": policy["id"],
            "evidence_environment": policy["evidence_environment"],
            "record_state": "revoked" if revoked else "expired" if as_utc(grant.expires_at) <= now else
                "policy_unavailable" if policy["record_state"] != "accepted" else "accepted",
            "revocation": {"subject": revoked.subject, "reason": revoked.reason, "created_at": as_utc(revoked.created_at)} if revoked else None,
            "current_authority_validated": False})
    # Metadata projection avoids loading up to 100 full 2 MiB proofs for a
    # page. Exact owner recovery remains a separate, bounded full-receipt read.
    r = SituationClosureReceipt
    if db.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import JSONB
        count_array = lambda value: func.jsonb_array_length(cast(value, JSONB))
    else:
        count_array = func.json_array_length
    summary_rows = list(db.execute(select(r.id, r.request_id, r.grant_id, r.epoch, r.committed_at,
        r.proof["proof_basis"].as_string().label("basis"), r.proof["owner_subject"].as_string().label("owner"),
        r.proof["reviewer_subject"].as_string().label("reviewer"), r.proof["evidence_environment"].as_string().label("environment"),
        r.proof["recovery"]["member_count"].as_integer().label("members"),
        count_array(r.proof["recovery"]["source_evidence"]).label("sources"), count_array(r.proof["related_actions"]).label("actions"))
        .where(r.situation_id == situation_id).order_by(r.committed_at.desc(), r.id).limit(limit + 1)).mappings())
    summaries = [{"id": row["id"], "request_id": row["request_id"], "grant_id": row["grant_id"], "epoch": row["epoch"],
        "committed_at": as_utc(row["committed_at"]), "historical": True, "summary_only": True, "grants_future_authority": False,
        "remediation_causality_proven": False, "physical_truth_automatically_verified": False,
        "proof_summary": {"proof_basis": row["basis"], "owner_subject": row["owner"], "reviewer_subject": row["reviewer"],
            "evidence_environment": row["environment"], "member_count": row["members"], "source_count": row["sources"],
            "related_action_count": row["actions"]}} for row in summary_rows[:limit]]
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == situation_id))
    request = _row(db, SituationClosureRequest, ownership.request_id) if ownership else None
    history = {"situation_id": situation_id, "receipts": summaries, "truncated": len(summary_rows) > limit,
        "ownership_epoch": ownership.epoch if ownership else 0, "grants_future_authority": False}
    latest_identity = db.scalar(select(r.proof["membership_identity"]).where(r.situation_id == situation_id)
        .order_by(r.committed_at.desc(), r.id).limit(1))
    identity = _current_identity(db, situation, actor)
    human = actor.principal_type == "user" and requested.principal_type == "user"
    return {"situation_id": situation_id, "evaluated_at": now, "host_enabled": get_settings().enable_reviewed_situation_closure,
        "replacement_closure_enabled": get_settings().enable_replacement_recovery and get_settings().enable_replacement_situation_closure,
        "authorizes_new_closure": False, "current_authority_validated": False,
        "can_review_authority": human and all(person.permits(QUALIFY) and person.permits("capabilities.read") for person in (actor, requested)),
        "can_revoke_authority": human and all(person.permits(QUALIFY) for person in (actor, requested)),
        "can_request_closure": all(person.permits(EXECUTE) for person in (actor, requested)),
        "policies": policies, "grants": grants, "catalog_truncated": scan_truncated or len(grant_rows) > limit,
        "policy_scan_limit": 200, "grant_limit": limit, "history": history,
        "ownership": {"request_id": request.id, "owner_principal_id": request.owner_principal_id,
            "owner_subject": request.owner_subject, "state": ownership.state, "epoch": ownership.epoch,
            "lease_expires_at": as_utc(ownership.lease_expires_at)} if request else None,
        "latest_receipt_matches_current_membership": bool(latest_identity and canonical(latest_identity) == canonical(identity))}


def guard_new_situation_action(db, investigation):
    closure_action_barrier(db, writer=True)
    if investigation.situation_id is None:
        return
    if session_namespace(db) is None and db.get_bind().dialect.name == "sqlite":
        # Old development-only execution helpers did not bind a namespace.
        # Preserve them only when there is no reviewed ownership at all;
        # qualified closure never inherits their implicit authority.
        if not db.scalar(select(SituationClosureOwnership.id).where(
            SituationClosureOwnership.situation_id == investigation.situation_id,
            SituationClosureOwnership.tenant_id == investigation.tenant_id,
            SituationClosureOwnership.region_id == investigation.region_id).limit(1)):
            return
    # NOWAIT avoids reversal with a caller already holding a Plan/Device.
    situation = _row(db, Situation, investigation.situation_id, lock=True, nowait=True)
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == situation.id))
    if ownership and ownership.state == "claimed" and as_utc(ownership.lease_expires_at) > utcnow():
        raise ValueError("Situation has an active reviewed-closure owner; release or wait before a new action")
    if not db.scalar(select(SituationClosureReceipt.id).where(SituationClosureReceipt.situation_id == situation.id).limit(1)):
        return
    from .agent_authorization import investigation_principal
    principal = investigation_principal(investigation)
    rows = _members(db, situation, principal)
    if all(alert.status == AlertStatus.RESOLVED or alert.source_retirement_id is not None for _, alert in rows):
        identity = _current_identity(db, situation, principal)
        receipts = list(db.scalars(select(SituationClosureReceipt).where(SituationClosureReceipt.situation_id == situation.id)
            .order_by(SituationClosureReceipt.committed_at.desc()).limit(257)).all())
        if len(receipts) > 256 or any(canonical(receipt.proof["membership_identity"]) == canonical(identity) for receipt in receipts):
            raise ValueError("Unchanged independently closed Situation cannot propose a new physical action")


def close_from_agent_call(db, investigation, call, arguments):
    """Runtime-owned request identity and lease token; neither is model input.

Each claim/finalization is independently durable. After a commit gap, first
recover the receipt. After a lost claim response, never mint a second live
lease: the same call may resume after expiry or an owner releases the claim.
"""
    from ..situation_closure_schemas import SituationClosureClaimCreate, SituationClosureFinalize, SituationClosureToolInput
    from .agent_authorization import investigation_principal
    payload = SituationClosureToolInput.model_validate(arguments)
    requested = investigation_principal(investigation)
    if investigation.situation_id != payload.situation_id:
        raise PermissionError("Closure Tool investigation is bound to a different Situation")
    if call.investigation_id != investigation.id or call.arguments != arguments:
        raise PermissionError("Closure Tool call does not bind this exact runtime invocation")
    _start_closure(db)
    request_key = "agent-closure:" + call.id
    previous = db.scalar(select(SituationClosureRequest).where(SituationClosureRequest.situation_id == payload.situation_id,
        SituationClosureRequest.request_key == request_key))
    if previous:
        _owned_request(db, previous.id, requested)
        if (previous.grant_id, previous.reason) != (payload.grant_id, payload.reason):
            raise ValueError("Closure runtime journal and durable request intent disagree")
        if payload.proof_version != _row(db, SituationClosureGrant, previous.grant_id).proof_version:
            raise ValueError("Closure runtime proof version differs from immutable intent")
        receipt = _receipt(db, previous.id)
        if receipt:
            result = read_receipt(db, receipt, requested)
            db.commit()
            return result
    grant = _row(db, SituationClosureGrant, payload.grant_id)
    ownership = db.scalar(select(SituationClosureOwnership).where(SituationClosureOwnership.situation_id == payload.situation_id))
    lease = claim_closure(db, payload.situation_id, SituationClosureClaimCreate(grant_id=grant.id,
        request_key=request_key, reason=payload.reason, lease_seconds=min(30, grant.max_lease_seconds),
        expected_epoch=ownership.epoch if ownership else 0, proof_version=payload.proof_version), requested)
    db.commit()
    if lease.receipt:
        return lease.receipt
    if lease.lease_token is None:
        raise ClosureLeasePending(call.id, lease)
    result = finalize_closure(db, lease.request_id, SituationClosureFinalize(
        attempt_id=lease.attempt_id, lease_token=lease.lease_token), requested)
    db.commit()
    return result
