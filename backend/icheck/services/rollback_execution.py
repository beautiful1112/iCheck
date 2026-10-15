"""Distinct restoration qualification and a sealed one-slot failed-parent budget."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta

from sqlalchemy import exists, select

from ..agent_schemas import RollbackExecutionGrantCreate, RollbackQualificationSettings
from ..config import get_settings
from ..database import require_locking_transaction
from ..models import (AgentActionProposal, AgentExecution, AgentExecutionStatus, Alert,
    ChangePreapprovalBudgetClaim, ChangePreapprovalExecutionGrant, ChangeRollbackAuthorization, ChangeRollbackExecutionGrant,
    ChangeRollbackGrantRevocation, GovernedChangeEvidence, GovernedChangePlan, Investigation, InvestigationToolCall, utcnow)
from .audit import record_audit_event
from .authorization_scope import scope_contains
from .capability_quality import as_utc, digest
from .change_governance import (_assert_plan_current, _latest_evidence,
    assert_change_stage_tool_current, change_stage_arguments, frozen_alert_identity_hash)
from .change_preapprovals import (_material, _set_path, _validate_settings,
    get_preapproval, IDEMPOTENCY_PLACEHOLDER)
from .change_verification import action_for_plan, validate_stage_call
from .control_plane_auth import PrincipalContext
from .preapproval_execution import (_reviewer, _row, assert_authorization_receipt,
    require_policy_device_scope)
from .remediation_quality import outcome_evidence, MAX_OUTCOME_EVIDENCE_BYTES


def _primary_context(db, primary_grant_id, *, actor=None):
    primary = _row(db, ChangePreapprovalExecutionGrant, primary_grant_id, shared=True)
    policy = get_preapproval(db, primary.policy_id, shared_lock=True)
    if actor is not None:
        require_policy_device_scope(db, policy, actor)
    if (policy.status != "reviewed" or policy.review_sha256 != primary.policy_review_sha256
        or policy.review_sha256 != digest(_material(policy))
        or as_utc(primary.expires_at) <= as_utc(utcnow())):
        raise PermissionError("Primary authority is expired, revoked or changed")
    _reviewer(db, policy, primary.granted_by_principal_id, primary.granted_by)
    _reviewer(db, policy, policy.reviewed_by_principal_id, policy.reviewed_by)
    device, contract = _validate_settings(db, policy, version_id=policy.tool_artifact_version_id,
        content_hash=policy.tool_content_hash, now=as_utc(utcnow()))
    if device.site != policy.target_site or contract.rollback_check is None:
        raise ValueError("Rollback qualification requires the current exact target and structured restoration contract")
    # Do not require healthy primary-purpose quality here: recovery does not
    # turn a failed purpose into success, nor erase its prior valid admission.
    return primary, policy, contract


def _settings(grant):
    return RollbackQualificationSettings.model_validate(grant.settings_snapshot)


def _dependencies(plan):
    return {key: plan.tool_contract_snapshot[key] for key in (
        "action_tool", "steps", "rollback", "risk_policy", "requires_maintenance_window")}


def restoration_evidence(db, primary_grant_id, settings, *, actor=None, exclude_parent=None):
    _, policy, contract = _primary_context(db, primary_grant_id, actor=actor)
    now = as_utc(utcnow())
    horizon = min(settings.window_minutes * 60, settings.max_sample_age_seconds)
    cutoff = now - timedelta(seconds=horizon)
    attempted = exists(select(AgentActionProposal.id).where(
        AgentActionProposal.rollback_of_change_plan_id == GovernedChangePlan.id,
        AgentActionProposal.execution_started_at.is_not(None),
        AgentActionProposal.tenant_id == policy.tenant_id,
        AgentActionProposal.region_id == policy.region_id).correlate(GovernedChangePlan))
    query = select(GovernedChangePlan).join(AgentActionProposal,
        AgentActionProposal.id == GovernedChangePlan.action_proposal_id).join(
        InvestigationToolCall, InvestigationToolCall.id == AgentActionProposal.tool_call_id).where(
        GovernedChangePlan.tenant_id == policy.tenant_id, GovernedChangePlan.region_id == policy.region_id,
        AgentActionProposal.tenant_id == policy.tenant_id, AgentActionProposal.region_id == policy.region_id,
        InvestigationToolCall.tenant_id == policy.tenant_id, InvestigationToolCall.region_id == policy.region_id,
        InvestigationToolCall.artifact_version_id == policy.tool_artifact_version_id,
        GovernedChangePlan.updated_at >= cutoff, attempted,
    )
    for path, kind in contract.authorization_target_paths.items():
        if kind == "device_id":
            query = query.where(GovernedChangePlan.target_snapshot[path].as_string() == policy.target_device_id)
    if exclude_parent is not None:
        query = query.where(GovernedChangePlan.id != exclude_parent)
    plans = list(db.scalars(query.order_by(GovernedChangePlan.updated_at.desc(), GovernedChangePlan.id)
        .limit(201).with_for_update(read=True, of=GovernedChangePlan)
        .execution_options(populate_existing=True)).all())
    manifest, actors, purposes = [], set(), set()
    dependencies = None
    budget = {"remaining": MAX_OUTCOME_EVIDENCE_BYTES}
    invalid = len(plans) > 200
    for plan in plans[:200]:
        proposal = _row(db, AgentActionProposal, plan.action_proposal_id, shared=True)
        call = _row(db, InvestigationToolCall, proposal.tool_call_id, shared=True)
        rollback_rows = list(db.scalars(select(AgentActionProposal).where(
            AgentActionProposal.rollback_of_change_plan_id == plan.id,
            AgentActionProposal.tenant_id == policy.tenant_id,
            AgentActionProposal.region_id == policy.region_id,
            AgentActionProposal.execution_started_at.is_not(None))
            .with_for_update(read=True).execution_options(populate_existing=True).limit(2)).all())
        for evidence in plan.evidence:
            _row(db, InvestigationToolCall, evidence.tool_call_id, shared=True)
        try:
            proof = outcome_evidence(db, call, version_id=policy.tool_artifact_version_id,
                content_hash=policy.tool_content_hash, now=now, budget=budget)
            arguments = copy.deepcopy(proposal.arguments)
            _set_path(arguments, contract.idempotency_key_argument_path, IDEMPOTENCY_PLACEHOLDER)
            if arguments != policy.arguments_template:
                continue
            current_dependencies = _dependencies(plan)
            if dependencies is not None and dependencies != current_dependencies:
                raise ValueError("Restoration history mixes different Tool implementations")
            dependencies = current_dependencies
            if len(rollback_rows) != 1:
                raise ValueError("Restoration has ambiguous or missing execution")
            rollback = rollback_rows[0]
            if (proof["outcome"] != "rolled_back" or proof.get("rollback_verification_basis") != "structured_state_restoration"
                or proof.get("rollback_verification", {}).get("passed") is not True
                or not cutoff <= as_utc(rollback.execution_finished_at) <= now):
                raise ValueError("Restoration is failed, unverified or stale")
            # Automatic recovery may invalidate the circuit but may not
            # bootstrap independent qualification by feeding itself successes.
            if rollback.approved_by == "system.rollback_preapproval":
                continue
            purpose = (proof["idempotency_sha256"], proof["target_sha256"])
            if purpose in purposes:
                continue
            purposes.add(purpose)
            manifest.append(proof)
            for source in (proposal, rollback):
                actors.update(value for value in (source.requested_by, source.approved_by,
                    source.requested_by_principal_id, source.approved_by_principal_id) if value)
        except (LookupError, PermissionError, TypeError, KeyError, ValueError):
            invalid = True
    material = {"contract": "icheck.restoration-qualification/v1", "primary_grant_id": primary_grant_id,
        "settings": settings.model_dump(), "dependencies": dependencies, "manifest": manifest, "invalid": invalid}
    ready = not invalid and len(manifest) >= settings.min_samples
    valid_until = min(as_utc(datetime.fromisoformat(item["finished_at"]))
        + timedelta(seconds=horizon) for item in manifest) if manifest else None
    return {"ready": ready, "required_samples": settings.min_samples, "matching_samples": len(manifest),
        "evidence_sha256": digest(material), "valid_until": valid_until,
        "reason": None if ready else "failed_unverified_or_insufficient_restoration", "manifest": manifest,
        "actors": actors, "dependencies": dependencies}


def qualify_rollback(db, primary_grant_id, payload: RollbackExecutionGrantCreate, *, actor):
    require_locking_transaction(db, purpose="Rollback qualification")
    primary = _row(db, ChangePreapprovalExecutionGrant, primary_grant_id, lock=True)
    _, policy, _ = _primary_context(db, primary_grant_id, actor=actor)
    reviewer = _reviewer(db, policy, actor.principal_id, actor.subject)
    if reviewer.subject == policy.created_by or reviewer.principal_id == policy.created_by_principal_id:
        raise PermissionError("The policy author cannot qualify rollback")
    settings = RollbackQualificationSettings.model_validate({key: getattr(payload, key)
        for key in RollbackQualificationSettings.model_fields})
    evidence = restoration_evidence(db, primary_grant_id, settings, actor=actor)
    if not evidence["ready"] or evidence["evidence_sha256"] != payload.expected_evidence_sha256:
        raise ValueError("Restoration evidence changed or is not ready; review it again")
    if reviewer.subject in evidence["actors"] or reviewer.principal_id in evidence["actors"]:
        raise PermissionError("Rollback qualification requires an independent evidence reviewer")
    for sample in evidence["manifest"]:
        source_plan = _row(db, GovernedChangePlan, sample["change_plan_id"])
        _assert_plan_current(db, source_plan, _row(db, AgentActionProposal, source_plan.action_proposal_id))
    if not as_utc(utcnow()) < as_utc(payload.expires_at) <= as_utc(primary.expires_at):
        raise ValueError("Rollback expiry must fit the primary grant expiry")
    from .collectors import assert_no_inline_secrets
    assert_no_inline_secrets({"reference": payload.acceptance_reference}, "rollback acceptance reference")
    existing = db.scalar(select(ChangeRollbackExecutionGrant).where(
        ChangeRollbackExecutionGrant.primary_grant_id == primary_grant_id,
        ChangeRollbackExecutionGrant.tenant_id == policy.tenant_id,
        ChangeRollbackExecutionGrant.region_id == policy.region_id))
    if existing is not None:
        if _revocation(db, existing.id) is not None:
            raise PermissionError("Revoked rollback qualification cannot be renewed; create a newly reviewed primary policy revision")
        if (existing.settings_snapshot != settings.model_dump() or existing.qualification_sha256 != evidence["evidence_sha256"]
            or existing.acceptance_reference != payload.acceptance_reference or as_utc(existing.expires_at) != as_utc(payload.expires_at)
            or existing.granted_by_principal_id != reviewer.principal_id):
            raise ValueError("This primary grant already has a different rollback qualification")
        db.commit(); return existing
    grant = ChangeRollbackExecutionGrant(primary_grant_id=primary.id, settings_snapshot=settings.model_dump(),
        dependency_snapshot=evidence["dependencies"],
        qualification_manifest=evidence["manifest"], qualification_sha256=evidence["evidence_sha256"],
        acceptance_reference=payload.acceptance_reference, granted_by_principal_id=reviewer.principal_id,
        granted_by=reviewer.subject, expires_at=payload.expires_at)
    db.add(grant); db.flush()
    record_audit_event(db, event_type="change.rollback.qualified", actor_type="user", actor_id=actor.subject,
        entity_type="change_rollback_execution_grant", entity_id=grant.id,
        details={"primary_grant_id": primary.id, "evidence_sha256": grant.qualification_sha256, "reason": payload.reason})
    db.commit(); db.refresh(grant); return grant


def revoke_rollback(db, grant_id, *, actor, reason):
    require_locking_transaction(db, purpose="Rollback revocation")
    grant = _row(db, ChangeRollbackExecutionGrant, grant_id, lock=True)
    primary = _row(db, ChangePreapprovalExecutionGrant, grant.primary_grant_id)
    policy = get_preapproval(db, primary.policy_id)
    require_policy_device_scope(db, policy, actor)
    if not actor.permits("changes.policy.manage"):
        raise PermissionError("Rollback revocation requires policy management")
    existing = _revocation(db, grant.id)
    if existing is not None:
        db.commit(); return existing
    revocation = ChangeRollbackGrantRevocation(grant_id=grant.id, revoked_by=actor.subject,
        revoked_by_principal_id=actor.principal_id, reason=reason)
    db.add(revocation); db.flush()
    record_audit_event(db, event_type="change.rollback.revoked", actor_type="user", actor_id=actor.subject,
        entity_type="change_rollback_grant_revocation", entity_id=revocation.id,
        details={"grant_id": grant.id, "reason": reason})
    db.commit(); return revocation


def _revocation(db, grant_id):
    return db.scalar(select(ChangeRollbackGrantRevocation).where(ChangeRollbackGrantRevocation.grant_id == grant_id))


def rollback_authorization(db, proposal):
    return db.scalar(select(ChangeRollbackAuthorization).where(
        ChangeRollbackAuthorization.rollback_proposal_id == proposal.id,
        ChangeRollbackAuthorization.tenant_id == proposal.tenant_id,
        ChangeRollbackAuthorization.region_id == proposal.region_id))


def _failure(db, plan):
    primary_proposal, action = action_for_plan(db, plan, now=utcnow())
    evidence = _latest_evidence(plan).get("postcheck")
    if action.status != "succeeded" or evidence is None or evidence.passed is not False:
        raise ValueError("Automatic rollback requires a succeeded primary action and verified failed post-check")
    evidence = _row(db, GovernedChangeEvidence, evidence.id, shared=True)
    call = _row(db, InvestigationToolCall, evidence.tool_call_id, shared=True)
    passed, summary = validate_stage_call(db, plan, "postcheck", call)
    expected = {"contract": "icheck.change-evidence/v1", "stage": "postcheck", "tool_id": call.tool_id,
        "tool_name": plan.tool_contract_snapshot["steps"]["postcheck"]["tool_name"], "tool_call_id": call.id,
        "arguments_hash": digest(call.arguments), "result_hash": call.result_hash, "passed": passed, "summary": summary}
    if (passed is not False or evidence.result_hash != call.result_hash or evidence.arguments_hash != digest(call.arguments)
        or evidence.tool_id != call.tool_id or evidence.evidence_snapshot != expected
        or not as_utc(call.finished_at) <= as_utc(evidence.created_at) <= as_utc(utcnow())):
        raise ValueError("Rollback failure evidence changed")
    return primary_proposal, {"contract": "icheck.rollback-failure/v1", "primary_proposal_id": primary_proposal.id,
        "approved_plan_hash": plan.approved_plan_hash, "postcheck_call_id": call.id,
        "call_hash": call.call_hash, "result_hash": call.result_hash,
        "finished_at": as_utc(call.finished_at).isoformat()}


def _current_grant(db, grant_id):
    grant = _row(db, ChangeRollbackExecutionGrant, grant_id, shared=True)
    primary, policy, contract = _primary_context(db, grant.primary_grant_id)
    if _revocation(db, grant.id) is not None or as_utc(grant.expires_at) <= as_utc(utcnow()):
        raise PermissionError("Rollback grant is revoked or expired")
    reviewer = _reviewer(db, policy, grant.granted_by_principal_id, grant.granted_by)
    original = {"contract": "icheck.restoration-qualification/v1", "primary_grant_id": grant.primary_grant_id,
        "settings": grant.settings_snapshot, "dependencies": grant.dependency_snapshot,
        "manifest": grant.qualification_manifest, "invalid": False}
    if digest(original) != grant.qualification_sha256:
        raise PermissionError("Rollback qualification history changed")
    return grant, primary, policy, contract, reviewer


def assert_rollback_receipt(db, proposal, plan):
    receipt = rollback_authorization(db, proposal)
    if receipt is None:
        if proposal.approved_by == "system.rollback_preapproval":
            raise ValueError("Reviewed rollback has no immutable authorization receipt")
        return None
    grant = _row(db, ChangeRollbackExecutionGrant, receipt.grant_id)
    material = {"contract": "icheck.restoration-qualification/v1", "primary_grant_id": grant.primary_grant_id,
        "settings": grant.settings_snapshot, "dependencies": grant.dependency_snapshot,
        "manifest": grant.qualification_manifest, "invalid": False}
    original, failure = _failure(db, plan)
    primary_receipt = assert_authorization_receipt(db, original, plan)
    from .agent_approvals import action_plan_hash
    if (digest(material) != grant.qualification_sha256 or _dependencies(plan) != grant.dependency_snapshot
        or primary_receipt is None or primary_receipt.id != receipt.primary_authorization_id
        or primary_receipt.grant_id != grant.primary_grant_id
        or receipt.parent_change_plan_id != plan.id or receipt.action_plan_hash != proposal.plan_hash
        or receipt.failure_snapshot != failure or digest(receipt.evidence_manifest) != receipt.evidence_sha256
        or proposal.rollback_of_change_plan_id != plan.id
        or proposal.tool_id != plan.tool_contract_snapshot["rollback"]["tool_id"]
        or proposal.arguments != change_stage_arguments(plan, "rollback")
        or proposal.plan_hash != action_plan_hash(tool_id=proposal.tool_id, arguments=proposal.arguments, purpose=proposal.purpose)
        or proposal.approved_by != "system.rollback_preapproval"
        or proposal.approved_by_principal_id != grant.granted_by_principal_id
        or proposal.decided_at is None or as_utc(proposal.decided_at) != as_utc(receipt.authorized_at)
        or datetime.fromisoformat(failure["finished_at"]) > as_utc(receipt.authorized_at)
        or not receipt.evidence_manifest or any(item.get("rollback_verification", {}).get("passed") is not True
            for item in receipt.evidence_manifest)):
        raise ValueError("Reviewed rollback authorization bindings changed")
    return receipt


def assert_parent_slot(db, proposal, plan):
    """Caller holds the parent lock until execution-start commits, including human rollback."""
    other = db.scalar(select(AgentActionProposal.id).where(
        AgentActionProposal.rollback_of_change_plan_id == plan.id, AgentActionProposal.id != proposal.id,
        AgentActionProposal.tenant_id == plan.tenant_id, AgentActionProposal.region_id == plan.region_id,
        AgentActionProposal.execution_started_at.is_not(None)).limit(1))
    receipt = db.scalar(select(ChangeRollbackAuthorization).where(
        ChangeRollbackAuthorization.parent_change_plan_id == plan.id,
        ChangeRollbackAuthorization.tenant_id == plan.tenant_id,
        ChangeRollbackAuthorization.region_id == plan.region_id))
    if other is not None or receipt is not None and receipt.rollback_proposal_id != proposal.id:
        raise ValueError("Failed-parent rollback budget is already owned; do not repeat it")


def _admission(db, grant_id, proposal, plan, *, actor):
    grant, primary, policy, contract, reviewer = _current_grant(db, grant_id)
    require_policy_device_scope(db, policy, actor)
    investigation = _row(db, Investigation, plan.investigation_id)
    if not scope_contains(db, actor, investigation.authorization_scope):
        raise PermissionError("Rollback parent is outside the requesting scope")
    original, failure = _failure(db, plan)
    from .agent_approvals import action_plan_hash
    if proposal.plan_hash != action_plan_hash(tool_id=proposal.tool_id, arguments=proposal.arguments, purpose=proposal.purpose):
        raise ValueError("Rollback purpose or arguments no longer match their action hash")
    receipt = assert_authorization_receipt(db, original, plan)
    if (receipt is None or receipt.grant_id != primary.id or plan.status != "rollback_required"
        or plan.risk_class != "low" or original.investigation_id != proposal.investigation_id
        or proposal.rollback_of_change_plan_id != plan.id
        or proposal.tool_id != plan.tool_contract_snapshot["rollback"]["tool_id"]
        or proposal.arguments != change_stage_arguments(plan, "rollback")):
        raise ValueError("Rollback is not the exact failed parent/template owned by the primary grant")
    if reviewer.subject == proposal.requested_by or reviewer.principal_id == proposal.requested_by_principal_id:
        raise PermissionError("Rollback requester cannot be its grant reviewer")
    _assert_plan_current(db, plan, original)
    assert_change_stage_tool_current(db, plan, "rollback")
    assert_change_stage_tool_current(db, plan, "rollback_check")
    settings = _settings(grant)
    age = (as_utc(utcnow()) - datetime.fromisoformat(failure["finished_at"])).total_seconds()
    if not 0 <= age <= settings.max_start_delay_seconds:
        raise PermissionError("Failed post-check is too old for automatic rollback")
    if plan.tool_contract_snapshot.get("requires_maintenance_window", True) and not (
        plan.maintenance_window_start and plan.maintenance_window_end
        and as_utc(plan.maintenance_window_start) <= as_utc(utcnow()) <= as_utc(plan.maintenance_window_end)):
        raise PermissionError("Automatic rollback is outside the parent maintenance window")
    if _dependencies(plan) != grant.dependency_snapshot:
        raise PermissionError("Rollback qualification Tool implementations changed")
    arguments = copy.deepcopy(original.arguments)
    _set_path(arguments, contract.idempotency_key_argument_path, IDEMPOTENCY_PLACEHOLDER)
    if arguments != policy.arguments_template:
        raise PermissionError("Rollback primary template changed")
    claim = _row(db, ChangePreapprovalBudgetClaim, receipt.budget_claim_id)
    alert = _row(db, Alert, claim.alert_id, shared=True)
    origins = plan.tool_contract_snapshot.get("origin", {}).get("alerts", [])
    if not any(item["id"] == alert.id and item["identity_sha256"] == frozen_alert_identity_hash(alert) for item in origins):
        raise PermissionError("Rollback causal Alert identity changed")
    assert_parent_slot(db, proposal, plan)
    current = restoration_evidence(db, primary.id, settings, exclude_parent=plan.id)
    if not current["ready"] or current["dependencies"] != grant.dependency_snapshot:
        raise PermissionError("Current independent restoration evidence is not healthy")
    return grant, reviewer, receipt, failure, current


def authorize_rollback(db, grant_id, proposal_id, *, actor, inline=False, expected_action_hash=None):
    if not get_settings().enable_reviewed_rollback_execution:
        raise PermissionError("Reviewed rollback execution is disabled by host configuration")
    require_locking_transaction(db, purpose="Rollback authorization")
    # Share the revocation/qualification lock order before taking the parent.
    # Exact completed retries retain historical receipt semantics below.
    grant = _row(db, ChangeRollbackExecutionGrant, grant_id, shared=True)
    _row(db, ChangePreapprovalExecutionGrant, grant.primary_grant_id, shared=True)
    proposal = _row(db, AgentActionProposal, proposal_id)
    plan = _row(db, GovernedChangePlan, proposal.rollback_of_change_plan_id, lock=True)
    proposal = _row(db, AgentActionProposal, proposal_id, lock=True)
    if expected_action_hash is not None and proposal.plan_hash != expected_action_hash:
        raise ValueError("Rollback action hash changed; reload its material")
    existing = rollback_authorization(db, proposal)
    if existing is not None:
        if existing.grant_id != grant_id:
            raise ValueError("A different rollback grant owns this action")
        primary = _row(db, ChangePreapprovalExecutionGrant, _row(db, ChangeRollbackExecutionGrant, grant_id).primary_grant_id)
        require_policy_device_scope(db, get_preapproval(db, primary.policy_id), actor)
        if not scope_contains(db, actor, _row(db, Investigation, plan.investigation_id).authorization_scope):
            raise PermissionError("Rollback is outside the requesting scope")
        assert_rollback_receipt(db, proposal, plan); db.commit(); return existing
    if proposal.status != "pending":
        raise ValueError("Only pending rollback proposals can use reviewed authority")
    grant, reviewer, primary_receipt, failure, current = _admission(db, grant_id, proposal, plan, actor=actor)
    investigation = _row(db, Investigation, proposal.investigation_id)
    execution = db.scalar(select(AgentExecution).where(AgentExecution.investigation_id == investigation.id)
        .with_for_update().execution_options(populate_existing=True))
    required = AgentExecutionStatus.RUNNING if inline else AgentExecutionStatus.WAITING_APPROVAL
    if execution is None or execution.status != required:
        raise ValueError("Rollback authorization requires the exact active or waiting execution")
    receipt = ChangeRollbackAuthorization(grant_id=grant.id, primary_authorization_id=primary_receipt.id,
        parent_change_plan_id=plan.id, rollback_proposal_id=proposal.id, action_plan_hash=proposal.plan_hash,
        failure_snapshot=failure, evidence_manifest=current["manifest"], evidence_sha256=digest(current["manifest"]))
    db.add(receipt); db.flush()
    proposal.status = "approved"; proposal.approved_by = "system.rollback_preapproval"
    proposal.approved_by_principal_id = reviewer.principal_id; proposal.decided_at = receipt.authorized_at
    proposal.decision_reason = f"Distinct rollback grant {grant.id}; failed-parent budget 1"
    investigation.status = "running"; investigation.updated_at = utcnow()
    if not inline:
        execution.status = AgentExecutionStatus.QUEUED
        execution.worker_id = None; execution.lease_token_hash = None; execution.lease_expires_at = None
        execution.finished_at = None; execution.error = None
        execution.completion_worker_id = None; execution.completion_token_hash = None; execution.completion_request_hash = None
        execution.updated_at = utcnow()
    from .agent_execution import append_execution_event
    append_execution_event(db, execution, event_type="execution.approval_recorded", payload={
        "proposal_id": proposal.id, "decision": "approve", "actor": "system.rollback_preapproval",
        "plan_hash": proposal.plan_hash, "authorization_id": receipt.id, "rollback_budget": 1})
    record_audit_event(db, event_type="change.rollback.authorized", actor_type="policy", actor_id=grant.id,
        entity_type="change_rollback_authorization", entity_id=receipt.id,
        details={"parent_plan_id": plan.id, "proposal_id": proposal.id, "rollback_budget": 1})
    db.commit(); db.refresh(receipt); return receipt


def validate_rollback_execution(db, proposal):
    receipt = rollback_authorization(db, proposal)
    if receipt is None and proposal.approved_by != "system.rollback_preapproval":
        return
    if not get_settings().enable_reviewed_rollback_execution or receipt is None:
        raise PermissionError("Reviewed rollback is disabled or has no receipt")
    require_locking_transaction(db, purpose="Rollback execution")
    grant = _row(db, ChangeRollbackExecutionGrant, receipt.grant_id, shared=True)
    _row(db, ChangePreapprovalExecutionGrant, grant.primary_grant_id, shared=True)
    plan = _row(db, GovernedChangePlan, receipt.parent_change_plan_id, lock=True)
    _row(db, AgentActionProposal, proposal.id, lock=True)
    assert_rollback_receipt(db, proposal, plan)
    from .agent_authorization import investigation_principal
    actor = investigation_principal(_row(db, Investigation, proposal.investigation_id))
    _admission(db, receipt.grant_id, proposal, plan, actor=actor)


def try_inline_rollback(db, proposal, *, actor):
    existing = rollback_authorization(db, proposal)
    if existing is not None:
        assert_rollback_receipt(db, proposal, _row(db, GovernedChangePlan, proposal.rollback_of_change_plan_id))
        return {"proposal_id": proposal.id, "plan_hash": proposal.plan_hash}
    if not get_settings().enable_reviewed_rollback_execution or proposal.rollback_of_change_plan_id is None:
        return None
    plan = _row(db, GovernedChangePlan, proposal.rollback_of_change_plan_id)
    original = _row(db, AgentActionProposal, plan.action_proposal_id)
    primary_receipt = assert_authorization_receipt(db, original, plan)
    if primary_receipt is None:
        return None
    grant = db.scalar(select(ChangeRollbackExecutionGrant).where(
        ChangeRollbackExecutionGrant.primary_grant_id == primary_receipt.grant_id))
    if grant is None:
        return None
    try:
        receipt = authorize_rollback(db, grant.id, proposal.id, actor=actor, inline=True)
        return {"proposal_id": receipt.rollback_proposal_id, "plan_hash": receipt.action_plan_hash}
    except (LookupError, PermissionError, ValueError):
        db.rollback(); return None
