"""Reviewed authority, Alert debit and exact action admission in one transaction."""
from __future__ import annotations

import copy

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import ChangePreapprovalExecutionGrantCreate
from ..config import get_settings
from ..database import require_locking_transaction, session_namespace
from ..models import (AgentActionProposal, AgentExecution, AgentExecutionStatus, Alert,
    CapabilityQualityAssessment, CapabilityQualityPolicy, ChangePreapprovalAuthorization,
    ChangePreapprovalBudgetClaim, ChangePreapprovalExecutionGrant, ChangePreapprovalPolicy,
    ControlPlanePrincipal, ControlPlaneRole, ControlPlaneRoleBinding, GovernedChangePlan,
    Investigation, utcnow)
from .audit import record_audit_event
from .authorization_scope import scope_contains
from .capability_quality import (as_utc, assessment_material, digest, evaluate_policy,
    get_policy as get_quality_policy, policy_snapshot, policy_state)
from .change_governance import _extract_path, decide_change_plan
from .change_preapprovals import (_current_reviewer, _material, _set_path, _version_contract,
    _validate_settings,
    IDEMPOTENCY_PLACEHOLDER, claim_preapproval_budget, get_preapproval, preview_preapproval)
from .control_plane_auth import PrincipalContext, _merge_authorization_scopes


def _row(db: Session, model, row_id: str, *, lock: bool = False, shared: bool = False):
    namespace = session_namespace(db)
    if namespace is None:
        raise PermissionError("Reviewed execution requires a selected namespace")
    query = select(model).where(model.id == row_id, model.tenant_id == namespace[0])
    if model is not ControlPlanePrincipal:
        query = query.where(model.region_id == namespace[1])
    query = query.execution_options(populate_existing=True)
    if lock or shared:
        query = query.with_for_update(read=shared)
    row = db.scalar(query)
    if row is None:
        raise LookupError("Reviewed execution resource not found")
    return row


def _reviewer(db: Session, policy: ChangePreapprovalPolicy, principal_id: str,
              subject: str) -> PrincipalContext:
    if not _current_reviewer(db, policy, principal_id, subject):
        raise PermissionError("Execution reviewer has no current persisted role")
    principal = _row(db, ControlPlanePrincipal, principal_id, shared=True)
    if (not principal.enabled or principal.subject != subject
        or (principal.allowed_region_ids and policy.region_id not in principal.allowed_region_ids)):
        raise PermissionError("Execution reviewer identity was disabled or changed")
    bindings = list(db.scalars(select(ControlPlaneRoleBinding).where(
        ControlPlaneRoleBinding.principal_id == principal_id,
        ControlPlaneRoleBinding.tenant_id == policy.tenant_id,
        ControlPlaneRoleBinding.region_id == policy.region_id)
        .with_for_update(read=True).execution_options(populate_existing=True)).all())
    roles = list(db.scalars(select(ControlPlaneRole).where(
        ControlPlaneRole.id.in_([item.role_id for item in bindings]),
        ControlPlaneRole.tenant_id == policy.tenant_id,
        ControlPlaneRole.region_id == policy.region_id)
        .with_for_update(read=True).execution_options(populate_existing=True)).all())
    context = PrincipalContext(principal_id=principal.id, subject=subject,
        principal_type=principal.principal_type,
        permissions=frozenset(permission for role in roles for permission in role.permissions),
        role_names=tuple(role.name for role in roles),
        authorization_scope=_merge_authorization_scopes(bindings), auth_method="execution_grant",
        tenant_id=policy.tenant_id, region_id=policy.region_id)
    if not context.permits("changes.policy.manage") or not context.permits("changes.approve"):
        raise PermissionError("Execution reviewer permissions were revoked")
    if not scope_contains(db, context, {"device_ids": [policy.target_device_id]}):
        raise PermissionError("Execution reviewer cannot authorize the selected device")
    return context


def _assert_quality(db: Session, policy: ChangePreapprovalPolicy,
                    quality: CapabilityQualityPolicy, assessment: CapabilityQualityAssessment) -> int:
    state = policy_state(db, quality)
    if (quality.artifact_version_id != policy.tool_artifact_version_id
        or quality.content_hash != policy.tool_content_hash
        or quality.evidence_mode != "remediation_outcome"
        or quality.max_failure_ppm != 0 or not state.current or state.state != "healthy"
        or state.latest_assessment.id != assessment.id or assessment.failed_count != 0
        or assessment.scan_truncated or not assessment.evidence_manifest):
        raise ValueError("Execution qualification requires current zero-failure desired-state evidence")
    _, contract = _version_contract(db, policy.tool_artifact_version_id, policy.tool_content_hash)
    if not contract.semantic_expectations:
        raise ValueError("Execution qualification requires structured desired-state observations")
    # A version-wide healthy score cannot qualify a different device or template.
    matches = 0
    for sample in assessment.evidence_manifest:
        if (sample.get("verification_basis") != "structured_state_transition"
            or sample.get("outcome") != "verified"
            or sample.get("semantic_verification", {}).get("passed") is not True):
            raise ValueError("Execution qualification contains an unproved state transition")
        plan = _row(db, GovernedChangePlan, sample["change_plan_id"])
        proposal = _row(db, AgentActionProposal, plan.action_proposal_id)
        arguments = copy.deepcopy(proposal.arguments)
        _set_path(arguments, contract.idempotency_key_argument_path, IDEMPOTENCY_PLACEHOLDER)
        if arguments == policy.arguments_template:
            matches += 1
    if matches < quality.min_samples:
        raise ValueError("Execution qualification lacks enough exact-device/template outcomes")
    return matches


def require_policy_device_scope(db: Session, policy: ChangePreapprovalPolicy, actor: PrincipalContext) -> None:
    if ((actor.tenant_id, actor.region_id) != (policy.tenant_id, policy.region_id)
        or not scope_contains(db, actor, {"device_ids": [policy.target_device_id]})):
        raise LookupError("Preapproval policy not found in the selected device scope")


def read_execution_qualification(db: Session, policy_id: str, *, actor: PrincipalContext) -> dict:
    policy = get_preapproval(db, policy_id)
    require_policy_device_scope(db, policy, actor)
    result = {"ready": False, "quality_policy_id": None, "assessment_id": None,
        "valid_until": None, "matching_samples": 0, "required_samples": None,
        "reason": "exact_outcome_evidence_not_current"}
    if policy.status != "reviewed" or policy.review_sha256 != digest(_material(policy)):
        return {**result, "reason": "policy_not_currently_reviewed"}
    quality = db.scalar(select(CapabilityQualityPolicy).where(
        CapabilityQualityPolicy.artifact_version_id == policy.tool_artifact_version_id,
        CapabilityQualityPolicy.evidence_mode == "remediation_outcome",
        CapabilityQualityPolicy.tenant_id == policy.tenant_id,
        CapabilityQualityPolicy.region_id == policy.region_id).execution_options(populate_existing=True))
    if quality is None or quality.last_assessment_id is None:
        return result
    result["required_samples"] = quality.min_samples
    try:
        assessment = _row(db, CapabilityQualityAssessment, quality.last_assessment_id)
        matches = _assert_quality(db, policy, quality, assessment)
    except (LookupError, PermissionError, KeyError, TypeError, ValueError):
        return result
    return {**result, "ready": True, "quality_policy_id": quality.id,
        "assessment_id": assessment.id, "valid_until": assessment.valid_until,
        "matching_samples": matches, "reason": None}


def list_execution_grants(db: Session, policy_id: str) -> list[ChangePreapprovalExecutionGrant]:
    policy = get_preapproval(db, policy_id)
    return list(db.scalars(select(ChangePreapprovalExecutionGrant).where(
        ChangePreapprovalExecutionGrant.policy_id == policy.id,
        ChangePreapprovalExecutionGrant.tenant_id == policy.tenant_id,
        ChangePreapprovalExecutionGrant.region_id == policy.region_id)
        .order_by(ChangePreapprovalExecutionGrant.granted_at.desc()).limit(100)).all())


def qualify_reviewed_execution(db: Session, policy_id: str,
                              payload: ChangePreapprovalExecutionGrantCreate,
                              *, actor: PrincipalContext) -> ChangePreapprovalExecutionGrant:
    require_locking_transaction(db, purpose="Reviewed execution qualification")
    policy = get_preapproval(db, policy_id, shared_lock=True)
    if (actor.tenant_id, actor.region_id) != (policy.tenant_id, policy.region_id):
        raise PermissionError("Execution reviewer is outside the selected namespace")
    if (policy.status != "reviewed" or policy.review_sha256 != payload.expected_policy_review_sha256
        or policy.review_sha256 != digest(_material(policy))):
        raise ValueError("Execution qualification requires the exact current reviewed policy")
    reviewer = _reviewer(db, policy, actor.principal_id, actor.subject)
    if reviewer.subject == policy.created_by or reviewer.principal_id == policy.created_by_principal_id:
        raise PermissionError("The policy author cannot qualify its execution")
    _reviewer(db, policy, policy.reviewed_by_principal_id, policy.reviewed_by)
    device, _ = _validate_settings(db, policy, version_id=policy.tool_artifact_version_id,
        content_hash=policy.tool_content_hash, now=as_utc(utcnow()))
    if device.site != policy.target_site:
        raise ValueError("Execution qualification target site changed")
    quality = get_quality_policy(db, str(payload.quality_policy_id), lock=True)
    if quality.last_assessment_id != str(payload.expected_assessment_id):
        raise ValueError("Qualification assessment changed; review the current evidence")
    assessment = _row(db, CapabilityQualityAssessment, quality.last_assessment_id)
    if reviewer.subject in {quality.created_by, assessment.evaluated_by}:
        raise PermissionError("Execution qualification requires an independent evidence reviewer")
    _assert_quality(db, policy, quality, assessment)
    now = utcnow()
    if not as_utc(now) < as_utc(payload.expires_at) <= as_utc(policy.expires_at):
        raise ValueError("Execution grant must expire within the reviewed policy expiry")
    from .collectors import assert_no_inline_secrets
    assert_no_inline_secrets({"reference": payload.acceptance_reference}, "acceptance reference")
    existing = db.scalar(select(ChangePreapprovalExecutionGrant).where(
        ChangePreapprovalExecutionGrant.policy_id == policy.id,
        ChangePreapprovalExecutionGrant.policy_review_sha256 == policy.review_sha256,
        ChangePreapprovalExecutionGrant.tenant_id == policy.tenant_id,
        ChangePreapprovalExecutionGrant.region_id == policy.region_id))
    if existing is not None:
        if (existing.quality_policy_id != quality.id
            or existing.qualification_assessment_id != assessment.id
            or existing.acceptance_reference != payload.acceptance_reference
            or as_utc(existing.expires_at) != as_utc(payload.expires_at)
            or existing.granted_by_principal_id != reviewer.principal_id):
            raise ValueError("This policy revision already has a different execution grant")
        db.commit()
        return existing
    grant = ChangePreapprovalExecutionGrant(policy_id=policy.id,
        policy_review_sha256=policy.review_sha256, quality_policy_id=quality.id,
        quality_policy_sha256=digest(policy_snapshot(quality)),
        qualification_assessment_id=assessment.id,
        qualification_assessment_sha256=assessment.assessment_sha256,
        acceptance_reference=payload.acceptance_reference,
        granted_by_principal_id=reviewer.principal_id, granted_by=reviewer.subject,
        granted_at=now, expires_at=payload.expires_at)
    db.add(grant); db.flush()
    record_audit_event(db, event_type="change.preapproval.execution_qualified", actor_type="user",
        actor_id=reviewer.subject, entity_type="change_preapproval_execution_grant", entity_id=grant.id,
        details={"policy_id": policy.id, "assessment_id": assessment.id,
            "policy_review_sha256": policy.review_sha256, "reason": payload.reason})
    db.commit(); db.refresh(grant)
    return grant


def _current_grant(db: Session, grant_id: str):
    grant = _row(db, ChangePreapprovalExecutionGrant, grant_id)
    policy = get_preapproval(db, grant.policy_id, shared_lock=True)
    if (policy.status != "reviewed" or grant.policy_review_sha256 != policy.review_sha256
        or policy.review_sha256 != digest(_material(policy))
        or as_utc(grant.expires_at) <= as_utc(utcnow())):
        raise PermissionError("Reviewed execution grant is expired, revoked or superseded")
    reviewer = _reviewer(db, policy, grant.granted_by_principal_id, grant.granted_by)
    _reviewer(db, policy, policy.reviewed_by_principal_id, policy.reviewed_by)
    quality = get_quality_policy(db, grant.quality_policy_id, lock=True)
    if digest(policy_snapshot(quality)) != grant.quality_policy_sha256:
        raise PermissionError("Reviewed execution quality configuration changed")
    qualification = _row(db, CapabilityQualityAssessment, grant.qualification_assessment_id)
    if (qualification.assessment_sha256 != grant.qualification_assessment_sha256
        or digest(assessment_material(qualification)) != grant.qualification_assessment_sha256
        or digest(qualification.evidence_manifest) != qualification.evidence_sha256
        or qualification.policy_sha256 != grant.quality_policy_sha256):
        raise PermissionError("Original execution qualification evidence changed")
    assessment = evaluate_policy(db, quality.id, actor="system.preapproval", commit=False)
    _assert_quality(db, policy, quality, assessment)
    return grant, policy, reviewer, assessment


def authorization_for_proposal(db: Session, proposal: AgentActionProposal):
    return db.scalar(select(ChangePreapprovalAuthorization).where(
        ChangePreapprovalAuthorization.action_proposal_id == proposal.id,
        ChangePreapprovalAuthorization.tenant_id == proposal.tenant_id,
        ChangePreapprovalAuthorization.region_id == proposal.region_id))


def authorize_reviewed_action(db: Session, grant_id: str, plan_id: str,
                              *, actor: PrincipalContext, inline: bool = False,
                              expected_plan_hash: str | None = None,
                              expected_action_hash: str | None = None):
    if not get_settings().enable_reviewed_change_execution:
        raise PermissionError("Reviewed execution is disabled by host configuration")
    require_locking_transaction(db, purpose="Reviewed action authorization")
    grant, policy, reviewer, assessment = _current_grant(db, grant_id)
    plan = _row(db, GovernedChangePlan, plan_id, lock=True)
    proposal = _row(db, AgentActionProposal, plan.action_proposal_id, lock=True)
    if ((expected_plan_hash is not None and expected_plan_hash != plan.plan_hash)
        or (expected_action_hash is not None and expected_action_hash != proposal.plan_hash)):
        raise ValueError("Reviewed authorization plan changed; reload its exact material")
    if (actor.tenant_id, actor.region_id) != (policy.tenant_id, policy.region_id):
        raise PermissionError("Reviewed action actor is outside the selected namespace")
    investigation = _row(db, Investigation, plan.investigation_id)
    if not scope_contains(db, actor, investigation.authorization_scope):
        raise PermissionError("Reviewed action is outside the requesting scope")
    existing = authorization_for_proposal(db, proposal)
    if existing is not None:
        if existing.grant_id != grant.id or existing.change_plan_hash != plan.approved_plan_hash:
            raise ValueError("A different reviewed authorization owns this action")
        assert_authorization_receipt(db, proposal, plan)
        db.commit()
        return existing
    if proposal.status != "pending" or proposal.rollback_of_change_plan_id is not None:
        raise ValueError("Only pending primary actions may use a reviewed execution grant")
    if (reviewer.subject == proposal.requested_by
        or reviewer.principal_id == proposal.requested_by_principal_id):
        raise PermissionError("The action requester cannot be its execution grant reviewer")
    execution = db.scalar(select(AgentExecution).where(
        AgentExecution.investigation_id == investigation.id,
        AgentExecution.tenant_id == policy.tenant_id, AgentExecution.region_id == policy.region_id)
        .with_for_update().execution_options(populate_existing=True))
    required_status = AgentExecutionStatus.RUNNING if inline else AgentExecutionStatus.WAITING_APPROVAL
    if execution is None or execution.status != required_status:
        raise ValueError("Reviewed authorization requires the exact active or waiting execution")
    claim = claim_preapproval_budget(db, policy.id, plan.id, actor=actor, commit=False)
    preview = preview_preapproval(db, policy, plan, execution_claim=claim)
    if not preview["candidate_matches"]:
        raise ValueError("Reviewed execution eligibility changed: " + ",".join(preview["blocking_reasons"]))
    decide_change_plan(db, proposal, decision="approve", expected_plan_hash=plan.plan_hash,
        actor="system.preapproval")
    receipt = ChangePreapprovalAuthorization(grant_id=grant.id, budget_claim_id=claim.id,
        action_proposal_id=proposal.id, action_plan_hash=proposal.plan_hash,
        change_plan_hash=plan.plan_hash, assessment_id=assessment.id,
        assessment_sha256=assessment.assessment_sha256)
    db.add(receipt); db.flush()
    proposal.status = "approved"
    proposal.approved_by = "system.preapproval"
    proposal.approved_by_principal_id = reviewer.principal_id
    proposal.decision_reason = f"Reviewed execution grant {grant.id}"
    proposal.decided_at = receipt.authorized_at
    investigation.status = "running"; investigation.updated_at = utcnow()
    if not inline:
        execution.status = AgentExecutionStatus.QUEUED
        execution.worker_id = None; execution.lease_token_hash = None
        execution.lease_expires_at = None; execution.finished_at = None
        execution.completion_worker_id = None; execution.completion_token_hash = None
        execution.completion_request_hash = None
        execution.error = None; execution.updated_at = utcnow()
    from .agent_execution import append_execution_event
    append_execution_event(db, execution, event_type="execution.approval_recorded",
        payload={"proposal_id": proposal.id, "decision": "approve",
            "plan_hash": proposal.plan_hash, "actor": "system.preapproval",
            "authorization_id": receipt.id, "grant_id": grant.id})
    record_audit_event(db, event_type="change.preapproval.action_authorized", actor_type="policy",
        actor_id=policy.id, entity_type="change_preapproval_authorization", entity_id=receipt.id,
        details={"grant_id": grant.id, "budget_claim_id": claim.id,
            "proposal_id": proposal.id, "plan_hash": plan.plan_hash,
            "requested_by": actor.subject, "assessment_id": assessment.id})
    db.commit(); db.refresh(receipt)
    return receipt


def assert_authorization_receipt(db: Session, proposal: AgentActionProposal,
                                 plan: GovernedChangePlan):
    """Check sealed historical bindings without interpreting revocation as erasure."""
    receipt = authorization_for_proposal(db, proposal)
    if receipt is None:
        if proposal.approved_by == "system.preapproval":
            raise ValueError("Reviewed action has no immutable authorization receipt")
        return None
    try:
        grant = _row(db, ChangePreapprovalExecutionGrant, receipt.grant_id)
        claim = _row(db, ChangePreapprovalBudgetClaim, receipt.budget_claim_id)
        assessment = _row(db, CapabilityQualityAssessment, receipt.assessment_id)
    except (LookupError, PermissionError) as exc:
        raise ValueError("Reviewed authorization evidence is unavailable") from exc
    from .change_governance import _plan_hash
    # Post-action evidence advances the live revision. The immutable receipt
    # binds the preceding approval, not the newer verification-history hash.
    after_approval = sum(item.stage in {"postcheck", "rollback", "rollback_check"} for item in plan.evidence)
    if (plan.plan_hash != _plan_hash(plan)
        or plan.approved_plan_hash != _plan_hash(plan, revision=plan.revision - after_approval)
        or receipt.action_plan_hash != proposal.plan_hash or receipt.change_plan_hash != plan.approved_plan_hash
        or claim.change_plan_id != plan.id or claim.policy_id != grant.policy_id
        or claim.plan_hash != receipt.change_plan_hash or claim.policy_review_sha256 != grant.policy_review_sha256
        or proposal.approved_by != "system.preapproval"
        or proposal.approved_by_principal_id != grant.granted_by_principal_id
        or proposal.decided_at is None or as_utc(proposal.decided_at) != as_utc(receipt.authorized_at)
        or assessment.policy_id != grant.quality_policy_id
        or assessment.policy_sha256 != grant.quality_policy_sha256
        or digest(assessment.policy_snapshot) != assessment.policy_sha256
        or assessment.status != "healthy" or assessment.failed_count != 0 or assessment.scan_truncated
        or assessment.assessment_sha256 != receipt.assessment_sha256
        or digest(assessment_material(assessment)) != receipt.assessment_sha256
        or digest(assessment.evidence_manifest) != assessment.evidence_sha256):
        raise ValueError("Reviewed action authorization bindings changed")
    return receipt


def validate_reviewed_execution(db: Session, proposal: AgentActionProposal) -> None:
    receipt = authorization_for_proposal(db, proposal)
    if receipt is None and proposal.approved_by != "system.preapproval":
        return
    if not get_settings().enable_reviewed_change_execution:
        raise PermissionError("Reviewed execution was disabled before action admission")
    require_locking_transaction(db, purpose="Reviewed action execution")
    if receipt is None:
        raise PermissionError("Reviewed action has no immutable authorization receipt")
    grant, policy, reviewer, assessment = _current_grant(db, receipt.grant_id)
    claim = _row(db, ChangePreapprovalBudgetClaim, receipt.budget_claim_id)
    plan = _row(db, GovernedChangePlan, claim.change_plan_id, lock=True)
    _row(db, AgentActionProposal, proposal.id, lock=True)
    assert_authorization_receipt(db, proposal, plan)
    _row(db, Alert, claim.alert_id, lock=True)
    if reviewer.subject == proposal.requested_by or reviewer.principal_id == proposal.requested_by_principal_id:
        raise PermissionError("Execution reviewer is the action requester")
    preview = preview_preapproval(db, policy, plan, execution_claim=claim)
    if not preview["candidate_matches"]:
        raise PermissionError("Reviewed execution is no longer eligible: " + ",".join(preview["blocking_reasons"]))
    record_audit_event(db, event_type="change.preapproval.execution_admitted", actor_type="policy",
        actor_id=policy.id, entity_type="change_preapproval_authorization", entity_id=receipt.id,
        details={"assessment_id": assessment.id, "proposal_id": proposal.id})


def try_inline_reviewed_authorization(db: Session, plan: GovernedChangePlan,
                                      *, actor: PrincipalContext):
    if not get_settings().enable_reviewed_change_execution:
        # Existing human-only deployments do not need an execution-grant session.
        proposal = db.get(AgentActionProposal, plan.action_proposal_id)
        if proposal is None or proposal.approved_by != "system.preapproval":
            return None
    proposal = _row(db, AgentActionProposal, plan.action_proposal_id)
    existing = authorization_for_proposal(db, proposal)
    if existing is not None:
        assert_authorization_receipt(db, proposal, plan)
        return {"proposal_id": proposal.id, "plan_hash": proposal.plan_hash}
    if not get_settings().enable_reviewed_change_execution or plan.status != "ready_for_approval":
        return None
    # Avoid enumerating policies/targets for principals that do not own this plan.
    tool_version_id = plan.tool_contract_snapshot.get("action_tool", {}).get("artifact_version_id")
    if tool_version_id is None:
        from .tool_provenance import tool_artifact_provenance
        from ..models import AgentToolRegistration
        tool = _row(db, AgentToolRegistration, plan.tool_contract_snapshot["action_tool"]["tool_id"])
        tool_version_id = tool_artifact_provenance(db, tool).get("artifact_version_id")
    grants = list(db.scalars(select(ChangePreapprovalExecutionGrant)
        .join(ChangePreapprovalPolicy, ChangePreapprovalPolicy.id == ChangePreapprovalExecutionGrant.policy_id)
        .where(ChangePreapprovalPolicy.tool_artifact_version_id == tool_version_id,
            ChangePreapprovalPolicy.status == "reviewed",
            ChangePreapprovalPolicy.tenant_id == actor.tenant_id,
            ChangePreapprovalPolicy.region_id == actor.region_id,
            ChangePreapprovalExecutionGrant.tenant_id == actor.tenant_id,
            ChangePreapprovalExecutionGrant.region_id == actor.region_id,
            ChangePreapprovalExecutionGrant.expires_at > utcnow())
        .order_by(ChangePreapprovalExecutionGrant.granted_at, ChangePreapprovalExecutionGrant.id).limit(101)).all())
    if len(grants) > 100:
        return None  # An ambiguous, saturated scan goes to the human path.
    for grant in grants:
        try:
            receipt = authorize_reviewed_action(db, grant.id, plan.id, actor=actor, inline=True)
            return {"proposal_id": receipt.action_proposal_id, "plan_hash": receipt.action_plan_hash}
        except (LookupError, PermissionError, ValueError):
            db.rollback()
    return None
