"""Reviewed, exact-scope preapproval envelopes and non-executing eligibility previews."""
from __future__ import annotations

import copy
import json
import math
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..agent_schemas import AgentChangeContract, ChangePreapprovalCreate, ChangePreapprovalUpdate
from ..database import require_locking_transaction, session_namespace
from ..models import (AgentActionProposal, AgentToolRegistration, Alert, AlertStatus, ArtifactKind, ChangePreapprovalBudgetClaim, ChangePreapprovalPolicy,
    ControlPlanePrincipal, ControlPlaneRole, ControlPlaneRoleBinding, CredentialProfile, Device,
    GovernedChangeEvidence, GovernedChangePlan, Investigation, InvestigationToolCall, MCPServer, MCPToolActivation,
    Situation, SituationAlert, utcnow)
from .audit import record_audit_event
from .capability_catalog import _mcp_tool_blockers
from .capability_quality import _validate_version, _version, as_utc, digest
from .change_governance import (MAX_FROZEN_ORIGIN_ALERTS, _assert_plan_current, _plan_hash,
    _extract_path, _latest_evidence, frozen_alert_identity_hash)
from .change_verification import scoped_row, validate_stage_call
from .collectors import assert_no_inline_secrets, validate_instance
from .control_plane_auth import PrincipalContext
from .tool_provenance import tool_artifact_provenance


IDEMPOTENCY_PLACEHOLDER = "__ICHECK_IDEMPOTENCY_KEY__"
MAX_TEMPLATE_BYTES = 4096


def _scope(db: Session) -> tuple[str, str]:
    namespace = session_namespace(db)
    if namespace is None:
        raise PermissionError("Preapproval policies require a selected tenant and region")
    return namespace


def _query(db: Session):
    tenant_id, region_id = _scope(db)
    return select(ChangePreapprovalPolicy).where(
        ChangePreapprovalPolicy.tenant_id == tenant_id,
        ChangePreapprovalPolicy.region_id == region_id,
    )


def _device(db: Session, device_id: str) -> Device:
    tenant_id, region_id = _scope(db)
    device = db.scalar(select(Device).where(Device.id == device_id,
        Device.tenant_id == tenant_id, Device.region_id == region_id).execution_options(populate_existing=True))
    if device is None or not device.enabled or device.onboarding_status != "active" or not device.site:
        raise ValueError("Preapproval target must be an active device with a site in this namespace")
    return device


def _version_contract(db: Session, version_id: str, content_hash: str) -> tuple[dict, AgentChangeContract]:
    version = _version(db, version_id)
    _validate_version(db, version, content_hash)
    spec = version.definition.get("spec", {})
    if version.artifact.kind != ArtifactKind.TOOL or spec.get("read_only") is not False:
        raise ValueError("Preapproval requires a published state-changing Tool")
    contract = AgentChangeContract.model_validate(spec.get("change_contract"))
    if contract.risk_class != "low" or not any(kind == "device_id" for kind in contract.authorization_target_paths.values()):
        raise ValueError("Preapproval requires a low-risk Tool with an explicit device authorization target")
    return spec, contract


def _set_path(document: dict, path: str, value: str) -> None:
    parts = path.split(".")
    cursor = document
    for part in parts[:-1]:
        cursor = cursor[part]
        if not isinstance(cursor, dict):
            raise ValueError("Idempotency key is not an object path")
    cursor[parts[-1]] = value


def _validate_settings(db: Session, settings, *, version_id: str, content_hash: str,
                       now: datetime, require_semantic: bool = True) -> tuple[Device, AgentChangeContract]:
    spec, contract = _version_contract(db, version_id, content_hash)
    if require_semantic and not contract.semantic_expectations:
        raise ValueError("Preapproval requires published desired-state observations")
    device = _device(db, str(settings.target_device_id))
    expires = as_utc(settings.expires_at)
    if not now < expires <= now + timedelta(days=30):
        raise ValueError("Preapproval expiry must be within the next 30 days")
    template = settings.arguments_template
    if len(json.dumps(template, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()) > MAX_TEMPLATE_BYTES:
        raise ValueError("Preapproval argument template exceeds 4096 bytes")
    assert_no_inline_secrets(template, "preapproval arguments")
    if _extract_path(template, contract.idempotency_key_argument_path) != IDEMPOTENCY_PLACEHOLDER:
        raise ValueError("Preapproval idempotency key must use the explicit placeholder")
    for path, kind in contract.authorization_target_paths.items():
        expected = device.id if kind == "device_id" else device.site
        if _extract_path(template, path) != expected:
            raise ValueError("Preapproval argument target must match the selected device and site")
    for expectation in contract.semantic_expectations:
        _extract_path(template, expectation.action_argument_path)
    validation_arguments = copy.deepcopy(template)
    _set_path(validation_arguments, contract.idempotency_key_argument_path, "icheck-preview-key")
    validate_instance(validation_arguments, spec["input_schema"], "preapproval action arguments")
    return device, contract


def _material(policy: ChangePreapprovalPolicy) -> dict:
    return {"contract": "icheck.change-preapproval/v1", "id": policy.id,
        "tenant_id": policy.tenant_id, "region_id": policy.region_id,
        "name": policy.name, "tool_artifact_version_id": policy.tool_artifact_version_id,
        "tool_content_hash": policy.tool_content_hash,
        "target_device_id": policy.target_device_id, "target_site": policy.target_site,
        "alert_event_type": policy.alert_event_type,
        "arguments_template": policy.arguments_template,
        "max_alert_age_seconds": policy.max_alert_age_seconds,
        "max_evidence_age_seconds": policy.max_evidence_age_seconds,
        "max_actions_per_alert": policy.max_actions_per_alert,
        "expires_at": as_utc(policy.expires_at).isoformat(),
        "revision": policy.revision,
        "created_by": policy.created_by,
        "created_by_principal_id": policy.created_by_principal_id,
        "reviewed_by": policy.reviewed_by,
        "reviewed_by_principal_id": policy.reviewed_by_principal_id,
        "reviewed_at": as_utc(policy.reviewed_at).isoformat() if policy.reviewed_at else None}


def list_preapprovals(db: Session, *, offset: int = 0, limit: int = 100) -> list[ChangePreapprovalPolicy]:
    return list(db.scalars(_query(db).order_by(ChangePreapprovalPolicy.created_at.desc(), ChangePreapprovalPolicy.id)
        .offset(offset).limit(limit)).all())


def get_preapproval(db: Session, policy_id: str, *, lock: bool = False,
                    shared_lock: bool = False) -> ChangePreapprovalPolicy:
    if lock and shared_lock:
        raise ValueError("Choose one preapproval lock mode")
    query = _query(db).where(ChangePreapprovalPolicy.id == policy_id).execution_options(populate_existing=True)
    if lock:
        query = query.with_for_update()
    elif shared_lock:
        query = query.with_for_update(read=True)
    policy = db.scalar(query)
    if policy is None:
        raise LookupError("Preapproval policy not found")
    return policy


def _audit(db: Session, policy: ChangePreapprovalPolicy, actor: PrincipalContext, event: str, reason: str) -> None:
    record_audit_event(db, event_type=f"change.preapproval.{event}", actor_type=actor.principal_type,
        actor_id=actor.subject, entity_type="change_preapproval_policy", entity_id=policy.id,
        details={"revision": policy.revision, "status": policy.status,
            "policy_sha256": digest(_material(policy)), "reason_sha256": digest(reason)})


def _current_reviewer(db: Session, policy: ChangePreapprovalPolicy, principal_id: str | None,
                      subject: str | None) -> bool:
    if not principal_id or not subject:
        return False
    reviewer = db.scalar(select(ControlPlanePrincipal).where(ControlPlanePrincipal.id == principal_id)
        .execution_options(populate_existing=True))
    if (reviewer is None or not reviewer.enabled or reviewer.tenant_id != policy.tenant_id
        or reviewer.subject != subject or (reviewer.allowed_region_ids and policy.region_id not in reviewer.allowed_region_ids)):
        return False
    roles = db.scalars(select(ControlPlaneRole).join(ControlPlaneRoleBinding,
        ControlPlaneRoleBinding.role_id == ControlPlaneRole.id).where(
            ControlPlaneRoleBinding.principal_id == principal_id,
            ControlPlaneRoleBinding.tenant_id == policy.tenant_id,
            ControlPlaneRoleBinding.region_id == policy.region_id,
            ControlPlaneRole.tenant_id == policy.tenant_id,
            ControlPlaneRole.region_id == policy.region_id,
        ).execution_options(populate_existing=True)).all()
    permissions = {permission for role in roles for permission in (role.permissions or [])}
    return "*" in permissions or {"changes.policy.manage", "changes.approve"} <= permissions


def _budget_state(db: Session, alert_id: str, policy_limit: int) -> tuple[int, int]:
    tenant_id, region_id = _scope(db)
    used, oldest_limit = db.execute(select(func.count(ChangePreapprovalBudgetClaim.id),
        func.min(ChangePreapprovalBudgetClaim.policy_limit_snapshot)).where(
            ChangePreapprovalBudgetClaim.tenant_id == tenant_id,
            ChangePreapprovalBudgetClaim.region_id == region_id,
            ChangePreapprovalBudgetClaim.alert_id == alert_id)).one()
    # The first claim freezes an upper bound for this Alert. Later policy edits
    # or a different policy cannot increase the already established ceiling.
    return int(used), min(policy_limit, int(oldest_limit)) if oldest_limit is not None else policy_limit


def _matching_alert(db: Session, investigation: Investigation, policy: ChangePreapprovalPolicy,
                    namespace: tuple[str, str], now: datetime, frozen_alert_ids: list[str]) -> Alert | None:
    if investigation.situation_id is None or not frozen_alert_ids:
        return None
    situation = db.scalar(select(Situation).where(Situation.id == investigation.situation_id,
        Situation.tenant_id == namespace[0], Situation.region_id == namespace[1]))
    if situation is None or situation.status != "open":
        return None
    return db.scalar(select(Alert).join(SituationAlert, SituationAlert.alert_id == Alert.id).where(
        SituationAlert.situation_id == situation.id, Alert.tenant_id == namespace[0],
        Alert.region_id == namespace[1], Alert.event_type == policy.alert_event_type,
        Alert.entity_type == "device", Alert.entity_id == policy.target_device_id,
        Alert.id.in_(frozen_alert_ids),
        Alert.status == AlertStatus.OPEN,
        Alert.source_retirement_id.is_(None),
        Alert.first_seen <= Alert.last_seen, Alert.first_seen <= now,
        Alert.last_seen >= now - timedelta(seconds=policy.max_alert_age_seconds), Alert.last_seen <= now
    ).order_by(Alert.last_seen.desc(), Alert.id).limit(1))


def _prerequisites_fresh(db: Session, plan: GovernedChangePlan, *, now: datetime,
                         max_age_seconds: int) -> bool:
    if not 60 <= max_age_seconds <= 3600:
        return False
    cutoff = now - timedelta(seconds=max_age_seconds)
    for stage in ("precheck", "dry_run"):
        evidence = db.scalar(select(GovernedChangeEvidence).where(
            GovernedChangeEvidence.change_plan_id == plan.id,
            GovernedChangeEvidence.tenant_id == plan.tenant_id,
            GovernedChangeEvidence.region_id == plan.region_id,
            GovernedChangeEvidence.stage == stage,
        ).order_by(GovernedChangeEvidence.created_at.desc(), GovernedChangeEvidence.id.desc())
            .limit(1).execution_options(populate_existing=True))
        if evidence is None or evidence.passed is not True:
            return False
        finished = db.scalar(select(InvestigationToolCall.finished_at).where(
            InvestigationToolCall.id == evidence.tool_call_id,
            InvestigationToolCall.tenant_id == plan.tenant_id,
            InvestigationToolCall.region_id == plan.region_id,
            InvestigationToolCall.governed_change_plan_id == plan.id,
            InvestigationToolCall.governed_stage == stage,
            InvestigationToolCall.status == "succeeded",
        ))
        if finished is None or not cutoff <= as_utc(finished) <= now:
            return False
    return True


def _semantic_precondition(db: Session, plan: GovernedChangePlan, proposal: AgentActionProposal,
                           contract: AgentChangeContract, *, now: datetime) -> str | None:
    """Require a fresh, different pre-state; a preview still grants no authority."""
    declared = [item.model_dump() for item in contract.semantic_expectations]
    if not declared:
        return "semantic_contract_missing"
    frozen = plan.tool_contract_snapshot.get("semantic_expectations")
    if not isinstance(frozen, list) or len(frozen) != len(declared):
        return "semantic_contract_drift"
    for source, item in zip(declared, frozen):
        if (not isinstance(item, dict)
            or {key: item.get(key) for key in source} != source
            or item.get("value_type") not in {"boolean", "integer", "number", "string"}):
            return "semantic_contract_drift"
    evidence = _latest_evidence(plan).get("precheck")
    call = scoped_row(db, InvestigationToolCall, evidence.tool_call_id if evidence else None, plan)
    if evidence is None or evidence.passed is not True or call is None:
        return "semantic_precondition_evidence_invalid"
    try:
        passed, _ = validate_stage_call(db, plan, "precheck", call, now=now)
        if not passed:
            return "semantic_precondition_evidence_invalid"
        age = (now - as_utc(call.finished_at)).total_seconds()
        for item in frozen:
            if not 0 <= age <= item["max_precheck_age_seconds"]:
                return "semantic_precondition_stale"
            expected = _extract_path(proposal.arguments, item["action_argument_path"])
            before = _extract_path(call.result, item["precheck_observation_path"])
            value_type = item["value_type"]
            if value_type == "boolean":
                valid = type(expected) is bool and type(before) is bool
            elif value_type == "integer":
                valid = type(expected) is int and type(before) is int
            elif value_type == "number":
                valid = (type(expected) in (int, float) and type(before) in (int, float)
                    and (type(expected) is not float or math.isfinite(expected))
                    and (type(before) is not float or math.isfinite(before)))
            else:
                valid = type(expected) is str and type(before) is str
            if not valid:
                return "semantic_precondition_evidence_invalid"
            if before == expected:
                return "semantic_precondition_not_met"
    except (LookupError, TypeError, KeyError, ValueError):
        return "semantic_precondition_evidence_invalid"
    return None


def create_preapproval(db: Session, payload: ChangePreapprovalCreate, *, actor: PrincipalContext) -> ChangePreapprovalPolicy:
    now = utcnow()
    device, _ = _validate_settings(db, payload, version_id=str(payload.tool_artifact_version_id),
        content_hash=payload.expected_content_hash, now=now)
    if db.scalar(_query(db).where(ChangePreapprovalPolicy.name == payload.name)):
        raise ValueError("Preapproval name already exists in this namespace")
    policy = ChangePreapprovalPolicy(name=payload.name, status="draft",
        tool_artifact_version_id=str(payload.tool_artifact_version_id), tool_content_hash=payload.expected_content_hash,
        target_device_id=device.id, target_site=device.site, alert_event_type=payload.alert_event_type,
        arguments_template=payload.arguments_template, max_alert_age_seconds=payload.max_alert_age_seconds,
        max_evidence_age_seconds=payload.max_evidence_age_seconds,
        max_actions_per_alert=payload.max_actions_per_alert, expires_at=payload.expires_at,
        revision=1, created_by=actor.subject, created_by_principal_id=actor.principal_id,
        updated_by=actor.subject, created_at=now, updated_at=now)
    db.add(policy); db.flush()
    _audit(db, policy, actor, "draft_created", payload.reason)
    db.commit(); db.refresh(policy)
    return policy


def revise_preapproval(db: Session, policy: ChangePreapprovalPolicy, payload: ChangePreapprovalUpdate, *, actor: PrincipalContext) -> ChangePreapprovalPolicy:
    if policy.status == "revoked" or policy.revision != payload.expected_revision:
        raise ValueError("Preapproval policy is revoked or its revision is stale")
    now = utcnow()
    device, _ = _validate_settings(db, payload, version_id=policy.tool_artifact_version_id,
        content_hash=policy.tool_content_hash, now=now)
    existing = db.scalar(_query(db).where(ChangePreapprovalPolicy.name == payload.name,
        ChangePreapprovalPolicy.id != policy.id))
    if existing:
        raise ValueError("Preapproval name already exists in this namespace")
    for field in ("name", "alert_event_type", "arguments_template", "max_alert_age_seconds", "max_evidence_age_seconds", "max_actions_per_alert", "expires_at"):
        setattr(policy, field, getattr(payload, field))
    policy.target_device_id, policy.target_site = device.id, device.site
    policy.status = "draft"; policy.revision += 1; policy.updated_by = actor.subject; policy.updated_at = now
    policy.reviewed_by = None; policy.reviewed_by_principal_id = None
    policy.reviewed_at = None; policy.review_sha256 = None
    _audit(db, policy, actor, "revised", payload.reason)
    db.commit(); db.refresh(policy)
    return policy


def review_preapproval(db: Session, policy: ChangePreapprovalPolicy, *, expected_revision: int,
                       actor: PrincipalContext, reason: str) -> ChangePreapprovalPolicy:
    if policy.status != "draft" or policy.revision != expected_revision:
        raise ValueError("Preapproval draft is stale or already reviewed")
    if actor.subject == policy.created_by or (policy.created_by_principal_id and actor.principal_id == policy.created_by_principal_id):
        raise PermissionError("Preapproval author cannot review their own policy")
    if not actor.permits("changes.approve") or not actor.permits("changes.policy.manage") or not actor.principal_id:
        raise PermissionError("Preapproval review requires a persistent approver with both permissions")
    if not _current_reviewer(db, policy, actor.principal_id, actor.subject):
        raise PermissionError("Preapproval reviewer identity or current role is unavailable")
    now = utcnow()
    # Review checks current published material, target state and template again.
    settings = SimpleNamespace(target_device_id=policy.target_device_id,
        expires_at=policy.expires_at, arguments_template=policy.arguments_template)
    _validate_settings(db, settings, version_id=policy.tool_artifact_version_id, content_hash=policy.tool_content_hash, now=now)
    policy.status = "reviewed"; policy.revision += 1; policy.updated_by = actor.subject; policy.updated_at = now
    policy.reviewed_by = actor.subject; policy.reviewed_by_principal_id = actor.principal_id; policy.reviewed_at = now
    policy.review_sha256 = digest(_material(policy))
    _audit(db, policy, actor, "reviewed", reason)
    db.commit(); db.refresh(policy)
    return policy


def revoke_preapproval(db: Session, policy: ChangePreapprovalPolicy, *, expected_revision: int,
                       actor: PrincipalContext, reason: str) -> ChangePreapprovalPolicy:
    if policy.status == "revoked" or policy.revision != expected_revision:
        raise ValueError("Preapproval policy is revoked or its revision is stale")
    policy.status = "revoked"; policy.revision += 1; policy.updated_by = actor.subject; policy.updated_at = utcnow()
    _audit(db, policy, actor, "revoked", reason)
    db.commit(); db.refresh(policy)
    return policy


def preview_preapproval(db: Session, policy: ChangePreapprovalPolicy, plan: GovernedChangePlan,
                        *, now: datetime | None = None,
                        execution_claim: ChangePreapprovalBudgetClaim | None = None) -> dict:
    """Check a concrete plan; no result from this method authorizes execution."""
    now = (now or utcnow()).astimezone(UTC)
    namespace = _scope(db)
    if (policy.tenant_id, policy.region_id) != namespace or (plan.tenant_id, plan.region_id) != namespace:
        raise LookupError("Preapproval policy or plan not found")
    reasons: list[str] = []
    matched_alert_id: str | None = None
    budget_used: int | None = None
    budget_limit: int | None = None
    if policy.status != "reviewed" or policy.review_sha256 != digest(_material(policy)):
        reasons.append("policy_not_currently_reviewed")
    if as_utc(policy.expires_at) <= now:
        reasons.append("policy_expired")
    if not _current_reviewer(db, policy, policy.reviewed_by_principal_id, policy.reviewed_by):
        reasons.append("reviewer_identity_not_current")
    allowed_states = {"ready_for_approval", "approved"} if execution_claim is not None else {"ready_for_approval"}
    if plan.status not in allowed_states or plan.risk_class != "low":
        reasons.append("plan_not_low_risk_ready")
    if plan.tool_contract_snapshot.get("requires_maintenance_window", True) and (
        plan.maintenance_window_start is None or plan.maintenance_window_end is None
        or not as_utc(plan.maintenance_window_start) <= now <= as_utc(plan.maintenance_window_end)
    ):
        reasons.append("maintenance_window_not_active")
    try:
        proposal = db.get(AgentActionProposal, plan.action_proposal_id)
        investigation = db.get(Investigation, plan.investigation_id)
        if (proposal is None or investigation is None or proposal.investigation_id != plan.investigation_id
            or (proposal.tenant_id, proposal.region_id) != namespace
            or (investigation.tenant_id, investigation.region_id) != namespace):
            raise ValueError("Missing exact proposal or investigation")
        _assert_plan_current(db, plan, proposal)
    except (LookupError, PermissionError, TypeError, KeyError, ValueError):
        reasons.append("governed_plan_evidence_invalid")
        proposal = None; investigation = None
    if proposal is not None and investigation is not None:
        if not _prerequisites_fresh(db, plan, now=now,
            max_age_seconds=policy.max_evidence_age_seconds):
            reasons.append("prerequisite_evidence_stale")
        semantic_contract = None
        try:
            spec, contract = _version_contract(db, policy.tool_artifact_version_id, policy.tool_content_hash)
            device = _device(db, policy.target_device_id)
            if device.site != policy.target_site or policy.target_device_id != device.id:
                raise ValueError("Target device site changed")
            _validate_settings(db, policy, version_id=policy.tool_artifact_version_id,
                content_hash=policy.tool_content_hash, now=now, require_semantic=False)
            activation = db.scalar(select(MCPToolActivation).where(
                MCPToolActivation.artifact_version_id == policy.tool_artifact_version_id,
                MCPToolActivation.tool_registration_id == proposal.tool_id,
                MCPToolActivation.status == "active",
                MCPToolActivation.tenant_id == namespace[0], MCPToolActivation.region_id == namespace[1]))
            tool = db.scalar(select(AgentToolRegistration).where(
                AgentToolRegistration.id == proposal.tool_id,
                AgentToolRegistration.tenant_id == namespace[0], AgentToolRegistration.region_id == namespace[1]))
            if (activation is None or tool is None or proposal.tool_id != plan.tool_contract_snapshot["action_tool"]["tool_id"]
                or tool_artifact_provenance(db, tool).get("artifact_version_id") != policy.tool_artifact_version_id
                or activation.input_schema_sha256 != digest(spec["input_schema"])
                or activation.output_schema_sha256 != digest(spec["output_schema"])):
                raise ValueError("Tool activation differs from reviewed version")
            server = db.scalar(select(MCPServer).where(MCPServer.id == activation.server_id,
                MCPServer.tenant_id == namespace[0], MCPServer.region_id == namespace[1])
                .execution_options(populate_existing=True))
            profile = None
            if server is not None and server.credential_profile_ref:
                profile = db.scalar(select(CredentialProfile).where(
                    or_(CredentialProfile.id == server.credential_profile_ref,
                        CredentialProfile.name == server.credential_profile_ref),
                    CredentialProfile.tenant_id == namespace[0],
                    CredentialProfile.region_id == namespace[1]).execution_options(populate_existing=True))
            profiles = {profile.id: profile, profile.name: profile} if profile is not None else {}
            blockers, _, _, _ = _mcp_tool_blockers(_version(db, policy.tool_artifact_version_id),
                activation, {tool.id: tool}, {server.id: server} if server is not None else {}, profiles)
            if blockers:
                raise ValueError("Preapproval Tool runtime is not ready")
            arguments = copy.deepcopy(proposal.arguments)
            key = _extract_path(arguments, contract.idempotency_key_argument_path)
            if not isinstance(key, str) or not key or key == IDEMPOTENCY_PLACEHOLDER:
                raise ValueError("Action idempotency key is invalid")
            _set_path(arguments, contract.idempotency_key_argument_path, IDEMPOTENCY_PLACEHOLDER)
            if arguments != policy.arguments_template or plan.target_snapshot.get(next(
                path for path, kind in contract.authorization_target_paths.items() if kind == "device_id")) != device.id:
                raise ValueError("Action arguments differ from reviewed template")
            validate_instance(proposal.arguments, spec["input_schema"], "proposed preapproval arguments")
            semantic_contract = contract
        except (LookupError, PermissionError, TypeError, KeyError, StopIteration, ValueError):
            reasons.append("tool_or_target_template_drift")
        if semantic_contract is not None:
            semantic_reason = _semantic_precondition(db, plan, proposal, semantic_contract, now=now)
            if semantic_reason is not None:
                reasons.append(semantic_reason)
        origin = plan.tool_contract_snapshot.get("origin")
        frozen_alerts = origin.get("alerts") if isinstance(origin, dict) else None
        if (not isinstance(origin, dict) or origin.get("contract") != "icheck.plan-origin/v1"
            or origin.get("situation_id") != investigation.situation_id or origin.get("truncated") is not False
            or not isinstance(frozen_alerts, list) or len(frozen_alerts) > MAX_FROZEN_ORIGIN_ALERTS
            or not all(isinstance(item, dict) and isinstance(item.get("id"), str)
                and isinstance(item.get("identity_sha256"), str)
                and len(item["identity_sha256"]) == 64 for item in frozen_alerts)
            or len({item["id"] for item in frozen_alerts}) != len(frozen_alerts)):
            reasons.append("plan_origin_not_frozen")
            frozen_alerts = []
        frozen_alert_ids = [item["id"] for item in frozen_alerts]
        alert = _matching_alert(db, investigation, policy, namespace, now, frozen_alert_ids)
        if alert is None:
            reasons.append("no_fresh_exact_device_alert")
        else:
            matched_alert_id = alert.id
            frozen_identity = next(item["identity_sha256"] for item in frozen_alerts if item["id"] == alert.id)
            if frozen_alert_identity_hash(alert) != frozen_identity:
                reasons.append("frozen_alert_identity_drift")
            budget_used, budget_limit = _budget_state(db, alert.id, policy.max_actions_per_alert)
            owns_slot = bool(execution_claim is not None
                and (execution_claim.tenant_id, execution_claim.region_id) == namespace
                and execution_claim.policy_id == policy.id
                and execution_claim.change_plan_id == plan.id
                and execution_claim.alert_id == alert.id
                and execution_claim.policy_review_sha256 == policy.review_sha256
                and execution_claim.plan_hash == plan.plan_hash)
            if (budget_used > budget_limit if owns_slot else budget_used >= budget_limit):
                reasons.append("alert_action_budget_exhausted")
            if execution_claim is not None and not owns_slot:
                reasons.append("execution_budget_binding_invalid")
        if policy.reviewed_by == proposal.requested_by or (policy.reviewed_by_principal_id and policy.reviewed_by_principal_id == proposal.requested_by_principal_id):
            reasons.append("reviewer_is_action_requester")
    candidate_matches = not reasons
    from ..config import get_settings
    reasons.append("execution_grant_and_admission_required" if get_settings().enable_reviewed_change_execution
        else "semantic_and_execution_gates_unavailable")
    return {"policy_id": policy.id, "change_plan_id": plan.id,
        "candidate_matches": candidate_matches, "blocking_reasons": reasons,
        "matched_alert_id": matched_alert_id, "budget_used": budget_used,
        "budget_limit": budget_limit,
        "authorizes_execution": False}


def claim_preapproval_budget(db: Session, policy_id: str, plan_id: str, *, actor: PrincipalContext,
                             commit: bool = True) -> ChangePreapprovalBudgetClaim:
    """Consume one Alert slot durably; never approves a plan or executes a Tool.

    The execution gate uses commit=False so its debit, approval and immutable
    decision share one transaction. A standalone claim still grants no authority.
    """
    require_locking_transaction(db, purpose="Preapproval budget claims")
    # Concurrent claims for different Alerts may share the reviewed policy
    # read lock. Policy revision/revocation still needs an exclusive lock.
    policy = get_preapproval(db, policy_id, shared_lock=True)
    tenant_id, region_id = _scope(db)
    if (actor.tenant_id, actor.region_id) != (tenant_id, region_id):
        raise PermissionError("Budget claim actor is outside the selected namespace")
    plan = db.scalar(select(GovernedChangePlan).where(GovernedChangePlan.id == plan_id,
        GovernedChangePlan.tenant_id == tenant_id, GovernedChangePlan.region_id == region_id)
        .with_for_update().execution_options(populate_existing=True))
    if plan is None:
        raise LookupError("Governed change plan not found")
    existing = db.scalar(select(ChangePreapprovalBudgetClaim).where(
        ChangePreapprovalBudgetClaim.change_plan_id == plan.id,
        ChangePreapprovalBudgetClaim.tenant_id == tenant_id,
        ChangePreapprovalBudgetClaim.region_id == region_id))
    if existing is not None:
        if (existing.policy_id != policy.id
            or existing.policy_review_sha256 != policy.review_sha256
            or existing.plan_hash != plan.plan_hash):
            raise ValueError("A different preapproval claim already owns this change plan")
        if (policy.review_sha256 != digest(_material(policy))
            or plan.plan_hash != _plan_hash(plan)):
            raise ValueError("The original preapproval claim binding is no longer current")
        # An exact retry only retrieves its immutable debit. It does not
        # reassert current eligibility or grant execution authority.
        if commit:
            db.commit()  # Caller-owned authorization transactions retain locks.
        return existing
    first = preview_preapproval(db, policy, plan)
    alert_id = first["matched_alert_id"]
    if alert_id is None:
        raise ValueError("No current exact-device Alert can consume a budget slot")
    # PostgreSQL row locking serializes all policies claiming the same Alert.
    # The unique plan constraint separately makes retries idempotent.
    alert = db.scalar(select(Alert).where(Alert.id == alert_id,
        Alert.tenant_id == tenant_id, Alert.region_id == region_id).with_for_update()
        .execution_options(populate_existing=True))
    if alert is None:
        raise LookupError("Alert no longer exists in this namespace")
    current = preview_preapproval(db, policy, plan)
    if not current["candidate_matches"] or current["matched_alert_id"] != alert.id:
        raise ValueError("Preapproval policy, plan or Alert budget is no longer eligible")
    claim = ChangePreapprovalBudgetClaim(policy_id=policy.id, alert_id=alert.id,
        change_plan_id=plan.id, policy_review_sha256=policy.review_sha256,
        plan_hash=plan.plan_hash, policy_limit_snapshot=policy.max_actions_per_alert,
        claimed_by=actor.subject, claimed_at=utcnow())
    db.add(claim); db.flush()
    record_audit_event(db, event_type="change.preapproval.budget_claimed", actor_type=actor.principal_type,
        actor_id=actor.subject, entity_type="change_preapproval_budget_claim", entity_id=claim.id,
        details={"policy_id": policy.id, "plan_id": plan.id, "alert_id": alert.id,
            "policy_review_sha256": policy.review_sha256, "plan_hash": plan.plan_hash,
            "policy_limit_snapshot": claim.policy_limit_snapshot})
    if commit:
        db.commit(); db.refresh(claim)
    return claim
