"""Outcome evidence from exact peer-approved actions and causal post-checks."""
from __future__ import annotations

import math
import json
import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import AgentChangeContract
from ..models import (AgentActionProposal, ArtifactVersion, ArtifactVersionStatus,
    GovernedChangePlan, Investigation, InvestigationToolCall)
from .change_verification import (action_for_plan, rollback_for_plan, rollback_observation,
    scoped_row, semantic_observation as _semantic_observation, validate_stage_call)


MAX_OUTCOME_SAMPLES = 200
MAX_OUTCOME_EVIDENCE_BYTES = 16 * 1024 * 1024


class OutcomeEvidenceBudgetExceeded(ValueError):
    pass


def _charge(budget: dict | None, *documents) -> None:
    if budget is None:
        return
    for document in documents:
        budget["remaining"] -= len(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        if budget["remaining"] < 0:
            raise OutcomeEvidenceBudgetExceeded("Outcome evidence byte budget exceeded")


def _bound_semantic_expectations(db: Session, plan: GovernedChangePlan,
                                 call: InvestigationToolCall, content_hash: str) -> list[dict]:
    version = db.scalar(select(ArtifactVersion).where(
        ArtifactVersion.id == call.artifact_version_id,
        ArtifactVersion.tenant_id == call.tenant_id,
        ArtifactVersion.region_id == call.region_id,
    ))
    if (version is None or version.status != ArtifactVersionStatus.PUBLISHED
        or version.content_hash != content_hash):
        raise ValueError("Outcome has no matching published Tool version")
    spec = version.definition.get("spec", {})
    if spec.get("read_only") is not False:
        raise ValueError("Outcome version is not a state-changing Tool")
    contract = AgentChangeContract.model_validate(spec.get("change_contract"))
    declared = [item.model_dump() for item in contract.semantic_expectations]
    frozen = plan.tool_contract_snapshot.get("semantic_expectations", [])
    if not isinstance(frozen, list) or len(frozen) != len(declared):
        raise ValueError("Outcome semantic requirements differ from the published Tool")
    for source, item in zip(declared, frozen):
        if not isinstance(item, dict) or {key: item.get(key) for key in source} != source:
            raise ValueError("Outcome semantic requirements differ from the published Tool")
    rollback_step = plan.tool_contract_snapshot.get("steps", {}).get("rollback_check")
    rollback_requirements = plan.tool_contract_snapshot.get("rollback_expectations", [])
    if contract.rollback_check is None:
        if rollback_step is not None or rollback_requirements:
            raise ValueError("Outcome restoration requirements were not published")
    else:
        from .change_governance import _step_mapping
        source = contract.rollback_check
        if (not isinstance(rollback_step, dict) or rollback_step.get("read_only") is not True
            or rollback_step.get("tool_name") != source.tool_name
            or rollback_step.get("success_path") != source.success_path
            or rollback_step.get("argument_mapping") != _step_mapping(source, contract.target_argument_paths)
            or rollback_step.get("summary_paths") != source.summary_paths):
            raise ValueError("Outcome restoration Tool differs from the published contract")
        declared_rollback = [item.model_dump() for item in contract.rollback_expectations]
        if not isinstance(rollback_requirements, list) or len(declared_rollback) != len(rollback_requirements):
            raise ValueError("Outcome restoration requirements differ from the published Tool")
        for source, item in zip(declared_rollback, rollback_requirements):
            if not isinstance(item, dict) or {key: item.get(key) for key in source} != source:
                raise ValueError("Outcome restoration requirements differ from the published Tool")
    return frozen


def outcome_evidence(db: Session, call: InvestigationToolCall, *, version_id: str,
                     content_hash: str, now: datetime, budget: dict | None = None) -> dict:
    from .capability_quality import as_utc, digest
    from .change_governance import _plan_hash
    if (call.artifact_version_id != version_id or call.artifact_content_hash != content_hash
        or not call.artifact_activation_id
        or not re.fullmatch(r"[0-9a-f]{64}", call.artifact_activation_sha256 or "")):
        raise ValueError("Outcome action has no exact Artifact/activation pins")
    proposal = db.scalar(select(AgentActionProposal).where(
        AgentActionProposal.tool_call_id == call.id, AgentActionProposal.investigation_id == call.investigation_id,
        AgentActionProposal.tenant_id == call.tenant_id, AgentActionProposal.region_id == call.region_id,
    ).execution_options(populate_existing=True))
    if proposal is None or proposal.rollback_of_change_plan_id is not None:
        raise ValueError("Outcome execution has no governed remediation proposal")
    plan = db.scalar(select(GovernedChangePlan).where(
        GovernedChangePlan.action_proposal_id == proposal.id, GovernedChangePlan.investigation_id == call.investigation_id,
        GovernedChangePlan.tenant_id == call.tenant_id, GovernedChangePlan.region_id == call.region_id,
    ).options(selectinload(GovernedChangePlan.evidence)).execution_options(populate_existing=True))
    if plan is None or len(plan.evidence) > 5:
        raise ValueError("Outcome has no bounded governed evidence")
    semantic_expectations = _bound_semantic_expectations(db, plan, call, content_hash)
    _charge(budget, plan.tool_contract_snapshot, plan.target_snapshot, plan.authorization_scope_snapshot,
        proposal.arguments, call.arguments, call.result)
    stages = {item.stage: item for item in plan.evidence}
    if len(stages) != len(plan.evidence) or plan.plan_hash != _plan_hash(plan):
        raise ValueError("Outcome plan or evidence history has drifted")
    after_approval = sum(item.stage in {"postcheck", "rollback", "rollback_check"} for item in plan.evidence)
    if plan.approved_plan_hash != _plan_hash(plan, revision=plan.revision - after_approval):
        raise ValueError("Outcome approval does not bind the preceding evidence")
    investigation = scoped_row(db, Investigation, plan.investigation_id, plan)
    if investigation is None or investigation.authorization_scope != plan.authorization_scope_snapshot:
        raise ValueError("Outcome authorization scope has drifted")
    _, action = action_for_plan(db, plan, now=now)
    if action.id != call.id:
        raise ValueError("Outcome action identity has drifted")
    if plan.tool_contract_snapshot.get("requires_maintenance_window", True):
        if not (plan.maintenance_window_start and plan.maintenance_window_end
            and as_utc(plan.maintenance_window_start) <= as_utc(proposal.decided_at)
            <= as_utc(proposal.execution_started_at) <= as_utc(plan.maintenance_window_end)):
            raise ValueError("Outcome action did not execute in its approved window")
    evidence = []
    finished = as_utc(call.finished_at)
    passed_stages = {}
    observation_results = {}
    observation_finished = {}
    for stage in ("precheck", "dry_run", "postcheck", "rollback", "rollback_check"):
        item = stages.get(stage)
        if item is None:
            if stage in {"precheck", "dry_run"}:
                raise ValueError("Outcome has no prerequisite evidence")
            continue
        stage_call = scoped_row(db, InvestigationToolCall, item.tool_call_id, plan)
        if stage_call is None or (item.tenant_id, item.region_id) != (call.tenant_id, call.region_id):
            raise ValueError("Outcome evidence crosses namespace boundaries")
        _charge(budget, stage_call.arguments, stage_call.result, item.evidence_snapshot)
        passed, summary = validate_stage_call(db, plan, stage, stage_call, now=now)
        frozen = plan.tool_contract_snapshot["rollback"] if stage == "rollback" else plan.tool_contract_snapshot["steps"][stage]
        expected = {"contract": "icheck.change-evidence/v1", "stage": stage,
            "tool_id": stage_call.tool_id, "tool_name": frozen.get("tool_name"), "tool_call_id": stage_call.id,
            "arguments_hash": digest(stage_call.arguments), "result_hash": stage_call.result_hash,
            "passed": passed, "summary": summary}
        if (item.tool_id != stage_call.tool_id or item.arguments_hash != expected["arguments_hash"]
            or item.result_hash != stage_call.result_hash or item.passed is not passed or item.evidence_snapshot != expected
            or as_utc(item.created_at) < as_utc(stage_call.finished_at) or as_utc(item.created_at) > now):
            raise ValueError("Outcome evidence no longer matches its persisted call")
        passed_stages[stage] = passed
        if stage in {"precheck", "postcheck", "rollback_check"}:
            observation_results[stage] = stage_call.result
            observation_finished[stage] = stage_call.finished_at
        evidence.append({"stage": stage, "evidence_id": item.id, "tool_call_id": stage_call.id,
            "arguments_sha256": item.arguments_hash, "result_sha256": item.result_hash,
            "passed": passed, "started_at": as_utc(stage_call.started_at).isoformat(),
            "finished_at": as_utc(stage_call.finished_at).isoformat()})
        if stage in {"postcheck", "rollback", "rollback_check"}:
            finished = max(finished, as_utc(stage_call.finished_at))
        db.expire(stage_call, ["arguments", "result"])
    if not all(passed_stages.get(stage) is True for stage in ("precheck", "dry_run")):
        raise ValueError("Outcome prerequisites did not pass")
    if plan.status == "verified" and call.status == "succeeded" and passed_stages.get("postcheck") is True and "rollback" not in stages:
        outcome = "verified"
    elif (plan.status == "rolled_back" and passed_stages.get("rollback") is True
        and ("rollback_check" not in plan.tool_contract_snapshot["steps"] or passed_stages.get("rollback_check") is True)):
        outcome = "rolled_back"
    elif plan.status == "rollback_failed" and (passed_stages.get("rollback") is False or passed_stages.get("rollback_check") is False):
        outcome = "rollback_failed"
    elif plan.status == "rollback_required" and (call.status == "failed" or passed_stages.get("postcheck") is False):
        outcome = "failed"
    elif (plan.status == "awaiting_rollback_check" and passed_stages.get("rollback") is True
        and "rollback_check" not in stages):
        outcome = "failed"
    elif plan.status == "awaiting_postcheck" and call.status == "succeeded" and "postcheck" not in stages:
        outcome = "unverified"
    else:
        raise ValueError("Outcome state is not supported by its causal evidence")

    semantic = None
    if semantic_expectations and call.status == "succeeded" and "postcheck" in stages:
        semantic = _semantic_observation(semantic_expectations, call.arguments,
            observation_results["precheck"], observation_results["postcheck"],
            precheck_finished=observation_finished["precheck"],
            action_started=call.started_at, action_finished=call.finished_at,
            postcheck_finished=observation_finished["postcheck"])
        if not semantic["passed"] and outcome in {"verified", "failed"}:
            from .change_governance import _extract_path
            raw_postcheck_passed = _extract_path(observation_results["postcheck"],
                plan.tool_contract_snapshot["steps"]["postcheck"]["success_path"])
            if raw_postcheck_passed is True:
                outcome = "semantic_mismatch"
    result = {"source": "remediation_outcome", "id": call.id, "status": call.status,
        "passed": outcome == "verified", "outcome": outcome,
        "verification_basis": "structured_state_transition" if semantic else "declared_boolean_postcheck",
        "change_plan_id": plan.id,
        "plan_sha256": plan.plan_hash, "approved_plan_sha256": plan.approved_plan_hash,
        "target_sha256": digest(plan.target_snapshot), "authorization_scope_sha256": digest(plan.authorization_scope_snapshot),
        "idempotency_sha256": plan.idempotency_key_hash, "arguments_sha256": digest(call.arguments),
        "content_hash": content_hash, "activation_id": call.artifact_activation_id,
        "activation_sha256": call.artifact_activation_sha256,
        "started_at": as_utc(call.started_at).isoformat(), "finished_at": finished.isoformat(),
        "duration_ms": math.ceil((finished - as_utc(call.started_at)).total_seconds() * 1000), "stages": evidence}
    if semantic is not None:
        result["semantic_verification"] = semantic
    if "rollback" in stages:
        result["rollback_verification_basis"] = (
            "structured_state_restoration" if "rollback_check" in stages else "declared_boolean_rollback")
    if "rollback_check" in stages:
        _, rollback = rollback_for_plan(db, plan, now=now)
        result["rollback_verification"] = rollback_observation(
            plan.tool_contract_snapshot["rollback_expectations"], semantic_expectations,
            observation_results["precheck"], observation_results["rollback_check"],
            precheck_finished=observation_finished["precheck"], action_started=call.started_at,
            rollback_finished=rollback.finished_at, check_finished=observation_finished["rollback_check"])
        from .change_governance import _extract_path
        reported_success = _extract_path(observation_results["rollback_check"],
            plan.tool_contract_snapshot["steps"]["rollback_check"]["success_path"])
        result["rollback_verification"]["reported_success"] = reported_success
        result["rollback_verification"]["passed"] = result["rollback_verification"]["passed"] and reported_success is True
    return result


def observe_outcomes(db: Session, rows, policy, now: datetime):
    from .capability_quality import as_utc
    samples, reasons, latest, seen = [], [], None, {}
    budget = {"remaining": MAX_OUTCOME_EVIDENCE_BYTES}
    for call in rows[:MAX_OUTCOME_SAMPLES]:
        try:
            item = outcome_evidence(db, call, version_id=policy.artifact_version_id,
                content_hash=policy.content_hash, now=now, budget=budget)
        except (KeyError, TypeError, ValueError) as exc:
            if (not isinstance(exc, OutcomeEvidenceBudgetExceeded) and call.status == "running"
                and call.started_at and 0 <= (now - as_utc(call.started_at)).total_seconds() * 1000 <= policy.max_p95_ms):
                continue
            item = {"source": "remediation_outcome", "id": call.id, "status": "unverified", "outcome": "invalid",
                "passed": False, "content_hash": policy.content_hash,
                "started_at": as_utc(call.started_at).isoformat() if call.started_at else None,
                "finished_at": as_utc(call.finished_at).isoformat() if call.finished_at else None,
                "duration_ms": max(0, math.ceil(((as_utc(call.finished_at) if call.finished_at else now) - as_utc(call.started_at)).total_seconds()*1000)) if call.started_at else 0}
            reasons.append("invalid_remediation_outcome_evidence")
            if isinstance(exc, OutcomeEvidenceBudgetExceeded):
                reasons.append("outcome_evidence_byte_budget_exceeded")
        finally:
            db.expire(call, ["arguments", "result"])
        if item.get("idempotency_sha256"):
            key = (item["idempotency_sha256"], item["target_sha256"])
            if key in seen:
                if seen[key] != item["arguments_sha256"]:
                    reasons.append("remediation_idempotency_collision")
                continue  # A replay cannot earn another independent purpose sample.
            seen[key] = item["arguments_sha256"]
        if item["outcome"] == "unverified":
            duration = math.ceil((now - as_utc(call.started_at)).total_seconds() * 1000)
            if duration <= policy.max_p95_ms:
                continue  # Allow the bounded verification stage to finish.
            item["duration_ms"] = duration
            reasons.append("remediation_verification_overdue")
        samples.append(item)
        if item["finished_at"] and item["outcome"] != "invalid":
            finished = datetime.fromisoformat(item["finished_at"])
            latest = max(latest, finished) if latest else finished
    return samples, list(dict.fromkeys(reasons)), latest


def assert_outcome_manifest_current(db: Session, assessment, *, now: datetime) -> None:
    from .capability_quality import _query
    from sqlalchemy.orm import defer
    budget = {"remaining": MAX_OUTCOME_EVIDENCE_BYTES}
    for item in assessment.evidence_manifest:
        call = db.scalar(_query(db, InvestigationToolCall).where(InvestigationToolCall.id == item["id"]).options(
            defer(InvestigationToolCall.arguments), defer(InvestigationToolCall.result), defer(InvestigationToolCall.error)
        ).execution_options(populate_existing=True))
        try:
            if call is None or outcome_evidence(db, call,
                version_id=assessment.artifact_version_id, content_hash=assessment.content_hash,
                now=now, budget=budget) != item:
                raise ValueError("Current outcome assessment sources have drifted")
        finally:
            if call is not None:
                db.expire(call, ["arguments", "result"])
