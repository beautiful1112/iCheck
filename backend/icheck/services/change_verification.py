"""Revalidate persisted change evidence; model prose and state labels are not proof."""
from __future__ import annotations

import hashlib
import math
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from ..models import AgentActionProposal, GovernedChangeEvidence, GovernedChangePlan, InvestigationToolCall, utcnow
from .collectors import validate_instance


def scoped_row(db: Session, model, row_id: str | None, plan: GovernedChangePlan):
    query = select(model).where(model.id == row_id,
        model.tenant_id == plan.tenant_id, model.region_id == plan.region_id
    ).execution_options(populate_existing=True)
    if model is InvestigationToolCall:
        query = query.options(defer(model.arguments), defer(model.result), defer(model.error))
    return db.scalar(query) if row_id else None


def semantic_observation(expectations: list[dict], action_arguments: dict,
                         precheck_result: dict, postcheck_result: dict, *,
                         precheck_finished: datetime, action_started: datetime,
                         action_finished: datetime, postcheck_finished: datetime) -> dict:
    """Recompute bounded desired-state transitions without returning raw values."""
    from .capability_quality import as_utc, digest
    from .change_governance import _extract_path
    if not 1 <= len(expectations) <= 8:
        raise ValueError("Semantic expectations are missing or unbounded")
    checks = []
    for index, item in enumerate(expectations):
        value_type = item["value_type"]
        expected = _extract_path(action_arguments, item["action_argument_path"])
        before = _extract_path(precheck_result, item["precheck_observation_path"])
        after = _extract_path(postcheck_result, item["postcheck_observation_path"])
        if value_type == "boolean":
            valid = all(type(value) is bool for value in (expected, before, after))
        elif value_type == "integer":
            valid = all(type(value) is int for value in (expected, before, after))
        elif value_type == "number":
            valid = all(type(value) is int or (type(value) is float and math.isfinite(value))
                for value in (expected, before, after))
        elif value_type == "string":
            valid = all(type(value) is str for value in (expected, before, after))
        else:
            raise ValueError("Semantic expectation has an invalid scalar type")
        if not valid:
            raise ValueError("Semantic observations do not match their frozen scalar type")
        before_age = (as_utc(action_started) - as_utc(precheck_finished)).total_seconds()
        after_delay = (as_utc(postcheck_finished) - as_utc(action_finished)).total_seconds()
        checks.append({"index": index, "before_different": before != expected,
            "after_matches": after == expected,
            "before_fresh": 0 <= before_age <= item["max_precheck_age_seconds"],
            "after_timely": 0 <= after_delay <= item["max_postcheck_delay_seconds"]})
    return {"contract": "icheck.semantic-observation/v1",
        "requirements_sha256": digest(expectations),
        "checks": checks,
        "passed": all(item["before_different"] and item["after_matches"]
            and item["before_fresh"] and item["after_timely"] for item in checks)}


def _time(value: datetime | None) -> datetime:
    from .change_governance import _as_utc
    if value is None:
        raise ValueError("Change evidence has no complete causal timestamps")
    return _as_utc(value)


def rollback_observation(expectations: list[dict], semantic_expectations: list[dict],
                         precheck_result: dict, check_result: dict, *,
                         precheck_finished: datetime, action_started: datetime,
                         rollback_finished: datetime, check_finished: datetime) -> dict:
    """Compare original state with fresh restoration observations, without values."""
    from .change_governance import _extract_path
    if not 1 <= len(expectations) <= 8:
        raise ValueError("Rollback restoration expectations are missing or unbounded")
    freshness = {}
    for item in semantic_expectations:
        path = item["precheck_observation_path"]
        freshness[path] = min(freshness.get(path, item["max_precheck_age_seconds"]), item["max_precheck_age_seconds"])
    checks = []
    for index, item in enumerate(expectations):
        before = _extract_path(precheck_result, item["precheck_observation_path"])
        after = _extract_path(check_result, item["rollback_observation_path"])
        kind = item["value_type"]
        valid = {
            "boolean": lambda value: type(value) is bool,
            "integer": lambda value: type(value) is int,
            "number": lambda value: type(value) is int or (type(value) is float and math.isfinite(value)),
            "string": lambda value: type(value) is str,
        }.get(kind)
        if valid is None or not all(valid(value) for value in (before, after)):
            raise ValueError("Rollback observations do not match their frozen scalar type")
        age = (_time(action_started) - _time(precheck_finished)).total_seconds()
        delay = (_time(check_finished) - _time(rollback_finished)).total_seconds()
        checks.append({"index": index, "restored": before == after,
            "before_fresh": 0 <= age <= freshness[item["precheck_observation_path"]],
            "after_timely": 0 <= delay <= item["max_check_delay_seconds"]})
    return {"contract": "icheck.rollback-observation/v1", "checks": checks,
        "passed": all(item["restored"] and item["before_fresh"] and item["after_timely"] for item in checks)}


def validate_call(call: InvestigationToolCall, snapshot: dict, plan: GovernedChangePlan, *, now: datetime) -> None:
    from .change_governance import _hash_document
    if ((call.tenant_id, call.region_id) != (plan.tenant_id, plan.region_id)
        or call.investigation_id != plan.investigation_id or call.tool_id != snapshot.get("tool_id")):
        raise ValueError("Change evidence identity does not match the frozen plan")
    for field in ("input_schema", "output_schema"):
        schema = snapshot.get(field)
        if not isinstance(schema, dict) or _hash_document(schema) != snapshot.get(field + "_hash"):
            raise ValueError("Change evidence has no integrity-bound frozen schema")
    validate_instance(call.arguments, snapshot["input_schema"], "change evidence arguments")
    material = {"tool_id": call.tool_id, "arguments": call.arguments}
    if call.governed_change_plan_id is not None:
        material.update(governed_change_plan_id=call.governed_change_plan_id, governed_stage=call.governed_stage)
    if call.call_hash != _hash_document(material):
        raise ValueError("Change evidence arguments no longer match their persisted hash")
    if not _time(call.started_at) <= _time(call.finished_at) <= _time(now):
        raise ValueError("Change evidence timestamps are invalid")
    if call.status == "succeeded":
        validate_instance(call.result, snapshot["output_schema"], "change evidence result")
        if call.result_hash != _hash_document(call.result):
            raise ValueError("Change evidence result no longer matches its persisted hash")
    elif call.status != "failed" or call.result_hash is not None:
        raise ValueError("Change evidence is not a terminal execution")


def validate_peer_action(db: Session, plan: GovernedChangePlan, proposal: AgentActionProposal,
                         call: InvestigationToolCall, snapshot: dict, *, now: datetime) -> None:
    from .agent_approvals import action_plan_hash
    from .preapproval_execution import assert_authorization_receipt
    if proposal.rollback_of_change_plan_id is not None:
        from .rollback_execution import assert_rollback_receipt
        assert_rollback_receipt(db, proposal, plan)
    else:
        assert_authorization_receipt(db, proposal, plan)
    if ((proposal.tenant_id, proposal.region_id) != (plan.tenant_id, plan.region_id)
        or proposal.investigation_id != plan.investigation_id or proposal.tool_call_id != call.id
        or proposal.tool_id != call.tool_id or proposal.arguments != call.arguments
        or proposal.status != call.status or proposal.result_hash != call.result_hash
        or proposal.plan_hash != action_plan_hash(tool_id=proposal.tool_id, arguments=proposal.arguments, purpose=proposal.purpose)
        or not proposal.approved_by or proposal.approved_by == proposal.requested_by
        or (proposal.requested_by_principal_id and proposal.requested_by_principal_id == proposal.approved_by_principal_id)):
        raise ValueError("Change outcome has no exact separately approved action")
    validate_call(call, snapshot, plan, now=now)
    if not (_time(plan.created_at) <= _time(proposal.decided_at) <= _time(proposal.execution_started_at)
        <= _time(call.started_at) <= _time(call.finished_at) <= _time(proposal.execution_finished_at) <= _time(now)):
        raise ValueError("Change action has no valid approval/execution sequence")


def action_for_plan(db: Session, plan: GovernedChangePlan, *, now: datetime):
    from .change_governance import _extract_path
    proposal = scoped_row(db, AgentActionProposal, plan.action_proposal_id, plan)
    call = scoped_row(db, InvestigationToolCall, proposal.tool_call_id if proposal else None, plan)
    if proposal is None or call is None:
        raise ValueError("Change outcome has no persisted action call")
    snapshot = plan.tool_contract_snapshot
    validate_peer_action(db, plan, proposal, call, snapshot.get("action_tool", {}), now=now)
    if snapshot.get("action_plan_hash") != proposal.plan_hash or snapshot.get("action_tool", {}).get("read_only") is not False:
        raise ValueError("Change action does not match its governed contract")
    for path, value in plan.target_snapshot.items():
        if _extract_path(call.arguments, path) != value:
            raise ValueError("Change outcome target has drifted")
    key = _extract_path(call.arguments, snapshot["idempotency_key_argument_path"])
    if not isinstance(key, str) or hashlib.sha256(key.encode()).hexdigest() != plan.idempotency_key_hash:
        raise ValueError("Change outcome idempotency binding has drifted")
    if not plan.approved_plan_hash:
        raise ValueError("Change outcome has no governed approval hash")
    return proposal, call


def rollback_for_plan(db: Session, plan: GovernedChangePlan, *, now: datetime):
    from .change_governance import _hash_document, _latest_evidence, _stage_contract
    evidence = _latest_evidence(plan).get("rollback")
    call = scoped_row(db, InvestigationToolCall, evidence.tool_call_id if evidence else None, plan)
    proposal = db.scalar(select(AgentActionProposal).where(
        AgentActionProposal.tool_call_id == call.id,
        AgentActionProposal.rollback_of_change_plan_id == plan.id,
        AgentActionProposal.tenant_id == plan.tenant_id,
        AgentActionProposal.region_id == plan.region_id,
    )) if call is not None else None
    if evidence is None or call is None or proposal is None:
        raise ValueError("Restoration check has no bound rollback action")
    passed, summary = validate_stage_call(db, plan, "rollback", call, now=now)
    expected = {"contract": "icheck.change-evidence/v1", "stage": "rollback",
        "tool_id": call.tool_id, "tool_name": _stage_contract(plan, "rollback").get("tool_name"),
        "tool_call_id": call.id, "arguments_hash": _hash_document(call.arguments),
        "result_hash": call.result_hash, "passed": passed, "summary": summary}
    if (not passed or evidence.passed is not True or evidence.tool_id != call.tool_id
        or evidence.arguments_hash != expected["arguments_hash"]
        or evidence.result_hash != call.result_hash or evidence.evidence_snapshot != expected
        or not _time(call.finished_at) <= _time(evidence.created_at) <= _time(now)):
        raise ValueError("Restoration check rollback evidence has drifted")
    return proposal, call


def stage_not_before(db: Session, plan: GovernedChangePlan, stage: str, *, now: datetime) -> datetime:
    if stage == "precheck":
        return _time(plan.created_at)
    if stage == "dry_run":
        evidence = db.scalar(select(GovernedChangeEvidence).where(
            GovernedChangeEvidence.change_plan_id == plan.id, GovernedChangeEvidence.stage == "precheck",
            GovernedChangeEvidence.tenant_id == plan.tenant_id, GovernedChangeEvidence.region_id == plan.region_id,
        ).order_by(GovernedChangeEvidence.created_at.desc(), GovernedChangeEvidence.id.desc()).limit(1))
        call = scoped_row(db, InvestigationToolCall, evidence.tool_call_id if evidence else None, plan)
        if evidence is None:
            call = db.scalar(select(InvestigationToolCall).where(
                InvestigationToolCall.governed_change_plan_id == plan.id, InvestigationToolCall.governed_stage == "precheck",
                InvestigationToolCall.tenant_id == plan.tenant_id, InvestigationToolCall.region_id == plan.region_id,
            ))
            if call is None or validate_stage_call(db, plan, "precheck", call, now=now)[0] is not True:
                raise ValueError("Dry-run requires a prior passed pre-check")
        elif not evidence.passed or call is None:
            raise ValueError("Dry-run requires a prior passed pre-check")
        return _time(call.finished_at)
    if stage == "rollback_check":
        _, rollback = rollback_for_plan(db, plan, now=now)
        return _time(rollback.finished_at)
    _, action = action_for_plan(db, plan, now=now)
    if stage == "rollback" and action.status != "failed":
        evidence = db.scalar(select(GovernedChangeEvidence).where(
            GovernedChangeEvidence.change_plan_id == plan.id, GovernedChangeEvidence.stage == "postcheck",
            GovernedChangeEvidence.tenant_id == plan.tenant_id, GovernedChangeEvidence.region_id == plan.region_id,
        ).order_by(GovernedChangeEvidence.created_at.desc(), GovernedChangeEvidence.id.desc()).limit(1))
        postcheck = scoped_row(db, InvestigationToolCall, evidence.tool_call_id if evidence else None, plan)
        if evidence is None or evidence.passed or postcheck is None or validate_stage_call(db, plan, "postcheck", postcheck, now=now)[0] is not False:
            raise ValueError("Rollback has no causal failed post-check")
        return max(_time(action.finished_at), _time(postcheck.finished_at))
    return _time(action.finished_at)


def validate_stage_call(db: Session, plan: GovernedChangePlan, stage: str, call: InvestigationToolCall,
                        *, now: datetime | None = None) -> tuple[bool, dict]:
    from .change_governance import (_extract_path, _hash_document, _latest_evidence,
        _stage_contract, change_stage_arguments)
    now = now or utcnow()
    snapshot = _stage_contract(plan, stage)
    validate_call(call, snapshot, plan, now=now)
    if call.status != "succeeded" or call.arguments != change_stage_arguments(plan, stage):
        raise ValueError("Change evidence must be a successful exact-target call")
    if (stage != "rollback" and (call.governed_change_plan_id != plan.id or call.governed_stage != stage)
        or stage == "rollback" and (call.governed_change_plan_id is not None or call.governed_stage is not None)):
        raise ValueError("Change evidence belongs to another plan or stage")
    if stage != "rollback" and (snapshot.get("read_only") is not True or call.tool_id == plan.tool_contract_snapshot["action_tool"]["tool_id"]):
        raise ValueError("Change verification must be a separate read-only Tool")
    if _time(call.started_at) < stage_not_before(db, plan, stage, now=now):
        raise ValueError("Change evidence predates the action or required preceding stage")
    if stage == "rollback":
        proposal = db.scalar(select(AgentActionProposal).where(
            AgentActionProposal.tool_call_id == call.id, AgentActionProposal.rollback_of_change_plan_id == plan.id,
            AgentActionProposal.tenant_id == plan.tenant_id, AgentActionProposal.region_id == plan.region_id,
        ))
        if proposal is None:
            raise ValueError("Rollback evidence requires its separately approved action")
        validate_peer_action(db, plan, proposal, call, snapshot, now=now)
    passed = _extract_path(call.result, snapshot["success_path"])
    if not isinstance(passed, bool):
        raise ValueError("Change evidence success path must be boolean")
    if stage in {"postcheck", "rollback_check"} and passed and plan.tool_contract_snapshot.get("semantic_expectations"):
        precheck = _latest_evidence(plan).get("precheck")
        before_call = scoped_row(db, InvestigationToolCall,
            precheck.tool_call_id if precheck else None, plan)
        if precheck is None or before_call is None:
            raise ValueError("Semantic post-check has no bound pre-check")
        before_passed, _ = validate_stage_call(db, plan, "precheck", before_call, now=now)
        if (before_passed is not True or precheck.passed is not True
            or precheck.tool_id != before_call.tool_id
            or precheck.result_hash != before_call.result_hash
            or precheck.arguments_hash != _hash_document(before_call.arguments)):
            raise ValueError("Semantic post-check pre-state evidence has drifted")
        _, action = action_for_plan(db, plan, now=now)
        if stage == "rollback_check":
            _, rollback = rollback_for_plan(db, plan, now=now)
            passed = rollback_observation(plan.tool_contract_snapshot["rollback_expectations"],
                plan.tool_contract_snapshot["semantic_expectations"], before_call.result, call.result,
                precheck_finished=before_call.finished_at, action_started=action.started_at,
                rollback_finished=rollback.finished_at, check_finished=call.finished_at)["passed"]
        else:
            passed = semantic_observation(plan.tool_contract_snapshot["semantic_expectations"],
                action.arguments, before_call.result, call.result,
                precheck_finished=before_call.finished_at, action_started=action.started_at,
                action_finished=action.finished_at, postcheck_finished=call.finished_at)["passed"]
    return passed, {path: _extract_path(call.result, path) for path in snapshot.get("summary_paths", [])}
