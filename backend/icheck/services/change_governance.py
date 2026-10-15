from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..database import session_namespace
from ..agent_schemas import (
    AgentChangeContract,
    GovernedChangeEvidenceAttach,
    GovernedChangeWindowUpdate,
)
from ..models import (
    AgentActionProposal,
    AgentToolRegistration,
    Alert,
    AlertStatus,
    Device,
    GovernedChangeEvidence,
    GovernedChangePlan,
    Investigation,
    InvestigationToolCall,
    Situation,
    SituationAlert,
    utcnow,
)
from .audit import record_audit_event
from .agent_authorization import investigation_principal
from .authorization_scope import device_scope_clause, has_global_scope
from .change_risk_policies import (
    assert_change_risk_policy_current,
    change_risk_policy_snapshot,
    get_change_risk_policy,
)


CHANGE_PLAN_CONTRACT = "icheck.change-plan/v1"
MAX_MAINTENANCE_WINDOW = timedelta(hours=8)
MAX_WINDOW_HORIZON = timedelta(days=90)
PAST_WINDOW_TOLERANCE = timedelta(minutes=15)
MAX_FROZEN_ORIGIN_ALERTS = 256


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _hash_document(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _extract_path(document: Any, path: str) -> Any:
    current = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"Required path {path!r} is absent")
        current = current[part]
    return current


def _schema_at_path(schema: dict[str, Any], path: str) -> dict[str, Any]:
    current: Any = schema
    for part in path.split("."):
        properties = current.get("properties") if isinstance(current, dict) else None
        if not isinstance(properties, dict) or part not in properties:
            raise ValueError(f"Required path {path!r} is absent from Tool schema")
        current = properties[part]
    if not isinstance(current, dict):
        raise ValueError(f"Tool schema path {path!r} is invalid")
    return current


def _schema_types(schema: dict[str, Any]) -> set[str]:
    raw = schema.get("type")
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {item for item in raw if isinstance(item, str)}
    return set()


def _validate_summary_path(schema: dict[str, Any], path: str) -> None:
    summary_schema = _schema_at_path(schema, path)
    types = _schema_types(summary_schema)
    if types and types.issubset({"boolean", "integer", "number"}):
        return
    if types == {"string"} and summary_schema.get("pattern") == r"^[0-9a-f]{64}$":
        return
    raise ValueError(
        "Governed change evidence summaries may contain only booleans, numbers, "
        "or SHA-256 strings"
    )


def _assert_authorization_targets(
    db: Session,
    investigation: Investigation,
    bindings: dict[str, str],
    arguments: dict[str, Any],
) -> None:
    principal = investigation_principal(investigation)
    if has_global_scope(principal):
        return
    if not bindings:
        raise PermissionError(
            "Scoped governed changes require authorization_target_paths"
        )
    allowed_sites = {
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    }
    for path, target_kind in bindings.items():
        value = _extract_path(arguments, path)
        if not isinstance(value, str) or not value:
            raise PermissionError("Governed change authorization target is invalid")
        if target_kind == "device_id":
            device = db.scalar(
                select(Device.id).where(
                    Device.id == value,
                    device_scope_clause(principal),
                )
            )
            if device is None:
                raise PermissionError(
                    "Investigation scope does not authorize the change device"
                )
        elif target_kind == "site":
            if value not in allowed_sites:
                raise PermissionError(
                    "Investigation scope does not authorize the change site"
                )
        else:
            raise ValueError("Governed change authorization target kind is invalid")


def _tool_snapshot(tool: AgentToolRegistration) -> dict[str, Any]:
    return {
        "tool_id": tool.id,
        "tool_name": tool.name,
        "transport": tool.transport,
        "read_only": tool.read_only,
        "risk_level": tool.risk_level,
        "required_permissions": list(tool.required_permissions or []),
        "input_schema_hash": _hash_document(tool.input_schema),
        "output_schema_hash": _hash_document(tool.output_schema),
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "tool_updated_at": _as_utc(tool.updated_at).isoformat(),
    }


def _dependency_tool(
    db: Session,
    *,
    name: str,
    read_only: bool,
    input_paths: list[str],
) -> AgentToolRegistration:
    tool = db.scalar(
        select(AgentToolRegistration).where(
            AgentToolRegistration.name == name,
            AgentToolRegistration.enabled.is_(True),
        )
    )
    if tool is None:
        raise ValueError(f"Governed change dependency {name!r} is unavailable")
    if tool.read_only is not read_only:
        expected = "read-only" if read_only else "state-changing"
        raise ValueError(f"Governed change dependency {name!r} must be {expected}")
    for path in input_paths:
        _schema_at_path(tool.input_schema, path)
    required = tool.input_schema.get("required", [])
    if not isinstance(required, list) or any(
        not isinstance(item, str) for item in required
    ):
        raise ValueError(
            f"Governed change dependency {name!r} has an invalid required list"
        )
    mapped_roots = {path.split(".", 1)[0] for path in input_paths}
    missing = sorted(set(required) - mapped_roots)
    if missing:
        raise ValueError(
            f"Governed change dependency {name!r} has unmapped required "
            f"arguments: {', '.join(missing)}"
        )
    return tool


def _step_mapping(
    definition: Any,
    target_paths: list[str],
) -> dict[str, str]:
    mapping = dict(definition.argument_mapping or {})
    if not mapping:
        mapping = {path: path for path in target_paths}
    if not set(target_paths).issubset(set(mapping.values())):
        raise ValueError(
            "Governed change stage mappings must include every frozen target"
        )
    if any(source not in target_paths for source in mapping.values()):
        raise ValueError(
            "Governed change stage mappings may read only frozen target values"
        )
    return mapping


def _contract_snapshot(
    db: Session,
    tool: AgentToolRegistration,
    contract: AgentChangeContract,
    *,
    action_plan_hash: str,
) -> dict[str, Any]:
    risk_policy = get_change_risk_policy(db, contract.risk_class)
    if not risk_policy.execution_enabled:
        raise ValueError(
            f"Governed {contract.risk_class} risk changes are disabled by policy"
        )
    if risk_policy.require_evidence_summary and not contract.dry_run.summary_paths:
        raise ValueError(
            "Governed change risk policy requires a bounded dry-run summary"
        )
    if (
        risk_policy.require_authorization_binding
        and not contract.authorization_target_paths
    ):
        raise ValueError(
            "Governed change risk policy requires an authorization target binding"
        )
    for path in contract.target_argument_paths:
        _schema_at_path(tool.input_schema, path)
    _schema_at_path(tool.input_schema, contract.idempotency_key_argument_path)

    steps: dict[str, dict[str, Any]] = {}
    stages = ["precheck", "dry_run", "postcheck"]
    if contract.rollback_check is not None:
        stages.append("rollback_check")
    for stage in stages:
        definition = getattr(contract, stage)
        argument_mapping = _step_mapping(
            definition,
            contract.target_argument_paths,
        )
        dependency = _dependency_tool(
            db,
            name=definition.tool_name,
            read_only=True,
            input_paths=list(argument_mapping),
        )
        success_schema = _schema_at_path(
            dependency.output_schema,
            definition.success_path,
        )
        if "boolean" not in _schema_types(success_schema):
            raise ValueError(
                f"Governed change {stage} success path must be boolean"
            )
        for path in definition.summary_paths:
            _validate_summary_path(dependency.output_schema, path)
        steps[stage] = {
            **_tool_snapshot(dependency),
            "success_path": definition.success_path,
            "argument_mapping": argument_mapping,
            "summary_paths": list(definition.summary_paths),
        }

    semantic_expectations: list[dict[str, str]] = []
    for expectation in contract.semantic_expectations:
        if (expectation.precheck_observation_path == contract.precheck.success_path
            or expectation.postcheck_observation_path == contract.postcheck.success_path):
            raise ValueError("Semantic observations cannot reuse stage success flags")
        action_schema = _schema_at_path(tool.input_schema, expectation.action_argument_path)
        before_schema = _schema_at_path(steps["precheck"]["output_schema"],
            expectation.precheck_observation_path)
        after_schema = _schema_at_path(steps["postcheck"]["output_schema"],
            expectation.postcheck_observation_path)
        value_types = [_schema_types(schema) for schema in (action_schema, before_schema, after_schema)]
        if (any(len(types) != 1 for types in value_types)
            or value_types[0] not in ({"boolean"}, {"integer"}, {"number"}, {"string"})
            or value_types[0] != value_types[1] or value_types[0] != value_types[2]):
            raise ValueError("Semantic observations require the same non-null scalar schema type")
        semantic_expectations.append({
            "action_argument_path": expectation.action_argument_path,
            "precheck_observation_path": expectation.precheck_observation_path,
            "postcheck_observation_path": expectation.postcheck_observation_path,
            "max_precheck_age_seconds": expectation.max_precheck_age_seconds,
            "max_postcheck_delay_seconds": expectation.max_postcheck_delay_seconds,
            "value_type": next(iter(value_types[0])),
        })

    rollback_mapping = _step_mapping(
        contract.rollback,
        contract.target_argument_paths,
    )
    rollback = _dependency_tool(
        db,
        name=contract.rollback.tool_name,
        read_only=False,
        input_paths=list(rollback_mapping),
    )
    if rollback.id == tool.id:
        raise ValueError("A governed change Tool cannot be its own rollback Tool")
    rollback_success_schema = _schema_at_path(
        rollback.output_schema,
        contract.rollback.success_path,
    )
    if "boolean" not in _schema_types(rollback_success_schema):
        raise ValueError("Governed change rollback success path must be boolean")
    for path in contract.rollback.summary_paths:
        _validate_summary_path(rollback.output_schema, path)
    snapshot = {
        "contract_version": contract.contract_version,
        "action_plan_hash": action_plan_hash,
        "action_tool": _tool_snapshot(tool),
        "risk_class": contract.risk_class,
        "target_argument_paths": list(contract.target_argument_paths),
        "authorization_target_paths": dict(contract.authorization_target_paths),
        "idempotency_key_argument_path": contract.idempotency_key_argument_path,
        "contract_requires_maintenance_window": (
            contract.requires_maintenance_window
        ),
        "requires_maintenance_window": (
            contract.requires_maintenance_window
            or risk_policy.maintenance_window_required
        ),
        "risk_policy": change_risk_policy_snapshot(risk_policy),
        "steps": steps,
        "semantic_expectations": semantic_expectations,
        "rollback": {
            **_tool_snapshot(rollback),
            "success_path": contract.rollback.success_path,
            "argument_mapping": rollback_mapping,
            "summary_paths": list(contract.rollback.summary_paths),
        },
    }
    if contract.rollback_check is not None:
        expectations = []
        for expectation in contract.rollback_expectations:
            if (expectation.precheck_observation_path == contract.precheck.success_path
                or expectation.rollback_observation_path == contract.rollback_check.success_path):
                raise ValueError("Rollback observations cannot reuse success flags")
            before = _schema_types(_schema_at_path(steps["precheck"]["output_schema"], expectation.precheck_observation_path))
            after = _schema_types(_schema_at_path(steps["rollback_check"]["output_schema"], expectation.rollback_observation_path))
            if before not in ({"boolean"}, {"integer"}, {"number"}, {"string"}) or before != after:
                raise ValueError("Rollback observations require the same non-null scalar schema type")
            expectations.append({**expectation.model_dump(), "value_type": next(iter(before))})
        snapshot["rollback_expectations"] = expectations
    return snapshot


def _latest_evidence(plan: GovernedChangePlan) -> dict[str, GovernedChangeEvidence]:
    latest: dict[str, GovernedChangeEvidence] = {}
    for item in plan.evidence:
        current = latest.get(item.stage)
        if current is None or (item.created_at, item.id) > (
            current.created_at,
            current.id,
        ):
            latest[item.stage] = item
    return latest


def frozen_alert_identity_hash(alert: Alert) -> str:
    """Hash stable causal identity, not mutable freshness/status fields."""
    return _hash_document({"contract": "icheck.alert-origin/v1", "id": alert.id,
        "event_type": alert.event_type, "entity_type": alert.entity_type,
        "entity_id": alert.entity_id, "dedup_key": alert.dedup_key,
        "first_seen": _as_utc(alert.first_seen).isoformat()})


def _origin_snapshot(db: Session, investigation: Investigation) -> dict[str, Any]:
    """Freeze the originating Situation's current Alert IDs for future automation.

    A later Alert membership must not make an already-created plan eligible for
    unattended action. Manual governed changes can still use a plan without a
    Situation, or one whose origin set exceeds this bounded snapshot.
    """
    origin: dict[str, Any] = {"contract": "icheck.plan-origin/v1",
        "situation_id": investigation.situation_id, "alerts": [], "truncated": False}
    if not investigation.situation_id:
        return origin
    namespace = (investigation.tenant_id, investigation.region_id)
    bound_namespace = session_namespace(db)
    if bound_namespace is not None and bound_namespace != namespace:
        origin["truncated"] = True
        return origin
    situation = db.scalar(select(Situation).where(Situation.id == investigation.situation_id,
        Situation.tenant_id == namespace[0], Situation.region_id == namespace[1]))
    if situation is None or situation.status != "open":
        origin["truncated"] = True
        return origin
    alerts = list(db.scalars(select(Alert).join(SituationAlert,
        SituationAlert.alert_id == Alert.id).where(
            SituationAlert.situation_id == investigation.situation_id,
            SituationAlert.tenant_id == namespace[0], SituationAlert.region_id == namespace[1],
            Alert.tenant_id == namespace[0], Alert.region_id == namespace[1],
            Alert.status == AlertStatus.OPEN,
            Alert.source_retirement_id.is_(None),
        ).order_by(Alert.id).limit(MAX_FROZEN_ORIGIN_ALERTS + 1)).all())
    origin["alerts"] = [{"id": alert.id, "identity_sha256": frozen_alert_identity_hash(alert)}
        for alert in alerts[:MAX_FROZEN_ORIGIN_ALERTS]]
    origin["truncated"] = len(alerts) > MAX_FROZEN_ORIGIN_ALERTS
    return origin


def _policy_evaluation(plan: GovernedChangePlan) -> dict[str, Any]:
    latest = _latest_evidence(plan)
    requirements = {
        stage: {
            "present": stage in latest,
            "passed": latest[stage].passed if stage in latest else False,
            "tool_call_id": latest[stage].tool_call_id if stage in latest else None,
        }
        for stage in ("precheck", "dry_run")
    }
    window_required = bool(
        plan.tool_contract_snapshot.get("requires_maintenance_window", True)
    )
    window_configured = (
        plan.maintenance_window_start is not None
        and plan.maintenance_window_end is not None
    )
    approval_ready = all(
        item["present"] and item["passed"] for item in requirements.values()
    ) and (not window_required or window_configured)
    return {
        "contract": "icheck.change-policy-evaluation/v1",
        "four_eyes_required": True,
        "risk_policy": plan.tool_contract_snapshot.get("risk_policy", {}),
        "evidence": requirements,
        "maintenance_window_required": window_required,
        "maintenance_window_configured": window_configured,
        "approval_ready": approval_ready,
    }


def _plan_hash(plan: GovernedChangePlan, *, revision: int | None = None) -> str:
    evidence = sorted(
        (
            {
                "stage": item.stage,
                "tool_call_id": item.tool_call_id,
                "tool_id": item.tool_id,
                "arguments_hash": item.arguments_hash,
                "result_hash": item.result_hash,
                "passed": item.passed,
            }
            for item in plan.evidence
            if item.stage in {"precheck", "dry_run"}
        ),
        key=lambda item: (item["stage"], item["tool_call_id"]),
    )
    return _hash_document(
        {
            "contract_version": plan.contract_version,
            "revision": plan.revision if revision is None else revision,
            "action_proposal_id": plan.action_proposal_id,
            "investigation_id": plan.investigation_id,
            "risk_class": plan.risk_class,
            "tool_contract_snapshot": plan.tool_contract_snapshot,
            "target_snapshot": plan.target_snapshot,
            "authorization_scope_snapshot": plan.authorization_scope_snapshot,
            "idempotency_key_hash": plan.idempotency_key_hash,
            "maintenance_window_start": (
                _as_utc(plan.maintenance_window_start).isoformat()
                if plan.maintenance_window_start
                else None
            ),
            "maintenance_window_end": (
                _as_utc(plan.maintenance_window_end).isoformat()
                if plan.maintenance_window_end
                else None
            ),
            "evidence": evidence,
        }
    )


def _recompute_preapproval(plan: GovernedChangePlan) -> None:
    plan.policy_evaluation = _policy_evaluation(plan)
    plan.status = (
        "ready_for_approval"
        if plan.policy_evaluation["approval_ready"]
        else "awaiting_evidence"
    )
    plan.plan_hash = _plan_hash(plan)


def create_change_plan(
    db: Session,
    *,
    proposal: AgentActionProposal,
    investigation: Investigation,
    tool: AgentToolRegistration,
) -> GovernedChangePlan | None:
    if tool.change_contract is None:
        return None
    contract = AgentChangeContract.model_validate(tool.change_contract)
    _assert_authorization_targets(
        db,
        investigation,
        dict(contract.authorization_target_paths),
        proposal.arguments,
    )
    idempotency_key = _extract_path(
        proposal.arguments,
        contract.idempotency_key_argument_path,
    )
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        raise ValueError("Governed changes require a non-empty string idempotency key")
    if len(idempotency_key) > 512:
        raise ValueError("Governed change idempotency keys cannot exceed 512 characters")
    targets: dict[str, Any] = {}
    for path in contract.target_argument_paths:
        value = _extract_path(proposal.arguments, path)
        if isinstance(value, (dict, list)) or value is None:
            raise ValueError("Governed change targets must be non-null scalar values")
        targets[path] = value
    snapshot = _contract_snapshot(
        db,
        tool,
        contract,
        action_plan_hash=proposal.plan_hash,
    )
    snapshot["origin"] = _origin_snapshot(db, investigation)
    plan = GovernedChangePlan(
        action_proposal_id=proposal.id,
        investigation_id=investigation.id,
        contract_version=CHANGE_PLAN_CONTRACT,
        revision=1,
        status="awaiting_evidence",
        risk_class=contract.risk_class,
        tool_contract_snapshot=snapshot,
        target_snapshot=targets,
        authorization_scope_snapshot=dict(investigation.authorization_scope or {}),
        idempotency_key_hash=hashlib.sha256(
            idempotency_key.encode("utf-8")
        ).hexdigest(),
        plan_hash="0" * 64,
        policy_evaluation={},
        created_by=investigation.created_by,
        updated_by=investigation.created_by,
    )
    db.add(plan)
    db.flush()
    _recompute_preapproval(plan)
    record_audit_event(
        db,
        event_type="change.plan.created",
        actor_type="agent",
        actor_id="agent.langgraph",
        entity_type="governed_change_plan",
        entity_id=plan.id,
        details={
            "proposal_id": proposal.id,
            "investigation_id": investigation.id,
            "risk_class": plan.risk_class,
            "plan_hash": plan.plan_hash,
        },
    )
    return plan


def get_change_plan_for_proposal(
    db: Session,
    proposal_id: str,
    *,
    lock: bool = False,
) -> GovernedChangePlan | None:
    query = (
        select(GovernedChangePlan)
        .where(GovernedChangePlan.action_proposal_id == proposal_id)
        .options(selectinload(GovernedChangePlan.evidence))
    )
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


def get_change_plan(
    db: Session,
    plan_id: str,
    *,
    lock: bool = False,
) -> GovernedChangePlan | None:
    query = (
        select(GovernedChangePlan)
        .where(GovernedChangePlan.id == plan_id)
        .options(selectinload(GovernedChangePlan.evidence))
    )
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


def update_change_window(
    db: Session,
    plan: GovernedChangePlan,
    payload: GovernedChangeWindowUpdate,
    *,
    actor: str,
) -> GovernedChangePlan:
    proposal = db.get(AgentActionProposal, plan.action_proposal_id)
    if proposal is None:
        raise LookupError("Action proposal not found")
    if proposal.status != "pending" or plan.status not in {
        "awaiting_evidence",
        "ready_for_approval",
    }:
        raise ValueError("Only pending change plans can update their window")
    if plan.revision != payload.expected_revision or not secrets.compare_digest(
        plan.plan_hash,
        payload.expected_plan_hash,
    ):
        raise ValueError("Change plan revision or hash is stale")
    start = _as_utc(payload.maintenance_window_start)
    end = _as_utc(payload.maintenance_window_end)
    now = _as_utc(utcnow())
    if start < now - PAST_WINDOW_TOLERANCE:
        raise ValueError("Maintenance window starts too far in the past")
    if start > now + MAX_WINDOW_HORIZON:
        raise ValueError("Maintenance window cannot start more than 90 days ahead")
    if end <= now or end <= start:
        raise ValueError("Maintenance window must end after its start and in the future")
    risk_policy = plan.tool_contract_snapshot.get("risk_policy", {})
    max_window_minutes = risk_policy.get(
        "max_window_minutes",
        int(MAX_MAINTENANCE_WINDOW.total_seconds() // 60),
    )
    if not isinstance(max_window_minutes, int) or not 5 <= max_window_minutes <= 480:
        raise ValueError("Governed change risk policy window limit is invalid")
    if end - start > timedelta(minutes=max_window_minutes):
        raise ValueError(
            f"{plan.risk_class.capitalize()} risk maintenance window cannot "
            f"exceed {max_window_minutes} minutes"
        )
    plan.maintenance_window_start = start
    plan.maintenance_window_end = end
    plan.revision += 1
    plan.updated_by = actor
    _recompute_preapproval(plan)
    record_audit_event(
        db,
        event_type="change.plan.window_updated",
        actor_type="user",
        actor_id=actor,
        entity_type="governed_change_plan",
        entity_id=plan.id,
        details={
            "revision": plan.revision,
            "plan_hash": plan.plan_hash,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "reason": payload.reason,
        },
    )
    db.commit()
    return get_change_plan_for_proposal(db, proposal.id) or plan


def _stage_contract(plan: GovernedChangePlan, stage: str) -> dict[str, Any]:
    if stage in {"precheck", "dry_run", "postcheck", "rollback_check"}:
        raw = plan.tool_contract_snapshot.get("steps", {}).get(stage)
    else:
        raw = plan.tool_contract_snapshot.get("rollback")
    if not isinstance(raw, dict):
        raise ValueError(f"Change plan does not define {stage} evidence")
    return raw


def _assert_tool_snapshot_current(
    db: Session,
    snapshot: dict[str, Any],
) -> AgentToolRegistration:
    tool_id = snapshot.get("tool_id")
    tool = db.get(AgentToolRegistration, tool_id) if tool_id else None
    frozen_tool = {
        key: value
        for key, value in snapshot.items()
        if key not in {"success_path", "argument_mapping", "summary_paths"}
    }
    if tool is None or not tool.enabled or _tool_snapshot(tool) != frozen_tool:
        raise ValueError("A Tool pinned by the governed change plan has drifted")
    return tool


def assert_change_stage_tool_current(
    db: Session,
    plan: GovernedChangePlan,
    stage: str,
) -> AgentToolRegistration:
    return _assert_tool_snapshot_current(db, _stage_contract(plan, stage))


def _assert_plan_current(
    db: Session,
    plan: GovernedChangePlan,
    proposal: AgentActionProposal,
) -> None:
    if not secrets.compare_digest(plan.plan_hash, _plan_hash(plan)):
        raise ValueError("Governed change plan material has drifted from its hash")
    snapshot = plan.tool_contract_snapshot
    if snapshot.get("action_plan_hash") != proposal.plan_hash:
        raise ValueError("Governed change action plan has drifted")
    _assert_tool_snapshot_current(db, snapshot["action_tool"])
    risk_policy = snapshot.get("risk_policy")
    if not isinstance(risk_policy, dict):
        raise ValueError("Governed change risk policy snapshot is missing")
    assert_change_risk_policy_current(db, risk_policy)
    for stage in ("precheck", "dry_run", "postcheck"):
        _assert_tool_snapshot_current(db, snapshot["steps"][stage])
    if "rollback_check" in snapshot["steps"]:
        _assert_tool_snapshot_current(db, snapshot["steps"]["rollback_check"])
    _assert_tool_snapshot_current(db, snapshot["rollback"])
    from .change_verification import scoped_row, validate_stage_call
    for stage, evidence in _latest_evidence(plan).items():
        if stage not in {"precheck", "dry_run"}:
            continue
        call = scoped_row(db, InvestigationToolCall, evidence.tool_call_id, plan)
        if call is None:
            raise ValueError("Governed prerequisite call is unavailable")
        passed, _ = validate_stage_call(db, plan, stage, call)
        if not passed or evidence.passed is not True or evidence.result_hash != call.result_hash or evidence.arguments_hash != _hash_document(call.arguments):
            raise ValueError("Governed prerequisite evidence has drifted")
    investigation = db.get(Investigation, plan.investigation_id)
    if investigation is None or dict(investigation.authorization_scope or {}) != (
        plan.authorization_scope_snapshot
    ):
        raise ValueError("Governed change authorization scope has drifted")
    origin = snapshot.get("origin")
    if origin is not None and (not isinstance(origin, dict)
        or origin.get("contract") != "icheck.plan-origin/v1"
        or origin.get("situation_id") != investigation.situation_id):
        raise ValueError("Governed change origin Situation has drifted")
    authorization_targets = snapshot.get("authorization_target_paths", {})
    if not isinstance(authorization_targets, dict):
        raise ValueError("Governed change authorization targets have drifted")
    _assert_authorization_targets(
        db,
        investigation,
        authorization_targets,
        proposal.arguments,
    )
    for path, expected in plan.target_snapshot.items():
        if _extract_path(proposal.arguments, path) != expected:
            raise ValueError("Governed change target has drifted")
    idempotency_key = _extract_path(
        proposal.arguments,
        str(snapshot["idempotency_key_argument_path"]),
    )
    if not isinstance(idempotency_key, str) or not secrets.compare_digest(
        hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
        plan.idempotency_key_hash,
    ):
        raise ValueError("Governed change idempotency key has drifted")


def _validate_evidence_phase(
    plan: GovernedChangePlan,
    proposal: AgentActionProposal,
    stage: str,
) -> None:
    if stage in {"precheck", "dry_run"}:
        if proposal.status != "pending" or plan.status not in {
            "awaiting_evidence",
            "ready_for_approval",
        }:
            raise ValueError("Pre-check and dry-run evidence require a pending plan")
    elif stage == "postcheck":
        if proposal.status != "succeeded" or plan.status != "awaiting_postcheck":
            raise ValueError("Post-check evidence requires a succeeded action")
    elif stage == "rollback":
        if plan.status != "rollback_required":
            raise ValueError("Rollback evidence requires a rollback-required plan")
    elif stage == "rollback_check":
        if plan.status != "awaiting_rollback_check":
            raise ValueError("Rollback restoration evidence requires a completed rollback awaiting verification")


def _assign_path(document: dict[str, Any], path: str, value: Any) -> None:
    current = document
    parts = path.split(".")
    for part in parts[:-1]:
        existing = current.get(part)
        if existing is None:
            existing = {}
            current[part] = existing
        if not isinstance(existing, dict):
            raise ValueError(f"Change stage argument path {path!r} conflicts")
        current = existing
    current[parts[-1]] = value


def change_stage_arguments(
    plan: GovernedChangePlan,
    stage: str,
) -> dict[str, Any]:
    contract = _stage_contract(plan, stage)
    mapping = contract.get("argument_mapping")
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Change stage has no frozen argument mapping")
    arguments: dict[str, Any] = {}
    for target_path, source_path in mapping.items():
        if source_path not in plan.target_snapshot:
            raise ValueError("Change stage mapping references an unfrozen target")
        _assign_path(arguments, target_path, plan.target_snapshot[source_path])
    return arguments


def find_required_rollback_plan(
    db: Session,
    *,
    investigation: Investigation,
    tool: AgentToolRegistration,
    arguments: dict[str, Any],
) -> GovernedChangePlan | None:
    candidates = list(
        db.scalars(
            select(GovernedChangePlan)
            .where(
                GovernedChangePlan.investigation_id == investigation.id,
                GovernedChangePlan.status.in_(["rollback_required", "awaiting_rollback_check", "rolled_back", "rollback_failed"]),
            )
            .options(selectinload(GovernedChangePlan.evidence))
            .order_by(GovernedChangePlan.updated_at, GovernedChangePlan.id)
            .limit(33)
        ).all()
    )
    if len(candidates) > 32:
        raise ValueError("Too many rollback-required plans to match safely")
    matches = [
        plan
        for plan in candidates
        if _stage_contract(plan, "rollback").get("tool_id") == tool.id
        and change_stage_arguments(plan, "rollback") == arguments
    ]
    if len(matches) > 1:
        raise ValueError("Rollback action ambiguously matches multiple change plans")
    if not matches:
        return None
    plan = matches[0]
    original_proposal = db.get(AgentActionProposal, plan.action_proposal_id)
    if original_proposal is None:
        raise LookupError("Original action proposal not found")
    _assert_plan_current(db, plan, original_proposal)
    assert_change_stage_tool_current(db, plan, "rollback")
    return plan


def attach_rollback_action_result(
    db: Session,
    rollback_proposal: AgentActionProposal,
    call: InvestigationToolCall,
) -> GovernedChangePlan | None:
    plan_id = rollback_proposal.rollback_of_change_plan_id
    if plan_id is None:
        return None
    plan = get_change_plan(db, plan_id, lock=True)
    if plan is None:
        raise LookupError("Rollback change plan not found")
    if (
        rollback_proposal.status != "succeeded"
        or rollback_proposal.investigation_id != plan.investigation_id
        or call.investigation_id != plan.investigation_id
    ):
        raise ValueError("Rollback result does not belong to the frozen change plan")
    existing = _latest_evidence(plan).get("rollback")
    if existing is not None:
        from .change_verification import validate_stage_call
        passed, _ = validate_stage_call(db, plan, "rollback", call)
        if existing.tool_call_id != call.id or existing.passed is not passed or existing.result_hash != call.result_hash:
            raise ValueError("A different rollback result is already bound")
        return plan
    investigation = db.get(Investigation, plan.investigation_id)
    tool = db.get(AgentToolRegistration, rollback_proposal.tool_id)
    if investigation is None or tool is None:
        raise LookupError("Rollback investigation or Tool not found")
    matched = find_required_rollback_plan(
        db,
        investigation=investigation,
        tool=tool,
        arguments=rollback_proposal.arguments,
    )
    if matched is None or matched.id != plan.id:
        raise ValueError("Rollback result no longer matches the required plan")
    return attach_change_evidence(
        db,
        plan,
        GovernedChangeEvidenceAttach(
            expected_revision=plan.revision,
            expected_plan_hash=plan.plan_hash,
            stage="rollback",
            tool_call_id=call.id,
            reason="Bound the separately approved rollback action result.",
        ),
        actor="agent.runtime",
    )


def attach_change_evidence(
    db: Session,
    plan: GovernedChangePlan,
    payload: GovernedChangeEvidenceAttach,
    *,
    actor: str,
) -> GovernedChangePlan:
    proposal = db.get(AgentActionProposal, plan.action_proposal_id)
    if proposal is None:
        raise LookupError("Action proposal not found")
    if plan.revision != payload.expected_revision or not secrets.compare_digest(
        plan.plan_hash,
        payload.expected_plan_hash,
    ):
        raise ValueError("Change plan revision or hash is stale")
    if not secrets.compare_digest(plan.plan_hash, _plan_hash(plan)):
        raise ValueError("Governed change plan material has drifted from its hash")
    _validate_evidence_phase(plan, proposal, payload.stage)
    call = db.get(InvestigationToolCall, payload.tool_call_id)
    if (
        call is None
        or call.investigation_id != plan.investigation_id
        or call.status != "succeeded"
        or call.result_hash is None
        or call.result is None
    ):
        raise ValueError(
            "Change evidence must be a successful Tool call from this Investigation"
        )
    contract = _stage_contract(plan, payload.stage)
    _assert_tool_snapshot_current(db, contract)
    from .change_verification import validate_stage_call
    passed, summary = validate_stage_call(db, plan, payload.stage, call)
    evidence = GovernedChangeEvidence(
        change_plan_id=plan.id,
        stage=payload.stage,
        tool_call_id=call.id,
        tool_id=call.tool_id,
        arguments_hash=_hash_document(call.arguments),
        result_hash=call.result_hash,
        passed=passed,
        evidence_snapshot={
            "contract": "icheck.change-evidence/v1",
            "stage": payload.stage,
            "tool_id": call.tool_id,
            "tool_name": contract.get("tool_name"),
            "tool_call_id": call.id,
            "arguments_hash": _hash_document(call.arguments),
            "result_hash": call.result_hash,
            "passed": passed,
            "summary": summary,
        },
        recorded_by=actor,
    )
    db.add(evidence)
    db.flush()
    plan.evidence.append(evidence)
    plan.revision += 1
    plan.updated_by = actor
    if payload.stage in {"precheck", "dry_run"}:
        _recompute_preapproval(plan)
    elif payload.stage == "postcheck":
        plan.status = "verified" if passed else "rollback_required"
        plan.plan_hash = _plan_hash(plan)
    elif payload.stage == "rollback":
        plan.status = ("awaiting_rollback_check" if passed and "rollback_check" in plan.tool_contract_snapshot.get("steps", {})
            else "rolled_back" if passed else "rollback_failed")
        plan.plan_hash = _plan_hash(plan)
    else:
        plan.status = "rolled_back" if passed else "rollback_failed"
        plan.plan_hash = _plan_hash(plan)
    record_audit_event(
        db,
        event_type=f"change.evidence.{payload.stage}",
        actor_type="agent" if actor.startswith("agent.") else "user",
        actor_id=actor,
        entity_type="governed_change_plan",
        entity_id=plan.id,
        outcome="success" if passed else "failure",
        details={
            "tool_call_id": call.id,
            "result_hash": call.result_hash,
            "revision": plan.revision,
            "plan_hash": plan.plan_hash,
            "reason": payload.reason,
        },
    )
    db.commit()
    return get_change_plan_for_proposal(db, proposal.id) or plan


def decide_change_plan(
    db: Session,
    proposal: AgentActionProposal,
    *,
    decision: str,
    expected_plan_hash: str | None,
    actor: str,
) -> GovernedChangePlan | None:
    plan = get_change_plan_for_proposal(db, proposal.id, lock=True)
    if plan is None:
        if expected_plan_hash is not None:
            raise ValueError("Action proposal has no governed change plan")
        return None
    if expected_plan_hash is None or not secrets.compare_digest(
        plan.plan_hash,
        expected_plan_hash,
    ):
        raise ValueError("Governed change plan hash is missing or stale")
    if decision == "reject":
        if plan.status not in {"awaiting_evidence", "ready_for_approval"}:
            raise ValueError("Governed change plan cannot be rejected in this state")
        plan.status = "rejected"
        plan.updated_by = actor
        return plan
    if plan.status != "ready_for_approval":
        raise ValueError("Governed change plan is not ready for approval")
    _assert_plan_current(db, plan, proposal)
    now = _as_utc(utcnow())
    if plan.tool_contract_snapshot.get("requires_maintenance_window", True):
        if (
            plan.maintenance_window_start is None
            or plan.maintenance_window_end is None
            or not (
                _as_utc(plan.maintenance_window_start)
                <= now
                <= _as_utc(plan.maintenance_window_end)
            )
        ):
            raise ValueError("Governed change approval is outside its maintenance window")
    plan.status = "approved"
    plan.approved_plan_hash = plan.plan_hash
    plan.updated_by = actor
    return plan


def mark_change_execution_started(
    db: Session,
    proposal: AgentActionProposal,
) -> GovernedChangePlan | None:
    if proposal.rollback_of_change_plan_id is not None:
        parent = get_change_plan(db, proposal.rollback_of_change_plan_id, lock=True)
        if parent is None or parent.status != "rollback_required":
            raise ValueError("Rollback parent is not awaiting its one-shot recovery")
        from .rollback_execution import assert_parent_slot
        assert_parent_slot(db, proposal, parent)
        original = db.get(AgentActionProposal, parent.action_proposal_id)
        _assert_plan_current(db, parent, original)
        assert_change_stage_tool_current(db, parent, "rollback")
        if proposal.tool_id != parent.tool_contract_snapshot["rollback"]["tool_id"] or proposal.arguments != change_stage_arguments(parent, "rollback"):
            raise ValueError("Rollback admission differs from its frozen parent")
        from .change_verification import stage_not_before
        stage_not_before(db, parent, "rollback", now=utcnow())
        return None
    plan = get_change_plan_for_proposal(db, proposal.id, lock=True)
    if plan is None:
        return None
    if (
        plan.status != "approved"
        or plan.approved_plan_hash is None
        or not secrets.compare_digest(plan.plan_hash, plan.approved_plan_hash)
    ):
        raise ValueError("Governed change approval does not match the current plan")
    _assert_plan_current(db, plan, proposal)
    now = _as_utc(utcnow())
    if plan.tool_contract_snapshot.get("requires_maintenance_window", True) and (
        plan.maintenance_window_start is None
        or plan.maintenance_window_end is None
        or not (
            _as_utc(plan.maintenance_window_start)
            <= now
            <= _as_utc(plan.maintenance_window_end)
        )
    ):
        raise ValueError("Governed change execution is outside its maintenance window")
    plan.status = "executing"
    plan.updated_by = "agent.runtime"
    return plan


def mark_change_execution_finished(
    db: Session,
    proposal: AgentActionProposal,
    *,
    failed: bool,
) -> GovernedChangePlan | None:
    plan = get_change_plan_for_proposal(db, proposal.id, lock=True)
    if plan is None:
        return None
    if plan.status != "executing":
        raise ValueError("Governed change plan is not executing")
    plan.status = "rollback_required" if failed else "awaiting_postcheck"
    plan.updated_by = "agent.runtime"
    return plan
