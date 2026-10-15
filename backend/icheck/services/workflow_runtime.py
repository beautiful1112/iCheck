from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..database import require_locking_transaction
from ..agent_schemas import InvestigationCreate
from ..config import get_settings
from ..models import (
    AIModelRoute,
    AgentToolRegistration,
    Alert,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    ControlPlanePrincipal,
    ControlPlaneRoleBinding,
    Investigation,
    InvestigationEvidence,
    Situation,
    SituationEvent,
    SituationIntegrationBinding,
    SituationIntegrationEvent,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
    WorkflowTriggerActivation,
    WorkflowTriggerEvent,
    utcnow,
)
from ..schema_validation import validate_instance
from ..report_schemas import ReportExportFormat, ServiceReportInstanceCreate
from ..studio_schemas import GeneratedWorkflowSpec, GeneratedRetainedProofReportSpec, WorkflowNode
from ..workflow_runtime_schemas import (
    PublishedWorkflowRead,
    SituationIntegrationBindingCreate,
    WorkflowInvestigationCreate,
    WorkflowScheduleActivationCreate,
    WorkflowScheduleExclusionsUpdate,
    WorkflowScheduleExclusionWindow,
    WorkflowTriggerActivationCreate,
)
from .agent_runtime import create_investigation, start_investigation
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .cron_schedule import next_cron_occurrence, validate_cron_schedule
from .authorization_scope import require_requested_investigation_scope
from .authorization_scope import require_alert_access
from .authorization_scope import require_situation_access
from .control_plane_auth import (
    PrincipalContext,
    development_principal,
    principal_context,
)
from .workflow_templates import (
    WORKFLOW_FORMAT_VERSION,
    WORKFLOW_RUNTIME,
    validate_workflow_artifact_contract,
)
from .situation_reconciliation import (
    validate_inbound_public_key,
    validate_remote_reference_contract,
)
from .service_health_reports import (
    published_service_report_spec,
    service_report_is_fully_visible,
    service_report_runtime_generate,
    verified_service_report_version_spec,
)
from .report_delivery_receipts import (
    validate_report_delivery_receipt_contract,
)
from .report_instances import build_report_instance, capture_report_instance, visible_report_instance, retained_workflow_input
from .report_attachments import attachment_manifest, create_report_attachment, render_attachment, verified_report_attachment


WORKFLOW_PLAN_PREFIX = "icheck.workflow"
ALERT_INPUT_ROOTS = {
    "id",
    "event_type",
    "severity",
    "status",
    "entity_type",
    "entity_id",
    "occurrence_count",
    "details",
}
SITUATION_INTEGRATION_EVENT_TYPES = {
    "situation.created",
    "situation.acknowledged",
    "situation.attention_reopened",
    "situation.resolved",
    "situation.severity_changed",
}
SITUATION_INPUT_ROOTS = {
    "id",
    "title",
    "summary",
    "status",
    "severity",
    "priority_score",
    "primary_entity_type",
    "primary_entity_id",
    "alert_count",
    "active_alert_count",
    "occurrence_count",
    "first_seen",
    "last_seen",
}
SITUATION_EVENT_INPUT_ROOTS = {
    "id",
    "event_type",
    "sequence",
    "actor",
    "created_at",
    "details",
}


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def workflow_plan_marker(node_id: str, phase: str, turn: int = 0) -> str:
    return f"{WORKFLOW_PLAN_PREFIX}:{node_id}:{phase}:{turn}"


def workflow_plan_cursor(plan: list[str]) -> tuple[str, str, int] | None:
    if not plan or not plan[0].startswith(f"{WORKFLOW_PLAN_PREFIX}:"):
        return None
    parts = plan[0].split(":")
    if len(parts) != 4:
        raise ValueError("Workflow execution cursor is invalid")
    try:
        turn = int(parts[3])
    except ValueError as exc:
        raise ValueError("Workflow execution cursor is invalid") from exc
    if turn < 0:
        raise ValueError("Workflow execution cursor is invalid")
    return parts[1], parts[2], turn


def workflow_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(selectinload(ArtifactVersion.artifact))
    )
    if version is None:
        raise LookupError("Workflow version not found")
    return version


def list_published_workflows(db: Session) -> list[ArtifactVersion]:
    return list(
        db.scalars(
            select(ArtifactVersion)
            .join(ArtifactVersion.artifact)
            .where(
                Artifact.kind == ArtifactKind.WORKFLOW,
                ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            )
            .options(selectinload(ArtifactVersion.artifact))
            .order_by(Artifact.name, ArtifactVersion.version.desc())
        ).all()
    )


def published_workflow_read(version: ArtifactVersion) -> PublishedWorkflowRead:
    spec = GeneratedWorkflowSpec.model_validate(version.definition["spec"])
    report = version.validation_report or {}
    return PublishedWorkflowRead(
        artifact_id=version.artifact_id,
        artifact_name=version.artifact.name,
        version_id=version.id,
        version=version.version,
        description=spec.description,
        trigger=spec.trigger.model_dump(mode="json"),
        input_schema=spec.input_schema,
        node_count=len(spec.nodes),
        required_permissions=sorted(report.get("required_permissions", [])),
        approval_required=any(node.node_type == "approval" for node in spec.nodes),
        max_runtime_seconds=spec.max_runtime_seconds,
        max_total_tool_calls=spec.max_total_tool_calls,
        max_total_tokens=spec.max_total_tokens,
        content_hash=version.content_hash or "",
    )


def assert_workflow_runtime_compatible(
    db: Session,
    version: ArtifactVersion,
    *,
    allow_deprecated: bool = False,
) -> tuple[GeneratedWorkflowSpec, dict[str, Any]]:
    if version.artifact.kind != ArtifactKind.WORKFLOW:
        raise ValueError("Runtime version must be a Workflow Artifact")
    allowed_statuses = {ArtifactVersionStatus.PUBLISHED}
    if allow_deprecated:
        allowed_statuses.add(ArtifactVersionStatus.DEPRECATED)
    if version.status not in allowed_statuses:
        raise ValueError("Only published Workflow versions can start execution")
    if version.definition.get("format_version") != WORKFLOW_FORMAT_VERSION:
        raise ValueError("Workflow format_version is unsupported")
    if version.implementation.get("runtime") != WORKFLOW_RUNTIME:
        raise ValueError("Workflow runtime contract is unsupported")
    report = validate_workflow_artifact_contract(
        db,
        version.definition,
        version.implementation,
        version.tests,
    )
    return GeneratedWorkflowSpec.model_validate(version.definition["spec"]), report


def workflow_runtime_snapshot(
    version: ArtifactVersion,
    spec: GeneratedWorkflowSpec,
) -> dict[str, Any]:
    return {
        "format_version": version.definition["format_version"],
        "content_hash": version.content_hash,
        "artifact_name": version.artifact.name,
        "description": spec.description,
        "trigger": spec.trigger.model_dump(mode="json"),
        "input_schema": spec.input_schema,
        "start_node": spec.start_node,
        "nodes": [node.model_dump(mode="json") for node in spec.nodes],
        "tool_dependencies": version.definition["tool_dependencies"],
        "budgets": {
            "max_runtime_seconds": spec.max_runtime_seconds,
            "max_total_tool_calls": spec.max_total_tool_calls,
            "max_total_tokens": spec.max_total_tokens,
        },
    }


def assert_bound_workflow_runtime_compatible(
    db: Session,
    investigation: Investigation,
) -> tuple[GeneratedWorkflowSpec, dict[str, Any]] | None:
    if not investigation.workflow_snapshot:
        return None
    if investigation.workflow_artifact_version_id is None:
        raise ValueError("Bound Workflow Artifact version is unavailable")
    version = workflow_version(db, investigation.workflow_artifact_version_id)
    spec, report = assert_workflow_runtime_compatible(
        db,
        version,
        allow_deprecated=True,
    )
    if investigation.workflow_snapshot != workflow_runtime_snapshot(version, spec):
        raise ValueError("Bound Workflow snapshot does not match its version")
    return spec, report


def _node_for_cursor(spec: GeneratedWorkflowSpec, plan: list[str]) -> WorkflowNode:
    cursor = workflow_plan_cursor(plan)
    if cursor is None:
        raise PermissionError("Workflow tool call has no deterministic node cursor")
    node_id, _phase, _turn = cursor
    node = next((item for item in spec.nodes if item.node_id == node_id), None)
    if node is None:
        raise PermissionError("Workflow node cursor is not in the bound template")
    return node


def assert_workflow_tool_allowed(
    db: Session,
    investigation: Investigation,
    tool: AgentToolRegistration,
    plan: list[str],
) -> None:
    bound = assert_bound_workflow_runtime_compatible(db, investigation)
    if bound is None:
        return
    spec, _report = bound
    node = _node_for_cursor(spec, plan)
    if node.node_type == "agent_loop":
        allowed = tool.name in node.allowed_tools
    else:
        allowed = node.node_type in {"tool", "post_check", "rollback"} and (
            node.tool_name == tool.name
        )
    if not allowed:
        raise PermissionError(
            f"Workflow node {node.node_id!r} does not allow tool {tool.name!r}"
        )


def assert_scheduled_report_delivery_allowed(
    db: Session, investigation: Investigation,
    tool: AgentToolRegistration, arguments: dict[str, Any],
) -> None:
    if investigation.workflow_schedule_event_id is None:
        return
    event = db.get(WorkflowScheduleEvent, investigation.workflow_schedule_event_id)
    activation = db.get(WorkflowScheduleActivation, event.activation_id) if event else None
    if activation is None or activation.report_artifact_version_id is None:
        return
    # Every fixed consumer (including post-check and rollback) must reauthorize
    # the exact report before external I/O, not only the producing send Tool.
    bindings = [binding for node in (investigation.workflow_snapshot or {}).get("nodes", [])
        if node.get("tool_name") == tool.name for binding in node.get("input_bindings", [])
        if binding.get("input_path") == activation.report_input_key
        or binding.get("input_path", "").startswith(activation.report_input_key + ".")]
    if not bindings:
        return
    report_input = (investigation.workflow_input or {}).get(activation.report_input_key)
    if not isinstance(report_input, dict):
        raise ValueError("Report delivery arguments do not match the scheduled input")
    for binding in bindings:
        expected = report_input
        for part in binding["input_path"].split(".")[1:]:
            if not isinstance(expected, dict) or part not in expected:
                raise ValueError("Report delivery arguments do not match the scheduled input")
            expected = expected[part]
        if arguments.get(binding["argument"]) != expected:
            raise ValueError("Report delivery arguments do not match the scheduled input")
    _verified_scheduled_report_input(db, investigation, activation, report_input)


def _verified_scheduled_report_input(db, investigation, activation, report_input):
    principal = _automation_principal(db, activation.run_as_principal_id)
    if not principal.permits("services.read"):
        raise PermissionError("Report delivery run-as read permission was revoked")
    version = db.get(ArtifactVersion, activation.report_artifact_version_id)
    if (version is None or version.tenant_id != principal.tenant_id or version.region_id != principal.region_id
        or report_input.get("artifact_version_id") != version.id
        or report_input.get("content_hash") != version.content_hash):
        raise ValueError("Report delivery provenance does not match")
    from .capability_pack_revocations import assert_artifact_version_not_revoked

    assert_artifact_version_not_revoked(db, version.id)
    spec = verified_service_report_version_spec(version)
    if not service_report_is_fully_visible(db, spec, principal):
        raise PermissionError("Report delivery is outside the current run-as service scope")
    instance = None
    if activation.report_attachment_format is not None:
        attachment, instance = verified_report_attachment(db, report_input.get("attachment_id"), principal)
        if (attachment.export_format != activation.report_attachment_format
            or instance.artifact_version_id != version.id
            or attachment_manifest(attachment, instance).model_dump(mode="json") != report_input):
            raise ValueError("Report delivery attachment manifest does not match")
    elif isinstance(spec, GeneratedRetainedProofReportSpec):
        instance = visible_report_instance(db, report_input.get("instance_id"), principal)
        if instance.artifact_version_id != version.id or retained_workflow_input(instance) != report_input:
            raise ValueError("Inline retained report input differs from its exact saved snapshot")
    if isinstance(spec, GeneratedRetainedProofReportSpec):
        evidence = db.scalar(select(InvestigationEvidence.id).where(
            InvestigationEvidence.investigation_id == investigation.id,
            InvestigationEvidence.report_instance_id == instance.id,
            InvestigationEvidence.evidence_type == "service_report_instance",
            InvestigationEvidence.evidence_id == instance.id,
            InvestigationEvidence.tenant_id == principal.tenant_id,
            InvestigationEvidence.region_id == principal.region_id).limit(1))
        if evidence is None:
            raise ValueError("Scheduled retained report lacks its saved evidence binding")
    return instance


def workflow_agent_input(db: Session, investigation: Investigation) -> dict[str, Any]:
    """Keep private inline proof bodies out of Workflow model context.

    Scheduled proof references are reauthorized on every model turn. Fixed
    delivery nodes still consume the original exact approved report object.
    """
    from ..report_schemas import RetainedProofWorkflowInput

    original = investigation.workflow_input or {}
    event = db.get(WorkflowScheduleEvent, investigation.workflow_schedule_event_id) if investigation.workflow_schedule_event_id else None
    activation = db.get(WorkflowScheduleActivation, event.activation_id) if event else None
    if activation and activation.report_artifact_version_id:
        version = db.get(ArtifactVersion, activation.report_artifact_version_id)
        if version is not None and version.definition.get("format_version") == "icheck.service-health-report/v2":
            report = original.get(activation.report_input_key)
            if not isinstance(report, dict):
                raise ValueError("Scheduled retained report input is unavailable")
            _verified_scheduled_report_input(db, investigation, activation, report)
    safe = dict(original)
    for key, value in original.items():
        if not isinstance(value, dict) or value.get("format_version") != "icheck.workflow-retained-report/v1":
            continue
        typed = RetainedProofWorkflowInput.model_validate(value)
        safe[key] = {
            "format_version": "icheck.workflow-retained-report-context/v1",
            "instance_id": str(typed.instance_id),
            "artifact_version_id": str(typed.artifact_version_id),
            "evidence_basis": "saved_snapshot",
            "historical": True,
            "grants_future_authority": False,
            "remediation_causality_proven": False,
            "physical_truth_automatically_verified": False,
            "references": [{"reference_kind": item.reference_kind, "reference_id": str(item.reference_id)}
                           for item in typed.snapshot.spec.retained_proofs],
        }
    return safe


def create_workflow_investigation(
    db: Session,
    version: ArtifactVersion,
    payload: WorkflowInvestigationCreate,
    *,
    principal: PrincipalContext,
    actor: str,
    expected_trigger: str = "manual",
    trigger_event_id: str | None = None,
    schedule_event_id: str | None = None,
    situation_integration_event_id: str | None = None,
    situation_id: str | None = None,
    report_instance_id: str | None = None,
    commit: bool = True,
) -> tuple[Investigation, Any]:
    spec, report = assert_workflow_runtime_compatible(db, version)
    if spec.trigger.trigger_type != expected_trigger:
        raise ValueError(
            f"Workflow trigger is {spec.trigger.trigger_type!r}, not {expected_trigger!r}"
        )
    assert_no_inline_secrets(payload.workflow_input, "workflow.input")
    validate_instance(payload.workflow_input, spec.input_schema, "workflow input")
    required_permissions = report["required_permissions"]
    if not principal.permits("investigations.create", *required_permissions):
        raise PermissionError(
            "Principal lacks one or more permissions required by the Workflow"
        )
    model_turn_budget = sum(
        node.max_iterations or 0
        for node in spec.nodes
        if node.node_type == "agent_loop"
    )
    route = db.scalar(
        select(AIModelRoute).where(AIModelRoute.purpose == payload.route_purpose)
    )
    if route is None:
        raise LookupError(f"AI model route {payload.route_purpose!r} not found")
    if model_turn_budget > route.max_iterations:
        raise ValueError(
            "Workflow agent-loop budget exceeds the selected model route"
        )
    objective = f"Execute published Workflow {version.artifact.name!r}."
    if payload.operator_context:
        objective += f" Operator context: {payload.operator_context}"
    investigation = create_investigation(
        db,
        InvestigationCreate(
            title=payload.title or spec.description[:255],
            objective=objective,
            scope=payload.scope,
            route_purpose=payload.route_purpose,
            created_by=actor,
        ),
        actor=principal,
        commit=False,
    )
    investigation.workflow_artifact_version_id = version.id
    investigation.workflow_input = payload.workflow_input
    investigation.workflow_snapshot = workflow_runtime_snapshot(version, spec)
    investigation.workflow_trigger_event_id = trigger_event_id
    investigation.workflow_schedule_event_id = schedule_event_id
    investigation.situation_integration_event_id = situation_integration_event_id
    investigation.situation_id = situation_id
    if report_instance_id is not None:
        saved_report = visible_report_instance(db, report_instance_id, principal)
        db.add(InvestigationEvidence(
            investigation_id=investigation.id,
            evidence_type="service_report_instance", evidence_id=saved_report.id,
            report_instance_id=saved_report.id,
            summary=f"Scheduled saved Report snapshot SHA256 {saved_report.content_sha256}.",
            observed_at=saved_report.generated_at,
            tenant_id=principal.tenant_id, region_id=principal.region_id,
        ))
    # Graph iterations include deterministic routing decisions. AI turns remain
    # separately bounded by the route check above and each agent-loop node.
    investigation.max_iterations = min(
        1000,
        len(spec.nodes) + spec.max_total_tool_calls + model_turn_budget + 1,
    )
    investigation.max_tool_calls = min(
        investigation.max_tool_calls,
        spec.max_total_tool_calls,
    )
    investigation.timeout_seconds = min(
        investigation.timeout_seconds,
        spec.max_runtime_seconds,
    )
    investigation.token_budget = min(
        investigation.token_budget,
        spec.max_total_tokens,
    )
    record_audit_event(
        db,
        event_type="workflow.investigation.bound",
        actor_type="user",
        actor_id=actor,
        entity_type="investigation",
        entity_id=investigation.id,
        details={
            "workflow_artifact_version_id": version.id,
            "workflow_content_hash": version.content_hash,
            "workflow_input_sha256": _hash(payload.workflow_input),
            "required_permissions": required_permissions,
            "budgets": {
                "max_iterations": investigation.max_iterations,
                "max_tool_calls": investigation.max_tool_calls,
                "timeout_seconds": investigation.timeout_seconds,
                "token_budget": investigation.token_budget,
            },
        },
    )
    return start_investigation(db, investigation, actor=actor, commit=commit)


def _automation_principal(
    db: Session,
    principal_id: str | None,
) -> PrincipalContext:
    if principal_id is None:
        if get_settings().control_plane_auth_mode != "disabled":
            raise ValueError(
                "Required-auth mode needs an enabled run_as_principal_id"
            )
        return development_principal()
    principal = db.scalar(
        select(ControlPlanePrincipal)
        .where(ControlPlanePrincipal.id == principal_id)
        .execution_options(populate_existing=True)
        .options(
            selectinload(ControlPlanePrincipal.role_bindings).selectinload(
                ControlPlaneRoleBinding.role
            )
        )
    )
    if principal is None or not principal.enabled:
        raise ValueError("Workflow run-as principal is unavailable")
    return principal_context(
        principal,
        db=db,
        tenant_selector=str(db.info.get("tenant_id") or principal.tenant_id),
        region_selector=str(db.info.get("region_id") or principal.region_id),
        auth_method="workflow_trigger",
    )


def _validate_alert_input_mapping(
    spec: GeneratedWorkflowSpec,
    mapping: dict[str, str],
) -> None:
    properties = spec.input_schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("Workflow input schema properties are invalid")
    unknown = sorted(set(mapping) - set(properties))
    if unknown:
        raise ValueError(f"Trigger maps unknown Workflow inputs {unknown}")
    missing = sorted(set(spec.input_schema.get("required", [])) - set(mapping))
    if missing:
        raise ValueError(f"Trigger does not map required Workflow inputs {missing}")
    for target, source in mapping.items():
        parts = source.split(".")
        if len(parts) < 2 or parts[0] != "alert" or parts[1] not in ALERT_INPUT_ROOTS:
            raise ValueError(
                f"Trigger mapping for {target!r} must use an allowed alert path"
            )
        if parts[1] != "details" and len(parts) != 2:
            raise ValueError(
                f"Trigger mapping for {target!r} has an invalid alert path"
            )
        if any(not part or len(part) > 128 for part in parts):
            raise ValueError(f"Trigger mapping for {target!r} is invalid")


def _validate_situation_input_mapping(
    spec: GeneratedWorkflowSpec,
    mapping: dict[str, str],
) -> None:
    properties = spec.input_schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("Workflow input schema properties are invalid")
    unknown = sorted(set(mapping) - set(properties))
    if unknown:
        raise ValueError(f"Integration maps unknown Workflow inputs {unknown}")
    missing = sorted(set(spec.input_schema.get("required", [])) - set(mapping))
    if missing:
        raise ValueError(f"Integration does not map required Workflow inputs {missing}")
    for target, source in mapping.items():
        parts = source.split(".")
        valid = False
        if len(parts) == 2 and parts[0] == "situation":
            valid = parts[1] in SITUATION_INPUT_ROOTS
        elif len(parts) == 2 and parts[0] == "event":
            valid = parts[1] in SITUATION_EVENT_INPUT_ROOTS - {"details"}
        elif len(parts) == 3 and parts[:2] == ["event", "details"]:
            valid = bool(parts[2])
        if not valid or any(not part or len(part) > 128 for part in parts):
            raise ValueError(
                f"Integration mapping for {target!r} has an invalid Situation path"
            )


def create_situation_integration_binding(
    db: Session,
    version: ArtifactVersion,
    payload: SituationIntegrationBindingCreate,
    *,
    actor: str,
) -> SituationIntegrationBinding:
    spec, report = assert_workflow_runtime_compatible(db, version)
    if spec.trigger.trigger_type != "situation" or not spec.trigger.event_type:
        raise ValueError("Only Situation-triggered Workflow versions can be bound")
    if spec.trigger.event_type not in SITUATION_INTEGRATION_EVENT_TYPES:
        raise ValueError("Situation integration event type is not allowed")
    dependencies = version.definition.get("tool_dependencies", [])
    if not any(item.get("transport") == "mcp" for item in dependencies):
        raise ValueError("Situation integrations require an MCP tool dependency")
    _validate_situation_input_mapping(spec, payload.input_mapping)
    validate_remote_reference_contract(
        db,
        dependencies=dependencies,
        tool_name=payload.remote_reference_tool_name,
        mapping=payload.remote_reference_mapping,
    )
    public_key_sha256 = (
        validate_inbound_public_key(payload.inbound_public_key_pem)
        if payload.inbound_enabled and payload.inbound_public_key_pem
        else None
    )
    assert_no_inline_secrets(
        payload.authorization_scope,
        "situation integration scope",
    )
    run_as = _automation_principal(db, payload.run_as_principal_id)
    if not run_as.permits(
        "alerts.read",
        "investigations.create",
        *report["required_permissions"],
    ):
        raise PermissionError(
            "Integration run-as principal lacks required execution permissions"
        )
    require_requested_investigation_scope(
        db,
        run_as,
        payload.authorization_scope,
    )
    binding = SituationIntegrationBinding(
        artifact_version_id=version.id,
        channel_kind=payload.channel_kind,
        event_type=spec.trigger.event_type,
        route_purpose=payload.route_purpose,
        run_as_principal_id=payload.run_as_principal_id,
        authorization_scope=payload.authorization_scope,
        input_mapping=payload.input_mapping,
        provider_key=payload.provider_key,
        remote_reference_tool_name=payload.remote_reference_tool_name,
        remote_reference_mapping=payload.remote_reference_mapping,
        inbound_enabled=payload.inbound_enabled,
        inbound_key_id=payload.inbound_key_id,
        inbound_public_key_pem=payload.inbound_public_key_pem,
        inbound_public_key_sha256=public_key_sha256,
        enabled=True,
        created_by=actor,
    )
    db.add(binding)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="situation.integration.bound",
            actor_type="user",
            actor_id=actor,
            entity_type="situation_integration_binding",
            entity_id=binding.id,
            details={
                "artifact_version_id": version.id,
                "channel_kind": binding.channel_kind,
                "event_type": binding.event_type,
                "run_as_principal_id": binding.run_as_principal_id,
                "authorization_scope": binding.authorization_scope,
                "input_mapping": binding.input_mapping,
                "provider_key": binding.provider_key,
                "remote_reference_tool_name": binding.remote_reference_tool_name,
                "remote_reference_mapping": binding.remote_reference_mapping,
                "inbound_enabled": binding.inbound_enabled,
                "inbound_key_id": binding.inbound_key_id,
                "inbound_public_key_sha256": binding.inbound_public_key_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Workflow version already has a Situation integration binding"
        ) from exc
    db.refresh(binding)
    return binding


def disable_situation_integration_binding(
    db: Session,
    binding: SituationIntegrationBinding,
    *,
    actor: str,
) -> SituationIntegrationBinding:
    if not binding.enabled:
        return binding
    binding.enabled = False
    binding.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="situation.integration.disabled",
        actor_type="user",
        actor_id=actor,
        entity_type="situation_integration_binding",
        entity_id=binding.id,
        details={"artifact_version_id": binding.artifact_version_id},
    )
    db.commit()
    db.refresh(binding)
    return binding


def enqueue_situation_integration_events(
    db: Session,
    event: SituationEvent,
) -> int:
    if event.event_type not in SITUATION_INTEGRATION_EVENT_TYPES:
        return 0
    db.flush()
    bindings = list(
        db.scalars(
            select(SituationIntegrationBinding)
            .join(
                ArtifactVersion,
                ArtifactVersion.id
                == SituationIntegrationBinding.artifact_version_id,
            )
            .where(
                SituationIntegrationBinding.enabled.is_(True),
                SituationIntegrationBinding.event_type == event.event_type,
                ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            )
        ).all()
    )
    for binding in bindings:
        db.add(
            SituationIntegrationEvent(
                binding_id=binding.id,
                situation_id=event.situation_id,
                situation_event_id=event.id,
                event_type=event.event_type,
                status="pending",
            )
        )
    return len(bindings)


def _situation_integration_document(
    situation: Situation,
    event: SituationEvent,
) -> dict[str, Any]:
    return {
        "situation": {
            "id": situation.id,
            "title": situation.title,
            "summary": situation.summary,
            "status": situation.status,
            "severity": situation.severity.value,
            "priority_score": situation.priority_score,
            "primary_entity_type": situation.primary_entity_type,
            "primary_entity_id": situation.primary_entity_id,
            "alert_count": situation.alert_count,
            "active_alert_count": situation.active_alert_count,
            "occurrence_count": situation.occurrence_count,
            "first_seen": situation.first_seen.isoformat(),
            "last_seen": situation.last_seen.isoformat(),
        },
        "event": {
            "id": event.id,
            "event_type": event.event_type,
            "sequence": event.sequence,
            "actor": event.actor,
            "created_at": event.created_at.isoformat(),
            "details": event.details,
        },
    }


def _mapped_situation_input(
    binding: SituationIntegrationBinding,
    situation: Situation,
    event: SituationEvent,
) -> dict[str, Any]:
    document: Any = _situation_integration_document(situation, event)
    result: dict[str, Any] = {}
    for target, source in binding.input_mapping.items():
        current = document
        for part in source.split("."):
            if not isinstance(current, dict) or part not in current:
                raise ValueError(f"Situation integration source {source!r} is missing")
            current = current[part]
        result[target] = current
    return result


def _stop_exhausted_dispatch(
    db: Session,
    event: SituationIntegrationEvent | WorkflowTriggerEvent | WorkflowScheduleEvent,
) -> bool:
    """Close a lost third claim only after checking for its committed result."""
    if event.attempt_count < 3:
        return False
    event.status = "failed"
    event.error_type = "DispatchAttemptsExhausted"
    event.error_sha256 = None
    event.updated_at = utcnow()
    db.commit()
    return True


class DispatchLeaseLost(RuntimeError):
    """A different attempt, terminal result or expired claim owns the event."""


def _assert_dispatch_claim(event: Any, attempt: int) -> None:
    if (
        event is None
        or event.status != "processing"
        or event.attempt_count != attempt
        or _as_utc(event.updated_at) <= utcnow() - timedelta(minutes=5)
    ):
        raise DispatchLeaseLost("Workflow dispatch claim is no longer active")


def _locked_dispatch_claim(
    db: Session, event_type: Any, event_id: str, attempt: int,
) -> Any:
    # Keep this mutex through report/quota/checkpoint/queue creation and the
    # terminal outbox update. Dispatch does not invoke external models/Tools.
    event = db.scalar(
        select(event_type).where(event_type.id == event_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    _assert_dispatch_claim(event, attempt)
    return event


def _complete_dispatch(db: Session, event: Any, attempt: int) -> None:
    # An expensive local capture may outlive the claim even while its mutex is
    # held. Roll back all staged results rather than publish under an expiry.
    _assert_dispatch_claim(event, attempt)
    event.status = "succeeded"
    event.error_type = None
    event.error_sha256 = None
    event.updated_at = utcnow()
    db.commit()


def _fail_dispatch(
    db: Session, event_type: Any, event_id: str, attempt: int, exc: Exception,
) -> None:
    db.rollback()
    try:
        event = _locked_dispatch_claim(db, event_type, event_id, attempt)
    except DispatchLeaseLost:
        db.rollback()
        return
    event.status = "failed"
    event.error_type = type(exc).__name__[:255]
    event.error_sha256 = hashlib.sha256(
        f"{type(exc).__name__}:{exc}".encode("utf-8")
    ).hexdigest()
    event.updated_at = utcnow()
    db.commit()


def dispatch_situation_integration_events(
    db: Session,
    *,
    limit: int = 10,
) -> int:
    require_locking_transaction(db, purpose="Workflow dispatch claims")
    dispatched = 0
    stale_before = datetime.now(UTC) - timedelta(minutes=5)
    for _ in range(max(0, min(limit, 100))):
        event = db.scalar(
            select(SituationIntegrationEvent)
            .where(
                or_(
                    SituationIntegrationEvent.status == "pending",
                    and_(
                        SituationIntegrationEvent.status == "failed",
                        SituationIntegrationEvent.attempt_count < 3,
                    ),
                    and_(
                        SituationIntegrationEvent.status == "processing",
                        SituationIntegrationEvent.updated_at < stale_before,
                    ),
                )
            )
            .order_by(
                SituationIntegrationEvent.created_at,
                SituationIntegrationEvent.id,
            )
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
            .limit(1)
        )
        if event is None:
            break
        existing = db.scalar(
            select(Investigation).where(
                Investigation.situation_integration_event_id == event.id
            )
        )
        if existing is not None:
            event.status = "succeeded"
            event.error_type = None
            event.error_sha256 = None
            event.updated_at = utcnow()
            db.commit()
            dispatched += 1
            continue
        if _stop_exhausted_dispatch(db, event):
            continue
        event.status = "processing"
        event.attempt_count += 1
        event.updated_at = utcnow()
        event_id = event.id
        attempt = event.attempt_count
        db.commit()
        try:
            event = _locked_dispatch_claim(db, SituationIntegrationEvent, event_id, attempt)
            binding = db.get(SituationIntegrationBinding, event.binding_id)
            source_event = db.get(SituationEvent, event.situation_event_id)
            if binding is None or source_event is None or not binding.enabled:
                raise ValueError("Situation integration binding or event is unavailable")
            if source_event.situation_id != event.situation_id:
                raise ValueError("Situation integration event scope is inconsistent")
            run_as = _automation_principal(db, binding.run_as_principal_id)
            if not run_as.permits("alerts.read", "investigations.create"):
                raise PermissionError(
                    "Integration run-as principal no longer permits Situation access"
                )
            situation = require_situation_access(db, run_as, event.situation_id)
            require_requested_investigation_scope(
                db,
                run_as,
                binding.authorization_scope,
            )
            version = workflow_version(db, binding.artifact_version_id)
            create_workflow_investigation(
                db,
                version,
                WorkflowInvestigationCreate(
                    title=f"{version.artifact.name}: {situation.title}"[:255],
                    workflow_input=_mapped_situation_input(
                        binding,
                        situation,
                        source_event,
                    ),
                    scope=binding.authorization_scope,
                    operator_context=(
                        f"Triggered by Situation {situation.id} lifecycle event "
                        f"{source_event.event_type} ({source_event.id})."
                    ),
                    route_purpose=binding.route_purpose,
                    actor=run_as.subject,
                ),
                principal=run_as,
                actor=run_as.subject,
                expected_trigger="situation",
                situation_integration_event_id=event.id,
                situation_id=situation.id,
                commit=False,
            )
            _complete_dispatch(db, event, attempt)
            dispatched += 1
        except Exception as exc:
            _fail_dispatch(db, SituationIntegrationEvent, event_id, attempt, exc)
    return dispatched


def create_workflow_trigger_activation(
    db: Session,
    version: ArtifactVersion,
    payload: WorkflowTriggerActivationCreate,
    *,
    actor: str,
) -> WorkflowTriggerActivation:
    spec, report = assert_workflow_runtime_compatible(db, version)
    if spec.trigger.trigger_type != "alert" or not spec.trigger.event_type:
        raise ValueError("Only alert-triggered Workflow versions can be activated")
    _validate_alert_input_mapping(spec, payload.input_mapping)
    assert_no_inline_secrets(payload.authorization_scope, "workflow trigger scope")
    run_as = _automation_principal(db, payload.run_as_principal_id)
    if not run_as.permits("investigations.create", *report["required_permissions"]):
        raise PermissionError(
            "Workflow run-as principal lacks required execution permissions"
        )
    require_requested_investigation_scope(
        db,
        run_as,
        payload.authorization_scope,
    )
    activation = WorkflowTriggerActivation(
        artifact_version_id=version.id,
        event_type=spec.trigger.event_type,
        route_purpose=payload.route_purpose,
        run_as_principal_id=payload.run_as_principal_id,
        authorization_scope=payload.authorization_scope,
        input_mapping=payload.input_mapping,
        enabled=True,
        created_by=actor,
    )
    db.add(activation)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="workflow.trigger.activated",
            actor_type="user",
            actor_id=actor,
            entity_type="workflow_trigger_activation",
            entity_id=activation.id,
            details={
                "artifact_version_id": version.id,
                "event_type": activation.event_type,
                "run_as_principal_id": activation.run_as_principal_id,
                "authorization_scope": activation.authorization_scope,
                "input_mapping": activation.input_mapping,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Workflow version already has a trigger activation") from exc
    db.refresh(activation)
    return activation


def disable_workflow_trigger_activation(
    db: Session,
    activation: WorkflowTriggerActivation,
    *,
    actor: str,
) -> WorkflowTriggerActivation:
    if not activation.enabled:
        return activation
    activation.enabled = False
    activation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="workflow.trigger.disabled",
        actor_type="user",
        actor_id=actor,
        entity_type="workflow_trigger_activation",
        entity_id=activation.id,
        details={"artifact_version_id": activation.artifact_version_id},
    )
    db.commit()
    db.refresh(activation)
    return activation


def enqueue_alert_trigger_events(db: Session, alert: Alert) -> int:
    activations = list(
        db.scalars(
            select(WorkflowTriggerActivation)
            .join(
                ArtifactVersion,
                ArtifactVersion.id == WorkflowTriggerActivation.artifact_version_id,
            )
            .where(
                WorkflowTriggerActivation.enabled.is_(True),
                WorkflowTriggerActivation.event_type == alert.event_type,
                ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            )
        ).all()
    )
    for activation in activations:
        db.add(
            WorkflowTriggerEvent(
                activation_id=activation.id,
                alert_id=alert.id,
                status="pending",
            )
        )
    return len(activations)


def _alert_document(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "event_type": alert.event_type,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "entity_type": alert.entity_type,
        "entity_id": alert.entity_id,
        "occurrence_count": alert.occurrence_count,
        "details": alert.details,
    }


def _mapped_alert_input(
    activation: WorkflowTriggerActivation,
    alert: Alert,
) -> dict[str, Any]:
    document: Any = {"alert": _alert_document(alert)}
    result: dict[str, Any] = {}
    for target, source in activation.input_mapping.items():
        current = document
        for part in source.split("."):
            if not isinstance(current, dict) or part not in current:
                raise ValueError(f"Alert trigger source {source!r} is missing")
            current = current[part]
        result[target] = current
    return result


def dispatch_workflow_trigger_events(
    db: Session,
    *,
    limit: int = 10,
) -> int:
    require_locking_transaction(db, purpose="Workflow dispatch claims")
    dispatched = 0
    stale_before = datetime.now(UTC) - timedelta(minutes=5)
    for _ in range(max(0, min(limit, 100))):
        event = db.scalar(
            select(WorkflowTriggerEvent)
            .where(
                or_(
                    WorkflowTriggerEvent.status == "pending",
                    and_(
                        WorkflowTriggerEvent.status == "failed",
                        WorkflowTriggerEvent.attempt_count < 3,
                    ),
                    and_(
                        WorkflowTriggerEvent.status == "processing",
                        WorkflowTriggerEvent.updated_at < stale_before,
                    ),
                )
            )
            .order_by(WorkflowTriggerEvent.created_at, WorkflowTriggerEvent.id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
            .limit(1)
        )
        if event is None:
            break
        existing = db.scalar(
            select(Investigation).where(
                Investigation.workflow_trigger_event_id == event.id
            )
        )
        if existing is not None:
            event.status = "succeeded"
            event.error_type = None
            event.error_sha256 = None
            event.updated_at = utcnow()
            db.commit()
            dispatched += 1
            continue
        if _stop_exhausted_dispatch(db, event):
            continue
        event.status = "processing"
        event.attempt_count += 1
        event.updated_at = utcnow()
        event_id = event.id
        attempt = event.attempt_count
        db.commit()
        try:
            event = _locked_dispatch_claim(db, WorkflowTriggerEvent, event_id, attempt)
            activation = db.get(WorkflowTriggerActivation, event.activation_id)
            alert = db.get(Alert, event.alert_id)
            if activation is None or alert is None or not activation.enabled:
                raise ValueError("Workflow trigger activation or alert is unavailable")
            run_as = _automation_principal(db, activation.run_as_principal_id)
            if not run_as.permits("alerts.read", "investigations.create"):
                raise PermissionError("Workflow run-as principal no longer permits Alert access")
            # The approved workflow scope alone does not authorize embedding
            # source Alert fields into the investigation's immutable input.
            alert = require_alert_access(db, run_as, event.alert_id)
            require_requested_investigation_scope(
                db,
                run_as,
                activation.authorization_scope,
            )
            version = workflow_version(db, activation.artifact_version_id)
            create_workflow_investigation(
                db,
                version,
                WorkflowInvestigationCreate(
                    title=f"{version.artifact.name}: {alert.title}"[:255],
                    workflow_input=_mapped_alert_input(activation, alert),
                    scope=activation.authorization_scope,
                    operator_context=(
                        f"Triggered by alert {alert.id} ({alert.event_type})."
                    ),
                    route_purpose=activation.route_purpose,
                    actor=run_as.subject,
                ),
                principal=run_as,
                actor=run_as.subject,
                expected_trigger="alert",
                trigger_event_id=event.id,
                commit=False,
            )
            _complete_dispatch(db, event, attempt)
            dispatched += 1
        except Exception as exc:
            _fail_dispatch(db, WorkflowTriggerEvent, event_id, attempt, exc)
    return dispatched


def _assert_report_delivery_dependency(
    version: ArtifactVersion,
    spec: GeneratedWorkflowSpec,
    report_input_key: str,
) -> tuple[str, str]:
    dependencies = version.definition.get("tool_dependencies", [])
    mcp_tools = {
        str(item.get("name"))
        for item in dependencies
        if isinstance(item, dict)
        and item.get("transport") == "mcp"
        and item.get("risk_level") == "change"
        and item.get("read_only") is False
    }
    if not mcp_tools:
        raise ValueError(
            "Scheduled report delivery requires a pinned state-changing MCP "
            "Tool dependency"
        )
    bound_nodes = [
        (node.node_id, str(node.tool_name), binding.argument)
        for node in spec.nodes
        if node.node_type == "tool"
        and node.tool_name in mcp_tools
        for binding in node.input_bindings
        if binding.input_path == report_input_key
    ]
    if not bound_nodes:
        raise ValueError(
            "Scheduled report input must bind directly to a pinned MCP Tool"
        )
    if len(bound_nodes) != 1:
        raise ValueError(
            "Scheduled report delivery requires exactly one primary MCP Tool "
            "binding"
        )
    _node_id, tool_name, argument = bound_nodes[0]
    return tool_name, argument


def _scheduled_report_workflow_input(
    db: Session,
    report_version_id: str,
    report_input_key: str,
    static_input: dict[str, Any],
    principal: PrincipalContext,
    *, attachment_format: ReportExportFormat | None = None,
    schedule_event_id: str | None = None,
) -> dict[str, Any]:
    if report_input_key in static_input:
        raise ValueError(
            "Static Workflow input cannot override the generated report input"
        )
    if not principal.permits("services.read"):
        raise PermissionError(
            "Workflow run-as principal lacks service report read permission"
        )
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == report_version_id)
        .options(selectinload(ArtifactVersion.artifact))
    )
    if version is None:
        raise ValueError("Scheduled Report Artifact version is unavailable")
    if (
        version.artifact.kind != ArtifactKind.REPORT
        or version.status != ArtifactVersionStatus.PUBLISHED
    ):
        raise ValueError(
            "Scheduled report requires an exact published Report Artifact version"
        )
    if version.content_hash is None or version.published_at is None:
        raise ValueError("Scheduled Report Artifact provenance is incomplete")
    spec = published_service_report_spec(
        version.definition,
        version.implementation,
        version.tests,
    )
    if not service_report_is_fully_visible(db, spec, principal):
        raise PermissionError(
            "Scheduled Report Artifact is outside the run-as service scope"
        )
    if attachment_format is not None or isinstance(spec, GeneratedRetainedProofReportSpec):
        capture = ServiceReportInstanceCreate(
            version_id=version.id,
            request_key=uuid5(NAMESPACE_URL, f"icheck.workflow-schedule:{schedule_event_id}")
            if schedule_event_id else uuid4(),
        )
        if schedule_event_id is None:
            instance = build_report_instance(db, version.artifact_id, capture, principal)
            if attachment_format is None:
                return {**static_input, report_input_key: retained_workflow_input(instance)}
            manifest = attachment_manifest(render_attachment(instance, attachment_format, principal), instance)
        else:
            instance, _created = capture_report_instance(db, version.artifact_id, capture, principal, commit=False)
            if attachment_format is None:
                return {**static_input, report_input_key: retained_workflow_input(instance)}
            manifest, _created = create_report_attachment(db, instance.id, attachment_format, principal, commit=False)
        return {**static_input, report_input_key: manifest.model_dump(mode="json")}
    generated = service_report_runtime_generate(db, spec, principal)
    report_input = {
        "artifact_id": version.artifact_id,
        "artifact_version_id": version.id,
        "artifact_version": version.version,
        "content_hash": version.content_hash,
        "published_at": version.published_at.isoformat(),
        **generated,
    }
    return {**static_input, report_input_key: report_input}


def _report_delivery_postcheck_tool(
    spec: GeneratedWorkflowSpec, tool_name: str, input_key: str,
) -> str:
    producer = next((node for node in spec.nodes if node.node_type == "tool"
                     and node.tool_name == tool_name
                     and any(binding.input_path == input_key for binding in node.input_bindings)), None)
    postcheck = next((node for node in spec.nodes if producer and node.node_id == producer.on_success), None)
    if postcheck is None or postcheck.node_type != "post_check" or not postcheck.tool_name:
        raise ValueError("Report attachment delivery requires a declared post-check Tool")
    return postcheck.tool_name


def create_workflow_schedule_activation(
    db: Session,
    version: ArtifactVersion,
    payload: WorkflowScheduleActivationCreate,
    *,
    actor: str,
) -> WorkflowScheduleActivation:
    spec, report = assert_workflow_runtime_compatible(db, version)
    if spec.trigger.trigger_type != "schedule":
        raise ValueError("Only schedule-triggered Workflow versions can be activated")
    assert_no_inline_secrets(payload.authorization_scope, "workflow schedule scope")
    assert_no_inline_secrets(payload.workflow_input, "workflow schedule input")
    run_as = _automation_principal(db, payload.run_as_principal_id)
    required_permissions = list(report["required_permissions"])
    if payload.report_artifact_version_id is not None:
        required_permissions.append("services.read")
    if not run_as.permits("investigations.create", *required_permissions):
        raise PermissionError(
            "Workflow run-as principal lacks required execution permissions"
        )
    require_requested_investigation_scope(
        db,
        run_as,
        payload.authorization_scope,
    )
    workflow_input = dict(payload.workflow_input)
    delivery_tool_name: str | None = None
    delivery_tool_argument: str | None = None
    if payload.report_artifact_version_id is not None:
        if payload.report_input_key is None:
            raise ValueError("Report schedule input key is unavailable")
        assert_no_inline_secrets(
            payload.report_delivery_receipt_mapping,
            "report delivery receipt mapping",
        )
        delivery_tool_name, delivery_tool_argument = (
            _assert_report_delivery_dependency(
                version,
                spec,
                payload.report_input_key,
            )
        )
        validate_report_delivery_receipt_contract(
            db,
            dependencies=version.definition.get("tool_dependencies", []),
            tool_name=delivery_tool_name,
            mapping=payload.report_delivery_receipt_mapping,
            postcheck_tool_name=(_report_delivery_postcheck_tool(spec, delivery_tool_name, payload.report_input_key)
                                 if payload.report_attachment_format else None),
        )
        workflow_input = _scheduled_report_workflow_input(
            db,
            payload.report_artifact_version_id,
            payload.report_input_key,
            workflow_input,
            run_as,
            attachment_format=payload.report_attachment_format,
        )
    validate_instance(workflow_input, spec.input_schema, "workflow input")
    now = utcnow()
    cron_expression, next_fire_at = validate_cron_schedule(
        payload.cron_expression,
        payload.timezone,
        after=now,
    )
    exclusion_windows = [
        window.model_dump(mode="json") for window in payload.exclusion_windows
    ]
    assert_no_inline_secrets(
        exclusion_windows,
        "workflow schedule exclusion calendar",
    )
    activation = WorkflowScheduleActivation(
        artifact_version_id=version.id,
        cron_expression=cron_expression,
        timezone=payload.timezone,
        route_purpose=payload.route_purpose,
        run_as_principal_id=payload.run_as_principal_id,
        authorization_scope=payload.authorization_scope,
        workflow_input=payload.workflow_input,
        report_artifact_version_id=payload.report_artifact_version_id,
        report_input_key=payload.report_input_key,
        report_attachment_format=payload.report_attachment_format,
        report_delivery_tool_name=delivery_tool_name,
        report_delivery_tool_argument=delivery_tool_argument,
        report_delivery_provider_key=payload.report_delivery_provider_key,
        report_delivery_receipt_mapping=(
            payload.report_delivery_receipt_mapping
        ),
        misfire_grace_seconds=payload.misfire_grace_seconds,
        exclusion_windows=exclusion_windows,
        next_fire_at=next_fire_at,
        enabled=True,
        created_by=actor,
    )
    db.add(activation)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="workflow.schedule.activated",
            actor_type="user",
            actor_id=actor,
            entity_type="workflow_schedule_activation",
            entity_id=activation.id,
            details={
                "artifact_version_id": version.id,
                "cron_expression": activation.cron_expression,
                "timezone": activation.timezone,
                "next_fire_at": activation.next_fire_at.isoformat(),
                "run_as_principal_id": activation.run_as_principal_id,
                "authorization_scope_sha256": _hash(
                    activation.authorization_scope
                ),
                "workflow_input_sha256": _hash(activation.workflow_input),
                "report_artifact_version_id": (
                    activation.report_artifact_version_id
                ),
                "report_input_key": activation.report_input_key,
                "report_attachment_format": activation.report_attachment_format,
                "report_delivery_tool_name": (
                    activation.report_delivery_tool_name
                ),
                "report_delivery_tool_argument": (
                    activation.report_delivery_tool_argument
                ),
                "report_delivery_provider_key": (
                    activation.report_delivery_provider_key
                ),
                "report_delivery_receipt_mapping_sha256": _hash(
                    activation.report_delivery_receipt_mapping
                ),
                "misfire_grace_seconds": activation.misfire_grace_seconds,
                "exclusion_window_count": len(exclusion_windows),
                "exclusion_calendar_sha256": _hash(exclusion_windows),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Workflow version already has a schedule activation") from exc
    db.refresh(activation)
    return activation


def update_workflow_schedule_exclusions(
    db: Session,
    activation_id: str,
    payload: WorkflowScheduleExclusionsUpdate,
    *,
    actor: str,
) -> WorkflowScheduleActivation:
    activation = db.scalar(
        select(WorkflowScheduleActivation)
        .where(WorkflowScheduleActivation.id == activation_id)
        .with_for_update()
    )
    if activation is None:
        raise LookupError("Workflow schedule not found")
    if not activation.enabled:
        raise ValueError("Disabled Workflow schedules cannot change exclusions")
    if activation.revision != payload.expected_revision:
        raise ValueError("Workflow schedule revision conflict")
    exclusion_windows = [
        window.model_dump(mode="json") for window in payload.exclusion_windows
    ]
    assert_no_inline_secrets(
        exclusion_windows,
        "workflow schedule exclusion calendar",
    )
    previous_sha256 = _hash(activation.exclusion_windows)
    activation.exclusion_windows = exclusion_windows
    activation.revision += 1
    activation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="workflow.schedule.exclusions.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="workflow_schedule_activation",
        entity_id=activation.id,
        details={
            "artifact_version_id": activation.artifact_version_id,
            "expected_revision": payload.expected_revision,
            "revision": activation.revision,
            "previous_calendar_sha256": previous_sha256,
            "exclusion_calendar_sha256": _hash(exclusion_windows),
            "exclusion_window_count": len(exclusion_windows),
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(activation)
    return activation


def disable_workflow_schedule_activation(
    db: Session,
    activation: WorkflowScheduleActivation,
    *,
    actor: str,
) -> WorkflowScheduleActivation:
    if not activation.enabled:
        return activation
    activation.enabled = False
    activation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="workflow.schedule.disabled",
        actor_type="user",
        actor_id=actor,
        entity_type="workflow_schedule_activation",
        entity_id=activation.id,
        details={"artifact_version_id": activation.artifact_version_id},
    )
    db.commit()
    db.refresh(activation)
    return activation


def _matching_schedule_exclusion(
    activation: WorkflowScheduleActivation,
    scheduled_for: datetime,
) -> WorkflowScheduleExclusionWindow | None:
    occurrence = _as_utc(scheduled_for)
    for document in activation.exclusion_windows:
        window = WorkflowScheduleExclusionWindow.model_validate(document)
        if window.starts_at <= occurrence < window.ends_at:
            return window
    return None


def enqueue_due_workflow_schedules(
    db: Session,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> int:
    require_locking_transaction(db, purpose="Workflow schedule occurrence publication")
    current = _as_utc(now or utcnow())
    activations = list(
        db.scalars(
            select(WorkflowScheduleActivation)
            .join(
                ArtifactVersion,
                ArtifactVersion.id
                == WorkflowScheduleActivation.artifact_version_id,
            )
            .where(
                WorkflowScheduleActivation.enabled.is_(True),
                WorkflowScheduleActivation.next_fire_at <= current,
                ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
            )
            .order_by(
                WorkflowScheduleActivation.next_fire_at,
                WorkflowScheduleActivation.id,
            )
            .with_for_update(of=WorkflowScheduleActivation, skip_locked=True)
            .execution_options(populate_existing=True)
            .limit(max(0, min(limit, 1000)))
        ).all()
    )
    enqueued = 0
    for activation in activations:
        scheduled_for = _as_utc(activation.next_fire_at)
        try:
            exclusion = _matching_schedule_exclusion(
                activation,
                scheduled_for,
            )
        except ValueError:
            activation.enabled = False
            activation.updated_at = current
            record_audit_event(
                db,
                event_type="workflow.schedule.exclusions.invalid",
                actor_type="system",
                actor_id="workflow.scheduler",
                entity_type="workflow_schedule_activation",
                entity_id=activation.id,
                outcome="failure",
                details={
                    "exclusion_calendar_sha256": _hash(
                        activation.exclusion_windows
                    ),
                    "revision": activation.revision,
                },
            )
            continue
        if exclusion is not None:
            db.add(
                WorkflowScheduleEvent(
                    activation_id=activation.id,
                    scheduled_for=scheduled_for,
                    status="skipped",
                    skip_reason="calendar_exclusion",
                    exclusion_window_id=exclusion.id,
                )
            )
            activation.excluded_runs += 1
            activation.last_excluded_at = scheduled_for
            activation.next_fire_at = next_cron_occurrence(
                activation.cron_expression,
                activation.timezone,
                current,
            )
            activation.updated_at = current
            record_audit_event(
                db,
                event_type="workflow.schedule.excluded",
                actor_type="system",
                actor_id="workflow.scheduler",
                entity_type="workflow_schedule_activation",
                entity_id=activation.id,
                details={
                    "scheduled_for": scheduled_for.isoformat(),
                    "next_fire_at": activation.next_fire_at.isoformat(),
                    "exclusion_window_id": exclusion.id,
                    "excluded_runs": activation.excluded_runs,
                    "revision": activation.revision,
                },
            )
            continue
        lateness = (current - scheduled_for).total_seconds()
        if lateness > activation.misfire_grace_seconds:
            activation.missed_runs += 1
            activation.last_misfire_at = current
            activation.next_fire_at = next_cron_occurrence(
                activation.cron_expression,
                activation.timezone,
                current,
            )
            activation.updated_at = current
            record_audit_event(
                db,
                event_type="workflow.schedule.misfired",
                actor_type="system",
                actor_id="workflow.scheduler",
                entity_type="workflow_schedule_activation",
                entity_id=activation.id,
                outcome="failure",
                details={
                    "scheduled_for": scheduled_for.isoformat(),
                    "observed_at": current.isoformat(),
                    "next_fire_at": activation.next_fire_at.isoformat(),
                    "missed_runs": activation.missed_runs,
                },
            )
            continue
        db.add(
            WorkflowScheduleEvent(
                activation_id=activation.id,
                scheduled_for=scheduled_for,
                status="pending",
            )
        )
        activation.last_fire_at = scheduled_for
        # Coalesce any additional occurrences already behind this scheduler
        # scan. A late-but-within-grace activation emits one durable event and
        # must advance to a future occurrence instead of creating a catch-up
        # storm on the next poll.
        activation.next_fire_at = next_cron_occurrence(
            activation.cron_expression,
            activation.timezone,
            current,
        )
        activation.updated_at = current
        enqueued += 1
    if activations:
        db.commit()
    return enqueued


def dispatch_workflow_schedule_events(
    db: Session,
    *,
    limit: int = 10,
) -> int:
    require_locking_transaction(db, purpose="Workflow dispatch claims")
    dispatched = 0
    stale_before = datetime.now(UTC) - timedelta(minutes=5)
    for _ in range(max(0, min(limit, 100))):
        event = db.scalar(
            select(WorkflowScheduleEvent)
            .where(
                or_(
                    WorkflowScheduleEvent.status == "pending",
                    and_(
                        WorkflowScheduleEvent.status == "failed",
                        WorkflowScheduleEvent.attempt_count < 3,
                    ),
                    and_(
                        WorkflowScheduleEvent.status == "processing",
                        WorkflowScheduleEvent.updated_at < stale_before,
                    ),
                )
            )
            .order_by(
                WorkflowScheduleEvent.scheduled_for,
                WorkflowScheduleEvent.id,
            )
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
            .limit(1)
        )
        if event is None:
            break
        existing = db.scalar(
            select(Investigation).where(
                Investigation.workflow_schedule_event_id == event.id
            )
        )
        if existing is not None:
            event.status = "succeeded"
            event.error_type = None
            event.error_sha256 = None
            event.updated_at = utcnow()
            db.commit()
            dispatched += 1
            continue
        if _stop_exhausted_dispatch(db, event):
            continue
        event.status = "processing"
        event.attempt_count += 1
        event.updated_at = utcnow()
        event_id = event.id
        attempt = event.attempt_count
        db.commit()
        try:
            event = _locked_dispatch_claim(db, WorkflowScheduleEvent, event_id, attempt)
            activation = db.get(WorkflowScheduleActivation, event.activation_id)
            if activation is None or not activation.enabled:
                raise ValueError("Workflow schedule activation is unavailable")
            run_as = _automation_principal(db, activation.run_as_principal_id)
            require_requested_investigation_scope(
                db,
                run_as,
                activation.authorization_scope,
            )
            version = workflow_version(db, activation.artifact_version_id)
            scheduled_for = _as_utc(event.scheduled_for)
            workflow_input = dict(activation.workflow_input)
            if activation.report_artifact_version_id is not None:
                if activation.report_input_key is None:
                    raise ValueError("Report schedule input key is unavailable")
                spec, _report = assert_workflow_runtime_compatible(db, version)
                delivery_tool_name, delivery_tool_argument = (
                    _assert_report_delivery_dependency(
                        version,
                        spec,
                        activation.report_input_key,
                    )
                )
                if activation.report_delivery_tool_name is not None:
                    if (
                        activation.report_delivery_tool_name
                        != delivery_tool_name
                        or activation.report_delivery_tool_argument
                        != delivery_tool_argument
                        or not activation.report_delivery_provider_key
                    ):
                        raise ValueError(
                            "Report delivery Tool binding drifted from activation"
                        )
                    validate_report_delivery_receipt_contract(
                        db,
                        dependencies=version.definition.get(
                            "tool_dependencies", []
                        ),
                        tool_name=delivery_tool_name,
                        mapping=activation.report_delivery_receipt_mapping,
                        postcheck_tool_name=(_report_delivery_postcheck_tool(spec, delivery_tool_name, activation.report_input_key)
                                             if activation.report_attachment_format else None),
                    )
                workflow_input = _scheduled_report_workflow_input(
                    db,
                    activation.report_artifact_version_id,
                    activation.report_input_key,
                    workflow_input,
                    run_as,
                    attachment_format=activation.report_attachment_format,
                    schedule_event_id=event.id,
                )
            create_workflow_investigation(
                db,
                version,
                WorkflowInvestigationCreate(
                    title=(
                        f"{version.artifact.name}: scheduled "
                        f"{scheduled_for.isoformat()}"
                    )[:255],
                    workflow_input=workflow_input,
                    scope=activation.authorization_scope,
                    operator_context=(
                        f"Triggered by schedule occurrence {event.id} at "
                        f"{scheduled_for.isoformat()}."
                    ),
                    route_purpose=activation.route_purpose,
                    actor=run_as.subject,
                ),
                principal=run_as,
                actor=run_as.subject,
                expected_trigger="schedule",
                schedule_event_id=event.id,
                report_instance_id=(workflow_input[activation.report_input_key].get("instance_id")
                                    if activation.report_artifact_version_id is not None else None),
                commit=False,
            )
            _complete_dispatch(db, event, attempt)
            dispatched += 1
        except Exception as exc:
            _fail_dispatch(db, WorkflowScheduleEvent, event_id, attempt, exc)
    return dispatched
