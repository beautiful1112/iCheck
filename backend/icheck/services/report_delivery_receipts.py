from __future__ import annotations

import hashlib
import json
from datetime import UTC
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentToolRegistration,
    ArtifactVersion,
    Investigation,
    InvestigationCheckpoint,
    InvestigationToolCall,
    ReportDeliveryReceipt,
    WorkflowScheduleActivation,
    WorkflowScheduleEvent,
)
from ..workflow_runtime_schemas import ReportDeliveryReceiptRead
from .audit import record_audit_event
from .workflow_execution_evidence import bound_node


RECEIPT_FIELDS = {"delivery_id", "delivery_url", "delivery_status", "document_sha256"}


def _schema_at_path(schema: dict[str, Any], path: str) -> dict[str, Any]:
    current: Any = schema
    for part in path.split("."):
        if not part or len(part) > 128 or not isinstance(current, dict):
            raise ValueError(f"Report delivery receipt path {path!r} is invalid")
        properties = current.get("properties")
        if not isinstance(properties, dict) or part not in properties:
            raise ValueError(
                f"Report delivery receipt path {path!r} is absent from Tool "
                "output schema"
            )
        current = properties[part]
    if not isinstance(current, dict):
        raise ValueError(f"Report delivery receipt path {path!r} is invalid")
    value_type = current.get("type")
    accepts_string = value_type == "string" or (
        isinstance(value_type, list) and "string" in value_type
    )
    if not accepts_string:
        raise ValueError(
            f"Report delivery receipt path {path!r} must resolve to a string"
        )
    return current


def validate_report_delivery_receipt_contract(
    db: Session,
    *,
    dependencies: list[dict[str, Any]],
    tool_name: str,
    mapping: dict[str, str],
    postcheck_tool_name: str | None = None,
) -> None:
    if set(mapping) - RECEIPT_FIELDS:
        raise ValueError(
            "Report delivery receipt mapping contains unsupported fields"
        )
    if "delivery_id" not in mapping:
        raise ValueError("Report delivery receipt mapping requires delivery_id")
    dependency = next(
        (item for item in dependencies if item.get("name") == tool_name), None
    )
    if (
        dependency is None
        or dependency.get("transport") != "mcp"
        or dependency.get("risk_level") != "change"
        or dependency.get("read_only") is not False
    ):
        raise ValueError(
            "Report delivery receipt Tool must be a pinned state-changing MCP "
            "dependency"
        )
    tool = db.scalar(
        select(AgentToolRegistration).where(
            AgentToolRegistration.name == tool_name,
            AgentToolRegistration.enabled.is_(True),
            AgentToolRegistration.transport == "mcp",
            AgentToolRegistration.risk_level == "change",
            AgentToolRegistration.read_only.is_(False),
        )
    )
    if tool is None:
        raise ValueError("Report delivery receipt Tool is unavailable")
    for path in mapping.values():
        _schema_at_path(tool.output_schema, path)
    if postcheck_tool_name is not None:
        if "document_sha256" not in mapping:
            raise ValueError("Report attachment delivery requires document_sha256 evidence")
        postcheck = db.scalar(select(AgentToolRegistration).where(
            AgentToolRegistration.name == postcheck_tool_name,
            AgentToolRegistration.enabled.is_(True), AgentToolRegistration.read_only.is_(True),
        ))
        if postcheck is None:
            raise ValueError("Report attachment post-check Tool is unavailable")
        _schema_at_path(postcheck.output_schema, mapping["document_sha256"])


def _extract_path(document: Any, path: str) -> Any:
    current = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(
                f"Report delivery receipt result path {path!r} is missing"
            )
        current = current[part]
    return current


def _optional_string(value: Any, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} is empty or too long")
    return normalized


def assert_report_attachment_tool_outcome(
    db: Session, investigation: Investigation, tool: AgentToolRegistration, result: dict,
) -> None:
    if investigation.workflow_schedule_event_id is None:
        return
    event = db.get(WorkflowScheduleEvent, investigation.workflow_schedule_event_id)
    activation = db.get(WorkflowScheduleActivation, event.activation_id) if event else None
    if activation is None or activation.report_attachment_format is None:
        return
    nodes = {item["node_id"]: item for item in (investigation.workflow_snapshot or {}).get("nodes", [])}
    producer = next((node for node in nodes.values() if node.get("tool_name") == activation.report_delivery_tool_name
                     and node["node_type"] == "tool"), None)
    postcheck = nodes.get(producer.get("on_success")) if producer else None
    if tool.name not in {activation.report_delivery_tool_name, postcheck.get("tool_name") if postcheck else None}:
        return
    path = (activation.report_delivery_receipt_mapping or {}).get("document_sha256")
    manifest = (investigation.workflow_input or {}).get(activation.report_input_key, {})
    if not path or _extract_path(result, path) != manifest.get("document_sha256"):
        raise ValueError("Report delivery adapter did not confirm the approved document digest")


def _safe_delivery_url(value: Any) -> str | None:
    normalized = _optional_string(value, "delivery_url", 2048)
    if normalized is None:
        return None
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "delivery_url must be an HTTP(S) URL without credentials, query, "
            "or fragment"
        )
    return normalized


def sync_report_delivery_receipt(
    db: Session,
    investigation: Investigation,
    *,
    checkpoint: InvestigationCheckpoint,
    actor: str,
) -> ReportDeliveryReceipt | None:
    if (
        investigation.status != "completed"
        or not investigation.workflow_schedule_event_id
    ):
        return None
    event = db.get(
        WorkflowScheduleEvent,
        investigation.workflow_schedule_event_id,
    )
    if event is None:
        raise LookupError("Workflow schedule event not found")
    activation = db.get(WorkflowScheduleActivation, event.activation_id)
    if activation is None:
        raise LookupError("Workflow schedule activation not found")
    if activation.report_artifact_version_id is None:
        return None
    if not activation.report_delivery_tool_name:
        # Schedules activated before receipt contracts were introduced remain
        # executable without claiming delivery evidence retroactively.
        return None
    if (
        not activation.report_delivery_tool_argument
        or not activation.report_delivery_provider_key
        or not activation.report_delivery_receipt_mapping
        or not activation.report_input_key
    ):
        raise ValueError("Report delivery receipt contract is incomplete")
    existing = db.scalar(
        select(ReportDeliveryReceipt).where(
            ReportDeliveryReceipt.schedule_event_id == event.id
        )
    )
    calls = list(
        db.scalars(
            select(InvestigationToolCall)
            .join(
                AgentToolRegistration,
                AgentToolRegistration.id == InvestigationToolCall.tool_id,
            )
            .where(
                InvestigationToolCall.investigation_id == investigation.id,
                InvestigationToolCall.status == "succeeded",
                AgentToolRegistration.name
                == activation.report_delivery_tool_name,
            )
            .order_by(InvestigationToolCall.finished_at, InvestigationToolCall.id)
        ).all()
    )
    verification = _verified_delivery_evidence(
        db, investigation, activation, checkpoint, calls
    )
    if verification is None:
        return None
    if len(calls) != 1:
        raise ValueError(
            "Report delivery receipt contract requires exactly one successful "
            "producing Tool call"
        )
    call = calls[0]
    report_input = (investigation.workflow_input or {}).get(
        activation.report_input_key
    )
    if not isinstance(report_input, dict):
        raise ValueError("Generated report input is unavailable at completion")
    if call.arguments.get(activation.report_delivery_tool_argument) != report_input:
        raise ValueError(
            "Report delivery Tool arguments do not match the generated report"
        )
    report_version = db.get(
        ArtifactVersion,
        activation.report_artifact_version_id,
    )
    workflow_version = db.get(ArtifactVersion, activation.artifact_version_id)
    if (
        report_version is None
        or not report_version.content_hash
        or workflow_version is None
        or not workflow_version.content_hash
    ):
        raise ValueError("Report delivery Artifact provenance is incomplete")
    if (
        report_input.get("artifact_version_id") != report_version.id
        or report_input.get("content_hash") != report_version.content_hash
        or investigation.workflow_artifact_version_id != workflow_version.id
        or (investigation.workflow_snapshot or {}).get("content_hash")
        != workflow_version.content_hash
    ):
        raise ValueError("Report delivery Artifact provenance does not match")

    report_instance_id = None
    report_attachment_id = None
    report_attachment_sha256 = None
    if activation.report_attachment_format is not None:
        from .report_attachments import attachment_manifest, verified_report_attachment
        from .workflow_runtime import _automation_principal

        run_as = _automation_principal(db, activation.run_as_principal_id)
        if not run_as.permits("services.read"):
            raise PermissionError("Report delivery run-as read permission was revoked")
        attachment_id = report_input.get("attachment_id")
        if not isinstance(attachment_id, str):
            raise ValueError("Report attachment reference is unavailable")
        attachment, instance = verified_report_attachment(db, attachment_id, run_as)
        if (attachment.export_format != activation.report_attachment_format
            or instance.artifact_version_id != report_version.id
            or attachment_manifest(attachment, instance).model_dump(mode="json") != report_input):
            raise ValueError("Delivered Report attachment does not match its immutable manifest")
        report_instance_id = instance.id
        report_attachment_id = attachment.id
        report_attachment_sha256 = attachment.content_sha256
    elif report_version.definition.get("format_version") == "icheck.service-health-report/v2":
        from .workflow_runtime import _automation_principal
        from .report_instances import retained_workflow_input, visible_report_instance

        run_as = _automation_principal(db, activation.run_as_principal_id)
        instance = visible_report_instance(db, report_input.get("instance_id"), run_as)
        if instance.artifact_version_id != report_version.id or retained_workflow_input(instance) != report_input:
            raise ValueError("Delivered proof report differs from its exact retained snapshot")
        report_instance_id = instance.id

    mapping = dict(activation.report_delivery_receipt_mapping or {})
    values = {
        target: _extract_path(call.result, path)
        for target, path in mapping.items()
    }
    if report_attachment_id is not None:
        path = mapping.get("document_sha256")
        if (path is None or values.get("document_sha256") != report_attachment_sha256
            or _extract_path(verification.result, path) != report_attachment_sha256):
            raise ValueError("Report delivery document digest evidence does not match")
    delivery_id = _optional_string(
        values.get("delivery_id"),
        "delivery_id",
        255,
    )
    if delivery_id is None:
        raise ValueError("delivery_id is required")
    delivery_url = _safe_delivery_url(values.get("delivery_url"))
    delivery_status = _optional_string(
        values.get("delivery_status"),
        "delivery_status",
        128,
    )
    if call.finished_at is None:
        raise ValueError("Report delivery Tool completion time is unavailable")

    expected = {
        "activation_id": activation.id,
        "investigation_id": investigation.id,
        "workflow_artifact_version_id": workflow_version.id,
        "workflow_content_hash": workflow_version.content_hash,
        "report_artifact_version_id": report_version.id,
        "report_content_hash": report_version.content_hash,
        "report_instance_id": report_instance_id,
        "report_attachment_id": report_attachment_id,
        "report_attachment_sha256": report_attachment_sha256,
        "provider_key": activation.report_delivery_provider_key,
        "delivery_tool_name": activation.report_delivery_tool_name,
        "delivery_id": delivery_id,
        "delivery_url": delivery_url,
        "delivery_status": delivery_status,
        "source_tool_call_id": call.id,
        "verification_tool_call_id": verification.id,
        "delivered_at": call.finished_at,
        "verified_at": verification.finished_at,
    }
    if existing is not None:
        if all(getattr(existing, key) == value for key, value in expected.items()):
            return existing
        raise ValueError("Report delivery receipt replay conflicts with stored data")

    receipt = ReportDeliveryReceipt(
        schedule_event_id=event.id,
        **expected,
    )
    db.add(receipt)
    db.flush()
    record_audit_event(
        db,
        event_type="report.delivery.receipt.recorded",
        actor_type="agent",
        actor_id=actor,
        entity_type="report_delivery_receipt",
        entity_id=receipt.id,
        details={
            "schedule_event_id": event.id,
            "activation_id": activation.id,
            "investigation_id": investigation.id,
            "workflow_artifact_version_id": workflow_version.id,
            "workflow_content_hash": workflow_version.content_hash,
            "report_artifact_version_id": report_version.id,
            "report_content_hash": report_version.content_hash,
            "report_instance_id": receipt.report_instance_id,
            "report_attachment_id": receipt.report_attachment_id,
            "report_attachment_sha256": receipt.report_attachment_sha256,
            "provider_key": receipt.provider_key,
            "delivery_id_sha256": hashlib.sha256(
                delivery_id.encode("utf-8")
            ).hexdigest(),
            "source_tool_call_id": call.id,
            "verification_tool_call_id": verification.id,
        },
    )
    return receipt


def _verified_delivery_evidence(
    db: Session,
    investigation: Investigation,
    activation: WorkflowScheduleActivation,
    terminal: InvestigationCheckpoint,
    successful_calls: list[InvestigationToolCall],
) -> InvestigationToolCall | None:
    """An end node is not delivery proof: failed/rolled-back runs also end."""
    from .workflow_runtime import assert_bound_workflow_runtime_compatible

    assert_bound_workflow_runtime_compatible(db, investigation)
    terminal_node = bound_node(investigation, terminal.state.get("plan", []))
    if terminal_node["node_type"] != "end":
        raise ValueError("Report delivery completion requires a bound Workflow end node")
    nodes = investigation.workflow_snapshot.get("nodes", [])
    producers = [
        node
        for node in nodes
        if node["node_type"] == "tool"
        and node.get("tool_name") == activation.report_delivery_tool_name
        and any(
            binding["argument"] == activation.report_delivery_tool_argument
            and binding["input_path"] == activation.report_input_key
            for binding in node.get("input_bindings", [])
        )
    ]
    if len(producers) != 1:
        raise ValueError("Report delivery evidence has no unique bound producer node")
    producer = producers[0]
    checks = [
        node for node in nodes
        if node["node_id"] == producer.get("on_success")
    ]
    if len(checks) != 1 or checks[0]["node_type"] != "post_check":
        raise ValueError("Report delivery evidence has no bound post-check")
    trace = []
    for item in db.scalars(
        select(InvestigationCheckpoint).where(
            InvestigationCheckpoint.investigation_id == investigation.id,
            InvestigationCheckpoint.node == "tools",
            InvestigationCheckpoint.sequence < terminal.sequence,
        ).order_by(InvestigationCheckpoint.sequence)
    ):
        node = bound_node(investigation, item.state.get("plan", []))
        outcomes = item.state.get("workflow_tool_outcomes", [])
        trace.append((item, node, outcomes))
    deliveries = [
        (item, outcome)
        for item, node, outcomes in trace
        if node["node_id"] == producer["node_id"]
        for outcome in outcomes
    ]
    delivery_ids = {outcome["call_id"] for _, outcome in deliveries}
    if len(delivery_ids) != 1:
        raise ValueError("Report delivery requires one producing node execution checkpoint")
    delivery_checkpoint, delivery_outcome = deliveries[-1]
    if delivery_outcome["status"] != "succeeded":
        return None
    if any(
        node["node_type"] == "rollback" and item.sequence > delivery_checkpoint.sequence
        for item, node, _outcomes in trace
    ):
        return None
    if len(successful_calls) != 1:
        raise ValueError(
            "Report delivery receipt contract requires exactly one successful "
            "producing Tool call"
        )
    call = successful_calls[0]
    if call.id != delivery_outcome["call_id"]:
        raise ValueError("Report delivery producer differs from its execution checkpoint")
    verifications = [
        (item, outcome)
        for item, node, outcomes in trace
        if node["node_id"] == checks[0]["node_id"]
        and item.sequence > delivery_checkpoint.sequence
        for outcome in outcomes
    ]
    if len({outcome["call_id"] for _, outcome in verifications}) != 1:
        raise ValueError("Report delivery requires a subsequent post-check execution checkpoint")
    verification_checkpoint, outcome = verifications[-1]
    if outcome["status"] != "succeeded":
        return None
    verification = db.get(InvestigationToolCall, outcome["call_id"])
    terminal_call_ids = terminal.state.get("tool_call_ids", [])
    if (
        verification is None
        or verification.status != "succeeded"
        or verification.investigation_id != investigation.id
        or call.id not in terminal_call_ids
        or verification.id not in terminal_call_ids
        or verification.id not in verification_checkpoint.state.get("tool_call_ids", [])
        or verification.started_at is None
        or verification.finished_at is None
        or call.finished_at is None
        or verification.started_at < call.finished_at
    ):
        raise ValueError("Report delivery verification evidence is incomplete or out of order")
    for evidence_call in (call, verification):
        result_hash = hashlib.sha256(
            json.dumps(
                evidence_call.result,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if evidence_call.result_hash != result_hash:
            raise ValueError("Report delivery evidence result hash does not match")
    return verification


def report_delivery_receipt_visible(db: Session, receipt: ReportDeliveryReceipt, principal) -> bool:
    """A delivery receipt must not bypass the retained report's read boundary."""
    if receipt.report_instance_id is None:
        return True  # Legacy inline metric reports have no retained private proof.
    from .report_instances import visible_report_instance

    try:
        visible_report_instance(db, receipt.report_instance_id, principal)
    except (LookupError, PermissionError):
        return False
    return True


def export_report_delivery_receipt(db: Session, receipt_id: str, *, principal=None) -> dict[str, Any]:
    receipt = db.get(ReportDeliveryReceipt, receipt_id)
    if receipt is None:
        raise LookupError("Report delivery receipt not found")
    if principal is not None and not report_delivery_receipt_visible(db, receipt, principal):
        raise LookupError("Report delivery receipt not found")
    document = ReportDeliveryReceiptRead.model_validate(receipt).model_dump(
        mode="json"
    )
    from ..models import ServiceReportInstance
    instance = db.get(ServiceReportInstance, receipt.report_instance_id) if receipt.report_instance_id else None
    retained_proof = instance is not None and instance.snapshot.get("format_version") == "icheck.service-health-report-render/v2"
    if receipt.report_attachment_id is None and not retained_proof:
        # Preserve the v1 export material and digest for legacy/numeric deliveries.
        for field in ("report_instance_id", "report_attachment_id", "report_attachment_sha256"):
            document.pop(field, None)
    # SQLite returns naive datetimes; PostgreSQL preserves tzinfo. Export bytes
    # must describe the same UTC instant regardless of database dialect.
    for field in ("delivered_at", "verified_at", "created_at"):
        value = getattr(receipt, field)
        if value is None:
            document[field] = None
        else:
            normalized = (
                value.replace(tzinfo=UTC)
                if value.tzinfo is None else value.astimezone(UTC)
            )
            document[field] = normalized.isoformat().replace("+00:00", "Z")
    material = {
        "format_version": ("icheck.report-delivery-receipt/v3" if retained_proof else
                           "icheck.report-delivery-receipt/v2" if receipt.report_attachment_id else
                           "icheck.report-delivery-receipt/v1"),
        "tenant_id": receipt.tenant_id,
        "region_id": receipt.region_id,
        "verification_level": (
            "workflow_postcheck"
            if receipt.verification_tool_call_id else "legacy_unverified"
        ),
        "receipt": document,
    }
    digest = hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        **material,
        "content_sha256": digest,
        "retention": {"mode": "retain", "automatic_pruning": False},
    }
