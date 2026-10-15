from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from .schemas import APIModel


class WorkflowRuntimeModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PublishedWorkflowRead(WorkflowRuntimeModel):
    artifact_id: str
    artifact_name: str
    version_id: str
    version: int
    description: str
    trigger: dict[str, Any]
    input_schema: dict[str, Any]
    node_count: int
    required_permissions: list[str]
    approval_required: bool
    max_runtime_seconds: int
    max_total_tool_calls: int
    max_total_tokens: int
    content_hash: str


class WorkflowInvestigationCreate(WorkflowRuntimeModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    workflow_input: dict[str, Any]
    scope: dict[str, Any] = Field(default_factory=dict)
    operator_context: str | None = Field(default=None, max_length=4000)
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    actor: str = Field(min_length=1, max_length=255)


class WorkflowTriggerActivationCreate(WorkflowRuntimeModel):
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    run_as_principal_id: str | None = None
    authorization_scope: dict[str, Any] = Field(default_factory=dict)
    input_mapping: dict[str, str] = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=255)


class WorkflowTriggerActivationRead(WorkflowRuntimeModel):
    id: str
    artifact_version_id: str
    event_type: str
    route_purpose: str
    run_as_principal_id: str | None
    authorization_scope: dict[str, Any]
    input_mapping: dict[str, str]
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class WorkflowTriggerEventRead(WorkflowRuntimeModel):
    id: str
    activation_id: str
    alert_id: str
    status: str
    attempt_count: int
    error_type: str | None
    error_sha256: str | None
    created_at: datetime
    updated_at: datetime


class WorkflowTriggerActivationAction(WorkflowRuntimeModel):
    actor: str = Field(min_length=1, max_length=255)


class SituationIntegrationBindingCreate(WorkflowRuntimeModel):
    channel_kind: Literal["ticket", "collaboration"]
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    run_as_principal_id: str | None = None
    authorization_scope: dict[str, Any] = Field(default_factory=dict)
    input_mapping: dict[str, str] = Field(min_length=1, max_length=64)
    provider_key: str = Field(
        default="generic",
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    remote_reference_tool_name: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    remote_reference_mapping: dict[str, str] = Field(
        default_factory=dict, max_length=3
    )
    inbound_enabled: bool = False
    inbound_key_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    inbound_public_key_pem: str | None = Field(
        default=None, min_length=1, max_length=4096
    )
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def coherent_external_contract(self):
        has_tool = self.remote_reference_tool_name is not None
        has_mapping = bool(self.remote_reference_mapping)
        if has_tool != has_mapping:
            raise ValueError(
                "remote reference tool and mapping must be configured together"
            )
        if has_mapping and "remote_id" not in self.remote_reference_mapping:
            raise ValueError("remote reference mapping requires remote_id")
        if self.inbound_enabled and (
            not self.inbound_key_id or not self.inbound_public_key_pem
        ):
            raise ValueError(
                "inbound reconciliation requires key ID and Ed25519 public key"
            )
        if not self.inbound_enabled and (
            self.inbound_key_id or self.inbound_public_key_pem
        ):
            raise ValueError(
                "inbound key configuration requires inbound_enabled"
            )
        if self.inbound_enabled and not has_mapping:
            raise ValueError(
                "inbound reconciliation requires remote reference capture"
            )
        return self


class SituationIntegrationBindingRead(WorkflowRuntimeModel):
    id: str
    artifact_version_id: str
    channel_kind: Literal["ticket", "collaboration"]
    event_type: str
    route_purpose: str
    run_as_principal_id: str | None
    authorization_scope: dict[str, Any]
    input_mapping: dict[str, str]
    provider_key: str
    remote_reference_tool_name: str | None
    remote_reference_mapping: dict[str, str]
    inbound_enabled: bool
    inbound_key_id: str | None
    inbound_public_key_sha256: str | None
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class SituationIntegrationEventRead(WorkflowRuntimeModel):
    id: str
    binding_id: str
    situation_id: str
    situation_event_id: str
    event_type: str
    status: Literal["pending", "processing", "succeeded", "failed"]
    attempt_count: int
    error_type: str | None
    error_sha256: str | None
    created_at: datetime
    updated_at: datetime


class SituationIntegrationRemoteReferenceRead(WorkflowRuntimeModel):
    id: str
    integration_event_id: str
    binding_id: str
    situation_id: str
    investigation_id: str | None
    provider_key: str
    remote_id: str
    remote_url: str | None
    remote_status: str | None
    remote_updated_at: datetime | None
    source_tool_call_id: str
    created_at: datetime
    updated_at: datetime


class SituationIntegrationInboundPayload(WorkflowRuntimeModel):
    provider_event_id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    remote_id: str = Field(min_length=1, max_length=255)
    remote_status: str = Field(min_length=1, max_length=128)
    remote_updated_at: datetime


class SituationIntegrationInboundEventRead(WorkflowRuntimeModel):
    id: str
    binding_id: str
    reference_id: str
    provider_event_id: str
    event_type: str
    remote_status: str
    remote_updated_at: datetime
    payload_sha256: str
    signature_sha256: str
    signature_key_id: str
    outcome: Literal["accepted", "ignored_stale"]
    received_at: datetime


class SituationIntegrationWebhookAck(WorkflowRuntimeModel):
    event_id: str
    reference_id: str
    outcome: Literal["accepted", "ignored_stale"]
    replayed: bool = False


class WorkflowScheduleExclusionWindow(WorkflowRuntimeModel):
    id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    name: str = Field(min_length=1, max_length=128)
    starts_at: datetime
    ends_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> "WorkflowScheduleExclusionWindow":
        if self.starts_at.tzinfo is None or self.starts_at.utcoffset() is None:
            raise ValueError("Schedule exclusion starts_at must include a timezone")
        if self.ends_at.tzinfo is None or self.ends_at.utcoffset() is None:
            raise ValueError("Schedule exclusion ends_at must include a timezone")
        self.starts_at = self.starts_at.astimezone(UTC)
        self.ends_at = self.ends_at.astimezone(UTC)
        if self.ends_at <= self.starts_at:
            raise ValueError("Schedule exclusion ends_at must be after starts_at")
        if self.ends_at - self.starts_at > timedelta(days=366):
            raise ValueError("A schedule exclusion cannot exceed 366 days")
        return self


def _validate_schedule_exclusion_windows(
    windows: list[WorkflowScheduleExclusionWindow],
) -> list[WorkflowScheduleExclusionWindow]:
    normalized = sorted(windows, key=lambda item: (item.starts_at, item.id))
    if len({item.id for item in normalized}) != len(normalized):
        raise ValueError("Schedule exclusion IDs must be unique")
    for previous, current in zip(normalized, normalized[1:], strict=False):
        if current.starts_at < previous.ends_at:
            raise ValueError("Schedule exclusion windows cannot overlap")
    return normalized


class WorkflowScheduleActivationCreate(WorkflowRuntimeModel):
    cron_expression: str = Field(min_length=5, max_length=255)
    timezone: str = Field(
        default="UTC",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9_+./-]+$",
    )
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    run_as_principal_id: str | None = None
    authorization_scope: dict[str, Any] = Field(default_factory=dict)
    workflow_input: dict[str, Any]
    report_artifact_version_id: str | None = Field(
        default=None,
        min_length=36,
        max_length=36,
    )
    report_input_key: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_-]*$",
    )
    report_attachment_format: Literal["json", "html", "csv", "pdf"] | None = None
    report_delivery_provider_key: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    report_delivery_receipt_mapping: dict[str, str] = Field(
        default_factory=dict,
        max_length=4,
    )
    misfire_grace_seconds: int = Field(default=300, ge=60, le=86400)
    exclusion_windows: list[WorkflowScheduleExclusionWindow] = Field(
        default_factory=list,
        max_length=100,
    )
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_exclusion_windows(self) -> "WorkflowScheduleActivationCreate":
        self.exclusion_windows = _validate_schedule_exclusion_windows(
            self.exclusion_windows
        )
        if (self.report_artifact_version_id is None) != (
            self.report_input_key is None
        ):
            raise ValueError(
                "report Artifact version and input key must be configured together"
            )
        if self.report_input_key and self.report_input_key in self.workflow_input:
            raise ValueError(
                "static Workflow input cannot override the generated report input"
            )
        has_report = self.report_artifact_version_id is not None
        if self.report_attachment_format is not None and not has_report:
            raise ValueError("Report attachment format requires a scheduled report")
        if self.report_attachment_format is not None and "document_sha256" not in self.report_delivery_receipt_mapping:
            raise ValueError("Report attachment delivery requires a document_sha256 receipt mapping")
        if self.report_attachment_format is None and "document_sha256" in self.report_delivery_receipt_mapping:
            raise ValueError("Document digest receipt mapping requires a Report attachment")
        has_provider = self.report_delivery_provider_key is not None
        has_receipt_mapping = bool(self.report_delivery_receipt_mapping)
        if has_report and not (has_provider and has_receipt_mapping):
            raise ValueError(
                "scheduled report delivery requires a provider key and receipt mapping"
            )
        if not has_report and (has_provider or has_receipt_mapping):
            raise ValueError(
                "report delivery receipt configuration requires a scheduled report"
            )
        if has_receipt_mapping and (
            "delivery_id" not in self.report_delivery_receipt_mapping
        ):
            raise ValueError("report delivery receipt mapping requires delivery_id")
        return self


class WorkflowScheduleExclusionsUpdate(WorkflowRuntimeModel):
    expected_revision: int = Field(ge=1)
    exclusion_windows: list[WorkflowScheduleExclusionWindow] = Field(
        default_factory=list,
        max_length=100,
    )
    reason: str = Field(min_length=3, max_length=1000)
    actor: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_exclusion_windows(self) -> "WorkflowScheduleExclusionsUpdate":
        self.exclusion_windows = _validate_schedule_exclusion_windows(
            self.exclusion_windows
        )
        return self


class WorkflowScheduleActivationRead(WorkflowRuntimeModel):
    id: str
    artifact_version_id: str
    cron_expression: str
    timezone: str
    route_purpose: str
    run_as_principal_id: str | None
    authorization_scope: dict[str, Any]
    workflow_input: dict[str, Any]
    report_artifact_version_id: str | None
    report_input_key: str | None
    report_attachment_format: str | None
    report_delivery_tool_name: str | None
    report_delivery_tool_argument: str | None
    report_delivery_provider_key: str | None
    report_delivery_receipt_mapping: dict[str, str]
    misfire_grace_seconds: int
    exclusion_windows: list[WorkflowScheduleExclusionWindow]
    excluded_runs: int
    last_excluded_at: datetime | None
    next_fire_at: datetime
    last_fire_at: datetime | None
    last_misfire_at: datetime | None
    missed_runs: int
    revision: int
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class WorkflowScheduleEventRead(WorkflowRuntimeModel):
    id: str
    activation_id: str
    scheduled_for: datetime
    status: str
    attempt_count: int
    skip_reason: str | None
    exclusion_window_id: str | None
    error_type: str | None
    error_sha256: str | None
    created_at: datetime
    updated_at: datetime
    investigation_id: str | None = None
    investigation_status: str | None = None
    report_delivery_tool_call_id: str | None = None
    report_delivery_state: Literal[
        "not_dispatched", "pending", "reconciliation_required", "verified",
        "unverified", "legacy_unverified"
    ] | None = None


class ReportDeliveryReceiptRead(WorkflowRuntimeModel):
    id: str
    schedule_event_id: str
    activation_id: str
    investigation_id: str
    workflow_artifact_version_id: str
    workflow_content_hash: str
    report_artifact_version_id: str
    report_content_hash: str
    report_instance_id: str | None = None
    report_attachment_id: str | None = None
    report_attachment_sha256: str | None = None
    provider_key: str
    delivery_tool_name: str
    delivery_id: str
    delivery_url: str | None
    delivery_status: str | None
    source_tool_call_id: str
    verification_tool_call_id: str | None
    delivered_at: datetime
    verified_at: datetime | None
    created_at: datetime


class ReportDeliveryReceiptExport(WorkflowRuntimeModel):
    format_version: Literal["icheck.report-delivery-receipt/v1", "icheck.report-delivery-receipt/v2", "icheck.report-delivery-receipt/v3"]
    tenant_id: str
    region_id: str
    verification_level: Literal["workflow_postcheck", "legacy_unverified"]
    receipt: ReportDeliveryReceiptRead
    content_sha256: str
    retention: dict[str, Any]
