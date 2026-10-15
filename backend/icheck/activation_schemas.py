from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field

from .collector_schemas import CollectorDeploymentRead
from .models import ArtifactVersionStatus, CollectorDeploymentMode
from .schemas import APIModel


DeviceProtocol = Literal[
    "snmp",
    "https_api",
    "ssh",
    "windows_exporter",
    "winrm_https",
    "icmp",
]


class ActivationModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class DeviceActivationPolicyCreate(ActivationModel):
    name: str = Field(min_length=1, max_length=255)
    protocol: DeviceProtocol
    artifact_version_id: str = Field(min_length=1, max_length=36)
    target_template: dict[str, Any] = Field(default_factory=dict)
    configuration_defaults: dict[str, Any] = Field(default_factory=dict)
    worker_selector: dict[str, Any] = Field(default_factory=dict)
    execution_mode: CollectorDeploymentMode = CollectorDeploymentMode.SCHEDULED
    schedule_seconds: int = Field(default=300, ge=5, le=86400)
    created_by: str = Field(min_length=1, max_length=255)


class DeviceActivationPolicyRead(ActivationModel):
    id: str
    name: str
    version: int
    revision: int
    status: ArtifactVersionStatus
    protocol: str
    adapter_type: str
    artifact_version_id: str
    target_template: dict[str, Any]
    configuration_defaults: dict[str, Any]
    worker_selector: dict[str, Any]
    execution_mode: CollectorDeploymentMode
    schedule_seconds: int
    content_hash: str | None
    created_by: str
    created_at: datetime
    updated_by: str | None
    updated_at: datetime | None
    validated_at: datetime | None
    validated_by: str | None
    published_at: datetime | None
    published_by: str | None


class ActivationPolicyDraftUpdate(ActivationModel):
    expected_revision: int = Field(ge=1)
    draft: DeviceActivationPolicyCreate
    actor: str = Field(min_length=1, max_length=255)


class ActivationCollectorOption(ActivationModel):
    artifact_version_id: str
    artifact_name: str
    version: int
    adapter_type: str
    target_schema: dict[str, Any]
    config_schema: dict[str, Any]
    defaults: dict[str, Any]


class ActivationCollectorSummary(ActivationModel):
    artifact_version_id: str
    artifact_name: str
    version: int
    adapter_type: str


class ActivationCollectorPage(ActivationModel):
    items: list[ActivationCollectorSummary]
    next_cursor: str | None


class DeviceActivationPolicyPage(ActivationModel):
    items: list[DeviceActivationPolicyRead]
    next_cursor: str | None


class GeneratedActivationPolicySpec(ActivationModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    rationale: str = Field(min_length=1, max_length=1000)
    target_template: dict[str, Any]
    configuration_defaults: dict[str, Any]
    worker_selector: dict[str, Any]
    execution_mode: CollectorDeploymentMode
    schedule_seconds: int = Field(ge=5, le=86400)


class ActivationPolicyProposalRequest(ActivationModel):
    protocol: DeviceProtocol
    artifact_version_id: str = Field(min_length=1, max_length=36)
    brief: str = Field(min_length=10, max_length=3000)
    device_id: str | None = Field(default=None, min_length=1, max_length=36)
    prior_suggestion: GeneratedActivationPolicySpec | None = None
    parent_id: str | None = Field(default=None, min_length=36, max_length=36)
    request_key: str | None = Field(default=None, min_length=36, max_length=36)
    actor: str = Field(min_length=1, max_length=255)


class ActivationPolicyProposalRead(ActivationModel):
    proposal_id: str
    parent_id: str | None
    draft: DeviceActivationPolicyCreate
    rationale: str
    warnings: list[str]
    route_id: str
    model_id: str
    tokens_used: int
    external_charge_unknown: bool | None = None


class ActivationDraftScopePreviewRequest(ActivationModel):
    draft: DeviceActivationPolicyCreate
    device_id: str | None = Field(default=None, min_length=1, max_length=36)


class ActivationScopeDetails(ActivationModel):
    evaluated_at: datetime
    advisory_only: bool
    device_id: str | None
    connection_id: str | None
    protocol: str
    artifact_version_id: str
    adapter_type: str | None
    rendered_target: dict[str, Any] | None
    policy_worker_selector: dict[str, str] | None
    connection_worker_selector: dict[str, str] | None
    effective_worker_selector: dict[str, str] | None
    credential_profile_ref: str | None
    credential_source: str
    credential_profile_enabled: bool | None
    credential_adapter_allowed: bool | None
    credential_worker_selector: dict[str, str] | None
    registered_worker_matches_in_scan: int | None
    fresh_worker_matches_in_scan: int | None
    worker_scan_truncated: bool
    blockers: list[str]
    warnings: list[str]


class ActivationProposalScopePreview(ActivationScopeDetails):
    proposal_id: str
    proposal_sha256: str


class ActivationDraftScopePreview(ActivationScopeDetails):
    draft_sha256: str


class ActivationPolicyProposalRecordRead(ActivationModel):
    id: str
    parent_id: str | None
    device_id: str | None
    artifact_version_id: str
    protocol: DeviceProtocol
    brief: str
    actor: str
    status: Literal["generating", "succeeded", "failed"]
    result: ActivationPolicyProposalRead | None
    failure_code: str | None
    tokens_used: int
    external_charge_unknown: bool | None
    created_at: datetime
    recovery_available_at: datetime


class ActivationPolicyProposalInterrupt(ActivationModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class ActivationPolicyProposalAdminRecoveryRead(ActivationPolicyProposalRecordRead):
    request_sha256: str


class ActivationPolicyProposalAdminInterrupt(ActivationModel):
    expected_request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=10, max_length=1000)


class ActivationPolicyAction(ActivationModel):
    actor: str = Field(min_length=1, max_length=255)
    expected_revision: int | None = Field(default=None, ge=1)


class ActivationPreviewRequest(ActivationModel):
    policy_id: str = Field(min_length=1, max_length=36)


class ActivationPlanRead(ActivationModel):
    policy_id: str
    policy_name: str
    policy_version: int
    connection_id: str
    scope_device_identity_revision: int
    target_classification: Literal["registered_device"]
    deployment_name: str
    artifact_version_id: str
    artifact_name: str
    artifact_version: int
    target: dict[str, Any]
    configuration: dict[str, Any]
    worker_selector: dict[str, Any]
    execution_mode: CollectorDeploymentMode
    schedule_seconds: int
    credential_profile_ref: str | None
    warnings: list[str]
    plan_hash: str


class ActivationApproval(ActivationPreviewRequest):
    expected_plan_hash: str = Field(min_length=64, max_length=64)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class ActivationDeactivate(ActivationModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class DeviceConnectionActivationRead(ActivationModel):
    id: str
    connection_id: str
    capability_key: str
    policy_id: str
    deployment_id: str | None
    status: str
    plan_hash: str
    expected_deployment_hash: str
    runtime_status: str
    consecutive_failures: int
    last_run_id: str | None
    last_run_status: str | None
    last_run_finished_at: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_evaluated_at: datetime | None
    health_reason: str | None
    approved_by: str
    approval_reason: str
    activated_at: datetime
    deactivated_at: datetime | None
    deactivated_by: str | None
    deactivation_reason: str | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class DeviceActivationResult(ActivationModel):
    activation: DeviceConnectionActivationRead
    deployment: CollectorDeploymentRead
