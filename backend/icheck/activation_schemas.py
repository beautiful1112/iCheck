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
    validated_at: datetime | None
    validated_by: str | None
    published_at: datetime | None
    published_by: str | None


class ActivationPolicyAction(ActivationModel):
    actor: str = Field(min_length=1, max_length=255)


class ActivationPreviewRequest(ActivationModel):
    policy_id: str = Field(min_length=1, max_length=36)


class ActivationPlanRead(ActivationModel):
    policy_id: str
    policy_name: str
    policy_version: int
    connection_id: str
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
