from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from .schemas import APIModel


class RolloutModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CollectorCanaryCreate(RolloutModel):
    name: str = Field(min_length=1, max_length=255)
    artifact_version_id: str
    scope_device_id: str | None = Field(default=None, max_length=36)
    scope_device_identity_revision: int | None = Field(default=None, ge=1)
    target_classification: Literal["registered_device", "external_source"] | None = None
    external_source_reason: str | None = Field(default=None, min_length=10, max_length=1000)
    scope_site: str | None = Field(default=None, max_length=128)
    target: dict[str, Any] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    worker_selector: dict[str, str] = Field(default_factory=dict)
    credential_profile_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    schedule_seconds: int = Field(default=30, ge=5, le=3600)
    timeout_seconds: int = Field(default=900, ge=30, le=86400)
    min_successful_runs: int = Field(default=3, ge=1, le=100)
    max_failed_runs: int = Field(default=1, ge=1, le=100)
    min_records_per_run: int = Field(default=1, ge=0, le=1_000_000)
    actor: str = Field(min_length=1, max_length=255)


class CollectorCanaryAction(RolloutModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)


class CollectorCanaryRead(RolloutModel):
    id: str
    name: str
    artifact_id: str
    candidate_version_id: str
    baseline_version_id: str | None
    deployment_id: str | None
    status: Literal["running", "passed", "aborted", "promoted"]
    target_classification: str | None
    scope_device_id: str | None
    scope_device_identity_revision: int | None
    scope_site: str | None
    external_source_reason: str | None
    target_ownership_sha256: str | None
    target: dict[str, Any]
    configuration: dict[str, Any]
    worker_selector: dict[str, Any]
    credential_profile_ref: str | None
    schedule_seconds: int
    min_successful_runs: int
    max_failed_runs: int
    min_records_per_run: int
    successful_runs: int
    qualifying_runs: int
    failed_runs: int
    records_received: int
    evidence_batches: int
    last_evidence_sha256: str | None
    last_run_id: str | None
    last_gate_result: str | None
    created_by: str
    started_at: datetime
    deadline_at: datetime
    evaluated_at: datetime | None
    passed_at: datetime | None
    aborted_at: datetime | None
    abort_reason: str | None
    promoted_at: datetime | None
    promoted_by: str | None
    promotion_reason: str | None
    created_at: datetime
    updated_at: datetime


class CollectorFleetPlanCreate(RolloutModel):
    canary_rollout_id: str
    scope_site: str | None = Field(default=None, min_length=1, max_length=128)
    include_disabled: bool = False
    batch_size: int = Field(default=25, ge=1, le=500)
    max_failures: int = Field(default=1, ge=1, le=500)
    max_deployments: int = Field(default=10_000, ge=1, le=10_000)
    progression_mode: Literal["manual", "automatic"] = "manual"
    ring_percentages: list[int] = Field(
        default_factory=lambda: [5, 25, 50, 100],
        min_length=1,
        max_length=20,
    )
    observation_seconds: int = Field(default=300, ge=30, le=86400)
    min_successful_runs_per_deployment: int = Field(default=1, ge=1, le=20)
    max_failed_runs_per_ring: int = Field(default=0, ge=0, le=500)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)

    @model_validator(mode="after")
    def validate_rings(self) -> CollectorFleetPlanCreate:
        if any(value < 1 or value > 100 for value in self.ring_percentages):
            raise ValueError("ring_percentages must contain values from 1 through 100")
        if self.ring_percentages != sorted(set(self.ring_percentages)):
            raise ValueError("ring_percentages must be strictly increasing")
        if self.ring_percentages[-1] != 100:
            raise ValueError("ring_percentages must end at 100")
        return self


class CollectorFleetAction(RolloutModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)
    plan_sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )


class CollectorFleetRolloutRead(RolloutModel):
    id: str
    canary_rollout_id: str
    artifact_id: str
    from_version_id: str
    to_version_id: str
    status: Literal[
        "planned",
        "running",
        "completed",
        "failed",
        "rolling_back",
        "rolled_back",
        "rollback_failed",
    ]
    scope_site: str | None
    include_disabled: bool
    batch_size: int
    max_failures: int
    progression_mode: Literal["manual", "automatic"]
    ring_percentages: list[int]
    observation_seconds: int
    min_successful_runs_per_deployment: int
    max_failed_runs_per_ring: int
    automation_state: Literal[
        "manual",
        "armed",
        "observing",
        "paused",
        "aborted",
        "completed",
        "failed",
    ]
    current_ring_index: int | None
    automation_updated_at: datetime | None
    plan_sha256: str
    planned_count: int
    pending_count: int
    blocked_count: int
    deferred_count: int
    migrated_count: int
    failed_count: int
    rolled_back_count: int
    rollback_failed_count: int
    last_batch_result: dict[str, Any]
    created_by: str
    reason: str
    started_at: datetime | None
    completed_at: datetime | None
    rollback_started_at: datetime | None
    rolled_back_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CollectorFleetRolloutItemRead(RolloutModel):
    id: str
    rollout_id: str
    deployment_id: str
    deployment_name: str
    pre_change_sha256: str
    post_change_sha256: str
    status: Literal[
        "pending",
        "blocked",
        "deferred",
        "migrated",
        "failed",
        "rollback_deferred",
        "rolled_back",
        "rollback_failed",
    ]
    ring_index: int | None
    block_reason_code: str | None
    attempt_count: int
    last_error_code: str | None
    last_error_sha256: str | None
    migrated_at: datetime | None
    rolled_back_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CollectorFleetRolloutRingRead(RolloutModel):
    id: str
    rollout_id: str
    ring_index: int
    target_percent: int
    target_count: int
    cohort_count: int
    status: Literal[
        "pending",
        "applying",
        "observing",
        "passed",
        "paused",
        "aborted",
        "failed",
    ]
    healthy_deployments: int
    missing_evidence_deployments: int
    successful_runs: int
    failed_runs: int
    last_gate_result: str | None
    evidence_sha256: str | None
    started_at: datetime | None
    observation_started_at: datetime | None
    evaluated_at: datetime | None
    passed_at: datetime | None
    created_at: datetime
    updated_at: datetime
