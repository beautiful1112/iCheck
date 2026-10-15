from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .schemas import APIModel


ScalingPool = Literal["collector", "agent"]


class ScalingPolicyCreate(APIModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    pool: ScalingPool
    selector: dict[str, str] = Field(default_factory=dict, max_length=16)
    required_capabilities: list[str] = Field(default_factory=list, max_length=32)
    enabled: bool = True
    min_replicas: int = Field(default=1, ge=0, le=1000)
    max_replicas: int = Field(default=20, ge=1, le=1000)
    target_queue_per_replica: int = Field(default=4, ge=1, le=100000)
    scale_out_step: int = Field(default=2, ge=1, le=1000)
    scale_in_step: int = Field(default=1, ge=1, le=1000)
    queue_age_target_seconds: int = Field(default=30, ge=1, le=86400)
    heartbeat_timeout_seconds: int = Field(default=60, ge=10, le=3600)
    cooldown_seconds: int = Field(default=120, ge=0, le=86400)
    reason: str = Field(min_length=1, max_length=4000)

    @field_validator("selector")
    @classmethod
    def normalize_selector(cls, value: dict[str, str]) -> dict[str, str]:
        normalized = {
            key.strip(): item.strip() for key, item in value.items()
        }
        if any(not key or not item or len(key) > 128 or len(item) > 255 for key, item in normalized.items()):
            raise ValueError("selector keys and values must be non-empty and bounded")
        return normalized

    @field_validator("required_capabilities")
    @classmethod
    def normalize_capabilities(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if len(normalized) != len(value) or any(len(item) > 128 for item in normalized):
            raise ValueError("capabilities must be non-empty and bounded")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_bounds(self) -> ScalingPolicyCreate:
        if self.max_replicas < self.min_replicas:
            raise ValueError("max_replicas must be at least min_replicas")
        if self.pool == "agent" and self.selector:
            raise ValueError("agent pools use required_capabilities, not label selectors")
        return self


class ScalingPolicyUpdate(ScalingPolicyCreate):
    expected_revision: int = Field(ge=1)


class ScalingPolicyRead(APIModel):
    id: str
    name: str
    pool: ScalingPool
    selector: dict[str, str]
    required_capabilities: list[str]
    enabled: bool
    min_replicas: int
    max_replicas: int
    target_queue_per_replica: int
    scale_out_step: int
    scale_in_step: int
    queue_age_target_seconds: int
    heartbeat_timeout_seconds: int
    cooldown_seconds: int
    revision: int
    created_by: str
    updated_by: str
    update_reason: str
    created_at: datetime
    updated_at: datetime


class ScalingDecisionRead(APIModel):
    id: str
    policy_id: str
    policy_revision: int
    queue_depth: int
    oldest_queue_age_seconds: float | None
    current_replicas: int
    ready_replicas: int
    busy_replicas: int
    stale_replicas: int
    desired_replicas: int
    direction: Literal["scale_out", "scale_in", "hold"]
    reasons: list[str]
    observed_at: datetime
    created_by: str


ScalingApplicationStatus = Literal[
    "accepted",
    "applying",
    "applied",
    "failed",
    "rejected",
]


class ScalingApplicationEventCreate(APIModel):
    idempotency_key: str = Field(min_length=1, max_length=255)
    status: ScalingApplicationStatus
    observed_replicas: int = Field(ge=0, le=1000)
    detail_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    error_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def validate_error_evidence(self) -> ScalingApplicationEventCreate:
        if self.status == "failed" and self.error_sha256 is None:
            raise ValueError("failed application events require error_sha256")
        if self.status != "failed" and self.error_sha256 is not None:
            raise ValueError("error_sha256 is allowed only for failed events")
        return self


class ScalingApplicationEventRead(APIModel):
    id: str
    decision_id: str
    provider_subject: str
    idempotency_key: str
    status: ScalingApplicationStatus
    observed_replicas: int
    detail_code: str
    error_sha256: str | None
    created_by: str
    created_at: datetime
