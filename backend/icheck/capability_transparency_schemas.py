from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field

from .schemas import APIModel


class CapabilityTransparencyModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CapabilityTransparencyRecordRead(CapabilityTransparencyModel):
    id: str
    sequence: int = Field(ge=1)
    previous_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_type: str
    entity_type: str
    entity_id: str
    subject_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    details: dict[str, str | int | bool | None]
    occurred_at: datetime


class CapabilityTransparencyRecordListRead(CapabilityTransparencyModel):
    items: list[CapabilityTransparencyRecordRead]
    head_sequence: int = Field(ge=0)
    head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sequence: int = Field(ge=0)
    limit: int = Field(ge=1)


class CapabilityTransparencyCheckpointRead(CapabilityTransparencyModel):
    format_version: str = "icheck.capability-transparency-checkpoint/v1"
    log_id: str
    epoch: int = Field(ge=1)
    last_sequence: int = Field(ge=0)
    head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    updated_at: datetime


class CapabilityTransparencyVerificationRead(CapabilityTransparencyModel):
    valid: bool
    record_count: int = Field(ge=0)
    first_sequence: int | None
    last_sequence: int = Field(ge=0)
    calculated_head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stored_head_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_sequence: int | None = None
