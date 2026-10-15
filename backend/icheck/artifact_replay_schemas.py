from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field

from .models import EnvelopeKind
from .schemas import APIModel


class ReplayModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ReplayEnvelope(ReplayModel):
    kind: EnvelopeKind
    type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=255)
    subject: str | None = Field(default=None, max_length=512)
    observed_at: str | None = Field(default=None, max_length=64)
    payload: dict[str, Any]
    idempotency_key: str | None = Field(default=None, max_length=512)


class ArtifactReplayCaseCreate(ReplayModel):
    name: str = Field(min_length=1, max_length=255)
    source_label: str = Field(min_length=1, max_length=255)
    configuration: dict[str, Any] = Field(default_factory=dict)
    input_envelopes: list[ReplayEnvelope] = Field(min_length=1, max_length=200)
    expected_envelopes: list[ReplayEnvelope] = Field(min_length=1, max_length=200)
    actor: str = Field(min_length=1, max_length=255)


class ArtifactReplayCaseRead(ReplayModel):
    id: str
    artifact_id: str
    name: str
    source_label: str
    input_count: int
    expected_count: int
    input_sha256: str
    expected_sha256: str
    configuration_sha256: str
    created_by: str
    created_at: datetime


class ArtifactReplayRunCreate(ReplayModel):
    artifact_version_id: str
    actor: str = Field(min_length=1, max_length=255)


class ArtifactReplayRunRead(ReplayModel):
    id: str
    case_id: str
    artifact_version_id: str
    status: Literal["passed", "failed", "error"]
    actual_sha256: str | None
    mismatch_count: int
    report: dict[str, Any]
    executed_by: str
    created_at: datetime
    finished_at: datetime
