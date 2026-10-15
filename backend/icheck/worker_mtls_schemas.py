from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from .schemas import APIModel


class WorkerMTLSModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class WorkerMTLSRotationCreate(WorkerMTLSModel):
    certificate_pem: str = Field(min_length=1, max_length=32_768)
    expected_revision: int = Field(ge=0)
    activate_after: datetime | None = None
    reason: str = Field(min_length=1, max_length=4000)

    @field_validator("activate_after")
    @classmethod
    def require_offset(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("activate_after requires a timezone offset")
        return value


class WorkerMTLSRotationRead(WorkerMTLSModel):
    worker_kind: Literal["collector", "agent"]
    worker_id: str
    current_fingerprint_sha256: str | None
    current_not_after: datetime | None
    next_fingerprint_sha256: str
    next_not_before: datetime
    next_not_after: datetime
    revision: int


class WorkerMTLSLifecycleAction(WorkerMTLSModel):
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=4000)


class WorkerMTLSStateRead(WorkerMTLSModel):
    worker_kind: Literal["collector", "agent"]
    worker_id: str
    current_fingerprint_sha256: str | None
    current_not_after: datetime | None
    next_fingerprint_sha256: str | None
    next_not_before: datetime | None
    next_not_after: datetime | None
    revision: int
