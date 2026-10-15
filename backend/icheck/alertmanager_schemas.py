from typing import Literal
from uuid import UUID
from pydantic import Field, field_validator
from .metric_alert_schemas import StrictModel


class SilenceCreate(StrictModel):
    request_key: UUID
    confirm: Literal[True]
    rule_id: UUID
    expected_revision: int = Field(ge=1, strict=True)
    duration_minutes: int = Field(ge=1, le=1440, strict=True)
    reason: str = Field(min_length=3, max_length=300)

    @field_validator("reason")
    @classmethod
    def plain_reason(cls, value):
        value = value.strip()
        if len(value) < 3 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Use a plain-text maintenance reason, without credentials")
        return value


class SilenceExpire(StrictModel):
    request_key: UUID
    confirm: Literal[True]
    expected_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
