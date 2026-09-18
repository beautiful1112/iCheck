from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


AIProviderType = Literal["openai_compatible"]
AIAuthType = Literal["none", "bearer", "api_key"]


class AIStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class AIProviderFields(AIStrictModel):
    name: str = Field(min_length=1, max_length=255)
    provider_type: AIProviderType = "openai_compatible"
    base_url: str = Field(min_length=1, max_length=2048)
    auth_type: AIAuthType = "bearer"
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    request_timeout_seconds: int = Field(default=20, ge=1, le=120)
    enabled: bool = True

    @model_validator(mode="after")
    def validate_auth_reference(self) -> AIProviderFields:
        if self.auth_type == "none" and self.credential_profile_ref:
            raise ValueError(
                "credential_profile_ref must be empty when auth_type is 'none'"
            )
        if self.auth_type != "none" and not self.credential_profile_ref:
            raise ValueError(
                "credential_profile_ref is required for authenticated providers"
            )
        return self


class AIProviderCreate(AIProviderFields):
    created_by: str = Field(min_length=1, max_length=255)


class AIProviderUpdate(AIProviderFields):
    actor: str = Field(min_length=1, max_length=255)


class AIProviderRead(AIProviderFields):
    id: str
    created_by: str
    last_checked_at: datetime | None
    last_health_status: str | None
    last_health_error: str | None
    created_at: datetime
    updated_at: datetime


class AIProviderHealth(AIStrictModel):
    provider_id: str
    status: Literal["healthy", "unhealthy"]
    checked_at: datetime
    model_count: int = 0
    error: str | None = None


class AIModelFields(AIStrictModel):
    provider_id: str
    display_name: str = Field(min_length=1, max_length=255)
    model_name: str = Field(min_length=1, max_length=255)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    context_window: int | None = Field(default=None, ge=1, le=10_000_000)
    max_output_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    default_parameters: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 64 for item in normalized):
            raise ValueError("capabilities must not exceed 64 characters")
        return list(dict.fromkeys(normalized))


class AIModelCreate(AIModelFields):
    created_by: str = Field(min_length=1, max_length=255)


class AIModelRead(AIModelFields):
    id: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class AIModelRouteCreate(AIStrictModel):
    purpose: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    primary_model_id: str
    fallback_model_ids: list[str] = Field(default_factory=list, max_length=8)
    max_iterations: int = Field(default=8, ge=1, le=100)
    max_tool_calls: int = Field(default=20, ge=1, le=500)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    token_budget: int = Field(default=50_000, ge=1, le=10_000_000)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_fallbacks(self) -> AIModelRouteCreate:
        self.fallback_model_ids = list(dict.fromkeys(self.fallback_model_ids))
        if self.primary_model_id in self.fallback_model_ids:
            raise ValueError("primary model must not also be a fallback")
        return self


class AIModelRouteRead(AIModelRouteCreate):
    id: str
    created_at: datetime
    updated_at: datetime
