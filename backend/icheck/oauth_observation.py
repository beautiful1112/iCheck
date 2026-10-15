"""Secret-free credential observations; never authorization or activation grants."""
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OAuthCredentialObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    generation: str = Field(pattern=r"^[0-9a-f]{32}$")
    vault_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    token_expires_at: datetime
    observed_at: datetime
    coordination_state: Literal["ready", "refreshing", "revoking", "uncertain"]

    @field_validator("token_expires_at", "observed_at")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("OAuth observation timestamps require a timezone")
        return value.astimezone(UTC)


class OAuthCredentialReceipt(OAuthCredentialObservation):
    source: Literal["attestor", "agent", "control_plane"]
    worker_id: str | None = Field(default=None, min_length=1, max_length=36)
    assignment_id: str = Field(min_length=1, max_length=64)
    received_at: datetime

    @field_validator("received_at")
    @classmethod
    def aware_received_timestamp(cls, value: datetime) -> datetime:
        return cls.aware_timestamp(value)


class OAuthRevocationIntent(BaseModel):
    """A pinned cleanup target, never a credential or execution permission."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: int = Field(strict=True, ge=1, le=1, default=1)
    intent_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    server_id: str = Field(min_length=1, max_length=36)
    tenant_id: str = Field(min_length=1, max_length=36)
    region_id: str = Field(min_length=1, max_length=36)
    generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    profile_id: str = Field(min_length=1, max_length=36)
    profile_revision: int = Field(strict=True, ge=0)
    secret_ref: str = Field(min_length=1, max_length=1024)
    vault_address: str | None = Field(default=None, max_length=2048)
    vault_namespace: str | None = Field(default=None, max_length=255)

    @field_validator("secret_ref")
    @classmethod
    def exact_oauth_reference(cls, value: str) -> str:
        # Lazy import avoids a module-loading cycle and preserves the existing
        # provider grammar, including dot-containing mounts and encoded paths.
        from .credentials import validate_secret_reference
        return validate_secret_reference("mcp_oauth_vault", value)
