"""Exact authorization-transaction recovery; no provider credentials or replay."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .oauth_consent import OAuthAuthorizationLocator, OAuthConsentSnapshot, OAuthConsentTarget


class OAuthRecoveryToolPin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    activation_id: str = Field(min_length=1, max_length=36)
    version_id: str = Field(min_length=1, max_length=36)
    server_id: str = Field(min_length=1, max_length=36)
    tool_id: str = Field(min_length=1, max_length=36)
    tool_name: str = Field(min_length=1, max_length=255)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class OAuthFamilyRecoverySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format_version: int = Field(default=1, strict=True, ge=1, le=1)
    consent: OAuthConsentSnapshot
    target: OAuthConsentTarget
    locator: OAuthAuthorizationLocator
    write_tool: OAuthRecoveryToolPin
    verification_tool: OAuthRecoveryToolPin


class MCPOAuthFamilyRecoveryStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=1000)
    write_activation_id: str = Field(min_length=1, max_length=36)
    verification_activation_id: str = Field(min_length=1, max_length=36)


class MCPOAuthFamilyRecoveryConfirm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    proposal_id: str = Field(min_length=1, max_length=36)
    verification_tool_call_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)


class MCPOAuthFamilyRecoveryRead(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server_id: str
    attempt_id: str
    recovery_id: str
    status: Literal["awaiting_evidence", "issuer_verified"]
    required_containment_arguments: dict[str, str | int]
    write_tool: OAuthRecoveryToolPin
    verification_tool: OAuthRecoveryToolPin
    initiated_by: str
    initiated_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    proposal_id: str | None
    verification_tool_call_id: str | None
    evidence_reference: str | None
    # Remote-family evidence is not a receipt for local Vault containment.
    local_cleanup_verified: bool = False
    reconnect_allowed: Literal[False] = False
