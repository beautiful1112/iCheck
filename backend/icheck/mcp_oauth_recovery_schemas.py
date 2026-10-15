from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from .mcp_schemas import MCPStrictModel


class MCPOAuthRecoveryStart(MCPStrictModel):
    reason: str = Field(min_length=10, max_length=1000)
    expected_recovery_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    connected_audit_id: str | None = Field(default=None, min_length=1, max_length=36)
    original_secret_ref: str | None = Field(default=None, min_length=1, max_length=1024)

    @model_validator(mode="after")
    def original_target_pair(self):
        if (self.connected_audit_id is None) != (self.original_secret_ref is None):
            raise ValueError("Legacy recovery requires both the consent audit ID and original reference")
        return self


class MCPOAuthRecoveryConfirm(MCPStrictModel):
    expected_recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    proposal_id: str = Field(min_length=1, max_length=36)
    verification_tool_call_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)


class MCPOAuthRecoveryRead(MCPStrictModel):
    server_id: str
    recovery_id: str
    status: Literal["awaiting_evidence", "cleanup_pending", "complete"]
    required_containment_arguments: dict[str, str | int]
    initiated_by: str
    initiated_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    proposal_id: str | None
    verification_tool_call_id: str | None
    fence_verified: bool
    completed_at: datetime | None
    reconnect_allowed: bool
