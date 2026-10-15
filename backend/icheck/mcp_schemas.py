from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel
from .oauth_observation import OAuthCredentialObservation, OAuthCredentialReceipt


MCP_PROTOCOL_VERSION = "2026-07-28"


class MCPStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class MCPServerCreate(MCPStrictModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    endpoint_url: str = Field(min_length=1, max_length=2048)
    protocol_version: Literal["2026-07-28"] = MCP_PROTOCOL_VERSION
    credential_profile_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    auth_mode: Literal[
        "none", "credential_profile", "oauth_authorization_code"
    ] | None = None
    oauth_client_id: str | None = Field(default=None, min_length=1, max_length=2048)
    oauth_client_secret_profile_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    oauth_authorization_server: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
    )
    oauth_requested_scopes: list[str] = Field(default_factory=list, max_length=100)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("oauth_requested_scopes")
    @classmethod
    def validate_oauth_scopes(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            scope = value.strip()
            if (
                not 1 <= len(scope) <= 255
                or any(ord(character) < 0x21 or character in {'"', "\\"} for character in scope)
            ):
                raise ValueError("OAuth scopes contain an invalid value")
            if scope not in normalized:
                normalized.append(scope)
        return normalized

    @model_validator(mode="after")
    def validate_auth_configuration(self) -> "MCPServerCreate":
        mode = self.auth_mode
        if mode is None:
            mode = (
                "oauth_authorization_code"
                if self.oauth_client_id
                else "credential_profile"
                if self.credential_profile_ref
                else "none"
            )
            self.auth_mode = mode
        oauth_configured = any(
            (
                self.oauth_client_id,
                self.oauth_client_secret_profile_ref,
                self.oauth_authorization_server,
                self.oauth_requested_scopes,
            )
        )
        if mode == "none":
            if self.credential_profile_ref or oauth_configured:
                raise ValueError("No-auth MCP servers cannot declare credentials")
        elif mode == "credential_profile":
            if not self.credential_profile_ref:
                raise ValueError(
                    "credential_profile_ref is required for credential authentication"
                )
            if oauth_configured:
                raise ValueError(
                    "Static credential MCP servers cannot declare OAuth settings"
                )
        else:
            if not self.credential_profile_ref:
                raise ValueError(
                    "OAuth MCP servers require a Vault token credential profile"
                )
            if not self.oauth_client_id:
                raise ValueError("oauth_client_id is required for OAuth MCP servers")
        return self


class MCPServerRead(MCPServerCreate):
    id: str
    last_checked_at: datetime | None
    last_health_status: str | None
    last_health_error: str | None
    last_tool_count: int | None
    oauth_status: Literal[
        "not_configured",
        "disconnected",
        "connected",
        "expired",
        "revoked",
        "revocation_pending",
    ]
    oauth_issuer: str | None
    oauth_resource: str | None
    oauth_granted_scopes: list[str]
    oauth_metadata_sha256: str | None
    oauth_refresh_token_present: bool
    oauth_token_expires_at: datetime | None
    oauth_generation: str | None = None
    oauth_bundle_version: int | None = None
    oauth_credential_observation: OAuthCredentialReceipt | None = None
    oauth_connected_by: str | None
    oauth_connected_at: datetime | None
    oauth_revoked_by: str | None
    oauth_revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class MCPOAuthStartRead(MCPStrictModel):
    authorization_url: str
    browser_token: str
    max_age_seconds: int = Field(ge=60, le=1800)


class MCPOAuthRevoke(MCPStrictModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPOAuthScopeChallengeApproval(MCPStrictModel):
    expected_revision: int = Field(ge=1)
    allow_scope_expansion: bool = False
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPOAuthScopeChallengeRead(MCPStrictModel):
    id: str
    server_id: str
    activation_id: str | None
    investigation_id: str | None
    tool_name: str
    challenged_scopes: list[str]
    requested_scopes: list[str]
    resource_metadata_url: str | None
    status: Literal["pending", "authorizing", "resolved"]
    occurrence_count: int
    revision: int
    approved_at: datetime | None
    approved_by: str | None
    approval_reason: str | None
    allowlist_expanded: bool
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    resolved_by: str | None
    created_at: datetime
    updated_at: datetime


class MCPClientMetadataRead(MCPStrictModel):
    client_id: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[Literal["authorization_code", "refresh_token"]]
    response_types: list[Literal["code"]]
    token_endpoint_auth_method: Literal["none"]


class MCPServerHealth(MCPStrictModel):
    server_id: str
    status: Literal["healthy"]
    protocol_version: Literal["2026-07-28"]
    checked_at: datetime
    tool_count: int = Field(ge=0)
    tool_names: list[str] = Field(max_length=1000)


class MCPFleetServerTelemetryRead(MCPStrictModel):
    server_id: str
    server_name: str
    enabled: bool
    posture: Literal["healthy", "degraded", "critical", "inactive"]
    health_status: str | None
    health_is_stale: bool
    oauth_status: str
    active_activations: int = Field(ge=0)
    canary_activations: int = Field(ge=0)
    full_activations: int = Field(ge=0)
    blocked_activations: int = Field(ge=0)
    open_circuits: int = Field(ge=0)
    successful_calls: int = Field(ge=0)
    failed_calls: int = Field(ge=0)
    success_rate_percent: float | None = Field(default=None, ge=0, le=100)
    pending_scope_challenges: int = Field(ge=0)
    authorizing_scope_challenges: int = Field(ge=0)
    attestation_backlog: int = Field(ge=0)
    dead_letter_attestations: int = Field(ge=0)
    fresh_attestations: int = Field(ge=0)
    last_checked_at: datetime | None


class MCPFleetTelemetryRead(MCPStrictModel):
    generated_at: datetime
    stale_after_seconds: int = Field(ge=60, le=86400)
    posture: Literal["empty", "healthy", "degraded", "critical"]
    server_count: int = Field(ge=0)
    enabled_server_count: int = Field(ge=0)
    disabled_server_count: int = Field(ge=0)
    healthy_server_count: int = Field(ge=0)
    unhealthy_server_count: int = Field(ge=0)
    stale_server_count: int = Field(ge=0)
    unchecked_server_count: int = Field(ge=0)
    oauth_attention_server_count: int = Field(ge=0)
    active_activation_count: int = Field(ge=0)
    canary_activation_count: int = Field(ge=0)
    full_activation_count: int = Field(ge=0)
    blocked_activation_count: int = Field(ge=0)
    open_circuit_count: int = Field(ge=0)
    successful_calls: int = Field(ge=0)
    failed_calls: int = Field(ge=0)
    success_rate_percent: float | None = Field(default=None, ge=0, le=100)
    pending_scope_challenge_count: int = Field(ge=0)
    authorizing_scope_challenge_count: int = Field(ge=0)
    attestation_backlog_count: int = Field(ge=0)
    dead_letter_attestation_count: int = Field(ge=0)
    fresh_attestation_count: int = Field(ge=0)
    servers: list[MCPFleetServerTelemetryRead]


class MCPToolActivationCreate(MCPStrictModel):
    artifact_version_id: str
    attestation_id: str
    canary_percent: int = Field(default=10, ge=1, le=100)
    minimum_successful_calls: int = Field(default=3, ge=1, le=1000)
    maximum_failed_calls: int = Field(default=1, ge=0, le=1000)
    circuit_failure_threshold: int = Field(default=3, ge=1, le=100)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPToolDeactivation(MCPStrictModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPToolRolloutAction(MCPStrictModel):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPToolCircuitRecovery(MCPToolRolloutAction):
    attestation_id: str
    canary_percent: int = Field(default=10, ge=1, le=100)


class MCPToolActivationRead(MCPStrictModel):
    id: str
    server_id: str
    artifact_version_id: str
    tool_registration_id: str
    status: Literal["active", "inactive"]
    tool_name: str
    mcp_tool_name: str
    contract_sha256: str
    input_schema_sha256: str
    output_schema_sha256: str
    rollout_state: Literal["canary", "full", "blocked"]
    traffic_percent: int
    minimum_successful_calls: int
    maximum_failed_calls: int
    circuit_failure_threshold: int
    successful_calls: int
    failed_calls: int
    consecutive_failures: int
    circuit_state: Literal["closed", "open"]
    last_call_at: datetime | None
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_failure_sha256: str | None
    circuit_opened_at: datetime | None
    promoted_at: datetime | None
    promoted_by: str | None
    promotion_reason: str | None
    revision: int
    activated_by: str
    activation_reason: str
    attested_at: datetime
    deactivated_by: str | None
    deactivation_reason: str | None
    deactivated_at: datetime | None
    created_at: datetime
    updated_at: datetime


MCPAttestationStatus = Literal[
    "pending",
    "processing",
    "passed",
    "failed",
    "dead_letter",
    "consumed",
]


class MCPToolAttestationCreate(MCPStrictModel):
    artifact_version_id: str
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class MCPToolAttestationRead(MCPStrictModel):
    id: str
    server_id: str
    artifact_version_id: str
    status: MCPAttestationStatus
    tool_name: str
    mcp_tool_name: str
    expected_contract_sha256: str
    expected_input_schema_sha256: str
    expected_output_schema_sha256: str
    requested_by: str
    request_reason: str
    worker_id: str | None
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    lease_expires_at: datetime | None
    advertised_tool_count: int | None
    catalog_sha256: str | None
    remote_contract_sha256: str | None
    failure_code: str | None
    failure_sha256: str | None
    attested_at: datetime | None
    expires_at: datetime | None
    consumed_at: datetime | None
    consumed_by_activation_id: str | None
    created_at: datetime
    updated_at: datetime


class MCPAttestationClaim(MCPStrictModel):
    max_assignments: int = Field(default=1, ge=1, le=10)
    lease_seconds: int = Field(default=120, ge=30, le=900)


class MCPAttestationCredentialGrant(MCPStrictModel):
    profile_id: str
    profile_name: str
    provider: str
    secret_ref: str
    adapter_type: str
    deployment_id: str
    expires_at: datetime
    profile_revision: int = Field(ge=0)
    oauth_generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class MCPToolAttestationAssignment(MCPStrictModel):
    attestation_id: str
    worker_id: str
    server_id: str
    artifact_version_id: str
    lease_token: str = Field(min_length=20, max_length=512)
    lease_expires_at: datetime
    attempt: int = Field(ge=1)
    endpoint_url: str = Field(min_length=1, max_length=2048)
    protocol_version: Literal["2026-07-28"]
    mcp_tool_name: str = Field(min_length=1, max_length=255)
    expected_input_schema: dict[str, Any]
    expected_output_schema: dict[str, Any]
    expected_input_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_output_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    credential_grant: MCPAttestationCredentialGrant | None = None


class MCPToolAttestationComplete(MCPStrictModel):
    lease_token: str = Field(min_length=20, max_length=512)
    status: Literal["passed", "failed"]
    checked_at: datetime
    oauth_observation: OAuthCredentialObservation | None = None
    protocol_version: Literal["2026-07-28"] | None = None
    advertised_tool_count: int | None = Field(default=None, ge=0, le=1000)
    catalog_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    remote_contract_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    input_schema_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    output_schema_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    failure_code: Literal[
        "credential_unavailable",
        "endpoint_rejected",
        "transport_error",
        "protocol_error",
        "contract_mismatch",
        "worker_error",
    ] | None = None
    failure_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    retryable: bool = False

    @model_validator(mode="after")
    def validate_completion(self) -> "MCPToolAttestationComplete":
        passed_fields = (
            self.protocol_version,
            self.advertised_tool_count,
            self.catalog_sha256,
            self.remote_contract_sha256,
            self.input_schema_sha256,
            self.output_schema_sha256,
        )
        if self.status == "passed":
            if any(value is None for value in passed_fields):
                raise ValueError("Passed MCP attestations require complete evidence")
            if self.failure_code or self.failure_sha256 or self.retryable:
                raise ValueError("Passed MCP attestations cannot include failure fields")
        else:
            if not self.failure_code or not self.failure_sha256:
                raise ValueError("Failed MCP attestations require bounded failure evidence")
            if any(value is not None for value in passed_fields):
                raise ValueError("Failed MCP attestations cannot include success evidence")
        return self
