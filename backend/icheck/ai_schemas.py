from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


AIProviderType = Literal["openai_compatible", "anthropic"]
AIAuthType = Literal["none", "bearer", "api_key"]
AIProviderPrivacyTier = Literal["external", "private", "local"]
AIModelCostClass = Literal["low", "standard", "premium"]
AgentToolPolicy = Literal["permission_scoped", "allowlist"]


class AIStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class AIProviderFields(AIStrictModel):
    name: str = Field(min_length=1, max_length=255)
    provider_type: AIProviderType = "openai_compatible"
    base_url: str = Field(min_length=1, max_length=2048)
    auth_type: AIAuthType = "bearer"
    credential_profile_ref: str | None = Field(default=None, max_length=255)
    request_timeout_seconds: int = Field(default=20, ge=1, le=120)
    privacy_tier: AIProviderPrivacyTier = "external"
    data_residency: str = Field(
        default="unspecified",
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_.-]*$",
    )
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


class AIProviderRuntimeSettingsUpdate(AIStrictModel):
    expected_request_timeout_seconds: int = Field(ge=1, le=120)
    request_timeout_seconds: int = Field(ge=1, le=120)
    expected_connection_revision: int | None = Field(default=None, ge=1)


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
    cost_class: AIModelCostClass = "standard"
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


class AIAuthoringQuotaUpdate(AIStrictModel):
    expected_revision: int = Field(ge=1)
    daily_token_limit: int | None = Field(default=None, ge=1, le=1_000_000_000_000)
    actor_daily_token_limit: int | None = Field(default=None, ge=1, le=1_000_000_000_000)
    reason: str = Field(min_length=10, max_length=1000)


class AIAuthoringQuotaSnapshotRead(AIStrictModel):
    period_start: date
    actor: str
    namespace_limit: int | None
    namespace_used: int
    namespace_available: int | None
    actor_limit: int | None
    actor_used: int
    actor_available: int | None
    pending_requests: int
    unknown_charge_requests: int
    policy_revision: int


class AIAuthoringQuotaReservationRead(AIStrictModel):
    id: str
    entity_type: str
    entity_id: str
    source_entity_type: str | None
    source_entity_id: str | None
    source_step: int | None
    actor: str
    period_start: date
    reserved_tokens: int
    known_tokens: int
    charged_tokens: int
    effective_charged_tokens: int
    adjustment_id: str | None
    latest_adjustment_id: str | None
    supplemental_adjustment_count: int
    status: Literal["reserved", "settled"]
    external_charge_unknown: bool
    created_at: datetime
    settled_at: datetime | None


class AIAuthoringQuotaReservationPage(AIStrictModel):
    items: list[AIAuthoringQuotaReservationRead]
    next_cursor: str | None


class AIQuotaSettlementConflictRead(AIStrictModel):
    id: str
    reservation_id: str
    actor: str
    period_start: date
    source_entity_type: str | None
    source_entity_id: str | None
    source_step: int | None
    original_charged_tokens: int
    effective_charged_tokens: int
    settled_known_tokens_snapshot: int
    settled_external_charge_unknown_snapshot: bool
    reported_known_tokens: int
    reported_external_charge_unknown: bool
    recorded_at: datetime


class AIQuotaSettlementConflictPage(AIStrictModel):
    items: list[AIQuotaSettlementConflictRead]
    next_cursor: str | None


class AIQuotaOrphanCandidateRead(AIStrictModel):
    reservation_id: str
    actor: str
    period_start: date
    reserved_tokens: int
    created_at: datetime
    source_entity_type: str | None
    source_entity_id: str | None
    source_step: int | None
    eligible: bool
    eligibility_reason: str
    source_status: str | None
    source_terminal_at: datetime | None
    audited_known_tokens: int | None
    audit_event_count: int | None
    audit_sha256: str | None


class AIQuotaOrphanCandidatePage(AIStrictModel):
    items: list[AIQuotaOrphanCandidateRead]
    next_cursor: str | None


class AIQuotaOrphanCaseCreate(AIStrictModel):
    reservation_id: str = Field(min_length=36, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaOrphanCaseReview(AIStrictModel):
    decision: Literal["close", "reject"]
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaOrphanCaseRead(AIStrictModel):
    id: str
    reservation_id: str
    actor: str
    period_start: date
    source_entity_type: str
    source_entity_id: str
    source_step: int | None
    source_status_snapshot: str
    source_terminal_at: datetime
    reserved_tokens_snapshot: int
    audited_known_tokens: int | None
    audit_event_count: int | None
    audit_sha256: str | None
    reason: str
    proposed_by_principal_id: str
    proposed_by: str
    proposed_at: datetime
    status: Literal["proposed", "closed", "rejected"]
    reviewed_by_principal_id: str | None
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None


class AIQuotaOrphanCasePage(AIStrictModel):
    items: list[AIQuotaOrphanCaseRead]
    next_cursor: str | None


class AIQuotaReconciliationCreate(AIStrictModel):
    reservation_id: str = Field(min_length=36, max_length=36)
    confirmed_total_tokens: int = Field(ge=0, le=1_000_000_000)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_reference: str = Field(min_length=10, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaReconciliationReview(AIStrictModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaReconciliationRead(AIStrictModel):
    id: str
    reservation_id: str
    actor: str
    period_start: date
    source_entity_type: str | None
    source_entity_id: str | None
    source_step: int | None
    known_tokens_snapshot: int
    original_charged_tokens: int
    confirmed_total_tokens: int
    delta_tokens: int
    evidence_sha256: str
    evidence_reference: str
    reason: str
    proposed_by_principal_id: str
    proposed_by: str
    proposed_at: datetime
    status: Literal["proposed", "applied", "rejected"]
    reviewed_by_principal_id: str | None
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None


class AIQuotaReconciliationPage(AIStrictModel):
    items: list[AIQuotaReconciliationRead]
    next_cursor: str | None


class AIQuotaSupplementCreate(AIStrictModel):
    reservation_id: str = Field(min_length=36, max_length=36)
    confirmed_total_tokens: int = Field(ge=0, le=1_000_000_000)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_reference: str = Field(min_length=10, max_length=255)
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaSupplementReview(AIStrictModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=10, max_length=1000)


class AIQuotaSupplementRead(AIStrictModel):
    id: str
    reservation_id: str
    base_adjustment_id: str
    sequence: int
    actor: str
    period_start: date
    source_entity_type: str | None
    source_entity_id: str | None
    source_step: int | None
    previous_total_tokens: int
    confirmed_total_tokens: int
    delta_tokens: int
    evidence_sha256: str
    evidence_reference: str
    reason: str
    proposed_by_principal_id: str
    proposed_by: str
    proposed_at: datetime
    status: Literal["proposed", "applied", "rejected"]
    reviewed_by_principal_id: str | None
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None


class AIQuotaSupplementPage(AIStrictModel):
    items: list[AIQuotaSupplementRead]
    next_cursor: str | None


class AIModelRouteRead(AIModelRouteCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class AgentProfileFields(AIStrictModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(default="", max_length=4000)
    role_instructions: str = Field(min_length=1, max_length=20_000)
    escalation_instructions: str = Field(default="", max_length=4000)
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    tool_policy: AgentToolPolicy = "permission_scoped"
    allowed_tool_names: list[str] = Field(default_factory=list, max_length=200)
    minimum_provider_privacy: AIProviderPrivacyTier = "external"
    allowed_data_residencies: list[str] = Field(default_factory=list, max_length=32)
    allowed_model_cost_classes: list[AIModelCostClass] = Field(
        default_factory=lambda: ["low", "standard", "premium"],
        min_length=1,
        max_length=3,
    )
    max_iterations: int = Field(default=8, ge=1, le=100)
    max_tool_calls: int = Field(default=20, ge=1, le=500)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    token_budget: int = Field(default=50_000, ge=1, le=10_000_000)
    enabled: bool = True

    @field_validator("allowed_tool_names", "allowed_data_residencies")
    @classmethod
    def normalize_string_lists(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 255 for item in normalized):
            raise ValueError("AgentProfile list entries cannot exceed 255 characters")
        return list(dict.fromkeys(normalized))

    @field_validator("allowed_model_cost_classes")
    @classmethod
    def normalize_cost_classes(
        cls,
        value: list[AIModelCostClass],
    ) -> list[AIModelCostClass]:
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def validate_tool_policy(self) -> AgentProfileFields:
        if self.tool_policy == "allowlist" and not self.allowed_tool_names:
            raise ValueError("allowlist AgentProfiles require allowed_tool_names")
        if self.tool_policy == "permission_scoped" and self.allowed_tool_names:
            raise ValueError(
                "permission_scoped AgentProfiles cannot declare allowed_tool_names"
            )
        return self


class AgentProfileCreate(AgentProfileFields):
    created_by: str = Field(min_length=1, max_length=255)


class AgentProfileUpdate(AgentProfileFields):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class AgentProfileRead(AgentProfileFields):
    id: str
    revision: int
    created_by: str
    updated_by: str
    update_reason: str
    created_at: datetime
    updated_at: datetime
