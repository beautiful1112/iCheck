from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


ToolTransport = Literal["internal", "mcp"]
ToolRiskLevel = Literal["observe", "diagnose", "change"]
AgentWorkerStateValue = Literal["online", "draining", "offline"]
AgentExecutionStatusValue = Literal[
    "queued",
    "running",
    "waiting_approval",
    "succeeded",
    "failed",
    "cancelled",
]
InvestigationStatus = Literal[
    "pending",
    "running",
    "waiting_approval",
    "completed",
    "escalated",
    "failed",
    "cancelled",
]


class AgentStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class AgentToolCreate(AgentStrictModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    transport: ToolTransport
    handler: str = Field(min_length=1, max_length=512)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: ToolRiskLevel = "observe"
    read_only: bool = True
    required_permissions: list[str] = Field(default_factory=list, max_length=32)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_result_bytes: int = Field(default=1_000_000, ge=1, le=10_000_000)
    enabled: bool = True
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("required_permissions")
    @classmethod
    def normalize_permissions(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 128 for item in normalized):
            raise ValueError("permissions must not exceed 128 characters")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_read_only_risk(self) -> AgentToolCreate:
        if self.read_only and self.risk_level == "change":
            raise ValueError("read-only tools cannot declare change risk")
        if not self.read_only and self.risk_level != "change":
            raise ValueError("state-changing tools must declare change risk")
        return self


class AgentToolRead(AgentToolCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class InvestigationCreate(AgentStrictModel):
    title: str = Field(min_length=1, max_length=255)
    objective: str = Field(min_length=1, max_length=10_000)
    scope: dict[str, Any] = Field(default_factory=dict)
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    created_by: str = Field(min_length=1, max_length=255)


class InvestigationRead(AgentStrictModel):
    id: str
    title: str
    objective: str
    scope: dict[str, Any]
    status: InvestigationStatus
    route_id: str
    model_id: str
    fallback_model_ids: list[str]
    max_iterations: int
    max_tool_calls: int
    timeout_seconds: int
    token_budget: int
    iterations_used: int
    tool_calls_used: int
    tokens_used: int
    confidence: float | None
    conclusion: str | None
    uncertainty: list[str]
    escalation_reason: str | None
    requested_by_principal_id: str | None
    permission_snapshot: list[str]
    authorization_scope: dict[str, Any]
    created_by: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InvestigationAction(AgentStrictModel):
    actor: str = Field(min_length=1, max_length=255)


class HypothesisState(AgentStrictModel):
    statement: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class InvestigationState(AgentStrictModel):
    investigation_id: str
    objective: str = Field(min_length=1, max_length=10_000)
    scope: dict[str, Any] = Field(default_factory=dict)
    status: InvestigationStatus
    iteration: int = Field(default=0, ge=0)
    plan: list[str] = Field(default_factory=list, max_length=100)
    hypotheses: list[HypothesisState] = Field(default_factory=list, max_length=100)
    evidence_ids: list[str] = Field(default_factory=list, max_length=1000)
    tool_call_ids: list[str] = Field(default_factory=list, max_length=1000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    conclusion: str | None = Field(default=None, max_length=20_000)
    uncertainty: list[str] = Field(default_factory=list, max_length=100)
    escalation_reason: str | None = Field(default=None, max_length=4000)


class InvestigationCheckpointCreate(AgentStrictModel):
    node: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    state: InvestigationState
    token_usage: int = Field(default=0, ge=0, le=10_000_000)
    actor: str = Field(min_length=1, max_length=255)


class InvestigationCheckpointRead(AgentStrictModel):
    id: str
    investigation_id: str
    sequence: int
    node: str
    state: dict[str, Any]
    state_hash: str
    created_by: str
    created_at: datetime


class InvestigationStartResult(AgentStrictModel):
    investigation: InvestigationRead
    checkpoint: InvestigationCheckpointRead


class InvestigationEvidenceCreate(AgentStrictModel):
    evidence_type: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    evidence_id: str = Field(min_length=1, max_length=512)
    summary: str = Field(min_length=1, max_length=10_000)
    observed_at: datetime | None = None


class InvestigationEvidenceRead(InvestigationEvidenceCreate):
    id: str
    investigation_id: str
    created_at: datetime


class InvestigationToolCallCreate(AgentStrictModel):
    tool_id: str
    iteration: int = Field(ge=1, le=100)
    arguments: dict[str, Any]


class InvestigationToolCallComplete(AgentStrictModel):
    status: Literal["succeeded", "failed"]
    result: dict[str, Any] | list[Any] | None = None
    error: str | None = Field(default=None, max_length=10_000)

    @model_validator(mode="after")
    def validate_completion(self) -> InvestigationToolCallComplete:
        if self.status == "succeeded" and self.error:
            raise ValueError("successful tool calls cannot include an error")
        if self.status == "failed" and not self.error:
            raise ValueError("failed tool calls require an error")
        return self


class InvestigationToolCallRead(AgentStrictModel):
    id: str
    investigation_id: str
    tool_id: str
    iteration: int
    call_hash: str
    arguments: dict[str, Any]
    status: str
    result: dict[str, Any] | list[Any] | None
    result_hash: str | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class AgentActionProposalRead(AgentStrictModel):
    id: str
    investigation_id: str
    tool_id: str
    tool_call_id: str | None
    iteration: int
    arguments: dict[str, Any]
    purpose: str
    plan_hash: str
    status: Literal[
        "pending",
        "approved",
        "rejected",
        "executing",
        "succeeded",
        "failed",
    ]
    requested_by_principal_id: str | None
    requested_by: str
    approved_by_principal_id: str | None
    approved_by: str | None
    decision_reason: str | None
    result_hash: str | None
    error: str | None
    requested_at: datetime
    decided_at: datetime | None
    execution_started_at: datetime | None
    execution_finished_at: datetime | None


class AgentActionDecision(AgentStrictModel):
    decision: Literal["approve", "reject"]
    expected_plan_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    reason: str = Field(min_length=1, max_length=4000)


class AgentWorkerRegister(AgentStrictModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    capabilities: list[str] = Field(
        default_factory=lambda: ["openai_compatible"],
        min_length=1,
        max_length=32,
    )
    labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if not normalized:
            raise ValueError("at least one capability is required")
        if any(len(item) > 64 for item in normalized):
            raise ValueError("capabilities must not exceed 64 characters")
        return list(dict.fromkeys(normalized))

    @field_validator("labels")
    @classmethod
    def normalize_labels(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 50:
            raise ValueError("labels must not contain more than 50 entries")
        normalized: dict[str, str] = {}
        for key, item in value.items():
            normalized_key = key.strip()
            normalized_value = item.strip()
            if not normalized_key or len(normalized_key) > 64:
                raise ValueError("label names must contain 1 to 64 characters")
            if len(normalized_value) > 255:
                raise ValueError("label values must not exceed 255 characters")
            normalized[normalized_key] = normalized_value
        return normalized


class AgentWorkerHeartbeat(AgentStrictModel):
    state: AgentWorkerStateValue = "online"
    capabilities: list[str] | None = Field(default=None, min_length=1, max_length=32)
    labels: dict[str, str] | None = None


class AgentWorkerRead(AgentStrictModel):
    id: str
    name: str
    capabilities: list[str]
    labels: dict[str, str]
    state: AgentWorkerStateValue
    token_issued_at: datetime
    last_heartbeat_at: datetime
    created_at: datetime
    updated_at: datetime


class AgentWorkerRegistration(AgentStrictModel):
    worker: AgentWorkerRead
    access_token: str


class AgentExecutionRead(AgentStrictModel):
    id: str
    investigation_id: str
    status: AgentExecutionStatusValue
    worker_id: str | None
    lease_expires_at: datetime | None
    attempt_count: int
    cancellation_requested_at: datetime | None
    cancellation_requested_by: str | None
    cancellation_reason: str | None
    started_at: datetime | None
    last_heartbeat_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class AgentExecutionClaim(AgentStrictModel):
    max_assignments: int = Field(default=1, ge=1, le=10)
    lease_seconds: int = Field(default=60, ge=15, le=3600)


class AgentExecutionAssignment(AgentStrictModel):
    execution_id: str
    investigation_id: str
    lease_token: str
    lease_expires_at: datetime
    attempt: int
    resume_required: bool


class AgentExecutionLeaseRenew(AgentStrictModel):
    lease_token: str = Field(min_length=20, max_length=512)
    lease_seconds: int = Field(default=60, ge=15, le=3600)


class AgentExecutionCancel(AgentStrictModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class AgentExecutionComplete(AgentStrictModel):
    lease_token: str = Field(min_length=20, max_length=512)
    status: Literal["succeeded", "failed", "cancelled", "waiting_approval"]
    error: str | None = Field(default=None, max_length=10_000)

    @model_validator(mode="after")
    def validate_completion(self) -> AgentExecutionComplete:
        if self.status == "succeeded" and self.error:
            raise ValueError("successful executions cannot include an error")
        if self.status == "failed" and not self.error:
            raise ValueError("failed executions require an error")
        return self


class AgentExecutionEventRead(AgentStrictModel):
    id: str
    execution_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
