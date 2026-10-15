from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator

from .schemas import APIModel


ToolTransport = Literal["internal", "mcp", "managed_mcp"]
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
ChangeRiskClass = Literal["low", "medium", "high", "critical"]
ChangeEvidenceStage = Literal["precheck", "dry_run", "postcheck", "rollback", "rollback_check"]


class AgentStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class AgentChangeEvidenceStep(AgentStrictModel):
    tool_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    success_path: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    argument_mapping: dict[str, str] = Field(default_factory=dict, max_length=32)
    summary_paths: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("argument_mapping")
    @classmethod
    def validate_argument_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        import re

        pattern = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        if any(
            re.fullmatch(pattern, target) is None
            or re.fullmatch(pattern, source) is None
            for target, source in value.items()
        ):
            raise ValueError("change stage mappings must use dotted object paths")
        return value

    @field_validator("summary_paths")
    @classmethod
    def validate_summary_paths(cls, value: list[str]) -> list[str]:
        import re

        pattern = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        sensitive = {
            "authorization",
            "community",
            "credential",
            "key",
            "passphrase",
            "password",
            "private",
            "secret",
            "token",
        }
        if len(set(value)) != len(value) or any(
            re.fullmatch(pattern, path) is None
            or any(part.lower() in sensitive for part in path.split("."))
            for path in value
        ):
            raise ValueError(
                "change evidence summaries require unique, non-sensitive dotted paths"
            )
        return value


class AgentChangeSemanticExpectation(AgentStrictModel):
    """Compare independent read-only observations with the action's desired state."""

    action_argument_path: str = Field(
        min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    precheck_observation_path: str = Field(
        min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    postcheck_observation_path: str = Field(
        min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    max_precheck_age_seconds: int = Field(default=300, ge=60, le=3600)
    max_postcheck_delay_seconds: int = Field(default=300, ge=60, le=3600)

    @field_validator("action_argument_path", "precheck_observation_path", "postcheck_observation_path")
    @classmethod
    def reject_sensitive_paths(cls, value: str) -> str:
        sensitive = {"authorization", "community", "credential", "key", "passphrase",
            "password", "private", "secret", "token"}
        if any(part.lower() in sensitive for part in value.split(".")):
            raise ValueError("semantic observations cannot contain credential paths")
        return value


class AgentChangeRollbackExpectation(AgentStrictModel):
    """Prove restoration to an original pre-change observation, not an action flag."""

    precheck_observation_path: str = Field(min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
    rollback_observation_path: str = Field(min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
    max_check_delay_seconds: int = Field(default=300, ge=60, le=3600)

    @field_validator("precheck_observation_path", "rollback_observation_path")
    @classmethod
    def reject_sensitive_paths(cls, value: str) -> str:
        return AgentChangeSemanticExpectation.reject_sensitive_paths(value)


class AgentChangeContract(AgentStrictModel):
    contract_version: Literal["icheck.change-tool/v1"] = "icheck.change-tool/v1"
    risk_class: ChangeRiskClass
    target_argument_paths: list[str] = Field(min_length=1, max_length=16)
    authorization_target_paths: dict[
        str,
        Literal["device_id", "site"],
    ] = Field(default_factory=dict, max_length=16)
    idempotency_key_argument_path: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    precheck: AgentChangeEvidenceStep
    dry_run: AgentChangeEvidenceStep
    postcheck: AgentChangeEvidenceStep
    rollback: AgentChangeEvidenceStep
    semantic_expectations: list[AgentChangeSemanticExpectation] = Field(default_factory=list, max_length=8)
    rollback_check: AgentChangeEvidenceStep | None = None
    rollback_expectations: list[AgentChangeRollbackExpectation] = Field(default_factory=list, max_length=8)
    requires_maintenance_window: bool = True

    @field_validator("target_argument_paths")
    @classmethod
    def normalize_target_paths(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        path_pattern = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        import re

        if len(normalized) != len(value) or any(
            re.fullmatch(path_pattern, item) is None for item in normalized
        ):
            raise ValueError("target argument paths must be dotted object paths")
        if len(set(normalized)) != len(normalized):
            raise ValueError("target argument paths must be unique")
        return normalized

    @field_validator("authorization_target_paths")
    @classmethod
    def validate_authorization_target_paths(
        cls,
        value: dict[str, Literal["device_id", "site"]],
    ) -> dict[str, Literal["device_id", "site"]]:
        import re

        path_pattern = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        if any(re.fullmatch(path_pattern, path) is None for path in value):
            raise ValueError("authorization targets must use dotted object paths")
        return value

    @model_validator(mode="after")
    def authorization_targets_are_frozen(self) -> "AgentChangeContract":
        if not set(self.authorization_target_paths).issubset(
            set(self.target_argument_paths)
        ):
            raise ValueError(
                "authorization target paths must also be frozen target paths"
            )
        paths = [item.action_argument_path for item in self.semantic_expectations]
        if len(paths) != len(set(paths)):
            raise ValueError("semantic expectations require distinct desired-state arguments")
        if any(path == self.idempotency_key_argument_path or path in self.target_argument_paths for path in paths):
            raise ValueError("semantic expectations cannot use identity or idempotency arguments")
        if self.rollback_check is not None or self.rollback_expectations:
            before = [item.precheck_observation_path for item in self.rollback_expectations]
            after = [item.rollback_observation_path for item in self.rollback_expectations]
            if (self.rollback_check is None or not self.rollback_expectations
                or not self.semantic_expectations
                or set(before) != {item.precheck_observation_path for item in self.semantic_expectations}
                or len(before) != len(set(before)) or len(after) != len(set(after))):
                raise ValueError("Rollback checks require distinct observations covering every pre-change semantic value")
        return self


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
    change_contract: AgentChangeContract | None = None
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
        if self.read_only and self.change_contract is not None:
            raise ValueError("read-only tools cannot declare a change contract")
        if self.change_contract is not None and self.risk_level != "change":
            raise ValueError("change contracts require change risk")
        return self


class AgentToolRead(AgentToolCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class InvestigationCreate(AgentStrictModel):
    title: str = Field(min_length=1, max_length=255)
    objective: str = Field(min_length=1, max_length=10_000)
    execution_mode: Literal["standard", "diagnose"] = "standard"
    scope: dict[str, Any] = Field(default_factory=dict)
    situation_id: str | None = None
    route_purpose: str = Field(
        default="investigation",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    agent_profile: str | None = Field(default=None, min_length=1, max_length=128)
    created_by: str = Field(min_length=1, max_length=255)


class InvestigationRead(AgentStrictModel):
    id: str
    title: str
    objective: str
    execution_mode: Literal["standard", "diagnose"]
    parent_investigation_id: str | None
    scope: dict[str, Any]
    status: InvestigationStatus
    route_id: str
    model_id: str
    fallback_model_ids: list[str]
    agent_profile_id: str | None
    agent_profile_snapshot: dict[str, Any]
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
    situation_id: str | None
    skill_artifact_version_id: str | None
    skill_input: dict[str, Any]
    skill_snapshot: dict[str, Any]
    structured_output: dict[str, Any] | None
    workflow_artifact_version_id: str | None
    workflow_input: dict[str, Any]
    workflow_snapshot: dict[str, Any]
    workflow_trigger_event_id: str | None
    requested_by_principal_id: str | None
    permission_snapshot: list[str]
    authorization_scope: dict[str, Any]
    created_by: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InvestigationPage(AgentStrictModel):
    items: list[InvestigationRead]
    next_cursor: str | None


class InvestigationAction(AgentStrictModel):
    actor: str = Field(min_length=1, max_length=255)


class HypothesisState(AgentStrictModel):
    statement: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class WorkflowToolOutcome(AgentStrictModel):
    """Minimized runtime outcome; Tool bodies stay in the ToolCall ledger."""

    call_id: str = Field(min_length=1, max_length=36)
    status: Literal["succeeded", "failed"]


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
    workflow_tool_outcomes: list[WorkflowToolOutcome] = Field(
        default_factory=list, max_length=20
    )
    confidence: float | None = Field(default=None, ge=0, le=1)
    conclusion: str | None = Field(default=None, max_length=20_000)
    uncertainty: list[str] = Field(default_factory=list, max_length=100)
    escalation_reason: str | None = Field(default=None, max_length=4000)
    structured_output: dict[str, Any] | None = None


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
    tool_name: str | None = None
    artifact_version_id: str | None = None
    artifact_content_hash: str | None = None
    artifact_activation_id: str | None = None
    artifact_activation_sha256: str | None = None
    governed_change_plan_id: str | None = None
    governed_stage: Literal["precheck", "dry_run", "postcheck", "rollback_check"] | None = None
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
    rollback_of_change_plan_id: str | None
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


class MCPWriteReconciliationPacket(AgentStrictModel):
    proposal_id: str
    investigation_id: str
    tool_call_id: str
    current_tool_name: str
    call_started_at: datetime
    artifact_activation_id: str | None
    artifact_version_id: str | None
    designated_lookup_tool_name: str | None = None
    provider_lookup_key: str
    outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False


class MCPWriteLookupResult(AgentStrictModel):
    source_tool_call_id: str = Field(min_length=1, max_length=36)
    provider_outcome: Literal["applied", "not_applied", "unknown"]
    provider_reference: str | None = Field(default=None, max_length=255)
    observed_at: datetime

    @model_validator(mode="after")
    def require_independent_reference(self) -> "MCPWriteLookupResult":
        if self.observed_at.tzinfo is None:
            raise ValueError("Provider lookup observation needs a timezone")
        if self.provider_outcome != "unknown" and not self.provider_reference:
            raise ValueError("Determinate provider lookup needs a reference")
        return self


class MCPWriteReconciliationObservationCreate(AgentStrictModel):
    lookup_tool_call_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)


class MCPWriteReconciliationObservationRead(AgentStrictModel):
    id: str
    proposal_id: str
    original_tool_call_id: str
    lookup_tool_call_id: str
    provider_outcome: Literal["applied", "not_applied", "unknown"]
    provider_reference: str | None
    observed_at: datetime
    lookup_result_hash: str
    recorded_by_principal_id: str | None
    recorded_by: str
    reason: str
    created_at: datetime


class MCPWriteReconciliationReviewCreate(AgentStrictModel):
    decision: Literal["accept", "reject", "inconclusive"]
    reason: str = Field(min_length=10, max_length=1000)


class MCPWriteReconciliationReviewRead(AgentStrictModel):
    id: str
    proposal_id: str
    observation_id: str
    decision: Literal["accept", "reject", "inconclusive"]
    reviewed_by_principal_id: str
    reviewed_by: str
    reason: str
    reviewed_at: datetime


class MCPWriteReconciliationSummary(AgentStrictModel):
    proposal_id: str
    original_tool_call_id: str
    observation_count: int
    reviewed_count: int
    accepted_provider_reports: list[Literal["applied", "not_applied", "unknown"]]
    contradictory_determinate_reports: bool
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPDeclaredProviderLookupQualification(AgentStrictModel):
    proposal_id: str
    observation_id: str
    lookup_tool_call_id: str
    reported_provider_outcome: Literal["applied", "not_applied", "unknown"]
    provider_reference: str | None
    observed_at: datetime
    consistency_window_seconds: int
    max_observation_age_seconds: int
    correlation_key: Literal["icheck/toolCallId"] = "icheck/toolCallId"
    provider_correlation_verified: Literal[False] = False
    final_disposition_allowed: Literal[False] = False
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False


class MCPIndependentVerificationResult(AgentStrictModel):
    source_tool_call_id: str = Field(min_length=1, max_length=36)
    verification_kind: Literal["target_state", "recipient_receipt"]
    observed_target_state: Literal["present", "absent", "unknown"]
    observed_at: datetime
    evidence_reference: str | None = Field(default=None, max_length=255)
    values: dict[str, Any] = Field(min_length=1, max_length=24)

    @model_validator(mode="after")
    def require_bounded_observation(self) -> "MCPIndependentVerificationResult":
        import math
        import re

        if self.observed_at.tzinfo is None:
            raise ValueError("Independent verification observation needs a timezone")
        if self.observed_target_state != "unknown" and not self.evidence_reference:
            raise ValueError("Determinate independent verification needs an evidence reference")
        if self.evidence_reference is not None and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}", self.evidence_reference
        ) is None:
            raise ValueError("Independent verification reference must be an opaque identifier")
        for key, value in self.values.items():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) is None:
                raise ValueError("Independent verification value keys must be bounded identifiers")
            if type(value) is str:
                maximum = 2048 if key in {"issuer", "client_id", "resource"} else 255
                if not value or len(value) > maximum:
                    raise ValueError("Independent verification strings must be bounded")
            elif type(value) is float:
                if not math.isfinite(value):
                    raise ValueError("Independent verification numbers must be finite")
            elif type(value) not in {bool, int}:
                raise ValueError("Independent verification values must be scalar")
        return self


class MCPIndependentVerificationQualification(AgentStrictModel):
    proposal_id: str
    original_tool_call_id: str
    verification_tool_call_id: str
    verification_kind: Literal["target_state", "recipient_receipt"]
    observed_target_state: Literal["present", "absent", "unknown"]
    observed_at: datetime
    evidence_reference: str | None
    bound_value_count: int = Field(ge=1, le=16)
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPIndependentEvidenceSummary(AgentStrictModel):
    proposal_id: str
    observation_count: int
    reviewed_count: int
    accepted_target_states: list[Literal["present", "absent", "unknown"]]
    accepted_recipient_receipt_states: list[Literal["present", "absent", "unknown"]]
    divergent_determinate_target_states: bool
    divergent_determinate_recipient_receipts: bool
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPDispositionContractQualification(AgentStrictModel):
    """Current frozen-contract checks, not provider or target truth."""

    checked_at: datetime
    accepted_provider_count: int = Field(ge=0)
    contract_qualified_provider_count: int = Field(ge=0)
    unqualified_provider_observation_ids: list[str]
    accepted_independent_count: int = Field(ge=0)
    contract_qualified_independent_count: int = Field(ge=0)
    unqualified_independent_observation_ids: list[str]
    provider_correlation_verified: Literal[False] = False
    final_disposition_allowed: Literal[False] = False


class MCPDispositionProviderEvidenceRef(AgentStrictModel):
    observation_id: str
    lookup_tool_call_id: str
    lookup_result_hash: str
    provider_outcome: Literal["applied", "not_applied", "unknown"]
    observed_at: datetime
    recorded_at: datetime
    recorded_by_principal_id: str | None
    review_id: str | None
    review_decision: Literal["accept", "reject", "inconclusive"] | None
    reviewed_by_principal_id: str | None
    reviewed_at: datetime | None


class MCPDispositionIndependentEvidenceRef(AgentStrictModel):
    observation_id: str
    verification_tool_call_id: str
    verification_result_hash: str
    verification_kind: Literal["target_state", "recipient_receipt"]
    observed_target_state: Literal["present", "absent", "unknown"]
    observed_at: datetime
    recorded_at: datetime
    recorded_by_principal_id: str
    review_id: str | None
    review_decision: Literal["accept", "reject", "inconclusive"] | None
    reviewed_by_principal_id: str | None
    reviewed_at: datetime | None


class MCPDispositionEvidenceManifest(AgentStrictModel):
    format_version: Literal["icheck.mcp-write-disposition-evidence/v1"] = (
        "icheck.mcp-write-disposition-evidence/v1"
    )
    proposal_id: str
    original_tool_call_id: str
    plan_hash: str
    artifact_activation_id: str | None
    artifact_version_id: str | None
    artifact_content_hash: str | None
    artifact_activation_sha256: str | None
    evidence_investigation_ids: list[str]
    provider_observations: list[MCPDispositionProviderEvidenceRef]
    independent_observations: list[MCPDispositionIndependentEvidenceRef]


class MCPWriteDispositionEvidenceSnapshot(AgentStrictModel):
    proposal_id: str
    original_tool_call_id: str
    provider: MCPWriteReconciliationSummary
    independent: MCPIndependentEvidenceSummary
    contract_qualification: MCPDispositionContractQualification
    evidence_manifest: MCPDispositionEvidenceManifest
    all_evidence_reviewable: Literal[True] = True
    native_transactional_lock: bool
    final_disposition_allowed: Literal[False] = False
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPWriteDispositionProviderRef(AgentStrictModel):
    observation_id: str
    lookup_result_hash: str
    review_id: str | None
    review_decision: Literal["accept", "reject", "inconclusive"] | None


class MCPWriteDispositionIndependentRef(AgentStrictModel):
    observation_id: str
    verification_result_hash: str
    review_id: str | None
    review_decision: Literal["accept", "reject", "inconclusive"] | None


class MCPWriteDispositionRefs(AgentStrictModel):
    format_version: Literal["icheck.mcp-write-disposition-refs/v1"] = (
        "icheck.mcp-write-disposition-refs/v1"
    )
    provider: list[MCPWriteDispositionProviderRef]
    independent: list[MCPWriteDispositionIndependentRef]


class MCPWriteDispositionCreate(AgentStrictModel):
    request_id: UUID
    reason: str = Field(min_length=10, max_length=1000)


class MCPWriteDispositionRead(AgentStrictModel):
    id: str
    request_id: str
    proposal_id: str
    original_tool_call_id: str
    decision: Literal["unresolved"]
    plan_hash: str
    evidence_refs: MCPWriteDispositionRefs
    reviewed_by: str
    reason: str
    recorded_at: datetime
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPIndependentObservationCreate(AgentStrictModel):
    verification_tool_call_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)


class MCPIndependentObservationRead(AgentStrictModel):
    id: str
    proposal_id: str
    original_tool_call_id: str
    verification_tool_call_id: str
    verification_kind: Literal["target_state", "recipient_receipt"]
    observed_target_state: Literal["present", "absent", "unknown"]
    observed_at: datetime
    evidence_reference: str | None
    bound_value_count: int
    verification_result_hash: str
    recorded_by_principal_id: str
    recorded_by: str
    reason: str
    created_at: datetime
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class MCPIndependentReviewCreate(AgentStrictModel):
    decision: Literal["accept", "reject", "inconclusive"]
    reason: str = Field(min_length=10, max_length=1000)


class MCPIndependentReviewRead(AgentStrictModel):
    id: str
    proposal_id: str
    observation_id: str
    decision: Literal["accept", "reject", "inconclusive"]
    reviewed_by_principal_id: str
    reviewed_by: str
    reason: str
    reviewed_at: datetime
    original_outcome: Literal["unknown"] = "unknown"
    automatic_retry_allowed: Literal[False] = False
    delivery_verified: Literal[False] = False


class GovernedChangeEvidenceRead(AgentStrictModel):
    id: str
    stage: ChangeEvidenceStage
    tool_call_id: str
    tool_id: str
    arguments_hash: str
    result_hash: str
    passed: bool
    evidence_snapshot: dict[str, Any]
    recorded_by: str
    created_at: datetime


class ChangeRiskPolicyRead(AgentStrictModel):
    id: str
    risk_class: ChangeRiskClass
    execution_enabled: bool
    maintenance_window_required: bool
    max_window_minutes: int
    require_evidence_summary: bool
    require_authorization_binding: bool
    revision: int
    updated_by: str
    update_reason: str
    created_at: datetime
    updated_at: datetime


class ChangeRiskPolicyUpdate(AgentStrictModel):
    expected_revision: int = Field(ge=1)
    execution_enabled: bool
    maintenance_window_required: bool
    max_window_minutes: int = Field(ge=5, le=480)
    require_evidence_summary: bool
    require_authorization_binding: bool
    reason: str = Field(min_length=3, max_length=4000)


class ChangePreapprovalSettings(AgentStrictModel):
    name: str = Field(min_length=3, max_length=128)
    target_device_id: UUID
    alert_event_type: str = Field(min_length=3, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")
    arguments_template: dict[str, Any] = Field(min_length=1, max_length=32)
    max_alert_age_seconds: int = Field(default=300, ge=60, le=3600)
    max_evidence_age_seconds: int = Field(default=300, ge=60, le=3600)
    max_actions_per_alert: int = Field(default=1, ge=1, le=3)
    expires_at: datetime


class ChangePreapprovalInputSettings(ChangePreapprovalSettings):
    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Preapproval expiry must have a timezone")
        return value


class ChangePreapprovalCreate(ChangePreapprovalInputSettings):
    tool_artifact_version_id: UUID
    expected_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=10, max_length=512)


class ChangePreapprovalUpdate(ChangePreapprovalInputSettings):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=512)


class ChangePreapprovalDecision(AgentStrictModel):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=512)


class ChangePreapprovalRead(ChangePreapprovalSettings):
    id: str
    status: Literal["draft", "reviewed", "revoked"]
    tool_artifact_version_id: str
    tool_content_hash: str
    target_device_id: str
    target_site: str
    revision: int
    created_by: str
    created_by_principal_id: str | None
    updated_by: str
    reviewed_by: str | None
    reviewed_by_principal_id: str | None
    reviewed_at: datetime | None
    review_sha256: str | None
    created_at: datetime
    updated_at: datetime
    authorizes_execution: Literal[False] = False


class ChangePreapprovalPreview(AgentStrictModel):
    policy_id: str
    change_plan_id: str
    candidate_matches: bool
    blocking_reasons: list[str]
    matched_alert_id: str | None
    budget_used: int | None
    budget_limit: int | None
    authorizes_execution: Literal[False] = False


class ChangePreapprovalExecutionGrantCreate(AgentStrictModel):
    expected_policy_review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    quality_policy_id: UUID
    expected_assessment_id: UUID
    independent_validation_confirmed: Literal[True]
    acceptance_reference: str = Field(min_length=10, max_length=1024)
    expires_at: datetime
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Execution grant expiry must have a timezone")
        return value


class ChangePreapprovalExecutionGrantRead(AgentStrictModel):
    id: str
    policy_id: str
    policy_review_sha256: str
    quality_policy_id: str
    quality_policy_sha256: str
    qualification_assessment_id: str
    qualification_assessment_sha256: str
    acceptance_reference: str
    granted_by_principal_id: str
    granted_by: str
    granted_at: datetime
    expires_at: datetime


class ChangePreapprovalExecutionGrantPage(AgentStrictModel):
    items: list[ChangePreapprovalExecutionGrantRead]
    execution_enabled: bool


class ChangePreapprovalExecutionRequest(AgentStrictModel):
    expected_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class RollbackQualificationSettings(AgentStrictModel):
    min_samples: int = Field(default=5, ge=1, le=200)
    window_minutes: int = Field(default=1440, ge=1, le=1440)
    max_sample_age_seconds: int = Field(default=86400, ge=60, le=86400)
    max_start_delay_seconds: int = Field(default=300, ge=60, le=3600)


class RollbackExecutionGrantCreate(RollbackQualificationSettings):
    expected_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    independent_validation_confirmed: Literal[True]
    acceptance_reference: str = Field(min_length=10, max_length=1024)
    expires_at: datetime
    reason: str = Field(min_length=10, max_length=512)

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime) -> datetime:
        return ChangePreapprovalExecutionGrantCreate.require_aware_expiry(value)


class RollbackExecutionGrantRead(AgentStrictModel):
    id: str
    primary_grant_id: str
    settings_snapshot: dict[str, Any]
    qualification_manifest: list[dict[str, Any]]
    qualification_sha256: str
    acceptance_reference: str
    granted_by_principal_id: str
    granted_by: str
    granted_at: datetime
    expires_at: datetime


class RollbackQualificationRead(AgentStrictModel):
    ready: bool
    required_samples: int
    matching_samples: int
    evidence_sha256: str
    valid_until: datetime | None
    reason: str | None
    authorizes_automation: Literal[False] = False
    evidence_scope: Literal["restoration_not_primary_success"] = "restoration_not_primary_success"


class RollbackExecutionGrantPage(AgentStrictModel):
    items: list[RollbackExecutionGrantRead]
    revoked_grant_ids: list[str]
    execution_enabled: bool


class RollbackGrantRevocationCreate(AgentStrictModel):
    reason: str = Field(min_length=10, max_length=512)


class RollbackAuthorizationRead(AgentStrictModel):
    id: str
    grant_id: str
    primary_authorization_id: str
    parent_change_plan_id: str
    rollback_proposal_id: str
    action_plan_hash: str
    failure_snapshot: dict[str, Any]
    evidence_manifest: list[dict[str, Any]]
    evidence_sha256: str
    authorized_at: datetime
    rollback_budget: Literal[1] = 1


class RollbackAuthorizationCreate(AgentStrictModel):
    grant_id: UUID
    expected_action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChangePreapprovalQualificationRead(AgentStrictModel):
    ready: bool
    quality_policy_id: str | None
    assessment_id: str | None
    valid_until: datetime | None
    matching_samples: int
    required_samples: int | None
    reason: str | None


class ChangePreapprovalAuthorizationRead(AgentStrictModel):
    id: str
    grant_id: str
    budget_claim_id: str
    action_proposal_id: str
    action_plan_hash: str
    change_plan_hash: str
    assessment_id: str
    assessment_sha256: str
    authorized_at: datetime
    approval_source: Literal["reviewed_policy"] = "reviewed_policy"


class GovernedChangePlanRead(AgentStrictModel):
    id: str
    action_proposal_id: str
    investigation_id: str
    contract_version: Literal["icheck.change-plan/v1"]
    revision: int
    status: Literal[
        "awaiting_evidence",
        "ready_for_approval",
        "approved",
        "rejected",
        "executing",
        "awaiting_postcheck",
        "verified",
        "rollback_required",
        "awaiting_rollback_check",
        "rolled_back",
        "rollback_failed",
    ]
    risk_class: ChangeRiskClass
    tool_contract_snapshot: dict[str, Any]
    target_snapshot: dict[str, Any]
    authorization_scope_snapshot: dict[str, Any]
    idempotency_key_hash: str
    maintenance_window_start: datetime | None
    maintenance_window_end: datetime | None
    plan_hash: str
    approved_plan_hash: str | None
    policy_evaluation: dict[str, Any]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime
    evidence: list[GovernedChangeEvidenceRead] = Field(default_factory=list)


class GovernedChangeWindowUpdate(AgentStrictModel):
    expected_revision: int = Field(ge=1)
    expected_plan_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    maintenance_window_start: datetime
    maintenance_window_end: datetime
    reason: str = Field(min_length=1, max_length=4000)


class GovernedChangeEvidenceAttach(AgentStrictModel):
    expected_revision: int = Field(ge=1)
    expected_plan_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    stage: ChangeEvidenceStage
    tool_call_id: str
    reason: str = Field(min_length=1, max_length=4000)


class AgentActionDecision(AgentStrictModel):
    decision: Literal["approve", "reject"]
    expected_plan_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    expected_change_plan_hash: str | None = Field(
        default=None,
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
    mtls_fingerprint_sha256: str | None
    mtls_not_after: datetime | None
    mtls_next_fingerprint_sha256: str | None
    mtls_next_not_before: datetime | None
    mtls_next_not_after: datetime | None
    mtls_revision: int
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


class AgentExecutionProgress(AgentStrictModel):
    lease_token: str = Field(min_length=20, max_length=512)
    node: Literal["reason", "tools", "finalize"]
    status: InvestigationStatus
    iteration: int = Field(ge=0, le=100_000)
    tokens_used: int = Field(ge=0, le=1_000_000_000_000)
    tool_calls_used: int = Field(ge=0, le=1_000_000)
    evidence_count: int = Field(ge=0, le=1_000_000)
    state: dict[str, Any] | None = None


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


AgentRuntimeProtocolVersion = Literal["icheck.agent-runtime/v1"]
MAX_AGENT_RUNTIME_MESSAGE_WIRE_CHARS = 15_000_000


class AgentRuntimeRequest(AgentStrictModel):
    protocol_version: AgentRuntimeProtocolVersion = "icheck.agent-runtime/v1"
    lease_token: str = Field(min_length=20, max_length=512)


class AgentRuntimeBootstrapRequest(AgentRuntimeRequest):
    pass


class AgentRuntimeBootstrapRead(AgentStrictModel):
    protocol_version: AgentRuntimeProtocolVersion
    execution_id: str
    investigation_id: str
    initial_state: dict[str, Any]
    resume_required: bool
    resume_value: dict[str, Any] | None = None
    reasoning_deadline: datetime | None = None


class AgentRuntimeWireValue(AgentStrictModel):
    type: str = Field(min_length=1, max_length=32, pattern=r"^[a-z0-9_.+-]+$")
    data_base64: str = Field(max_length=14_000_000)


class AgentRuntimeCheckpointGet(AgentRuntimeRequest):
    config: dict[str, Any]


class AgentRuntimeCheckpointList(AgentRuntimeRequest):
    config: dict[str, Any] | None = None
    filter: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    limit: int = Field(default=20, ge=1, le=100)


class AgentRuntimeCheckpointPut(AgentRuntimeRequest):
    config: dict[str, Any]
    checkpoint: AgentRuntimeWireValue
    metadata: AgentRuntimeWireValue
    new_versions: AgentRuntimeWireValue

    @model_validator(mode="after")
    def bound_checkpoint_message(self) -> "AgentRuntimeCheckpointPut":
        encoded_chars = sum(
            len(value.data_base64)
            for value in (self.checkpoint, self.metadata, self.new_versions)
        )
        if encoded_chars > MAX_AGENT_RUNTIME_MESSAGE_WIRE_CHARS:
            raise ValueError("runtime checkpoint message exceeds its size limit")
        return self


class AgentRuntimeCheckpointWrites(AgentRuntimeRequest):
    config: dict[str, Any]
    writes: list[tuple[str, AgentRuntimeWireValue]] = Field(max_length=1000)
    task_id: str = Field(min_length=1, max_length=512)
    task_path: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def bound_checkpoint_writes(self) -> "AgentRuntimeCheckpointWrites":
        encoded_chars = sum(len(value.data_base64) for _, value in self.writes)
        if encoded_chars > MAX_AGENT_RUNTIME_MESSAGE_WIRE_CHARS:
            raise ValueError("runtime checkpoint writes exceed their size limit")
        return self


class AgentRuntimePendingWrite(AgentStrictModel):
    task_id: str = Field(min_length=1, max_length=512)
    channel: str = Field(min_length=1, max_length=512)
    value: AgentRuntimeWireValue


class AgentRuntimeCheckpointTupleRead(AgentStrictModel):
    config: dict[str, Any]
    checkpoint: AgentRuntimeWireValue
    metadata: AgentRuntimeWireValue
    parent_config: dict[str, Any] | None = None
    pending_writes: list[AgentRuntimePendingWrite] = Field(
        default_factory=list,
        max_length=10_000,
    )


class AgentRuntimeCheckpointPutRead(AgentStrictModel):
    config: dict[str, Any]


class AgentRuntimeReasonRequest(AgentRuntimeRequest):
    operation_id: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    state: dict[str, Any]


class AgentRuntimeReasonRead(AgentStrictModel):
    protocol_version: AgentRuntimeProtocolVersion
    operation_id: str
    decision: dict[str, Any]


class AgentRuntimeToolRequest(AgentRuntimeRequest):
    operation_id: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    request: dict[str, Any]
    state: dict[str, Any]
    resume_value: dict[str, Any] | None = None


class AgentRuntimeToolFailure(AgentStrictModel):
    error_type: Literal["ActionRejected", "OutcomeUnknown"]
    tool_call_ids: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_identifiers(self):
        for values in (self.tool_call_ids, self.evidence_ids):
            if len(values) != len(set(values)) or any(not 1 <= len(value) <= 36 for value in values):
                raise ValueError("Runtime Tool failure identifiers must be bounded and unique")
        return self


class AgentRuntimeOwnedClosureWait(AgentStrictModel):
    kind: Literal["owned_closure_wait"] = "owned_closure_wait"
    format_version: Literal["icheck.owned-closure-wait/v1"] = "icheck.owned-closure-wait/v1"
    tool_call_id: UUID
    request_id: UUID
    attempt_id: UUID
    epoch: int = Field(strict=True, ge=1)
    retry_after_seconds: int = Field(default=1, strict=True, ge=1, le=1)


class AgentRuntimeToolRead(AgentStrictModel):
    protocol_version: AgentRuntimeProtocolVersion
    operation_id: str
    status: Literal["completed", "interrupted", "failed"]
    result: dict[str, Any] | None = None
    interrupt: dict[str, Any] | None = None
    failure: AgentRuntimeToolFailure | None = None

    @model_validator(mode="after")
    def validate_runtime_tool_response(self) -> "AgentRuntimeToolRead":
        if self.status == "failed":
            if self.failure is None or self.result is not None or self.interrupt is not None:
                raise ValueError("failed runtime Tool operations require only a typed failure")
            return self
        if self.failure is not None:
            raise ValueError("Only failed runtime Tool operations carry failure accounting")
        if self.status == "completed" and self.result is None:
            raise ValueError("completed runtime Tool operations require a result")
        if self.status == "interrupted" and self.interrupt is None:
            raise ValueError("interrupted runtime Tool operations require a payload")
        if self.status == "completed" and self.interrupt is not None:
            raise ValueError("completed runtime Tool operations cannot be interrupted")
        if self.status == "interrupted" and self.result is not None:
            raise ValueError("interrupted runtime Tool operations cannot have a result")
        return self
