from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Iterator, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver, CheckpointTuple
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_runtime_protocol import (
    AGENT_RUNTIME_PROTOCOL_VERSION,
    decode_wire_value,
    encode_wire_value,
    runtime_operation_id,
)
from ..agent_schemas import (
    AgentRuntimeBootstrapRead,
    AgentRuntimeCheckpointGet,
    AgentRuntimeCheckpointList,
    AgentRuntimeCheckpointPut,
    AgentRuntimeCheckpointPutRead,
    AgentRuntimeCheckpointTupleRead,
    AgentRuntimeCheckpointWrites,
    AgentRuntimePendingWrite,
    AgentRuntimeReasonRead,
    AgentRuntimeReasonRequest,
    AgentRuntimeToolRead,
    AgentRuntimeToolRequest,
    InvestigationEvidenceCreate,
)
from ..config import get_settings
from ..credentials import CredentialGrant, CredentialUnavailable
from ..langgraph_runtime import (
    GraphDecision,
    GraphToolRequest,
    GraphToolExecutionFailure,
    GraphToolOutcomeUnknown,
    GraphToolResult,
    InvestigationGraphState,
    initial_graph_state,
    postgres_checkpointer,
)
from ..models import (
    AgentExecution,
    AgentExecutionStatus,
    AgentToolRegistration,
    AgentWorker,
    ArtifactVersion,
    ArtifactVersionStatus,
    CredentialProfile,
    Investigation,
    InvestigationToolCall,
    MCPServer,
    MCPToolActivation,
    utcnow,
)
from .agent_approvals import approval_resume_value
from .agent_execution import active_agent_execution
from .agent_tools import DatabaseToolExecutor
from .collectors import assert_no_inline_secrets, validate_instance
from .mcp_gateway import (
    MCP_PROTOCOL_VERSION,
    MCPContractError,
    MCPGatewayError,
    MCPWriteOutcomeUnknown,
    _adapter_type,
    _canonical_hash,
    _credential_profile,
    _record_mcp_runtime_failure,
    _record_mcp_runtime_success,
    mcp_activation_allows_investigation,
    validate_mcp_endpoint,
)
from .mcp_scope_challenges import (
    MCPInsufficientScopeError,
    mcp_tool_has_open_scope_challenge,
    normalize_scope_values,
    record_mcp_scope_challenge,
)
from .model_reasoner import OpenAICompatibleReasoner
from .workflow_reasoner import WorkflowReasoner


_DEVELOPMENT_CHECKPOINTER = InMemorySaver()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@contextmanager
def runtime_checkpointer(
    investigation: Investigation,
) -> Iterator[BaseCheckpointSaver]:
    settings = get_settings()
    if settings.database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        with postgres_checkpointer(
            settings.database_url,
            tenant_id=investigation.tenant_id,
            region_id=investigation.region_id,
        ) as saver:
            yield saver
        return
    if settings.environment.strip().lower() == "production":
        raise RuntimeError(
            "Production Agent runtime checkpoints require PostgreSQL"
        )
    yield _DEVELOPMENT_CHECKPOINTER


def _canonical_document_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _runtime_context(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    lease_token: str,
    check_alert_stop: bool = False,
) -> tuple[AgentExecution, Investigation]:
    if db.new or db.deleted or any(db.is_modified(row, include_collections=True) for row in db.dirty):
        raise ValueError("Commit pending edits before starting an Agent runtime operation")
    execution = active_agent_execution(
        db,
        execution_id,
        worker_id=worker.id,
        lease_token=lease_token,
    )
    investigation = db.get(Investigation, execution.investigation_id)
    if investigation is None:
        raise LookupError("Investigation not found")
    if check_alert_stop:
        from .alert_investigation_control import enforce_stop
        enforce_stop(db, execution)
    if execution.cancellation_requested_at is not None:
        # Commit the stop even though the runtime request is rejected. Otherwise
        # a failed HTTP operation would roll back the cancellation itself.
        db.commit()
        raise ValueError("Agent execution cancellation was requested")
    # A live Worker lease is not permission to return retained private source
    # material. This also guards cached Tool/reason/checkpoint/bootstrap reads,
    # where the executor would otherwise never run its domain read checks.
    from .agent_authorization import investigation_principal
    from .situation_closure_reads import investigation_receipts_visible
    if not investigation_receipts_visible(db, investigation, investigation_principal(investigation)):
        raise LookupError("Agent runtime history is unavailable in the current initiating scope")
    # Historical readers briefly take shared authority locks. Release this
    # read-only transaction before model/MCP I/O or independent checkpoint I/O.
    # Fresh domain writes still recheck their own actual authority after locks.
    db.commit()
    return execution, investigation


def _validate_graph_state(
    state: dict[str, Any],
    investigation: Investigation,
    *,
    require_persisted_counters: bool,
) -> InvestigationGraphState:
    required = {
        "investigation_id",
        "objective",
        "scope",
        "status",
        "iteration",
        "max_iterations",
        "tool_calls_used",
        "max_tool_calls",
        "tokens_used",
        "token_budget",
        "plan",
        "hypotheses",
        "evidence_ids",
        "tool_call_ids",
        "pending_tool_requests",
        "tool_results",
        "call_hashes",
        "confidence",
        "conclusion",
        "uncertainty",
        "escalation_reason",
        "structured_output",
        "current_node",
    }
    if set(state) != required:
        raise ValueError("Agent runtime state has an invalid shape")
    if (
        state["investigation_id"] != investigation.id
        or state["objective"] != investigation.objective
        or state["scope"] != investigation.scope
        or state["max_iterations"] != investigation.max_iterations
        or state["max_tool_calls"] != investigation.max_tool_calls
        or state["token_budget"] != investigation.token_budget
    ):
        raise ValueError("Agent runtime state does not match the investigation")
    for key in ("iteration", "tool_calls_used", "tokens_used"):
        value = state[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Agent runtime {key} is invalid")
    if state["iteration"] > investigation.max_iterations:
        raise ValueError("Agent runtime iteration exceeds its budget")
    if (
        require_persisted_counters
        and (
            state["iteration"] != investigation.iterations_used
            or state["tool_calls_used"] != investigation.tool_calls_used
            or state["tokens_used"] != investigation.tokens_used
        )
    ):
        raise ValueError(
            "Agent runtime counters do not match persisted investigation state"
        )
    encoded = json.dumps(
        state,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > 2_000_000:
        raise ValueError("Agent runtime state exceeds 2000000 bytes")
    assert_no_inline_secrets(state, "agent runtime state")
    return state  # type: ignore[return-value]


def _checkpoint_config(
    config: dict[str, Any],
    *,
    investigation_id: str,
) -> dict[str, Any]:
    configurable = config.get("configurable")
    if not isinstance(configurable, dict):
        raise ValueError("Checkpoint config requires configurable values")
    if configurable.get("thread_id") != investigation_id:
        raise ValueError("Checkpoint thread does not match the investigation")
    allowed = {"thread_id", "checkpoint_ns", "checkpoint_id"}
    if set(configurable) - allowed:
        raise ValueError("Checkpoint config contains unsupported values")
    namespace = configurable.get("checkpoint_ns", "")
    checkpoint_id = configurable.get("checkpoint_id")
    if not isinstance(namespace, str) or len(namespace) > 512:
        raise ValueError("Checkpoint namespace is invalid")
    if checkpoint_id is not None and (
        not isinstance(checkpoint_id, str) or len(checkpoint_id) > 255
    ):
        raise ValueError("Checkpoint ID is invalid")
    return {
        "configurable": {
            key: value
            for key, value in configurable.items()
            if key in allowed
        }
    }


def _tuple_document(
    saver: BaseCheckpointSaver,
    item: CheckpointTuple,
) -> AgentRuntimeCheckpointTupleRead:
    return AgentRuntimeCheckpointTupleRead(
        config=item.config,
        checkpoint=encode_wire_value(saver.serde, item.checkpoint),
        metadata=encode_wire_value(saver.serde, item.metadata),
        parent_config=item.parent_config,
        pending_writes=[
            AgentRuntimePendingWrite(
                task_id=task_id,
                channel=channel,
                value=encode_wire_value(saver.serde, value),
            )
            for task_id, channel, value in (item.pending_writes or [])
        ],
    )


def runtime_bootstrap(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    lease_token: str,
) -> AgentRuntimeBootstrapRead:
    execution, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=lease_token,
    )
    initial = initial_graph_state(
        investigation_id=investigation.id,
        objective=investigation.objective,
        scope=investigation.scope,
        max_iterations=investigation.max_iterations,
        max_tool_calls=investigation.max_tool_calls,
        token_budget=investigation.token_budget,
    )
    with runtime_checkpointer(investigation) as saver:
        persisted = saver.get_tuple(
            {"configurable": {"thread_id": investigation.id}}
        )
    resume_required = persisted is not None
    if any(
        (
            investigation.iterations_used,
            investigation.tool_calls_used,
            investigation.tokens_used,
        )
    ) and not resume_required:
        raise ValueError(
            "Investigation state exists without a durable runtime checkpoint"
        )
    return AgentRuntimeBootstrapRead(
        protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
        execution_id=execution.id,
        investigation_id=investigation.id,
        initial_state=initial,
        resume_required=resume_required,
        resume_value=approval_resume_value(db, investigation.id),
        reasoning_deadline=_utc(investigation.started_at) + timedelta(seconds=investigation.timeout_seconds),
    )


def checkpoint_get(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeCheckpointGet,
) -> AgentRuntimeCheckpointTupleRead | None:
    _, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
    )
    config = _checkpoint_config(
        payload.config,
        investigation_id=investigation.id,
    )
    with runtime_checkpointer(investigation) as saver:
        item = saver.get_tuple(config)
        return _tuple_document(saver, item) if item is not None else None


def checkpoint_list(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeCheckpointList,
) -> list[AgentRuntimeCheckpointTupleRead]:
    _, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
    )
    config = (
        _checkpoint_config(
            payload.config,
            investigation_id=investigation.id,
        )
        if payload.config is not None
        else {"configurable": {"thread_id": investigation.id}}
    )
    before = (
        _checkpoint_config(
            payload.before,
            investigation_id=investigation.id,
        )
        if payload.before is not None
        else None
    )
    if payload.filter is not None:
        assert_no_inline_secrets(payload.filter, "checkpoint metadata filter")
    with runtime_checkpointer(investigation) as saver:
        return [
            _tuple_document(saver, item)
            for item in saver.list(
                config,
                filter=payload.filter,
                before=before,
                limit=payload.limit,
            )
        ]


def checkpoint_put(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeCheckpointPut,
) -> AgentRuntimeCheckpointPutRead:
    _, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
    )
    config = _checkpoint_config(
        payload.config,
        investigation_id=investigation.id,
    )
    with runtime_checkpointer(investigation) as saver:
        checkpoint = decode_wire_value(saver.serde, payload.checkpoint)
        metadata = decode_wire_value(saver.serde, payload.metadata)
        new_versions = decode_wire_value(saver.serde, payload.new_versions)
        for document, label in (
            (checkpoint, "runtime checkpoint"),
            (metadata, "runtime checkpoint metadata"),
            (new_versions, "runtime checkpoint versions"),
        ):
            assert_no_inline_secrets(document, label)
        result = saver.put(config, checkpoint, metadata, new_versions)
    return AgentRuntimeCheckpointPutRead(config=result)


def checkpoint_writes(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeCheckpointWrites,
) -> None:
    _, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
    )
    config = _checkpoint_config(
        payload.config,
        investigation_id=investigation.id,
    )
    with runtime_checkpointer(investigation) as saver:
        writes: list[tuple[str, Any]] = []
        for channel, wire_value in payload.writes:
            if not channel or len(channel) > 512:
                raise ValueError("Checkpoint write channel is invalid")
            value = decode_wire_value(saver.serde, wire_value)
            assert_no_inline_secrets(value, "runtime checkpoint write")
            writes.append((channel, value))
        saver.put_writes(
            config,
            writes,
            payload.task_id,
            payload.task_path,
        )


class _ReasonOperationState(TypedDict):
    input_hash: str
    graph_state: dict[str, Any]
    decision: dict[str, Any] | None


def execute_runtime_reason(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeReasonRequest,
) -> AgentRuntimeReasonRead:
    execution, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
        check_alert_stop=True,
    )
    state = _validate_graph_state(
        payload.state,
        investigation,
        require_persisted_counters=True,
    )
    document = {"state": dict(state)}
    expected_operation_id = runtime_operation_id(
        "reason",
        execution_id,
        document,
    )
    if not secrets.compare_digest(payload.operation_id, expected_operation_id):
        raise ValueError("Reason operation ID does not match its input")
    input_hash = _canonical_document_hash(document)
    def reason_node(operation: _ReasonOperationState) -> dict[str, Any]:
        current = _validate_graph_state(
                operation["graph_state"],
                investigation,
                require_persisted_counters=True,
            )
        from .conversational_onboarding import deterministic_decision
        decision = deterministic_decision(db, investigation, current)
        if decision is None:
            reasoner = (WorkflowReasoner(db, investigation, runtime_deadline=_utc(execution.lease_expires_at) - timedelta(seconds=10))
                if investigation.workflow_snapshot else OpenAICompatibleReasoner(db, investigation,
                    runtime_deadline=_utc(execution.lease_expires_at) - timedelta(seconds=10)))
            decision = reasoner(current)
        return {"decision": decision.model_dump(mode="json")}

    builder = StateGraph(_ReasonOperationState)
    builder.add_node("reason", reason_node)
    builder.add_edge(START, "reason")
    builder.add_edge("reason", END)
    config = {
        "configurable": {
            "thread_id": f"agent-runtime-reason:{execution_id}:{payload.operation_id}"
        }
    }
    with runtime_checkpointer(investigation) as saver:
        graph = builder.compile(checkpointer=saver)
        snapshot = graph.get_state(config)
        if snapshot.values:
            if snapshot.values.get("input_hash") != input_hash:
                raise ValueError("Reason operation replay input changed")
            if snapshot.next:
                result = graph.invoke(None, config=config)
            else:
                result = snapshot.values
        else:
            result = graph.invoke(
                {
                    "input_hash": input_hash,
                    "graph_state": dict(state),
                    "decision": None,
                },
                config=config,
            )
    decision = GraphDecision.model_validate(result.get("decision"))
    return AgentRuntimeReasonRead(
        protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
        operation_id=payload.operation_id,
        decision=decision.model_dump(mode="json"),
    )


class DelegatedMCPRuntime:
    def __init__(
        self,
        *,
        worker: AgentWorker,
        execution: AgentExecution,
        allowed_hosts: list[str],
    ) -> None:
        self.worker = worker
        self.execution = execution
        self.allowed_hosts = allowed_hosts

    def consume_recorded_call(self, call: InvestigationToolCall) -> None:
        # LangGraph resumes interrupt positions, not mutable database phases.
        # Keep the position of a completed MCP phase even when its persisted
        # evidence lets us skip I/O. New interruptions are read-only acknowledgments
        # with no endpoint/credentials; old resume values are never replayed.
        interrupt({"kind": "recorded_mcp_result", "tool_call_id": call.id})

    def _credential_grant(
        self,
        db: Session,
        server: MCPServer,
        activation: MCPToolActivation,
    ) -> dict[str, Any] | None:
        if not server.credential_profile_ref:
            if server.auth_mode == "oauth_authorization_code":
                raise MCPGatewayError("MCP OAuth requires its configured token profile")
            return None
        if (
            server.auth_mode == "oauth_authorization_code"
            and server.oauth_status != "connected"
        ):
            raise MCPGatewayError(
                f"MCP OAuth is {server.oauth_status}; connect it before execution"
            )
        if server.auth_mode == "oauth_authorization_code" and not server.oauth_generation:
            raise MCPGatewayError("Legacy OAuth consent must be reconnected before worker handoff")
        profile: CredentialProfile | None = _credential_profile(
            db,
            server.credential_profile_ref,
        )
        if profile is None or not profile.enabled:
            raise MCPGatewayError("MCP credential profile is unavailable")
        adapter_type = _adapter_type(profile, server)
        if any(
            (self.worker.labels or {}).get(key) != expected
            for key, expected in (profile.worker_selector or {}).items()
        ):
            raise MCPGatewayError(
                "Agent worker does not match the credential profile scope"
            )
        if (
            self.execution.status != AgentExecutionStatus.RUNNING
            or self.execution.worker_id != self.worker.id
            or self.execution.lease_expires_at is None
            or self.execution.lease_expires_at.replace(
                tzinfo=self.execution.lease_expires_at.tzinfo or UTC
            )
            <= datetime.now(UTC)
        ):
            raise MCPGatewayError("Agent execution lease is not active")
        grant = CredentialGrant(
            profile_id=profile.id,
            profile_name=profile.name,
            provider=profile.provider,
            secret_ref=profile.secret_ref,
            adapter_type=adapter_type,
            deployment_id=activation.id,
            expires_at=self.execution.lease_expires_at.replace(
                tzinfo=self.execution.lease_expires_at.tzinfo or UTC
            ),
            profile_revision=profile.revision,
            oauth_generation=server.oauth_generation if server.auth_mode == "oauth_authorization_code" else None,
        )
        return {
            "profile_id": grant.profile_id,
            "profile_name": grant.profile_name,
            "provider": grant.provider,
            "secret_ref": grant.secret_ref,
            "adapter_type": grant.adapter_type,
            "deployment_id": grant.deployment_id,
            "expires_at": grant.expires_at.isoformat(),
            "profile_revision": grant.profile_revision,
            "oauth_generation": grant.oauth_generation,
        }

    def execute(
        self,
        db: Session,
        tool: AgentToolRegistration,
        arguments: dict[str, Any],
        *,
        investigation: Investigation,
        tool_call_id: str,
    ) -> tuple[dict[str, Any], list[InvestigationEvidenceCreate]]:
        if "mcp" not in self.worker.capabilities:
            raise MCPGatewayError("Agent worker does not advertise MCP capability")
        activation = db.query(MCPToolActivation).filter(
            MCPToolActivation.tool_registration_id == tool.id,
            MCPToolActivation.status == "active",
        ).one_or_none()
        if activation is None or not tool.enabled:
            raise MCPGatewayError("MCP tool has no active governed activation")
        if not mcp_activation_allows_investigation(
            activation,
            investigation.id,
        ):
            raise MCPGatewayError(
                "MCP tool is outside this investigation's canary cohort or its circuit is open"
            )
        if mcp_tool_has_open_scope_challenge(
            db,
            activation.server_id,
            activation.tool_name,
        ):
            raise MCPGatewayError(
                "MCP tool is waiting for operator-approved OAuth scope step-up"
            )
        server = db.get(MCPServer, activation.server_id)
        version = db.get(ArtifactVersion, activation.artifact_version_id)
        if server is None or not server.enabled:
            raise MCPGatewayError("MCP server is unavailable")
        if server.protocol_version != MCP_PROTOCOL_VERSION:
            raise MCPGatewayError("MCP server protocol version is unsupported")
        if version is None or version.status != ArtifactVersionStatus.PUBLISHED:
            raise MCPGatewayError("Activated Tool Artifact is no longer published")
        if (
            activation.tool_name != tool.name
            or tool.transport != "mcp"
            or tool.handler != f"{server.name}/{activation.mcp_tool_name}"
            or activation.input_schema_sha256 != _canonical_hash(tool.input_schema)
            or activation.output_schema_sha256 != _canonical_hash(tool.output_schema)
        ):
            raise MCPContractError("Activated MCP Tool Registry contract has drifted")
        from .tool_provenance import assert_tool_execution_provenance

        assert_tool_execution_provenance(db, investigation, tool, arguments, activation, version)
        endpoint = validate_mcp_endpoint(server.endpoint_url, self.allowed_hosts)
        validate_instance(arguments, tool.input_schema, "MCP tool arguments")
        call = db.get(InvestigationToolCall, tool_call_id)
        if (
            call is None or call.investigation_id != investigation.id
            or call.tool_id != tool.id or call.status != "running"
            or call.arguments != arguments
        ):
            raise MCPGatewayError("Delegated MCP invocation has no bound running Tool call")
        invocation_id = _canonical_document_hash(
            {
                "investigation_id": investigation.id,
                "activation_id": activation.id,
                "tool_name": tool.name,
                "arguments": arguments,
                "tool_call_id": call.id,
            }
        )
        resumed = interrupt(
            {
                "kind": "mcp_invocation",
                "invocation_id": invocation_id,
                "worker_id": self.worker.id,
                "execution_id": self.execution.id,
                "execution_attempt": self.execution.attempt_count,
                "tool_call_id": call.id,
                "read_only": tool.read_only,
                "activation_id": activation.id,
                "endpoint": endpoint,
                "mcp_tool_name": activation.mcp_tool_name,
                "arguments": arguments,
                "output_schema": tool.output_schema,
                "timeout_seconds": tool.timeout_seconds,
                "max_response_bytes": tool.max_result_bytes,
                "credential_grant": self._credential_grant(
                    db,
                    server,
                    activation,
                ),
                "metadata": {
                    "icheck/investigationId": investigation.id,
                    "icheck/toolActivationId": activation.id,
                    "icheck/toolCallId": call.id,
                },
            }
        )
        if (
            not isinstance(resumed, dict)
            or resumed.get("kind") != "mcp_result"
            or resumed.get("invocation_id") != invocation_id
            or resumed.get("status")
            not in {"succeeded", "failed", "scope_required", "outcome_unknown"}
        ):
            raise MCPGatewayError("Delegated MCP result is invalid")
        if resumed["status"] == "scope_required":
            scopes = resumed.get("required_scopes")
            metadata_url = resumed.get("resource_metadata_url")
            if (
                not isinstance(scopes, list)
                or not all(isinstance(scope, str) for scope in scopes)
                or (
                    metadata_url is not None
                    and (
                        not isinstance(metadata_url, str)
                        or not 1 <= len(metadata_url) <= 2048
                    )
                )
            ):
                raise MCPGatewayError("Delegated MCP scope challenge is invalid")
            try:
                required_scopes = normalize_scope_values(scopes)
            except ValueError as exc:
                raise MCPGatewayError(
                    "Delegated MCP scope challenge is invalid"
                ) from exc
            scope_error = MCPInsufficientScopeError(
                required_scopes=required_scopes,
                resource_metadata_url=metadata_url,
            )
            record_mcp_scope_challenge(
                db,
                server=server,
                activation=activation,
                investigation=investigation,
                error=scope_error,
            )
            raise MCPGatewayError(
                "MCP tool requires operator-approved OAuth scope step-up"
            ) from scope_error
        if resumed["status"] == "failed":
            error = MCPGatewayError(
                f"Delegated MCP execution failed: {str(resumed.get('error', 'unknown'))[:255]}"
            )
            _record_mcp_runtime_failure(db, activation.id, error)
            raise error
        if resumed["status"] == "outcome_unknown":
            if tool.read_only:
                raise MCPGatewayError("Read-only MCP invocation reported an invalid unknown-write result")
            error = MCPWriteOutcomeUnknown(
                "Delegated MCP write outcome is unknown after transport; independent provider reconciliation is required"
            )
            _record_mcp_runtime_failure(db, activation.id, error)
            raise error
        result = resumed.get("result")
        try:
            validate_instance(result, tool.output_schema, "MCP tool result")
        except ValueError as exc:
            _record_mcp_runtime_failure(db, activation.id, exc)
            raise
        _record_mcp_runtime_success(db, activation.id)
        result_hash = _canonical_hash(result)
        return result, [
            InvestigationEvidenceCreate(
                evidence_type="mcp_tool_result",
                evidence_id=f"{activation.id}:{result_hash}",
                summary=(
                    f"MCP tool {tool.name!r} returned a schema-validated "
                    f"structured result with SHA-256 {result_hash}."
                ),
                observed_at=utcnow(),
            )
        ]


class _ToolOperationState(TypedDict):
    input_hash: str
    request: dict[str, Any]
    graph_state: dict[str, Any]
    result: dict[str, Any] | None
    failure: dict[str, Any] | None


def _interrupt_document(result: dict[str, Any]) -> dict[str, Any] | None:
    values = result.get("__interrupt__")
    if not values:
        return None
    first = values[0]
    value = getattr(first, "value", None)
    return dict(value) if isinstance(value, dict) else None


def _snapshot_interrupt(snapshot: Any) -> dict[str, Any] | None:
    for task in snapshot.tasks:
        for item in getattr(task, "interrupts", ()):
            value = getattr(item, "value", None)
            if isinstance(value, dict):
                return dict(value)
    return None


def _resume_pending_interrupt(snapshot: Any, value: dict[str, Any]) -> Command:
    pending = [item for task in snapshot.tasks for item in getattr(task, "interrupts", ())]
    if len(pending) != 1 or not isinstance(getattr(pending[0], "id", None), str):
        raise ValueError("Tool operation does not have one exact pending interrupt")
    # Explicit task binding preserves repeated resumes within the same node;
    # an unkeyed global resume can collide with an older saved resume write.
    return Command(resume={pending[0].id: value})


def _pending_mcp_result_call(
    db: Session,
    pending: dict[str, Any] | None,
    *,
    execution: AgentExecution,
    worker: AgentWorker,
    resume_value: dict[str, Any] | None,
) -> InvestigationToolCall | None:
    """Fence an already-issued write, allowing only its original owner's result.

    An interrupted checkpoint is not another dispatch permission. Even an exact
    retry by the same owner without a result is ambiguous and cannot resend a
    write. Old unbound checkpoints fail closed and require reconciliation.
    """
    if pending is None or pending.get("kind") != "mcp_invocation":
        return None
    from .agent_approvals import ActionOutcomeUnknown

    if not isinstance(pending.get("read_only"), bool):
        raise ActionOutcomeUnknown("Unbound delegated invocation requires independent reconciliation")
    if pending["read_only"]:
        return None
    call_id = pending.get("tool_call_id")
    if not isinstance(call_id, str) or not 1 <= len(call_id) <= 36:
        raise ActionOutcomeUnknown("Delegated write has no bound Tool call; independent reconciliation required")
    call = db.get(InvestigationToolCall, call_id)
    tool = db.get(AgentToolRegistration, call.tool_id) if call is not None else None
    if (
        call is None or tool is None or tool.read_only
        or call.investigation_id != execution.investigation_id
        or call.arguments != pending.get("arguments")
        or pending.get("execution_id") != execution.id
    ):
        raise ActionOutcomeUnknown("Delegated write no longer matches its bound Tool call")
    if call.status in {"succeeded", "failed"}:
        # No adapter invocation is permitted: the executor will recover only
        # the already committed terminal result and independently check it.
        return call
    if (
        call.status != "running"
        or pending.get("worker_id") != worker.id
        or pending.get("execution_attempt") != execution.attempt_count
        or not isinstance(resume_value, dict)
        or resume_value.get("kind") != "mcp_result"
        or resume_value.get("invocation_id") != pending.get("invocation_id")
        or resume_value.get("status") not in {"succeeded", "failed", "scope_required", "outcome_unknown"}
    ):
        raise ActionOutcomeUnknown(
            "Delegated write outcome is unknown; redispatch or replacement-owner result blocked"
        )
    return call


def _receive_pending_oauth_observation(
    db: Session, pending: dict[str, Any] | None, *, execution: AgentExecution,
    worker: AgentWorker, resume_value: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Metadata cannot change custody of an already-issued write's result."""
    if not isinstance(resume_value, dict) or "oauth_observation" not in resume_value:
        return resume_value
    from pydantic import ValidationError
    from ..oauth_observation import OAuthCredentialObservation
    from .mcp_oauth_observations import accept_oauth_observation

    safe = dict(resume_value)
    document = safe.pop("oauth_observation")  # Never checkpoint unvalidated extras.
    if not isinstance(pending, dict) or (
        pending.get("kind") != "mcp_invocation"
        or pending.get("execution_id") != execution.id
        or pending.get("execution_attempt") != execution.attempt_count
        or pending.get("worker_id") != worker.id
        or safe.get("kind") != "mcp_result"
        or safe.get("invocation_id") != pending.get("invocation_id")
        or safe.get("status") not in {"succeeded", "failed", "scope_required", "outcome_unknown"}
        or execution.status != AgentExecutionStatus.RUNNING
        or execution.worker_id != worker.id
        or execution.lease_expires_at is None
        or execution.lease_expires_at.replace(tzinfo=execution.lease_expires_at.tzinfo or UTC) <= datetime.now(UTC)
    ):
        return safe
    try:
        observation = OAuthCredentialObservation.model_validate(document)
        grant = CredentialGrant.from_mapping(pending.get("credential_grant") or {})
    except (ValidationError, CredentialUnavailable, TypeError, AttributeError):
        return safe
    activation = db.get(MCPToolActivation, pending.get("activation_id"))
    call = db.get(InvestigationToolCall, pending.get("tool_call_id"))
    if (activation is None or call is None or call.status != "running"
        or call.investigation_id != execution.investigation_id
        or call.tool_id != activation.tool_registration_id
        or call.arguments != pending.get("arguments")
        or grant.deployment_id != activation.id or grant.expires_at <= datetime.now(UTC)):
        return safe
    server = db.get(MCPServer, activation.server_id)
    if server is not None and accept_oauth_observation(
        db, server, observation, source="agent", worker=worker,
        assignment_id=pending["invocation_id"], expected_generation=grant.oauth_generation,
        profile_id=grant.profile_id, profile_revision=grant.profile_revision,
    ):
        # This is a separate informational receipt, not a Tool result commit.
        # Release its row lock before independent LangGraph checkpoint I/O.
        db.commit()
        safe["oauth_observation"] = observation.model_dump(mode="json")
    return safe


def execute_runtime_tool(
    db: Session,
    execution_id: str,
    *,
    worker: AgentWorker,
    payload: AgentRuntimeToolRequest,
) -> AgentRuntimeToolRead:
    execution, investigation = _runtime_context(
        db,
        execution_id,
        worker=worker,
        lease_token=payload.lease_token,
        check_alert_stop=True,
    )
    state = _validate_graph_state(
        payload.state,
        investigation,
        require_persisted_counters=False,
    )
    request = GraphToolRequest.model_validate(payload.request)
    document = {
        "request": request.model_dump(mode="json"),
        "state": dict(state),
    }
    expected_operation_id = runtime_operation_id(
        "tool",
        execution_id,
        document,
    )
    if not secrets.compare_digest(payload.operation_id, expected_operation_id):
        raise ValueError("Tool operation ID does not match its input")
    input_hash = _canonical_document_hash(document)
    mcp_runtime = DelegatedMCPRuntime(
        worker=worker,
        execution=execution,
        allowed_hosts=get_settings().mcp_allowed_host_list,
    )
    executor = DatabaseToolExecutor(
        db,
        investigation,
        mcp_runtime=mcp_runtime,
        resume_interrupted_calls=True,
    )

    def tool_node(operation: _ToolOperationState) -> dict[str, Any]:
        graph_state = _validate_graph_state(
            operation["graph_state"],
            investigation,
            require_persisted_counters=False,
        )
        try:
            result = executor(
                GraphToolRequest.model_validate(operation["request"]),
                graph_state,
            )
        except GraphToolExecutionFailure as exc:
            return {"failure": {"error_type": (
                "OutcomeUnknown" if isinstance(exc, GraphToolOutcomeUnknown) else "ActionRejected"
            ),
                "tool_call_ids": exc.tool_call_ids, "evidence_ids": exc.evidence_ids}}
        return {"result": result.model_dump(mode="json")}

    builder = StateGraph(_ToolOperationState)
    builder.add_node("tool", tool_node)
    builder.add_edge(START, "tool")
    builder.add_edge("tool", END)
    config = {
        "configurable": {
            "thread_id": f"agent-runtime-tool:{execution_id}:{payload.operation_id}"
        }
    }
    with runtime_checkpointer(investigation) as saver:
        graph = builder.compile(checkpointer=saver)
        def invoke_owned(value):
            from .situation_closure import ClosureLeasePending
            try:
                return graph.invoke(value, config=config)
            except ClosureLeasePending as pending:
                # The nested Task remains nonterminal and its exact owned
                # journal stays running. No fake Tool failure or new token.
                db.rollback()
                return {"owned_closure_wait": pending.wait.model_dump(mode="json")}
        snapshot = graph.get_state(config)
        if snapshot.values:
            if snapshot.values.get("input_hash") != input_hash:
                raise ValueError("Tool operation replay input changed")
            interrupt_document = _snapshot_interrupt(snapshot)
            if snapshot.next or interrupt_document is not None:
                result_call = _pending_mcp_result_call(
                    db, interrupt_document, execution=execution, worker=worker,
                    resume_value=payload.resume_value,
                )
                payload = payload.model_copy(update={"resume_value": _receive_pending_oauth_observation(
                    db, interrupt_document, execution=execution, worker=worker,
                    resume_value=payload.resume_value,
                )})
                if result_call is not None:
                    if result_call.status == "running":
                        executor.running_result_call_id = result_call.id
                    else:
                        # Let the normal result/interrupt handling below consume
                        # any additional already-recorded MCP phase positions.
                        payload = payload.model_copy(update={"resume_value": {
                            "kind": "recorded_result_recovery",
                        }})
                if payload.resume_value is None:
                    if interrupt_document is None:
                        # The API may have died after a call/result commit but
                        # before the node output checkpoint. Recover the ledger
                        # through the normal executor, never reset the operation.
                        executor.recover_plain_checkpoint = True
                        result = invoke_owned(None)
                    else:
                        return AgentRuntimeToolRead(
                            protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
                            operation_id=payload.operation_id,
                            status="interrupted",
                            interrupt=interrupt_document,
                        )
                else:
                    result = invoke_owned(_resume_pending_interrupt(snapshot, payload.resume_value))
            else:
                result = snapshot.values
        else:
            if payload.resume_value is not None:
                raise ValueError("Cannot resume a Tool operation that has not started")
            result = invoke_owned(
                {
                    "input_hash": input_hash,
                    "request": request.model_dump(mode="json"),
                    "graph_state": dict(state),
                    "result": None,
                    "failure": None,
                },
            )
    if result.get("owned_closure_wait") is not None:
        return AgentRuntimeToolRead(protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
            operation_id=payload.operation_id, status="interrupted", interrupt=result["owned_closure_wait"])
    interrupt_document = _interrupt_document(result)
    if interrupt_document is not None:
        return AgentRuntimeToolRead(
            protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
            operation_id=payload.operation_id,
            status="interrupted",
            interrupt=interrupt_document,
        )
    if result.get("failure") is not None:
        return AgentRuntimeToolRead(protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
            operation_id=payload.operation_id, status="failed", failure=result["failure"])
    tool_result = GraphToolResult.model_validate(result.get("result"))
    from .source_replacement_runtime import assert_replacement_graph_result
    assert_replacement_graph_result(db, investigation, request, tool_result)
    from .situation_closure_runtime import assert_closure_graph_result
    assert_closure_graph_result(db, investigation, request, tool_result)
    return AgentRuntimeToolRead(
        protocol_version=AGENT_RUNTIME_PROTOCOL_VERSION,
        operation_id=payload.operation_id,
        status="completed",
        result=tool_result.model_dump(mode="json"),
    )
