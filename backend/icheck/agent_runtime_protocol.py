from __future__ import annotations

import base64
import hashlib
import json
import random
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from http.client import IncompleteRead
from typing import Any
from urllib.error import URLError

from langgraph.checkpoint.base import BaseCheckpointSaver, CheckpointTuple
from langgraph.types import interrupt

from .agent_schemas import (
    AgentRuntimeBootstrapRead,
    AgentRuntimeCheckpointPutRead,
    AgentRuntimeCheckpointTupleRead,
    AgentRuntimeReasonRead,
    AgentRuntimeToolRead,
    AgentRuntimeOwnedClosureWait,
    AgentRuntimeWireValue,
)
from .credentials import (
    CredentialBroker,
    CredentialContext,
    CredentialGrant,
    DisabledCredentialBroker,
    OAuthCredentialUnavailable,
    SecretRedactor,
)
from .collector_worker import ControlPlaneHTTPError
from .langgraph_runtime import (
    GraphDecision,
    GraphToolRequest,
    GraphToolExecutionFailure,
    GraphToolOutcomeUnknown,
    GraphToolResult,
    InvestigationGraphState,
    Reasoner,
    ToolExecutor,
)
from .services.collectors import validate_instance
from .services.mcp_gateway import MCPHTTPClient, validate_mcp_endpoint
from .services.mcp_scope_challenges import MCPInsufficientScopeError


AGENT_RUNTIME_PROTOCOL_VERSION = "icheck.agent-runtime/v1"
MAX_RUNTIME_WIRE_BYTES = 10_000_000
MAX_REMOTE_TOOL_INTERRUPTS = 32
MAX_OWNED_CLOSURE_WAIT_SECONDS = 35
MAX_TOOL_TRANSPORT_RETRIES = 2


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def runtime_operation_id(
    operation: str,
    execution_id: str,
    document: dict[str, Any],
) -> str:
    return _canonical_hash(
        {
            "protocol_version": AGENT_RUNTIME_PROTOCOL_VERSION,
            "operation": operation,
            "execution_id": execution_id,
            "document": document,
        }
    )


class SynchronizedControlPlaneClient:
    """Serialize one graph execution's synchronous HTTP operations.

    LangGraph may persist checkpoints from executor threads while scheduling
    the next node. urllib openers and test transports are not guaranteed to be
    safe for overlapping calls, and ordered RPC also makes lease/progress
    behavior deterministic.
    """

    def __init__(self, client: Any) -> None:
        self.client = client
        self._lock = threading.RLock()

    def request(self, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return self.client.request(*args, **kwargs)


def encode_wire_value(serde: Any, value: Any) -> AgentRuntimeWireValue:
    value_type, encoded = serde.dumps_typed(value)
    if not isinstance(value_type, str) or not value_type:
        raise ValueError("Runtime serializer returned an invalid type")
    if len(encoded) > MAX_RUNTIME_WIRE_BYTES:
        raise ValueError("Runtime checkpoint value exceeds 10000000 bytes")
    return AgentRuntimeWireValue(
        type=value_type,
        data_base64=base64.b64encode(encoded).decode("ascii"),
    )


def decode_wire_value(serde: Any, value: AgentRuntimeWireValue) -> Any:
    try:
        encoded = base64.b64decode(value.data_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Runtime checkpoint value is not valid base64") from exc
    if len(encoded) > MAX_RUNTIME_WIRE_BYTES:
        raise ValueError("Runtime checkpoint value exceeds 10000000 bytes")
    return serde.loads_typed((value.type, encoded))


class HTTPCheckpointSaver(BaseCheckpointSaver[str]):
    """Lease-bound LangGraph saver backed by the control-plane checkpoint RPC."""

    def __init__(
        self,
        client: Any,
        execution_id: str,
        lease_token: str,
    ) -> None:
        super().__init__()
        self.client = client
        self.execution_id = execution_id
        self.lease_token = lease_token
        self.path = (
            f"/api/v1/agent/executions/{execution_id}/runtime/checkpoints"
        )

    def _base(self) -> dict[str, Any]:
        return {
            "protocol_version": AGENT_RUNTIME_PROTOCOL_VERSION,
            "lease_token": self.lease_token,
        }

    @staticmethod
    def _wire_config(config: dict[str, Any]) -> dict[str, Any]:
        configurable = config.get("configurable")
        if configurable is None:
            configurable = {}
        allowed = {"thread_id", "checkpoint_ns", "checkpoint_id"}
        return {
            "configurable": {
                key: value
                for key, value in dict(configurable).items()
                if key in allowed
            }
        }

    def _decode_tuple(self, document: dict[str, Any]) -> CheckpointTuple:
        item = AgentRuntimeCheckpointTupleRead.model_validate(document)
        pending = [
            (
                write.task_id,
                write.channel,
                decode_wire_value(self.serde, write.value),
            )
            for write in item.pending_writes
        ]
        return CheckpointTuple(
            config=item.config,
            checkpoint=decode_wire_value(self.serde, item.checkpoint),
            metadata=decode_wire_value(self.serde, item.metadata),
            parent_config=item.parent_config,
            pending_writes=pending,
        )

    def get_tuple(self, config: dict[str, Any]) -> CheckpointTuple | None:
        response = self.client.request(
            "POST",
            f"{self.path}/get",
            {**self._base(), "config": self._wire_config(config)},
        )
        return self._decode_tuple(response) if response is not None else None

    def list(
        self,
        config: dict[str, Any] | None,
        *,
        filter: dict[str, Any] | None = None,
        before: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        bounded_limit = 20 if limit is None else max(1, min(limit, 100))
        response = self.client.request(
            "POST",
            f"{self.path}/list",
            {
                **self._base(),
                "config": (
                    self._wire_config(config) if config is not None else None
                ),
                "filter": filter,
                "before": (
                    self._wire_config(before) if before is not None else None
                ),
                "limit": bounded_limit,
            },
        )
        for item in response or []:
            yield self._decode_tuple(item)

    def put(
        self,
        config: dict[str, Any],
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        response = self.client.request(
            "POST",
            f"{self.path}/put",
            {
                **self._base(),
                "config": self._wire_config(config),
                "checkpoint": encode_wire_value(
                    self.serde,
                    checkpoint,
                ).model_dump(mode="json"),
                "metadata": encode_wire_value(
                    self.serde,
                    metadata,
                ).model_dump(mode="json"),
                "new_versions": encode_wire_value(
                    self.serde,
                    new_versions,
                ).model_dump(mode="json"),
            },
        )
        return AgentRuntimeCheckpointPutRead.model_validate(response).config

    def put_writes(
        self,
        config: dict[str, Any],
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self.client.request(
            "POST",
            f"{self.path}/writes",
            {
                **self._base(),
                "config": self._wire_config(config),
                "writes": [
                    [
                        channel,
                        encode_wire_value(
                            self.serde,
                            value,
                        ).model_dump(mode="json"),
                    ]
                    for channel, value in writes
                ],
                "task_id": task_id,
                "task_path": task_path,
            },
        )

    def delete_thread(self, thread_id: str) -> None:
        raise PermissionError(
            "Remote Agent checkpoints are immutable through the Worker protocol"
        )

    def get_next_version(self, current: str | None, channel: None) -> str:
        if current is None:
            current_version = 0
        elif isinstance(current, int):
            current_version = current
        else:
            current_version = int(current.split(".")[0])
        return f"{current_version + 1:032}.{random.random():016}"


class RemoteReasoner(Reasoner):
    def __init__(
        self,
        client: Any,
        execution_id: str,
        lease_token: str,
        *,
        reasoning_deadline: datetime | None = None,
        before_call: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self.execution_id = execution_id
        self.lease_token = lease_token
        self.reasoning_deadline = reasoning_deadline
        self.before_call = before_call

    def __call__(self, state: InvestigationGraphState) -> GraphDecision:
        document = {"state": dict(state)}
        operation_id = runtime_operation_id(
            "reason",
            self.execution_id,
            document,
        )
        timeout_options = {}
        if self.reasoning_deadline is not None:
            remaining = (self.reasoning_deadline - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                return GraphDecision(action="escalate", escalation_reason="Investigation reasoning deadline exhausted")
            timeout_options = {"timeout_seconds": min(3605, remaining + 5), "allow_extended_timeout": True}
        if self.before_call is not None:
            self.before_call()
        try:
            response = self.client.request(
                "POST",
                (
                    f"/api/v1/agent/executions/{self.execution_id}"
                    "/runtime/reason"
                ),
                {
                    "protocol_version": AGENT_RUNTIME_PROTOCOL_VERSION,
                    "lease_token": self.lease_token,
                    "operation_id": operation_id,
                    **document,
                },
                **timeout_options,
            )
        except (TimeoutError, URLError) as exc:
            from .ai_failure_diagnostics import timeout_diagnostic, diagnostic_text
            if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
                value = timeout_diagnostic(worker=True, timeout_seconds=timeout_options.get("timeout_seconds", 30))
                return GraphDecision(action="escalate", escalation_reason=diagnostic_text(value))
            raise
        result = AgentRuntimeReasonRead.model_validate(response)
        if result.operation_id != operation_id:
            raise RuntimeError("Control plane returned a mismatched reason operation")
        return GraphDecision.model_validate(result.decision)


class RemoteToolExecutor(ToolExecutor):
    def __init__(
        self,
        client: Any,
        execution_id: str,
        lease_token: str,
        *,
        credential_broker: CredentialBroker | None = None,
        mcp_allowed_hosts: list[str] | None = None,
        wait_heartbeat: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self.execution_id = execution_id
        self.lease_token = lease_token
        self.credential_broker = credential_broker or DisabledCredentialBroker()
        self.mcp_allowed_hosts = list(mcp_allowed_hosts or [])
        self.wait_heartbeat = wait_heartbeat

    def _run_mcp(self, payload: dict[str, Any]) -> dict[str, Any]:
        invocation_id = payload.get("invocation_id")
        endpoint = payload.get("endpoint")
        tool_name = payload.get("mcp_tool_name")
        arguments = payload.get("arguments")
        output_schema = payload.get("output_schema")
        read_only = payload.get("read_only")
        tool_call_id = payload.get("tool_call_id")
        metadata = payload.get("metadata")
        if (
            not isinstance(invocation_id, str)
            or len(invocation_id) != 64
            or not isinstance(endpoint, str)
            or not isinstance(tool_name, str)
            or not isinstance(arguments, dict)
            or not isinstance(output_schema, dict)
            or not isinstance(read_only, bool)
            or not isinstance(tool_call_id, str)
            or not 1 <= len(tool_call_id) <= 36
            or not isinstance(metadata, dict)
            or metadata.get("icheck/toolCallId") != tool_call_id
        ):
            raise ValueError("Control plane returned an invalid MCP invocation")
        endpoint = validate_mcp_endpoint(endpoint, self.mcp_allowed_hosts)
        credentials: dict[str, str] = {}
        resolved = None
        observation = None

        def report(document: dict[str, Any]) -> dict[str, Any]:
            if observation is not None:
                document["oauth_observation"] = observation.model_dump(mode="json")
            return document

        client: MCPHTTPClient | None = None
        redactor = SecretRedactor()
        try:
            grant_document = payload.get("credential_grant")
            if grant_document is not None:
                grant = CredentialGrant.from_mapping(grant_document)
                resolved = self.credential_broker.resolve(
                    grant,
                    CredentialContext(
                        worker_id=str(payload.get("worker_id", "")),
                        deployment_id=str(payload.get("activation_id", "")),
                        adapter_type=grant.adapter_type,
                    ),
                )
                credentials = dict(resolved.values)
                observation = resolved.oauth_observation
                redactor.add_mapping(credentials)
                if (
                    resolved.renewable
                    and (resolved.expires_at - datetime.now(UTC)).total_seconds()
                    < 60
                ):
                    resolved.renew(
                        min(
                            300,
                            max(
                                15,
                                int(
                                    (
                                        grant.expires_at
                                        - datetime.now(UTC)
                                    ).total_seconds()
                                ),
                            ),
                        )
                    )
            client = MCPHTTPClient(
                endpoint,
                timeout_seconds=int(payload.get("timeout_seconds", 30)),
                max_response_bytes=int(
                    payload.get("max_response_bytes", 1_000_000)
                ),
                credentials=credentials,
            )
            result = client.call_tool(
                tool_name,
                arguments,
                metadata=metadata,
            )
            validate_instance(result, output_schema, "MCP tool result")
            return report({
                "kind": "mcp_result",
                "invocation_id": invocation_id,
                "status": "succeeded",
                "result": result,
            })
        except MCPInsufficientScopeError as exc:
            if client is not None and client.request_dispatched and not read_only:
                return report({"kind": "mcp_result", "invocation_id": invocation_id,
                    "status": "outcome_unknown"})
            return report({
                "kind": "mcp_result",
                "invocation_id": invocation_id,
                "status": "scope_required",
                "required_scopes": list(exc.required_scopes),
                "resource_metadata_url": exc.resource_metadata_url,
            })
        except Exception as exc:
            if isinstance(exc, OAuthCredentialUnavailable):
                observation = exc.oauth_observation
            if client is not None and client.request_dispatched and not read_only:
                return report({"kind": "mcp_result", "invocation_id": invocation_id,
                    "status": "outcome_unknown"})
            return report({
                "kind": "mcp_result",
                "invocation_id": invocation_id,
                "status": "failed",
                "error": redactor.redact_text(type(exc).__name__)[:255],
            })
        finally:
            if resolved is not None:
                resolved.close()

    def __call__(
        self,
        request: GraphToolRequest,
        state: InvestigationGraphState,
    ) -> GraphToolResult:
        request_document = request.model_dump(mode="json")
        operation_document = {
            "request": request_document,
            "state": dict(state),
        }
        operation_id = runtime_operation_id(
            "tool",
            self.execution_id,
            operation_document,
        )
        resume_value: dict[str, Any] | None = None
        wait_started: float | None = None
        owned_wait: AgentRuntimeOwnedClosureWait | None = None
        transport_failures = 0
        for _ in range(MAX_REMOTE_TOOL_INTERRUPTS):
            if wait_started is not None and time.monotonic() - wait_started >= MAX_OWNED_CLOSURE_WAIT_SECONDS:
                raise RuntimeError("Owned closure wait exceeded its recovery budget")
            try:
                response = self.client.request(
                    "POST",
                    (
                        f"/api/v1/agent/executions/{self.execution_id}"
                        "/runtime/tool"
                    ),
                    {
                        "protocol_version": AGENT_RUNTIME_PROTOCOL_VERSION,
                        "lease_token": self.lease_token,
                        "operation_id": operation_id,
                        **operation_document,
                        "resume_value": resume_value,
                    },
                )
            except (URLError, TimeoutError, ConnectionError, IncompleteRead, ControlPlaneHTTPError) as exc:
                if (self.wait_heartbeat is None or transport_failures >= MAX_TOOL_TRANSPORT_RETRIES or
                    isinstance(exc, ControlPlaneHTTPError) and exc.status_code not in {502, 503, 504}):
                    raise
                # Only this durably keyed Tool RPC is replayed. Preserve a
                # recorded MCP resume verbatim; never call the adapter again.
                # Authority/cancellation is checked before either retry.
                self.wait_heartbeat()
                time.sleep(0.2 * (2 ** transport_failures))
                transport_failures += 1
                continue
            result = AgentRuntimeToolRead.model_validate(response)
            if result.operation_id != operation_id:
                raise RuntimeError(
                    "Control plane returned a mismatched Tool operation"
                )
            if result.status == "completed":
                completed = GraphToolResult.model_validate(result.result)
                if owned_wait is not None and completed.call_id != str(owned_wait.tool_call_id):
                    raise ValueError("Owned closure result changed its retained Tool identity")
                return completed
            if result.status == "failed":
                assert result.failure is not None
                failure = (
                    GraphToolOutcomeUnknown if result.failure.error_type == "OutcomeUnknown"
                    else GraphToolExecutionFailure
                )
                raise failure(tool_call_ids=result.failure.tool_call_ids,
                    evidence_ids=result.failure.evidence_ids)
            payload = dict(result.interrupt or {})
            kind = payload.get("kind")
            if owned_wait is not None and kind != "owned_closure_wait":
                raise ValueError("Owned closure recovery cannot switch to another interruption")
            if kind == "mcp_invocation":
                resume_value = self._run_mcp(payload)
            elif kind == "recorded_mcp_result":
                call_id = payload.get("tool_call_id")
                if not isinstance(call_id, str) or not 1 <= len(call_id) <= 36:
                    raise ValueError("Recorded MCP acknowledgment is invalid")
                resume_value = {"kind": "recorded_mcp_ack", "tool_call_id": call_id}
            elif kind == "action_approval":
                approved = interrupt(payload)
                if not isinstance(approved, dict):
                    raise ValueError("Action approval resume value is invalid")
                resume_value = approved
            elif kind == "owned_closure_wait":
                pending = AgentRuntimeOwnedClosureWait.model_validate(payload)
                if resume_value is not None or self.wait_heartbeat is None:
                    raise ValueError("Owned closure wait requires a lease-renewing current Worker")
                if owned_wait is not None and (
                    (pending.tool_call_id, pending.request_id) != (owned_wait.tool_call_id, owned_wait.request_id)
                    or pending.epoch < owned_wait.epoch
                    or (pending.epoch == owned_wait.epoch and pending.attempt_id != owned_wait.attempt_id)
                    or (pending.epoch > owned_wait.epoch and pending.attempt_id == owned_wait.attempt_id)
                ):
                    raise ValueError("Owned closure wait changed its retained lease identity")
                owned_wait = pending
                if wait_started is None:
                    wait_started = time.monotonic()
                if time.monotonic() - wait_started >= MAX_OWNED_CLOSURE_WAIT_SECONDS:
                    raise RuntimeError("Owned closure wait exceeded its recovery budget")
                # Renew/cancel before waiting outside every DB transaction.
                # Retry the same operation with no client-supplied lease token,
                # resume value, fresh intent or extra Tool accounting.
                self.wait_heartbeat()
                time.sleep(payload["retry_after_seconds"])
            else:
                raise ValueError("Control plane requested an unsupported interruption")
        raise RuntimeError("Remote Tool operation exceeded its interruption budget")


def validate_bootstrap(document: Any) -> AgentRuntimeBootstrapRead:
    return AgentRuntimeBootstrapRead.model_validate(document)
