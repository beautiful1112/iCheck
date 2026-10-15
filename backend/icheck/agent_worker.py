from __future__ import annotations

import argparse
import logging
import os
import socket
import time
from typing import Any
from urllib.error import URLError

from .agent_runtime_protocol import (
    HTTPCheckpointSaver,
    RemoteReasoner,
    RemoteToolExecutor,
    SynchronizedControlPlaneClient,
    validate_bootstrap,
)
from .agent_schemas import AgentExecutionAssignment, AgentExecutionComplete
from .collector_worker import (
    ControlPlaneClient,
    ControlPlaneHTTPError,
    _read_private_file,
    build_credential_broker,
)
from .config import get_settings
from .langgraph_runtime import (
    InvestigationGraphState,
    build_investigation_graph,
    invoke_investigation_graph,
    resume_investigation_graph,
)
from .worker_namespace import (
    add_worker_namespace_arguments,
    parse_worker_namespace,
)


LOGGER = logging.getLogger("icheck.agent_worker")


class ExecutionCancellationRequested(RuntimeError):
    pass


class RemoteLeasedCheckpointHook:
    """Renew ownership and publish the complete bounded graph state over HTTPS."""

    def __init__(
        self,
        client: ControlPlaneClient,
        assignment: AgentExecutionAssignment,
        *,
        lease_seconds: int,
    ) -> None:
        self.client = client
        self.assignment = assignment
        self.lease_seconds = lease_seconds

    def renew_lease(self) -> None:
        execution = self.client.request(
            "POST",
            (
                f"/api/v1/agent/executions/"
                f"{self.assignment.execution_id}/lease"
            ),
            {
                "lease_token": self.assignment.lease_token,
                "lease_seconds": self.lease_seconds,
            },
        )
        if execution["cancellation_requested_at"] is not None:
            raise ExecutionCancellationRequested(
                "Agent execution cancellation was requested"
            )

    def __call__(self, node: str, state: InvestigationGraphState) -> None:
        self.renew_lease()
        event = self.client.request(
            "POST",
            (
                f"/api/v1/agent/executions/"
                f"{self.assignment.execution_id}/progress"
            ),
            {
                "lease_token": self.assignment.lease_token,
                "node": node,
                "status": state["status"],
                "iteration": state["iteration"],
                "tokens_used": state["tokens_used"],
                "tool_calls_used": state["tool_calls_used"],
                "evidence_count": len(state["evidence_ids"]),
                "state": dict(state),
            },
        )
        LOGGER.debug(
            "execution=%s event=%s sequence=%s",
            self.assignment.execution_id,
            event["event_type"],
            event["sequence"],
        )


def execute_remote_assignment(
    client: ControlPlaneClient,
    assignment: AgentExecutionAssignment,
    *,
    lease_seconds: int,
    credential_broker: Any,
    mcp_allowed_hosts: list[str],
) -> Any:
    runtime_client = SynchronizedControlPlaneClient(client)
    bootstrap = validate_bootstrap(
        runtime_client.request(
            "POST",
            (
                f"/api/v1/agent/executions/{assignment.execution_id}"
                "/runtime/bootstrap"
            ),
            {
                "protocol_version": "icheck.agent-runtime/v1",
                "lease_token": assignment.lease_token,
            },
        )
    )
    if (
        bootstrap.execution_id != assignment.execution_id
        or bootstrap.investigation_id != assignment.investigation_id
    ):
        raise RuntimeError("Control plane returned a mismatched runtime bootstrap")
    initial_state = InvestigationGraphState(**bootstrap.initial_state)
    checkpointer = HTTPCheckpointSaver(
        runtime_client,
        assignment.execution_id,
        assignment.lease_token,
    )
    lease_hook = RemoteLeasedCheckpointHook(runtime_client, assignment, lease_seconds=lease_seconds)
    graph = build_investigation_graph(
        reasoner=RemoteReasoner(
            runtime_client,
            assignment.execution_id,
            assignment.lease_token,
            reasoning_deadline=bootstrap.reasoning_deadline,
            before_call=lease_hook.renew_lease,
        ),
        tool_executor=RemoteToolExecutor(
            runtime_client,
            assignment.execution_id,
            assignment.lease_token,
            credential_broker=credential_broker,
            mcp_allowed_hosts=mcp_allowed_hosts,
            wait_heartbeat=lease_hook.renew_lease,
        ),
        checkpointer=checkpointer,
        checkpoint_hook=lease_hook,
    )

    def finish(payload: AgentExecutionComplete) -> Any:
        path = f"/api/v1/agent/executions/{assignment.execution_id}/complete"
        document = payload.model_dump(mode="json")
        for attempt in range(3):
            try:
                return runtime_client.request("POST", path, document)
            except (
                URLError, TimeoutError, ConnectionError, ControlPlaneHTTPError,
            ) as exc:
                if attempt == 2 or (
                    isinstance(exc, ControlPlaneHTTPError)
                    and exc.status_code < 500
                ):
                    raise
                LOGGER.warning(
                    "Agent execution %s completion response unavailable (%s); "
                    "retrying the same request",
                    assignment.execution_id,
                    type(exc).__name__,
                )
                time.sleep(0.2 * (2 ** attempt))
        raise AssertionError("Unreachable completion retry state")

    try:
        if bootstrap.resume_required:
            result = resume_investigation_graph(
                graph,
                investigation_id=bootstrap.investigation_id,
                max_iterations=initial_state["max_iterations"],
                resume_value=bootstrap.resume_value,
            )
        else:
            if assignment.resume_required:
                raise RuntimeError(
                    "Assignment requires resume but no runtime checkpoint exists"
                )
            result = invoke_investigation_graph(graph, initial_state)
    except ExecutionCancellationRequested:
        return finish(
            AgentExecutionComplete(
                lease_token=assignment.lease_token,
                status="cancelled",
            )
        )
    except Exception as exc:
        LOGGER.exception("Agent execution %s failed", assignment.execution_id)
        return finish(
            AgentExecutionComplete(
                lease_token=assignment.lease_token,
                status="failed",
                error=f"Agent worker failed: {type(exc).__name__}",
            )
        )

    graph_status = result["status"]
    if graph_status == "completed":
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="succeeded",
        )
    elif graph_status == "waiting_approval" or result.get("__interrupt__"):
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="waiting_approval",
        )
    else:
        completion = AgentExecutionComplete(
            lease_token=assignment.lease_token,
            status="failed",
            error="Investigation did not complete; inspect its checkpoint trace",
        )
    return finish(completion)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an iCheck agent worker")
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--control-plane",
        default=os.getenv("ICHECK_CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--allow-insecure-control-plane",
        action="store_true",
        default=os.getenv(
            "ICHECK_AGENT_ALLOW_INSECURE_CONTROL_PLANE", ""
        ).lower()
        in {"1", "true", "yes"},
        help="Allow remote HTTP control plane (isolated test labs only)",
    )
    parser.add_argument(
        "--control-plane-tls-ca-file",
        default=os.getenv("ICHECK_WORKER_TLS_CA_FILE"),
    )
    parser.add_argument(
        "--control-plane-tls-cert-file",
        default=os.getenv("ICHECK_WORKER_TLS_CERT_FILE"),
    )
    parser.add_argument(
        "--control-plane-tls-key-file",
        default=os.getenv("ICHECK_WORKER_TLS_KEY_FILE"),
    )
    parser.add_argument(
        "--control-plane-tls-key-password-file",
        default=os.getenv("ICHECK_WORKER_TLS_KEY_PASSWORD_FILE"),
    )
    parser.add_argument(
        "--registration-token-file",
        default=os.getenv("ICHECK_AGENT_REGISTRATION_TOKEN_FILE"),
    )
    parser.add_argument(
        "--name",
        default=os.environ.get("ICHECK_AGENT_WORKER_NAME", socket.gethostname()),
    )
    parser.add_argument(
        "--capabilities",
        default=os.environ.get(
            "ICHECK_AGENT_WORKER_CAPABILITIES",
            "openai_compatible,anthropic,mcp",
        ),
        help="Comma-separated provider and Tool transport capabilities",
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.environ.get("ICHECK_AGENT_WORKER_LEASE_SECONDS", "300")),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ICHECK_AGENT_WORKER_POLL_SECONDS", "2")),
    )
    parser.add_argument(
        "--allow-environment-credentials",
        action="store_true",
        default=os.getenv("ICHECK_CREDENTIAL_ALLOW_ENVIRONMENT", "").lower()
        in {"1", "true", "yes"},
    )
    parser.add_argument(
        "--vault-address",
        default=os.getenv("ICHECK_CREDENTIAL_VAULT_ADDR"),
    )
    parser.add_argument(
        "--vault-token-file",
        default=os.getenv("ICHECK_CREDENTIAL_VAULT_TOKEN_FILE"),
    )
    parser.add_argument(
        "--vault-namespace",
        default=os.getenv("ICHECK_CREDENTIAL_VAULT_NAMESPACE"),
    )
    parser.add_argument(
        "--vault-timeout-seconds",
        type=int,
        default=int(os.getenv("ICHECK_CREDENTIAL_VAULT_TIMEOUT_SECONDS", "5")),
    )
    parser.add_argument(
        "--mcp-oauth-allowed-host",
        action="append",
        dest="mcp_oauth_allowed_hosts",
        default=None,
        help="Exact hostname or *.suffix allowed for MCP OAuth token refresh",
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> list[str]:
    if not args.name:
        parser.error("--name or ICHECK_AGENT_WORKER_NAME is required")
    if args.lease_seconds < 15 or args.lease_seconds > 3600:
        parser.error("--lease-seconds must be between 15 and 3600")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")
    capabilities = [
        item.strip() for item in args.capabilities.split(",") if item.strip()
    ]
    if not capabilities:
        parser.error("at least one worker capability is required")
    return capabilities


def load_agent_registration_token(token_file: str | None) -> str:
    if token_file:
        if not os.path.isabs(token_file):
            raise SystemExit("Agent registration token file path must be absolute")
        try:
            token = _read_private_file(
                token_file,
                label="agent registration token file",
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        token = os.getenv("ICHECK_AGENT_REGISTRATION_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "Set ICHECK_AGENT_REGISTRATION_TOKEN_FILE or "
            "ICHECK_AGENT_REGISTRATION_TOKEN"
        )
    return token


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _parser()
    args = parser.parse_args()
    capabilities = _validate_args(parser, args)
    namespace = parse_worker_namespace(parser, args)
    credential_broker = build_credential_broker(args)
    settings = get_settings()

    client = ControlPlaneClient(
        args.control_plane,
        allow_insecure=args.allow_insecure_control_plane,
        tenant_id=namespace.tenant_id,
        region_id=namespace.region_id,
        tls_ca_file=args.control_plane_tls_ca_file,
        tls_cert_file=args.control_plane_tls_cert_file,
        tls_key_file=args.control_plane_tls_key_file,
        tls_key_password_file=args.control_plane_tls_key_password_file,
        user_agent="iCheck-agent-worker/0.5",
    )
    registration = client.request(
        "POST",
        "/api/v1/agent/workers/register",
        {
            "name": args.name,
            "capabilities": capabilities,
            "labels": {
                "runtime": "systemd",
                "control_transport": "http_api",
                "execution_protocol": "icheck.agent-runtime/v1",
                "execution_store": "control_plane",
            },
        },
        extra_headers={
            "X-iCheck-Registration-Token": load_agent_registration_token(
                args.registration_token_file
            )
        },
    )
    client.access_token = registration["access_token"]
    worker_id = registration["worker"]["id"]

    while True:
        heartbeat = client.request(
            "POST",
            f"/api/v1/agent/workers/{worker_id}/heartbeat",
            {"state": "online"},
        )
        if heartbeat["state"] == "draining":
            LOGGER.info("worker=%s drain complete; exiting", worker_id)
            return 0
        assignment_documents = client.request(
            "POST",
            f"/api/v1/agent/workers/{worker_id}/executions/claim",
            {"max_assignments": 1, "lease_seconds": args.lease_seconds},
        )
        assignments = [
            AgentExecutionAssignment.model_validate(item)
            for item in assignment_documents
        ]
        for assignment in assignments:
            execute_remote_assignment(
                client,
                assignment,
                lease_seconds=args.lease_seconds,
                credential_broker=credential_broker,
                mcp_allowed_hosts=settings.mcp_allowed_host_list,
            )
        if args.once:
            return 0
        if not assignments:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
