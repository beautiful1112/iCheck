from __future__ import annotations

import argparse
import hashlib
import logging
import os
import socket
import time
from typing import Any

from .collector_worker import (
    ControlPlaneClient,
    _read_private_file,
    build_credential_broker,
)
from .credentials import (
    CredentialContext,
    CredentialGrant,
    CredentialUnavailable,
)
from .mcp_schemas import (
    MCP_PROTOCOL_VERSION,
    MCPToolAttestationAssignment,
    MCPToolAttestationComplete,
)
from .schema_validation import validate_schema
from .services.mcp_gateway import (
    MCPGatewayError,
    MCPHTTPClient,
    _canonical_hash,
    validate_mcp_endpoint,
)
from .worker_namespace import add_worker_namespace_arguments, parse_worker_namespace


LOGGER = logging.getLogger("icheck.mcp_attestor_worker")


def load_attestor_registration_token(token_file: str | None) -> str:
    if token_file:
        if not os.path.isabs(token_file):
            raise SystemExit("MCP attestor registration token file must be absolute")
        try:
            token = _read_private_file(
                token_file,
                label="MCP attestor registration token file",
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        token = os.getenv("ICHECK_MCP_ATTESTOR_REGISTRATION_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "Set ICHECK_MCP_ATTESTOR_REGISTRATION_TOKEN_FILE or "
            "ICHECK_MCP_ATTESTOR_REGISTRATION_TOKEN"
        )
    return token


def _failure(
    assignment: MCPToolAttestationAssignment,
    *,
    code: str,
    error: Exception,
    retryable: bool,
) -> MCPToolAttestationComplete:
    digest = hashlib.sha256(
        f"{type(error).__name__}:{error}".encode("utf-8")
    ).hexdigest()
    return MCPToolAttestationComplete(
        lease_token=assignment.lease_token,
        status="failed",
        checked_at=_utcnow(),
        failure_code=code,
        failure_sha256=digest,
        retryable=retryable,
    )


def _utcnow():
    from datetime import UTC, datetime

    return datetime.now(UTC)


def attest_assignment(
    assignment: MCPToolAttestationAssignment,
    *,
    credential_broker: Any,
    allowed_hosts: list[str],
    opener: Any | None = None,
) -> MCPToolAttestationComplete:
    observation = None

    def failure(*args, **kwargs):
        error = kwargs.get("error")
        value = _failure(*args, **kwargs)
        return value.model_copy(update={"oauth_observation": observation or getattr(error, "oauth_observation", None)})

    try:
        endpoint = validate_mcp_endpoint(assignment.endpoint_url, allowed_hosts)
    except ValueError as exc:
        return failure(
            assignment,
            code="endpoint_rejected",
            error=exc,
            retryable=False,
        )
    resolved = None
    credentials: dict[str, str] = {}
    try:
        if assignment.credential_grant is not None:
            grant = CredentialGrant.from_mapping(
                assignment.credential_grant.model_dump(mode="json")
            )
            resolved = credential_broker.resolve(
                grant,
                CredentialContext(
                    worker_id=assignment.worker_id,
                    deployment_id=assignment.attestation_id,
                    adapter_type=grant.adapter_type,
                ),
            )
            credentials = dict(resolved.values)
            observation = resolved.oauth_observation
    except CredentialUnavailable as exc:
        return failure(
            assignment,
            code="credential_unavailable",
            error=exc,
            retryable=True,
        )
    try:
        try:
            tools = MCPHTTPClient(
                endpoint,
                timeout_seconds=20,
                max_response_bytes=2_000_000,
                credentials=credentials,
                opener=opener,
            ).list_tools()
        except MCPGatewayError as exc:
            return failure(
                assignment,
                code="transport_error",
                error=exc,
                retryable=True,
            )
        names = [item.get("name") for item in tools]
        if (
            any(not isinstance(name, str) or not name for name in names)
            or len(names) != len(set(names))
        ):
            return failure(
                assignment,
                code="protocol_error",
                error=ValueError("MCP tools/list advertised invalid or duplicate names"),
                retryable=False,
            )
        advertised = [
            item for item in tools
            if item.get("name") == assignment.mcp_tool_name
        ]
        if len(advertised) != 1:
            return failure(
                assignment,
                code="contract_mismatch",
                error=ValueError(
                    "MCP tools/list did not advertise exactly one matching tool"
                ),
                retryable=False,
            )
        remote = advertised[0]
        remote_input = remote.get("inputSchema")
        remote_output = remote.get("outputSchema")
        if not isinstance(remote_input, dict) or not isinstance(remote_output, dict):
            return failure(
                assignment,
                code="contract_mismatch",
                error=ValueError(
                    "MCP tool did not advertise object input/output schemas"
                ),
                retryable=False,
            )
        try:
            validate_schema(remote_input, "MCP advertised inputSchema")
            validate_schema(remote_output, "MCP advertised outputSchema")
        except ValueError as exc:
            return failure(
                assignment,
                code="contract_mismatch",
                error=exc,
                retryable=False,
            )
        if (
            remote_input != assignment.expected_input_schema
            or remote_output != assignment.expected_output_schema
        ):
            return failure(
                assignment,
                code="contract_mismatch",
                error=ValueError(
                    "MCP advertised schemas do not exactly match the published contract"
                ),
                retryable=False,
            )
        input_hash = _canonical_hash(remote_input)
        output_hash = _canonical_hash(remote_output)
        if (
            input_hash != assignment.expected_input_schema_sha256
            or output_hash != assignment.expected_output_schema_sha256
        ):
            return failure(
                assignment,
                code="contract_mismatch",
                error=ValueError("MCP schema digest does not match the assignment"),
                retryable=False,
            )
        remote_contract_hash = _canonical_hash(
            {
                "name": assignment.mcp_tool_name,
                "inputSchema": remote_input,
                "outputSchema": remote_output,
            }
        )
        return MCPToolAttestationComplete(
            lease_token=assignment.lease_token,
            oauth_observation=observation,
            status="passed",
            checked_at=_utcnow(),
            protocol_version=MCP_PROTOCOL_VERSION,
            advertised_tool_count=len(tools),
            catalog_sha256=_canonical_hash(tools),
            remote_contract_sha256=remote_contract_hash,
            input_schema_sha256=input_hash,
            output_schema_sha256=output_hash,
        )
    except Exception as exc:
        LOGGER.exception(
            "Unexpected MCP attestor failure for %s",
            assignment.attestation_id,
        )
        return failure(
            assignment,
            code="worker_error",
            error=exc,
            retryable=True,
        )
    finally:
        for key in list(credentials):
            credentials[key] = ""
        credentials.clear()
        if resolved is not None:
            resolved.close()


def run_once(
    client: ControlPlaneClient,
    worker_id: str,
    *,
    max_assignments: int,
    lease_seconds: int,
    credential_broker: Any,
    allowed_hosts: list[str],
) -> int:
    documents = client.request(
        "POST",
        f"/api/v1/mcp/attestors/{worker_id}/attestations/claim",
        {
            "max_assignments": max_assignments,
            "lease_seconds": lease_seconds,
        },
    )
    assignments = [
        MCPToolAttestationAssignment.model_validate(item)
        for item in documents
    ]
    for assignment in assignments:
        result = attest_assignment(
            assignment,
            credential_broker=credential_broker,
            allowed_hosts=allowed_hosts,
        )
        completed = client.request(
            "POST",
            (
                f"/api/v1/mcp/attestors/{worker_id}/attestations/"
                f"{assignment.attestation_id}/complete"
            ),
            result.model_dump(mode="json"),
        )
        LOGGER.info(
            "attestation=%s status=%s attempt=%s",
            assignment.attestation_id,
            completed["status"],
            assignment.attempt,
        )
    return len(assignments)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the authenticated iCheck MCP contract attestor"
    )
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--control-plane",
        default=os.getenv("ICHECK_CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--allow-insecure-control-plane",
        action="store_true",
        default=os.getenv(
            "ICHECK_MCP_ATTESTOR_ALLOW_INSECURE_CONTROL_PLANE", ""
        ).lower()
        in {"1", "true", "yes"},
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
        default=os.getenv("ICHECK_MCP_ATTESTOR_REGISTRATION_TOKEN_FILE"),
    )
    parser.add_argument(
        "--name",
        default=os.getenv(
            "ICHECK_MCP_ATTESTOR_NAME",
            f"{socket.gethostname()}-mcp-attestor",
        ),
    )
    parser.add_argument(
        "--max-assignments",
        type=int,
        default=int(os.getenv("ICHECK_MCP_ATTESTOR_MAX_ASSIGNMENTS", "4")),
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.getenv("ICHECK_MCP_ATTESTOR_LEASE_SECONDS", "120")),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.getenv("ICHECK_MCP_ATTESTOR_POLL_SECONDS", "2")),
    )
    parser.add_argument(
        "--mcp-allowed-host",
        action="append",
        dest="mcp_allowed_hosts",
        default=None,
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
    )
    parser.add_argument("--once", action="store_true")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: Any) -> list[str]:
    if not args.name or not args.name.strip():
        parser.error("--name or ICHECK_MCP_ATTESTOR_NAME is required")
    if not 1 <= args.max_assignments <= 10:
        parser.error("--max-assignments must be between 1 and 10")
    if not 30 <= args.lease_seconds <= 900:
        parser.error("--lease-seconds must be between 30 and 900")
    if args.poll_seconds <= 0 or args.poll_seconds > 60:
        parser.error("--poll-seconds must be greater than 0 and at most 60")
    hosts = args.mcp_allowed_hosts
    if hosts is None:
        hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_MCP_ALLOWED_HOSTS",
                "127.0.0.1,localhost",
            ).split(",")
            if item.strip()
        ]
    if not hosts:
        parser.error("at least one MCP endpoint host must be allowlisted")
    return hosts


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("ICHECK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _parser()
    args = parser.parse_args()
    allowed_hosts = _validate_args(parser, args)
    namespace = parse_worker_namespace(parser, args)
    credential_broker = build_credential_broker(args)
    client = ControlPlaneClient(
        args.control_plane,
        allow_insecure=args.allow_insecure_control_plane,
        tenant_id=namespace.tenant_id,
        region_id=namespace.region_id,
        tls_ca_file=args.control_plane_tls_ca_file,
        tls_cert_file=args.control_plane_tls_cert_file,
        tls_key_file=args.control_plane_tls_key_file,
        tls_key_password_file=args.control_plane_tls_key_password_file,
        user_agent="iCheck-mcp-attestor/0.1",
    )
    registration = client.request(
        "POST",
        "/api/v1/mcp/attestors/register",
        {
            "name": args.name,
            "labels": {
                "runtime": "systemd",
                "role": "mcp_attestor",
                "control_transport": "http_api",
            },
        },
        extra_headers={
            "X-iCheck-Registration-Token": load_attestor_registration_token(
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
            return 0
        count = run_once(
            client,
            worker_id,
            max_assignments=args.max_assignments,
            lease_seconds=args.lease_seconds,
            credential_broker=credential_broker,
            allowed_hosts=allowed_hosts,
        )
        if args.once:
            return 0
        if not count:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
