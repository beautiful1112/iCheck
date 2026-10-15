from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import ssl
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .collectors import (
    collect_http_json,
    collect_http_json_sandbox,
    collect_psrp_cim,
    collect_snmp_exporter,
    collect_snmp_topology,
    collect_ssh_command_sandbox,
    collect_windows_exporter,
)
from .collector_adapter_supervisor import ISOLATED_ADAPTERS, run_supervised_adapter
from .credentials import (
    CredentialBroker,
    CredentialContext,
    CredentialGrant,
    DisabledCredentialBroker,
    EnvironmentCredentialProvider,
    MCPOAuthVaultCredentialProvider,
    SecretRedactor,
    VaultDynamicCredentialProvider,
    VaultKV2CredentialProvider,
    WorkerCredentialBroker,
)
from .sandbox import (
    BubblewrapSandboxExecutor,
    HardenedProcessSandboxExecutor,
    SandboxExecutor,
)
from .psrp_executor import PSRPCIMTransportExecutor, PSRPDependencyUnavailable
from .ssh_executor import AsyncSSHCommandExecutor
from .device_preflight_worker import (
    DevicePreflightFailure,
    PREFLIGHT_ONLY_ADAPTERS,
    execute_device_preflight,
    require_icmp_preflight_support,
)
from .worker_namespace import (
    add_worker_namespace_arguments,
    parse_worker_namespace,
)


MAX_CONTROL_PLANE_MESSAGE_BYTES = 32_000_000
MAX_CONTROL_PLANE_ERROR_BYTES = 65_536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_private_file(path: str, *, label: str) -> str:
    try:
        metadata = os.stat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{label} must not be accessible by group or others")
        if metadata.st_size > 4096:
            raise ValueError(f"{label} is oversized")
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise ValueError(f"Unable to read {label}: {exc}") from exc
    if not value:
        raise ValueError(f"{label} is empty")
    return value


class ControlPlaneHTTPError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"Control plane returned HTTP {status_code}: {detail}")
        self.status_code = status_code


class ControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 30,
        *,
        allow_insecure: bool = False,
        tenant_id: str | None = None,
        region_id: str | None = None,
        tls_ca_file: str | None = None,
        tls_cert_file: str | None = None,
        tls_key_file: str | None = None,
        tls_key_password_file: str | None = None,
        user_agent: str = "iCheck-collector/0.4",
        max_message_bytes: int = MAX_CONTROL_PLANE_MESSAGE_BYTES,
    ):
        parsed = urlsplit(base_url)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Control-plane URL must be an HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("Control-plane URL must not contain credentials")
        if not 1 <= max_message_bytes <= MAX_CONTROL_PLANE_MESSAGE_BYTES:
            raise ValueError(
                "Control-plane message limit must be between 1 and 32000000 bytes"
            )
        if parsed.scheme != "https" and not loopback and not allow_insecure:
            raise ValueError(
                "Non-loopback control-plane connections require HTTPS; use the "
                "explicit insecure override only for an isolated test lab"
            )
        if bool(tls_cert_file) != bool(tls_key_file):
            raise ValueError(
                "Control-plane mTLS requires both a certificate and private key"
            )
        if tls_key_password_file and not tls_key_file:
            raise ValueError(
                "A control-plane TLS key password requires a private key"
            )
        if parsed.scheme != "https" and any(
            (tls_ca_file, tls_cert_file, tls_key_file, tls_key_password_file)
        ):
            raise ValueError("Control-plane TLS files require an HTTPS URL")
        for tls_path in (
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            tls_key_password_file,
        ):
            if tls_path and not os.path.isabs(tls_path):
                raise ValueError("Control-plane TLS file paths must be absolute")
        if parsed.scheme == "https":
            try:
                context = ssl.create_default_context(cafile=tls_ca_file)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                if tls_cert_file and tls_key_file:
                    password = (
                        _read_private_file(
                            tls_key_password_file,
                            label="control-plane TLS key password file",
                        )
                        if tls_key_password_file
                        else None
                    )
                    key_metadata = os.stat(tls_key_file)
                    if not stat.S_ISREG(key_metadata.st_mode):
                        raise ValueError(
                            "Control-plane TLS private key must be a regular file"
                        )
                    if stat.S_IMODE(key_metadata.st_mode) & 0o077:
                        raise ValueError(
                            "Control-plane TLS private key must not be accessible "
                            "by group or others"
                        )
                    context.load_cert_chain(
                        certfile=tls_cert_file,
                        keyfile=tls_key_file,
                        password=password,
                    )
            except (OSError, ssl.SSLError) as exc:
                raise ValueError(
                    f"Unable to configure control-plane TLS: {exc}"
                ) from exc
            self.opener = build_opener(
                _NoRedirect(),
                HTTPSHandler(context=context),
            )
        else:
            self.opener = build_opener(_NoRedirect())
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout_seconds = timeout_seconds
        self.access_token: str | None = None
        self.tenant_id = tenant_id
        self.region_id = region_id
        self.user_agent = user_agent
        self.max_message_bytes = max_message_bytes

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        allow_extended_timeout: bool = False,
    ) -> Any:
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        if body is not None and len(body) > self.max_message_bytes:
            raise ValueError("Control-plane request exceeds its size limit")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.tenant_id and self.region_id:
            headers["X-Icheck-Tenant-ID"] = self.tenant_id
            headers["X-Icheck-Region-ID"] = self.region_id
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if extra_headers:
            headers.update(extra_headers)
        request = Request(
            urljoin(self.base_url, path.lstrip("/")),
            data=body,
            headers=headers,
            method=method,
        )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("Control-plane request timeout must be positive")
        timeout = self.timeout_seconds
        if timeout_seconds is not None:
            if allow_extended_timeout:
                if method != "POST" or not path.startswith("/api/v1/agent/executions/") or not path.endswith("/runtime/reason") or timeout_seconds > 3605:
                    raise ValueError("Extended timeout is restricted to bounded Agent reasoning")
                timeout = timeout_seconds
            else:
                timeout = min(timeout, timeout_seconds)
        try:
            with self.opener.open(
                request,
                timeout=timeout,
            ) as response:
                response_body = response.read(self.max_message_bytes + 1)
                headers = getattr(response, "headers", None)
                declared_length = headers.get("Content-Length") if headers is not None else None
        except HTTPError as exc:
            detail = exc.read(MAX_CONTROL_PLANE_ERROR_BYTES + 1)
            if len(detail) > MAX_CONTROL_PLANE_ERROR_BYTES:
                detail = detail[:MAX_CONTROL_PLANE_ERROR_BYTES] + b"..."
            detail_text = detail.decode("utf-8", errors="replace")
            raise ControlPlaneHTTPError(exc.code, detail_text) from exc
        if len(response_body) > self.max_message_bytes:
            raise RuntimeError("Control-plane response exceeds its size limit")
        if declared_length is not None:
            from http.client import IncompleteRead
            expected_length = int(declared_length)
            if expected_length < 0:
                raise ValueError("Control-plane response has an invalid content length")
            if expected_length > self.max_message_bytes:
                raise RuntimeError("Control-plane response exceeds its size limit")
            if len(response_body) < expected_length:
                # read(size) may return a short body without raising. Preserve
                # transport loss as such, rather than a misleading JSON error.
                raise IncompleteRead(response_body, expected_length - len(response_body))
        if not response_body:
            return None
        return json.loads(response_body.decode("utf-8"))


ADAPTERS = {
    "http_json": collect_http_json,
    "http_json_sandbox": collect_http_json_sandbox,
    "psrp_cim": collect_psrp_cim,
    "snmp_exporter": collect_snmp_exporter,
    "snmp_topology": collect_snmp_topology,
    "ssh_command_sandbox": collect_ssh_command_sandbox,
    "windows_exporter": collect_windows_exporter,
}


def validate_worker_capabilities(capabilities: list[str]) -> list[str]:
    if not capabilities:
        raise SystemExit("At least one collector capability is required")
    if set(ADAPTERS) != ISOLATED_ADAPTERS:
        raise SystemExit("Collector adapter registry must match the supervised-I/O registry")
    if set(capabilities) - (ISOLATED_ADAPTERS | PREFLIGHT_ONLY_ADAPTERS):
        raise SystemExit("Collector capabilities include an adapter without supervised I/O or a monitoring preflight executor")
    return list(dict.fromkeys(capabilities))


class WorkerDrainRequested(RuntimeError):
    """The control plane asked this worker to finish and exit cleanly."""


def run_assignment(
    client: ControlPlaneClient,
    worker_id: str,
    assignment: dict[str, Any],
    *,
    http_allowed_hosts: list[str],
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    windows_exporter_allowed_hosts: list[str],
    windows_allowed_targets: list[str],
    ssh_allowed_targets: list[str] | None = None,
    credential_broker: CredentialBroker,
    sandbox_executor: SandboxExecutor | None = None,
    psrp_cim_executor: Any | None = None,
    ssh_command_executor: Any | None = None,
) -> bool:
    run_id = assignment["run_id"]
    lease_token = assignment["lease_token"]
    adapter_type = assignment["adapter_type"]
    redactor = SecretRedactor()
    resolved_credential = None
    try:
        assignment["_runtime"] = {
            "http_allowed_hosts": http_allowed_hosts,
            "exporter_allowed_hosts": exporter_allowed_hosts,
            "snmp_allowed_targets": snmp_allowed_targets,
            "windows_exporter_allowed_hosts": windows_exporter_allowed_hosts,
            "windows_allowed_targets": windows_allowed_targets,
            "ssh_allowed_targets": ssh_allowed_targets or [],
            "psrp_cim_executor": psrp_cim_executor,
            "ssh_command_executor": ssh_command_executor,
            "sandbox_executor": sandbox_executor,
            "lease_seconds": assignment.get("_lease_seconds", 60),
        }
        admission = {
            "lease_token": lease_token,
            "assignment_sha256": assignment["assignment_sha256"],
        }
        if assignment.get("credential_profile_ref"):
            client.request(
                "POST", f"/api/v1/collector-runs/{run_id}/admit", admission,
            )
            grant_payload = client.request(
                "POST",
                f"/api/v1/collector-runs/{run_id}/credential-grant",
                {"lease_token": lease_token},
            )
            grant = CredentialGrant.from_mapping(grant_payload)
            if grant.provider == "managed_device":
                from .credentials import ResolvedCredential
                secret = client.request("POST", f"/api/v1/collector-runs/{run_id}/managed-credential",
                                        {"lease_token": lease_token})
                resolved_credential = ResolvedCredential(values=secret["values"], expires_at=grant.expires_at,
                                                        grant_expires_at=grant.expires_at)
                secret = None
            else:
                resolved_credential = credential_broker.resolve(
                    grant,
                    CredentialContext(worker_id=worker_id, deployment_id=assignment["deployment_id"], adapter_type=adapter_type),
                )
            remaining_seconds = int(
                (
                    resolved_credential.expires_at
                    - datetime.now(UTC)
                ).total_seconds()
            )
            renewal_window = max(
                15,
                min(int(assignment["_runtime"]["lease_seconds"]) - 5, 300),
            )
            if (
                resolved_credential.renewable
                and remaining_seconds < renewal_window
            ):
                resolved_credential.renew(renewal_window)
            redactor.add_mapping(resolved_credential.values)
            assignment["_runtime"]["credential"] = resolved_credential.values
        client.request(
            "POST", f"/api/v1/collector-runs/{run_id}/admit", admission,
        )
        if adapter_type in ISOLATED_ADAPTERS:
            def check_admission(timeout_seconds: float) -> None:
                client.request(
                    "POST", f"/api/v1/collector-runs/{run_id}/admit",
                    admission, timeout_seconds=timeout_seconds,
                )

            raw_envelopes = run_supervised_adapter(
                assignment, adapter_type,
                check_admission=check_admission,
                credential_expires_at=(
                    resolved_credential.expires_at
                    if resolved_credential is not None else None
                ),
            )
        else:
            raw_envelopes = ADAPTERS[adapter_type](assignment)
        envelopes = redactor.redact_value(raw_envelopes)
        if envelopes:
            client.request(
                "POST",
                f"/api/v1/collector-runs/{run_id}/envelopes",
                {"lease_token": lease_token, "envelopes": envelopes},
            )
        client.request(
            "POST",
            f"/api/v1/collector-runs/{run_id}/complete",
            {
                "lease_token": lease_token,
                "status": "succeeded",
                "stats": {"adapter": adapter_type, "records": len(envelopes)},
            },
        )
        return True
    except Exception as exc:
        safe_error = redactor.redact_text(str(exc))[:10000]
        try:
            client.request(
                "POST",
                f"/api/v1/collector-runs/{run_id}/complete",
                {
                    "lease_token": lease_token,
                    "status": "failed",
                    "error": safe_error,
                    "stats": {"adapter": adapter_type},
                },
            )
        except Exception as completion_exc:
            print(
                f"failed to report run {run_id}: "
                f"{redactor.redact_text(str(completion_exc))}",
                file=sys.stderr,
            )
        print(f"collector run {run_id} failed: {safe_error}", file=sys.stderr)
        return False
    finally:
        assignment.get("_runtime", {}).pop("credential", None)
        if resolved_credential is not None:
            resolved_credential.close()


def run_device_preflight(
    client: ControlPlaneClient,
    worker_id: str,
    assignment: dict[str, Any],
    *,
    allowed_targets: list[str],
    timeout_seconds: int,
    snmp_exporter_url: str | None,
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    lease_seconds: int,
) -> bool:
    preflight_id = assignment["preflight_id"]
    lease_token = assignment["lease_token"]
    redactor = SecretRedactor()
    try:
        http_auth = (assignment.get("configuration") or {}).get("http_monitor", {}).get("auth_mode", "none")
        exporter_auth = (assignment.get("configuration") or {}).get("exporter_monitor", {}).get("auth_mode", "none")
        if assignment.get("credential_provider") == "managed_device" and (assignment.get("adapter_type") == "snmp_exporter"
                or (assignment.get("adapter_type") == "http_json" and http_auth != "none")
                or (assignment.get("adapter_type") in {"node_exporter", "windows_exporter", "cadvisor", "vmware_exporter"} and exporter_auth != "none")):
            secret = client.request("POST", f"/api/v1/collector-workers/{worker_id}/device-preflights/{preflight_id}/managed-credential",
                                    {"lease_token": lease_token})
            if (assignment.get("adapter_type") == "http_json" or
                    assignment.get("configuration",{}).get("monitoring_template_version_id")) and secret["profile_revision"] != assignment.get("credential_revision"):
                raise DevicePreflightFailure("Credential changed after test assignment; request a new test", {"check": "credential_revision", "verified": False})
            assignment["_runtime"] = {"credential": secret["values"], "credential_revision": secret["profile_revision"]}
            redactor.add_mapping(secret["values"])
            secret = None
        evidence, latency_ms = execute_device_preflight(
            assignment,
            allowed_targets=allowed_targets,
            timeout_seconds=timeout_seconds,
            snmp_exporter_url=snmp_exporter_url,
            exporter_allowed_hosts=exporter_allowed_hosts,
            snmp_allowed_targets=snmp_allowed_targets,
            lease_seconds=lease_seconds,
        )
        payload = {
            "lease_token": lease_token,
            "status": "verified",
            "latency_ms": latency_ms,
            "evidence": evidence,
        }
        succeeded = True
    except DevicePreflightFailure as exc:
        payload = {
            "lease_token": lease_token,
            "status": "failed",
            "latency_ms": exc.latency_ms,
            "evidence": exc.evidence,
            "error": redactor.redact_text(str(exc))[:2000],
        }
        succeeded = False
    except Exception as exc:
        payload = {
            "lease_token": lease_token,
            "status": "failed",
            "evidence": {
                "check": "worker_execution",
                "verified": False,
            },
            "error": redactor.redact_text(str(exc))[:2000],
        }
        succeeded = False
    finally:
        assignment.pop("_runtime", None)
    try:
        client.request(
            "POST",
            (
                f"/api/v1/collector-workers/{worker_id}/device-preflights/"
                f"{preflight_id}/complete"
            ),
            payload,
        )
    except Exception as exc:
        print(
            f"failed to report device preflight {preflight_id}: {exc}",
            file=sys.stderr,
        )
        return False
    if not succeeded:
        print(
            f"device preflight {preflight_id} failed: {payload['error']}",
            file=sys.stderr,
        )
    return succeeded


def run_once(
    client: ControlPlaneClient,
    worker_id: str,
    *,
    max_assignments: int,
    lease_seconds: int,
    http_allowed_hosts: list[str],
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    windows_exporter_allowed_hosts: list[str],
    windows_allowed_targets: list[str],
    ssh_allowed_targets: list[str],
    max_preflights: int,
    preflight_allowed_targets: list[str],
    preflight_timeout_seconds: int,
    preflight_snmp_exporter_url: str | None,
    credential_broker: CredentialBroker | None = None,
    sandbox_executor: SandboxExecutor | None = None,
    psrp_cim_executor: Any | None = None,
    ssh_command_executor: Any | None = None,
) -> tuple[int, int]:
    if credential_broker is None:
        credential_broker = DisabledCredentialBroker()
    heartbeat = client.request(
        "POST",
        f"/api/v1/collector-workers/{worker_id}/heartbeat",
        {"state": "online"},
    )
    if heartbeat["state"] == "draining":
        raise WorkerDrainRequested
    assignments = client.request(
        "POST",
        f"/api/v1/collector-workers/{worker_id}/leases/claim",
        {
            "max_assignments": max_assignments,
            "lease_seconds": lease_seconds,
        },
    )
    preflight_lease_seconds = min(lease_seconds, 600)
    preflights = client.request(
        "POST",
        f"/api/v1/collector-workers/{worker_id}/device-preflights/claim",
        {
            "max_assignments": max_preflights,
            "lease_seconds": preflight_lease_seconds,
        },
    )
    for item in assignments:
        item["_lease_seconds"] = lease_seconds
    with ThreadPoolExecutor(max_workers=max(1, len(assignments))) as executor:
        outcomes = list(
            executor.map(
                lambda item: run_assignment(
                    client,
                    worker_id,
                    item,
                    http_allowed_hosts=http_allowed_hosts,
                    exporter_allowed_hosts=exporter_allowed_hosts,
                    snmp_allowed_targets=snmp_allowed_targets,
                    windows_exporter_allowed_hosts=(
                        windows_exporter_allowed_hosts
                    ),
                    windows_allowed_targets=windows_allowed_targets,
                    ssh_allowed_targets=ssh_allowed_targets,
                    credential_broker=credential_broker,
                    sandbox_executor=sandbox_executor,
                    psrp_cim_executor=psrp_cim_executor,
                    ssh_command_executor=ssh_command_executor,
                ),
                assignments,
            )
        )
    succeeded = sum(outcomes)
    with ThreadPoolExecutor(max_workers=max(1, len(preflights))) as executor:
        preflight_outcomes = list(
            executor.map(
                lambda item: run_device_preflight(
                    client,
                    worker_id,
                    item,
                    allowed_targets=preflight_allowed_targets,
                    timeout_seconds=preflight_timeout_seconds,
                    snmp_exporter_url=preflight_snmp_exporter_url,
                    exporter_allowed_hosts=exporter_allowed_hosts,
                    snmp_allowed_targets=snmp_allowed_targets,
                    lease_seconds=preflight_lease_seconds,
                ),
                preflights,
            )
        )
    succeeded += sum(preflight_outcomes)
    total = len(assignments) + len(preflights)
    return succeeded, total - succeeded


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an iCheck collector worker")
    add_worker_namespace_arguments(parser)
    parser.add_argument(
        "--control-plane",
        default=os.getenv("ICHECK_CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--name",
        default=os.getenv("ICHECK_COLLECTOR_NAME", socket.gethostname()),
    )
    parser.add_argument(
        "--allow-insecure-control-plane",
        action="store_true",
        default=os.getenv(
            "ICHECK_COLLECTOR_ALLOW_INSECURE_CONTROL_PLANE", ""
        ).lower() in {"1", "true", "yes"},
        help="Allow remote HTTP control plane (isolated test labs only)",
    )
    parser.add_argument(
        "--control-plane-tls-ca-file",
        default=os.getenv("ICHECK_WORKER_TLS_CA_FILE"),
        help="Private CA bundle for the HTTPS control plane",
    )
    parser.add_argument(
        "--control-plane-tls-cert-file",
        default=os.getenv("ICHECK_WORKER_TLS_CERT_FILE"),
        help="Worker client certificate PEM for control-plane mTLS",
    )
    parser.add_argument(
        "--control-plane-tls-key-file",
        default=os.getenv("ICHECK_WORKER_TLS_KEY_FILE"),
        help="Mode-0600 Worker client private key PEM",
    )
    parser.add_argument(
        "--control-plane-tls-key-password-file",
        default=os.getenv("ICHECK_WORKER_TLS_KEY_PASSWORD_FILE"),
        help="Optional mode-0600 file containing the private-key password",
    )
    parser.add_argument("--site", default=os.getenv("ICHECK_COLLECTOR_SITE"))
    parser.add_argument(
        "--capability",
        action="append",
        dest="capabilities",
        default=None,
        help="Collection adapter or monitoring-only preflight supported by this worker; may be repeated",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_POLL_SECONDS", "5")),
    )
    parser.add_argument(
        "--lease-seconds",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_LEASE_SECONDS", "60")),
    )
    parser.add_argument(
        "--max-assignments",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_MAX_ASSIGNMENTS", "1")),
    )
    parser.add_argument(
        "--max-preflights",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_MAX_PREFLIGHTS", "2")),
    )
    parser.add_argument(
        "--preflight-timeout-seconds",
        type=int,
        default=int(os.getenv("ICHECK_COLLECTOR_PREFLIGHT_TIMEOUT_SECONDS", "5")),
    )
    parser.add_argument(
        "--preflight-allowed-target",
        action="append",
        dest="preflight_allowed_targets",
        default=None,
        help="Exact IP or CIDR allowed for device connection preflights",
    )
    parser.add_argument(
        "--preflight-snmp-exporter-url",
        default=os.getenv("ICHECK_COLLECTOR_PREFLIGHT_SNMP_EXPORTER_URL"),
        help="Site-local SNMP Exporter base URL used for SNMP preflights",
    )
    parser.add_argument(
        "--http-allowed-host",
        action="append",
        dest="http_allowed_hosts",
        default=None,
        help="Exact hostname or *.suffix allowed for HTTP collection",
    )
    parser.add_argument(
        "--registration-token-file",
        default=os.getenv("ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE"),
        help="Path to the bootstrap registration token (preferred over env)",
    )
    parser.add_argument(
        "--exporter-allowed-host",
        action="append",
        dest="exporter_allowed_hosts",
        default=None,
        help="Exact hostname or CIDR allowed for exporter HTTP requests",
    )
    parser.add_argument(
        "--snmp-allowed-target",
        action="append",
        dest="snmp_allowed_targets",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed as an SNMP target",
    )
    parser.add_argument(
        "--windows-exporter-allowed-host",
        action="append",
        dest="windows_exporter_allowed_hosts",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed for windows_exporter",
    )
    parser.add_argument(
        "--windows-allowed-target",
        action="append",
        dest="windows_allowed_targets",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed for PSRP/CIM diagnostics",
    )
    parser.add_argument(
        "--psrp-allowed-port",
        action="append",
        type=int,
        dest="psrp_allowed_ports",
        default=None,
        help="WinRM HTTPS port allowed for PSRP/CIM; may be repeated",
    )
    parser.add_argument(
        "--psrp-auth",
        choices=["ntlm", "basic"],
        default=os.getenv("ICHECK_COLLECTOR_PSRP_AUTH", "ntlm").lower(),
        help="Explicit PSRP authentication mode (TLS is always required)",
    )
    parser.add_argument(
        "--psrp-ca-file",
        default=os.getenv("ICHECK_COLLECTOR_PSRP_CA_FILE"),
        help="Optional absolute PEM CA bundle for WinRM server verification",
    )
    parser.add_argument(
        "--psrp-configuration-name",
        default=os.getenv(
            "ICHECK_COLLECTOR_PSRP_CONFIGURATION_NAME",
            "Microsoft.PowerShell",
        ),
        help="PowerShell endpoint name, including a preconfigured JEA endpoint",
    )
    parser.add_argument(
        "--ssh-allowed-target",
        action="append",
        dest="ssh_allowed_targets",
        default=None,
        help="Exact host, *.suffix, or CIDR allowed for fixed SSH commands",
    )
    parser.add_argument(
        "--ssh-known-hosts-file",
        default=os.getenv("ICHECK_COLLECTOR_SSH_KNOWN_HOSTS_FILE"),
        help="Absolute OpenSSH known_hosts path for SSH host-key verification",
    )
    parser.add_argument(
        "--allow-environment-credentials",
        action="store_true",
        default=os.getenv(
            "ICHECK_CREDENTIAL_ALLOW_ENVIRONMENT", ""
        ).lower() in {"1", "true", "yes"},
        help="Enable env:// credential references (development only)",
    )
    parser.add_argument(
        "--vault-address",
        default=os.getenv("ICHECK_CREDENTIAL_VAULT_ADDR"),
        help="HashiCorp Vault base URL for worker-local KV v2 resolution",
    )
    parser.add_argument(
        "--vault-token-file",
        default=os.getenv("ICHECK_CREDENTIAL_VAULT_TOKEN_FILE"),
        help="Path to the worker-local Vault token",
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
        "--sandbox-enabled",
        action="store_true",
        default=os.getenv("ICHECK_SANDBOX_ENABLED", "").lower()
        in {"1", "true", "yes"},
    )
    parser.add_argument(
        "--sandbox-bwrap-path",
        default=os.getenv(
            "ICHECK_SANDBOX_BWRAP_PATH",
            "/usr/bin/bwrap",
        ),
    )
    parser.add_argument(
        "--sandbox-backend",
        choices=["process", "bubblewrap"],
        default=os.getenv("ICHECK_SANDBOX_BACKEND", "process"),
    )
    parser.add_argument(
        "--sandbox-python-path",
        default=os.getenv("ICHECK_SANDBOX_PYTHON_PATH", "/usr/bin/python3"),
    )
    parser.add_argument(
        "--sandbox-timeout-seconds",
        type=int,
        default=int(os.getenv("ICHECK_SANDBOX_TIMEOUT_SECONDS", "5")),
    )
    parser.add_argument("--once", action="store_true")
    return parser.parse_args(argv)


def load_registration_token(token_file: str | None) -> str:
    if token_file:
        try:
            with open(token_file, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise SystemExit(
                f"Unable to read collector registration token file: {exc}"
            ) from exc
    else:
        token = os.getenv("ICHECK_COLLECTOR_REGISTRATION_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "Set ICHECK_COLLECTOR_REGISTRATION_TOKEN_FILE or "
            "ICHECK_COLLECTOR_REGISTRATION_TOKEN"
        )
    return token


def build_credential_broker(args: argparse.Namespace) -> CredentialBroker:
    providers: dict[str, Any] = {}
    if args.allow_environment_credentials:
        providers["environment"] = EnvironmentCredentialProvider()
    if args.vault_address or args.vault_token_file:
        if not args.vault_address or not args.vault_token_file:
            raise SystemExit(
                "Vault credentials require both ICHECK_CREDENTIAL_VAULT_ADDR and "
                "ICHECK_CREDENTIAL_VAULT_TOKEN_FILE"
            )
        vault = VaultKV2CredentialProvider(
            address=args.vault_address,
            token_file=args.vault_token_file,
            namespace=args.vault_namespace,
            timeout_seconds=args.vault_timeout_seconds,
        )
        providers["vault"] = vault
        providers["vault_kv2"] = vault
        providers["vault_dynamic"] = VaultDynamicCredentialProvider(
            address=args.vault_address,
            token_file=args.vault_token_file,
            namespace=args.vault_namespace,
            timeout_seconds=args.vault_timeout_seconds,
        )
        oauth_allowed_hosts = getattr(args, "mcp_oauth_allowed_hosts", None)
        if oauth_allowed_hosts is None:
            oauth_allowed_hosts = [
                value.strip()
                for value in os.getenv("ICHECK_MCP_OAUTH_ALLOWED_HOSTS", "").split(",")
                if value.strip()
            ]
        providers["mcp_oauth_vault"] = MCPOAuthVaultCredentialProvider(
            address=args.vault_address,
            token_file=args.vault_token_file,
            namespace=args.vault_namespace,
            timeout_seconds=args.vault_timeout_seconds,
            oauth_allowed_hosts=oauth_allowed_hosts,
        )
    if not providers:
        return DisabledCredentialBroker()
    return WorkerCredentialBroker(providers)


def build_sandbox_executor(
    args: argparse.Namespace,
) -> SandboxExecutor | None:
    if not args.sandbox_enabled:
        return None
    if args.sandbox_timeout_seconds < 1 or args.sandbox_timeout_seconds > 30:
        raise SystemExit("Sandbox timeout must be between 1 and 30 seconds")
    if args.sandbox_backend == "bubblewrap":
        return BubblewrapSandboxExecutor(
            bwrap_path=args.sandbox_bwrap_path,
            python_path=args.sandbox_python_path,
            timeout_seconds=args.sandbox_timeout_seconds,
        )
    return HardenedProcessSandboxExecutor(
        python_path=args.sandbox_python_path,
        timeout_seconds=args.sandbox_timeout_seconds,
    )


def build_psrp_cim_executor(
    args: argparse.Namespace,
    capabilities: list[str],
    *,
    allowed_targets: list[str],
    allowed_ports: list[int],
) -> PSRPCIMTransportExecutor | None:
    if "psrp_cim" not in capabilities:
        return None
    if not allowed_targets:
        raise SystemExit(
            "psrp_cim capability requires ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS"
        )
    try:
        executor = PSRPCIMTransportExecutor(
            allowed_targets=tuple(allowed_targets),
            allowed_ports=tuple(allowed_ports),
            auth=args.psrp_auth,
            ca_file=args.psrp_ca_file,
            configuration_name=args.psrp_configuration_name,
        )
        executor.require_dependency()
    except (ValueError, PSRPDependencyUnavailable) as exc:
        raise SystemExit(str(exc)) from exc
    return executor


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    validation_parser = argparse.ArgumentParser(
        description="Run an iCheck collector worker"
    )
    namespace = parse_worker_namespace(validation_parser, args)
    capabilities = args.capabilities
    if capabilities is None:
        capabilities = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_CAPABILITIES",
                "http_json",
            ).split(",")
            if item.strip()
        ]
    capabilities = validate_worker_capabilities(capabilities)
    http_allowed_hosts = args.http_allowed_hosts
    if http_allowed_hosts is None:
        http_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_HTTP_ALLOWED_HOSTS", ""
            ).split(",")
            if item.strip()
        ]
    exporter_allowed_hosts = args.exporter_allowed_hosts
    if exporter_allowed_hosts is None:
        exporter_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_EXPORTER_ALLOWED_HOSTS",
                "127.0.0.1,localhost",
            ).split(",")
            if item.strip()
        ]
    snmp_allowed_targets = args.snmp_allowed_targets
    if snmp_allowed_targets is None:
        snmp_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_SNMP_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    windows_exporter_allowed_hosts = args.windows_exporter_allowed_hosts
    if windows_exporter_allowed_hosts is None:
        windows_exporter_allowed_hosts = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_WINDOWS_EXPORTER_ALLOWED_HOSTS",
                "",
            ).split(",")
            if item.strip()
        ]
    windows_allowed_targets = args.windows_allowed_targets
    if windows_allowed_targets is None:
        windows_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_WINDOWS_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    psrp_allowed_ports = args.psrp_allowed_ports
    if psrp_allowed_ports is None:
        try:
            psrp_allowed_ports = [
                int(item.strip())
                for item in os.getenv(
                    "ICHECK_COLLECTOR_PSRP_ALLOWED_PORTS",
                    "5986",
                ).split(",")
                if item.strip()
            ]
        except ValueError as exc:
            raise SystemExit(
                "ICHECK_COLLECTOR_PSRP_ALLOWED_PORTS must contain integers"
            ) from exc
    ssh_allowed_targets = args.ssh_allowed_targets
    if ssh_allowed_targets is None:
        ssh_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_SSH_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    preflight_allowed_targets = args.preflight_allowed_targets
    if preflight_allowed_targets is None:
        preflight_allowed_targets = [
            item.strip()
            for item in os.getenv(
                "ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS",
                "",
            ).split(",")
            if item.strip()
        ]
    if args.poll_seconds < 1 or args.poll_seconds > 300:
        raise SystemExit("--poll-seconds must be between 1 and 300")
    if PREFLIGHT_ONLY_ADAPTERS.intersection(capabilities) and not preflight_allowed_targets:
        raise SystemExit("Preflight-only capabilities require ICHECK_COLLECTOR_PREFLIGHT_ALLOWED_TARGETS")
    if "icmp" in capabilities:
        try:
            require_icmp_preflight_support(
                [ipaddress.ip_network(target, strict=False).version for target in preflight_allowed_targets])
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    if args.lease_seconds < 15 or args.lease_seconds > 3600:
        raise SystemExit("--lease-seconds must be between 15 and 3600")
    if args.max_assignments < 1 or args.max_assignments > 20:
        raise SystemExit("--max-assignments must be between 1 and 20")
    if args.max_preflights < 1 or args.max_preflights > 20:
        raise SystemExit("--max-preflights must be between 1 and 20")
    if args.preflight_timeout_seconds < 1 or args.preflight_timeout_seconds > 30:
        raise SystemExit("--preflight-timeout-seconds must be between 1 and 30")
    if args.preflight_timeout_seconds + 5 >= min(args.lease_seconds, 600):
        raise SystemExit(
            "preflight timeout must leave at least 5 seconds in the lease"
        )

    client = ControlPlaneClient(
        args.control_plane,
        allow_insecure=args.allow_insecure_control_plane,
        tenant_id=namespace.tenant_id,
        region_id=namespace.region_id,
        tls_ca_file=args.control_plane_tls_ca_file,
        tls_cert_file=args.control_plane_tls_cert_file,
        tls_key_file=args.control_plane_tls_key_file,
        tls_key_password_file=args.control_plane_tls_key_password_file,
    )
    credential_broker = build_credential_broker(args)
    sandbox_executor = build_sandbox_executor(args)
    psrp_cim_executor = build_psrp_cim_executor(
        args,
        capabilities,
        allowed_targets=windows_allowed_targets,
        allowed_ports=psrp_allowed_ports,
    )
    ssh_command_executor = None
    if "ssh_command_sandbox" in capabilities:
        if sandbox_executor is None:
            raise SystemExit(
                "ssh_command_sandbox capability requires ICHECK_SANDBOX_ENABLED=true"
            )
        if not ssh_allowed_targets:
            raise SystemExit(
                "ssh_command_sandbox capability requires "
                "ICHECK_COLLECTOR_SSH_ALLOWED_TARGETS"
            )
        if not args.ssh_known_hosts_file:
            raise SystemExit(
                "ssh_command_sandbox capability requires "
                "ICHECK_COLLECTOR_SSH_KNOWN_HOSTS_FILE"
            )
        try:
            ssh_command_executor = AsyncSSHCommandExecutor(
                args.ssh_known_hosts_file
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    registration = client.request(
        "POST",
        "/api/v1/collector-workers/register",
        {
            "name": args.name,
            "site": args.site,
            "capabilities": capabilities,
            "labels": {
                "runtime": "python",
                "execution_admission_v1": True,
                "io_supervisor_v1": sys.platform.startswith("linux"),
            },
        },
        extra_headers={
            "X-iCheck-Registration-Token": load_registration_token(
                args.registration_token_file
            )
        },
    )
    client.access_token = registration["access_token"]
    worker_id = registration["worker"]["id"]
    while True:
        try:
            run_once(
                client,
                worker_id,
                max_assignments=args.max_assignments,
                lease_seconds=args.lease_seconds,
                http_allowed_hosts=http_allowed_hosts,
                exporter_allowed_hosts=exporter_allowed_hosts,
                snmp_allowed_targets=snmp_allowed_targets,
                windows_exporter_allowed_hosts=windows_exporter_allowed_hosts,
                windows_allowed_targets=windows_allowed_targets,
                ssh_allowed_targets=ssh_allowed_targets,
                max_preflights=args.max_preflights,
                preflight_allowed_targets=preflight_allowed_targets,
                preflight_timeout_seconds=args.preflight_timeout_seconds,
                preflight_snmp_exporter_url=args.preflight_snmp_exporter_url,
                credential_broker=credential_broker,
                sandbox_executor=sandbox_executor,
                psrp_cim_executor=psrp_cim_executor,
                ssh_command_executor=ssh_command_executor,
            )
        except WorkerDrainRequested:
            return 0
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
