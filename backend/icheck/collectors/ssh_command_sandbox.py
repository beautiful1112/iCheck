from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from ..command_profiles import get_ssh_command_profile
from ..sandbox import SandboxUnavailable
from .http_json import document_to_envelopes


def _host_allowed(hostname: str, patterns: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for pattern in patterns:
        normalized = pattern.strip().rstrip(".").lower()
        if not normalized:
            continue
        if "/" in normalized and address is not None:
            try:
                if address in ipaddress.ip_network(normalized, strict=False):
                    return True
            except ValueError:
                continue
        elif normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def _target_host(value: Any) -> str:
    if not isinstance(value, str) or not value or "://" in value:
        raise ValueError(
            "ssh_command_sandbox target.host must be a hostname or IP address"
        )
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    parsed = urlsplit(f"//{value}")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "ssh_command_sandbox target.host must not contain credentials, "
            "a port, path, query, or fragment"
        )
    return parsed.hostname


def _reject_constant(value: str) -> None:
    raise ValueError(f"SSH command JSON contains non-finite value {value!r}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"SSH command JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def collect_ssh_command_sandbox(
    assignment: dict[str, Any],
) -> list[dict[str, Any]]:
    """Execute a fixed read-only SSH command and transform bounded JSON."""

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    host = _target_host(target.get("host"))
    port = int(target.get("port", 22))
    if port < 1 or port > 65535:
        raise ValueError(
            "ssh_command_sandbox target.port must be between 1 and 65535"
        )
    profile = get_ssh_command_profile(configuration.get("command_profile"))

    credential_ref = assignment.get("credential_profile_ref")
    if not isinstance(credential_ref, str) or not credential_ref:
        raise ValueError(
            "ssh_command_sandbox requires a credential profile reference"
        )
    runtime = assignment.get("_runtime", {})
    credential = runtime.get("credential")
    if not isinstance(credential, dict) or not credential:
        raise RuntimeError("SSH command credential was not resolved")
    allowed_targets = runtime.get("ssh_allowed_targets", [])
    if not isinstance(allowed_targets, list) or not _host_allowed(
        host, allowed_targets
    ):
        raise ValueError(f"SSH command target {host!r} is not allowlisted")

    command_executor = runtime.get("ssh_command_executor")
    if not callable(command_executor):
        raise RuntimeError(
            "SSH command collection requires the host-key-verifying executor"
        )
    sandbox_executor = runtime.get("sandbox_executor")
    if sandbox_executor is None or not hasattr(sandbox_executor, "transform"):
        raise SandboxUnavailable("Generated-code sandbox is unavailable on Worker")
    implementation = assignment.get("implementation")
    if not isinstance(implementation, dict):
        raise ValueError("Sandbox collector implementation is missing")

    timeout_seconds = int(configuration.get("timeout_seconds", 15))
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    lease_seconds = int(runtime.get("lease_seconds", 60))
    if timeout_seconds + 5 >= lease_seconds:
        raise ValueError(
            "timeout_seconds must leave at least 5 seconds in the run lease"
        )
    max_bytes = int(configuration.get("max_response_bytes", 2_000_000))
    if max_bytes < 1 or max_bytes > 10_000_000:
        raise ValueError("max_response_bytes must be between 1 and 10000000")

    output = command_executor(
        host=host,
        port=port,
        credential_profile_ref=credential_ref,
        credential=dict(credential),
        command_profile=profile.key,
        command=profile.command,
        timeout_seconds=timeout_seconds,
    )
    if isinstance(output, str):
        encoded = output.encode("utf-8")
    elif isinstance(output, bytes):
        encoded = output
    else:
        raise ValueError("SSH command executor must return text or bytes")
    if len(encoded) > max_bytes:
        raise ValueError("SSH command output exceeded max_response_bytes")
    try:
        document = json.loads(
            encoded.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except UnicodeDecodeError as exc:
        raise ValueError("SSH command output must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("SSH command output must be valid JSON") from exc
    if not isinstance(document, (dict, list)):
        raise ValueError("SSH command JSON output must be an object or array")

    trusted_envelopes = document_to_envelopes(
        assignment,
        document,
        configuration,
    )
    return sandbox_executor.transform(
        implementation,
        trusted_envelopes,
        configuration,
        list(assignment.get("output_kinds") or []),
    )
