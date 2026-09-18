from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.parse import urlsplit


CIM_OPERATIONS = {
    "operating_system": (
        "$ErrorActionPreference='Stop';"
        "Get-CimInstance -ClassName Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,LastBootUpTime,"
        "TotalVisibleMemorySize,FreePhysicalMemory | "
        "ConvertTo-Json -Compress -Depth 4"
    ),
    "computer_system": (
        "$ErrorActionPreference='Stop';"
        "Get-CimInstance -ClassName Win32_ComputerSystem | "
        "Select-Object Name,Domain,Manufacturer,Model,TotalPhysicalMemory,"
        "NumberOfLogicalProcessors | ConvertTo-Json -Compress -Depth 4"
    ),
    "logical_disks": (
        "$ErrorActionPreference='Stop';"
        "Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | "
        "Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace | "
        "ConvertTo-Json -Compress -Depth 4"
    ),
    "network_adapters": (
        "$ErrorActionPreference='Stop';"
        "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration "
        "-Filter 'IPEnabled=True' | Select-Object Description,MACAddress,"
        "IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder | "
        "ConvertTo-Json -Compress -Depth 5"
    ),
}


PSRPCIMExecutor = Callable[..., Any]


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
        raise ValueError("psrp_cim target.host must be a hostname or IP address")
    parsed = urlsplit(f"//{value}")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.path
    ):
        raise ValueError("psrp_cim target.host must not contain credentials or a port")
    return parsed.hostname


def _operations(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("operations must contain at least one operation")
    if len(value) > len(CIM_OPERATIONS):
        raise ValueError("operations contains too many entries")
    result: list[str] = []
    for item in value:
        if item not in CIM_OPERATIONS:
            raise ValueError(f"Unsupported read-only CIM operation: {item!r}")
        if item not in result:
            result.append(item)
    return result


def collect_psrp_cim(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute fixed read-only CIM templates through a credential-aware runtime."""

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    host = _target_host(target.get("host"))
    use_ssl = target.get("use_ssl", True)
    if use_ssl is not True:
        raise ValueError("psrp_cim requires WinRM over TLS")
    port = int(target.get("port", 5986))
    if port < 1 or port > 65535:
        raise ValueError("psrp_cim target.port must be between 1 and 65535")
    credential_ref = assignment.get("credential_profile_ref")
    if not isinstance(credential_ref, str) or not credential_ref:
        raise ValueError("psrp_cim requires a credential profile reference")

    runtime = assignment.get("_runtime", {})
    allowed_targets = runtime.get("windows_allowed_targets", [])
    if not isinstance(allowed_targets, list) or not _host_allowed(
        host,
        allowed_targets,
    ):
        raise ValueError(f"Windows diagnostic target {host!r} is not allowlisted")
    executor = runtime.get("psrp_cim_executor")
    if not callable(executor):
        raise RuntimeError(
            "PSRP/CIM execution requires an external credential-provider-backed "
            "executor"
        )

    operations = _operations(configuration.get("operations"))
    timeout_seconds = int(configuration.get("timeout_seconds", 30))
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    lease_seconds = int(runtime.get("lease_seconds", 60))
    if timeout_seconds * len(operations) + 5 >= lease_seconds:
        raise ValueError(
            "diagnostic timeout budget must leave at least 5 seconds in the run lease"
        )
    max_records = int(configuration.get("max_records", 500))
    if max_records < 1 or max_records > 500:
        raise ValueError("max_records must be between 1 and 500")
    max_bytes = int(configuration.get("max_response_bytes", 2_000_000))
    if max_bytes < 1 or max_bytes > 10_000_000:
        raise ValueError("max_response_bytes must be between 1 and 10000000")
    if "observation" not in set(assignment.get("output_kinds") or []):
        raise ValueError("psrp_cim collectors must declare observation output")

    source = configuration.get(
        "source",
        f"psrp_cim:{assignment.get('artifact_name', 'unknown')}",
    )
    observed_at = datetime.now(UTC).isoformat()
    envelopes: list[dict[str, Any]] = []
    response_bytes = 0
    for operation in operations:
        result = executor(
            host=host,
            port=port,
            use_ssl=True,
            credential_profile_ref=credential_ref,
            operation=operation,
            script=CIM_OPERATIONS[operation],
            timeout_seconds=timeout_seconds,
        )
        records = result if isinstance(result, list) else [result]
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("PSRP/CIM executor must return objects or object lists")
            response_bytes += len(
                json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            if response_bytes > max_bytes:
                raise ValueError("PSRP/CIM result exceeded max_response_bytes")
            if len(envelopes) >= max_records:
                raise ValueError("PSRP/CIM result exceeded max_records")
            envelopes.append(
                {
                    "kind": "observation",
                    "type": f"windows.cim.{operation}",
                    "source": str(source),
                    "subject": host,
                    "observed_at": observed_at,
                    "payload": {
                        "operation": operation,
                        "target": host,
                        "data": record,
                    },
                    "idempotency_key": None,
                }
            )
    if not envelopes:
        raise ValueError("PSRP/CIM diagnostics returned no records")
    return envelopes
