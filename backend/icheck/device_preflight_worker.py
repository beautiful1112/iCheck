from __future__ import annotations

import ipaddress
import math
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from .collectors.snmp_exporter import collect_snmp_exporter


@dataclass
class DevicePreflightFailure(Exception):
    message: str
    evidence: dict[str, Any]
    latency_ms: int | None = None

    def __str__(self) -> str:
        return self.message


def _target_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, patterns: list[str]) -> bool:
    for pattern in patterns:
        value = pattern.strip()
        if not value:
            continue
        try:
            if "/" in value:
                if address in ipaddress.ip_network(value, strict=False):
                    return True
            elif address == ipaddress.ip_address(value):
                return True
        except ValueError:
            continue
    return False


def _bounded_target(
    assignment: dict[str, Any],
    allowed_targets: list[str],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    target = assignment.get("target_host")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise DevicePreflightFailure(
            "Device preflight target must be a valid IP address",
            {"check": "target_policy", "allowed": False},
        ) from exc
    if not _target_allowed(address, allowed_targets):
        raise DevicePreflightFailure(
            f"Device preflight target {address} is not allowlisted",
            {
                "check": "target_policy",
                "allowed": False,
                "address_family": address.version,
            },
        )
    return address


def _tcp_preflight(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int | None,
    *,
    adapter_type: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    if port is None:
        raise DevicePreflightFailure(
            f"{adapter_type} preflight requires a TCP port",
            {"check": "tcp_connect", "reachable": False},
        )
    started = time.monotonic()
    try:
        with socket.create_connection(
            (str(address), port),
            timeout=timeout_seconds,
        ):
            pass
    except OSError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        raise DevicePreflightFailure(
            f"TCP connection to port {port} failed: {exc}",
            {
                "check": "tcp_connect",
                "verification_level": "transport",
                "authentication_tested": False,
                "reachable": False,
                "port": port,
                "address_family": address.version,
            },
            latency_ms,
        ) from exc
    latency_ms = int((time.monotonic() - started) * 1000)
    return (
        {
            "check": "tcp_connect",
            "verification_level": "transport",
            "authentication_tested": False,
            "reachable": True,
            "port": port,
            "address_family": address.version,
        },
        latency_ms,
    )


def _icmp_preflight(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    executable = shutil.which("ping")
    if executable is None:
        raise DevicePreflightFailure(
            "ICMP preflight requires the ping executable",
            {"check": "icmp_echo", "reachable": False},
        )
    command = [executable]
    if address.version == 6:
        command.append("-6")
    command.extend(
        [
            "-n",
            "-c",
            "1",
            "-W",
            str(max(1, math.ceil(timeout_seconds))),
            str(address),
        ]
    )
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds + 1,
        )
    except subprocess.TimeoutExpired as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        raise DevicePreflightFailure(
            "ICMP echo timed out",
            {
                "check": "icmp_echo",
                "verification_level": "network_reachability",
                "reachable": False,
                "address_family": address.version,
            },
            latency_ms,
        ) from exc
    latency_ms = int((time.monotonic() - started) * 1000)
    evidence = {
        "check": "icmp_echo",
        "verification_level": "network_reachability",
        "reachable": result.returncode == 0,
        "address_family": address.version,
    }
    if result.returncode != 0:
        raise DevicePreflightFailure(
            "ICMP echo did not receive a reply",
            evidence,
            latency_ms,
        )
    return evidence, latency_ms


def _snmp_preflight(
    assignment: dict[str, Any],
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    exporter_url: str | None,
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    timeout_seconds: int,
    lease_seconds: int,
) -> tuple[dict[str, Any], int]:
    if not exporter_url:
        raise DevicePreflightFailure(
            "SNMP preflight requires a site-local SNMP Exporter URL",
            {"check": "snmp_exporter_query", "verified": False},
        )
    configuration = dict(assignment.get("configuration") or {})
    configuration["timeout_seconds"] = timeout_seconds
    configuration["max_metrics"] = min(
        int(configuration.get("max_metrics", 100)),
        100,
    )
    configuration["max_response_bytes"] = min(
        int(configuration.get("max_response_bytes", 2_000_000)),
        2_000_000,
    )
    exporter_assignment = {
        "artifact_name": "device-connection-preflight",
        "target": {
            "exporter_url": exporter_url,
            "target": str(address),
        },
        "configuration": configuration,
        "defaults": {},
        "output_kinds": ["observation"],
        "_runtime": {
            "exporter_allowed_hosts": exporter_allowed_hosts,
            "snmp_allowed_targets": snmp_allowed_targets,
            "lease_seconds": lease_seconds,
        },
    }
    started = time.monotonic()
    try:
        samples = collect_snmp_exporter(exporter_assignment)
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        raise DevicePreflightFailure(
            f"SNMP Exporter query failed: {exc}",
            {
                "check": "snmp_exporter_query",
                "verification_level": "protocol_query",
                "verified": False,
            },
            latency_ms,
        ) from exc
    latency_ms = int((time.monotonic() - started) * 1000)
    if not samples:
        raise DevicePreflightFailure(
            "SNMP Exporter query returned no metric samples",
            {
                "check": "snmp_exporter_query",
                "verification_level": "protocol_query",
                "verified": False,
                "sample_count": 0,
            },
            latency_ms,
        )
    return (
        {
            "check": "snmp_exporter_query",
            "verification_level": "protocol_query",
            "verified": True,
            "sample_count": len(samples),
            "modules": configuration.get("modules", ["if_mib"]),
            "auth_module": configuration.get("auth_module", "public_v2"),
        },
        latency_ms,
    )


def execute_device_preflight(
    assignment: dict[str, Any],
    *,
    allowed_targets: list[str],
    timeout_seconds: int,
    snmp_exporter_url: str | None,
    exporter_allowed_hosts: list[str],
    snmp_allowed_targets: list[str],
    lease_seconds: int,
) -> tuple[dict[str, Any], int]:
    address = _bounded_target(assignment, allowed_targets)
    adapter_type = assignment.get("adapter_type")
    if adapter_type == "icmp":
        return _icmp_preflight(address, timeout_seconds=timeout_seconds)
    if adapter_type == "snmp_exporter":
        return _snmp_preflight(
            assignment,
            address,
            exporter_url=snmp_exporter_url,
            exporter_allowed_hosts=exporter_allowed_hosts,
            snmp_allowed_targets=snmp_allowed_targets,
            timeout_seconds=timeout_seconds,
            lease_seconds=lease_seconds,
        )
    if adapter_type in {
        "http_json",
        "ssh",
        "windows_exporter",
        "psrp_cim",
    }:
        return _tcp_preflight(
            address,
            assignment.get("port"),
            adapter_type=adapter_type,
            timeout_seconds=timeout_seconds,
        )
    raise DevicePreflightFailure(
        f"No device preflight executor is registered for {adapter_type!r}",
        {"check": "executor_registry", "supported": False},
    )
