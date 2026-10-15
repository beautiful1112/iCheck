from __future__ import annotations

import ipaddress
import math
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from .collectors.snmp_exporter import SNMPExporterFailure, collect_snmp_exporter
from .snmp_modules import IDENTITY_MODULE, safe_sysname, validate_modules
from .http_metrics import HTTPMonitorSpec, HTTPMetricError, auth_headers, fetch_http, render_result


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


def require_icmp_preflight_support(address_versions=(4,)):
    """Check local dependency/permission only; never send an echo or probe a host."""
    if shutil.which("ping") is None:
        raise ValueError("ICMP capability requires the ping executable")
    for version in set(address_versions):
        family, protocol = ((socket.AF_INET, socket.IPPROTO_ICMP) if version == 4 else
                            (socket.AF_INET6, socket.IPPROTO_ICMPV6))
        permitted = False
        for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            try:
                with socket.socket(family, kind, protocol):
                    permitted = True
                break
            except OSError:
                continue
        if not permitted:
            raise ValueError("ICMP capability requires an authorized local ICMP socket; configure host permission or omit ICMP")


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
    try:
        requested_modules = validate_modules(configuration.get("modules", ["if_mib"]))
    except ValueError as exc:
        raise DevicePreflightFailure(str(exc), {"check": "snmp_module_catalog", "verified": False,
            "diagnostic": {"code": "snmp_invalid_modules",
                "next_action": "Save valid installed SNMP modules and reverify."}}) from None
    managed = bool((assignment.get("_runtime") or {}).get("credential"))
    template = bool(configuration.get("monitoring_template_version_id"))
    expected = configuration.get("snmp_expected_metrics",[]) if template else []
    if template:
        from .managed_snmp import module_document
        import hashlib,yaml
        actual=module_document()["modules"].get(requested_modules[0]) if len(requested_modules)==1 else None
        if (not managed or not isinstance(expected,list) or not 1<=len(expected)<=32 or actual is None
                or hashlib.sha256(yaml.safe_dump(actual,sort_keys=True).encode()).hexdigest()!=configuration.get("snmp_module_sha256")):
            raise DevicePreflightFailure("Installed SNMP template or protected credential does not match this test",{"check":"snmp_metric_query","success":False})
    configuration["modules"] = requested_modules if managed else ["system"]
    configuration["include_metric_prefixes"] = [m["name"] for m in expected] if template else ["sysName", "sysDescr", "sysObjectID", "sysUpTime"]
    configuration["timeout_seconds"] = timeout_seconds
    configuration["max_metrics"] = min(
        int(configuration.get("max_metrics", 20000 if template else 100)),
        20000 if template else 100,
    )
    configuration["max_response_bytes"] = min(
        int(configuration.get("max_response_bytes", 2_000_000)),
        2_000_000,
    )
    exporter_assignment = {
        "artifact_name": "device-connection-preflight",
        "target": {
            "exporter_url": exporter_url,
            "target": (str(address) if assignment.get("port") in {None, 161}
                else f"[{address}]:{assignment['port']}" if address.version == 6
                else f"{address}:{assignment['port']}"),
        },
        "configuration": configuration,
        "defaults": {},
        "output_kinds": ["observation"],
        "_runtime": {
            "credential": (assignment.get("_runtime") or {}).get("credential", {}),
            "exporter_allowed_hosts": exporter_allowed_hosts,
            "snmp_allowed_targets": snmp_allowed_targets,
            "lease_seconds": lease_seconds,
            "snmp_identity_preflight": not template,
            "snmp_requested_metric_test": template,
        },
    }
    started = time.monotonic()
    try:
        samples = collect_snmp_exporter(exporter_assignment)
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        raise DevicePreflightFailure(
            "Requested SNMP metric test failed; check module, credential and device support" if template else f"SNMP Exporter query failed: {exc}",
            {
                "check": "snmp_exporter_query",
                "verification_level": "protocol_query",
                "verified": False,
                "diagnostic": (exc.diagnostic if isinstance(exc, SNMPExporterFailure) else
                    {"code": "snmp_query_failed", "next_action": "Check target policy, exporter setup and SNMP reachability."}),
            },
            latency_ms,
        ) from exc
    latency_ms = int((time.monotonic() - started) * 1000)
    if template:
        import math
        current=module_document()["modules"].get(requested_modules[0])
        if current is None or hashlib.sha256(yaml.safe_dump(current,sort_keys=True).encode()).hexdigest()!=configuration["snmp_module_sha256"]:
            raise DevicePreflightFailure("Installed SNMP module changed during the requested-metric test",{"check":"snmp_metric_query","success":False})
        wanted={m["name"] for m in expected}
        counter_aliases={m["name"]+"_total":m["name"] for m in expected if m["type"]=="counter"}
        names=set(); count=0
        for sample in samples:
            payload=sample.get("payload",{}); name=payload.get("metric")
            name=counter_aliases.get(name,name)
            value=payload.get("value")
            if name in wanted and isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value):
                names.add(name); count+=1
        if names!=wanted:
            raise DevicePreflightFailure("Device did not return every requested SNMP metric",{"check":"snmp_metric_query","success":False,"metric_names":sorted(names)})
        return {"check":"snmp_metric_query","success":True,"verification_level":"requested_metrics",
            "modules":requested_modules,"module_sha256":configuration["snmp_module_sha256"],
            "metric_names":sorted(names),"metric_samples":count,"target_host":str(address),
            "target_port":assignment.get("port"),"credential_revision":(assignment.get("_runtime") or {}).get("credential_revision")},latency_ms
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
    discovered = {safe_sysname(sample.get("payload", {}).get("labels", {}).get("sysName"))
        for sample in samples if sample.get("payload", {}).get("metric") == "sysName"}
    discovered.discard(None)
    secret_values = (assignment.get("_runtime") or {}).get("credential", {}).values()
    discovered = {name for name in discovered if not any(isinstance(secret, str) and secret and secret in name
        for secret in secret_values)}
    evidence = {
            "check": "snmp_exporter_query",
            "verification_level": "protocol_query",
            "verified": True,
            "sample_count": len(samples),
            "modules": [IDENTITY_MODULE] if managed else ["system"],
            "monitoring_modules": requested_modules,
            "auth_module": "managed" if managed else configuration.get("auth_module", "public_v2"),
            "target_host": str(address),
        }
    if len(discovered) == 1:
        evidence["discovered_name"] = next(iter(discovered))
    return evidence, latency_ms


def _http_preflight(assignment, address, *, timeout_seconds, lease_seconds):
    try:
        spec = HTTPMonitorSpec.model_validate(assignment["configuration"]["http_monitor"])
        if spec.scheme == "http" and spec.auth_mode != "none":
            raise HTTPMetricError("HTTP authentication requires verified HTTPS")
        values = (assignment.get("_runtime") or {}).get("credential")
        headers = auth_headers(spec, values)
        result = fetch_http(spec, str(address), assignment["port"], headers,
            deadline=time.monotonic() + min(timeout_seconds, max(1, lease_seconds - 5)))
        _, evidence = render_result(spec, result, values=values, headers=headers)
        if not evidence["success"]:
            raise HTTPMetricError("Target returned an unexpected status; no metric test succeeded")
        evidence.update(check="http_metric_query", verification_level="protocol_query", verified=True,
            target_host=str(address), target_port=assignment["port"],
            credential_revision=(assignment.get("_runtime") or {}).get("credential_revision"))
        return evidence, evidence["latency_ms"]
    except (ValueError, KeyError, TypeError):
        raise DevicePreflightFailure("HTTP metric test failed; inspect the template, target policy, TLS and protected credential",
            {"check": "http_metric_query", "verified": False}) from None


def _exporter_preflight(assignment, address, *, timeout_seconds, lease_seconds):
    from .exporter_metrics import ExporterMonitorSpec, PROTOCOLS, collect
    try:
        spec = ExporterMonitorSpec.model_validate(assignment["configuration"]["exporter_monitor"])
        if assignment["adapter_type"] != PROTOCOLS[spec.plugin]:
            raise ValueError("Exporter platform and connection must match")
        runtime = assignment.get("_runtime") or {}
        _, evidence = collect(spec, str(address), assignment["port"],
            values=runtime.get("credential"),
            deadline=time.monotonic() + min(timeout_seconds, max(1, lease_seconds - 5)))
        evidence.update(check="native_exporter_metric_query", verification_level="protocol_query", verified=True,
            target_host=str(address), target_port=assignment["port"], credential_revision=runtime.get("credential_revision"))
        return evidence, evidence["latency_ms"]
    except (ValueError, KeyError, TypeError):
        raise DevicePreflightFailure("Exporter metric test failed; check the selected collectors, target policy, TLS and credential",
            {"check": "native_exporter_metric_query", "success": False, "verified": False}) from None


# Reachability/transport checks and native exporter tests are not ordinary
# Collector envelope jobs. Routine exporter metrics belong to Prometheus.
PREFLIGHT_ONLY_ADAPTERS = frozenset({"icmp", "ssh", "node_exporter", "cadvisor", "vmware_exporter"})


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
    if adapter_type in {"node_exporter", "windows_exporter", "cadvisor", "vmware_exporter"} and (assignment.get("configuration") or {}).get("exporter_monitor"):
        return _exporter_preflight(assignment, address, timeout_seconds=timeout_seconds, lease_seconds=lease_seconds)
    if adapter_type == "http_json" and (assignment.get("configuration") or {}).get("http_monitor") is not None:
        return _http_preflight(assignment, address, timeout_seconds=timeout_seconds, lease_seconds=lease_seconds)
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
        "node_exporter",
        "cadvisor",
        "vmware_exporter",
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
