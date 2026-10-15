from __future__ import annotations

import ipaddress
import math
import re
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from prometheus_client.parser import text_string_to_metric_families


NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


class SNMPExporterFailure(ValueError):
    """Recognized, bounded diagnostics; never retain the raw exporter body."""
    def __init__(self, message, diagnostic):
        super().__init__(message)
        self.diagnostic = diagnostic


def _http_failure(error, modules, auth_module):
    try:
        body = error.read(4097).decode("utf-8", "replace").strip()
    except Exception:
        body = ""
    finally:
        error.close()
    for kind, allowed in (("module", modules), ("auth", [auth_module])):
        match = re.fullmatch(r"Unknown " + kind + r" ['\"]([A-Za-z0-9_.-]{1,128})['\"]", body)
        if error.code == 400 and match and match[1] in allowed:
            name = match[1]
            return SNMPExporterFailure(f"SNMP Exporter HTTP 400: Unknown {kind} '{name}'. "
                "Correct the connection using the installed exporter catalog; this is not a community rejection.",
                {"code": f"snmp_unknown_{kind}", "http_status": 400, kind: name,
                 "next_action": "Correct the exporter module/auth configuration and reverify."})
    return SNMPExporterFailure(f"SNMP Exporter returned HTTP {error.code}. "
        "No recognized safe diagnostic was returned; this alone does not prove an invalid community.",
        {"code": "snmp_exporter_http_error", "http_status": error.code,
         "next_action": "Review exporter configuration, reachability and SNMP access; raw response withheld."})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for SNMP exporter targets",
            headers,
            fp,
        )


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


def _target_host(target: str) -> str:
    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme not in {"udp", "udp6", "tcp", "tcp6"}:
            raise ValueError("SNMP target transport must be udp, udp6, tcp, or tcp6")
    else:
        parsed = urlsplit(f"//{target}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("SNMP target must contain a valid host without credentials")
    return parsed.hostname


def _name_list(value: Any, field: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must contain at least one name")
    if len(value) > maximum:
        raise ValueError(f"{field} must contain at most {maximum} names")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not NAME_PATTERN.fullmatch(item):
            raise ValueError(f"{field} contains an invalid name")
        if item not in names:
            names.append(item)
    return names


def _sample_timestamp(value: Any, fallback: datetime) -> str:
    if value is None:
        return fallback.isoformat()
    try:
        return datetime.fromtimestamp(float(value), UTC).isoformat()
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("SNMP exporter returned an invalid sample timestamp") from exc


def collect_snmp_exporter(
    assignment: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run a bounded scrape through a preconfigured Prometheus SNMP Exporter."""

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    exporter_url = target.get("exporter_url")
    snmp_target = target.get("target")
    if not isinstance(exporter_url, str) or not exporter_url:
        raise ValueError("snmp_exporter target.exporter_url is required")
    if not isinstance(snmp_target, str) or not snmp_target:
        raise ValueError("snmp_exporter target.target is required")
    parsed_exporter = urlsplit(exporter_url)
    if (
        parsed_exporter.scheme not in {"http", "https"}
        or not parsed_exporter.hostname
    ):
        raise ValueError("target.exporter_url must be an HTTP(S) URL")
    if parsed_exporter.username or parsed_exporter.password:
        raise ValueError("Credentials are not allowed in exporter URLs")
    if parsed_exporter.query or parsed_exporter.fragment:
        raise ValueError("target.exporter_url must not contain query or fragment")

    runtime = assignment.get("_runtime", {})
    exporter_hosts = runtime.get("exporter_allowed_hosts", [])
    if not isinstance(exporter_hosts, list) or not _host_allowed(
        parsed_exporter.hostname,
        exporter_hosts,
    ):
        raise ValueError(
            f"SNMP exporter host {parsed_exporter.hostname!r} is not allowlisted"
        )
    snmp_host = _target_host(snmp_target)
    allowed_targets = runtime.get("snmp_allowed_targets", [])
    if not isinstance(allowed_targets, list) or not _host_allowed(
        snmp_host,
        allowed_targets,
    ):
        raise ValueError(f"SNMP target host {snmp_host!r} is not allowlisted")

    modules = _name_list(
        configuration.get("modules", ["if_mib"]),
        "modules",
        maximum=8,
    )
    credential = runtime.get("credential", {})
    if credential:
        from ..managed_snmp import exporter, module_document
        from ..snmp_modules import IDENTITY_MODULE, validate_modules
        validate_modules(modules, available=module_document()["modules"])
        identity_only = bool(runtime.get("snmp_identity_preflight"))
        with exporter(credential, timeout_seconds=int(configuration.get("timeout_seconds", 15)),
            identity_only=identity_only, requested_modules=modules) as local_url:
            isolated = {**assignment, "target": {**target, "exporter_url": local_url},
                "configuration": {**configuration, "auth_module": "managed",
                    "modules": [IDENTITY_MODULE] if identity_only else modules},
                "_runtime": {**runtime, "credential": {}, "exporter_allowed_hosts": ["127.0.0.1"]}}
            return collect_snmp_exporter(isolated)
    auth_module = configuration.get("auth_module", "public_v2")
    if not isinstance(auth_module, str) or not NAME_PATTERN.fullmatch(auth_module):
        raise ValueError("auth_module contains an invalid name")
    timeout_seconds = int(configuration.get("timeout_seconds", 15))
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    lease_seconds = int(runtime.get("lease_seconds", 60))
    if timeout_seconds + 5 >= lease_seconds:
        raise ValueError(
            "timeout_seconds must leave at least 5 seconds in the run lease"
        )
    max_bytes = int(configuration.get("max_response_bytes", 10_000_000))
    if max_bytes < 1 or max_bytes > 50_000_000:
        raise ValueError("max_response_bytes must be between 1 and 50000000")
    max_metrics = int(configuration.get("max_metrics", 2000))
    inventory_mode = configuration.get("inventory_tables") is True
    if "inventory_tables" in configuration and type(configuration["inventory_tables"]) is not bool:
        raise ValueError("inventory_tables must be a boolean")
    if inventory_mode and configuration.get("inventory_vlan_context") is not None:
        if runtime.get("snmp_inventory_context_vlan") != configuration["inventory_vlan_context"]:
            raise ValueError("Inventory VLAN labeling requires a runtime-verified SNMP context")
    metric_limit = 20000 if runtime.get("snmp_requested_metric_test") or inventory_mode else 2000
    if max_metrics < 1 or max_metrics > metric_limit:
        raise ValueError(f"max_metrics must be between 1 and {metric_limit}")
    include_prefixes = configuration.get("include_metric_prefixes", [])
    if not isinstance(include_prefixes, list) or any(
        not isinstance(item, str) for item in include_prefixes
    ):
        raise ValueError("include_metric_prefixes must be a list of strings")

    parameters: list[tuple[str, str]] = [
        ("target", snmp_target),
        ("auth", auth_module),
    ]
    parameters.extend(("module", module) for module in modules)
    url = f"{exporter_url.rstrip('/')}/snmp?{urlencode(parameters)}"
    request = Request(
        url,
        headers={
            "Accept": "text/plain; version=0.0.4",
            "User-Agent": "iCheck-collector/0.4",
        },
        method="GET",
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout_seconds) as response:
            body = response.read(max_bytes + 1)
    except HTTPError as exc:
        raise _http_failure(exc, modules, auth_module) from None
    if len(body) > max_bytes:
        raise ValueError("SNMP exporter response exceeded max_response_bytes")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("SNMP exporter response is not UTF-8") from exc

    allowed_kinds = set(assignment.get("output_kinds") or [])
    if "observation" not in allowed_kinds:
        raise ValueError(
            "SNMP exporter collectors must declare observation output"
        )
    collected_at = datetime.now(UTC)
    source = configuration.get(
        "source",
        f"snmp_exporter:{assignment.get('artifact_name', 'unknown')}",
    )
    envelopes: list[dict[str, Any]] = []
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if include_prefixes and not any(
                sample.name.startswith(prefix) for prefix in include_prefixes
            ):
                continue
            if len(envelopes) >= max_metrics:
                raise ValueError("SNMP exporter response exceeded max_metrics")
            numeric_value = float(sample.value)
            value: float | str = (
                numeric_value if math.isfinite(numeric_value) else str(numeric_value)
            )
            envelopes.append(
                {
                    "kind": "observation",
                    "type": "metric.sample",
                    "source": str(source),
                    "subject": snmp_target,
                    "observed_at": _sample_timestamp(
                        sample.timestamp,
                        collected_at,
                    ),
                    "payload": {
                        "metric": sample.name,
                        "labels": dict(sorted(sample.labels.items())),
                        "value": value,
                        "target": snmp_target,
                        "modules": modules,
                        "auth_module": auth_module,
                    },
                    "idempotency_key": None,
                }
            )
    if not envelopes and not runtime.get("allow_empty_snmp_metrics", False):
        raise ValueError("SNMP exporter response contained no selected metrics")
    if inventory_mode:
        from .snmp_inventory import normalize_tables
        return normalize_tables(envelopes, target=snmp_target, source=str(source),
            context_vlan=configuration.get("inventory_vlan_context"),
            max_endpoints=configuration.get("max_inventory_endpoints", 2000))
    return envelopes
