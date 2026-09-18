from __future__ import annotations

import ipaddress
import math
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from prometheus_client.parser import text_string_to_metric_families


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for Windows exporter targets",
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


def _sample_timestamp(value: Any, fallback: datetime) -> str:
    if value is None:
        return fallback.isoformat()
    try:
        return datetime.fromtimestamp(float(value), UTC).isoformat()
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            "Windows exporter returned an invalid sample timestamp"
        ) from exc


def _names(value: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    if len(value) > maximum:
        raise ValueError(f"{field} must contain at most {maximum} values")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 128:
            raise ValueError(f"{field} contains an invalid value")
        if item not in result:
            result.append(item)
    return result


def collect_windows_exporter(
    assignment: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect a bounded windows_exporter sample for preview and evidence."""

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    url = target.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("windows_exporter target.url is required")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("windows_exporter target.url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in exporter URLs")
    if parsed.query or parsed.fragment:
        raise ValueError("windows_exporter target.url must not contain query or fragment")
    if parsed.path not in {"", "/", "/metrics"}:
        raise ValueError("windows_exporter target.url path must be /metrics")
    runtime = assignment.get("_runtime", {})
    allowed_hosts = runtime.get("windows_exporter_allowed_hosts", [])
    if not isinstance(allowed_hosts, list) or not _host_allowed(
        parsed.hostname,
        allowed_hosts,
    ):
        raise ValueError(
            f"Windows exporter host {parsed.hostname!r} is not allowlisted"
        )
    if assignment.get("credential_profile_ref"):
        raise ValueError(
            "Credential-backed Windows exporter scraping is not enabled; "
            "use a protected Prometheus scrape path"
        )

    collectors = _names(configuration.get("collectors", []), "collectors", 32)
    include_prefixes = _names(
        configuration.get("include_metric_prefixes", ["windows_"]),
        "include_metric_prefixes",
        32,
    )
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
    if max_metrics < 1 or max_metrics > 2000:
        raise ValueError("max_metrics must be between 1 and 2000")

    metrics_url = url.rstrip("/")
    if not metrics_url.endswith("/metrics"):
        metrics_url = f"{metrics_url}/metrics"
    if collectors:
        metrics_url = f"{metrics_url}?{urlencode([('collect[]', item) for item in collectors])}"
    request = Request(
        metrics_url,
        headers={
            "Accept": "text/plain; version=0.0.4",
            "User-Agent": "iCheck-collector/0.5",
        },
        method="GET",
    )
    with build_opener(_NoRedirect()).open(
        request,
        timeout=timeout_seconds,
    ) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("Windows exporter response exceeded max_response_bytes")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Windows exporter response is not UTF-8") from exc

    allowed_kinds = set(assignment.get("output_kinds") or [])
    if "observation" not in allowed_kinds:
        raise ValueError(
            "Windows exporter collectors must declare observation output"
        )
    collected_at = datetime.now(UTC)
    source = configuration.get(
        "source",
        f"windows_exporter:{assignment.get('artifact_name', 'unknown')}",
    )
    envelopes: list[dict[str, Any]] = []
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if include_prefixes and not any(
                sample.name.startswith(prefix) for prefix in include_prefixes
            ):
                continue
            if len(envelopes) >= max_metrics:
                raise ValueError("Windows exporter response exceeded max_metrics")
            numeric_value = float(sample.value)
            value: float | str = (
                numeric_value if math.isfinite(numeric_value) else str(numeric_value)
            )
            envelopes.append(
                {
                    "kind": "observation",
                    "type": "metric.sample",
                    "source": str(source),
                    "subject": parsed.hostname,
                    "observed_at": _sample_timestamp(
                        sample.timestamp,
                        collected_at,
                    ),
                    "payload": {
                        "exporter": "windows_exporter",
                        "metric": sample.name,
                        "labels": dict(sorted(sample.labels.items())),
                        "value": value,
                        "target": parsed.hostname,
                        "collectors": collectors,
                    },
                    "idempotency_key": None,
                }
            )
    if not envelopes:
        raise ValueError("Windows exporter response contained no selected metrics")
    return envelopes
