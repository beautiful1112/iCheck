from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def _path(value: Any, dotted_path: str | None) -> Any:
    if not dotted_path:
        return value
    current = value
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise ValueError(f"JSON path {dotted_path!r} was not found")
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            try:
                current = current[index]
            except IndexError as exc:
                raise ValueError(
                    f"JSON path {dotted_path!r} was not found"
                ) from exc
        else:
            raise ValueError(f"JSON path {dotted_path!r} was not found")
    return current


def _optional_path(value: Any, dotted_path: str | None) -> Any | None:
    if not dotted_path:
        return None
    try:
        return _path(value, dotted_path)
    except ValueError:
        return None


def _timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    raise ValueError("observed_at_field must resolve to an ISO-8601 string")


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        normalized = pattern.rstrip(".").lower()
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for collector targets",
            headers,
            fp,
        )


def collect_http_json(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect an unauthenticated JSON endpoint into normalized envelopes.

    Authentication is intentionally unavailable until the credential broker is
    implemented. The deployment may contain a credential reference, but never a
    literal token, password, or Authorization header.
    """

    target = assignment.get("target") or {}
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    url = target.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("http_json target.url is required")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("http_json target.url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in target URLs")
    allowed_hosts = (
        assignment.get("_runtime", {}).get("http_allowed_hosts", [])
    )
    if not isinstance(allowed_hosts, list) or not _host_allowed(
        parsed.hostname, allowed_hosts
    ):
        raise ValueError(
            f"HTTP target host {parsed.hostname!r} is not in the worker allowlist"
        )
    if assignment.get("credential_profile_ref"):
        raise ValueError(
            "Credential-backed HTTP collection requires the future credential broker"
        )

    timeout_seconds = int(configuration.get("timeout_seconds", 10))
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    lease_seconds = int(
        assignment.get("_runtime", {}).get("lease_seconds", 60)
    )
    if timeout_seconds + 5 >= lease_seconds:
        raise ValueError(
            "timeout_seconds must leave at least 5 seconds in the run lease"
        )
    max_bytes = int(configuration.get("max_response_bytes", 10_000_000))
    if max_bytes < 1 or max_bytes > 50_000_000:
        raise ValueError("max_response_bytes must be between 1 and 50000000")
    max_records = int(configuration.get("max_records", 2000))
    if max_records < 1 or max_records > 2000:
        raise ValueError("max_records must be between 1 and 2000")

    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "iCheck-collector/0.2"},
        method="GET",
    )
    opener = build_opener(_NoRedirect())
    with opener.open(request, timeout=timeout_seconds) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("HTTP response exceeded max_response_bytes")
    document = json.loads(body.decode("utf-8"))
    records = _path(document, configuration.get("records_path"))
    if not isinstance(records, list):
        records = [records]
    if len(records) > max_records:
        raise ValueError("HTTP response exceeded max_records")

    kind = configuration.get("envelope_kind", "observation")
    allowed_kinds = set(assignment.get("output_kinds") or [])
    if kind not in allowed_kinds:
        raise ValueError(
            f"Envelope kind {kind!r} is not declared by this collector version"
        )
    record_type = configuration.get("record_type", "http.record")
    source = configuration.get(
        "source", f"artifact:{assignment.get('artifact_name', 'unknown')}"
    )
    subject_field = configuration.get("subject_field")
    idempotency_field = configuration.get("idempotency_field")
    observed_at_field = configuration.get("observed_at_field")

    envelopes: list[dict[str, Any]] = []
    for record in records:
        payload = record if isinstance(record, dict) else {"value": record}
        subject = _optional_path(record, subject_field)
        idempotency_key = _optional_path(record, idempotency_field)
        observed_at = _optional_path(record, observed_at_field)
        envelopes.append(
            {
                "kind": kind,
                "type": str(record_type),
                "source": str(source),
                "subject": str(subject) if subject is not None else None,
                "observed_at": _timestamp(observed_at),
                "payload": payload,
                "idempotency_key": (
                    str(idempotency_key)
                    if idempotency_key is not None
                    else None
                ),
            }
        )
    return envelopes
