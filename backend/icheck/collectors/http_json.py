from __future__ import annotations

import base64
import json
import re
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


SAFE_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
FORBIDDEN_CREDENTIAL_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}


def _credential_headers(
    credential: dict[str, str],
    configuration: dict[str, Any],
) -> dict[str, str]:
    if not credential:
        raise ValueError("Resolved HTTP credential is empty")
    if "authorization" in credential:
        return {"Authorization": credential["authorization"]}
    token = credential.get("bearer_token") or credential.get("token")
    if token:
        mode = str(configuration.get("credential_mode", "bearer"))
        if mode == "bearer":
            return {"Authorization": f"Bearer {token}"}
        if mode == "api_key":
            header = str(configuration.get("credential_header", "X-API-Key"))
            if (
                SAFE_HEADER.fullmatch(header) is None
                or header.lower() in FORBIDDEN_CREDENTIAL_HEADERS
            ):
                raise ValueError("credential_header is not allowed")
            return {header: token}
        raise ValueError("credential_mode must be bearer or api_key")
    username = credential.get("username")
    password = credential.get("password")
    if username and password:
        encoded = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    raise ValueError(
        "HTTP credential requires authorization, token, bearer_token, or "
        "username/password values"
    )


def collect_http_json(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect an allowlisted JSON endpoint into normalized envelopes."""

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
    credential_ref = assignment.get("credential_profile_ref")
    runtime_credential = assignment.get("_runtime", {}).get("credential")
    if credential_ref and not isinstance(runtime_credential, dict):
        raise ValueError("Credential-backed HTTP collection was not resolved")

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

    headers = {
        "Accept": "application/json",
        "User-Agent": "iCheck-collector/0.3",
    }
    if credential_ref:
        headers.update(_credential_headers(runtime_credential, configuration))
    request = Request(
        url,
        headers=headers,
        method="GET",
    )
    opener = build_opener(_NoRedirect())
    with opener.open(request, timeout=timeout_seconds) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("HTTP response exceeded max_response_bytes")
    document = json.loads(body.decode("utf-8"))
    return document_to_envelopes(assignment, document, configuration)


def document_to_envelopes(
    assignment: dict[str, Any],
    document: Any,
    configuration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Normalize a trusted adapter's bounded JSON result into envelopes."""

    max_records = int(configuration.get("max_records", 2000))
    if max_records < 1 or max_records > 2000:
        raise ValueError("max_records must be between 1 and 2000")
    records = _path(document, configuration.get("records_path"))
    if not isinstance(records, list):
        records = [records]
    if len(records) > max_records:
        raise ValueError("JSON document exceeded max_records")

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
        subject = _optional_path(payload, subject_field)
        idempotency_key = _optional_path(payload, idempotency_field)
        observed_at = _path(payload, observed_at_field) if observed_at_field else None
        if observed_at_field and observed_at is None:
            raise ValueError("Configured observed_at_field cannot be missing or null")
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
