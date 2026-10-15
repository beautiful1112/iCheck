from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..credentials import CredentialUnavailable
from ..log_schemas import (
    LogBackendCreate,
    LogBackendHealth,
    LogBackendUpdate,
    LogEntry,
    LogQueryRange,
    LogQueryResult,
)
from ..models import LogBackend, utcnow
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .observability_auth import (
    resolve_backend_auth,
    validate_backend_credential_profile,
)


MAX_LOG_RESPONSE_BYTES = 5_000_000
MAX_LOG_LINE_CHARS = 4_096
_SENSITIVE_LABELS = {
    "authorization",
    "email",
    "password",
    "passwd",
    "secret",
    "token",
    "username",
    "user",
}
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}")
_BASIC_PATTERN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
    r"(\s*[=:]\s*)"
    r"(?:\"[^\"\r\n]{0,2048}\"|'[^'\r\n]{0,2048}'|[^\s,;]{1,2048})"
)


class LogQueryError(ValueError):
    pass


class LogBackendUnavailable(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for log backends",
            headers,
            fp,
        )


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


def _validate_url(url: str, allowed_hosts: list[str]) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("query_base_url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("query_base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("query_base_url must not contain a query or fragment")
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError(
            f"query_base_url host {parsed.hostname!r} is not in the logs allowlist"
        )
    return url.rstrip("/")


def create_log_backend(
    db: Session,
    payload: LogBackendCreate,
    *,
    allowed_hosts: list[str],
) -> LogBackend:
    query_base_url = _validate_url(payload.query_base_url, allowed_hosts)
    if any(label.lower() in _SENSITIVE_LABELS for label in payload.allowed_labels):
        raise ValueError("allowed_labels contains a sensitive identity or secret label")
    assert_no_inline_secrets(payload.allowed_labels, "allowed_labels")
    validate_backend_credential_profile(
        db,
        auth_type=payload.auth_type,
        auth_header_name=payload.auth_header_name,
        credential_profile_ref=payload.credential_profile_ref,
        adapter_type="loki_query",
    )
    backend = LogBackend(
        **payload.model_dump(exclude={"query_base_url"}),
        query_base_url=query_base_url,
    )
    db.add(backend)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="logs.backend.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="log_backend",
            entity_id=backend.id,
            details={
                "provider": backend.provider,
                "query_host": urlsplit(query_base_url).hostname,
                "credential_profile_configured": bool(
                    backend.credential_profile_ref
                ),
                "auth_type": backend.auth_type,
                "auth_header_name": backend.auth_header_name,
                "device_label": backend.device_label,
                "allowed_label_count": len(backend.allowed_labels),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Log backend name already exists") from exc
    db.refresh(backend)
    return backend


def get_log_backend(db: Session, backend_id: str) -> LogBackend:
    backend = db.get(LogBackend, backend_id)
    if backend is None:
        raise LookupError("Log backend not found")
    return backend


def update_log_backend(
    db: Session,
    backend: LogBackend,
    payload: LogBackendUpdate,
    *,
    allowed_hosts: list[str],
) -> LogBackend:
    db.refresh(backend, with_for_update=True)
    if backend.revision != payload.expected_revision:
        raise ValueError(
            "Log backend revision conflict: "
            f"expected {payload.expected_revision}, current {backend.revision}"
        )
    query_base_url = _validate_url(payload.query_base_url, allowed_hosts)
    if any(label.lower() in _SENSITIVE_LABELS for label in payload.allowed_labels):
        raise ValueError("allowed_labels contains a sensitive identity or secret label")
    assert_no_inline_secrets(payload.allowed_labels, "allowed_labels")
    validate_backend_credential_profile(
        db,
        auth_type=payload.auth_type,
        auth_header_name=payload.auth_header_name,
        credential_profile_ref=payload.credential_profile_ref,
        adapter_type="loki_query",
    )
    previous = {
        "name": backend.name,
        "provider": backend.provider,
        "query_base_url": backend.query_base_url,
        "auth_type": backend.auth_type,
        "auth_header_name": backend.auth_header_name,
        "credential_profile_ref": backend.credential_profile_ref,
        "device_label": backend.device_label,
        "allowed_labels": backend.allowed_labels,
        "enabled": backend.enabled,
    }
    current = {
        "name": payload.name,
        "provider": payload.provider,
        "query_base_url": query_base_url,
        "auth_type": payload.auth_type,
        "auth_header_name": payload.auth_header_name,
        "credential_profile_ref": payload.credential_profile_ref,
        "device_label": payload.device_label,
        "allowed_labels": payload.allowed_labels,
        "enabled": payload.enabled,
    }
    changed_fields = sorted(
        field
        for field in current
        if field != "credential_profile_ref" and previous[field] != current[field]
    )
    if previous["credential_profile_ref"] != current["credential_profile_ref"]:
        changed_fields.append("credential_profile")
    if not changed_fields:
        raise ValueError("Log backend update does not change any fields")
    for field, value in current.items():
        setattr(backend, field, value)
    backend.revision += 1
    backend.last_checked_at = None
    backend.last_health_status = None
    backend.last_health_error = None
    backend.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="logs.backend.updated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="log_backend",
        entity_id=backend.id,
        details={
            "revision": backend.revision,
            "changed_fields": sorted(changed_fields),
            "query_host": urlsplit(query_base_url).hostname,
            "auth_type": backend.auth_type,
            "auth_header_name": backend.auth_header_name,
            "credential_profile_configured": bool(
                backend.credential_profile_ref
            ),
            "device_label": backend.device_label,
            "allowed_label_count": len(backend.allowed_labels),
            "enabled": backend.enabled,
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Log backend name already exists") from exc
    db.refresh(backend)
    return backend


def build_device_log_query(
    backend: LogBackend,
    *,
    device_name: str,
    management_ip: str | None,
) -> tuple[str, re.Pattern[str]]:
    aliases = [device_name]
    if management_ip:
        aliases.append(management_ip)
        if ":" in management_ip:
            aliases.append(f"[{management_ip}]")
    aliases = list(dict.fromkeys(aliases))
    pattern = (
        "^(?:" + "|".join(re.escape(item) for item in aliases) + ")"
        "(?::[0-9]{1,5})?$"
    )
    return (
        f"{{{backend.device_label}=~{json.dumps(pattern)}}}",
        re.compile(pattern),
    )


def assert_device_log_result(
    backend: LogBackend,
    result: LogQueryResult,
    matcher: re.Pattern[str],
) -> None:
    for entry in result.entries:
        label_value = entry.labels.get(backend.device_label)
        if not isinstance(label_value, str) or matcher.fullmatch(label_value) is None:
            raise PermissionError(
                "Log backend returned an entry outside the device selector"
            )


def _iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _request_loki(
    db: Session,
    backend: LogBackend,
    payload: LogQueryRange,
) -> dict[str, Any]:
    if not backend.enabled:
        raise LogBackendUnavailable("Log backend is disabled")
    try:
        auth = resolve_backend_auth(
            db,
            auth_type=backend.auth_type,
            auth_header_name=backend.auth_header_name,
            credential_profile_ref=backend.credential_profile_ref,
            adapter_type="loki_query",
        )
    except (CredentialUnavailable, ValueError) as exc:
        raise LogBackendUnavailable(
            f"Log backend credential is unavailable: {exc}"
        ) from exc
    try:
        base_url = _validate_url(
            backend.query_base_url,
            get_settings().logs_allowed_host_list,
        )
    except ValueError as exc:
        raise LogBackendUnavailable(str(exc)) from exc
    fields = {
        "query": payload.query,
        "start": _iso_timestamp(payload.start),
        "end": _iso_timestamp(payload.end),
        "direction": payload.direction,
        "limit": str(payload.limit),
    }
    request = Request(
        f"{base_url}/loki/api/v1/query_range?{urlencode(fields)}",
        headers={
            "Accept": "application/json",
            "User-Agent": "iCheck-logs/0.1",
            **auth.headers,
        },
        method="GET",
    )
    try:
        with build_opener(_NoRedirect()).open(
            request,
            timeout=payload.timeout_seconds + 2,
        ) as response:
            body = response.read(MAX_LOG_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        body = exc.read(MAX_LOG_RESPONSE_BYTES + 1)
        message = f"Loki query returned HTTP {exc.code}"
        try:
            document = json.loads(body.decode("utf-8"))
            if isinstance(document, dict) and isinstance(document.get("error"), str):
                message = auth.redactor.redact_text(document["error"][:1000])
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        if exc.code in {400, 422}:
            raise LogQueryError(message) from exc
        raise LogBackendUnavailable(message) from exc
    except (OSError, URLError) as exc:
        raise LogBackendUnavailable(
            "Log backend request failed: "
            f"{auth.redactor.redact_text(str(exc))}"
        ) from exc
    if len(body) > MAX_LOG_RESPONSE_BYTES:
        raise LogBackendUnavailable(
            "Log backend response exceeded the 5000000 byte limit"
        )
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LogBackendUnavailable("Log backend returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise LogBackendUnavailable("Log backend returned an invalid envelope")
    document = auth.redactor.redact_value(document)
    assert isinstance(document, dict)
    if document.get("status") != "success":
        error = document.get("error")
        raise LogQueryError(
            auth.redactor.redact_text(str(error)[:1000])
            if error
            else "Loki query failed"
        )
    data = document.get("data")
    if not isinstance(data, dict) or data.get("resultType") != "streams":
        raise LogBackendUnavailable("Log backend must return a streams result")
    if not isinstance(data.get("result"), list):
        raise LogBackendUnavailable("Log backend response is missing streams")
    return document


def _sanitize_line(line: Any) -> str:
    if not isinstance(line, str):
        raise LogBackendUnavailable("Log entry line must be a string")
    line = _BEARER_PATTERN.sub("Bearer [REDACTED]", line)
    line = _BASIC_PATTERN.sub("Basic [REDACTED]", line)
    line = _ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        line,
    )
    if len(line) > MAX_LOG_LINE_CHARS:
        line = line[: MAX_LOG_LINE_CHARS - 1] + "…"
    return line


def _timestamp_from_loki(value: Any) -> datetime:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,30}", value) is None:
        raise LogBackendUnavailable("Log entry timestamp must be Unix nanoseconds")
    nanoseconds = int(value)
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    try:
        return datetime.fromtimestamp(seconds, UTC).replace(
            microsecond=remainder // 1_000
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise LogBackendUnavailable("Log entry timestamp is out of range") from exc


def _query_result(
    backend: LogBackend,
    payload: LogQueryRange,
    document: dict[str, Any],
) -> LogQueryResult:
    allowed_labels = set(backend.allowed_labels) - _SENSITIVE_LABELS
    entries: list[LogEntry] = []
    for stream in document["data"]["result"]:
        if not isinstance(stream, dict):
            raise LogBackendUnavailable("Log stream is invalid")
        labels = stream.get("stream")
        values = stream.get("values")
        if not isinstance(labels, dict) or not isinstance(values, list):
            raise LogBackendUnavailable("Log stream is missing labels or values")
        safe_labels: dict[str, str] = {}
        for key, value in labels.items():
            if key not in allowed_labels:
                continue
            if not isinstance(value, str) or len(value) > 512:
                raise LogBackendUnavailable("Log label value is invalid")
            safe_labels[key] = value
        for value in values:
            if not isinstance(value, list) or len(value) != 2:
                raise LogBackendUnavailable("Log entry is invalid")
            entries.append(
                LogEntry(
                    timestamp=_timestamp_from_loki(value[0]),
                    labels=safe_labels,
                    line=_sanitize_line(value[1]),
                )
            )
            if len(entries) > payload.limit:
                break
        if len(entries) > payload.limit:
            break
    reverse = payload.direction == "backward"
    entries.sort(key=lambda item: item.timestamp, reverse=reverse)
    truncated = len(entries) >= payload.limit
    entries = entries[: payload.limit]
    warnings = document.get("warnings", [])
    if not isinstance(warnings, list):
        warnings = []
    return LogQueryResult(
        backend_id=backend.id,
        provider=backend.provider,
        entries=entries,
        truncated=truncated,
        warnings=[str(item)[:1000] for item in warnings[:100]],
    )


def _record_query(
    db: Session,
    backend: LogBackend,
    payload: LogQueryRange,
    *,
    result: LogQueryResult | None,
    error: Exception | None,
    actor_type: str,
) -> None:
    record_audit_event(
        db,
        event_type=("logs.query.executed" if error is None else "logs.query.failed"),
        actor_type=actor_type,
        actor_id=payload.actor,
        entity_type="log_backend",
        entity_id=backend.id,
        outcome="success" if error is None else "failure",
        details={
            "query_sha256": hashlib.sha256(
                payload.query.encode("utf-8")
            ).hexdigest(),
            "start": _iso_timestamp(payload.start),
            "end": _iso_timestamp(payload.end),
            "direction": payload.direction,
            "requested_limit": payload.limit,
            "entry_count": len(result.entries) if result is not None else 0,
            "error_type": type(error).__name__ if error is not None else None,
        },
    )
    db.commit()


def query_logs(
    db: Session,
    backend: LogBackend,
    payload: LogQueryRange,
    *,
    actor_type: str = "user",
) -> LogQueryResult:
    try:
        document = _request_loki(db, backend, payload)
        result = _query_result(backend, payload, document)
    except (LogQueryError, LogBackendUnavailable) as exc:
        _record_query(
            db,
            backend,
            payload,
            result=None,
            error=exc,
            actor_type=actor_type,
        )
        raise
    _record_query(
        db,
        backend,
        payload,
        result=result,
        error=None,
        actor_type=actor_type,
    )
    return result


def check_log_backend(
    db: Session,
    backend: LogBackend,
    *,
    actor: str,
) -> LogBackendHealth:
    checked_at = utcnow()
    probe = LogQueryRange(
        query='{job=~".+"}',
        start=checked_at - timedelta(minutes=1),
        end=checked_at,
        limit=1,
        timeout_seconds=5,
        actor=actor,
    )
    error: str | None = None
    try:
        _request_loki(db, backend, probe)
        status = "healthy"
    except (LogQueryError, LogBackendUnavailable) as exc:
        status = "unhealthy"
        error = str(exc)[:1000]
    backend.last_checked_at = checked_at
    backend.last_health_status = status
    backend.last_health_error = error
    backend.updated_at = checked_at
    record_audit_event(
        db,
        event_type="logs.backend.health_checked",
        actor_type="user",
        actor_id=actor,
        entity_type="log_backend",
        entity_id=backend.id,
        outcome="success" if status == "healthy" else "failure",
        details={"status": status, "error": error},
    )
    db.commit()
    return LogBackendHealth(
        backend_id=backend.id,
        status=status,
        checked_at=checked_at,
        error=error,
    )
