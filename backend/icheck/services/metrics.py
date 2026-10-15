from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..credentials import CredentialUnavailable
from ..metric_schemas import (
    MetricBackendCreate,
    MetricBackendHealth,
    MetricBackendUpdate,
    PrometheusInstantQuery,
    PrometheusQueryResult,
    PrometheusRangeQuery,
)
from ..models import MetricBackend, utcnow
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .observability_auth import (
    resolve_backend_auth,
    validate_backend_credential_profile,
)
from .control_plane_auth import PrincipalContext
from .metric_query_scope import (
    MetricScopeError,
    compile_scoped_query,
    query_authority,
)


MAX_PROMETHEUS_RESPONSE_BYTES = 10_000_000


class MetricQueryError(ValueError):
    pass


class MetricBackendUnavailable(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for metric backends",
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


def _validate_url(url: str, allowed_hosts: list[str], field: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{field} must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{field} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field} must not contain a query or fragment")
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError(
            f"{field} host {parsed.hostname!r} is not in the metrics allowlist"
        )
    return url.rstrip("/")


def create_metric_backend(
    db: Session,
    payload: MetricBackendCreate,
    *,
    allowed_hosts: list[str],
) -> MetricBackend:
    query_base_url = _validate_url(
        payload.query_base_url,
        allowed_hosts,
        "query_base_url",
    )
    remote_write_url = (
        _validate_url(
            payload.remote_write_url,
            allowed_hosts,
            "remote_write_url",
        )
        if payload.remote_write_url
        else None
    )
    assert_no_inline_secrets(payload.external_labels, "external_labels")
    validate_backend_credential_profile(
        db,
        auth_type=payload.auth_type,
        auth_header_name=payload.auth_header_name,
        credential_profile_ref=payload.credential_profile_ref,
        adapter_type="prometheus_query",
    )

    backend = MetricBackend(
        **payload.model_dump(
            exclude={"query_base_url", "remote_write_url"}
        ),
        query_base_url=query_base_url,
        remote_write_url=remote_write_url,
    )
    db.add(backend)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="metrics.backend.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="metric_backend",
            entity_id=backend.id,
            details={
                "provider": backend.provider,
                "query_host": urlsplit(query_base_url).hostname,
                "remote_write_configured": remote_write_url is not None,
                "auth_type": backend.auth_type,
                "credential_profile_configured": bool(
                    backend.credential_profile_ref
                ),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Metric backend name already exists") from exc
    db.refresh(backend)
    return backend


def get_metric_backend(db: Session, backend_id: str) -> MetricBackend:
    backend = db.get(MetricBackend, backend_id)
    if backend is None:
        raise LookupError("Metric backend not found")
    return backend


def update_metric_backend(
    db: Session,
    backend: MetricBackend,
    payload: MetricBackendUpdate,
    *,
    allowed_hosts: list[str],
) -> MetricBackend:
    db.refresh(backend, with_for_update=True)
    if backend.revision != payload.expected_revision:
        raise ValueError(
            "Metric backend revision conflict: "
            f"expected {payload.expected_revision}, current {backend.revision}"
        )
    query_base_url = _validate_url(
        payload.query_base_url,
        allowed_hosts,
        "query_base_url",
    )
    remote_write_url = (
        _validate_url(
            payload.remote_write_url,
            allowed_hosts,
            "remote_write_url",
        )
        if payload.remote_write_url
        else None
    )
    assert_no_inline_secrets(payload.external_labels, "external_labels")
    validate_backend_credential_profile(
        db,
        auth_type=payload.auth_type,
        auth_header_name=payload.auth_header_name,
        credential_profile_ref=payload.credential_profile_ref,
        adapter_type="prometheus_query",
    )
    previous = {
        "name": backend.name,
        "provider": backend.provider,
        "query_base_url": backend.query_base_url,
        "remote_write_url": backend.remote_write_url,
        "auth_type": backend.auth_type,
        "auth_header_name": backend.auth_header_name,
        "credential_profile_ref": backend.credential_profile_ref,
        "external_labels": backend.external_labels,
        "enabled": backend.enabled,
    }
    current = {
        "name": payload.name,
        "provider": payload.provider,
        "query_base_url": query_base_url,
        "remote_write_url": remote_write_url,
        "auth_type": payload.auth_type,
        "auth_header_name": payload.auth_header_name,
        "credential_profile_ref": payload.credential_profile_ref,
        "external_labels": payload.external_labels,
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
        raise ValueError("Metric backend update does not change any fields")
    for field, value in current.items():
        setattr(backend, field, value)
    backend.revision += 1
    backend.last_checked_at = None
    backend.last_health_status = None
    backend.last_health_error = None
    backend.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="metrics.backend.updated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="metric_backend",
        entity_id=backend.id,
        details={
            "revision": backend.revision,
            "changed_fields": sorted(changed_fields),
            "query_host": urlsplit(query_base_url).hostname,
            "remote_write_configured": remote_write_url is not None,
            "auth_type": backend.auth_type,
            "credential_profile_configured": bool(
                backend.credential_profile_ref
            ),
            "enabled": backend.enabled,
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Metric backend name already exists") from exc
    db.refresh(backend)
    return backend


def _response_error(document: dict[str, Any]) -> str:
    error_type = document.get("errorType")
    error = document.get("error") or "Prometheus query failed"
    return f"{error_type}: {error}" if error_type else str(error)


def _request_prometheus(
    db: Session,
    backend: MetricBackend,
    endpoint: Literal["query", "query_range"],
    fields: dict[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    if not backend.enabled:
        raise MetricBackendUnavailable("Metric backend is disabled")
    try:
        auth = resolve_backend_auth(
            db,
            auth_type=backend.auth_type,
            auth_header_name=backend.auth_header_name,
            credential_profile_ref=backend.credential_profile_ref,
            adapter_type="prometheus_query",
        )
    except (CredentialUnavailable, ValueError) as exc:
        raise MetricBackendUnavailable(
            f"Metric backend credential is unavailable: {exc}"
        ) from exc
    try:
        query_base_url = _validate_url(
            backend.query_base_url,
            get_settings().metrics_allowed_host_list,
            "query_base_url",
        )
    except ValueError as exc:
        raise MetricBackendUnavailable(str(exc)) from exc
    url = f"{query_base_url}/api/v1/{endpoint}"
    request = Request(
        url,
        data=urlencode(fields).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "iCheck-metrics/0.1",
            **auth.headers,
        },
        method="POST",
    )
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(
            request,
            timeout=timeout_seconds + 2,
        ) as response:
            body = response.read(MAX_PROMETHEUS_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        body = exc.read(MAX_PROMETHEUS_RESPONSE_BYTES + 1)
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = {}
        message = auth.redactor.redact_text(_response_error(document))
        if exc.code in {400, 422}:
            raise MetricQueryError(message) from exc
        raise MetricBackendUnavailable(
            f"Metric backend returned HTTP {exc.code}: {message}"
        ) from exc
    except (OSError, URLError) as exc:
        raise MetricBackendUnavailable(
            "Metric backend request failed: "
            f"{auth.redactor.redact_text(str(exc))}"
        ) from exc
    if len(body) > MAX_PROMETHEUS_RESPONSE_BYTES:
        raise MetricBackendUnavailable(
            "Metric backend response exceeded the 10000000 byte limit"
        )
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MetricBackendUnavailable(
            "Metric backend returned invalid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise MetricBackendUnavailable(
            "Metric backend returned an invalid response envelope"
        )
    document = auth.redactor.redact_value(document)
    assert isinstance(document, dict)
    if document.get("status") != "success":
        raise MetricQueryError(
            auth.redactor.redact_text(_response_error(document))
        )
    data = document.get("data")
    if not isinstance(data, dict):
        raise MetricBackendUnavailable(
            "Metric backend response is missing the data object"
        )
    if not isinstance(data.get("resultType"), str) or "result" not in data:
        raise MetricBackendUnavailable(
            "Metric backend response is missing query result fields"
        )
    return document


def _iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _query_result(
    backend: MetricBackend,
    mode: Literal["instant", "range"],
    document: dict[str, Any],
) -> PrometheusQueryResult:
    data = document["data"]
    return PrometheusQueryResult(
        backend_id=backend.id,
        mode=mode,
        result_type=data["resultType"],
        result=data["result"],
        warnings=[str(item) for item in document.get("warnings", [])],
        infos=[str(item) for item in document.get("infos", [])],
    )


def _record_query(
    db: Session,
    backend: MetricBackend,
    *,
    actor: str,
    query: str,
    mode: str,
    result: PrometheusQueryResult,
    actor_type: str,
) -> None:
    series_count = len(result.result) if isinstance(result.result, list) else 1
    record_audit_event(
        db,
        event_type="metrics.query.executed",
        actor_type=actor_type,
        actor_id=actor,
        entity_type="metric_backend",
        entity_id=backend.id,
        details={
            "mode": mode,
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "result_type": result.result_type,
            "series_count": series_count,
            "warning_count": len(result.warnings),
        },
    )
    db.commit()


def _record_query_failure(
    db: Session,
    backend: MetricBackend,
    *,
    actor: str,
    query: str,
    mode: str,
    error: Exception,
    actor_type: str,
) -> None:
    record_audit_event(
        db,
        event_type="metrics.query.failed",
        actor_type=actor_type,
        actor_id=actor,
        entity_type="metric_backend",
        entity_id=backend.id,
        outcome="failure",
        details={
            "mode": mode,
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "error_type": type(error).__name__,
        },
    )
    db.commit()


def query_instant(
    db: Session,
    backend: MetricBackend,
    payload: PrometheusInstantQuery,
    *,
    actor_type: str = "user",
    principal: PrincipalContext | None = None,
) -> PrometheusQueryResult:
    fields = {
        "query": payload.query,
        "timeout": f"{payload.timeout_seconds}s",
        "limit": str(payload.limit),
    }
    if payload.time:
        fields["time"] = _iso_timestamp(payload.time)
    try:
        authority = query_authority(
            db, backend, principal, internal_service=actor_type == "service"
        )
        fields["query"] = compile_scoped_query(payload.query, authority)
        document = _request_prometheus(
            db,
            backend,
            "query",
            fields,
            payload.timeout_seconds,
        )
        if query_authority(
            db, backend, principal, internal_service=actor_type == "service"
        ) != authority:
            raise MetricScopeError("Metric query authority changed during evaluation")
    except MetricScopeError as exc:
        error = MetricQueryError(str(exc))
        _record_query_failure(
            db, backend, actor=payload.actor, query=payload.query,
            mode="instant", error=error, actor_type=actor_type,
        )
        raise error from exc
    except (MetricQueryError, MetricBackendUnavailable) as exc:
        _record_query_failure(
            db,
            backend,
            actor=payload.actor,
            query=payload.query,
            mode="instant",
            error=exc,
            actor_type=actor_type,
        )
        raise
    result = _query_result(backend, "instant", document)
    _record_query(
        db,
        backend,
        actor=payload.actor,
        query=payload.query,
        mode="instant",
        result=result,
        actor_type=actor_type,
    )
    return result


def query_range(
    db: Session,
    backend: MetricBackend,
    payload: PrometheusRangeQuery,
    *,
    actor_type: str = "user",
    principal: PrincipalContext | None = None,
) -> PrometheusQueryResult:
    try:
        authority = query_authority(
            db, backend, principal, internal_service=actor_type == "service"
        )
        scoped_query = compile_scoped_query(payload.query, authority)
        document = _request_prometheus(
            db,
            backend,
            "query_range",
            {
                "query": scoped_query,
                "start": _iso_timestamp(payload.start),
                "end": _iso_timestamp(payload.end),
                "step": f"{payload.step_seconds}s",
                "timeout": f"{payload.timeout_seconds}s",
                "limit": str(payload.limit),
            },
            payload.timeout_seconds,
        )
        if query_authority(
            db, backend, principal, internal_service=actor_type == "service"
        ) != authority:
            raise MetricScopeError("Metric query authority changed during evaluation")
    except MetricScopeError as exc:
        error = MetricQueryError(str(exc))
        _record_query_failure(
            db, backend, actor=payload.actor, query=payload.query,
            mode="range", error=error, actor_type=actor_type,
        )
        raise error from exc
    except (MetricQueryError, MetricBackendUnavailable) as exc:
        _record_query_failure(
            db,
            backend,
            actor=payload.actor,
            query=payload.query,
            mode="range",
            error=exc,
            actor_type=actor_type,
        )
        raise
    result = _query_result(backend, "range", document)
    _record_query(
        db,
        backend,
        actor=payload.actor,
        query=payload.query,
        mode="range",
        result=result,
        actor_type=actor_type,
    )
    return result


def check_metric_backend(
    db: Session,
    backend: MetricBackend,
    *,
    actor: str,
) -> MetricBackendHealth:
    checked_at = utcnow()
    error: str | None = None
    try:
        _request_prometheus(
            db,
            backend,
            "query",
            {
                "query": "vector(1)",
                "timeout": "5s",
                "limit": "1",
            },
            5,
        )
        health_status = "healthy"
    except (MetricQueryError, MetricBackendUnavailable) as exc:
        health_status = "unhealthy"
        error = str(exc)[:1000]
    backend.last_checked_at = checked_at
    backend.last_health_status = health_status
    backend.last_health_error = error
    backend.updated_at = checked_at
    record_audit_event(
        db,
        event_type="metrics.backend.health_checked",
        actor_type="user",
        actor_id=actor,
        entity_type="metric_backend",
        entity_id=backend.id,
        outcome="success" if health_status == "healthy" else "failure",
        details={"status": health_status, "error": error},
    )
    db.commit()
    return MetricBackendHealth(
        backend_id=backend.id,
        status=health_status,
        checked_at=checked_at,
        error=error,
    )
