from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..metric_schemas import (
    MetricBackendCreate,
    MetricBackendHealth,
    PrometheusInstantQuery,
    PrometheusQueryResult,
    PrometheusRangeQuery,
)
from ..models import CredentialProfile, MetricBackend, utcnow
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


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


def _credential_profile(
    db: Session,
    reference: str,
) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        )
    )


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
    if payload.credential_profile_ref:
        profile = _credential_profile(db, payload.credential_profile_ref)
        if profile is None:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} "
                "does not exist"
            )
        if not profile.enabled:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} "
                "is disabled"
            )
        if "prometheus_query" not in profile.allowed_adapters:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} "
                "does not allow adapter 'prometheus_query'"
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


def _response_error(document: dict[str, Any]) -> str:
    error_type = document.get("errorType")
    error = document.get("error") or "Prometheus query failed"
    return f"{error_type}: {error}" if error_type else str(error)


def _request_prometheus(
    backend: MetricBackend,
    endpoint: Literal["query", "query_range"],
    fields: dict[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    if not backend.enabled:
        raise MetricBackendUnavailable("Metric backend is disabled")
    if backend.credential_profile_ref:
        raise MetricBackendUnavailable(
            "Credential-backed metric queries require a configured "
            "credential-provider adapter"
        )
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
        },
        method="POST",
    )
    try:
        with build_opener(_NoRedirect()).open(
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
        message = _response_error(document)
        if exc.code in {400, 422}:
            raise MetricQueryError(message) from exc
        raise MetricBackendUnavailable(
            f"Metric backend returned HTTP {exc.code}: {message}"
        ) from exc
    except (OSError, URLError) as exc:
        raise MetricBackendUnavailable(
            f"Metric backend request failed: {exc}"
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
    if document.get("status") != "success":
        raise MetricQueryError(_response_error(document))
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
) -> None:
    series_count = len(result.result) if isinstance(result.result, list) else 1
    record_audit_event(
        db,
        event_type="metrics.query.executed",
        actor_type="user",
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
) -> None:
    record_audit_event(
        db,
        event_type="metrics.query.failed",
        actor_type="user",
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
) -> PrometheusQueryResult:
    fields = {
        "query": payload.query,
        "timeout": f"{payload.timeout_seconds}s",
        "limit": str(payload.limit),
    }
    if payload.time:
        fields["time"] = _iso_timestamp(payload.time)
    try:
        document = _request_prometheus(
            backend,
            "query",
            fields,
            payload.timeout_seconds,
        )
    except (MetricQueryError, MetricBackendUnavailable) as exc:
        _record_query_failure(
            db,
            backend,
            actor=payload.actor,
            query=payload.query,
            mode="instant",
            error=exc,
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
    )
    return result


def query_range(
    db: Session,
    backend: MetricBackend,
    payload: PrometheusRangeQuery,
) -> PrometheusQueryResult:
    try:
        document = _request_prometheus(
            backend,
            "query_range",
            {
                "query": payload.query,
                "start": _iso_timestamp(payload.start),
                "end": _iso_timestamp(payload.end),
                "step": f"{payload.step_seconds}s",
                "timeout": f"{payload.timeout_seconds}s",
                "limit": str(payload.limit),
            },
            payload.timeout_seconds,
        )
    except (MetricQueryError, MetricBackendUnavailable) as exc:
        _record_query_failure(
            db,
            backend,
            actor=payload.actor,
            query=payload.query,
            mode="range",
            error=exc,
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
