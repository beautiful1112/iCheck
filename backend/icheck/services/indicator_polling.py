from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..database import require_locking_transaction
from ..metric_schemas import PrometheusInstantQuery, PrometheusQueryResult
from ..models import (
    IndicatorPollRunStatus,
    IndicatorWorkerState,
    MetricBackend,
    ServiceCatalogEntry,
    ServiceIndicatorDefinition,
    ServiceIndicatorPollRun,
    ServiceIndicatorPrometheusBinding,
    ServiceIndicatorWorker,
    utcnow,
)
from ..service_indicator_schemas import (
    PrometheusIndicatorBindingCreate,
    PrometheusIndicatorBindingRead,
    PrometheusIndicatorBindingUpdate,
    ServiceIndicatorObservationCreate,
    ServiceIndicatorPollAssignment,
    ServiceIndicatorPollRunRead,
)
from .audit import record_audit_event
from .metrics import (
    MetricBackendUnavailable,
    MetricQueryError,
    query_instant,
)
from .service_indicators import ingest_observation


class IndicatorPollLeaseLost(RuntimeError):
    pass


class IndicatorResultError(ValueError):
    pass


class IndicatorResultUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ReducedSample:
    value: float
    observed_at: datetime
    dimensions: dict[str, str]
    result_type: str
    series_count: int


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _error_hash(error: Exception) -> str:
    return hashlib.sha256(str(error).encode("utf-8")).hexdigest()


def _query_hash(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def binding_to_read(
    binding: ServiceIndicatorPrometheusBinding,
) -> PrometheusIndicatorBindingRead:
    return PrometheusIndicatorBindingRead(
        id=binding.id,
        definition_id=binding.definition_id,
        metric_backend_id=binding.metric_backend_id,
        metric_backend_name=binding.metric_backend.name,
        query=binding.query,
        query_sha256=_query_hash(binding.query),
        reduction=binding.reduction,
        dimension_labels=list(binding.dimension_labels or []),
        interval_seconds=binding.interval_seconds,
        timeout_seconds=binding.timeout_seconds,
        enabled=binding.enabled,
        revision=binding.revision,
        next_run_at=binding.next_run_at,
        last_scheduled_at=binding.last_scheduled_at,
        last_started_at=binding.last_started_at,
        last_succeeded_at=binding.last_succeeded_at,
        last_failed_at=binding.last_failed_at,
        consecutive_failures=binding.consecutive_failures,
        last_error_type=binding.last_error_type,
        last_error_sha256=binding.last_error_sha256,
        created_by=binding.created_by,
        updated_by=binding.updated_by,
        created_at=binding.created_at,
        updated_at=binding.updated_at,
    )


def poll_run_to_read(run: ServiceIndicatorPollRun) -> ServiceIndicatorPollRunRead:
    return ServiceIndicatorPollRunRead(
        id=run.id,
        binding_id=run.binding_id,
        scheduled_for=run.scheduled_for,
        status=run.status.value,
        attempt_count=run.attempt_count,
        max_attempts=run.max_attempts,
        next_attempt_at=run.next_attempt_at,
        worker_name=run.lease_worker.name if run.lease_worker else None,
        lease_expires_at=run.lease_expires_at,
        observation_id=run.observation_id,
        result_type=run.result_type,
        series_count=run.series_count,
        error_type=run.error_type,
        error_sha256=run.error_sha256,
        completed_at=run.completed_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def get_prometheus_binding(
    db: Session,
    definition_id: str,
) -> ServiceIndicatorPrometheusBinding:
    binding = db.scalar(
        select(ServiceIndicatorPrometheusBinding)
        .where(ServiceIndicatorPrometheusBinding.definition_id == definition_id)
        .options(selectinload(ServiceIndicatorPrometheusBinding.metric_backend))
    )
    if binding is None:
        raise LookupError("Prometheus indicator binding not found")
    return binding


def _enabled_backend(db: Session, backend_id: str) -> MetricBackend:
    backend = db.get(MetricBackend, backend_id)
    if backend is None:
        raise LookupError("Metric backend not found")
    if not backend.enabled:
        raise ValueError("Metric backend is disabled")
    return backend


def create_prometheus_binding(
    db: Session,
    service: ServiceCatalogEntry,
    definition: ServiceIndicatorDefinition,
    payload: PrometheusIndicatorBindingCreate,
    *,
    actor: str,
) -> ServiceIndicatorPrometheusBinding:
    locked_service = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service.id)
        .with_for_update()
    )
    locked_definition = db.scalar(
        select(ServiceIndicatorDefinition)
        .where(
            ServiceIndicatorDefinition.id == definition.id,
            ServiceIndicatorDefinition.service_id == service.id,
        )
        .with_for_update()
    )
    if locked_service is None or locked_definition is None:
        raise LookupError("Service indicator not found")
    if locked_definition.revision != payload.expected_indicator_revision:
        raise ValueError("Service indicator revision conflict; reload before updating")
    if locked_definition.source_type != "prometheus":
        raise ValueError("Only a prometheus indicator can have this binding")
    if not locked_definition.enabled:
        raise ValueError("A disabled indicator cannot activate polling")
    if not payload.query.strip():
        raise ValueError("Prometheus query cannot be blank")
    backend = _enabled_backend(db, payload.metric_backend_id)
    if db.scalar(
        select(ServiceIndicatorPrometheusBinding.id).where(
            ServiceIndicatorPrometheusBinding.definition_id == definition.id
        )
    ):
        raise ValueError("Prometheus indicator binding already exists")

    now = utcnow()
    binding = ServiceIndicatorPrometheusBinding(
        definition_id=definition.id,
        metric_backend_id=backend.id,
        query=payload.query.strip(),
        reduction=payload.reduction,
        dimension_labels=payload.dimension_labels,
        interval_seconds=payload.interval_seconds,
        timeout_seconds=payload.timeout_seconds,
        enabled=True,
        revision=1,
        next_run_at=now,
        created_by=actor,
        updated_by=actor,
    )
    db.add(binding)
    locked_definition.revision += 1
    locked_definition.updated_by = actor
    locked_definition.updated_at = now
    locked_service.revision += 1
    locked_service.updated_by = actor
    locked_service.updated_at = now
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="service_indicator.prometheus_binding_created",
            actor_type="user",
            actor_id=actor,
            entity_type="service_indicator_prometheus_binding",
            entity_id=binding.id,
            details={
                "service_id": service.id,
                "definition_id": definition.id,
                "metric_backend_id": backend.id,
                "query_sha256": _query_hash(binding.query),
                "reduction": binding.reduction,
                "interval_seconds": binding.interval_seconds,
                "indicator_revision": locked_definition.revision,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Prometheus indicator binding already exists") from exc
    return get_prometheus_binding(db, definition.id)


def update_prometheus_binding(
    db: Session,
    service: ServiceCatalogEntry,
    definition: ServiceIndicatorDefinition,
    binding: ServiceIndicatorPrometheusBinding,
    payload: PrometheusIndicatorBindingUpdate,
    *,
    actor: str,
) -> ServiceIndicatorPrometheusBinding:
    locked_service = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service.id)
        .with_for_update()
    )
    locked_definition = db.scalar(
        select(ServiceIndicatorDefinition)
        .where(
            ServiceIndicatorDefinition.id == definition.id,
            ServiceIndicatorDefinition.service_id == service.id,
        )
        .with_for_update()
    )
    locked = db.scalar(
        select(ServiceIndicatorPrometheusBinding)
        .where(ServiceIndicatorPrometheusBinding.id == binding.id)
        .with_for_update()
    )
    if locked_service is None or locked_definition is None or locked is None:
        raise LookupError("Prometheus indicator binding not found")
    if locked.revision != payload.expected_revision:
        raise ValueError("Prometheus binding revision conflict; reload before updating")
    if locked_definition.source_type != "prometheus":
        raise ValueError("The indicator is no longer a prometheus source")
    values = payload.model_dump(
        exclude={"expected_revision", "actor"}, exclude_unset=True
    )
    if values.get("enabled") and not locked_definition.enabled:
        raise ValueError("A disabled indicator cannot activate polling")
    if "metric_backend_id" in values:
        _enabled_backend(db, values["metric_backend_id"])
    if "query" in values:
        values["query"] = values["query"].strip()
        if not values["query"]:
            raise ValueError("Prometheus query cannot be blank")
    merged_reduction = values.get("reduction", locked.reduction)
    merged_dimensions = values.get(
        "dimension_labels", list(locked.dimension_labels or [])
    )
    if merged_reduction != "single" and merged_dimensions:
        raise ValueError("Dimension labels require single reduction")

    changed: list[str] = []
    for key, value in values.items():
        if getattr(locked, key) != value:
            setattr(locked, key, value)
            changed.append(key)
    if not changed:
        return get_prometheus_binding(db, definition.id)

    now = utcnow()
    locked.revision += 1
    locked.updated_by = actor
    locked.updated_at = now
    if any(
        field in changed
        for field in (
            "metric_backend_id",
            "query",
            "reduction",
            "dimension_labels",
            "interval_seconds",
            "enabled",
        )
    ):
        locked.next_run_at = now
        locked.consecutive_failures = 0
        locked.last_error_type = None
        locked.last_error_sha256 = None
    locked_definition.revision += 1
    locked_definition.updated_by = actor
    locked_definition.updated_at = now
    locked_service.revision += 1
    locked_service.updated_by = actor
    locked_service.updated_at = now
    record_audit_event(
        db,
        event_type="service_indicator.prometheus_binding_updated",
        actor_type="user",
        actor_id=actor,
        entity_type="service_indicator_prometheus_binding",
        entity_id=locked.id,
        details={
            "service_id": service.id,
            "definition_id": definition.id,
            "revision": locked.revision,
            "indicator_revision": locked_definition.revision,
            "changed_fields": sorted(changed),
            "query_sha256": _query_hash(locked.query),
        },
    )
    db.commit()
    return get_prometheus_binding(db, definition.id)


def enqueue_poll_now(
    db: Session,
    binding: ServiceIndicatorPrometheusBinding,
    *,
    actor: str,
) -> ServiceIndicatorPollRun:
    locked = db.scalar(
        select(ServiceIndicatorPrometheusBinding)
        .where(ServiceIndicatorPrometheusBinding.id == binding.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("Prometheus indicator binding not found")
    if not locked.enabled:
        raise ValueError("Prometheus indicator binding is disabled")
    now = utcnow()
    run = ServiceIndicatorPollRun(
        binding_id=locked.id,
        scheduled_for=now,
        status=IndicatorPollRunStatus.PENDING,
        attempt_count=0,
        max_attempts=3,
        next_attempt_at=now,
    )
    db.add(run)
    db.flush()
    record_audit_event(
        db,
        event_type="service_indicator.poll_enqueued",
        actor_type="user",
        actor_id=actor,
        entity_type="service_indicator_poll_run",
        entity_id=run.id,
        details={"binding_id": locked.id, "mode": "manual"},
    )
    db.commit()
    db.refresh(run)
    return run


def enqueue_due_polls(db: Session, *, limit: int = 100) -> int:
    require_locking_transaction(db, purpose="Indicator scheduling")
    if not 1 <= limit <= 1000:
        raise ValueError("Poll enqueue limit must be between 1 and 1000")
    now = utcnow()
    bindings = list(
        db.scalars(
            select(ServiceIndicatorPrometheusBinding)
            .join(ServiceIndicatorPrometheusBinding.definition)
            .join(ServiceIndicatorPrometheusBinding.metric_backend)
            .where(
                ServiceIndicatorPrometheusBinding.enabled.is_(True),
                ServiceIndicatorDefinition.enabled.is_(True),
                MetricBackend.enabled.is_(True),
                ServiceIndicatorPrometheusBinding.next_run_at <= now,
            )
            .order_by(
                ServiceIndicatorPrometheusBinding.next_run_at,
                ServiceIndicatorPrometheusBinding.id,
            )
            .with_for_update(
                skip_locked=True, of=ServiceIndicatorPrometheusBinding
            )
            .limit(limit)
        ).all()
    )
    for binding in bindings:
        scheduled_for = binding.next_run_at
        existing = db.scalar(
            select(ServiceIndicatorPollRun.id).where(
                ServiceIndicatorPollRun.binding_id == binding.id,
                ServiceIndicatorPollRun.scheduled_for == scheduled_for,
            )
        )
        if existing is None:
            db.add(
                ServiceIndicatorPollRun(
                    binding_id=binding.id,
                    scheduled_for=scheduled_for,
                    status=IndicatorPollRunStatus.PENDING,
                    attempt_count=0,
                    max_attempts=3,
                    next_attempt_at=now,
                )
            )
        binding.last_scheduled_at = scheduled_for
        binding.next_run_at = now + timedelta(seconds=binding.interval_seconds)
        binding.updated_at = now
    db.commit()
    return len(bindings)


def list_poll_runs(
    db: Session,
    binding: ServiceIndicatorPrometheusBinding,
    *,
    limit: int,
) -> list[ServiceIndicatorPollRunRead]:
    runs = list(
        db.scalars(
            select(ServiceIndicatorPollRun)
            .where(ServiceIndicatorPollRun.binding_id == binding.id)
            .options(selectinload(ServiceIndicatorPollRun.lease_worker))
            .order_by(
                ServiceIndicatorPollRun.scheduled_for.desc(),
                ServiceIndicatorPollRun.id.desc(),
            )
            .limit(limit)
        ).all()
    )
    return [poll_run_to_read(run) for run in runs]


def register_indicator_worker(db: Session, *, name: str) -> ServiceIndicatorWorker:
    normalized = name.strip()
    if not normalized:
        raise ValueError("Indicator worker name is required")
    worker = db.scalar(
        select(ServiceIndicatorWorker).where(ServiceIndicatorWorker.name == normalized)
    )
    now = utcnow()
    if worker is None:
        worker = ServiceIndicatorWorker(
            name=normalized,
            state=IndicatorWorkerState.ONLINE,
            last_heartbeat_at=now,
        )
        db.add(worker)
    else:
        worker.state = IndicatorWorkerState.ONLINE
        worker.last_heartbeat_at = now
    db.commit()
    db.refresh(worker)
    return worker


def _clear_lease(run: ServiceIndicatorPollRun) -> None:
    run.lease_worker_id = None
    run.lease_token_hash = None
    run.lease_expires_at = None


def claim_indicator_polls(
    db: Session,
    worker: ServiceIndicatorWorker,
    *,
    limit: int,
    lease_seconds: int,
) -> list[ServiceIndicatorPollAssignment]:
    require_locking_transaction(db, purpose="Indicator poll claims")
    if worker.state != IndicatorWorkerState.ONLINE:
        raise ValueError("Indicator worker is not online")
    if not 1 <= limit <= 100:
        raise ValueError("Poll claim limit must be between 1 and 100")
    if not 30 <= lease_seconds <= 3600:
        raise ValueError("Poll lease must be between 30 and 3600 seconds")
    now = utcnow()
    worker.last_heartbeat_at = now
    ready = and_(
        ServiceIndicatorPollRun.status.in_(
            [IndicatorPollRunStatus.PENDING, IndicatorPollRunStatus.RETRY]
        ),
        ServiceIndicatorPollRun.next_attempt_at <= now,
    )
    abandoned = and_(
        ServiceIndicatorPollRun.status == IndicatorPollRunStatus.PROCESSING,
        ServiceIndicatorPollRun.lease_expires_at.is_not(None),
        ServiceIndicatorPollRun.lease_expires_at <= now,
    )
    runs = list(
        db.scalars(
            select(ServiceIndicatorPollRun)
            .where(or_(ready, abandoned))
            .order_by(
                ServiceIndicatorPollRun.next_attempt_at,
                ServiceIndicatorPollRun.created_at,
                ServiceIndicatorPollRun.id,
            )
            .with_for_update(skip_locked=True)
            .limit(limit)
        ).all()
    )
    assignments: list[ServiceIndicatorPollAssignment] = []
    for run in runs:
        if (
            run.status == IndicatorPollRunStatus.PROCESSING
            and run.attempt_count >= run.max_attempts
        ):
            error = IndicatorPollLeaseLost(
                "Poll lease expired at the maximum attempt count"
            )
            run.status = IndicatorPollRunStatus.DEAD_LETTER
            run.error_type = type(error).__name__
            run.error_sha256 = _error_hash(error)
            run.completed_at = now
            run.binding.last_failed_at = now
            run.binding.consecutive_failures += 1
            run.binding.last_error_type = run.error_type
            run.binding.last_error_sha256 = run.error_sha256
            run.binding.updated_at = now
            _clear_lease(run)
            continue
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=lease_seconds)
        run.status = IndicatorPollRunStatus.PROCESSING
        run.attempt_count += 1
        run.lease_worker_id = worker.id
        run.lease_token_hash = _token_hash(token)
        run.lease_expires_at = expires_at
        run.completed_at = None
        assignments.append(
            ServiceIndicatorPollAssignment(
                run_id=run.id,
                binding_id=run.binding_id,
                lease_token=token,
                lease_expires_at=expires_at,
            )
        )
    db.commit()
    return assignments


def _active_poll(
    db: Session,
    worker: ServiceIndicatorWorker,
    assignment: ServiceIndicatorPollAssignment,
) -> ServiceIndicatorPollRun:
    require_locking_transaction(db, purpose="Indicator poll mutations")
    run = db.scalar(
        select(ServiceIndicatorPollRun)
        .where(ServiceIndicatorPollRun.id == assignment.run_id)
        .with_for_update(of=ServiceIndicatorPollRun)
        .execution_options(populate_existing=True)
        .options(
            selectinload(ServiceIndicatorPollRun.binding).selectinload(
                ServiceIndicatorPrometheusBinding.definition
            ),
            selectinload(ServiceIndicatorPollRun.binding).selectinload(
                ServiceIndicatorPrometheusBinding.metric_backend
            ),
        )
    )
    if run is None:
        raise LookupError("Service indicator poll run not found")
    if run.status != IndicatorPollRunStatus.PROCESSING:
        raise IndicatorPollLeaseLost("Service indicator poll is not processing")
    if run.lease_worker_id != worker.id:
        raise IndicatorPollLeaseLost("Service indicator poll belongs to another worker")
    if not run.lease_token_hash or not hmac.compare_digest(
        run.lease_token_hash, _token_hash(assignment.lease_token)
    ):
        raise IndicatorPollLeaseLost("Service indicator poll lease token is invalid")
    if run.lease_expires_at is None or _as_utc(run.lease_expires_at) <= utcnow():
        raise IndicatorPollLeaseLost("Service indicator poll lease expired")
    if run.binding_id != assignment.binding_id:
        raise IndicatorPollLeaseLost("Service indicator poll binding changed")
    return run


def _parse_value(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise IndicatorResultError("Prometheus sample is not numeric") from exc
    if not math.isfinite(parsed):
        raise IndicatorResultError("Prometheus sample must be finite")
    return parsed


def _parse_timestamp(value: Any) -> datetime:
    try:
        timestamp = float(value)
        if not math.isfinite(timestamp):
            raise ValueError
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise IndicatorResultError("Prometheus sample timestamp is invalid") from exc


def reduce_prometheus_result(
    result: PrometheusQueryResult,
    *,
    reduction: str,
    dimension_labels: list[str],
) -> ReducedSample:
    samples: list[tuple[float, datetime, dict[str, str]]] = []
    if result.result_type == "scalar":
        raw = result.result
        if not isinstance(raw, list) or len(raw) != 2:
            raise IndicatorResultError("Prometheus scalar result is malformed")
        samples.append((_parse_value(raw[1]), _parse_timestamp(raw[0]), {}))
    elif result.result_type == "vector":
        if not isinstance(result.result, list):
            raise IndicatorResultError("Prometheus vector result is malformed")
        if len(result.result) > 100:
            raise IndicatorResultError("Prometheus vector exceeds the 100-series limit")
        for series in result.result:
            if not isinstance(series, dict):
                raise IndicatorResultError("Prometheus vector series is malformed")
            raw_value = series.get("value")
            labels = series.get("metric", {})
            if not isinstance(raw_value, list) or len(raw_value) != 2:
                raise IndicatorResultError("Prometheus vector sample is malformed")
            if not isinstance(labels, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in labels.items()
            ):
                raise IndicatorResultError("Prometheus metric labels are malformed")
            samples.append(
                (
                    _parse_value(raw_value[1]),
                    _parse_timestamp(raw_value[0]),
                    {
                        label: labels[label]
                        for label in dimension_labels
                        if label in labels
                    },
                )
            )
    else:
        raise IndicatorResultError(
            "Indicator polling accepts only Prometheus scalar or vector results"
        )
    if not samples:
        raise IndicatorResultUnavailable("Prometheus query returned no samples")
    if reduction == "single":
        if len(samples) != 1:
            raise IndicatorResultError(
                "single reduction requires exactly one Prometheus sample"
            )
        value, observed_at, dimensions = samples[0]
    else:
        values = [sample[0] for sample in samples]
        if reduction == "sum":
            value = sum(values)
        elif reduction == "avg":
            value = sum(values) / len(values)
        elif reduction == "min":
            value = min(values)
        elif reduction == "max":
            value = max(values)
        else:
            raise IndicatorResultError("Unknown Prometheus reduction")
        if not math.isfinite(value):
            raise IndicatorResultError("Reduced Prometheus sample must be finite")
        observed_at = max(sample[1] for sample in samples)
        dimensions = {}
    return ReducedSample(
        value=value,
        observed_at=observed_at,
        dimensions=dimensions,
        result_type=result.result_type,
        series_count=len(samples),
    )


def _complete_failure(
    db: Session,
    worker: ServiceIndicatorWorker,
    assignment: ServiceIndicatorPollAssignment,
    error: Exception,
    *,
    permanent: bool,
) -> ServiceIndicatorPollRun:
    db.expire_all()
    run = _active_poll(db, worker, assignment)
    now = utcnow()
    run.error_type = type(error).__name__
    run.error_sha256 = _error_hash(error)
    run.binding.last_failed_at = now
    run.binding.consecutive_failures += 1
    run.binding.last_error_type = run.error_type
    run.binding.last_error_sha256 = run.error_sha256
    run.binding.updated_at = now
    if permanent or run.attempt_count >= run.max_attempts:
        run.status = IndicatorPollRunStatus.DEAD_LETTER
        run.completed_at = now
    else:
        run.status = IndicatorPollRunStatus.RETRY
        run.next_attempt_at = now + timedelta(
            seconds=min(300, 30 * (2 ** (run.attempt_count - 1)))
        )
        run.completed_at = None
    _clear_lease(run)
    record_audit_event(
        db,
        event_type="service_indicator.poll_failed",
        actor_type="service",
        actor_id=f"indicator.worker.{worker.id}",
        entity_type="service_indicator_poll_run",
        entity_id=run.id,
        outcome="failure",
        details={
            "binding_id": run.binding_id,
            "attempt_count": run.attempt_count,
            "status": run.status.value,
            "error_type": run.error_type,
            "error_sha256": run.error_sha256,
        },
    )
    db.commit()
    db.refresh(run)
    return run


def process_poll_assignment(
    db: Session,
    worker: ServiceIndicatorWorker,
    assignment: ServiceIndicatorPollAssignment,
) -> ServiceIndicatorPollRun:
    run = _active_poll(db, worker, assignment)
    binding = run.binding
    definition = binding.definition
    backend = binding.metric_backend
    contract = (binding.id, binding.revision, definition.id, definition.revision,
                backend.id, backend.revision)
    query_text = binding.query
    reduction = binding.reduction
    dimension_labels = list(binding.dimension_labels or [])
    query_timeout = binding.timeout_seconds
    if not binding.enabled or not definition.enabled or not backend.enabled:
        return _complete_failure(
            db,
            worker,
            assignment,
            IndicatorResultError("Polling contract or dependency is disabled"),
            permanent=True,
        )
    if definition.source_type != "prometheus":
        return _complete_failure(
            db,
            worker,
            assignment,
            IndicatorResultError("Indicator source type is no longer prometheus"),
            permanent=True,
        )
    binding.last_started_at = utcnow()
    binding.updated_at = binding.last_started_at
    db.commit()

    try:
        result = query_instant(
            db,
            backend,
            PrometheusInstantQuery(
                query=query_text,
                time=run.scheduled_for,
                timeout_seconds=query_timeout,
                limit=100,
                actor=f"indicator.worker.{worker.id}",
            ),
            actor_type="service",
        )
        sample = reduce_prometheus_result(
            result,
            reduction=reduction,
            dimension_labels=dimension_labels,
        )
        db.expire_all()
        run = _active_poll(db, worker, assignment)
        # Do not hold database locks during upstream I/O. After the query,
        # fence lease ownership and lock the referenced contract until the
        # observation and completion commit together. Definition-before-binding
        # matches the configuration editor's lock order.
        current_definition = db.scalar(select(ServiceIndicatorDefinition).where(
            ServiceIndicatorDefinition.id == contract[2]
        ).with_for_update().execution_options(populate_existing=True))
        current_backend = db.scalar(select(MetricBackend).where(
            MetricBackend.id == contract[4]
        ).with_for_update().execution_options(populate_existing=True))
        current_binding = db.scalar(select(ServiceIndicatorPrometheusBinding).where(
            ServiceIndicatorPrometheusBinding.id == contract[0]
        ).with_for_update().execution_options(populate_existing=True))
        if (current_definition is None or current_backend is None or current_binding is None
                or (current_binding.id, current_binding.revision,
                    current_binding.definition_id, current_definition.revision,
                    current_binding.metric_backend_id, current_backend.revision) != contract
                or not current_binding.enabled or not current_definition.enabled
                or not current_backend.enabled or current_definition.source_type != "prometheus"):
            raise IndicatorResultError("Polling contract changed during the query")
        query_sha256 = _query_hash(query_text)
        scheduled_key = _as_utc(run.scheduled_for).isoformat()
        observation = ingest_observation(
            db,
            run.binding.definition,
            ServiceIndicatorObservationCreate(
                source_observation_id=(
                    f"prometheus:{run.binding_id}:{scheduled_key}"
                ),
                value=sample.value,
                measurement_quality="measured",
                dimensions=sample.dimensions,
                evidence_ref=(
                    f"prometheus://{run.binding.metric_backend_id}/"
                    f"{query_sha256}/{int(sample.observed_at.timestamp())}"
                ),
                observed_at=sample.observed_at,
                actor=f"indicator.worker.{worker.id}",
            ),
            actor=f"indicator.worker.{worker.id}",
            commit=False,
        )
        run = _active_poll(db, worker, assignment)
        now = utcnow()
        run.status = IndicatorPollRunStatus.SUCCEEDED
        run.observation_id = observation.id
        run.result_type = sample.result_type
        run.series_count = sample.series_count
        run.error_type = None
        run.error_sha256 = None
        run.completed_at = now
        run.binding.last_succeeded_at = now
        run.binding.consecutive_failures = 0
        run.binding.last_error_type = None
        run.binding.last_error_sha256 = None
        run.binding.updated_at = now
        _clear_lease(run)
        record_audit_event(
            db,
            event_type="service_indicator.poll_succeeded",
            actor_type="service",
            actor_id=f"indicator.worker.{worker.id}",
            entity_type="service_indicator_poll_run",
            entity_id=run.id,
            details={
                "binding_id": run.binding_id,
                "observation_id": observation.id,
                "query_sha256": query_sha256,
                "result_type": sample.result_type,
                "series_count": sample.series_count,
                "reduction": reduction,
            },
        )
        db.commit()
        db.refresh(run)
        return run
    except IndicatorPollLeaseLost:
        db.rollback()
        raise
    except (IndicatorResultError, MetricQueryError, ValueError) as exc:
        db.rollback()
        return _complete_failure(
            db, worker, assignment, exc, permanent=True
        )
    except (IndicatorResultUnavailable, MetricBackendUnavailable) as exc:
        db.rollback()
        return _complete_failure(
            db, worker, assignment, exc, permanent=False
        )
    except Exception as exc:
        db.rollback()
        return _complete_failure(
            db, worker, assignment, exc, permanent=False
        )
