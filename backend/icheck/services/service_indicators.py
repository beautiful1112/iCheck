from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    ServiceCatalogEntry,
    ServiceIndicatorArtifactBinding,
    ServiceIndicatorDefinition,
    ServiceIndicatorObservation,
    ServiceIndicatorPrometheusBinding,
    utcnow,
)
from ..service_indicator_schemas import (
    ServiceIndicatorCreate,
    ServiceIndicatorObservationCreate,
    ServiceIndicatorObservationRead,
    ServiceIndicatorRead,
    ServiceIndicatorUpdate,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _validate_thresholds(
    direction: str,
    warning: float | None,
    critical: float | None,
) -> None:
    if direction == "none":
        if warning is not None or critical is not None:
            raise ValueError("Informational indicators cannot define thresholds")
        return
    if warning is None and critical is None:
        raise ValueError("A thresholded indicator requires at least one threshold")
    if warning is None or critical is None:
        return
    if direction == "above" and critical <= warning:
        raise ValueError("An above critical threshold must exceed warning")
    if direction == "below" and critical >= warning:
        raise ValueError("A below critical threshold must be below warning")


def _assert_safe_reference(value: str | None, field: str) -> None:
    if value is None:
        return
    normalized = value.casefold()
    credential_markers = (
        "api_key=",
        "apikey=",
        "access_token=",
        "token=",
        "password=",
        "passwd=",
        "secret=",
    )
    if any(marker in normalized for marker in credential_markers):
        raise ValueError(f"{field} must not contain inline credentials")
    parsed = urlsplit(value)
    if parsed.username or parsed.password:
        raise ValueError(f"{field} must not contain URL user credentials")
    if parsed.scheme and (parsed.query or parsed.fragment):
        raise ValueError(
            f"{field} URLs must not contain query parameters or fragments"
        )


def threshold_status(
    definition: ServiceIndicatorDefinition,
    value: float,
) -> str:
    direction = definition.breach_direction
    if direction == "none":
        return "informational"
    if direction == "above":
        if (
            definition.critical_threshold is not None
            and value >= definition.critical_threshold
        ):
            return "critical"
        if (
            definition.warning_threshold is not None
            and value >= definition.warning_threshold
        ):
            return "warning"
    elif direction == "below":
        if (
            definition.critical_threshold is not None
            and value <= definition.critical_threshold
        ):
            return "critical"
        if (
            definition.warning_threshold is not None
            and value <= definition.warning_threshold
        ):
            return "warning"
    return "healthy"


def observation_to_read(
    definition: ServiceIndicatorDefinition,
    observation: ServiceIndicatorObservation,
    *,
    now: datetime | None = None,
) -> ServiceIndicatorObservationRead:
    evaluated_at = _as_utc(now or utcnow())
    observed_at = _as_utc(observation.observed_at)
    expires_at = observed_at + timedelta(seconds=definition.freshness_seconds)
    freshness = "fresh" if expires_at >= evaluated_at else "stale"
    threshold = threshold_status(definition, observation.value)
    effective = threshold if freshness == "fresh" else "stale"
    return ServiceIndicatorObservationRead(
        id=observation.id,
        definition_id=observation.definition_id,
        source_observation_id=observation.source_observation_id,
        value=observation.value,
        measurement_quality=observation.measurement_quality,
        dimensions=dict(observation.dimensions or {}),
        evidence_ref=observation.evidence_ref,
        threshold_status=threshold,
        freshness_status=freshness,
        effective_status=effective,
        observed_at=observation.observed_at,
        expires_at=expires_at,
        ingested_at=observation.ingested_at,
        created_by=observation.created_by,
    )


def definition_to_read(
    definition: ServiceIndicatorDefinition,
    observation: ServiceIndicatorObservation | None,
    *,
    now: datetime | None = None,
) -> ServiceIndicatorRead:
    latest = (
        observation_to_read(definition, observation, now=now)
        if observation is not None
        else None
    )
    return ServiceIndicatorRead(
        id=definition.id,
        service_id=definition.service_id,
        indicator_key=definition.indicator_key,
        name=definition.name,
        description=definition.description,
        kind=definition.kind,
        unit=definition.unit,
        source_type=definition.source_type,
        source_ref=definition.source_ref,
        breach_direction=definition.breach_direction,
        warning_threshold=definition.warning_threshold,
        critical_threshold=definition.critical_threshold,
        freshness_seconds=definition.freshness_seconds,
        enabled=definition.enabled,
        revision=definition.revision,
        effective_status=latest.effective_status if latest else "unknown",
        latest_observation=latest,
        created_by=definition.created_by,
        updated_by=definition.updated_by,
        created_at=definition.created_at,
        updated_at=definition.updated_at,
    )


def latest_indicator_rows(
    db: Session,
    service_ids: Iterable[str],
    *,
    enabled_only: bool = True,
) -> list[tuple[ServiceIndicatorDefinition, ServiceIndicatorObservation | None]]:
    ids = {str(value) for value in service_ids}
    if not ids:
        return []
    latest_observation_id = (
        select(ServiceIndicatorObservation.id)
        .where(
            ServiceIndicatorObservation.definition_id
            == ServiceIndicatorDefinition.id
        )
        .order_by(
            ServiceIndicatorObservation.observed_at.desc(),
            ServiceIndicatorObservation.ingested_at.desc(),
            ServiceIndicatorObservation.id.desc(),
        )
        .limit(1)
        .correlate(ServiceIndicatorDefinition)
        .scalar_subquery()
    )
    query = (
        select(ServiceIndicatorDefinition, ServiceIndicatorObservation)
        .outerjoin(
            ServiceIndicatorObservation,
            ServiceIndicatorObservation.id == latest_observation_id,
        )
        .where(ServiceIndicatorDefinition.service_id.in_(ids))
        .order_by(
            ServiceIndicatorDefinition.service_id,
            ServiceIndicatorDefinition.indicator_key,
        )
    )
    if enabled_only:
        query = query.where(ServiceIndicatorDefinition.enabled.is_(True))
    return list(db.execute(query).all())


def list_indicators(
    db: Session,
    service: ServiceCatalogEntry,
    *,
    include_disabled: bool,
) -> list[ServiceIndicatorRead]:
    return [
        definition_to_read(definition, observation)
        for definition, observation in latest_indicator_rows(
            db,
            [service.id],
            enabled_only=not include_disabled,
        )
    ]


def create_indicator(
    db: Session,
    service: ServiceCatalogEntry,
    payload: ServiceIndicatorCreate,
    *,
    actor: str,
) -> ServiceIndicatorDefinition:
    locked_service = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service.id)
        .with_for_update()
    )
    if locked_service is None:
        raise LookupError("Service not found")
    if locked_service.revision != payload.expected_service_revision:
        raise ValueError("Service revision conflict; reload before updating")
    _assert_safe_reference(payload.source_ref, "source_ref")
    definition = ServiceIndicatorDefinition(
        service_id=locked_service.id,
        indicator_key=payload.indicator_key,
        name=payload.name,
        description=payload.description,
        kind=payload.kind,
        unit=payload.unit,
        source_type=payload.source_type,
        source_ref=payload.source_ref,
        breach_direction=payload.breach_direction,
        warning_threshold=payload.warning_threshold,
        critical_threshold=payload.critical_threshold,
        freshness_seconds=payload.freshness_seconds,
        enabled=True,
        revision=1,
        created_by=actor,
        updated_by=actor,
    )
    db.add(definition)
    locked_service.revision += 1
    locked_service.updated_by = actor
    locked_service.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="service_indicator.created",
            actor_type="user",
            actor_id=actor,
            entity_type="service_indicator_definition",
            entity_id=definition.id,
            details={
                "service_id": service.id,
                "indicator_key": definition.indicator_key,
                "kind": definition.kind,
                "source_type": definition.source_type,
                "service_revision": locked_service.revision,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Service indicator key already exists") from exc
    db.refresh(definition)
    return definition


def update_indicator(
    db: Session,
    service: ServiceCatalogEntry,
    definition: ServiceIndicatorDefinition,
    payload: ServiceIndicatorUpdate,
    *,
    actor: str,
) -> ServiceIndicatorDefinition:
    locked_service = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service.id)
        .with_for_update()
    )
    locked = db.scalar(
        select(ServiceIndicatorDefinition)
        .where(
            ServiceIndicatorDefinition.id == definition.id,
            ServiceIndicatorDefinition.service_id == service.id,
        )
        .with_for_update()
    )
    if locked_service is None or locked is None:
        raise LookupError("Service indicator not found")
    if locked.revision != payload.expected_revision:
        raise ValueError("Service indicator revision conflict; reload before updating")
    values = payload.model_dump(
        exclude={"expected_revision", "actor"},
        exclude_unset=True,
    )
    if "source_ref" in values:
        _assert_safe_reference(values["source_ref"], "source_ref")
    merged: dict[str, Any] = {
        "breach_direction": locked.breach_direction,
        "warning_threshold": locked.warning_threshold,
        "critical_threshold": locked.critical_threshold,
        **values,
    }
    _validate_thresholds(
        merged["breach_direction"],
        merged["warning_threshold"],
        merged["critical_threshold"],
    )
    changed: list[str] = []
    for key, value in values.items():
        if getattr(locked, key) != value:
            setattr(locked, key, value)
            changed.append(key)
    if not changed:
        return locked
    polling_binding = db.scalar(
        select(ServiceIndicatorPrometheusBinding)
        .where(ServiceIndicatorPrometheusBinding.definition_id == locked.id)
        .with_for_update()
    )
    polling_disabled = False
    if (
        polling_binding is not None
        and polling_binding.enabled
        and (not locked.enabled or locked.source_type != "prometheus")
    ):
        polling_binding.enabled = False
        polling_binding.revision += 1
        polling_binding.updated_by = actor
        polling_binding.updated_at = utcnow()
        polling_disabled = True
    artifact_binding = db.scalar(
        select(ServiceIndicatorArtifactBinding)
        .where(ServiceIndicatorArtifactBinding.definition_id == locked.id)
        .with_for_update()
    )
    artifact_disabled = False
    if (
        artifact_binding is not None
        and artifact_binding.enabled
        and (
            not locked.enabled
            or locked.source_type not in {"api", "collector", "business_system"}
            or (
                locked.source_type == "collector"
                and artifact_binding.producer_kind != "collector"
            )
        )
    ):
        artifact_binding.enabled = False
        artifact_binding.revision += 1
        artifact_binding.updated_by = actor
        artifact_binding.updated_at = utcnow()
        artifact_disabled = True
    locked.revision += 1
    locked.updated_by = actor
    locked.updated_at = utcnow()
    locked_service.revision += 1
    locked_service.updated_by = actor
    locked_service.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="service_indicator.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="service_indicator_definition",
        entity_id=locked.id,
        details={
            "service_id": service.id,
            "indicator_key": locked.indicator_key,
            "revision": locked.revision,
            "service_revision": locked_service.revision,
            "changed_fields": sorted(changed),
            "prometheus_polling_disabled": polling_disabled,
            "artifact_publication_disabled": artifact_disabled,
        },
    )
    db.commit()
    db.refresh(locked)
    return locked


def get_indicator(
    db: Session,
    service_id: str,
    definition_id: str,
) -> ServiceIndicatorDefinition:
    definition = db.scalar(
        select(ServiceIndicatorDefinition).where(
            ServiceIndicatorDefinition.id == definition_id,
            ServiceIndicatorDefinition.service_id == service_id,
        )
    )
    if definition is None:
        raise LookupError("Service indicator not found")
    return definition


def _observation_matches(
    observation: ServiceIndicatorObservation,
    payload: ServiceIndicatorObservationCreate,
) -> bool:
    return (
        observation.value == payload.value
        and observation.measurement_quality == payload.measurement_quality
        and dict(observation.dimensions or {}) == payload.dimensions
        and observation.evidence_ref == payload.evidence_ref
        and _as_utc(observation.observed_at) == _as_utc(payload.observed_at)
    )


def ingest_observation(
    db: Session,
    definition: ServiceIndicatorDefinition,
    payload: ServiceIndicatorObservationCreate,
    *,
    actor: str,
    commit: bool = True,
) -> ServiceIndicatorObservation:
    if not definition.enabled:
        raise ValueError("Service indicator is disabled")
    observed_at = _as_utc(payload.observed_at)
    if observed_at > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("observed_at cannot be more than five minutes in the future")
    assert_no_inline_secrets(payload.dimensions, "indicator.dimensions")
    _assert_safe_reference(payload.evidence_ref, "evidence_ref")
    existing = db.scalar(
        select(ServiceIndicatorObservation).where(
            ServiceIndicatorObservation.definition_id == definition.id,
            ServiceIndicatorObservation.source_observation_id
            == payload.source_observation_id,
        )
    )
    if existing is not None:
        if _observation_matches(existing, payload):
            return existing
        raise ValueError("Source observation ID is already used with different data")
    observation = ServiceIndicatorObservation(
        definition_id=definition.id,
        source_observation_id=payload.source_observation_id,
        value=payload.value,
        measurement_quality=payload.measurement_quality,
        dimensions=payload.dimensions,
        evidence_ref=payload.evidence_ref,
        observed_at=observed_at,
        created_by=actor,
    )
    try:
        with db.begin_nested():
            db.add(observation)
            db.flush()
        record_audit_event(
            db,
            event_type="service_indicator.observation_ingested",
            actor_type="service",
            actor_id=actor,
            entity_type="service_indicator_observation",
            entity_id=observation.id,
            details={
                "service_id": definition.service_id,
                "definition_id": definition.id,
                "indicator_key": definition.indicator_key,
                "source_observation_id": observation.source_observation_id,
                "observed_at": observed_at.isoformat(),
                "measurement_quality": observation.measurement_quality,
            },
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        if commit:
            db.rollback()
        existing = db.scalar(
            select(ServiceIndicatorObservation).where(
                ServiceIndicatorObservation.definition_id == definition.id,
                ServiceIndicatorObservation.source_observation_id
                == payload.source_observation_id,
            )
        )
        if existing is not None and _observation_matches(existing, payload):
            return existing
        raise ValueError(
            "Source observation ID is already used with different data"
        ) from exc
    if commit:
        db.refresh(observation)
    return observation


def list_observations(
    db: Session,
    definition: ServiceIndicatorDefinition,
    *,
    limit: int,
) -> list[ServiceIndicatorObservationRead]:
    observations = list(
        db.scalars(
            select(ServiceIndicatorObservation)
            .where(ServiceIndicatorObservation.definition_id == definition.id)
            .order_by(
                ServiceIndicatorObservation.observed_at.desc(),
                ServiceIndicatorObservation.ingested_at.desc(),
                ServiceIndicatorObservation.id.desc(),
            )
            .limit(limit)
        ).all()
    )
    now = utcnow()
    return [
        observation_to_read(definition, observation, now=now)
        for observation in observations
    ]
