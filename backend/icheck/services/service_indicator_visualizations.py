from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from ..models import (
    ServiceCatalogEntry,
    ServiceIndicatorDefinition,
    ServiceIndicatorObservation,
    utcnow,
)
from ..studio_schemas import GeneratedVisualizationSpec
from .authorization_scope import has_global_scope, service_scope_clause
from .control_plane_auth import PrincipalContext
from .service_indicators import observation_to_read, threshold_status


VISUALIZATION_FORMAT_VERSION = "icheck.visualization/v1"
VISUALIZATION_RUNTIME = "icheck_service_indicator_visualization_v1"
MAX_CATALOG_INDICATORS = 500


def _hash(document: Any) -> str:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def visualization_indicator_catalog(
    db: Session,
    principal: PrincipalContext | None = None,
) -> dict[str, Any]:
    """Return safe, bounded service-indicator choices for the authoring model."""

    query = (
        select(ServiceCatalogEntry, ServiceIndicatorDefinition)
        .join(
            ServiceIndicatorDefinition,
            ServiceIndicatorDefinition.service_id == ServiceCatalogEntry.id,
        )
        .where(
            ServiceCatalogEntry.status == "active",
            ServiceIndicatorDefinition.enabled.is_(True),
        )
    )
    if principal is not None:
        query = query.where(service_scope_clause(principal))
    rows = list(
        db.execute(
            query.order_by(
                ServiceCatalogEntry.service_key,
                ServiceIndicatorDefinition.indicator_key,
            ).limit(MAX_CATALOG_INDICATORS + 1)
        ).all()
    )
    truncated = len(rows) > MAX_CATALOG_INDICATORS
    rows = rows[:MAX_CATALOG_INDICATORS]
    indicators = []
    for service, definition in rows:
        has_data = db.scalar(
            select(
                exists().where(
                    ServiceIndicatorObservation.definition_id == definition.id
                )
            )
        )
        indicators.append(
            {
                "service_key": service.service_key,
                "service_name": service.name,
                "criticality": service.criticality,
                "indicator_key": definition.indicator_key,
                "indicator_name": definition.name,
                "kind": definition.kind,
                "unit": definition.unit,
                "breach_direction": definition.breach_direction,
                "warning_threshold": definition.warning_threshold,
                "critical_threshold": definition.critical_threshold,
                "has_observations": bool(has_data),
            }
        )
    return {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "truncated": truncated,
    }


def validate_visualization_selectors(
    spec: GeneratedVisualizationSpec,
    catalog: dict[str, Any],
) -> None:
    available = {
        (str(item["service_key"]), str(item["indicator_key"]))
        for item in catalog.get("indicators", [])
        if isinstance(item, dict)
    }
    requested = {
        (panel.service_key, panel.indicator_key) for panel in spec.panels
    }
    unavailable = sorted(requested - available)
    if unavailable:
        labels = [f"{service}/{indicator}" for service, indicator in unavailable]
        raise ValueError(
            "visualization selected unavailable service indicators: "
            f"{labels}"
        )


def visualization_artifact_documents(
    spec: GeneratedVisualizationSpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    spec_document = spec.model_dump(mode="json")
    spec_hash = _hash(spec_document)
    return (
        {
            "format_version": VISUALIZATION_FORMAT_VERSION,
            "spec": spec_document,
        },
        {
            "runtime": VISUALIZATION_RUNTIME,
            "data_source": "service_indicator_observations",
        },
        [
            {
                "name": "Deterministic service-indicator visualization validation",
                "expected_spec_sha256": spec_hash,
                "expected_panel_keys": sorted(
                    panel.panel_key for panel in spec.panels
                ),
            }
        ],
    )


def published_visualization_spec(
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> GeneratedVisualizationSpec:
    if set(definition) != {"format_version", "spec"}:
        raise ValueError("visualization definition has unsupported fields")
    if definition.get("format_version") != VISUALIZATION_FORMAT_VERSION:
        raise ValueError("visualization format_version is unsupported")
    spec = GeneratedVisualizationSpec.model_validate(definition.get("spec"))
    expected = visualization_artifact_documents(spec)
    if definition != expected[0]:
        raise ValueError("visualization definition is not canonical")
    if implementation != expected[1]:
        raise ValueError("visualization implementation contract is invalid")
    if tests != expected[2]:
        raise ValueError(
            "visualization validation contract does not match its spec"
        )
    return spec


def _service_rows(
    db: Session,
    service_keys: set[str],
    principal: PrincipalContext | None,
) -> list[ServiceCatalogEntry]:
    if not service_keys:
        return []
    query = select(ServiceCatalogEntry).where(
        ServiceCatalogEntry.service_key.in_(service_keys)
    )
    if principal is not None:
        query = query.where(service_scope_clause(principal))
    return list(db.scalars(query).all())


def visualization_is_fully_visible(
    db: Session,
    spec: GeneratedVisualizationSpec,
    principal: PrincipalContext,
) -> bool:
    if has_global_scope(principal):
        return True
    requested = {panel.service_key for panel in spec.panels}
    visible = {
        item.service_key for item in _service_rows(db, requested, principal)
    }
    return visible == requested


def _render_visualization(
    db: Session,
    spec: GeneratedVisualizationSpec,
    *,
    principal: PrincipalContext | None,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    now = evaluated_at or utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    else:
        now = now.astimezone(UTC)
    cutoff = now - timedelta(minutes=spec.lookback_minutes)
    service_keys = {panel.service_key for panel in spec.panels}
    services = {
        service.service_key: service
        for service in _service_rows(db, service_keys, principal)
    }
    service_ids = {service.id for service in services.values()}
    definitions = {}
    if service_ids:
        for definition in db.scalars(
            select(ServiceIndicatorDefinition).where(
                ServiceIndicatorDefinition.service_id.in_(service_ids)
            )
        ).all():
            service = next(
                item
                for item in services.values()
                if item.id == definition.service_id
            )
            definitions[(service.service_key, definition.indicator_key)] = definition

    panels: list[dict[str, Any]] = []
    total_points = 0
    for panel in spec.panels:
        service = services.get(panel.service_key)
        definition = definitions.get((panel.service_key, panel.indicator_key))
        drift_code: str | None = None
        if service is None:
            drift_code = "service_missing_or_out_of_scope"
        elif service.status != "active":
            drift_code = "service_retired"
        elif definition is None:
            drift_code = "indicator_missing"
        elif not definition.enabled:
            drift_code = "indicator_disabled"

        points: list[dict[str, Any]] = []
        truncated = False
        current_status = "unknown"
        service_name = service.name if service is not None else None
        indicator_name = definition.name if definition is not None else None
        kind = definition.kind if definition is not None else None
        unit = definition.unit if definition is not None else None
        warning_threshold = None
        critical_threshold = None
        breach_direction = None
        if definition is not None:
            if panel.show_thresholds:
                warning_threshold = definition.warning_threshold
                critical_threshold = definition.critical_threshold
                breach_direction = definition.breach_direction
            if drift_code is None:
                observations = list(
                    db.scalars(
                        select(ServiceIndicatorObservation)
                        .where(
                            ServiceIndicatorObservation.definition_id
                            == definition.id,
                            ServiceIndicatorObservation.observed_at >= cutoff,
                            ServiceIndicatorObservation.observed_at <= now,
                        )
                        .order_by(
                            ServiceIndicatorObservation.observed_at.desc(),
                            ServiceIndicatorObservation.ingested_at.desc(),
                            ServiceIndicatorObservation.id.desc(),
                        )
                        .limit(panel.max_points + 1)
                    ).all()
                )
                truncated = len(observations) > panel.max_points
                observations = observations[: panel.max_points]
                observations.reverse()
                points = [
                    {
                        "observed_at": (
                            item.observed_at.replace(tzinfo=UTC)
                            if item.observed_at.tzinfo is None
                            else item.observed_at.astimezone(UTC)
                        ).isoformat(),
                        "value": item.value,
                        "measurement_quality": item.measurement_quality,
                        "threshold_status": threshold_status(
                            definition,
                            item.value,
                        ),
                    }
                    for item in observations
                ]
                if observations:
                    latest = observation_to_read(
                        definition,
                        observations[-1],
                        now=now,
                    )
                    current_status = latest.effective_status

        state = "drifted" if drift_code else ("ready" if points else "no_data")
        total_points += len(points)
        panels.append(
            {
                "panel_key": panel.panel_key,
                "title": panel.title,
                "chart_type": panel.chart_type,
                "service_key": panel.service_key,
                "service_name": service_name,
                "indicator_key": panel.indicator_key,
                "indicator_name": indicator_name,
                "kind": kind,
                "unit": unit,
                "state": state,
                "drift_code": drift_code,
                "current_status": current_status,
                "breach_direction": breach_direction,
                "warning_threshold": warning_threshold,
                "critical_threshold": critical_threshold,
                "points": points,
                "point_count": len(points),
                "points_truncated": truncated,
            }
        )
    return {
        "rendered_at": now.isoformat(),
        "lookback_minutes": spec.lookback_minutes,
        "panels": panels,
        "panel_count": len(panels),
        "point_count": total_points,
        "drifted_panel_count": sum(
            1 for item in panels if item["state"] == "drifted"
        ),
    }


def visualization_preview(
    db: Session,
    spec: GeneratedVisualizationSpec,
) -> dict[str, Any]:
    return _render_visualization(db, spec, principal=None)


def visualization_runtime_render(
    db: Session,
    spec: GeneratedVisualizationSpec,
    principal: PrincipalContext,
) -> dict[str, Any]:
    return _render_visualization(db, spec, principal=principal)


def validate_visualization_artifact_contract(
    db: Session,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
    *,
    principal: PrincipalContext | None = None,
) -> dict[str, Any]:
    spec = published_visualization_spec(definition, implementation, tests)
    catalog = visualization_indicator_catalog(db, principal)
    validate_visualization_selectors(spec, catalog)
    preview = _render_visualization(db, spec, principal=principal)
    return {
        "runtime": VISUALIZATION_RUNTIME,
        "isolation": "declarative_view",
        "spec_sha256": tests[0]["expected_spec_sha256"],
        "panel_count": len(spec.panels),
        "layout_columns": spec.layout_columns,
        "refresh_seconds": spec.refresh_seconds,
        "lookback_minutes": spec.lookback_minutes,
        "preview": preview,
    }
