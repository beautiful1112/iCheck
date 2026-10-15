from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy.orm import Session

from ..models import ArtifactKind, ArtifactVersion, utcnow

from ..studio_schemas import (
    GeneratedServiceReportSpec,
    GeneratedRetainedProofReportSpec,
    GeneratedVisualizationSpec,
    VisualizationPanel,
)
from .control_plane_auth import PrincipalContext
from .service_indicator_visualizations import (
    visualization_indicator_catalog,
    visualization_is_fully_visible,
    visualization_preview,
    visualization_runtime_render,
)


SERVICE_REPORT_FORMAT_VERSION = "icheck.service-health-report/v1"
SERVICE_REPORT_RUNTIME = "icheck_service_health_report_v1"
RETAINED_REPORT_FORMAT_VERSION = "icheck.service-health-report/v2"
RETAINED_REPORT_RUNTIME = "icheck_service_health_report_v2"
_STATUS_RANK = {"unknown": 0, "healthy": 1, "warning": 2, "critical": 3}


def _hash(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _visualization_spec(
    spec: GeneratedServiceReportSpec,
) -> GeneratedVisualizationSpec:
    return GeneratedVisualizationSpec(
        artifact_name=spec.artifact_name,
        description=spec.description,
        layout_columns=1,
        refresh_seconds=3600,
        lookback_minutes=spec.lookback_minutes,
        panels=[
            VisualizationPanel(
                panel_key=item.section_key,
                title=item.title,
                chart_type="stat",
                service_key=item.service_key,
                indicator_key=item.indicator_key,
                show_thresholds=spec.include_thresholds,
                max_points=spec.max_samples_per_indicator,
            )
            for item in spec.indicators
        ],
    )


def validate_service_report_selectors(
    spec: GeneratedServiceReportSpec,
    catalog: dict[str, Any],
) -> None:
    available = {
        (str(item["service_key"]), str(item["indicator_key"]))
        for item in catalog.get("indicators", [])
        if isinstance(item, dict)
    }
    requested = {
        (item.service_key, item.indicator_key) for item in spec.indicators
    }
    unavailable = sorted(requested - available)
    if unavailable:
        labels = [f"{service}/{indicator}" for service, indicator in unavailable]
        raise ValueError(
            "report selected unavailable service indicators: " f"{labels}"
        )


def service_report_artifact_documents(
    spec: GeneratedServiceReportSpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    document = spec.model_dump(mode="json")
    retained = isinstance(spec, GeneratedRetainedProofReportSpec)
    return (
        {
            "format_version": RETAINED_REPORT_FORMAT_VERSION if retained else SERVICE_REPORT_FORMAT_VERSION,
            "spec": document,
        },
        {
            "runtime": RETAINED_REPORT_RUNTIME if retained else SERVICE_REPORT_RUNTIME,
            "data_source": "service_indicators_and_retained_domain_proofs" if retained else "service_indicator_observations",
            "render_mode": "deterministic_snapshot",
        },
        [
            {
                "name": "Deterministic service-health report validation",
                "expected_spec_sha256": _hash(document),
                "expected_section_keys": sorted(
                    [item.section_key for item in spec.indicators] +
                    ([item.section_key for item in spec.retained_proofs] if retained else [])
                ),
            }
        ],
    )


def published_service_report_spec(
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> GeneratedServiceReportSpec:
    if set(definition) != {"format_version", "spec"}:
        raise ValueError("service report definition has unsupported fields")
    if definition.get("format_version") not in {SERVICE_REPORT_FORMAT_VERSION, RETAINED_REPORT_FORMAT_VERSION}:
        raise ValueError("service report format_version is unsupported")
    model = GeneratedRetainedProofReportSpec if definition["format_version"] == RETAINED_REPORT_FORMAT_VERSION else GeneratedServiceReportSpec
    spec = model.model_validate(definition.get("spec"))
    expected = service_report_artifact_documents(spec)
    if definition != expected[0]:
        raise ValueError("service report definition is not canonical")
    if implementation != expected[1]:
        raise ValueError("service report implementation contract is invalid")
    if tests != expected[2]:
        raise ValueError("service report validation contract does not match its spec")
    return spec


def verified_service_report_version_spec(version: ArtifactVersion) -> GeneratedServiceReportSpec:
    from .collectors import artifact_content_hash

    spec = published_service_report_spec(version.definition, version.implementation, version.tests)
    if version.published_at is None or not version.content_hash:
        raise ValueError("Published service report provenance is incomplete")
    actual = artifact_content_hash(
        kind=ArtifactKind.REPORT, definition=version.definition,
        implementation=version.implementation, tests=version.tests,
        collector_definition=None,
    )
    if actual != version.content_hash:
        raise ValueError("Published service report content hash does not match")
    return spec


def service_report_version_summary(version: ArtifactVersion, spec: GeneratedServiceReportSpec) -> dict[str, Any]:
    return {
        "artifact_id": version.artifact_id, "name": version.artifact.name,
        "description": version.artifact.description, "version_id": version.id,
        "version": version.version, "published_at": version.published_at,
        "content_hash": version.content_hash, "report_title": spec.report_title,
        "lookback_minutes": spec.lookback_minutes, "section_count": len(spec.indicators) +
            (len(spec.retained_proofs) if isinstance(spec, GeneratedRetainedProofReportSpec) else 0),
    }


def service_report_is_fully_visible(
    db: Session,
    spec: GeneratedServiceReportSpec,
    principal: PrincipalContext,
) -> bool:
    if spec.indicators and not visualization_is_fully_visible(db, _visualization_spec(spec), principal):
        return False
    if isinstance(spec, GeneratedRetainedProofReportSpec):
        from .report_retained_proofs import retained_section
        try:
            if not principal.principal_id or principal.principal_type not in {"user", "service", "investigation_snapshot"}:
                raise PermissionError("Retained proof reads require a persisted identity")
            for selector in spec.retained_proofs:
                retained_section(db, selector, principal)
        except (LookupError, PermissionError):
            return False
    return True


def _trend(points: list[dict[str, Any]], direction: str | None) -> str:
    if len(points) < 2 or direction not in {"above", "below"}:
        return "insufficient_data"
    first = float(points[0]["value"])
    last = float(points[-1]["value"])
    tolerance = max(abs(first), abs(last), 1.0) * 0.001
    if abs(last - first) <= tolerance:
        return "stable"
    moving_toward_breach = last > first if direction == "above" else last < first
    return "degrading" if moving_toward_breach else "improving"


def _report_from_render(
    spec: GeneratedServiceReportSpec,
    render: dict[str, Any],
) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    overall = "unknown"
    for panel in render["panels"]:
        points = list(panel["points"])
        values = [float(item["value"]) for item in points]
        current_value = values[-1] if values else None
        current_status = str(panel["current_status"])
        if _STATUS_RANK.get(current_status, 0) > _STATUS_RANK.get(overall, 0):
            overall = current_status
        sections.append(
            {
                "section_key": panel["panel_key"],
                "title": panel["title"],
                "service_key": panel["service_key"],
                "service_name": panel["service_name"],
                "indicator_key": panel["indicator_key"],
                "indicator_name": panel["indicator_name"],
                "kind": panel["kind"],
                "unit": panel["unit"],
                "state": panel["state"],
                "drift_code": panel["drift_code"],
                "current_status": current_status,
                "current_value": current_value,
                "sample_count": len(values),
                "minimum": min(values) if values else None,
                "maximum": max(values) if values else None,
                "average": (sum(values) / len(values)) if values else None,
                "first_observed_at": points[0]["observed_at"] if points else None,
                "last_observed_at": points[-1]["observed_at"] if points else None,
                "trend": _trend(points, panel["breach_direction"]),
                "breach_direction": panel["breach_direction"],
                "warning_threshold": panel["warning_threshold"],
                "critical_threshold": panel["critical_threshold"],
                "samples_truncated": panel["points_truncated"],
            }
        )
    return {
        "report_title": spec.report_title,
        "generated_at": render["rendered_at"],
        "lookback_minutes": render["lookback_minutes"],
        "overall_status": overall,
        "sections": sections,
        "section_count": len(sections),
        "sample_count": render["point_count"],
        "drifted_section_count": render["drifted_panel_count"],
    }


def service_report_preview(
    db: Session,
    spec: GeneratedServiceReportSpec,
) -> dict[str, Any]:
    if isinstance(spec, GeneratedRetainedProofReportSpec):
        # Artifact validation is declarative and non-material. Runtime captures
        # separately authorize every exact retained reference; no system-owned
        # Studio preview may expose another reader's private proof.
        metric = service_report_preview(db, GeneratedServiceReportSpec.model_validate(
            spec.model_dump(exclude={"proof_contract_version", "retained_proofs"}))) if spec.indicators else {
                "generated_at": utcnow().isoformat(),
                "lookback_minutes": spec.lookback_minutes, "overall_status": "unknown",
                "sample_count": 0, "drifted_section_count": 0, "sections": [], "section_count": 0}
        return {**metric, "report_title": spec.report_title,
            "section_count": len(spec.indicators) + len(spec.retained_proofs),
            "retained_reference_count": len(spec.retained_proofs), "retained_material_included": False}
    return _report_from_render(
        spec,
        visualization_preview(db, _visualization_spec(spec)),
    )


def service_report_runtime_generate(
    db: Session,
    spec: GeneratedServiceReportSpec,
    principal: PrincipalContext,
) -> dict[str, Any]:
    if spec.indicators:
        metric = _report_from_render(spec, visualization_runtime_render(db, _visualization_spec(spec), principal))
    else:
        metric = {"report_title": spec.report_title, "generated_at": utcnow(),
            "lookback_minutes": spec.lookback_minutes, "overall_status": "unknown",
            "sample_count": 0, "drifted_section_count": 0, "sections": [], "section_count": 0}
    if isinstance(spec, GeneratedRetainedProofReportSpec):
        from .report_retained_proofs import initiating_reader, retained_section
        return {**metric, "format_version": "icheck.service-health-report-render/v2",
            "initiating_reader": initiating_reader(principal),
            "retained_proofs": [retained_section(db, selector, principal) for selector in spec.retained_proofs],
            "section_count": len(spec.indicators) + len(spec.retained_proofs)}
    return metric


def validate_service_report_artifact_contract(
    db: Session,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> dict[str, Any]:
    spec = published_service_report_spec(definition, implementation, tests)
    validate_service_report_selectors(spec, visualization_indicator_catalog(db))
    preview = service_report_preview(db, spec)
    return {
        "runtime": RETAINED_REPORT_RUNTIME if isinstance(spec, GeneratedRetainedProofReportSpec) else SERVICE_REPORT_RUNTIME,
        "isolation": "declarative_report",
        "spec_sha256": tests[0]["expected_spec_sha256"],
        "section_count": len(spec.indicators) + (len(spec.retained_proofs) if isinstance(spec, GeneratedRetainedProofReportSpec) else 0),
        "lookback_minutes": spec.lookback_minutes,
        "max_samples_per_indicator": spec.max_samples_per_indicator,
        "preview": preview,
    }
