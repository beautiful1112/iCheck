"""Offline synthetic PDF layout fixtures. Does not connect to the control plane."""
from __future__ import annotations

import argparse
import hashlib
from datetime import UTC, datetime
from pathlib import Path

from .models import ServiceReportInstance
from .report_schemas import ServiceReportRender
from .services.report_exports import render_report_export
from .services.report_instances import canonical_bytes, instance_material


def sample_instance(*, long: bool = False) -> tuple[ServiceReportInstance, ServiceReportRender]:
    timestamp = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    title = "Synthetic acceptance fixture - \u4e2d\u6587\u670d\u52a1\u5065\u5eb7\u62a5\u544a" if long else "Synthetic acceptance fixture - Orders API"
    sections = []
    selectors = []
    for index in range(20 if long else 2):
        label = f"{index + 1:02d}. " + (
            "\u4e2d\u6587\u76d1\u63a7\u6307\u6807 / Service-health acceptance - " + "long but bounded title for layout validation " * 3
            if long else ("Latency p95" if index == 0 else "Availability")
        )
        selector = {"section_key": f"metric-{index}", "title": label,
                    "service_key": "sample-api", "indicator_key": f"metric-{index}"}
        selectors.append(selector)
        drift = long and index % 5 == 3
        no_data = long and index % 5 == 4
        availability = not long and index == 1
        value = None if drift or no_data else (98.5 if availability else 220.0)
        sections.append({**selector, "service_name": "Synthetic sample API", "indicator_name": label,
                         "kind": "availability" if availability else "latency", "unit": "percent" if availability else "ms",
                         "state": "drifted" if drift else "no_data" if no_data else "ready",
                         "drift_code": "indicator_disabled" if drift else None,
                         "current_status": "unknown" if value is None else "critical", "current_value": value,
                         "sample_count": 0 if value is None else 3, "minimum": None if value is None else 98.5 if availability else 80.0,
                         "maximum": 99.99 if availability else value,
                         "average": None if value is None else 99.43 if availability else 140.0,
                         "first_observed_at": None if value is None else timestamp,
                         "last_observed_at": None if value is None else timestamp,
                         "trend": "insufficient_data" if value is None else "degrading", "breach_direction": "below" if availability else "above",
                         "warning_threshold": 99.9 if availability else 100.0,
                         "critical_threshold": 99.0 if availability else 200.0, "samples_truncated": long})
    snapshot = ServiceReportRender.model_validate({
        "artifact_id": "00000000-0000-0000-0000-000000000010", "name": "synthetic-report",
        "description": "Offline synthetic layout fixture. Not live lab acceptance evidence.",
        "version_id": "00000000-0000-0000-0000-000000000011", "version": 1, "published_at": timestamp,
        "content_hash": "1" * 64, "report_title": title, "lookback_minutes": 60,
        "section_count": len(sections), "generated_at": timestamp, "overall_status": "critical",
        "sample_count": sum(item["sample_count"] for item in sections),
        "drifted_section_count": sum(item["state"] == "drifted" for item in sections),
        "sections": sections, "scope_applied": True,
        "spec": {"artifact_name": "synthetic-report", "description": "Offline synthetic layout fixture.",
                 "report_title": title, "lookback_minutes": 60, "max_samples_per_indicator": 120,
                 "include_thresholds": True, "indicators": selectors},
    })
    instance = ServiceReportInstance(
        id="00000000-0000-0000-0000-000000000012", artifact_id=snapshot.artifact_id,
        artifact_version_id=snapshot.version_id, tenant_id="00000000-0000-0000-0000-000000000001",
        region_id="00000000-0000-0000-0000-000000000002", snapshot=snapshot.model_dump(mode="json"),
        generated_at=timestamp, created_at=timestamp, created_by="synthetic.fixture", request_sha256="2" * 64,
    )
    encoded = canonical_bytes(instance_material(instance))
    instance.snapshot_size_bytes = len(encoded)
    instance.content_sha256 = hashlib.sha256(encoded).hexdigest()
    return instance, snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("output/pdf"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, long in (("service-report-synthetic", False), ("service-report-long-cjk-synthetic", True)):
        instance, snapshot = sample_instance(long=long)
        export = render_report_export(instance, snapshot, "pdf")
        path = args.output_dir / f"{name}.pdf"
        path.write_bytes(export.body)
        print(f"{path.resolve()} sha256={export.sha256}")


if __name__ == "__main__":
    main()
