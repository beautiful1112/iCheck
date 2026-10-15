from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from .schemas import APIModel
from .studio_schemas import GeneratedVisualizationSpec


class VisualizationAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PublishedVisualization(VisualizationAPIModel):
    artifact_id: str
    name: str
    description: str
    version_id: str
    version: int = Field(ge=1)
    published_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    layout_columns: int = Field(ge=1, le=4)
    refresh_seconds: int = Field(ge=15, le=3600)
    lookback_minutes: int = Field(ge=5, le=10_080)
    panel_count: int = Field(ge=1, le=12)


class VisualizationPoint(VisualizationAPIModel):
    observed_at: datetime
    value: float
    measurement_quality: Literal["measured", "estimated", "manual"]
    threshold_status: Literal[
        "healthy", "warning", "critical", "informational"
    ]


class VisualizationPanelRender(VisualizationAPIModel):
    panel_key: str
    title: str
    chart_type: Literal["line", "stat", "status"]
    service_key: str
    service_name: str | None
    indicator_key: str
    indicator_name: str | None
    kind: str | None
    unit: str | None
    state: Literal["ready", "no_data", "drifted"]
    drift_code: str | None
    current_status: Literal[
        "unknown",
        "stale",
        "healthy",
        "warning",
        "critical",
        "informational",
    ]
    breach_direction: Literal["above", "below", "none"] | None
    warning_threshold: float | None
    critical_threshold: float | None
    points: list[VisualizationPoint] = Field(max_length=500)
    point_count: int = Field(ge=0, le=500)
    points_truncated: bool


class VisualizationRender(PublishedVisualization):
    rendered_at: datetime
    scope_applied: bool
    spec: GeneratedVisualizationSpec
    panels: list[VisualizationPanelRender] = Field(min_length=1, max_length=12)
    point_count: int = Field(ge=0, le=6000)
    drifted_panel_count: int = Field(ge=0, le=12)
