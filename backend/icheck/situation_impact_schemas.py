from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from .schemas import APIModel


class SituationImpactAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class SituationImpactNode(SituationImpactAPIModel):
    id: str
    entity_id: str
    node_type: Literal[
        "device",
        "endpoint",
        "knowledge_entity",
        "service",
        "service_indicator",
        "external_entity",
    ]
    role: Literal[
        "root",
        "adjacent",
        "correlated_symptom",
        "scoped_component",
        "dependency",
        "impacted_service",
        "dependent_service",
        "dependency_service",
        "service_indicator",
    ]
    label: str
    kind: str
    site: str | None
    status: str
    observed_at: datetime
    criticality: Literal["tier_0", "tier_1", "tier_2", "tier_3"] | None = None
    business_impact: Literal["critical", "high", "moderate", "low"] | None = None
    slo_target_percent: float | None = Field(default=None, ge=0, le=100)
    owner_team: str | None = None
    service_id: str | None = None
    indicator_key: str | None = None
    indicator_revision: int | None = Field(default=None, ge=1)
    value: float | None = None
    unit: str | None = None
    freshness_seconds: int | None = Field(default=None, ge=10, le=2_592_000)
    expires_at: datetime | None = None
    source_type: str | None = None
    source_ref: str | None = None
    measurement_quality: Literal["measured", "estimated", "manual"] | None = None
    threshold_status: Literal[
        "healthy", "warning", "critical", "informational"
    ] | None = None
    freshness_status: Literal["fresh", "stale"] | None = None
    evidence_ref: str | None = None


class SituationImpactEdge(SituationImpactAPIModel):
    id: str
    relationship_type: str
    source: str
    target: str
    directed: bool
    evidence_type: Literal[
        "endpoint_attachment",
        "wireless_session",
        "ip_observation",
        "scope_binding",
        "knowledge_relationship",
        "service_catalog_component",
        "service_catalog_dependency",
        "service_indicator_observation",
        "situation_alert_correlation",
        "situation_alert_topology_correlation",
    ]
    evidence_id: str
    observed_at: datetime


class SituationImpactPath(SituationImpactAPIModel):
    target_node_id: str
    node_ids: list[str] = Field(min_length=2, max_length=4)
    edge_ids: list[str] = Field(min_length=1, max_length=3)
    relationship_types: list[str] = Field(min_length=1, max_length=3)
    hop_count: int = Field(ge=1, le=3)


class SituationImpactSummary(SituationImpactAPIModel):
    native_neighbor_count: int = Field(ge=0, le=100)
    knowledge_entity_count: int = Field(ge=0, le=100)
    service_count: int = Field(ge=0, le=100)
    service_dependency_count: int = Field(ge=0, le=200)
    service_indicator_count: int = Field(ge=0, le=100)
    service_indicator_breach_count: int = Field(ge=0, le=100)
    stale_service_indicator_count: int = Field(ge=0, le=100)
    path_count: int = Field(ge=0, le=99)


class SituationImpactRead(SituationImpactAPIModel):
    situation_id: str
    root_node_id: str
    generated_at: datetime
    scope_applied: bool
    hypothesis_boundary: Literal["deterministic_context_not_root_cause"]
    nodes: list[SituationImpactNode] = Field(max_length=100)
    edges: list[SituationImpactEdge] = Field(max_length=200)
    paths: list[SituationImpactPath] = Field(max_length=99)
    summary: SituationImpactSummary
    nodes_truncated: bool
    edges_truncated: bool
    limits: dict[Literal["nodes", "edges", "path_hops"], int]
