from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field

from .schemas import APIModel
from .studio_schemas import GeneratedTopologySpec


class TopologyAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class PublishedTopologyView(TopologyAPIModel):
    artifact_id: str
    name: str
    description: str
    version_id: str
    version: int = Field(ge=1)
    published_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    layout: Literal["force", "hierarchical", "radial"]
    group_by: Literal["none", "site", "kind"]
    node_types: list[Literal["device", "endpoint", "knowledge_entity"]]
    edge_types: list[
        Literal[
            "wired_attachment",
            "wireless_association",
            "ip_observation",
            "knowledge_relationship",
        ]
    ]
    max_nodes: int = Field(ge=10, le=500)
    max_edges: int = Field(ge=10, le=1000)


class TopologyNode(TopologyAPIModel):
    id: str
    entity_id: str
    node_type: Literal["device", "endpoint", "knowledge_entity"]
    label: str
    kind: str
    site: str | None
    group: str | None
    status: str
    mac_address: str | None = None
    external_key: str | None = None


class TopologyEdge(TopologyAPIModel):
    id: str
    edge_type: Literal[
        "wired_attachment",
        "wireless_association",
        "ip_observation",
        "knowledge_relationship",
    ]
    relationship_type: str | None = None
    source: str
    target: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyLimits(TopologyAPIModel):
    nodes: int = Field(ge=0, le=500)
    edges: int = Field(ge=0, le=1000)


class SituationTopologyContext(TopologyAPIModel):
    situation_id: str
    title: str
    status: str
    severity: str
    root_node_id: str
    hypothesis_boundary: Literal["deterministic_context_not_root_cause"]
    native_neighbor_count: int = Field(ge=0, le=100)
    knowledge_entity_count: int = Field(ge=0, le=100)
    service_count: int = Field(ge=0, le=100)
    service_dependency_count: int = Field(ge=0, le=200)
    service_indicator_count: int = Field(ge=0, le=100)
    service_indicator_breach_count: int = Field(ge=0, le=100)
    stale_service_indicator_count: int = Field(ge=0, le=100)
    path_count: int = Field(ge=0, le=99)


class TopologyRender(PublishedTopologyView):
    rendered_at: datetime
    scope_applied: bool
    spec: GeneratedTopologySpec
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    node_count: int = Field(ge=0, le=500)
    edge_count: int = Field(ge=0, le=1000)
    nodes_truncated: bool
    edges_truncated: bool
    limits: TopologyLimits
    context: SituationTopologyContext | None = None
