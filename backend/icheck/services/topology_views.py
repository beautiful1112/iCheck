from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from ..models import (
    Device,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    KnowledgeEntity,
    KnowledgeRelationship,
    WirelessClientSession,
)
from ..studio_schemas import GeneratedTopologySpec
from .authorization_scope import (
    device_scope_clause,
    endpoint_scope_clause,
    knowledge_entity_scope_clause,
    knowledge_relationship_scope_clause,
)
from .control_plane_auth import PrincipalContext


TOPOLOGY_FORMAT_VERSION = "icheck.topology/v1"
TOPOLOGY_RUNTIME = "icheck_topology_view_v1"
MAX_PREVIEW_NODES = 100
MAX_PREVIEW_EDGES = 200
MAX_RUNTIME_NODES = 500
MAX_RUNTIME_EDGES = 1000


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def topology_inventory_catalog(
    db: Session,
    principal: PrincipalContext | None = None,
) -> dict[str, Any]:
    device_count_query = select(func.count()).select_from(Device)
    endpoint_count_query = select(func.count()).select_from(Endpoint)
    entity_count_query = select(func.count()).select_from(KnowledgeEntity)
    relationship_count_query = select(func.count()).select_from(
        KnowledgeRelationship
    )
    device_kind_query = select(distinct(Device.kind))
    device_site_query = select(distinct(Device.site)).where(
        Device.site.is_not(None)
    )
    entity_type_query = select(distinct(KnowledgeEntity.entity_type))
    entity_site_query = select(distinct(KnowledgeEntity.scope_site)).where(
        KnowledgeEntity.scope_site.is_not(None)
    )
    relationship_type_query = select(
        distinct(KnowledgeRelationship.relationship_type)
    )
    if principal is not None:
        device_clause = device_scope_clause(principal)
        endpoint_clause = endpoint_scope_clause(principal)
        entity_clause = knowledge_entity_scope_clause(principal)
        relationship_clause = knowledge_relationship_scope_clause(principal)
        device_count_query = device_count_query.where(device_clause)
        endpoint_count_query = endpoint_count_query.where(endpoint_clause)
        entity_count_query = entity_count_query.where(entity_clause)
        relationship_count_query = relationship_count_query.where(
            relationship_clause
        )
        device_kind_query = device_kind_query.where(device_clause)
        device_site_query = device_site_query.where(device_clause)
        entity_type_query = entity_type_query.where(entity_clause)
        entity_site_query = entity_site_query.where(entity_clause)
        relationship_type_query = relationship_type_query.where(
            relationship_clause
        )

    knowledge_entity_count = db.scalar(entity_count_query) or 0
    knowledge_relationship_count = db.scalar(relationship_count_query) or 0
    sites = {
        item
        for item in db.scalars(device_site_query).all()
        if item
    }
    sites.update(
        item
        for item in db.scalars(entity_site_query).all()
        if item
    )
    return {
        "device_count": db.scalar(device_count_query) or 0,
        "endpoint_count": db.scalar(endpoint_count_query) or 0,
        "device_kinds": list(
            db.scalars(device_kind_query.order_by(Device.kind)).all()
        ),
        "knowledge_entity_count": knowledge_entity_count,
        "knowledge_relationship_count": knowledge_relationship_count,
        "knowledge_entity_types": list(
            db.scalars(
                entity_type_query.order_by(KnowledgeEntity.entity_type)
            ).all()
        ),
        "knowledge_relationship_types": list(
            db.scalars(
                relationship_type_query.order_by(
                    KnowledgeRelationship.relationship_type
                )
            ).all()
        ),
        "sites": sorted(sites),
        "available_node_types": [
            "device",
            "endpoint",
            *(["knowledge_entity"] if knowledge_entity_count else []),
        ],
        "available_edge_types": [
            "wired_attachment",
            "wireless_association",
            "ip_observation",
            *(
                ["knowledge_relationship"]
                if knowledge_relationship_count
                else []
            ),
        ],
    }


def _group(
    spec: GeneratedTopologySpec,
    *,
    kind: str | None,
    site: str | None,
) -> str | None:
    if spec.group_by == "site":
        return site or "unassigned"
    if spec.group_by == "kind":
        return kind or "endpoint"
    return None


def _topology_graph(
    db: Session,
    spec: GeneratedTopologySpec,
    *,
    node_limit: int,
    edge_limit: int,
    device_scope: ColumnElement[bool] | None = None,
    endpoint_scope: ColumnElement[bool] | None = None,
    knowledge_entity_scope: ColumnElement[bool] | None = None,
    knowledge_relationship_scope: ColumnElement[bool] | None = None,
    focus_device_ids: set[str] | None = None,
    focus_endpoint_ids: set[str] | None = None,
    focus_knowledge_entity_ids: set[str] | None = None,
) -> dict[str, Any]:
    graph_node_limit = min(spec.max_nodes, node_limit)
    graph_edge_limit = min(spec.max_edges, edge_limit)
    node_types = set(spec.node_types)
    ordered_node_types = [
        item
        for item in ("device", "endpoint", "knowledge_entity")
        if item in node_types
    ]
    base_limit = graph_node_limit // len(ordered_node_types)
    remainder = graph_node_limit % len(ordered_node_types)
    node_limits = {
        node_type: base_limit + (1 if index < remainder else 0)
        for index, node_type in enumerate(ordered_node_types)
    }
    device_limit = node_limits.get("device", 0)
    endpoint_limit = node_limits.get("endpoint", 0)
    knowledge_limit = node_limits.get("knowledge_entity", 0)

    devices: list[Device] = []
    endpoints: list[Endpoint] = []
    knowledge_entities: list[KnowledgeEntity] = []
    nodes_truncated = False
    if "device" in node_types:
        query = select(Device)
        if device_scope is not None:
            query = query.where(device_scope)
        if focus_device_ids is not None:
            query = query.where(Device.id.in_(focus_device_ids))
        if spec.device_kinds:
            query = query.where(Device.kind.in_(spec.device_kinds))
        if spec.sites:
            query = query.where(Device.site.in_(spec.sites))
        if spec.enabled_devices_only:
            query = query.where(Device.enabled.is_(True))
        found = list(
            db.scalars(query.order_by(Device.name).limit(device_limit + 1)).all()
        )
        nodes_truncated = nodes_truncated or len(found) > device_limit
        devices = found[:device_limit]
    if "endpoint" in node_types:
        query = select(Endpoint)
        if endpoint_scope is not None:
            query = query.where(endpoint_scope)
        if focus_endpoint_ids is not None:
            query = query.where(Endpoint.id.in_(focus_endpoint_ids))
        found = list(
            db.scalars(
                query.order_by(Endpoint.last_seen.desc(), Endpoint.id).limit(
                    endpoint_limit + 1
                )
            ).all()
        )
        nodes_truncated = nodes_truncated or len(found) > endpoint_limit
        endpoints = found[:endpoint_limit]
    if "knowledge_entity" in node_types:
        query = select(KnowledgeEntity)
        if knowledge_entity_scope is not None:
            query = query.where(knowledge_entity_scope)
        if focus_knowledge_entity_ids is not None:
            query = query.where(
                KnowledgeEntity.id.in_(focus_knowledge_entity_ids)
            )
        if spec.knowledge_entity_types:
            query = query.where(
                KnowledgeEntity.entity_type.in_(spec.knowledge_entity_types)
            )
        if spec.sites:
            query = query.where(KnowledgeEntity.scope_site.in_(spec.sites))
        if spec.active_entities_only:
            query = query.where(KnowledgeEntity.active.is_(True))
        found = list(
            db.scalars(
                query.order_by(
                    KnowledgeEntity.last_seen.desc(),
                    KnowledgeEntity.id,
                ).limit(knowledge_limit + 1)
            ).all()
        )
        nodes_truncated = nodes_truncated or len(found) > knowledge_limit
        knowledge_entities = found[:knowledge_limit]

    nodes: list[dict[str, Any]] = [
        {
            "id": f"device:{device.id}",
            "entity_id": device.id,
            "node_type": "device",
            "label": device.name,
            "kind": device.kind,
            "site": device.site,
            "group": _group(spec, kind=device.kind, site=device.site),
            "status": device.onboarding_status,
        }
        for device in devices
    ]
    nodes.extend(
        {
            "id": f"endpoint:{endpoint.id}",
            "entity_id": endpoint.id,
            "node_type": "endpoint",
            "label": endpoint.hostname or endpoint.mac_address,
            "kind": "endpoint",
            "site": None,
            "group": _group(spec, kind="endpoint", site=None),
            "status": "observed",
            "mac_address": endpoint.mac_address,
        }
        for endpoint in endpoints
    )
    nodes.extend(
        {
            "id": f"knowledge:{entity.id}",
            "entity_id": entity.id,
            "node_type": "knowledge_entity",
            "label": entity.display_name,
            "kind": entity.entity_type,
            "site": entity.scope_site,
            "group": _group(
                spec,
                kind=entity.entity_type,
                site=entity.scope_site,
            ),
            "status": entity.status or ("active" if entity.active else "inactive"),
            "external_key": entity.external_key,
        }
        for entity in knowledge_entities
    )
    device_ids = {device.id for device in devices}
    endpoint_ids = {endpoint.id for endpoint in endpoints}
    knowledge_entity_ids = {entity.id for entity in knowledge_entities}
    edges: list[dict[str, Any]] = []
    edges_truncated = False

    def remaining() -> int:
        return max(0, graph_edge_limit - len(edges))

    if device_ids and endpoint_ids and "wired_attachment" in spec.edge_types:
        query = select(EndpointAttachment).where(
            EndpointAttachment.endpoint_id.in_(endpoint_ids),
            EndpointAttachment.collector_device_id.in_(device_ids),
        )
        if spec.active_edges_only:
            query = query.where(EndpointAttachment.active.is_(True))
        rows = list(
            db.scalars(
                query.order_by(EndpointAttachment.last_seen.desc()).limit(
                    remaining() + 1
                )
            ).all()
        )
        edges_truncated = edges_truncated or len(rows) > remaining()
        for row in rows[: remaining()]:
            edges.append(
                {
                    "id": f"wired_attachment:{row.id}",
                    "edge_type": "wired_attachment",
                    "source": f"device:{row.collector_device_id}",
                    "target": f"endpoint:{row.endpoint_id}",
                    "label": row.interface_name or "wired",
                    "metadata": {
                        "interface_name": row.interface_name,
                        "vlan_id": row.vlan_id,
                    },
                }
            )

    if device_ids and endpoint_ids and "wireless_association" in spec.edge_types:
        query = select(WirelessClientSession).where(
            WirelessClientSession.endpoint_id.in_(endpoint_ids),
            WirelessClientSession.controller_id.in_(device_ids),
        )
        if spec.active_edges_only:
            query = query.where(WirelessClientSession.active.is_(True))
        rows = list(
            db.scalars(
                query.order_by(WirelessClientSession.last_seen.desc()).limit(
                    remaining() + 1
                )
            ).all()
        )
        edges_truncated = edges_truncated or len(rows) > remaining()
        for row in rows[: remaining()]:
            edges.append(
                {
                    "id": f"wireless_association:{row.id}",
                    "edge_type": "wireless_association",
                    "source": f"device:{row.controller_id}",
                    "target": f"endpoint:{row.endpoint_id}",
                    "label": row.access_point or row.ssid or "wireless",
                    "metadata": {
                        "access_point": row.access_point,
                        "ssid": row.ssid,
                        "vlan_id": row.vlan_id,
                        "rssi": row.rssi,
                    },
                }
            )

    if device_ids and endpoint_ids and "ip_observation" in spec.edge_types:
        query = select(IPAddressObservation).where(
            IPAddressObservation.endpoint_id.in_(endpoint_ids),
            IPAddressObservation.collector_device_id.in_(device_ids),
        )
        if spec.active_edges_only:
            query = query.where(IPAddressObservation.active.is_(True))
        rows = list(
            db.scalars(
                query.order_by(IPAddressObservation.last_seen.desc()).limit(
                    remaining() + 1
                )
            ).all()
        )
        edges_truncated = edges_truncated or len(rows) > remaining()
        for row in rows[: remaining()]:
            edges.append(
                {
                    "id": f"ip_observation:{row.id}",
                    "edge_type": "ip_observation",
                    "source": f"device:{row.collector_device_id}",
                    "target": f"endpoint:{row.endpoint_id}",
                    "label": row.ip_address,
                    "metadata": {
                        "ip_address": row.ip_address,
                        "vlan_id": row.vlan_id,
                        "source": row.source.value,
                    },
                }
            )

    if (
        knowledge_entity_ids
        and "knowledge_relationship" in spec.edge_types
        and remaining() > 0
    ):
        query = select(KnowledgeRelationship).where(
            KnowledgeRelationship.source_entity_id.in_(knowledge_entity_ids),
            KnowledgeRelationship.target_entity_id.in_(knowledge_entity_ids),
        )
        if knowledge_relationship_scope is not None:
            query = query.where(knowledge_relationship_scope)
        if spec.knowledge_relationship_types:
            query = query.where(
                KnowledgeRelationship.relationship_type.in_(
                    spec.knowledge_relationship_types
                )
            )
        if spec.active_edges_only:
            query = query.where(KnowledgeRelationship.active.is_(True))
        rows = list(
            db.scalars(
                query.order_by(
                    KnowledgeRelationship.last_seen.desc(),
                    KnowledgeRelationship.id,
                ).limit(remaining() + 1)
            ).all()
        )
        edges_truncated = edges_truncated or len(rows) > remaining()
        for row in rows[: remaining()]:
            edges.append(
                {
                    "id": f"knowledge_relationship:{row.id}",
                    "edge_type": "knowledge_relationship",
                    "relationship_type": row.relationship_type,
                    "source": f"knowledge:{row.source_entity_id}",
                    "target": f"knowledge:{row.target_entity_id}",
                    "label": row.relationship_type,
                    "metadata": {"directed": row.directed},
                }
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes_truncated": nodes_truncated,
        "edges_truncated": edges_truncated,
        "limits": {
            "nodes": graph_node_limit,
            "edges": graph_edge_limit,
        },
    }


def topology_preview(
    db: Session,
    spec: GeneratedTopologySpec,
) -> dict[str, Any]:
    graph = _topology_graph(
        db,
        spec,
        node_limit=MAX_PREVIEW_NODES,
        edge_limit=MAX_PREVIEW_EDGES,
    )
    graph["preview_limits"] = graph.pop("limits")
    return graph


def topology_scoped_preview(
    db: Session,
    spec: GeneratedTopologySpec,
    principal: PrincipalContext,
) -> dict[str, Any]:
    graph = _topology_graph(
        db,
        spec,
        node_limit=MAX_PREVIEW_NODES,
        edge_limit=MAX_PREVIEW_EDGES,
        device_scope=device_scope_clause(principal),
        endpoint_scope=endpoint_scope_clause(principal),
        knowledge_entity_scope=knowledge_entity_scope_clause(principal),
        knowledge_relationship_scope=knowledge_relationship_scope_clause(
            principal
        ),
    )
    graph["preview_limits"] = graph.pop("limits")
    return graph


def validate_topology_selectors(
    spec: GeneratedTopologySpec,
    catalog: dict[str, Any],
) -> None:
    unknown_kinds = sorted(
        set(spec.device_kinds) - set(catalog["device_kinds"])
    )
    if unknown_kinds:
        raise ValueError(
            f"topology references unavailable device kinds {unknown_kinds}"
        )
    unknown_sites = sorted(set(spec.sites) - set(catalog["sites"]))
    if unknown_sites:
        raise ValueError(f"topology references unavailable sites {unknown_sites}")
    unknown_entity_types = sorted(
        set(spec.knowledge_entity_types)
        - set(catalog["knowledge_entity_types"])
    )
    if unknown_entity_types:
        raise ValueError(
            "topology references unavailable knowledge entity types "
            f"{unknown_entity_types}"
        )
    unknown_relationship_types = sorted(
        set(spec.knowledge_relationship_types)
        - set(catalog["knowledge_relationship_types"])
    )
    if unknown_relationship_types:
        raise ValueError(
            "topology references unavailable knowledge relationship types "
            f"{unknown_relationship_types}"
        )


def topology_runtime_graph(
    db: Session,
    spec: GeneratedTopologySpec,
    principal: PrincipalContext,
    *,
    focus_node_ids: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Render a published view against current, object-scoped inventory."""

    return _topology_graph(
        db,
        spec,
        node_limit=MAX_RUNTIME_NODES,
        edge_limit=MAX_RUNTIME_EDGES,
        device_scope=device_scope_clause(principal),
        endpoint_scope=endpoint_scope_clause(principal),
        knowledge_entity_scope=knowledge_entity_scope_clause(principal),
        knowledge_relationship_scope=knowledge_relationship_scope_clause(
            principal
        ),
        focus_device_ids=(
            focus_node_ids.get("device", set()) if focus_node_ids else None
        ),
        focus_endpoint_ids=(
            focus_node_ids.get("endpoint", set()) if focus_node_ids else None
        ),
        focus_knowledge_entity_ids=(
            focus_node_ids.get("knowledge_entity", set())
            if focus_node_ids
            else None
        ),
    )


def topology_artifact_documents(
    spec: GeneratedTopologySpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    spec_document = spec.model_dump(mode="json")
    spec_hash = _hash(spec_document)
    return (
        {
            "format_version": TOPOLOGY_FORMAT_VERSION,
            "spec": spec_document,
        },
        {
            "runtime": TOPOLOGY_RUNTIME,
            "layout": spec.layout,
        },
        [
            {
                "name": "Deterministic topology view validation",
                "expected_spec_sha256": spec_hash,
                "expected_node_types": sorted(spec.node_types),
                "expected_edge_types": sorted(spec.edge_types),
            }
        ],
    )


def published_topology_spec(
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> GeneratedTopologySpec:
    """Load a canonical immutable topology contract without querying inventory."""

    if set(definition) != {"format_version", "spec"}:
        raise ValueError("topology definition has unsupported fields")
    if definition.get("format_version") != TOPOLOGY_FORMAT_VERSION:
        raise ValueError("topology format_version is unsupported")
    spec = GeneratedTopologySpec.model_validate(definition.get("spec"))
    expected_definition, expected_implementation, expected_tests = (
        topology_artifact_documents(spec)
    )
    if definition != expected_definition:
        raise ValueError("topology definition is not canonical")
    if implementation != expected_implementation:
        raise ValueError("topology implementation contract is invalid")
    if tests != expected_tests:
        raise ValueError("topology validation contract does not match its spec")
    return spec


def validate_topology_artifact_contract(
    db: Session,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
    *,
    principal: PrincipalContext | None = None,
) -> dict[str, Any]:
    spec = published_topology_spec(definition, implementation, tests)
    if principal is not None:
        validate_topology_selectors(
            spec,
            topology_inventory_catalog(db, principal),
        )
        preview = topology_scoped_preview(db, spec, principal)
    else:
        preview = topology_preview(db, spec)
    if not preview["nodes"]:
        raise ValueError("topology selectors produced an empty preview")
    return {
        "runtime": TOPOLOGY_RUNTIME,
        "isolation": "declarative_view",
        "spec_sha256": tests[0]["expected_spec_sha256"],
        "layout": spec.layout,
        "group_by": spec.group_by,
        "node_types": sorted(spec.node_types),
        "edge_types": sorted(spec.edge_types),
        "preview": preview,
    }
