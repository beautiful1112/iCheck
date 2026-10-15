from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import (
    Alert,
    Device,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    KnowledgeEntity,
    KnowledgeRelationship,
    ServiceCatalogComponent,
    ServiceCatalogDependency,
    ServiceCatalogEntry,
    Situation,
    SituationAlert,
    WirelessClientSession,
    utcnow,
)
from .authorization_scope import (
    device_scope_clause,
    endpoint_scope_clause,
    has_global_scope,
    knowledge_entity_scope_clause,
    knowledge_relationship_scope_clause,
    service_scope_clause,
)
from .control_plane_auth import PrincipalContext
from .service_indicators import latest_indicator_rows, observation_to_read


MAX_IMPACT_NODES = 100
MAX_IMPACT_EDGES = 200
MAX_PATH_HOPS = 3
DEVICE_ENTITY_TYPES = {"device", "collector_device"}
ENDPOINT_ENTITY_TYPES = {"endpoint", "terminal"}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _device_node(device: Device, *, role: str) -> dict[str, Any]:
    return {
        "id": f"device:{device.id}",
        "entity_id": device.id,
        "node_type": "device",
        "role": role,
        "label": device.name,
        "kind": device.kind,
        "site": device.site,
        "status": device.onboarding_status,
        "observed_at": device.updated_at,
    }


def _endpoint_node(endpoint: Endpoint, *, role: str) -> dict[str, Any]:
    return {
        "id": f"endpoint:{endpoint.id}",
        "entity_id": endpoint.id,
        "node_type": "endpoint",
        "role": role,
        "label": endpoint.hostname or endpoint.mac_address,
        "kind": "endpoint",
        "site": None,
        "status": "observed",
        "observed_at": endpoint.last_seen,
    }


def _knowledge_node(entity: KnowledgeEntity, *, role: str) -> dict[str, Any]:
    return {
        "id": f"knowledge:{entity.id}",
        "entity_id": entity.id,
        "node_type": "knowledge_entity",
        "role": role,
        "label": entity.display_name,
        "kind": entity.entity_type,
        "site": entity.scope_site,
        "status": entity.status or ("active" if entity.active else "inactive"),
        "observed_at": entity.last_seen,
    }


def _external_root(situation: Situation) -> dict[str, Any]:
    return {
        "id": f"external:{situation.primary_entity_type}:{situation.primary_entity_id}",
        "entity_id": situation.primary_entity_id,
        "node_type": "external_entity",
        "role": "root",
        "label": situation.primary_entity_id,
        "kind": situation.primary_entity_type,
        "site": None,
        "status": situation.status,
        "observed_at": situation.last_seen,
    }


def _service_node(
    service: ServiceCatalogEntry,
    *,
    role: str = "impacted_service",
) -> dict[str, Any]:
    return {
        "id": f"service:{service.id}",
        "entity_id": service.id,
        "node_type": "service",
        "role": role,
        "label": service.name,
        "kind": "service",
        "site": None,
        "status": service.status,
        "observed_at": service.updated_at,
        "criticality": service.criticality,
        "business_impact": service.business_impact,
        "slo_target_percent": service.slo_target_percent,
        "owner_team": service.owner_team,
    }


def _shortest_paths(
    root_id: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    visible_ids = {item["id"] for item in nodes}
    edge_by_id = {item["id"]: item for item in edges}
    adjacency: dict[str, list[tuple[str, str]]] = {
        node_id: [] for node_id in visible_ids
    }
    for edge in edges:
        if edge["source"] not in visible_ids or edge["target"] not in visible_ids:
            continue
        adjacency[edge["source"]].append((edge["target"], edge["id"]))
        adjacency[edge["target"]].append((edge["source"], edge["id"]))
    for values in adjacency.values():
        values.sort(key=lambda item: (item[0], item[1]))

    queue: deque[tuple[str, list[str], list[str]]] = deque(
        [(root_id, [root_id], [])]
    )
    visited = {root_id}
    paths: list[dict[str, Any]] = []
    while queue:
        current, node_path, edge_path = queue.popleft()
        if len(edge_path) >= MAX_PATH_HOPS:
            continue
        for neighbor, edge_id in adjacency.get(current, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            next_nodes = [*node_path, neighbor]
            next_edges = [*edge_path, edge_id]
            paths.append(
                {
                    "target_node_id": neighbor,
                    "node_ids": next_nodes,
                    "edge_ids": next_edges,
                    "relationship_types": [
                        edge_by_id[item]["relationship_type"]
                        for item in next_edges
                    ],
                    "hop_count": len(next_edges),
                }
            )
            queue.append((neighbor, next_nodes, next_edges))
    return paths


def situation_impact_graph(
    db: Session,
    situation: Situation,
    principal: PrincipalContext,
) -> dict[str, Any]:
    """Return bounded, scoped context; never claim causal root cause."""

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    nodes_truncated = False
    edges_truncated = False

    def add_node(node: dict[str, Any]) -> bool:
        nonlocal nodes_truncated
        if node["id"] in node_ids:
            return True
        if len(nodes) >= MAX_IMPACT_NODES:
            nodes_truncated = True
            return False
        nodes.append(node)
        node_ids.add(node["id"])
        return True

    def add_edge(edge: dict[str, Any]) -> bool:
        nonlocal edges_truncated
        if edge["id"] in edge_ids:
            return True
        if edge["source"] not in node_ids or edge["target"] not in node_ids:
            return False
        if len(edges) >= MAX_IMPACT_EDGES:
            edges_truncated = True
            return False
        edges.append(edge)
        edge_ids.add(edge["id"])
        return True

    root_device: Device | None = None
    root_endpoint: Endpoint | None = None
    root_knowledge: KnowledgeEntity | None = None
    if situation.primary_entity_type in DEVICE_ENTITY_TYPES:
        root_device = db.scalar(
            select(Device).where(
                Device.id == situation.primary_entity_id,
                device_scope_clause(principal),
            )
        )
    elif situation.primary_entity_type in ENDPOINT_ENTITY_TYPES:
        root_endpoint = db.scalar(
            select(Endpoint).where(
                Endpoint.id == situation.primary_entity_id,
                endpoint_scope_clause(principal),
            )
        )
    elif situation.primary_entity_type == "knowledge_entity":
        root_knowledge = db.scalar(
            select(KnowledgeEntity).where(
                KnowledgeEntity.id == situation.primary_entity_id,
                knowledge_entity_scope_clause(principal),
            )
        )

    if root_device is not None:
        root = _device_node(root_device, role="root")
    elif root_endpoint is not None:
        root = _endpoint_node(root_endpoint, role="root")
    elif root_knowledge is not None:
        root = _knowledge_node(root_knowledge, role="root")
    else:
        root = _external_root(situation)
    add_node(root)

    native_candidates: list[tuple[str, Any]] = []
    if root_device is not None:
        native_candidates.extend(
            ("endpoint_attachment", item)
            for item in db.scalars(
                select(EndpointAttachment)
                .where(
                    EndpointAttachment.collector_device_id == root_device.id,
                    EndpointAttachment.active.is_(True),
                )
                .order_by(EndpointAttachment.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        native_candidates.extend(
            ("wireless_session", item)
            for item in db.scalars(
                select(WirelessClientSession)
                .where(
                    WirelessClientSession.controller_id == root_device.id,
                    WirelessClientSession.active.is_(True),
                )
                .order_by(WirelessClientSession.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        native_candidates.extend(
            ("ip_observation", item)
            for item in db.scalars(
                select(IPAddressObservation)
                .where(
                    IPAddressObservation.collector_device_id == root_device.id,
                    IPAddressObservation.active.is_(True),
                )
                .order_by(IPAddressObservation.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        endpoint_ids = {
            item.endpoint_id for _, item in native_candidates
        }
        endpoints = list(
            db.scalars(
                select(Endpoint)
                .where(
                    Endpoint.id.in_(endpoint_ids),
                    endpoint_scope_clause(principal),
                )
                .order_by(Endpoint.last_seen.desc(), Endpoint.id)
                .limit(MAX_IMPACT_NODES)
            ).all()
        ) if endpoint_ids else []
        for endpoint in endpoints:
            add_node(_endpoint_node(endpoint, role="adjacent"))
        visible_endpoint_ids = {item.id for item in endpoints}
        participating_device_ids = {root_device.id}
    elif root_endpoint is not None:
        native_candidates.extend(
            ("endpoint_attachment", item)
            for item in db.scalars(
                select(EndpointAttachment)
                .where(
                    EndpointAttachment.endpoint_id == root_endpoint.id,
                    EndpointAttachment.active.is_(True),
                )
                .order_by(EndpointAttachment.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        native_candidates.extend(
            ("wireless_session", item)
            for item in db.scalars(
                select(WirelessClientSession)
                .where(
                    WirelessClientSession.endpoint_id == root_endpoint.id,
                    WirelessClientSession.active.is_(True),
                )
                .order_by(WirelessClientSession.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        native_candidates.extend(
            ("ip_observation", item)
            for item in db.scalars(
                select(IPAddressObservation)
                .where(
                    IPAddressObservation.endpoint_id == root_endpoint.id,
                    IPAddressObservation.active.is_(True),
                )
                .order_by(IPAddressObservation.last_seen.desc())
                .limit(MAX_IMPACT_EDGES + 1)
            ).all()
        )
        device_ids = {
            (
                item.controller_id
                if evidence_type == "wireless_session"
                else item.collector_device_id
            )
            for evidence_type, item in native_candidates
        }
        devices = list(
            db.scalars(
                select(Device)
                .where(
                    Device.id.in_(device_ids),
                    device_scope_clause(principal),
                )
                .order_by(Device.name, Device.id)
                .limit(MAX_IMPACT_NODES)
            ).all()
        ) if device_ids else []
        for device in devices:
            add_node(_device_node(device, role="adjacent"))
        participating_device_ids = {item.id for item in devices}
        visible_endpoint_ids = {root_endpoint.id}
    else:
        participating_device_ids = set()
        visible_endpoint_ids = set()

    member_rows = list(
        db.execute(
            select(SituationAlert, Alert)
            .join(Alert, Alert.id == SituationAlert.alert_id)
            .where(SituationAlert.situation_id == situation.id)
            .order_by(SituationAlert.added_at, SituationAlert.id)
            .limit(MAX_IMPACT_NODES + 1)
        ).all()
    )
    nodes_truncated = nodes_truncated or len(member_rows) > MAX_IMPACT_NODES
    member_rows = member_rows[:MAX_IMPACT_NODES]
    member_device_ids = {
        alert.entity_id
        for _membership, alert in member_rows
        if alert.entity_type in DEVICE_ENTITY_TYPES
    }
    member_endpoint_ids = {
        alert.entity_id
        for _membership, alert in member_rows
        if alert.entity_type in ENDPOINT_ENTITY_TYPES
    }
    member_knowledge_ids = {
        alert.entity_id
        for _membership, alert in member_rows
        if alert.entity_type == "knowledge_entity"
    }
    member_devices = {
        item.id: item
        for item in db.scalars(
            select(Device).where(
                Device.id.in_(member_device_ids),
                device_scope_clause(principal),
            )
        ).all()
    } if member_device_ids else {}
    member_endpoints = {
        item.id: item
        for item in db.scalars(
            select(Endpoint).where(
                Endpoint.id.in_(member_endpoint_ids),
                endpoint_scope_clause(principal),
            )
        ).all()
    } if member_endpoint_ids else {}
    member_knowledge = {
        item.id: item
        for item in db.scalars(
            select(KnowledgeEntity).where(
                KnowledgeEntity.id.in_(member_knowledge_ids),
                knowledge_entity_scope_clause(principal),
            )
        ).all()
    } if member_knowledge_ids else {}
    participating_device_ids.update(member_devices)
    visible_endpoint_ids.update(member_endpoints)
    for membership, alert in member_rows:
        target_node_id: str | None = None
        if alert.entity_type in DEVICE_ENTITY_TYPES:
            device = member_devices.get(alert.entity_id)
            if device is not None:
                add_node(_device_node(device, role="correlated_symptom"))
                target_node_id = f"device:{device.id}"
        elif alert.entity_type in ENDPOINT_ENTITY_TYPES:
            endpoint = member_endpoints.get(alert.entity_id)
            if endpoint is not None:
                add_node(_endpoint_node(endpoint, role="correlated_symptom"))
                target_node_id = f"endpoint:{endpoint.id}"
        elif alert.entity_type == "knowledge_entity":
            entity = member_knowledge.get(alert.entity_id)
            if entity is not None:
                add_node(_knowledge_node(entity, role="correlated_symptom"))
                target_node_id = f"knowledge:{entity.id}"
        if (
            membership.correlation_reason != "same_entity"
            and target_node_id is not None
            and target_node_id != root["id"]
        ):
            topology_correlation = (
                membership.correlation_reason == "fresh_topology_adjacency"
            )
            add_edge(
                {
                    "id": f"situation_alert_correlation:{membership.id}",
                    "relationship_type": (
                        "correlated_by_fresh_topology"
                        if topology_correlation
                        else "correlated_by_reviewed_service"
                    ),
                    "source": root["id"],
                    "target": target_node_id,
                    "directed": False,
                    "evidence_type": (
                        "situation_alert_topology_correlation"
                        if topology_correlation
                        else "situation_alert_correlation"
                    ),
                    "evidence_id": membership.id,
                    "observed_at": membership.added_at,
                }
            )

    native_candidates.sort(
        key=lambda item: (_as_utc(item[1].last_seen), item[0], item[1].id),
        reverse=True,
    )
    if len(native_candidates) > MAX_IMPACT_EDGES:
        edges_truncated = True
    for evidence_type, item in native_candidates:
        if evidence_type == "wireless_session":
            device_id = item.controller_id
        else:
            device_id = item.collector_device_id
        if (
            device_id not in participating_device_ids
            or item.endpoint_id not in visible_endpoint_ids
        ):
            continue
        add_edge(
            {
                "id": f"{evidence_type}:{item.id}",
                "relationship_type": evidence_type,
                "source": f"device:{device_id}",
                "target": f"endpoint:{item.endpoint_id}",
                "directed": False,
                "evidence_type": evidence_type,
                "evidence_id": item.id,
                "observed_at": item.last_seen,
            }
        )

    seed_entities: list[KnowledgeEntity] = list(member_knowledge.values())
    if root_knowledge is not None and root_knowledge.id not in member_knowledge:
        seed_entities.append(root_knowledge)
    if participating_device_ids and len(nodes) < MAX_IMPACT_NODES:
        remaining_nodes = MAX_IMPACT_NODES - len(nodes)
        found = list(
            db.scalars(
                select(KnowledgeEntity)
                .where(
                    KnowledgeEntity.scope_device_id.in_(participating_device_ids),
                    KnowledgeEntity.active.is_(True),
                    knowledge_entity_scope_clause(principal),
                )
                .order_by(KnowledgeEntity.last_seen.desc(), KnowledgeEntity.id)
                .limit(remaining_nodes + 1)
            ).all()
        )
        nodes_truncated = nodes_truncated or len(found) > remaining_nodes
        known_seed_ids = {item.id for item in seed_entities}
        seed_entities.extend(
            item for item in found[:remaining_nodes] if item.id not in known_seed_ids
        )
        for entity in seed_entities:
            if not add_node(_knowledge_node(entity, role="scoped_component")):
                continue
            add_edge(
                {
                    "id": f"scope_binding:{entity.id}",
                    "relationship_type": "scope_contains",
                    "source": f"device:{entity.scope_device_id}",
                    "target": f"knowledge:{entity.id}",
                    "directed": True,
                    "evidence_type": "scope_binding",
                    "evidence_id": entity.id,
                    "observed_at": entity.last_seen,
                }
            )

    seed_ids = {item.id for item in seed_entities}
    if seed_ids and len(edges) < MAX_IMPACT_EDGES:
        remaining_edges = MAX_IMPACT_EDGES - len(edges)
        found_relationships = list(
            db.scalars(
                select(KnowledgeRelationship)
                .where(
                    or_(
                        KnowledgeRelationship.source_entity_id.in_(seed_ids),
                        KnowledgeRelationship.target_entity_id.in_(seed_ids),
                    ),
                    KnowledgeRelationship.active.is_(True),
                    knowledge_relationship_scope_clause(principal),
                )
                .order_by(
                    KnowledgeRelationship.last_seen.desc(),
                    KnowledgeRelationship.id,
                )
                .limit(remaining_edges + 1)
            ).all()
        )
        edges_truncated = edges_truncated or len(found_relationships) > remaining_edges
        found_relationships = found_relationships[:remaining_edges]
        neighbor_ids = {
            entity_id
            for relationship in found_relationships
            for entity_id in (
                relationship.source_entity_id,
                relationship.target_entity_id,
            )
            if entity_id not in seed_ids
        }
        remaining_nodes = MAX_IMPACT_NODES - len(nodes)
        neighbors = list(
            db.scalars(
                select(KnowledgeEntity)
                .where(
                    KnowledgeEntity.id.in_(neighbor_ids),
                    KnowledgeEntity.active.is_(True),
                    knowledge_entity_scope_clause(principal),
                )
                .order_by(KnowledgeEntity.last_seen.desc(), KnowledgeEntity.id)
                .limit(remaining_nodes + 1)
            ).all()
        ) if neighbor_ids and remaining_nodes else []
        nodes_truncated = nodes_truncated or len(neighbors) > remaining_nodes
        for entity in neighbors[:remaining_nodes]:
            add_node(_knowledge_node(entity, role="dependency"))
        visible_knowledge_ids = {
            item["entity_id"]
            for item in nodes
            if item["node_type"] == "knowledge_entity"
        }
        for relationship in found_relationships:
            if not {
                relationship.source_entity_id,
                relationship.target_entity_id,
            } <= visible_knowledge_ids:
                continue
            add_edge(
                {
                    "id": f"knowledge_relationship:{relationship.id}",
                    "relationship_type": relationship.relationship_type,
                    "source": f"knowledge:{relationship.source_entity_id}",
                    "target": f"knowledge:{relationship.target_entity_id}",
                    "directed": relationship.directed,
                    "evidence_type": "knowledge_relationship",
                    "evidence_id": relationship.id,
                    "observed_at": relationship.last_seen,
                }
            )

    component_node_ids = set(node_ids)
    seed_service_ids: set[str] = set()
    if component_node_ids and len(edges) < MAX_IMPACT_EDGES:
        remaining_edges = MAX_IMPACT_EDGES - len(edges)
        service_components = list(
            db.scalars(
                select(ServiceCatalogComponent)
                .join(
                    ServiceCatalogEntry,
                    ServiceCatalogEntry.id == ServiceCatalogComponent.service_id,
                )
                .where(
                    ServiceCatalogComponent.node_id.in_(component_node_ids),
                    ServiceCatalogEntry.status == "active",
                )
                .order_by(
                    ServiceCatalogEntry.criticality,
                    ServiceCatalogEntry.name,
                    ServiceCatalogComponent.node_id,
                )
                .limit(remaining_edges + 1)
            ).all()
        )
        edges_truncated = edges_truncated or len(service_components) > remaining_edges
        service_ids = {item.service_id for item in service_components[:remaining_edges]}
        services = {
            item.id: item
            for item in db.scalars(
                select(ServiceCatalogEntry).where(
                    ServiceCatalogEntry.id.in_(service_ids)
                )
            ).all()
        }
        seed_service_ids = set(services)
        for component in service_components[:remaining_edges]:
            service = services.get(component.service_id)
            if service is None or not add_node(_service_node(service)):
                continue
            add_edge(
                {
                    "id": f"service_catalog_component:{component.id}",
                    "relationship_type": component.role,
                    "source": component.node_id,
                    "target": f"service:{service.id}",
                    "directed": True,
                    "evidence_type": "service_catalog_component",
                    "evidence_id": component.id,
                    "observed_at": component.updated_at,
                }
            )

    if seed_service_ids and len(edges) < MAX_IMPACT_EDGES:
        remaining_edges = MAX_IMPACT_EDGES - len(edges)
        dependencies = list(
            db.scalars(
                select(ServiceCatalogDependency)
                .where(
                    or_(
                        ServiceCatalogDependency.source_service_id.in_(
                            seed_service_ids
                        ),
                        ServiceCatalogDependency.target_service_id.in_(
                            seed_service_ids
                        ),
                    )
                )
                .order_by(
                    ServiceCatalogDependency.critical.desc(),
                    ServiceCatalogDependency.dependency_type,
                    ServiceCatalogDependency.id,
                )
                .limit(remaining_edges + 1)
            ).all()
        )
        edges_truncated = edges_truncated or len(dependencies) > remaining_edges
        dependencies = dependencies[:remaining_edges]
        related_service_ids = {
            service_id
            for dependency in dependencies
            for service_id in (
                dependency.source_service_id,
                dependency.target_service_id,
            )
        }
        visible_services = {
            item.id: item
            for item in db.scalars(
                select(ServiceCatalogEntry).where(
                    ServiceCatalogEntry.id.in_(related_service_ids),
                    ServiceCatalogEntry.status == "active",
                    service_scope_clause(principal),
                )
            ).all()
        }
        for dependency in dependencies:
            source = visible_services.get(dependency.source_service_id)
            target = visible_services.get(dependency.target_service_id)
            if source is None or target is None:
                continue
            source_role = (
                "impacted_service"
                if source.id in seed_service_ids
                else "dependent_service"
            )
            target_role = (
                "impacted_service"
                if target.id in seed_service_ids
                else "dependency_service"
            )
            if not add_node(_service_node(source, role=source_role)):
                continue
            if not add_node(_service_node(target, role=target_role)):
                continue
            add_edge(
                {
                    "id": f"service_catalog_dependency:{dependency.id}",
                    "relationship_type": (
                        f"depends_on:{dependency.dependency_type}"
                    ),
                    "source": f"service:{source.id}",
                    "target": f"service:{target.id}",
                    "directed": True,
                    "evidence_type": "service_catalog_dependency",
                    "evidence_id": dependency.id,
                    "observed_at": dependency.updated_at,
                }
            )

    visible_service_ids = {
        str(item["entity_id"])
        for item in nodes
        if item["node_type"] == "service"
    }
    indicator_candidates: list[tuple[Any, Any, Any]] = []
    for definition, observation in latest_indicator_rows(
        db,
        visible_service_ids,
    ):
        if observation is None:
            continue
        evaluated = observation_to_read(definition, observation)
        indicator_candidates.append((definition, observation, evaluated))
    priority = {
        "critical": 0,
        "warning": 1,
        "stale": 2,
        "healthy": 3,
        "informational": 4,
        "unknown": 5,
    }
    indicator_candidates.sort(
        key=lambda item: (
            priority[item[2].effective_status],
            item[0].service_id,
            item[0].indicator_key,
        )
    )
    for definition, observation, evaluated in indicator_candidates:
        if len(nodes) >= MAX_IMPACT_NODES or len(edges) >= MAX_IMPACT_EDGES:
            nodes_truncated = nodes_truncated or len(nodes) >= MAX_IMPACT_NODES
            edges_truncated = edges_truncated or len(edges) >= MAX_IMPACT_EDGES
            break
        node_id = f"service_indicator:{definition.id}"
        if not add_node(
            {
                "id": node_id,
                "entity_id": definition.id,
                "node_type": "service_indicator",
                "role": "service_indicator",
                "label": definition.name,
                "kind": definition.kind,
                "site": None,
                "status": evaluated.effective_status,
                "observed_at": observation.observed_at,
                "service_id": definition.service_id,
                "indicator_key": definition.indicator_key,
                "indicator_revision": definition.revision,
                "value": observation.value,
                "unit": definition.unit,
                "freshness_seconds": definition.freshness_seconds,
                "expires_at": evaluated.expires_at,
                "source_type": definition.source_type,
                "source_ref": definition.source_ref,
                "measurement_quality": observation.measurement_quality,
                "threshold_status": evaluated.threshold_status,
                "freshness_status": evaluated.freshness_status,
                "evidence_ref": observation.evidence_ref,
            }
        ):
            continue
        add_edge(
            {
                "id": f"service_indicator_observation:{observation.id}",
                "relationship_type": "measures_service",
                "source": node_id,
                "target": f"service:{definition.service_id}",
                "directed": True,
                "evidence_type": "service_indicator_observation",
                "evidence_id": observation.id,
                "observed_at": observation.observed_at,
            }
        )

    paths = _shortest_paths(root["id"], nodes, edges)
    return {
        "situation_id": situation.id,
        "root_node_id": root["id"],
        "generated_at": utcnow(),
        "scope_applied": not has_global_scope(principal),
        "hypothesis_boundary": "deterministic_context_not_root_cause",
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "summary": {
            "native_neighbor_count": sum(
                item["role"] == "adjacent" for item in nodes
            ),
            "knowledge_entity_count": sum(
                item["node_type"] == "knowledge_entity" for item in nodes
            ),
            "service_count": sum(
                item["node_type"] == "service" for item in nodes
            ),
            "service_dependency_count": sum(
                item["evidence_type"] == "service_catalog_dependency"
                for item in edges
            ),
            "service_indicator_count": sum(
                item["node_type"] == "service_indicator" for item in nodes
            ),
            "service_indicator_breach_count": sum(
                item["node_type"] == "service_indicator"
                and item.get("freshness_status") == "fresh"
                and item.get("threshold_status") in {"warning", "critical"}
                for item in nodes
            ),
            "stale_service_indicator_count": sum(
                item["node_type"] == "service_indicator"
                and item.get("freshness_status") == "stale"
                for item in nodes
            ),
            "path_count": len(paths),
        },
        "nodes_truncated": nodes_truncated,
        "edges_truncated": edges_truncated,
        "limits": {
            "nodes": MAX_IMPACT_NODES,
            "edges": MAX_IMPACT_EDGES,
            "path_hops": MAX_PATH_HOPS,
        },
    }
