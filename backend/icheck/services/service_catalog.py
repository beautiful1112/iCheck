from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..models import (
    Device,
    Endpoint,
    KnowledgeEntity,
    ServiceCatalogComponent,
    ServiceCatalogDependency,
    ServiceCatalogEntry,
    utcnow,
)
from ..service_catalog_schemas import (
    ServiceComponentCreate,
    ServiceComponentRead,
    ServiceCreate,
    ServiceDependencyCreate,
    ServiceDependencyRead,
    ServiceRead,
    ServiceUpdate,
)
from .audit import record_audit_event
from .authorization_scope import (
    device_scope_clause,
    endpoint_scope_clause,
    has_global_scope,
    knowledge_entity_scope_clause,
    service_component_scope_clause,
    service_scope_clause,
)
from .control_plane_auth import PrincipalContext


def canonical_service_node_id(node_type: str, entity_id: str) -> str:
    prefix = "knowledge" if node_type == "knowledge_entity" else node_type
    return f"{prefix}:{entity_id}"


def _resolve_component_entity(
    db: Session,
    principal: PrincipalContext,
    node_type: str,
    entity_id: str,
) -> tuple[str, str | None]:
    if node_type == "device":
        entity = db.scalar(
            select(Device).where(
                Device.id == entity_id,
                device_scope_clause(principal),
            )
        )
        if entity is not None:
            return entity.name, entity.site
    elif node_type == "endpoint":
        entity = db.scalar(
            select(Endpoint).where(
                Endpoint.id == entity_id,
                endpoint_scope_clause(principal),
            )
        )
        if entity is not None:
            return entity.hostname or entity.mac_address, None
    elif node_type == "knowledge_entity":
        entity = db.scalar(
            select(KnowledgeEntity).where(
                KnowledgeEntity.id == entity_id,
                knowledge_entity_scope_clause(principal),
            )
        )
        if entity is not None:
            return entity.display_name, entity.scope_site
    raise LookupError("Service component entity not found")


def _new_component(
    db: Session,
    principal: PrincipalContext,
    service: ServiceCatalogEntry,
    payload: ServiceComponentCreate,
    *,
    actor: str,
) -> ServiceCatalogComponent:
    _resolve_component_entity(
        db,
        principal,
        payload.node_type,
        payload.entity_id,
    )
    component = ServiceCatalogComponent(
        service_id=service.id,
        node_id=canonical_service_node_id(payload.node_type, payload.entity_id),
        node_type=payload.node_type,
        entity_id=payload.entity_id,
        role=payload.role,
        required=payload.required,
        evidence_note=payload.evidence_note,
        created_by=actor,
    )
    db.add(component)
    return component


def create_service(
    db: Session,
    payload: ServiceCreate,
    principal: PrincipalContext,
    *,
    actor: str,
) -> ServiceCatalogEntry:
    service = ServiceCatalogEntry(
        **payload.model_dump(exclude={"components", "created_by"}),
        status="active",
        revision=1,
        created_by=actor,
        updated_by=actor,
    )
    db.add(service)
    try:
        db.flush()
        for component in payload.components:
            _new_component(db, principal, service, component, actor=actor)
        db.flush()
        record_audit_event(
            db,
            event_type="service_catalog.created",
            actor_type="user",
            actor_id=actor,
            entity_type="service_catalog_entry",
            entity_id=service.id,
            details={
                "service_key": service.service_key,
                "criticality": service.criticality,
                "business_impact": service.business_impact,
                "component_count": len(payload.components),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Service key or component binding already exists") from exc
    db.refresh(service)
    return service


def update_service(
    db: Session,
    service: ServiceCatalogEntry,
    payload: ServiceUpdate,
    *,
    actor: str,
) -> ServiceCatalogEntry:
    locked = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service.id)
        .with_for_update()
    )
    if locked is None:
        raise LookupError("Service not found")
    if locked.revision != payload.expected_revision:
        raise ValueError("Service revision conflict; reload before updating")
    changed: list[str] = []
    values = payload.model_dump(
        exclude={"expected_revision", "actor"},
        exclude_unset=True,
    )
    for key, value in values.items():
        if getattr(locked, key) != value:
            setattr(locked, key, value)
            changed.append(key)
    if not changed:
        return locked
    locked.revision += 1
    locked.updated_by = actor
    locked.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="service_catalog.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="service_catalog_entry",
        entity_id=locked.id,
        details={"revision": locked.revision, "changed_fields": sorted(changed)},
    )
    db.commit()
    db.refresh(locked)
    return locked


def add_service_component(
    db: Session,
    service: ServiceCatalogEntry,
    payload: ServiceComponentCreate,
    principal: PrincipalContext,
    *,
    actor: str,
) -> ServiceCatalogEntry:
    component = _new_component(db, principal, service, payload, actor=actor)
    service.revision += 1
    service.updated_by = actor
    service.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="service_catalog.component_added",
            actor_type="user",
            actor_id=actor,
            entity_type="service_catalog_entry",
            entity_id=service.id,
            details={
                "component_id": component.id,
                "node_id": component.node_id,
                "revision": service.revision,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Service component binding already exists") from exc
    db.refresh(service)
    return service


def remove_service_component(
    db: Session,
    service: ServiceCatalogEntry,
    component_id: str,
    *,
    actor: str,
) -> ServiceCatalogEntry:
    components = list(
        db.scalars(
            select(ServiceCatalogComponent).where(
                ServiceCatalogComponent.service_id == service.id
            )
        ).all()
    )
    component = next((item for item in components if item.id == component_id), None)
    if component is None:
        raise LookupError("Service component not found")
    if len(components) == 1:
        raise ValueError("A service must retain at least one component")
    node_id = component.node_id
    db.delete(component)
    service.revision += 1
    service.updated_by = actor
    service.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="service_catalog.component_removed",
        actor_type="user",
        actor_id=actor,
        entity_type="service_catalog_entry",
        entity_id=service.id,
        details={
            "component_id": component_id,
            "node_id": node_id,
            "revision": service.revision,
        },
    )
    db.commit()
    db.refresh(service)
    return service


def _locked_service_revision(
    db: Session,
    service_id: str,
    expected_revision: int,
) -> ServiceCatalogEntry:
    service = db.scalar(
        select(ServiceCatalogEntry)
        .where(ServiceCatalogEntry.id == service_id)
        .with_for_update()
    )
    if service is None:
        raise LookupError("Service not found")
    if service.revision != expected_revision:
        raise ValueError("Service revision conflict; reload before updating")
    return service


def service_dependency_to_read(
    dependency: ServiceCatalogDependency,
    services: dict[str, ServiceCatalogEntry],
) -> ServiceDependencyRead:
    source = services[dependency.source_service_id]
    target = services[dependency.target_service_id]
    return ServiceDependencyRead(
        id=dependency.id,
        source_service_id=source.id,
        source_service_key=source.service_key,
        source_service_name=source.name,
        target_service_id=target.id,
        target_service_key=target.service_key,
        target_service_name=target.name,
        dependency_type=dependency.dependency_type,
        critical=dependency.critical,
        evidence_note=dependency.evidence_note,
        created_by=dependency.created_by,
        created_at=dependency.created_at,
        updated_at=dependency.updated_at,
    )


def list_service_dependencies(
    db: Session,
    service: ServiceCatalogEntry,
    principal: PrincipalContext,
    *,
    direction: str,
    limit: int,
) -> list[ServiceDependencyRead]:
    if direction == "outgoing":
        predicate = ServiceCatalogDependency.source_service_id == service.id
    elif direction == "incoming":
        predicate = ServiceCatalogDependency.target_service_id == service.id
    else:
        predicate = or_(
            ServiceCatalogDependency.source_service_id == service.id,
            ServiceCatalogDependency.target_service_id == service.id,
        )
    dependencies = list(
        db.scalars(
            select(ServiceCatalogDependency)
            .where(predicate)
            .order_by(
                ServiceCatalogDependency.critical.desc(),
                ServiceCatalogDependency.dependency_type,
                ServiceCatalogDependency.id,
            )
            .limit(limit)
        ).all()
    )
    service_ids = {
        item_id
        for item in dependencies
        for item_id in (item.source_service_id, item.target_service_id)
    }
    services = {
        item.id: item
        for item in db.scalars(
            select(ServiceCatalogEntry).where(
                ServiceCatalogEntry.id.in_(service_ids),
                service_scope_clause(principal),
            )
        ).all()
    } if service_ids else {}
    return [
        service_dependency_to_read(item, services)
        for item in dependencies
        if item.source_service_id in services and item.target_service_id in services
    ]


def create_service_dependency(
    db: Session,
    source: ServiceCatalogEntry,
    target: ServiceCatalogEntry,
    payload: ServiceDependencyCreate,
    *,
    actor: str,
) -> ServiceCatalogDependency:
    if source.id == target.id:
        raise ValueError("A service cannot depend on itself")
    if source.status != "active" or target.status != "active":
        raise ValueError("Dependencies can only connect active services")
    source = _locked_service_revision(
        db,
        source.id,
        payload.expected_revision,
    )
    dependency = ServiceCatalogDependency(
        source_service_id=source.id,
        target_service_id=target.id,
        dependency_type=payload.dependency_type,
        critical=payload.critical,
        evidence_note=payload.evidence_note,
        created_by=actor,
    )
    db.add(dependency)
    source.revision += 1
    source.updated_by = actor
    source.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="service_catalog.dependency_added",
            actor_type="user",
            actor_id=actor,
            entity_type="service_catalog_dependency",
            entity_id=dependency.id,
            details={
                "source_service_id": source.id,
                "target_service_id": target.id,
                "dependency_type": dependency.dependency_type,
                "critical": dependency.critical,
                "source_revision": source.revision,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Service dependency already exists") from exc
    db.refresh(dependency)
    return dependency


def remove_service_dependency(
    db: Session,
    source: ServiceCatalogEntry,
    dependency: ServiceCatalogDependency,
    *,
    expected_revision: int,
    actor: str,
) -> None:
    if dependency.source_service_id != source.id:
        raise LookupError("Service dependency not found")
    source = _locked_service_revision(db, source.id, expected_revision)
    details = {
        "source_service_id": source.id,
        "target_service_id": dependency.target_service_id,
        "dependency_type": dependency.dependency_type,
        "critical": dependency.critical,
        "source_revision": source.revision + 1,
    }
    db.delete(dependency)
    source.revision += 1
    source.updated_by = actor
    source.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="service_catalog.dependency_removed",
        actor_type="user",
        actor_id=actor,
        entity_type="service_catalog_dependency",
        entity_id=dependency.id,
        details=details,
    )
    db.commit()


def service_query():
    return select(ServiceCatalogEntry).options(
        selectinload(ServiceCatalogEntry.components)
    )


def _visible_components(
    db: Session,
    service: ServiceCatalogEntry,
    principal: PrincipalContext,
) -> list[ServiceCatalogComponent]:
    if has_global_scope(principal):
        return list(service.components)
    return list(
        db.scalars(
            select(ServiceCatalogComponent).where(
                ServiceCatalogComponent.service_id == service.id,
                service_component_scope_clause(principal),
            )
        ).all()
    )


def service_to_read(
    db: Session,
    service: ServiceCatalogEntry,
    principal: PrincipalContext,
) -> ServiceRead:
    components: list[ServiceComponentRead] = []
    for component in _visible_components(db, service, principal):
        try:
            display_name, site = _resolve_component_entity(
                db,
                principal,
                component.node_type,
                component.entity_id,
            )
            available = True
        except LookupError:
            display_name, site, available = component.node_id, None, False
        components.append(
            ServiceComponentRead(
                id=component.id,
                node_id=component.node_id,
                node_type=component.node_type,
                entity_id=component.entity_id,
                display_name=display_name,
                site=site,
                available=available,
                role=component.role,
                required=component.required,
                evidence_note=component.evidence_note,
                created_by=component.created_by,
                created_at=component.created_at,
                updated_at=component.updated_at,
            )
        )
    document: dict[str, Any] = {
        column: getattr(service, column)
        for column in (
            "id",
            "service_key",
            "name",
            "description",
            "owner_team",
            "owner_contact",
            "criticality",
            "business_impact",
            "business_impact_summary",
            "slo_target_percent",
            "recovery_time_objective_minutes",
            "recovery_point_objective_minutes",
            "status",
            "tags",
            "revision",
            "created_by",
            "updated_by",
            "created_at",
            "updated_at",
        )
    }
    return ServiceRead(**document, components=components)
