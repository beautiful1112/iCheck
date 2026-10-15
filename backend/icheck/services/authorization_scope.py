from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import Select, and_, exists, false, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from ..models import (
    Alert,
    CollectorDeployment,
    CollectorWorker,
    Device,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    KnowledgeEntity,
    KnowledgeRelationship,
    ServiceCatalogComponent,
    ServiceCatalogEntry,
    Situation,
    SituationAlert,
    WirelessClientSession,
)
from .control_plane_auth import PrincipalContext


def has_global_scope(principal: PrincipalContext) -> bool:
    return principal.authorization_scope.get("all") is True


def namespace_clause(
    model: Any,
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    return and_(
        model.tenant_id == principal.tenant_id,
        model.region_id == principal.region_id,
    )


def authorized_device_ids_query(
    principal: PrincipalContext,
) -> Select[tuple[str]]:
    query = select(Device.id).where(namespace_clause(Device, principal))
    if has_global_scope(principal):
        return query

    scope = principal.authorization_scope
    clauses: list[ColumnElement[bool]] = []
    device_ids = [
        str(value) for value in scope.get("device_ids", []) if value
    ]
    sites = [str(value) for value in scope.get("sites", []) if value]
    if device_ids:
        clauses.append(Device.id.in_(device_ids))
    if sites:
        clauses.append(Device.site.in_(sites))
    return query.where(or_(*clauses) if clauses else false())


def authorized_device_ids(
    db: Session,
    principal: PrincipalContext,
) -> set[str] | None:
    if has_global_scope(principal):
        return None
    return set(db.scalars(authorized_device_ids_query(principal)).all())


def device_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(Device, principal)
    return and_(
        namespace_clause(Device, principal),
        Device.id.in_(authorized_device_ids_query(principal)),
    )


def endpoint_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(Endpoint, principal)
    device_ids = authorized_device_ids_query(principal)
    return and_(
        namespace_clause(Endpoint, principal),
        or_(
            exists(
            select(IPAddressObservation.id).where(
                IPAddressObservation.endpoint_id == Endpoint.id,
                namespace_clause(IPAddressObservation, principal),
                IPAddressObservation.collector_device_id.in_(device_ids),
            )
            ),
            exists(
            select(EndpointAttachment.id).where(
                EndpointAttachment.endpoint_id == Endpoint.id,
                namespace_clause(EndpointAttachment, principal),
                EndpointAttachment.collector_device_id.in_(device_ids),
            )
            ),
            exists(
            select(WirelessClientSession.id).where(
                WirelessClientSession.endpoint_id == Endpoint.id,
                namespace_clause(WirelessClientSession, principal),
                WirelessClientSession.controller_id.in_(device_ids),
            )
            ),
        ),
    )


def collector_deployment_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(CollectorDeployment, principal)
    sites = [
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    ]
    clauses: list[ColumnElement[bool]] = [
        CollectorDeployment.scope_device_id.in_(
            authorized_device_ids_query(principal)
        )
    ]
    if sites:
        clauses.append(CollectorDeployment.scope_site.in_(sites))
    return and_(
        namespace_clause(CollectorDeployment, principal),
        or_(*clauses),
    )


def collector_worker_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(CollectorWorker, principal)
    sites = [
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    ]
    return and_(
        namespace_clause(CollectorWorker, principal),
        CollectorWorker.site.in_(sites) if sites else false(),
    )


def knowledge_entity_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(KnowledgeEntity, principal)
    sites = [
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    ]
    clauses: list[ColumnElement[bool]] = [
        KnowledgeEntity.scope_device_id.in_(
            authorized_device_ids_query(principal)
        )
    ]
    if sites:
        clauses.append(KnowledgeEntity.scope_site.in_(sites))
    return and_(namespace_clause(KnowledgeEntity, principal), or_(*clauses))


def knowledge_relationship_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(KnowledgeRelationship, principal)
    sites = [
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    ]
    clauses: list[ColumnElement[bool]] = [
        KnowledgeRelationship.scope_device_id.in_(
            authorized_device_ids_query(principal)
        )
    ]
    if sites:
        clauses.append(KnowledgeRelationship.scope_site.in_(sites))
    return and_(
        namespace_clause(KnowledgeRelationship, principal),
        or_(*clauses),
    )


def alert_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(Alert, principal)
    device_ids = authorized_device_ids_query(principal)
    endpoint_ids = select(Endpoint.id).where(endpoint_scope_clause(principal))
    return and_(
        namespace_clause(Alert, principal),
        or_(
        and_(
            Alert.entity_type.in_(("device", "collector_device")),
            Alert.entity_id.in_(device_ids),
        ),
        and_(
            Alert.entity_type.in_(("endpoint", "terminal")),
            Alert.entity_id.in_(endpoint_ids),
        ),
        ),
    )


def situation_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(Situation, principal)
    device_ids = authorized_device_ids_query(principal)
    endpoint_ids = select(Endpoint.id).where(endpoint_scope_clause(principal))
    primary_visible = or_(
        and_(
            Situation.primary_entity_type.in_(("device", "collector_device")),
            Situation.primary_entity_id.in_(device_ids),
        ),
        and_(
            Situation.primary_entity_type.in_(("endpoint", "terminal")),
            Situation.primary_entity_id.in_(endpoint_ids),
        ),
    )
    hidden_member = exists(
        select(SituationAlert.id)
        .join(Alert, Alert.id == SituationAlert.alert_id)
        .where(
            SituationAlert.situation_id == Situation.id,
            ~alert_scope_clause(principal),
        )
    )
    # A cross-entity Situation is visible only when every source Alert is in
    # scope. Partial rendering would leak evidence through the visible root.
    return and_(
        namespace_clause(Situation, principal),
        primary_visible,
        ~hidden_member,
    )


def service_component_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(ServiceCatalogComponent, principal)
    visible_endpoint_ids = select(Endpoint.id).where(
        endpoint_scope_clause(principal)
    )
    visible_knowledge_ids = select(KnowledgeEntity.id).where(
        knowledge_entity_scope_clause(principal)
    )
    return and_(
        namespace_clause(ServiceCatalogComponent, principal),
        or_(
        and_(
            ServiceCatalogComponent.node_type == "device",
            ServiceCatalogComponent.entity_id.in_(
                authorized_device_ids_query(principal)
            ),
        ),
        and_(
            ServiceCatalogComponent.node_type == "endpoint",
            ServiceCatalogComponent.entity_id.in_(visible_endpoint_ids),
        ),
        and_(
            ServiceCatalogComponent.node_type == "knowledge_entity",
            ServiceCatalogComponent.entity_id.in_(visible_knowledge_ids),
        ),
        ),
    )


def service_scope_clause(
    principal: PrincipalContext,
) -> ColumnElement[bool]:
    if has_global_scope(principal):
        return namespace_clause(ServiceCatalogEntry, principal)
    return and_(
        namespace_clause(ServiceCatalogEntry, principal),
        exists(
            select(ServiceCatalogComponent.id).where(
                ServiceCatalogComponent.service_id == ServiceCatalogEntry.id,
                service_component_scope_clause(principal),
            )
        )
    )


def require_service_access(
    db: Session,
    principal: PrincipalContext,
    service_id: str,
) -> ServiceCatalogEntry:
    service = db.scalar(
        select(ServiceCatalogEntry).where(
            ServiceCatalogEntry.id == service_id,
            service_scope_clause(principal),
        )
    )
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return service


def require_service_manage_access(
    db: Session,
    principal: PrincipalContext,
    service_id: str,
) -> ServiceCatalogEntry:
    service = require_service_access(db, principal, service_id)
    if has_global_scope(principal):
        return service
    total = db.scalar(
        select(func.count(ServiceCatalogComponent.id)).where(
            ServiceCatalogComponent.service_id == service.id
        )
    ) or 0
    visible = db.scalar(
        select(func.count(ServiceCatalogComponent.id)).where(
            ServiceCatalogComponent.service_id == service.id,
            service_component_scope_clause(principal),
        )
    ) or 0
    if total == 0 or visible != total:
        raise HTTPException(status_code=404, detail="Service not found")
    return service


def require_situation_access(
    db: Session,
    principal: PrincipalContext,
    situation_id: str,
) -> Situation:
    situation = db.scalar(
        select(Situation).where(
            Situation.id == situation_id,
            situation_scope_clause(principal),
        )
    )
    if situation is None:
        raise HTTPException(status_code=404, detail="Situation not found")
    return situation


def require_device_access(
    db: Session,
    principal: PrincipalContext,
    device_id: str,
) -> Device:
    device = db.scalar(
        select(Device).where(
            Device.id == device_id,
            device_scope_clause(principal),
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


def require_endpoint_access(
    db: Session,
    principal: PrincipalContext,
    endpoint_id: str,
) -> Endpoint:
    endpoint = db.scalar(
        select(Endpoint).where(
            Endpoint.id == endpoint_id,
            endpoint_scope_clause(principal),
        )
    )
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint


def require_alert_access(
    db: Session,
    principal: PrincipalContext,
    alert_id: str,
) -> Alert:
    alert = db.scalar(
        select(Alert).where(
            Alert.id == alert_id,
            alert_scope_clause(principal),
        )
    )
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def require_site_access(
    principal: PrincipalContext,
    site: str | None,
) -> None:
    if has_global_scope(principal):
        return
    sites = {
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    }
    if site is None or site not in sites:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization scope does not permit this site",
        )


def require_global_scope(principal: PrincipalContext) -> None:
    if not has_global_scope(principal):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This operation requires global authorization scope",
        )


def permits_resource_scope(
    db: Session,
    principal: PrincipalContext,
    *,
    device_id: str | None = None,
    site: str | None = None,
) -> bool:
    if has_global_scope(principal):
        return True
    if device_id:
        return (
            db.scalar(
                authorized_device_ids_query(principal).where(
                    Device.id == device_id
                )
            )
            is not None
        )
    if site:
        return site in {
            str(value)
            for value in principal.authorization_scope.get("sites", [])
            if value
        }
    return False


def permits_mapping_scope(
    db: Session,
    principal: PrincipalContext,
    *documents: dict[str, Any] | None,
) -> bool:
    if has_global_scope(principal):
        return True
    for document in documents:
        if not document:
            continue
        device_id = document.get("device_id")
        site = document.get("site")
        if device_id and permits_resource_scope(
            db, principal, device_id=str(device_id)
        ):
            return True
        if site and permits_resource_scope(db, principal, site=str(site)):
            return True
    return False


def require_mapping_scope(
    db: Session,
    principal: PrincipalContext,
    *documents: dict[str, Any] | None,
) -> None:
    if not permits_mapping_scope(db, principal, *documents):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization scope does not permit this resource",
        )


def scope_contains(
    db: Session,
    principal: PrincipalContext,
    resource_scope: dict[str, Any] | None,
) -> bool:
    return scope_contains_with_devices(
        principal,
        resource_scope,
        authorized_device_ids(db, principal),
    )


def scope_contains_with_devices(
    principal: PrincipalContext,
    resource_scope: dict[str, Any] | None,
    allowed_device_ids: set[str] | None,
) -> bool:
    """Check several resources against one request's authorized Device snapshot."""
    if has_global_scope(principal):
        return True
    resource_scope = resource_scope or {}
    if resource_scope.get("all") is True:
        return False

    resource_ids = {
        str(value) for value in resource_scope.get("device_ids", []) if value
    }
    if not resource_ids.issubset(allowed_device_ids or set()):
        return False

    allowed_sites = {
        str(value)
        for value in principal.authorization_scope.get("sites", [])
        if value
    }
    resource_sites = {
        str(value) for value in resource_scope.get("sites", []) if value
    }
    return resource_sites.issubset(allowed_sites)


def require_requested_investigation_scope(
    db: Session,
    principal: PrincipalContext,
    requested_scope: dict[str, Any],
) -> None:
    sites = [
        str(value)
        for value in requested_scope.get("sites", [])
        if value
    ]
    if requested_scope.get("site"):
        sites.append(str(requested_scope["site"]))
    normalized = {
        "device_ids": [
            str(value)
            for value in requested_scope.get("device_ids", [])
            if value
        ],
        "sites": sorted(set(sites)),
    }
    if not scope_contains(db, principal, normalized):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Investigation scope exceeds the authenticated scope",
        )


def request_actor(
    principal: PrincipalContext,
    claimed_actor: str | None = None,
) -> str:
    if principal.auth_method == "disabled" and claimed_actor:
        return claimed_actor
    return principal.subject
