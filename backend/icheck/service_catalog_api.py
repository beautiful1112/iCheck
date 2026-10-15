from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .models import ServiceCatalogEntry
from .models import ServiceCatalogDependency
from .service_catalog_schemas import (
    ServiceComponentAction,
    ServiceComponentCreate,
    ServiceCreate,
    ServiceDependencyAction,
    ServiceDependencyCreate,
    ServiceDependencyRead,
    ServiceRead,
    ServiceUpdate,
)
from .service_indicator_schemas import (
    ServiceIndicatorCreate,
    ServiceIndicatorObservationCreate,
    ServiceIndicatorObservationRead,
    ServiceIndicatorRead,
    ServiceIndicatorUpdate,
)
from .services.authorization_scope import (
    request_actor,
    require_service_access,
    require_service_manage_access,
    service_scope_clause,
)
from .services.control_plane_auth import PrincipalContext
from .services.service_catalog import (
    add_service_component,
    create_service_dependency,
    create_service,
    list_service_dependencies,
    remove_service_component,
    remove_service_dependency,
    service_dependency_to_read,
    service_query,
    service_to_read,
    update_service,
)
from .services.service_indicators import (
    create_indicator,
    definition_to_read,
    get_indicator,
    ingest_observation,
    latest_indicator_rows,
    list_indicators,
    list_observations,
    observation_to_read,
    update_indicator,
)


router = APIRouter(prefix="/api/v1/services", tags=["service-catalog"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[ServiceRead])
def list_services(
    db: DBSession,
    service_status: Literal["active", "retired"] | None = Query(
        default=None, alias="status"
    ),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceRead]:
    query = service_query().where(service_scope_clause(principal))
    if service_status is not None:
        query = query.where(ServiceCatalogEntry.status == service_status)
    services = list(
        db.scalars(
            query.order_by(
                ServiceCatalogEntry.criticality,
                ServiceCatalogEntry.name,
            ).limit(limit)
        ).all()
    )
    return [service_to_read(db, item, principal) for item in services]


@router.post("", response_model=ServiceRead, status_code=status.HTTP_201_CREATED)
def create_service_route(
    payload: ServiceCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceRead:
    try:
        service = create_service(
            db,
            payload,
            principal,
            actor=request_actor(principal, payload.created_by),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    service = db.scalar(service_query().where(ServiceCatalogEntry.id == service.id))
    if service is None:
        raise RuntimeError("Created service disappeared")
    return service_to_read(db, service, principal)


@router.get("/{service_id}", response_model=ServiceRead)
def get_service(
    service_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> ServiceRead:
    require_service_access(db, principal, service_id)
    service = db.scalar(service_query().where(ServiceCatalogEntry.id == service_id))
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return service_to_read(db, service, principal)


@router.patch("/{service_id}", response_model=ServiceRead)
def update_service_route(
    service_id: str,
    payload: ServiceUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        update_service(
            db,
            service,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    service = db.scalar(service_query().where(ServiceCatalogEntry.id == service_id))
    if service is None:
        raise RuntimeError("Updated service disappeared")
    return service_to_read(db, service, principal)


@router.post(
    "/{service_id}/components",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_service_component_route(
    service_id: str,
    payload: ServiceComponentCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        add_service_component(
            db,
            service,
            payload,
            principal,
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    service = db.scalar(service_query().where(ServiceCatalogEntry.id == service_id))
    if service is None:
        raise RuntimeError("Updated service disappeared")
    return service_to_read(db, service, principal)


@router.delete(
    "/{service_id}/components/{component_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_service_component_route(
    service_id: str,
    component_id: str,
    payload: ServiceComponentAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> Response:
    service = require_service_manage_access(db, principal, service_id)
    try:
        remove_service_component(
            db,
            service,
            component_id,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{service_id}/dependencies",
    response_model=list[ServiceDependencyRead],
)
def get_service_dependencies(
    service_id: str,
    db: DBSession,
    direction: Literal["outgoing", "incoming", "both"] = "both",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceDependencyRead]:
    service = require_service_access(db, principal, service_id)
    return list_service_dependencies(
        db,
        service,
        principal,
        direction=direction,
        limit=limit,
    )


@router.post(
    "/{service_id}/dependencies",
    response_model=ServiceDependencyRead,
    status_code=status.HTTP_201_CREATED,
)
def add_service_dependency_route(
    service_id: str,
    payload: ServiceDependencyCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceDependencyRead:
    source = require_service_manage_access(db, principal, service_id)
    target = require_service_manage_access(
        db,
        principal,
        payload.target_service_id,
    )
    try:
        dependency = create_service_dependency(
            db,
            source,
            target,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return service_dependency_to_read(
        dependency,
        {source.id: source, target.id: target},
    )


@router.delete(
    "/{service_id}/dependencies/{dependency_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_service_dependency_route(
    service_id: str,
    dependency_id: str,
    payload: ServiceDependencyAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> Response:
    source = require_service_manage_access(db, principal, service_id)
    dependency = db.scalar(
        select(ServiceCatalogDependency).where(
            ServiceCatalogDependency.id == dependency_id,
            ServiceCatalogDependency.source_service_id == source.id,
        )
    )
    if dependency is None:
        raise HTTPException(status_code=404, detail="Service dependency not found")
    require_service_manage_access(db, principal, dependency.target_service_id)
    try:
        remove_service_dependency(
            db,
            source,
            dependency,
            expected_revision=payload.expected_revision,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{service_id}/indicators",
    response_model=list[ServiceIndicatorRead],
)
def get_service_indicators(
    service_id: str,
    db: DBSession,
    include_disabled: bool = False,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceIndicatorRead]:
    service = require_service_access(db, principal, service_id)
    return list_indicators(
        db,
        service,
        include_disabled=include_disabled,
    )


@router.post(
    "/{service_id}/indicators",
    response_model=ServiceIndicatorRead,
    status_code=status.HTTP_201_CREATED,
)
def add_service_indicator(
    service_id: str,
    payload: ServiceIndicatorCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceIndicatorRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = create_indicator(
            db,
            service,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return definition_to_read(definition, None)


@router.patch(
    "/{service_id}/indicators/{indicator_id}",
    response_model=ServiceIndicatorRead,
)
def edit_service_indicator(
    service_id: str,
    indicator_id: str,
    payload: ServiceIndicatorUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceIndicatorRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        definition = update_indicator(
            db,
            service,
            definition,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    rows = latest_indicator_rows(db, [service.id], enabled_only=False)
    observation = next(
        (item for item_definition, item in rows if item_definition.id == definition.id),
        None,
    )
    return definition_to_read(definition, observation)


@router.get(
    "/{service_id}/indicators/{indicator_id}/observations",
    response_model=list[ServiceIndicatorObservationRead],
)
def get_service_indicator_observations(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceIndicatorObservationRead]:
    service = require_service_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return list_observations(db, definition, limit=limit)


@router.post(
    "/{service_id}/indicators/{indicator_id}/observations",
    response_model=ServiceIndicatorObservationRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_service_indicator_observation(
    service_id: str,
    indicator_id: str,
    payload: ServiceIndicatorObservationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.manage")),
) -> ServiceIndicatorObservationRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        observation = ingest_observation(
            db,
            definition,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return observation_to_read(definition, observation)
