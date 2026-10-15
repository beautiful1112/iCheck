from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .service_indicator_schemas import (
    ServiceIndicatorArtifactBindingCreate,
    ServiceIndicatorArtifactBindingRead,
    ServiceIndicatorArtifactBindingUpdate,
    ServiceIndicatorArtifactPublicationRead,
)
from .services.authorization_scope import (
    request_actor,
    require_service_access,
    require_service_manage_access,
)
from .services.control_plane_auth import PrincipalContext
from .services.indicator_artifacts import (
    binding_to_read,
    create_artifact_indicator_binding,
    get_artifact_indicator_binding,
    list_artifact_indicator_publications,
    update_artifact_indicator_binding,
)
from .services.service_indicators import get_indicator


router = APIRouter(prefix="/api/v1/services", tags=["service-indicator-artifacts"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/{service_id}/indicators/{indicator_id}/artifact-binding",
    response_model=ServiceIndicatorArtifactBindingRead,
)
def get_indicator_artifact_binding_route(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> ServiceIndicatorArtifactBindingRead:
    service = require_service_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        return binding_to_read(
            get_artifact_indicator_binding(db, definition.id)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{service_id}/indicators/{indicator_id}/artifact-binding",
    response_model=ServiceIndicatorArtifactBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def add_indicator_artifact_binding_route(
    service_id: str,
    indicator_id: str,
    payload: ServiceIndicatorArtifactBindingCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("services.manage", "capabilities.read")
    ),
) -> ServiceIndicatorArtifactBindingRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = create_artifact_indicator_binding(
            db,
            definition,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return binding_to_read(binding)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.patch(
    "/{service_id}/indicators/{indicator_id}/artifact-binding",
    response_model=ServiceIndicatorArtifactBindingRead,
)
def edit_indicator_artifact_binding_route(
    service_id: str,
    indicator_id: str,
    payload: ServiceIndicatorArtifactBindingUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("services.manage", "capabilities.read")
    ),
) -> ServiceIndicatorArtifactBindingRead:
    service = require_service_manage_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = get_artifact_indicator_binding(db, definition.id)
        binding = update_artifact_indicator_binding(
            db,
            binding,
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return binding_to_read(binding)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/{service_id}/indicators/{indicator_id}/artifact-binding/publications",
    response_model=list[ServiceIndicatorArtifactPublicationRead],
)
def list_indicator_artifact_publications_route(
    service_id: str,
    indicator_id: str,
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[ServiceIndicatorArtifactPublicationRead]:
    service = require_service_access(db, principal, service_id)
    try:
        definition = get_indicator(db, service.id, indicator_id)
        binding = get_artifact_indicator_binding(db, definition.id)
        return [
            ServiceIndicatorArtifactPublicationRead.model_validate(item)
            for item in list_artifact_indicator_publications(
                db, binding, limit=limit
            )
        ]
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
