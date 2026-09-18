from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .ai_schemas import (
    AIModelCreate,
    AIModelRead,
    AIModelRouteCreate,
    AIModelRouteRead,
    AIProviderCreate,
    AIProviderHealth,
    AIProviderRead,
    AIProviderUpdate,
)
from .config import get_settings
from .database import get_db
from .models import AIModelConfig, AIModelRoute, AIProviderConfig
from .services.ai_settings import (
    check_ai_provider,
    create_ai_model,
    create_ai_model_route as create_ai_model_route_service,
    create_ai_provider,
    get_ai_provider,
    update_ai_provider,
)


router = APIRouter(prefix="/api/v1/ai", tags=["ai-settings"])
settings = get_settings()


def db_session():
    yield from get_db()


@router.post(
    "/providers",
    response_model=AIProviderRead,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_provider_route(
    payload: AIProviderCreate,
    db: Session = Depends(db_session),
) -> AIProviderConfig:
    try:
        return create_ai_provider(
            db,
            payload,
            allowed_hosts=settings.ai_allowed_host_list,
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/providers", response_model=list[AIProviderRead])
def list_ai_providers(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[AIProviderConfig]:
    query = select(AIProviderConfig)
    if enabled is not None:
        query = query.where(AIProviderConfig.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIProviderConfig.name).limit(limit)).all()
    )


@router.put("/providers/{provider_id}", response_model=AIProviderRead)
def update_ai_provider_route(
    provider_id: str,
    payload: AIProviderUpdate,
    db: Session = Depends(db_session),
) -> AIProviderConfig:
    try:
        return update_ai_provider(
            db,
            get_ai_provider(db, provider_id),
            payload,
            allowed_hosts=settings.ai_allowed_host_list,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post(
    "/providers/{provider_id}/health",
    response_model=AIProviderHealth,
)
def check_ai_provider_route(
    provider_id: str,
    actor: str = Query(min_length=1, max_length=255),
    db: Session = Depends(db_session),
) -> AIProviderHealth:
    try:
        return check_ai_provider(
            db,
            get_ai_provider(db, provider_id),
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/models",
    response_model=AIModelRead,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_model_config_route(
    payload: AIModelCreate,
    db: Session = Depends(db_session),
) -> AIModelConfig:
    try:
        return create_ai_model(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/models", response_model=list[AIModelRead])
def list_ai_models(
    provider_id: str | None = None,
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[AIModelConfig]:
    query = select(AIModelConfig)
    if provider_id:
        query = query.where(AIModelConfig.provider_id == provider_id)
    if enabled is not None:
        query = query.where(AIModelConfig.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIModelConfig.display_name).limit(limit)).all()
    )


@router.post(
    "/routes",
    response_model=AIModelRouteRead,
    status_code=status.HTTP_201_CREATED,
)
def create_model_route_route(
    payload: AIModelRouteCreate,
    db: Session = Depends(db_session),
) -> AIModelRoute:
    try:
        return create_ai_model_route_service(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/routes", response_model=list[AIModelRouteRead])
def list_model_routes(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[AIModelRoute]:
    query = select(AIModelRoute)
    if enabled is not None:
        query = query.where(AIModelRoute.enabled == enabled)
    return list(
        db.scalars(query.order_by(AIModelRoute.purpose).limit(limit)).all()
    )
