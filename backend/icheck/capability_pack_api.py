from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .capability_pack_schemas import (
    CapabilityPackInstallCreate,
    CapabilityPackInstallationRead,
    CapabilityPackPreviewCreate,
    CapabilityPackPreviewRead,
    CapabilityPackUninstallCreate,
    CapabilityPackUninstallPreviewRead,
)
from .database import get_db
from .sandbox import SandboxUnavailable
from .services.authorization_scope import request_actor
from .services.capability_packs import (
    get_capability_pack_installation,
    install_capability_pack,
    list_capability_pack_installations,
    preview_capability_pack,
)
from .services.capability_pack_uninstall import (
    preview_capability_pack_uninstall,
    uninstall_capability_pack,
)
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/capability-packs", tags=["capability-packs"])
DBSession = Annotated[Session, Depends(get_db)]


@router.post("/preview", response_model=CapabilityPackPreviewRead)
def preview_capability_pack_route(
    payload: CapabilityPackPreviewCreate,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackPreviewRead:
    try:
        return preview_capability_pack(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/install",
    response_model=CapabilityPackInstallationRead,
    status_code=status.HTTP_201_CREATED,
)
def install_capability_pack_route(
    payload: CapabilityPackInstallCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackInstallationRead:
    try:
        return install_capability_pack(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        code = 409 if (
            "not installable" in str(exc)
            or "already exists" in str(exc)
        ) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("", response_model=list[CapabilityPackInstallationRead])
def list_capability_pack_installations_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityPackInstallationRead]:
    return list_capability_pack_installations(db, limit=limit)


@router.get(
    "/{installation_id}/uninstall-preview",
    response_model=CapabilityPackUninstallPreviewRead,
)
def preview_capability_pack_uninstall_route(
    installation_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackUninstallPreviewRead:
    try:
        return preview_capability_pack_uninstall(db, installation_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{installation_id}/uninstall",
    response_model=CapabilityPackInstallationRead,
)
def uninstall_capability_pack_route(
    installation_id: str,
    payload: CapabilityPackUninstallCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackInstallationRead:
    try:
        return uninstall_capability_pack(
            db,
            installation_id,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/{installation_id}",
    response_model=CapabilityPackInstallationRead,
)
def get_capability_pack_installation_route(
    installation_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityPackInstallationRead:
    try:
        return get_capability_pack_installation(db, installation_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
