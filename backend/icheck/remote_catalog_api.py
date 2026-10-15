from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .config import get_settings
from .database import get_db
from .remote_catalog_schemas import (
    RemoteCatalogEntryListRead,
    RemoteCatalogKeyRotationCreate,
    RemoteCatalogKeyRotationRead,
    RemoteCatalogPackActionCreate,
    RemoteCatalogRefreshCreate,
    RemoteCatalogSnapshotRead,
    RemoteCatalogSourceCreate,
    RemoteCatalogSourceRead,
    RemoteCatalogSourceStateCreate,
)
from .capability_pack_schemas import (
    CapabilityPackInstallationRead,
    CapabilityPackPreviewRead,
)
from .sandbox import SandboxUnavailable
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.remote_capability_catalogs import (
    RemoteCatalogUnavailable,
    create_remote_catalog_source,
    list_current_remote_catalog_entries,
    list_remote_catalog_sources,
    refresh_remote_catalog,
    set_remote_catalog_source_state,
)
from .services.remote_capability_pack_acquisition import (
    RemotePackUnavailable,
    install_remote_catalog_pack,
    preview_remote_catalog_pack,
)
from .services.remote_catalog_key_rotation import (
    list_remote_catalog_key_rotations,
    rotate_remote_catalog_key,
)


router = APIRouter(
    prefix="/api/v1/remote-capability-catalogs",
    tags=["remote-capability-catalogs"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "",
    response_model=RemoteCatalogSourceRead,
    status_code=status.HTTP_201_CREATED,
)
def create_remote_catalog_source_route(
    payload: RemoteCatalogSourceCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> RemoteCatalogSourceRead:
    try:
        return RemoteCatalogSourceRead.model_validate(
            create_remote_catalog_source(
                db,
                payload,
                allowed_hosts=(
                    get_settings().capability_catalog_allowed_host_list
                ),
                actor=request_actor(principal, payload.created_by),
            )
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("", response_model=list[RemoteCatalogSourceRead])
def list_remote_catalog_sources_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[RemoteCatalogSourceRead]:
    return [
        RemoteCatalogSourceRead.model_validate(item)
        for item in list_remote_catalog_sources(db, limit=limit)
    ]


@router.post(
    "/{source_id}/state",
    response_model=RemoteCatalogSourceRead,
)
def set_remote_catalog_source_state_route(
    source_id: str,
    payload: RemoteCatalogSourceStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> RemoteCatalogSourceRead:
    try:
        return RemoteCatalogSourceRead.model_validate(
            set_remote_catalog_source_state(
                db,
                source_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/{source_id}/refresh",
    response_model=RemoteCatalogSnapshotRead,
)
def refresh_remote_catalog_route(
    source_id: str,
    payload: RemoteCatalogRefreshCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> RemoteCatalogSnapshotRead:
    try:
        return refresh_remote_catalog(
            db,
            source_id,
            payload,
            allowed_hosts=(
                get_settings().capability_catalog_allowed_host_list
            ),
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteCatalogUnavailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "sequence" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/entries/current",
    response_model=RemoteCatalogEntryListRead,
)
def list_current_remote_catalog_entries_route(
    db: DBSession,
    q: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    source_id: Annotated[str | None, Query(max_length=36)] = None,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> RemoteCatalogEntryListRead:
    return list_current_remote_catalog_entries(
        db,
        q=q,
        source_id=source_id,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/key-rotations",
    response_model=list[RemoteCatalogKeyRotationRead],
)
def list_remote_catalog_key_rotations_route(
    db: DBSession,
    source_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[RemoteCatalogKeyRotationRead]:
    return [
        RemoteCatalogKeyRotationRead.model_validate(item)
        for item in list_remote_catalog_key_rotations(
            db,
            source_id=source_id,
            limit=limit,
        )
    ]


@router.post(
    "/{source_id}/rotate-trust-key",
    response_model=RemoteCatalogSourceRead,
)
def rotate_remote_catalog_key_route(
    source_id: str,
    payload: RemoteCatalogKeyRotationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> RemoteCatalogSourceRead:
    try:
        return RemoteCatalogSourceRead.model_validate(
            rotate_remote_catalog_key(
                db,
                source_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _remote_pack_error_status(exc: ValueError) -> int:
    conflict_markers = (
        "not current",
        "disabled",
        "expired",
        "revoked",
        "not installable",
        "previously uninstalled",
        "already exists",
    )
    return 409 if any(item in str(exc) for item in conflict_markers) else 422


@router.post(
    "/entries/{entry_id}/preview",
    response_model=CapabilityPackPreviewRead,
)
def preview_remote_catalog_pack_route(
    entry_id: str,
    payload: RemoteCatalogPackActionCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackPreviewRead:
    try:
        return preview_remote_catalog_pack(
            db,
            entry_id,
            payload,
            allowed_hosts=(
                get_settings().capability_catalog_allowed_host_list
            ),
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemotePackUnavailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=_remote_pack_error_status(exc),
            detail=str(exc),
        ) from exc


@router.post(
    "/entries/{entry_id}/install",
    response_model=CapabilityPackInstallationRead,
    status_code=status.HTTP_201_CREATED,
)
def install_remote_catalog_pack_route(
    entry_id: str,
    payload: RemoteCatalogPackActionCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> CapabilityPackInstallationRead:
    try:
        return install_remote_catalog_pack(
            db,
            entry_id,
            payload,
            allowed_hosts=(
                get_settings().capability_catalog_allowed_host_list
            ),
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemotePackUnavailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=_remote_pack_error_status(exc),
            detail=str(exc),
        ) from exc
