from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .capability_catalog_schemas import CapabilityCatalogRead
from .database import get_db
from .models import ArtifactKind
from .services.capability_catalog import capability_catalog
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/capability-catalog", tags=["capability-catalog"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=CapabilityCatalogRead)
def list_capability_catalog(
    db: DBSession,
    q: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    kind: ArtifactKind | None = None,
    readiness: Literal["ready", "blocked", "declarative"] | None = None,
    preapproval_tool: bool = False,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityCatalogRead:
    return capability_catalog(
        db,
        query=q,
        kind=kind,
        readiness=readiness,
        preapproval_tool=preapproval_tool,
        offset=offset,
        limit=limit,
    )
