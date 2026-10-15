from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .capability_transparency_schemas import (
    CapabilityTransparencyCheckpointRead,
    CapabilityTransparencyRecordListRead,
    CapabilityTransparencyVerificationRead,
)
from .database import get_db
from .services.capability_transparency import (
    get_capability_transparency_checkpoint,
    list_capability_transparency_records,
    verify_capability_transparency_chain,
)
from .services.control_plane_auth import PrincipalContext


router = APIRouter(
    prefix="/api/v1/capability-transparency",
    tags=["capability-transparency"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/checkpoint",
    response_model=CapabilityTransparencyCheckpointRead,
)
def get_capability_transparency_checkpoint_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityTransparencyCheckpointRead:
    return get_capability_transparency_checkpoint(db)


@router.get(
    "/records",
    response_model=CapabilityTransparencyRecordListRead,
)
def list_capability_transparency_records_route(
    db: DBSession,
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    event_type: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityTransparencyRecordListRead:
    return list_capability_transparency_records(
        db,
        after_sequence=after_sequence,
        event_type=event_type,
        limit=limit,
    )


@router.get(
    "/verify",
    response_model=CapabilityTransparencyVerificationRead,
)
def verify_capability_transparency_chain_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityTransparencyVerificationRead:
    return verify_capability_transparency_chain(db)
