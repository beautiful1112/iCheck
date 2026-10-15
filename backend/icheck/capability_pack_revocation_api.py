from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .capability_pack_revocation_schemas import (
    CapabilityPackRevocationFeedRead,
    CapabilityPackRevocationIngestCreate,
)
from .database import get_db
from .services.authorization_scope import request_actor
from .services.capability_pack_revocations import (
    get_revocation_feed,
    ingest_revocation_feed,
    list_revocation_feeds,
)
from .services.control_plane_auth import PrincipalContext


router = APIRouter(
    prefix="/api/v1/capability-pack-revocations",
    tags=["capability-pack-revocations"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "",
    response_model=CapabilityPackRevocationFeedRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_revocation_feed_route(
    payload: CapabilityPackRevocationIngestCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> CapabilityPackRevocationFeedRead:
    try:
        return ingest_revocation_feed(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except ValueError as exc:
        code = 409 if (
            "sequence" in str(exc) or "already exists" in str(exc)
        ) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("", response_model=list[CapabilityPackRevocationFeedRead])
def list_revocation_feeds_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[CapabilityPackRevocationFeedRead]:
    return [
        CapabilityPackRevocationFeedRead.model_validate(item)
        for item in list_revocation_feeds(db, limit=limit)
    ]


@router.get("/{feed_id}", response_model=CapabilityPackRevocationFeedRead)
def get_revocation_feed_route(
    feed_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> CapabilityPackRevocationFeedRead:
    try:
        return CapabilityPackRevocationFeedRead.model_validate(
            get_revocation_feed(db, feed_id)
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
