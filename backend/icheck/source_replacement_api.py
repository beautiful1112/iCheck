from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .source_replacement_schemas import (SourceReplacementCreate, SourceReplacementRequestRead,
    SourceReplacementReviewCreate, SourceReplacementReviewRead, SourceReplacementRevoke,
    SourceReplacementRevocationRead, SourceReplacementDetailRead, SourceReplacementApply,
    SourceRetirementRead, SourceReplacementWorkspaceRead)
from .services.control_plane_auth import PrincipalContext
from .services.source_replacements import (MANAGE, REVIEW, propose_source_replacement,
    review_source_replacement, revoke_source_replacement, source_replacement_detail)
from .services.source_retirements import apply_source_replacement, read_source_retirement
from .services.source_replacement_workspace import replacement_workspace

router = APIRouter(prefix="/api/v1", tags=["source-replacement"])
DB = Annotated[Session, Depends(get_db)]


def _call(db, operation, *, write=False):
    try:
        result = operation()
        if write: db.commit()
        return result
    except (LookupError, PermissionError, ValueError) as exc:
        db.rollback()
        code = 404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except (IntegrityError, OperationalError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Replacement changed or is contended; refresh and retry the same intent.") from exc


@router.get("/collector-condition-sources/{source_id}/replacement-workspace", response_model=SourceReplacementWorkspaceRead)
def workspace(source_id: str, db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 50,
    new_source_id: Annotated[str | None, Query(min_length=36, max_length=36)] = None,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    return _call(db, lambda: replacement_workspace(db, source_id, actor, new_source_id=new_source_id, limit=limit))


@router.post("/source-replacement-requests", response_model=SourceReplacementRequestRead, status_code=201)
def propose(payload: SourceReplacementCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(MANAGE, "capabilities.read"))):
    if payload.request_key.startswith("agent-replacement-"):
        raise HTTPException(status_code=409, detail="Agent replacement request identities are reserved for the owned runtime.")
    return _call(db, lambda: SourceReplacementRequestRead.model_validate(propose_source_replacement(db, payload, actor)), write=True)


@router.get("/source-replacement-requests/{request_id}", response_model=SourceReplacementDetailRead)
def detail(request_id: str, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    return _call(db, lambda: source_replacement_detail(db, request_id, actor))


@router.post("/source-replacement-requests/{request_id}/review", response_model=SourceReplacementReviewRead, status_code=201)
def review(request_id: str, payload: SourceReplacementReviewCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(REVIEW, "capabilities.read"))):
    return _call(db, lambda: SourceReplacementReviewRead.model_validate(review_source_replacement(db, request_id, payload, actor)), write=True)


@router.post("/source-replacement-reviews/{review_id}/revoke", response_model=SourceReplacementRevocationRead, status_code=201)
def revoke(review_id: str, payload: SourceReplacementRevoke, db: DB,
    actor: PrincipalContext = Depends(require_permissions(REVIEW))):
    return _call(db, lambda: SourceReplacementRevocationRead.model_validate(revoke_source_replacement(db, review_id, payload, actor)), write=True)


@router.post("/source-replacement-requests/{request_id}/apply", response_model=SourceRetirementRead)
def apply(request_id: str, payload: SourceReplacementApply, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    if payload.execution_key.startswith("agent-replacement-"):
        raise HTTPException(status_code=409, detail="Agent replacement execution identities are reserved for the owned runtime.")
    # A committed exact retry needs read authority only. The service rechecks
    # execution permission and the default-off gate for every fresh operation.
    return _call(db, lambda: apply_source_replacement(db, request_id, payload, actor), write=True)


@router.get("/source-retirements/{retirement_id}", response_model=SourceRetirementRead)
def retirement(retirement_id: str, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    return _call(db, lambda: read_source_retirement(db, retirement_id, actor))
