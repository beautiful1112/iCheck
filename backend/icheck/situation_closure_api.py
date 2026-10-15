from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .situation_closure_schemas import (SituationClosureGrantCreate, SituationClosureGrantRead,
    SituationClosureClaimCreate, SituationClosureClaimRead, SituationClosureFinalize, SituationClosureReceiptRead)
from .source_qualification_schemas import SourceQualificationRevoke
from .situation_recovery_api import _recovery_call
from .services.control_plane_auth import PrincipalContext
from .services.situation_closure import (QUALIFY, qualify_closure, revoke_closure,
    claim_closure, finalize_closure, release_closure, closure_history, closure_workspace, closure_request_detail)

router = APIRouter(prefix="/api/v1", tags=["situation-closure"])
DB = Annotated[Session, Depends(get_db)]


@router.post("/situation-closure-grants", response_model=SituationClosureGrantRead, status_code=201)
def qualify(payload: SituationClosureGrantCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(QUALIFY, "alerts.read", "capabilities.read"))):
    return _recovery_call(db, lambda: qualify_closure(db, payload, actor), write=True)


@router.post("/situation-closure-grants/{grant_id}/revoke", status_code=201)
def revoke(grant_id: str, payload: SourceQualificationRevoke, db: DB,
    actor: PrincipalContext = Depends(require_permissions(QUALIFY, "alerts.read"))):
    def operation():
        row = revoke_closure(db, grant_id, payload, actor)
        return {"id": row.id, "grant_id": row.grant_id, "principal_id": row.principal_id,
            "subject": row.subject, "reason": row.reason, "created_at": row.created_at}
    return _recovery_call(db, operation, write=True)


@router.post("/situations/{situation_id}/closure-claims", response_model=SituationClosureClaimRead, status_code=201)
def claim(situation_id: str, payload: SituationClosureClaimCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    # Service requires fresh situations.close for a new claim, but a committed
    # retry is an alerts.read historical recovery even after execution revoke.
    return _recovery_call(db, lambda: claim_closure(db, situation_id, payload, actor), write=True)


@router.post("/situation-closure-requests/{request_id}/finalize", response_model=SituationClosureReceiptRead)
def finalize(request_id: str, payload: SituationClosureFinalize, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: finalize_closure(db, request_id, payload, actor), write=True)


@router.post("/situation-closure-requests/{request_id}/release", response_model=SituationClosureClaimRead)
def release(request_id: str, payload: SituationClosureFinalize, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: release_closure(db, request_id, payload, actor), write=True)


@router.get("/situations/{situation_id}/closure-history")
def history(situation_id: str, db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 50,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: closure_history(db, situation_id, actor, limit=limit))


@router.get("/situations/{situation_id}/closure-workspace")
def workspace(situation_id: str, db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 50,
    grant_id: Annotated[str | None, Query(min_length=36, max_length=36)] = None,
    policy_request_id: Annotated[str | None, Query(min_length=36, max_length=36)] = None,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: closure_workspace(db, situation_id, actor, limit=limit, grant_id=grant_id, policy_request_id=policy_request_id))


@router.get("/situation-closure-requests/{request_id}")
def request_detail(request_id: str, db: DB, actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: closure_request_detail(db, request_id, actor))
