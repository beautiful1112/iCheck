from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .source_qualification_api import _call
from .situation_recovery_schemas import (SituationRecoveryPolicyCreate, SituationRecoveryPolicyDetail,
    SituationRecoveryPolicyRequestRead, SituationRecoveryPolicyReviewCreate, SituationRecoveryPolicyReviewRead,
    SituationRecoveryPolicyRevoke, SituationRecoveryPolicyRevocationRead, SituationRecoveryEvidenceRead)
from .services.control_plane_auth import PrincipalContext
from .services.situation_recovery import (MANAGE, REVIEW, propose_recovery_policy, review_recovery_policy,
    revoke_recovery_policy, recovery_policy_detail, situation_recovery_evidence)

router = APIRouter(prefix="/api/v1", tags=["situation-recovery"])
DB = Annotated[Session, Depends(get_db)]


def _recovery_call(db, operation, *, write=False):
    try:
        return _call(db, operation, write=write)
    except OperationalError as exc:
        db.rollback()
        if getattr(exc.orig, "sqlstate", None) == "55P03":
            raise HTTPException(status_code=409, detail="Recovery evidence origin is busy; retry the full transaction") from exc
        raise


@router.post("/situation-recovery-policies", response_model=SituationRecoveryPolicyRequestRead, status_code=201)
def propose(payload: SituationRecoveryPolicyCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(MANAGE, "capabilities.read"))):
    return _recovery_call(db, lambda: propose_recovery_policy(db, payload, actor), write=True)


@router.get("/situation-recovery-policies/{request_id}", response_model=SituationRecoveryPolicyDetail)
def detail(request_id: str, db: DB, actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: recovery_policy_detail(db, request_id, actor))


@router.post("/situation-recovery-policies/{request_id}/review", response_model=SituationRecoveryPolicyReviewRead, status_code=201)
def review(request_id: str, payload: SituationRecoveryPolicyReviewCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(REVIEW, "capabilities.read"))):
    return _recovery_call(db, lambda: review_recovery_policy(db, request_id, payload, actor), write=True)


@router.post("/situation-recovery-policy-reviews/{review_id}/revoke", response_model=SituationRecoveryPolicyRevocationRead, status_code=201)
def revoke(review_id: str, payload: SituationRecoveryPolicyRevoke, db: DB,
    actor: PrincipalContext = Depends(require_permissions(REVIEW))):
    return _recovery_call(db, lambda: revoke_recovery_policy(db, review_id, payload, actor), write=True)


@router.get("/situations/{situation_id}/recovery-evidence", response_model=SituationRecoveryEvidenceRead)
def evidence(situation_id: str, policy_review_id: str, db: DB,
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _recovery_call(db, lambda: situation_recovery_evidence(db, situation_id, policy_review_id, actor))
