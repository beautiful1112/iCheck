from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .database import get_db
from .promotion_recovery_schemas import (PromotionRecoveryPolicyStatementCreate, PromotionRecoveryPolicyCreate,
    PromotionRecoveryPolicyStatement, PromotionRecoveryPolicyRead, PromotionKeyRecoveryStatementCreate,
    PromotionKeyRecoveryStatement, PromotionKeyRecoveryProposalCreate, PromotionKeyRecoveryRead,
    PromotionKeyRecoveryAction, PromotionRecoveryEventRead)
from .services import promotion_recovery as service

router = APIRouter(prefix="/api/v1/capability-promotions", tags=["promotion-recovery"])
DB = Annotated[Session, Depends(get_db)]
Manager = Annotated[PrincipalContext, Depends(require_global_permissions("capabilities.manage"))]


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/sources/{source_id}/recovery-policy-statements", response_model=PromotionRecoveryPolicyStatement)
def policy_statement(source_id: str, payload: PromotionRecoveryPolicyStatementCreate, db: DB, principal: Manager):
    return _call(service.create_promotion_recovery_policy_statement, db, source_id, payload, actor=request_actor(principal, payload.actor))


@router.post("/sources/{source_id}/recovery-policies", response_model=PromotionRecoveryPolicyRead)
def authorize_policy(source_id: str, payload: PromotionRecoveryPolicyCreate, db: DB, principal: Manager):
    return _call(service.authorize_promotion_recovery_policy, db, source_id, payload, actor=request_actor(principal, payload.actor))


@router.get("/recovery-policies", response_model=list[PromotionRecoveryPolicyRead])
def policies(db: DB, principal: Manager, source_id: str | None = None):
    return service.list_promotion_recovery_policies(db, source_id)


@router.post("/sources/{source_id}/key-recovery-statements", response_model=PromotionKeyRecoveryStatement)
def recovery_statement(source_id: str, payload: PromotionKeyRecoveryStatementCreate, db: DB, principal: Manager):
    return _call(service.create_promotion_key_recovery_statement, db, source_id, payload, actor=request_actor(principal, payload.actor))


@router.post("/sources/{source_id}/key-recoveries", response_model=PromotionKeyRecoveryRead)
def propose(source_id: str, payload: PromotionKeyRecoveryProposalCreate, db: DB, principal: Manager):
    return _call(service.propose_promotion_key_recovery, db, source_id, payload, actor=request_actor(principal, payload.actor))


@router.post("/sources/{source_id}/key-recoveries/preview")
def preview(source_id: str, payload: PromotionKeyRecoveryProposalCreate, db: DB, principal: Manager):
    return _call(service.preview_promotion_key_recovery, db, source_id, payload)


@router.get("/key-recoveries", response_model=list[PromotionKeyRecoveryRead])
def ceremonies(db: DB, principal: Manager, source_id: str | None = None):
    return service.list_promotion_key_recoveries(db, source_id)


@router.post("/key-recoveries/{ceremony_id}/execute", response_model=PromotionKeyRecoveryRead)
def execute(ceremony_id: str, payload: PromotionKeyRecoveryAction, db: DB, principal: Manager):
    return _call(service.execute_promotion_key_recovery, db, ceremony_id, payload, actor=request_actor(principal, payload.actor))


@router.post("/key-recoveries/{ceremony_id}/cancel", response_model=PromotionKeyRecoveryRead)
def cancel(ceremony_id: str, payload: PromotionKeyRecoveryAction, db: DB, principal: Manager):
    return _call(service.cancel_promotion_key_recovery, db, ceremony_id, payload, actor=request_actor(principal, payload.actor))


@router.get("/recovery-events", response_model=list[PromotionRecoveryEventRead])
def events(db: DB, principal: Manager, source_id: str | None = None):
    return service.list_promotion_recovery_events(db, source_id)
