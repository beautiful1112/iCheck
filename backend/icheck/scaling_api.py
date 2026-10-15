from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    WorkerScalingApplicationEvent,
    WorkerScalingDecision,
    WorkerScalingPolicy,
)
from .scaling_schemas import (
    ScalingApplicationEventCreate,
    ScalingApplicationEventRead,
    ScalingDecisionRead,
    ScalingPolicyCreate,
    ScalingPolicyRead,
    ScalingPolicyUpdate,
)
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.worker_scaling import (
    create_scaling_policy,
    evaluate_scaling_policy,
    get_scaling_policy,
    list_scaling_application_events,
    list_scaling_decisions,
    list_scaling_policies,
    record_scaling_application_event,
    update_scaling_policy,
)


router = APIRouter(prefix="/api/v1/scaling", tags=["worker-scaling"])
DBSession = Annotated[Session, Depends(get_db)]


def _policy(db: Session, policy_id: str) -> WorkerScalingPolicy:
    try:
        return get_scaling_policy(db, policy_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _decision(db: Session, decision_id: str) -> WorkerScalingDecision:
    decision = db.get(WorkerScalingDecision, decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Scaling decision not found")
    return decision


@router.get("/policies", response_model=list[ScalingPolicyRead])
def list_policies(
    db: DBSession,
    _: PrincipalContext = Depends(require_permissions("scaling.read")),
) -> list[WorkerScalingPolicy]:
    return list_scaling_policies(db)


@router.post(
    "/policies",
    response_model=ScalingPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_policy(
    payload: ScalingPolicyCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("scaling.manage")
    ),
) -> WorkerScalingPolicy:
    try:
        return create_scaling_policy(
            db,
            payload,
            actor=request_actor(principal, None),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/policies/{policy_id}", response_model=ScalingPolicyRead)
def update_policy(
    policy_id: str,
    payload: ScalingPolicyUpdate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("scaling.manage")
    ),
) -> WorkerScalingPolicy:
    try:
        return update_scaling_policy(
            db,
            _policy(db, policy_id),
            payload,
            actor=request_actor(principal, None),
        )
    except ValueError as exc:
        code = 409 if "conflict" in str(exc) or "exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post(
    "/policies/{policy_id}/evaluate",
    response_model=ScalingDecisionRead,
)
def evaluate_policy(
    policy_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("scaling.manage")
    ),
) -> WorkerScalingDecision:
    return evaluate_scaling_policy(
        db,
        _policy(db, policy_id),
        actor=request_actor(principal, None),
    )


@router.post("/evaluate", response_model=list[ScalingDecisionRead])
def evaluate_all_policies(
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("scaling.manage")
    ),
) -> list[WorkerScalingDecision]:
    actor = request_actor(principal, None)
    decisions = [
        evaluate_scaling_policy(
            db,
            policy,
            actor=actor,
            commit=False,
        )
        for policy in sorted(list_scaling_policies(db), key=lambda policy: policy.id)
    ]
    db.commit()
    for decision in decisions:
        db.refresh(decision)
    return decisions


@router.get("/decisions", response_model=list[ScalingDecisionRead])
def list_decisions(
    db: DBSession,
    policy_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("scaling.read")),
) -> list[WorkerScalingDecision]:
    if policy_id is not None:
        _policy(db, policy_id)
    return list_scaling_decisions(db, policy_id=policy_id, limit=limit)


@router.post(
    "/decisions/{decision_id}/application-events",
    response_model=ScalingApplicationEventRead,
    status_code=status.HTTP_201_CREATED,
)
def report_application_event(
    decision_id: str,
    payload: ScalingApplicationEventCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("scaling.apply")
    ),
) -> WorkerScalingApplicationEvent:
    try:
        return record_scaling_application_event(
            db,
            _decision(db, decision_id),
            payload,
            provider_subject=principal.subject,
            actor=request_actor(principal, None),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/application-events",
    response_model=list[ScalingApplicationEventRead],
)
def list_application_events(
    db: DBSession,
    decision_id: str | None = None,
    provider_subject: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("scaling.read")),
) -> list[WorkerScalingApplicationEvent]:
    if decision_id is not None:
        _decision(db, decision_id)
    return list_scaling_application_events(
        db,
        decision_id=decision_id,
        provider_subject=provider_subject,
        limit=limit,
    )
