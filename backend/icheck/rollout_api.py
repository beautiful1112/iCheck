from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .models import (
    CollectorCanaryRollout,
    CollectorFleetRollout,
    CollectorFleetRolloutItem,
    CollectorFleetRolloutRing,
)
from .rollout_schemas import (
    CollectorCanaryAction,
    CollectorCanaryCreate,
    CollectorCanaryRead,
    CollectorFleetAction,
    CollectorFleetPlanCreate,
    CollectorFleetRolloutItemRead,
    CollectorFleetRolloutRingRead,
    CollectorFleetRolloutRead,
)
from .services.authorization_scope import request_actor
from .services.canary_rollouts import (
    abort_canary_rollout,
    create_canary_rollout,
    promote_canary_rollout,
    reconcile_timed_out_rollouts,
)
from .services.control_plane_auth import PrincipalContext
from .services.fleet_rollouts import (
    apply_next_fleet_batch,
    create_fleet_rollout_plan,
    rollback_next_fleet_batch,
)
from .services.fleet_rollout_automation import set_automatic_rollout_state


router = APIRouter(prefix="/api/v1/collector-canary-rollouts", tags=["rollouts"])
fleet_router = APIRouter(
    prefix="/api/v1/collector-fleet-rollouts",
    tags=["rollouts"],
)
DBSession = Annotated[Session, Depends(get_db)]


def _rollout(db: Session, rollout_id: str) -> CollectorCanaryRollout:
    rollout = db.get(CollectorCanaryRollout, rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail="Collector canary rollout not found")
    return rollout


@router.post(
    "",
    response_model=CollectorCanaryRead,
    status_code=status.HTTP_201_CREATED,
)
def create_canary_rollout_route(
    payload: CollectorCanaryCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorCanaryRollout:
    try:
        return create_canary_rollout(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "active canary" in str(exc) or "exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("", response_model=list[CollectorCanaryRead])
def list_canary_rollouts_route(
    db: DBSession,
    artifact_id: str | None = None,
    rollout_status: Literal["running", "passed", "aborted", "promoted"] | None = Query(
        default=None,
        alias="status",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> list[CollectorCanaryRollout]:
    reconcile_timed_out_rollouts(db)
    query = select(CollectorCanaryRollout)
    if artifact_id:
        query = query.where(CollectorCanaryRollout.artifact_id == artifact_id)
    if rollout_status:
        query = query.where(CollectorCanaryRollout.status == rollout_status)
    return list(
        db.scalars(
            query.order_by(CollectorCanaryRollout.created_at.desc()).limit(limit)
        ).all()
    )


@router.get("/{rollout_id}", response_model=CollectorCanaryRead)
def get_canary_rollout_route(
    rollout_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> CollectorCanaryRollout:
    reconcile_timed_out_rollouts(db)
    return _rollout(db, rollout_id)


@router.post("/{rollout_id}/abort", response_model=CollectorCanaryRead)
def abort_canary_rollout_route(
    rollout_id: str,
    payload: CollectorCanaryAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorCanaryRollout:
    try:
        return abort_canary_rollout(
            db,
            _rollout(db, rollout_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{rollout_id}/promote", response_model=CollectorCanaryRead)
def promote_canary_rollout_route(
    rollout_id: str,
    payload: CollectorCanaryAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorCanaryRollout:
    try:
        return promote_canary_rollout(
            db,
            _rollout(db, rollout_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _fleet_rollout(db: Session, rollout_id: str) -> CollectorFleetRollout:
    rollout = db.get(CollectorFleetRollout, rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail="Collector fleet rollout not found")
    return rollout


@fleet_router.post(
    "",
    response_model=CollectorFleetRolloutRead,
    status_code=status.HTTP_201_CREATED,
)
def create_fleet_rollout_plan_route(
    payload: CollectorFleetPlanCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    try:
        return create_fleet_rollout_plan(
            db,
            payload,
            actor=request_actor(principal, payload.actor),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@fleet_router.get("", response_model=list[CollectorFleetRolloutRead])
def list_fleet_rollouts_route(
    db: DBSession,
    canary_rollout_id: str | None = None,
    rollout_status: Literal[
        "planned",
        "running",
        "completed",
        "failed",
        "rolling_back",
        "rolled_back",
        "rollback_failed",
    ]
    | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> list[CollectorFleetRollout]:
    query = select(CollectorFleetRollout)
    if canary_rollout_id:
        query = query.where(
            CollectorFleetRollout.canary_rollout_id == canary_rollout_id
        )
    if rollout_status:
        query = query.where(CollectorFleetRollout.status == rollout_status)
    return list(
        db.scalars(
            query.order_by(CollectorFleetRollout.created_at.desc()).limit(limit)
        ).all()
    )


@fleet_router.get(
    "/{rollout_id}",
    response_model=CollectorFleetRolloutRead,
)
def get_fleet_rollout_route(
    rollout_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> CollectorFleetRollout:
    return _fleet_rollout(db, rollout_id)


@fleet_router.get(
    "/{rollout_id}/items",
    response_model=list[CollectorFleetRolloutItemRead],
)
def list_fleet_rollout_items_route(
    rollout_id: str,
    db: DBSession,
    item_status: Literal[
        "pending",
        "blocked",
        "deferred",
        "migrated",
        "failed",
        "rollback_deferred",
        "rolled_back",
        "rollback_failed",
    ]
    | None = Query(default=None, alias="status"),
    limit: int = Query(default=1000, ge=1, le=10_000),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> list[CollectorFleetRolloutItem]:
    _fleet_rollout(db, rollout_id)
    query = select(CollectorFleetRolloutItem).where(
        CollectorFleetRolloutItem.rollout_id == rollout_id
    )
    if item_status:
        query = query.where(CollectorFleetRolloutItem.status == item_status)
    return list(
        db.scalars(
            query.order_by(CollectorFleetRolloutItem.deployment_id).limit(limit)
        ).all()
    )


@fleet_router.get(
    "/{rollout_id}/rings",
    response_model=list[CollectorFleetRolloutRingRead],
)
def list_fleet_rollout_rings_route(
    rollout_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read", "collectors.read")
    ),
) -> list[CollectorFleetRolloutRing]:
    _fleet_rollout(db, rollout_id)
    return list(
        db.scalars(
            select(CollectorFleetRolloutRing)
            .where(CollectorFleetRolloutRing.rollout_id == rollout_id)
            .order_by(CollectorFleetRolloutRing.ring_index)
        ).all()
    )


def _automatic_action(
    rollout_id: str,
    action: Literal["pause", "resume", "abort"],
    payload: CollectorFleetAction,
    db: Session,
    principal: PrincipalContext,
) -> CollectorFleetRollout:
    try:
        return set_automatic_rollout_state(
            db,
            rollout_id,
            action=action,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
            plan_sha256=payload.plan_sha256,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@fleet_router.post(
    "/{rollout_id}/automation/pause",
    response_model=CollectorFleetRolloutRead,
)
def pause_fleet_automation_route(
    rollout_id: str,
    payload: CollectorFleetAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    return _automatic_action(rollout_id, "pause", payload, db, principal)


@fleet_router.post(
    "/{rollout_id}/automation/resume",
    response_model=CollectorFleetRolloutRead,
)
def resume_fleet_automation_route(
    rollout_id: str,
    payload: CollectorFleetAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    return _automatic_action(rollout_id, "resume", payload, db, principal)


@fleet_router.post(
    "/{rollout_id}/automation/abort",
    response_model=CollectorFleetRolloutRead,
)
def abort_fleet_automation_route(
    rollout_id: str,
    payload: CollectorFleetAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    return _automatic_action(rollout_id, "abort", payload, db, principal)


@fleet_router.post(
    "/{rollout_id}/apply-next",
    response_model=CollectorFleetRolloutRead,
)
def apply_next_fleet_batch_route(
    rollout_id: str,
    payload: CollectorFleetAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    try:
        return apply_next_fleet_batch(
            db,
            rollout_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
            plan_sha256=payload.plan_sha256,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@fleet_router.post(
    "/{rollout_id}/rollback-next",
    response_model=CollectorFleetRolloutRead,
)
def rollback_next_fleet_batch_route(
    rollout_id: str,
    payload: CollectorFleetAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage", "collectors.manage")
    ),
) -> CollectorFleetRollout:
    try:
        return rollback_next_fleet_batch(
            db,
            rollout_id,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
            plan_sha256=payload.plan_sha256,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
