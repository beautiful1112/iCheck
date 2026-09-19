from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .activation_schemas import (
    ActivationApproval,
    ActivationDeactivate,
    ActivationPlanRead,
    ActivationPolicyAction,
    ActivationPreviewRequest,
    DeviceActivationPolicyCreate,
    DeviceActivationPolicyRead,
    DeviceActivationResult,
)
from .database import get_db
from .models import ArtifactVersionStatus, DeviceActivationPolicy
from .services.activation import (
    approve_activation,
    create_activation_policy,
    deactivate_connection,
    preview_activation,
    publish_activation_policy,
    validate_activation_policy,
)


router = APIRouter(prefix="/api/v1/assets", tags=["asset-activation"])


def db_session():
    yield from get_db()


def _policy(db: Session, policy_id: str) -> DeviceActivationPolicy:
    policy = db.get(DeviceActivationPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Activation policy not found")
    return policy


@router.post(
    "/activation-policies",
    response_model=DeviceActivationPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_activation_policy_route(
    payload: DeviceActivationPolicyCreate,
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    try:
        return create_activation_policy(db, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/activation-policies",
    response_model=list[DeviceActivationPolicyRead],
)
def list_activation_policies(
    protocol: str | None = Query(default=None, max_length=32),
    policy_status: ArtifactVersionStatus | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(db_session),
) -> list[DeviceActivationPolicy]:
    query = select(DeviceActivationPolicy)
    if protocol:
        query = query.where(DeviceActivationPolicy.protocol == protocol)
    if policy_status:
        query = query.where(DeviceActivationPolicy.status == policy_status)
    return list(
        db.scalars(
            query.order_by(
                DeviceActivationPolicy.name,
                DeviceActivationPolicy.version.desc(),
            ).limit(limit)
        ).all()
    )


@router.get(
    "/activation-policies/{policy_id}",
    response_model=DeviceActivationPolicyRead,
)
def get_activation_policy_route(
    policy_id: str,
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    return _policy(db, policy_id)


@router.post(
    "/activation-policies/{policy_id}/validate",
    response_model=DeviceActivationPolicyRead,
)
def validate_activation_policy_route(
    policy_id: str,
    payload: ActivationPolicyAction,
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    try:
        return validate_activation_policy(db, _policy(db, policy_id), payload.actor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/activation-policies/{policy_id}/publish",
    response_model=DeviceActivationPolicyRead,
)
def publish_activation_policy_route(
    policy_id: str,
    payload: ActivationPolicyAction,
    db: Session = Depends(db_session),
) -> DeviceActivationPolicy:
    try:
        return publish_activation_policy(db, _policy(db, policy_id), payload.actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/preview",
    response_model=ActivationPlanRead,
)
def preview_activation_route(
    device_id: str,
    connection_id: str,
    payload: ActivationPreviewRequest,
    db: Session = Depends(db_session),
) -> ActivationPlanRead:
    try:
        return preview_activation(db, device_id, connection_id, payload.policy_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/approve",
    response_model=DeviceActivationResult,
)
def approve_activation_route(
    device_id: str,
    connection_id: str,
    payload: ActivationApproval,
    db: Session = Depends(db_session),
) -> dict[str, object]:
    try:
        activation, deployment = approve_activation(
            db,
            device_id,
            connection_id,
            payload.policy_id,
            expected_plan_hash=payload.expected_plan_hash,
            actor=payload.actor,
            reason=payload.reason,
        )
        return {"activation": activation, "deployment": deployment}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/devices/{device_id}/connections/{connection_id}/activation/deactivate",
    response_model=DeviceActivationResult,
)
def deactivate_connection_route(
    device_id: str,
    connection_id: str,
    payload: ActivationDeactivate,
    db: Session = Depends(db_session),
) -> dict[str, object]:
    try:
        activation, deployment = deactivate_connection(
            db,
            device_id,
            connection_id,
            actor=payload.actor,
            reason=payload.reason,
        )
        return {"activation": activation, "deployment": deployment}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
