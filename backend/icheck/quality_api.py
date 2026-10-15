from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .quality_schemas import (
    QualityAssessmentRead, QualityAssessmentSummary, QualityEvaluate, QualityPolicyCreate, QualityPolicyRead,
    QualityPolicyStateRead, QualityPolicyUpdate,
)
from .services import capability_quality as quality
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/capability-quality", tags=["capability-quality"])
DBSession = Annotated[Session, Depends(get_db)]
Reader = Annotated[PrincipalContext, Depends(require_global_permissions("capabilities.read"))]
Manager = Annotated[PrincipalContext, Depends(require_global_permissions("capabilities.manage"))]


def _error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=404 if isinstance(exc, LookupError) else 409, detail=str(exc))


@router.get("/policies", response_model=list[QualityPolicyStateRead])
def policies(db: DBSession, response: Response, _: Reader,
             offset: Annotated[int, Query(ge=0, le=1000)] = 0,
             limit: Annotated[int, Query(ge=1, le=100)] = 50,
             evidence_mode: Literal["execution_health", "remediation_outcome"] | None = None):
    response.headers["Cache-Control"] = "no-store"
    return [quality.policy_state(db, policy) for policy in quality.list_policies(db, offset=offset, limit=limit, evidence_mode=evidence_mode)]


@router.post("/policies", response_model=QualityPolicyRead, status_code=201)
def create(payload: QualityPolicyCreate, db: DBSession, response: Response, principal: Manager):
    response.headers["Cache-Control"] = "no-store"
    try:
        return quality.create_policy(db, payload, actor=request_actor(principal, None))
    except (LookupError, ValueError) as exc:
        raise _error(exc) from exc


@router.put("/policies/{policy_id}", response_model=QualityPolicyRead)
def update(policy_id: str, payload: QualityPolicyUpdate, db: DBSession, response: Response, principal: Manager):
    response.headers["Cache-Control"] = "no-store"
    try:
        return quality.update_policy(db, policy_id, payload, actor=request_actor(principal, None))
    except (LookupError, ValueError) as exc:
        raise _error(exc) from exc


@router.post("/policies/{policy_id}/evaluate", response_model=QualityAssessmentRead)
def evaluate(policy_id: str, payload: QualityEvaluate, db: DBSession, response: Response, principal: Manager):
    response.headers["Cache-Control"] = "no-store"
    try:
        return quality.evaluate_policy(db, policy_id, actor=request_actor(principal, None), reason=payload.reason)
    except (LookupError, ValueError) as exc:
        raise _error(exc) from exc


@router.get("/policies/{policy_id}/assessments", response_model=list[QualityAssessmentSummary])
def history(policy_id: str, db: DBSession, response: Response, _: Reader,
            limit: Annotated[int, Query(ge=1, le=100)] = 50):
    response.headers["Cache-Control"] = "no-store"
    try:
        return quality.list_assessments(db, policy_id, limit=limit)
    except LookupError as exc:
        raise _error(exc) from exc


@router.get("/assessments/{assessment_id}", response_model=QualityAssessmentRead)
def assessment(assessment_id: str, db: DBSession, response: Response, _: Reader):
    response.headers["Cache-Control"] = "no-store"
    try:
        return quality.get_assessment(db, assessment_id)
    except LookupError as exc:
        raise _error(exc) from exc
