from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_permissions
from .database import get_db
from .models import (AlertConditionState, CollectorConditionReceipt, CollectorConditionSource, CollectorSourceQualificationRequest,
    CollectorSourceQualificationReview, CollectorSourceQualificationRevocation)
from .source_qualification_schemas import (SourceQualificationCreate, SourceQualificationHistoryRead,
    SourceQualificationRequestRead, SourceQualificationReviewCreate, SourceQualificationReviewRead,
    SourceQualificationRevoke, SourceQualificationRevocationRead, SourceQuietEvidenceRead, SourceDetailRead, SourceReceiptRead)
from .services.authorization_scope import require_alert_access
from .services.control_plane_auth import PrincipalContext
from .services.source_qualifications import (MANAGE, QUALIFY, _row, propose_source_qualification,
    require_source_access, review_source_qualification, revoke_source_qualification, source_quiet_evidence)

router = APIRouter(prefix="/api/v1", tags=["source-qualification"])
DB = Annotated[Session, Depends(get_db)]


def _call(db, operation, *, write=False):
    try:
        result = operation()
        if write:
            db.commit()
        return result
    except (LookupError, PermissionError, ValueError) as exc:
        db.rollback()
        code = 404 if isinstance(exc, LookupError) else 403 if isinstance(exc, PermissionError) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/collector-condition-sources/{source_id}", response_model=SourceDetailRead)
def source_detail(source_id: str, db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    def read():
        source = _row(db, CollectorConditionSource, source_id)
        require_source_access(db, source, actor)
        state = db.scalar(select(AlertConditionState).where(AlertConditionState.dedup_key == source.dedup_key)
            .execution_options(populate_existing=True))
        if state and state.latest_alert_id:
            require_alert_access(db, actor, state.latest_alert_id)
        rows = list(db.scalars(select(CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id)
            .order_by(CollectorConditionReceipt.observed_at.desc(), CollectorConditionReceipt.created_at.desc(), CollectorConditionReceipt.id)
            .limit(limit+1)).all())
        return SourceDetailRead(source_id=source.id, condition_key=source.condition_key, entity_type=source.entity_type,
            entity_id=source.entity_id, context=source.context, logical_state=state.state if state else "unavailable",
            observed_at=state.observed_at if state else None, latest_alert_id=state.latest_alert_id if state else None,
            receipts=[SourceReceiptRead.model_validate(row) for row in rows[:limit]], receipts_truncated=len(rows)>limit)
    return _call(db, read)


@router.post("/collector-condition-sources/{source_id}/qualifications", response_model=SourceQualificationRequestRead, status_code=201)
def propose(source_id: str, payload: SourceQualificationCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(MANAGE, "capabilities.read"))):
    return _call(db, lambda: propose_source_qualification(db, source_id, payload, actor), write=True)


@router.post("/source-qualification-requests/{request_id}/review", response_model=SourceQualificationReviewRead, status_code=201)
def accept(request_id: str, payload: SourceQualificationReviewCreate, db: DB,
    actor: PrincipalContext = Depends(require_permissions(QUALIFY, "capabilities.read"))):
    return _call(db, lambda: review_source_qualification(db, request_id, payload, actor), write=True)


@router.post("/source-qualification-reviews/{review_id}/revoke", response_model=SourceQualificationRevocationRead, status_code=201)
def revoke(review_id: str, payload: SourceQualificationRevoke, db: DB,
    actor: PrincipalContext = Depends(require_permissions(QUALIFY))):
    return _call(db, lambda: revoke_source_qualification(db, review_id, payload, actor), write=True)


@router.get("/collector-condition-sources/{source_id}/quiet-evidence", response_model=SourceQuietEvidenceRead)
def quiet(source_id: str, db: DB, review_id: Annotated[str, Query(min_length=36, max_length=36)],
    alert_id: Annotated[str, Query(min_length=36, max_length=36)],
    actor: PrincipalContext = Depends(require_permissions("alerts.read"))):
    return _call(db, lambda: source_quiet_evidence(db, source_id, review_id, alert_id, actor))


@router.get("/collector-condition-sources/{source_id}/qualifications", response_model=SourceQualificationHistoryRead)
def history(source_id: str, db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    actor: PrincipalContext = Depends(require_permissions("alerts.read", "capabilities.read"))):
    def read():
        source = _row(db, CollectorConditionSource, source_id)
        require_source_access(db, source, actor)
        requests = list(db.scalars(select(CollectorSourceQualificationRequest).where(
            CollectorSourceQualificationRequest.source_id == source.id)
            .order_by(CollectorSourceQualificationRequest.created_at.desc(), CollectorSourceQualificationRequest.id)
            .limit(limit+1)).all())
        # No descendants of omitted requests are returned as an apparently
        # complete history. Every bounded list discloses truncation.
        reviews = list(db.scalars(select(CollectorSourceQualificationReview).where(
            CollectorSourceQualificationReview.request_id.in_([row.id for row in requests[:limit]]))
            .order_by(CollectorSourceQualificationReview.created_at.desc(), CollectorSourceQualificationReview.id)
            .limit(limit+1)).all())
        revocations = list(db.scalars(select(CollectorSourceQualificationRevocation).where(
            CollectorSourceQualificationRevocation.review_id.in_([row.id for row in reviews[:limit]]))
            .order_by(CollectorSourceQualificationRevocation.created_at.desc(), CollectorSourceQualificationRevocation.id)
            .limit(limit+1)).all())
        return SourceQualificationHistoryRead(source_id=source.id,
            requests=[SourceQualificationRequestRead.model_validate(row) for row in requests[:limit]],
            reviews=[SourceQualificationReviewRead.model_validate(row) for row in reviews[:limit]],
            revocations=[SourceQualificationRevocationRead.model_validate(row) for row in revocations[:limit]],
            truncated=any(len(rows) > limit for rows in (requests, reviews, revocations)))
    return _call(db, read)
