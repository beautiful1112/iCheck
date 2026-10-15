from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    Alert,
    AlertSeverity,
    CollectorConditionSource,
    Investigation,
    Situation,
    SituationAlert,
    SituationEvent,
    SituationHypothesis,
    SituationHypothesisEvidence,
    SituationHypothesisRevision,
    SituationImpactAssessment,
    SituationImpactAssessmentEvidence,
    SituationIntegrationRemoteReference,
    SituationStatus,
)
from .schemas import (
    SituationAction,
    SituationAlertEvidenceRead,
    SituationDetailRead,
    SituationInvestigationRead,
    SituationReconcileRead,
    SituationSummaryRead,
)
from .situation_impact_schemas import SituationImpactRead
from .workflow_runtime_schemas import SituationIntegrationRemoteReferenceRead
from .situation_assessment_schemas import (
    SituationImpactAssessmentEvidenceRead,
    SituationImpactAssessmentRead,
    SituationImpactAssessmentReview,
)
from .situation_hypothesis_schemas import (
    SituationHypothesisEvidenceRead,
    SituationHypothesisRead,
    SituationHypothesisReview,
    SituationHypothesisRevisionRead,
)
from .services.authorization_scope import (
    request_actor,
    require_situation_access,
    situation_scope_clause,
)
from .services.control_plane_auth import PrincipalContext
from .services.situations import (
    acknowledge_situation,
    reconcile_uncorrelated_alerts,
    resolve_situation,
)
from .services.situation_impact import situation_impact_graph
from .services.situation_hypotheses import review_hypothesis
from .services.situation_assessments import review_impact_assessment


router = APIRouter(prefix="/api/v1/situations", tags=["situations"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[SituationSummaryRead])
def list_situations(
    db: DBSession,
    situation_status: SituationStatus | None = Query(default=None, alias="status"),
    severity: AlertSeverity | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[Situation]:
    query = select(Situation).where(situation_scope_clause(principal))
    if situation_status is not None:
        query = query.where(Situation.status == situation_status.value)
    if severity is not None:
        query = query.where(Situation.severity == severity)
    return list(
        db.scalars(
            query.order_by(
                Situation.priority_score.desc(),
                Situation.last_seen.desc(),
            ).limit(limit)
        ).all()
    )


@router.get("/{situation_id}", response_model=SituationDetailRead)
def get_situation(
    situation_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> SituationDetailRead:
    situation = require_situation_access(db, principal, situation_id)
    alert_limit = 500
    event_limit = 500
    alert_rows = db.execute(
        select(SituationAlert, Alert)
        .join(Alert, Alert.id == SituationAlert.alert_id)
        .where(SituationAlert.situation_id == situation.id)
        .order_by(Alert.last_seen.desc(), Alert.id)
        .limit(alert_limit + 1)
    ).all()
    events = list(
        db.scalars(
            select(SituationEvent)
            .where(SituationEvent.situation_id == situation.id)
            .order_by(SituationEvent.sequence.desc())
            .limit(event_limit + 1)
        ).all()
    )
    investigations = list(
        db.scalars(
            select(Investigation)
            .where(Investigation.situation_id == situation.id)
            .order_by(Investigation.created_at.desc())
            .limit(100)
        ).all()
    )
    # A payload's source_id is not provenance. Link only the actual immutable
    # source bound to this reserved Alert key under the selected namespace.
    source_ids = dict(db.execute(select(CollectorConditionSource.dedup_key, CollectorConditionSource.id)
        .where(CollectorConditionSource.dedup_key.in_([alert.dedup_key for _, alert in alert_rows[:alert_limit]]))).all())
    return SituationDetailRead(
        situation=SituationSummaryRead.model_validate(situation),
        alerts=[
            SituationAlertEvidenceRead(
                alert_id=alert.id,
                condition_source_id=source_ids.get(alert.dedup_key),
                role=membership.role,
                correlation_reason=membership.correlation_reason,
                correlation_confidence=membership.correlation_confidence,
                correlation_evidence=membership.correlation_evidence,
                event_type=alert.event_type,
                severity=alert.severity,
                status=alert.status,
                title=alert.title,
                description=alert.description,
                occurrence_count=alert.occurrence_count,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
            )
            for membership, alert in alert_rows[:alert_limit]
        ],
        events=events[:event_limit],
        investigations=[
            SituationInvestigationRead.model_validate(item)
            for item in investigations
        ],
        alerts_truncated=len(alert_rows) > alert_limit,
        events_truncated=len(events) > event_limit,
    )


@router.get(
    "/{situation_id}/external-references",
    response_model=list[SituationIntegrationRemoteReferenceRead],
)
def list_situation_external_references(
    situation_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[SituationIntegrationRemoteReference]:
    situation = require_situation_access(db, principal, situation_id)
    return list(
        db.scalars(
            select(SituationIntegrationRemoteReference)
            .where(SituationIntegrationRemoteReference.situation_id == situation.id)
            .order_by(SituationIntegrationRemoteReference.updated_at.desc())
        ).all()
    )


@router.get("/{situation_id}/impact", response_model=SituationImpactRead)
def get_situation_impact(
    situation_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> dict[str, object]:
    situation = require_situation_access(db, principal, situation_id)
    return situation_impact_graph(db, situation, principal)


def _impact_assessment_read(
    assessment: SituationImpactAssessment,
) -> SituationImpactAssessmentRead:
    return SituationImpactAssessmentRead(
        id=assessment.id,
        situation_id=assessment.situation_id,
        investigation_id=assessment.investigation_id,
        checkpoint_id=assessment.checkpoint_id,
        contract_version=assessment.contract_version,
        status=assessment.status,
        impact_level=assessment.impact_level,
        summary=assessment.summary,
        confidence=assessment.confidence,
        affected_node_ids=list(assessment.affected_node_ids or []),
        uncertainty=list(assessment.uncertainty or []),
        service_context_snapshot=list(
            assessment.service_context_snapshot or []
        ),
        dependency_context_snapshot=list(
            assessment.dependency_context_snapshot or []
        ),
        indicator_context_snapshot=list(
            assessment.indicator_context_snapshot or []
        ),
        source_model_id=assessment.source_model_id,
        created_by=assessment.created_by,
        reviewed_by=assessment.reviewed_by,
        review_reason=assessment.review_reason,
        reviewed_at=assessment.reviewed_at,
        evidence=[
            SituationImpactAssessmentEvidenceRead(
                evidence_reference_id=link.evidence.id,
                evidence_type=link.evidence.evidence_type,
                evidence_id=link.evidence.evidence_id,
                summary=link.evidence.summary,
                observed_at=link.evidence.observed_at,
            )
            for link in assessment.evidence_links
        ],
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _impact_assessment_query(situation_id: str):
    return (
        select(SituationImpactAssessment)
        .where(SituationImpactAssessment.situation_id == situation_id)
        .options(
            selectinload(SituationImpactAssessment.evidence_links).selectinload(
                SituationImpactAssessmentEvidence.evidence
            )
        )
    )


@router.get(
    "/{situation_id}/impact-assessments",
    response_model=list[SituationImpactAssessmentRead],
)
def list_situation_impact_assessments(
    situation_id: str,
    db: DBSession,
    assessment_status: Literal["proposed", "accepted", "rejected"]
    | None = Query(default=None, alias="status"),
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[SituationImpactAssessmentRead]:
    situation = require_situation_access(db, principal, situation_id)
    query = _impact_assessment_query(situation.id)
    if assessment_status is not None:
        query = query.where(SituationImpactAssessment.status == assessment_status)
    assessments = list(
        db.scalars(
            query.order_by(SituationImpactAssessment.created_at.desc()).limit(limit)
        ).all()
    )
    return [_impact_assessment_read(item) for item in assessments]


def _review_impact_assessment_route(
    situation_id: str,
    assessment_id: str,
    payload: SituationImpactAssessmentReview,
    db: Session,
    principal: PrincipalContext,
    *,
    decision: str,
) -> SituationImpactAssessmentRead:
    situation = require_situation_access(db, principal, situation_id)
    assessment = db.scalar(
        _impact_assessment_query(situation.id).where(
            SituationImpactAssessment.id == assessment_id
        )
    )
    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="Situation impact assessment not found",
        )
    try:
        review_impact_assessment(
            db,
            situation,
            assessment,
            decision=decision,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    assessment = db.scalar(
        _impact_assessment_query(situation.id).where(
            SituationImpactAssessment.id == assessment.id
        )
    )
    if assessment is None:
        raise RuntimeError("Reviewed impact assessment disappeared")
    return _impact_assessment_read(assessment)


@router.post(
    "/{situation_id}/impact-assessments/{assessment_id}/accept",
    response_model=SituationImpactAssessmentRead,
)
def accept_situation_impact_assessment(
    situation_id: str,
    assessment_id: str,
    payload: SituationImpactAssessmentReview,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> SituationImpactAssessmentRead:
    return _review_impact_assessment_route(
        situation_id,
        assessment_id,
        payload,
        db,
        principal,
        decision="accepted",
    )


@router.post(
    "/{situation_id}/impact-assessments/{assessment_id}/reject",
    response_model=SituationImpactAssessmentRead,
)
def reject_situation_impact_assessment(
    situation_id: str,
    assessment_id: str,
    payload: SituationImpactAssessmentReview,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> SituationImpactAssessmentRead:
    return _review_impact_assessment_route(
        situation_id,
        assessment_id,
        payload,
        db,
        principal,
        decision="rejected",
    )


def _hypothesis_read(hypothesis: SituationHypothesis) -> SituationHypothesisRead:
    revisions = list(hypothesis.revisions)[-50:]
    return SituationHypothesisRead(
        id=hypothesis.id,
        situation_id=hypothesis.situation_id,
        investigation_id=hypothesis.investigation_id,
        statement=hypothesis.statement,
        status=hypothesis.status,
        current_confidence=hypothesis.current_confidence,
        revision_count=hypothesis.revision_count,
        source_model_id=hypothesis.source_model_id,
        created_by=hypothesis.created_by,
        reviewed_by=hypothesis.reviewed_by,
        review_reason=hypothesis.review_reason,
        reviewed_at=hypothesis.reviewed_at,
        revisions=[
            SituationHypothesisRevisionRead(
                id=revision.id,
                checkpoint_id=revision.checkpoint_id,
                revision=revision.revision,
                iteration=revision.iteration,
                confidence=revision.confidence,
                evidence=[
                    SituationHypothesisEvidenceRead(
                        evidence_reference_id=link.evidence.id,
                        stance=link.stance,
                        evidence_type=link.evidence.evidence_type,
                        evidence_id=link.evidence.evidence_id,
                        summary=link.evidence.summary,
                        observed_at=link.evidence.observed_at,
                    )
                    for link in revision.evidence_links
                ],
                created_at=revision.created_at,
            )
            for revision in revisions
        ],
        revisions_truncated=len(hypothesis.revisions) > len(revisions),
        created_at=hypothesis.created_at,
        updated_at=hypothesis.updated_at,
    )


def _hypothesis_query(situation_id: str):
    return (
        select(SituationHypothesis)
        .where(SituationHypothesis.situation_id == situation_id)
        .options(
            selectinload(SituationHypothesis.revisions)
            .selectinload(SituationHypothesisRevision.evidence_links)
            .selectinload(SituationHypothesisEvidence.evidence)
        )
    )


@router.get(
    "/{situation_id}/hypotheses",
    response_model=list[SituationHypothesisRead],
)
def list_situation_hypotheses(
    situation_id: str,
    db: DBSession,
    hypothesis_status: Literal[
        "candidate", "proposed", "accepted", "rejected", "superseded"
    ]
    | None = Query(default=None, alias="status"),
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    principal: PrincipalContext = Depends(require_permissions("alerts.read")),
) -> list[SituationHypothesisRead]:
    situation = require_situation_access(db, principal, situation_id)
    query = _hypothesis_query(situation.id)
    if hypothesis_status is not None:
        query = query.where(SituationHypothesis.status == hypothesis_status)
    hypotheses = list(
        db.scalars(
            query.order_by(
                SituationHypothesis.current_confidence.desc(),
                SituationHypothesis.updated_at.desc(),
            ).limit(limit)
        ).all()
    )
    return [_hypothesis_read(item) for item in hypotheses]


def _review_hypothesis_route(
    situation_id: str,
    hypothesis_id: str,
    payload: SituationHypothesisReview,
    db: Session,
    principal: PrincipalContext,
    *,
    decision: str,
) -> SituationHypothesisRead:
    situation = require_situation_access(db, principal, situation_id)
    hypothesis = db.scalar(
        _hypothesis_query(situation.id).where(
            SituationHypothesis.id == hypothesis_id
        )
    )
    if hypothesis is None:
        raise HTTPException(status_code=404, detail="Situation hypothesis not found")
    try:
        review_hypothesis(
            db,
            situation,
            hypothesis,
            decision=decision,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(hypothesis)
    hypothesis = db.scalar(
        _hypothesis_query(situation.id).where(
            SituationHypothesis.id == hypothesis.id
        )
    )
    if hypothesis is None:
        raise RuntimeError("Reviewed hypothesis disappeared")
    return _hypothesis_read(hypothesis)


@router.post(
    "/{situation_id}/hypotheses/{hypothesis_id}/accept",
    response_model=SituationHypothesisRead,
)
def accept_situation_hypothesis(
    situation_id: str,
    hypothesis_id: str,
    payload: SituationHypothesisReview,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> SituationHypothesisRead:
    return _review_hypothesis_route(
        situation_id,
        hypothesis_id,
        payload,
        db,
        principal,
        decision="accepted",
    )


@router.post(
    "/{situation_id}/hypotheses/{hypothesis_id}/reject",
    response_model=SituationHypothesisRead,
)
def reject_situation_hypothesis(
    situation_id: str,
    hypothesis_id: str,
    payload: SituationHypothesisReview,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> SituationHypothesisRead:
    return _review_hypothesis_route(
        situation_id,
        hypothesis_id,
        payload,
        db,
        principal,
        decision="rejected",
    )


@router.post("/{situation_id}/acknowledge", response_model=SituationSummaryRead)
def acknowledge_situation_route(
    situation_id: str,
    payload: SituationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> Situation:
    situation = require_situation_access(db, principal, situation_id)
    try:
        acknowledge_situation(
            db,
            situation,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
            principal=principal,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(situation)
    return situation


@router.post("/{situation_id}/resolve", response_model=SituationSummaryRead)
def resolve_situation_route(
    situation_id: str,
    payload: SituationAction,
    db: DBSession,
    principal: PrincipalContext = Depends(require_permissions("alerts.manage")),
) -> Situation:
    situation = require_situation_access(db, principal, situation_id)
    try:
        resolve_situation(
            db,
            situation,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
            principal=principal,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    db.refresh(situation)
    return situation


@router.post("/reconcile/active-alerts", response_model=SituationReconcileRead)
def reconcile_active_alerts_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    _: PrincipalContext = Depends(require_global_permissions("alerts.manage")),
) -> SituationReconcileRead:
    correlated = reconcile_uncorrelated_alerts(db, limit=limit)
    db.commit()
    return SituationReconcileRead(correlated_alerts=correlated)
