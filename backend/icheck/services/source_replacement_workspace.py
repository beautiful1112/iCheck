"""Bounded scoped discovery, never a substitute for fresh cutover checks."""
from fastapi import HTTPException
from sqlalchemy import select

from ..config import get_settings
from ..models import (AlertConditionState, CollectorConditionSource,
    CollectorSourceQualificationRequest, CollectorSourceQualificationReview,
    CollectorSourceQualificationRevocation, CollectorSourceReplacementRequest,
    CollectorSourceReplacementReview, CollectorSourceReplacementRevocation,
    CollectorSourceRetirement)
from ..source_replacement_schemas import SourceReplacementWorkspaceRead
from .source_qualifications import _row
from .source_replacements import MANAGE, REVIEW, _authority, _namespace_query, _scope
from .source_retirements import EXECUTE, retirement_for_source
from .alert_conditions import as_utc


def _summary(db, source):
    state = db.scalar(_namespace_query(db, AlertConditionState).where(
        AlertConditionState.dedup_key == source.dedup_key))
    retirement = retirement_for_source(db, source.id)
    return {"source_id": source.id, "deployment_id": source.deployment_id,
        "condition_key": source.condition_key, "entity_type": source.entity_type,
        "entity_id": source.entity_id, "definition": source.context["definition"],
        "logical_state": state.state if state else "unavailable",
        "observed_at": as_utc(state.observed_at) if state and state.observed_at else None,
        "retirement_id": retirement.id if retirement else None}


def replacement_workspace(db, old_source_id, actor, *, new_source_id=None, limit=50):
    if not 1 <= limit <= 100:
        raise ValueError("Replacement discovery limit must be between one and one hundred")
    old = _row(db, CollectorConditionSource, old_source_id)
    current = _authority(db, [old], actor, "alerts.read")
    new = _row(db, CollectorConditionSource, new_source_id) if new_source_id else None
    if new:
        for principal in (actor, current): _scope(db, [new], principal)
        if new.id == old.id or (new.entity_type, new.entity_id) != (old.entity_type, old.entity_id):
            raise ValueError("Replacement discovery requires distinct generations of the same entity")
    rows = list(db.scalars(_namespace_query(db, CollectorConditionSource).where(
        CollectorConditionSource.entity_type == old.entity_type,
        CollectorConditionSource.entity_id == old.entity_id,
        CollectorConditionSource.id != old.id)
        .order_by(CollectorConditionSource.created_at.desc(), CollectorConditionSource.id).limit(limit+1)))
    candidates = []
    for source in rows[:limit]:
        try:
            for principal in (actor, current): _scope(db, [source], principal)
        except (LookupError, PermissionError, HTTPException):
            continue
        candidates.append(_summary(db, source))
    selected = [old] + ([new] if new else [])
    requests = list(db.scalars(_namespace_query(db, CollectorSourceQualificationRequest).where(
        CollectorSourceQualificationRequest.source_id.in_([source.id for source in selected]))
        .order_by(CollectorSourceQualificationRequest.created_at.desc(), CollectorSourceQualificationRequest.id).limit(limit+1)))
    qualifications = []
    for request in requests[:limit]:
        review = db.scalar(_namespace_query(db, CollectorSourceQualificationReview).where(
            CollectorSourceQualificationReview.request_id == request.id))
        revoked = review is not None and db.scalar(_namespace_query(db, CollectorSourceQualificationRevocation).where(
            CollectorSourceQualificationRevocation.review_id == review.id)) is not None
        qualifications.append({"source_id": request.source_id, "request_id": request.id,
            "review_id": review.id if review else None, "author_subject": request.author_subject,
            "reviewer_subject": review.reviewer_subject if review else None,
            "evidence_environment": request.evidence_environment, "expires_at": as_utc(request.expires_at), "revoked": revoked})
    history = list(db.scalars(_namespace_query(db, CollectorSourceReplacementRequest).where(
        CollectorSourceReplacementRequest.old_source_id == old.id)
        .order_by(CollectorSourceReplacementRequest.created_at.desc(), CollectorSourceReplacementRequest.id).limit(limit+1)))
    summaries = []
    for request in history[:limit]:
        target = _row(db, CollectorConditionSource, request.new_source_id)
        try:
            for principal in (actor, current): _scope(db, [target], principal)
        except (LookupError, PermissionError, HTTPException):
            continue
        review = db.scalar(_namespace_query(db, CollectorSourceReplacementReview).where(
            CollectorSourceReplacementReview.request_id == request.id))
        revoked = review is not None and db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
            CollectorSourceReplacementRevocation.review_id == review.id)) is not None
        retirement = db.scalar(_namespace_query(db, CollectorSourceRetirement).where(
            CollectorSourceRetirement.request_id == request.id))
        summaries.append({"request_id": request.id, "old_source_id": old.id, "new_source_id": target.id,
            "review_id": review.id if review else None, "retirement_id": retirement.id if retirement else None,
            "prior_retirement_id": request.prior_retirement_id, "author_subject": request.author_subject,
            "reviewer_subject": review.reviewer_subject if review else None,
            "evidence_environment": request.evidence_environment, "expires_at": as_utc(request.expires_at), "revoked": revoked})
    def permits(permission):
        return all(person.permits(permission) for person in (actor, current))
    human = actor.principal_type == "user" and current.principal_type == "user"
    return SourceReplacementWorkspaceRead(old_source=_summary(db, old), new_source=_summary(db, new) if new else None,
        candidates=candidates, candidates_truncated=len(rows)>limit,
        qualifications=qualifications, qualifications_truncated=len(requests)>limit,
        requests=summaries, requests_truncated=len(history)>limit,
        host_enabled=get_settings().enable_reviewed_source_replacement,
        can_propose=permits(MANAGE), can_review=human and permits(REVIEW),
        can_revoke=human and permits(REVIEW), can_apply=permits(EXECUTE))
