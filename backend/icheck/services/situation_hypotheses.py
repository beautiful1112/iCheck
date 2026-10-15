from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import InvestigationState
from ..models import (
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    Situation,
    SituationHypothesis,
    SituationHypothesisEvidence,
    SituationHypothesisRevision,
    utcnow,
)
from .audit import record_audit_event
from .situations import append_situation_event


def _statement_hash(statement: str) -> str:
    normalized = " ".join(statement.split()).casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_hypothesis_evidence(
    db: Session,
    investigation: Investigation,
    state: InvestigationState,
) -> dict[str, InvestigationEvidence]:
    state_evidence_ids = set(state.evidence_ids)
    requested: set[str] = set()
    for hypothesis in state.hypotheses:
        supporting = set(hypothesis.supporting_evidence_ids)
        contradicting = set(hypothesis.contradicting_evidence_ids)
        if supporting & contradicting:
            raise ValueError(
                "Hypothesis evidence cannot be both supporting and contradicting"
            )
        if not (supporting | contradicting) <= state_evidence_ids:
            raise ValueError(
                "Hypothesis evidence IDs must be present in checkpoint evidence_ids"
            )
        requested.update(supporting)
        requested.update(contradicting)
    if not requested:
        return {}
    evidence = list(
        db.scalars(
            select(InvestigationEvidence).where(
                InvestigationEvidence.id.in_(requested),
                InvestigationEvidence.investigation_id == investigation.id,
            )
        ).all()
    )
    by_id = {item.id: item for item in evidence}
    if set(by_id) != requested:
        raise ValueError(
            "Hypothesis evidence must belong to the same Investigation"
        )
    return by_id


def sync_situation_hypotheses(
    db: Session,
    investigation: Investigation,
    checkpoint: InvestigationCheckpoint,
    state: InvestigationState,
    *,
    actor: str,
    evidence_by_id: dict[str, InvestigationEvidence],
) -> None:
    if investigation.situation_id is None:
        return
    situation = db.get(Situation, investigation.situation_id)
    if situation is None:
        raise RuntimeError("Investigation references a missing Situation")

    terminal_proposal = state.status == "completed"
    touched_hashes: set[str] = set()
    proposed_count = 0
    for item in state.hypotheses:
        statement_hash = _statement_hash(item.statement)
        touched_hashes.add(statement_hash)
        hypothesis = db.scalar(
            select(SituationHypothesis)
            .where(
                SituationHypothesis.investigation_id == investigation.id,
                SituationHypothesis.statement_hash == statement_hash,
            )
            .with_for_update()
        )
        if hypothesis is None:
            hypothesis = SituationHypothesis(
                situation_id=situation.id,
                investigation_id=investigation.id,
                statement_hash=statement_hash,
                statement=" ".join(item.statement.split()),
                status="proposed" if terminal_proposal else "candidate",
                current_confidence=item.confidence,
                revision_count=0,
                source_model_id=investigation.model_id,
                created_by=actor,
            )
            db.add(hypothesis)
            db.flush()
        existing_revision = db.scalar(
            select(SituationHypothesisRevision).where(
                SituationHypothesisRevision.hypothesis_id == hypothesis.id,
                SituationHypothesisRevision.checkpoint_id == checkpoint.id,
            )
        )
        if existing_revision is not None:
            continue
        hypothesis.current_confidence = item.confidence
        hypothesis.revision_count += 1
        hypothesis.updated_at = utcnow()
        if terminal_proposal and hypothesis.status == "candidate":
            hypothesis.status = "proposed"
            proposed_count += 1
        elif terminal_proposal and hypothesis.status == "proposed":
            proposed_count += 1
        revision = SituationHypothesisRevision(
            hypothesis_id=hypothesis.id,
            checkpoint_id=checkpoint.id,
            revision=hypothesis.revision_count,
            iteration=state.iteration,
            confidence=item.confidence,
        )
        db.add(revision)
        db.flush()
        for evidence_id in item.supporting_evidence_ids:
            db.add(
                SituationHypothesisEvidence(
                    revision_id=revision.id,
                    investigation_evidence_id=evidence_by_id[evidence_id].id,
                    stance="supporting",
                )
            )
        for evidence_id in item.contradicting_evidence_ids:
            db.add(
                SituationHypothesisEvidence(
                    revision_id=revision.id,
                    investigation_evidence_id=evidence_by_id[evidence_id].id,
                    stance="contradicting",
                )
            )

    if terminal_proposal:
        hypotheses = list(
            db.scalars(
                select(SituationHypothesis).where(
                    SituationHypothesis.investigation_id == investigation.id
                )
            ).all()
        )
        for hypothesis in hypotheses:
            if (
                hypothesis.statement_hash not in touched_hashes
                and hypothesis.status == "candidate"
            ):
                hypothesis.status = "superseded"
                hypothesis.updated_at = utcnow()
        if proposed_count:
            append_situation_event(
                db,
                situation,
                event_type="hypotheses.proposed",
                actor=actor,
                details={
                    "investigation_id": investigation.id,
                    "count": proposed_count,
                },
            )
            situation.updated_at = utcnow()
            record_audit_event(
                db,
                event_type="situation.hypotheses.proposed",
                actor_type="agent",
                actor_id=actor,
                entity_type="situation",
                entity_id=situation.id,
                details={
                    "investigation_id": investigation.id,
                    "count": proposed_count,
                },
            )


def review_hypothesis(
    db: Session,
    situation: Situation,
    hypothesis: SituationHypothesis,
    *,
    decision: str,
    actor: str,
    reason: str,
) -> SituationHypothesis:
    if decision not in {"accepted", "rejected"}:
        raise ValueError("Hypothesis review decision is invalid")
    if hypothesis.situation_id != situation.id:
        raise LookupError("Situation hypothesis not found")
    if hypothesis.status in {"candidate", "superseded"}:
        raise ValueError("Only a completed proposed hypothesis can be reviewed")
    if hypothesis.status == decision:
        return hypothesis
    previous = hypothesis.status
    hypothesis.status = decision
    hypothesis.reviewed_by = actor
    hypothesis.review_reason = reason
    hypothesis.reviewed_at = utcnow()
    hypothesis.updated_at = utcnow()
    append_situation_event(
        db,
        situation,
        event_type=f"hypothesis.{decision}",
        actor=actor,
        details={
            "hypothesis_id": hypothesis.id,
            "from": previous,
            "reason": reason,
        },
    )
    situation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type=f"situation.hypothesis.{decision}",
        actor_type="user",
        actor_id=actor,
        entity_type="situation_hypothesis",
        entity_id=hypothesis.id,
        details={
            "situation_id": situation.id,
            "from": previous,
            "reason": reason,
        },
    )
    return hypothesis
