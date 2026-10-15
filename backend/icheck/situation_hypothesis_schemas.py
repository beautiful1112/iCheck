from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from .schemas import APIModel


class SituationHypothesisAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class SituationHypothesisEvidenceRead(SituationHypothesisAPIModel):
    evidence_reference_id: str
    stance: Literal["supporting", "contradicting"]
    evidence_type: str
    evidence_id: str
    summary: str
    observed_at: datetime | None


class SituationHypothesisRevisionRead(SituationHypothesisAPIModel):
    id: str
    checkpoint_id: str
    revision: int = Field(ge=1)
    iteration: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    evidence: list[SituationHypothesisEvidenceRead]
    created_at: datetime


class SituationHypothesisRead(SituationHypothesisAPIModel):
    id: str
    situation_id: str
    investigation_id: str
    statement: str
    status: Literal["candidate", "proposed", "accepted", "rejected", "superseded"]
    current_confidence: float = Field(ge=0, le=1)
    revision_count: int = Field(ge=1)
    source_model_id: str
    created_by: str
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None
    revisions: list[SituationHypothesisRevisionRead]
    revisions_truncated: bool
    created_at: datetime
    updated_at: datetime


class SituationHypothesisReview(SituationHypothesisAPIModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)
