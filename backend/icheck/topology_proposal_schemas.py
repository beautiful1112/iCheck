from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator

from .schemas import APIModel
from .studio_schemas import GeneratedTopologySpec


TOPOLOGY_PROPOSAL_CONTRACT = "icheck.topology-proposal/v1"


class TopologyProposalAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class InvestigationTopologyProposalOutput(TopologyProposalAPIModel):
    contract: Literal["icheck.topology-proposal/v1"]
    rationale: str = Field(min_length=3, max_length=4000)
    spec: GeneratedTopologySpec
    supporting_evidence_ids: list[str] = Field(min_length=1, max_length=100)
    uncertainty: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("supporting_evidence_ids", "uncertainty")
    @classmethod
    def unique_values(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("values must be unique")
        return value


class TopologyProposalEvidenceRead(TopologyProposalAPIModel):
    evidence_reference_id: str
    evidence_type: str
    evidence_id: str
    summary: str
    observed_at: datetime | None


class InvestigationTopologyProposalRead(TopologyProposalAPIModel):
    id: str
    investigation_id: str
    checkpoint_id: str
    contract_version: Literal["icheck.topology-proposal/v1"]
    status: Literal["proposed", "published", "rejected"]
    rationale: str
    spec: GeneratedTopologySpec
    validation_report: dict[str, Any]
    uncertainty: list[str]
    authorization_scope: dict[str, Any]
    source_model_id: str
    created_by: str
    reviewed_by: str | None
    review_reason: str | None
    reviewed_at: datetime | None
    artifact_id: str | None
    artifact_version_id: str | None
    evidence: list[TopologyProposalEvidenceRead]
    created_at: datetime
    updated_at: datetime


class TopologyProposalReview(TopologyProposalAPIModel):
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=4000)
