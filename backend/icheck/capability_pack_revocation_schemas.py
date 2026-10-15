from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


REVOCATION_FEED_FORMAT = "icheck.capability-pack.revocations/v1"
SIGNED_REVOCATION_FEED_FORMAT = "icheck.capability-pack.revocations.signed/v1"

RevocationReason = Literal[
    "compromised",
    "malicious",
    "vulnerable",
    "policy_violation",
    "superseded",
]


class CapabilityPackRevocationModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CapabilityPackRevocationEntry(CapabilityPackRevocationModel):
    pack_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_code: RevocationReason
    effective_at: datetime


class CapabilityPackRevocationStatement(CapabilityPackRevocationModel):
    format_version: Literal[
        "icheck.capability-pack.revocations/v1"
    ] = REVOCATION_FEED_FORMAT
    sequence: int = Field(ge=1)
    issued_at: datetime
    entries: list[CapabilityPackRevocationEntry] = Field(
        min_length=1,
        max_length=500,
    )
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_entries(self) -> CapabilityPackRevocationStatement:
        if self.issued_at.tzinfo is None:
            raise ValueError("Revocation feed issued_at must include a timezone")
        digests = [item.pack_digest_sha256 for item in self.entries]
        if len(set(digests)) != len(digests):
            raise ValueError("Revocation feed pack digests must be unique")
        for entry in self.entries:
            if entry.effective_at.tzinfo is None:
                raise ValueError(
                    "Revocation entry effective_at must include a timezone"
                )
            if entry.effective_at > self.issued_at:
                raise ValueError(
                    "Revocation entry effective_at cannot be after issued_at"
                )
        return self


class SignedCapabilityPackRevocationFeed(CapabilityPackRevocationModel):
    format_version: Literal[
        "icheck.capability-pack.revocations.signed/v1"
    ] = SIGNED_REVOCATION_FEED_FORMAT
    feed: CapabilityPackRevocationStatement
    signature: ArtifactBundleSignature


class CapabilityPackRevocationIngestCreate(CapabilityPackRevocationModel):
    signed_feed: SignedCapabilityPackRevocationFeed
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPackRevocationEntryRead(CapabilityPackRevocationModel):
    id: str
    pack_digest_sha256: str
    reason_code: RevocationReason
    effective_at: datetime
    created_at: datetime


class CapabilityPackQuarantineSummary(CapabilityPackRevocationModel):
    installed_packs: int = Field(ge=0, default=0)
    artifact_versions: int = Field(ge=0, default=0)
    collector_deployments: int = Field(ge=0, default=0)
    collector_canaries: int = Field(ge=0, default=0)
    mcp_activations: int = Field(ge=0, default=0)
    workflow_triggers: int = Field(ge=0, default=0)
    workflow_schedules: int = Field(ge=0, default=0)
    investigations: int = Field(ge=0, default=0)
    agent_executions: int = Field(ge=0, default=0)
    indicator_bindings: int = Field(ge=0, default=0)
    integration_bindings: int = Field(ge=0, default=0)


class CapabilityPackRevocationFeedRead(CapabilityPackRevocationModel):
    id: str
    trust_key_id: str
    sequence: int
    issued_at: datetime
    feed_digest_sha256: str
    key_fingerprint_sha256: str
    signature_sha256: str
    entry_count: int
    quarantine_summary: CapabilityPackQuarantineSummary
    reason: str
    ingested_by: str
    ingested_at: datetime
    entries: list[CapabilityPackRevocationEntryRead]
