"""Separate read-only lookup evidence for an unresolved MCP write."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import (
    MCPDeclaredProviderLookupQualification,
    MCPDispositionContractQualification,
    MCPDispositionEvidenceManifest,
    MCPDispositionIndependentEvidenceRef,
    MCPDispositionProviderEvidenceRef,
    MCPIndependentEvidenceSummary,
    MCPIndependentVerificationQualification,
    MCPIndependentVerificationResult,
    MCPWriteLookupResult,
    MCPWriteReconciliationPacket,
    MCPWriteReconciliationSummary,
)
from ..database import require_locking_transaction
from ..models import (
    AgentActionProposal,
    AgentToolRegistration,
    ArtifactVersion,
    Investigation,
    InvestigationToolCall,
    MCPServer,
    MCPToolActivation,
    MCPWriteIndependentObservation,
    MCPWriteIndependentReview,
    MCPWriteReconciliationObservation,
    MCPWriteReconciliationReview,
    utcnow,
)
from ..studio_schemas import GeneratedToolSpec
from ..schema_validation import validate_instance
from .audit import record_audit_event
from .change_governance import _hash_document
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _declared_outcome_lookup(
    db: Session,
    original: InvestigationToolCall,
    lookup: InvestigationToolCall,
) -> bool:
    if not all((
        original.artifact_activation_id,
        original.artifact_version_id,
        original.artifact_content_hash,
        original.artifact_activation_sha256,
        lookup.artifact_activation_id,
        lookup.artifact_version_id,
        lookup.artifact_content_hash,
        lookup.artifact_activation_sha256,
    )):
        return False
    write_activation = db.get(MCPToolActivation, original.artifact_activation_id)
    write_version = db.get(ArtifactVersion, original.artifact_version_id)
    lookup_activation = db.get(MCPToolActivation, lookup.artifact_activation_id)
    lookup_version = db.get(ArtifactVersion, lookup.artifact_version_id)
    write_server = db.get(MCPServer, write_activation.server_id) if write_activation else None
    lookup_server = db.get(MCPServer, lookup_activation.server_id) if lookup_activation else None
    namespace = (original.tenant_id, original.region_id)
    if (
        write_activation is None or write_version is None
        or lookup_activation is None or lookup_version is None
        or write_server is None or lookup_server is None
        or any((row.tenant_id, row.region_id) != namespace for row in (
            write_activation, write_version, lookup_activation, lookup_version,
            write_server, lookup_server,
        ))
        or write_activation.server_id != lookup_activation.server_id
        or write_activation.tool_registration_id != original.tool_id
        or write_activation.artifact_version_id != write_version.id
        or original.artifact_content_hash != write_version.content_hash
        or original.artifact_activation_sha256 != write_activation.contract_sha256
        or lookup_activation.tool_registration_id != lookup.tool_id
        or lookup_activation.artifact_version_id != lookup_version.id
        or lookup.artifact_content_hash != lookup_version.content_hash
        or lookup.artifact_activation_sha256 != lookup_activation.contract_sha256
    ):
        return False
    try:
        write_spec = GeneratedToolSpec.model_validate(write_version.definition["spec"])
        lookup_spec = GeneratedToolSpec.model_validate(lookup_version.definition["spec"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        not write_spec.read_only
        and lookup_spec.read_only
        and write_spec.tool_name == write_activation.tool_name
        and lookup_spec.tool_name == lookup_activation.tool_name
        and write_spec.mcp_tool_name == write_activation.mcp_tool_name
        and lookup_spec.mcp_tool_name == lookup_activation.mcp_tool_name
        and write_spec.mcp_server_name == write_server.name
        and lookup_spec.mcp_server_name == lookup_server.name
        and write_spec.outcome_lookup_tool_name == lookup_spec.tool_name
    )


def mcp_write_reconciliation_packet(
    db: Session,
    proposal: AgentActionProposal,
) -> MCPWriteReconciliationPacket:
    investigation = db.get(Investigation, proposal.investigation_id)
    call = (
        db.get(InvestigationToolCall, proposal.tool_call_id)
        if proposal.tool_call_id is not None else None
    )
    tool = db.get(AgentToolRegistration, proposal.tool_id)
    namespace = (proposal.tenant_id, proposal.region_id)
    if (
        investigation is None or call is None or tool is None
        or any((row.tenant_id, row.region_id) != namespace
               for row in (investigation, call, tool))
        or investigation.status not in {"escalated", "failed", "cancelled"}
        or proposal.status != "executing"
        or proposal.execution_started_at is None
        or call.status != "running" or call.started_at is None
        or call.investigation_id != investigation.id
        or call.tool_id != tool.id
        or call.arguments != proposal.arguments
        or tool.transport != "mcp" or tool.read_only
    ):
        raise ValueError("No unresolved bound MCP write is available for reconciliation")
    designated_lookup_tool_name = None
    version = db.get(ArtifactVersion, call.artifact_version_id) if call.artifact_version_id else None
    activation = (
        db.get(MCPToolActivation, call.artifact_activation_id)
        if call.artifact_activation_id else None
    )
    server = db.get(MCPServer, activation.server_id) if activation else None
    if (
        version is not None and activation is not None and server is not None
        and (version.tenant_id, version.region_id) == namespace
        and (activation.tenant_id, activation.region_id) == namespace
        and (server.tenant_id, server.region_id) == namespace
        and version.content_hash == call.artifact_content_hash
        and activation.contract_sha256 == call.artifact_activation_sha256
        and activation.artifact_version_id == version.id
        and activation.tool_registration_id == tool.id
        and isinstance(version.definition, dict)
    ):
        try:
            frozen_spec = GeneratedToolSpec.model_validate(version.definition["spec"])
        except (KeyError, TypeError, ValueError):
            pass
        else:
            if (
                not frozen_spec.read_only
                and frozen_spec.tool_name == tool.name == activation.tool_name
                and frozen_spec.mcp_tool_name == activation.mcp_tool_name
                and frozen_spec.mcp_server_name == server.name
            ):
                designated_lookup_tool_name = frozen_spec.outcome_lookup_tool_name
    # An old call may lack activation provenance. Do not infer it from today's
    # mutable Tool registry or claim that the provider acknowledged the write.
    return MCPWriteReconciliationPacket(
        proposal_id=proposal.id,
        investigation_id=investigation.id,
        tool_call_id=call.id,
        current_tool_name=tool.name,
        call_started_at=call.started_at,
        artifact_activation_id=call.artifact_activation_id,
        artifact_version_id=call.artifact_version_id,
        designated_lookup_tool_name=designated_lookup_tool_name,
        provider_lookup_key=call.id,
    )


def record_mcp_write_lookup_observation(
    db: Session,
    proposal_id: str,
    lookup_tool_call_id: str,
    reason: str,
    *,
    actor: PrincipalContext,
) -> MCPWriteReconciliationObservation:
    if not actor.permits("changes.approve"):
        raise PermissionError("Change approval permission is required")
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Reconciliation reason must contain 10-1000 characters")
    assert_no_inline_secrets(reason, "MCP write reconciliation reason")
    require_locking_transaction(db, purpose="MCP write reconciliation")
    proposal = db.scalar(
        select(AgentActionProposal).where(AgentActionProposal.id == proposal_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if proposal is None:
        raise LookupError("Action proposal not found")
    packet = mcp_write_reconciliation_packet(db, proposal)
    original = db.scalar(
        select(InvestigationToolCall).where(InvestigationToolCall.id == packet.tool_call_id)
        .with_for_update(read=True).execution_options(populate_existing=True)
    )
    lookup = db.scalar(
        select(InvestigationToolCall).where(InvestigationToolCall.id == lookup_tool_call_id)
        .with_for_update(read=True).execution_options(populate_existing=True)
    )
    lookup_tool = db.get(AgentToolRegistration, lookup.tool_id) if lookup else None
    lookup_investigation = db.get(Investigation, lookup.investigation_id) if lookup else None
    activation = (
        db.get(MCPToolActivation, lookup.artifact_activation_id)
        if lookup and lookup.artifact_activation_id else None
    )
    version = (
        db.get(ArtifactVersion, lookup.artifact_version_id)
        if lookup and lookup.artifact_version_id else None
    )
    namespace = (proposal.tenant_id, proposal.region_id)
    if (
        original is None or lookup is None or lookup_tool is None
        or lookup_investigation is None or activation is None or version is None
        or lookup.id == original.id
        or original.status != "running" or original.arguments != proposal.arguments
        or lookup.investigation_id == original.investigation_id
        or any((row.tenant_id, row.region_id) != namespace
               for row in (original, lookup, lookup_tool, lookup_investigation, activation, version))
        or lookup.status != "succeeded" or lookup.finished_at is None
        or lookup.started_at is None or lookup.result_hash is None
        or lookup.artifact_activation_id is None or lookup.artifact_version_id is None
        or activation.tool_registration_id != lookup_tool.id
        or activation.artifact_version_id != version.id
        or lookup.artifact_content_hash != version.content_hash
        or lookup.artifact_activation_sha256 != activation.contract_sha256
        or lookup_tool.transport != "mcp" or not lookup_tool.read_only
        or not isinstance(lookup.arguments, dict)
        or lookup.arguments.get("source_tool_call_id") != packet.tool_call_id
        or not isinstance(lookup.result, dict)
    ):
        raise ValueError("A separate, pinned, successful read-only MCP lookup is required")
    try:
        result = MCPWriteLookupResult.model_validate(lookup.result)
    except ValueError as exc:
        raise ValueError("MCP lookup result does not satisfy the reconciliation contract") from exc
    if result.source_tool_call_id != original.id:
        raise ValueError("MCP lookup result does not match the original Tool call")
    if result.provider_reference is not None and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", result.provider_reference
    ):
        raise ValueError("Provider lookup reference must be a bounded opaque identifier")
    assert_no_inline_secrets(
        {"provider_reference": result.provider_reference}, "MCP provider lookup reference"
    )
    observed_at = _utc(result.observed_at)
    if (
        observed_at < _utc(original.started_at)
        or observed_at < _utc(lookup.started_at) - timedelta(minutes=5)
        or observed_at > _utc(lookup.finished_at) + timedelta(minutes=5)
        or observed_at > utcnow() + timedelta(minutes=5)
    ):
        raise ValueError("MCP lookup observation time is outside the exact call window")
    existing = db.scalar(select(MCPWriteReconciliationObservation).where(
        MCPWriteReconciliationObservation.lookup_tool_call_id == lookup.id
    ))
    if existing is not None:
        if (
            existing.proposal_id == proposal.id
            and existing.original_tool_call_id == original.id
            and existing.lookup_result_hash == lookup.result_hash
            and existing.reason == reason.strip()
            and existing.provider_outcome == result.provider_outcome
            and existing.provider_reference == result.provider_reference
            and _utc(existing.observed_at) == observed_at
        ):
            return existing
        raise ValueError("MCP lookup Tool call is already bound to another observation")
    observation = MCPWriteReconciliationObservation(
        proposal_id=proposal.id,
        original_tool_call_id=original.id,
        lookup_tool_call_id=lookup.id,
        provider_outcome=result.provider_outcome,
        provider_reference=result.provider_reference,
        observed_at=observed_at,
        lookup_result_hash=lookup.result_hash,
        recorded_by_principal_id=actor.principal_id,
        recorded_by=actor.subject,
        reason=reason.strip(),
        created_at=utcnow(),
    )
    db.add(observation)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.write.reconciliation_observation.recorded",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="mcp_write_reconciliation_observation",
        entity_id=observation.id,
        details={
            "proposal_id": proposal.id,
            "original_tool_call_id": original.id,
            "lookup_tool_call_id": lookup.id,
            "provider_outcome_reported": result.provider_outcome,
            "original_action_completed": False,
        },
    )
    db.commit()
    db.refresh(observation)
    return observation


def list_mcp_write_lookup_observations(
    db: Session, proposal_id: str, *, limit: int = 100,
) -> list[MCPWriteReconciliationObservation]:
    return list(db.scalars(
        select(MCPWriteReconciliationObservation)
        .where(MCPWriteReconciliationObservation.proposal_id == proposal_id)
        .order_by(MCPWriteReconciliationObservation.created_at, MCPWriteReconciliationObservation.id)
        .limit(limit)
    ).all())


def review_mcp_write_lookup_observation(
    db: Session,
    proposal_id: str,
    observation_id: str,
    decision: str,
    reason: str,
    *,
    actor: PrincipalContext,
) -> MCPWriteReconciliationReview:
    if (
        actor.principal_type != "user"
        or actor.principal_id is None
        or not actor.permits("changes.approve")
    ):
        raise PermissionError("Authenticated change approver is required")
    if decision not in {"accept", "reject", "inconclusive"}:
        raise ValueError("Review decision must be accept, reject or inconclusive")
    if not 10 <= len(reason.strip()) <= 1000:
        raise ValueError("Review reason must contain 10-1000 characters")
    assert_no_inline_secrets(reason, "MCP lookup review reason")
    require_locking_transaction(db, purpose="MCP lookup independent review")
    proposal = db.scalar(
        select(AgentActionProposal).where(AgentActionProposal.id == proposal_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if proposal is None:
        raise LookupError("Action proposal not found")
    packet = mcp_write_reconciliation_packet(db, proposal)
    observation = db.scalar(
        select(MCPWriteReconciliationObservation).where(
            MCPWriteReconciliationObservation.id == observation_id,
            MCPWriteReconciliationObservation.proposal_id == proposal.id,
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )
    if observation is None:
        raise LookupError("Lookup observation not found")
    if (
        observation.recorded_by_principal_id is None
        or observation.recorded_by_principal_id == actor.principal_id
        or observation.recorded_by == actor.subject
    ):
        raise PermissionError("Reviewer must be independent of the evidence recorder")
    lookup = db.scalar(
        select(InvestigationToolCall).where(
            InvestigationToolCall.id == observation.lookup_tool_call_id
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )
    if (
        observation.original_tool_call_id != packet.tool_call_id
        or (observation.tenant_id, observation.region_id) != (proposal.tenant_id, proposal.region_id)
        or lookup is None
        or lookup.status != "succeeded"
        or not isinstance(lookup.arguments, dict)
        or lookup.arguments.get("source_tool_call_id") != packet.tool_call_id
        or lookup.result_hash != observation.lookup_result_hash
        or not isinstance(lookup.result, dict)
        or (lookup.tenant_id, lookup.region_id) != (proposal.tenant_id, proposal.region_id)
    ):
        raise ValueError("Lookup evidence no longer matches the unresolved write")
    try:
        lookup_result = MCPWriteLookupResult.model_validate(lookup.result)
    except ValueError as exc:
        raise ValueError("Lookup evidence no longer satisfies the result contract") from exc
    if (
        lookup_result.source_tool_call_id != packet.tool_call_id
        or lookup_result.provider_outcome != observation.provider_outcome
        or lookup_result.provider_reference != observation.provider_reference
        or _utc(lookup_result.observed_at) != _utc(observation.observed_at)
    ):
        raise ValueError("Lookup result has diverged from the immutable observation")
    if decision == "accept":
        original = db.get(InvestigationToolCall, packet.tool_call_id)
        if original is None or not _declared_outcome_lookup(db, original, lookup):
            raise ValueError("The frozen write Artifact does not designate this lookup Tool")
    existing = db.scalar(select(MCPWriteReconciliationReview).where(
        MCPWriteReconciliationReview.observation_id == observation.id
    ))
    if existing is not None:
        if (
            existing.proposal_id == proposal.id
            and existing.decision == decision
            and existing.reason == reason.strip()
            and existing.reviewed_by_principal_id == actor.principal_id
        ):
            return existing
        raise ValueError("Lookup observation has already been reviewed")
    review = MCPWriteReconciliationReview(
        proposal_id=proposal.id,
        observation_id=observation.id,
        decision=decision,
        reviewed_by_principal_id=actor.principal_id,
        reviewed_by=actor.subject,
        reason=reason.strip(),
        reviewed_at=utcnow(),
    )
    db.add(review)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.write.reconciliation_observation.reviewed",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="mcp_write_reconciliation_review",
        entity_id=review.id,
        details={
            "proposal_id": proposal.id,
            "observation_id": observation.id,
            "decision": decision,
            "provider_outcome_reported": observation.provider_outcome,
            "original_action_completed": False,
        },
    )
    db.commit()
    db.refresh(review)
    return review


def list_mcp_write_lookup_reviews(
    db: Session, proposal_id: str, *, limit: int = 100,
) -> list[MCPWriteReconciliationReview]:
    return list(db.scalars(
        select(MCPWriteReconciliationReview)
        .where(MCPWriteReconciliationReview.proposal_id == proposal_id)
        .order_by(MCPWriteReconciliationReview.reviewed_at, MCPWriteReconciliationReview.id)
        .limit(limit)
    ).all())


def mcp_write_reconciliation_summary(
    db: Session,
    proposal: AgentActionProposal,
    observations: list[MCPWriteReconciliationObservation],
    reviews: list[MCPWriteReconciliationReview],
) -> MCPWriteReconciliationSummary:
    packet = mcp_write_reconciliation_packet(db, proposal)
    namespace = (proposal.tenant_id, proposal.region_id)
    if len(observations) > 1000 or len(reviews) > 1000:
        raise ValueError("Provider evidence exceeds the bounded summary; escalate for manual review")
    visible = {
        row.id: row for row in observations
        if row.proposal_id == proposal.id
        and (row.tenant_id, row.region_id) == namespace
    }
    visible_reviews = [
        row for row in reviews
        if row.proposal_id == proposal.id
        and (row.tenant_id, row.region_id) == namespace
        and row.observation_id in visible
    ]
    accepted_reports = sorted({
        visible[row.observation_id].provider_outcome
        for row in visible_reviews if row.decision == "accept"
    })
    return MCPWriteReconciliationSummary(
        proposal_id=proposal.id,
        original_tool_call_id=packet.tool_call_id,
        observation_count=len(visible),
        reviewed_count=len(visible_reviews),
        accepted_provider_reports=accepted_reports,
        contradictory_determinate_reports=(
            "applied" in accepted_reports and "not_applied" in accepted_reports
        ),
    )


def qualify_declared_provider_lookup(
    db: Session,
    proposal: AgentActionProposal,
    observation_id: str,
    *,
    qualified_at: datetime | None = None,
) -> MCPDeclaredProviderLookupQualification:
    """Check a frozen correlation declaration, not the provider's live truth."""
    packet = mcp_write_reconciliation_packet(db, proposal)
    namespace = (proposal.tenant_id, proposal.region_id)
    observation = db.get(MCPWriteReconciliationObservation, observation_id)
    review = db.scalar(select(MCPWriteReconciliationReview).where(
        MCPWriteReconciliationReview.observation_id == observation_id,
        MCPWriteReconciliationReview.proposal_id == proposal.id,
    ))
    original = db.get(InvestigationToolCall, packet.tool_call_id)
    lookup = (
        db.get(InvestigationToolCall, observation.lookup_tool_call_id)
        if observation is not None else None
    )
    if (
        observation is None or review is None or original is None or lookup is None
        or observation.proposal_id != proposal.id
        or observation.original_tool_call_id != original.id
        or any((row.tenant_id, row.region_id) != namespace
               for row in (observation, review, original, lookup))
        or review.decision != "accept"
        or observation.recorded_by_principal_id is None
        or observation.recorded_by_principal_id == review.reviewed_by_principal_id
        or observation.recorded_by == review.reviewed_by
        or lookup.investigation_id == original.investigation_id
        or lookup.status != "succeeded"
        or not isinstance(lookup.arguments, dict)
        or lookup.arguments.get("source_tool_call_id") != original.id
        or lookup.started_at is None or lookup.finished_at is None
        or _utc(lookup.finished_at) < _utc(lookup.started_at)
        or lookup.result_hash != observation.lookup_result_hash
        or not isinstance(lookup.result, dict)
        or not _declared_outcome_lookup(db, original, lookup)
    ):
        raise ValueError("Accepted exact provider lookup evidence is required")
    write_version = db.get(ArtifactVersion, original.artifact_version_id)
    lookup_version = db.get(ArtifactVersion, lookup.artifact_version_id)
    try:
        write_spec = GeneratedToolSpec.model_validate(write_version.definition["spec"])
        lookup_spec = GeneratedToolSpec.model_validate(lookup_version.definition["spec"])
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Frozen provider lookup contracts are invalid") from exc
    contract = write_spec.outcome_lookup_correlation
    if contract is None or contract.tool_name != lookup_spec.tool_name:
        raise ValueError("The write has no frozen provider correlation contract")
    validate_instance(lookup.result, lookup_spec.output_schema, "provider lookup result")
    try:
        result = MCPWriteLookupResult.model_validate(lookup.result)
    except ValueError as exc:
        raise ValueError("Provider lookup result does not satisfy its contract") from exc
    observed_at = _utc(result.observed_at)
    now = _utc(qualified_at) if qualified_at is not None else utcnow()
    if (
        result.source_tool_call_id != original.id
        or result.provider_outcome != observation.provider_outcome
        or result.provider_reference != observation.provider_reference
        or observed_at != _utc(observation.observed_at)
        or observed_at < _utc(original.started_at) + timedelta(
            seconds=contract.consistency_window_seconds
        )
        or observed_at > now
        or now - observed_at > timedelta(seconds=contract.max_observation_age_seconds)
    ):
        raise ValueError("Provider lookup is not fresh, settled and bound to the original call")
    return MCPDeclaredProviderLookupQualification(
        proposal_id=proposal.id,
        observation_id=observation.id,
        lookup_tool_call_id=lookup.id,
        reported_provider_outcome=result.provider_outcome,
        provider_reference=result.provider_reference,
        observed_at=observed_at,
        consistency_window_seconds=contract.consistency_window_seconds,
        max_observation_age_seconds=contract.max_observation_age_seconds,
    )


def qualify_independent_mcp_verification(
    db: Session,
    proposal: AgentActionProposal,
    verification_tool_call_id: str,
    *,
    qualified_at: datetime | None = None,
) -> MCPIndependentVerificationQualification:
    """Preview exact external-state evidence without resolving the lost write."""
    packet = mcp_write_reconciliation_packet(db, proposal)
    original = db.get(InvestigationToolCall, packet.tool_call_id)
    evidence = _qualify_independent_external_state(
        db, proposal, original, verification_tool_call_id, qualified_at=qualified_at,
    )
    return MCPIndependentVerificationQualification(**vars(evidence))


@dataclass(frozen=True)
class IndependentMCPVerificationEvidence:
    proposal_id: str
    original_tool_call_id: str
    verification_tool_call_id: str
    verification_kind: str
    observed_target_state: str
    observed_at: datetime
    evidence_reference: str | None
    bound_value_count: int


def qualify_completed_mcp_verification(
    db: Session, proposal: AgentActionProposal, verification_tool_call_id: str, *,
    qualified_at: datetime | None = None,
) -> IndependentMCPVerificationEvidence:
    """Verify external state of a completed approved write, without re-executing it.

    Keep this separate from lost-write reconciliation: successful execution
    does not become an unknown write, and neither helper grants replay rights.
    """
    original = db.get(InvestigationToolCall, proposal.tool_call_id) if proposal.tool_call_id else None
    investigation = db.get(Investigation, proposal.investigation_id)
    tool = db.get(AgentToolRegistration, proposal.tool_id)
    namespace = (proposal.tenant_id, proposal.region_id)
    if (
        original is None or investigation is None or tool is None
        or any((row.tenant_id, row.region_id) != namespace for row in (original, investigation, tool))
        or proposal.status != "succeeded" or original.status != "succeeded"
        or not proposal.approved_by_principal_id or not proposal.approved_by
        or proposal.decided_at is None or proposal.execution_started_at is None
        or proposal.execution_finished_at is None or original.started_at is None
        or original.finished_at is None or proposal.error or original.error
        or original.investigation_id != proposal.investigation_id
        or original.tool_id != proposal.tool_id or original.arguments != proposal.arguments
        or tool.transport != "mcp" or tool.read_only
        or not isinstance(original.result, dict) or not original.result_hash
        or original.result_hash != _hash_document(original.result)
        or proposal.result_hash != original.result_hash
    ):
        raise ValueError("A completed, approved, exact MCP write is required")
    if not (_utc(proposal.decided_at) <= _utc(proposal.execution_started_at)
            <= _utc(original.started_at) <= _utc(original.finished_at)
            <= _utc(proposal.execution_finished_at)):
        raise ValueError("Completed MCP write timestamps are inconsistent")
    return _qualify_independent_external_state(
        db, proposal, original, verification_tool_call_id, qualified_at=qualified_at,
    )


def _qualify_independent_external_state(
    db: Session, proposal: AgentActionProposal, original: InvestigationToolCall | None,
    verification_tool_call_id: str, *, qualified_at: datetime | None,
) -> IndependentMCPVerificationEvidence:
    verification = db.get(InvestigationToolCall, verification_tool_call_id)
    verification_tool = db.get(AgentToolRegistration, verification.tool_id) if verification else None
    verification_investigation = db.get(Investigation, verification.investigation_id) if verification else None
    namespace = (proposal.tenant_id, proposal.region_id)
    if (
        original is None or verification is None or verification_tool is None
        or verification_investigation is None
        or verification.id == original.id
        or verification.investigation_id == original.investigation_id
        or any((row.tenant_id, row.region_id) != namespace for row in (
            original, verification, verification_tool, verification_investigation,
        ))
        or verification.status != "succeeded" or verification.started_at is None
        or verification.finished_at is None or verification.result_hash is None
        or _utc(verification.finished_at) < _utc(verification.started_at)
        or verification_tool.transport != "mcp" or not verification_tool.read_only
        or not isinstance(verification.arguments, dict)
        or verification.arguments.get("source_tool_call_id") != original.id
        or not isinstance(verification.result, dict)
        or verification.result_hash != _hash_document(verification.result)
    ):
        raise ValueError("A separate successful, exact read-only verification Tool call is required")
    if not all((
        original.artifact_activation_id, original.artifact_version_id,
        original.artifact_content_hash, original.artifact_activation_sha256,
        verification.artifact_activation_id, verification.artifact_version_id,
        verification.artifact_content_hash, verification.artifact_activation_sha256,
    )):
        raise ValueError("Both Tool calls need frozen Artifact and activation provenance")
    write_activation = db.get(MCPToolActivation, original.artifact_activation_id)
    write_version = db.get(ArtifactVersion, original.artifact_version_id)
    verification_activation = db.get(MCPToolActivation, verification.artifact_activation_id)
    verification_version = db.get(ArtifactVersion, verification.artifact_version_id)
    write_server = db.get(MCPServer, write_activation.server_id) if write_activation else None
    verification_server = (
        db.get(MCPServer, verification_activation.server_id) if verification_activation else None
    )
    if (
        write_activation is None or write_version is None or write_server is None
        or verification_activation is None or verification_version is None
        or verification_server is None
        or any((row.tenant_id, row.region_id) != namespace for row in (
            write_activation, write_version, write_server,
            verification_activation, verification_version, verification_server,
        ))
        or write_activation.server_id == verification_activation.server_id
        or write_activation.tool_registration_id != original.tool_id
        or verification_activation.tool_registration_id != verification.tool_id
        or write_activation.artifact_version_id != write_version.id
        or verification_activation.artifact_version_id != verification_version.id
        or original.artifact_content_hash != write_version.content_hash
        or verification.artifact_content_hash != verification_version.content_hash
        or original.artifact_activation_sha256 != write_activation.contract_sha256
        or verification.artifact_activation_sha256 != verification_activation.contract_sha256
    ):
        raise ValueError("Verification must use a separately pinned MCP server")
    try:
        write_spec = GeneratedToolSpec.model_validate(write_version.definition["spec"])
        verification_spec = GeneratedToolSpec.model_validate(verification_version.definition["spec"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Frozen Tool verification contracts are invalid") from exc
    contract = write_spec.independent_verification
    if (
        contract is None or write_spec.read_only or not verification_spec.read_only
        or contract.tool_name != verification_spec.tool_name
        or write_spec.tool_name != write_activation.tool_name
        or verification_spec.tool_name != verification_activation.tool_name
        or verification_tool.name != verification_spec.tool_name
        or write_spec.mcp_tool_name != write_activation.mcp_tool_name
        or verification_spec.mcp_tool_name != verification_activation.mcp_tool_name
        or write_spec.mcp_server_name != write_server.name
        or verification_spec.mcp_server_name != verification_server.name
    ):
        raise ValueError("The frozen write Artifact does not designate this independent verifier")
    validate_instance(verification.result, verification_spec.output_schema,
                      "independent verification result")
    try:
        result = MCPIndependentVerificationResult.model_validate(verification.result)
    except ValueError as exc:
        raise ValueError("Independent verification result does not satisfy its contract") from exc
    if result.source_tool_call_id != original.id or result.verification_kind != contract.kind:
        raise ValueError("Independent verification does not bind to this write and kind")
    assert_no_inline_secrets(result.model_dump(mode="json"), "independent verification result")
    observed_at = _utc(result.observed_at)
    qualification_time = _utc(qualified_at) if qualified_at is not None else utcnow()
    if (
        observed_at < _utc(original.started_at)
        or observed_at < _utc(verification.started_at) - timedelta(minutes=5)
        or observed_at > _utc(verification.finished_at) + timedelta(minutes=5)
        or observed_at > qualification_time + timedelta(minutes=5)
        or qualification_time - observed_at > timedelta(seconds=contract.max_age_seconds)
    ):
        raise ValueError("Independent verification is not fresh and causally bound")
    for binding in contract.bindings:
        expected = proposal.arguments
        for part in binding.original_argument_path.split("."):
            if not isinstance(expected, dict) or part not in expected:
                raise ValueError("Frozen verification target argument is absent")
            expected = expected[part]
        observed = result.values.get(binding.observed_value_key)
        valid = {
            "string": lambda value: type(value) is str,
            "boolean": lambda value: type(value) is bool,
            "integer": lambda value: type(value) is int,
            "number": lambda value: type(value) in {int, float},
        }[binding.value_type]
        if not valid(expected) or not valid(observed) or expected != observed:
            raise ValueError("Independent verification target differs from the approved write")
    return IndependentMCPVerificationEvidence(
        proposal_id=proposal.id,
        original_tool_call_id=original.id,
        verification_tool_call_id=verification.id,
        verification_kind=result.verification_kind,
        observed_target_state=result.observed_target_state,
        observed_at=observed_at,
        evidence_reference=result.evidence_reference,
        bound_value_count=len(contract.bindings),
    )


def record_independent_mcp_observation(
    db: Session,
    proposal_id: str,
    verification_tool_call_id: str,
    reason: str,
    *,
    actor: PrincipalContext,
) -> MCPWriteIndependentObservation:
    """Retain a qualified observation without deciding the original write."""
    if (
        actor.principal_type != "user" or actor.principal_id is None
        or not actor.permits("changes.approve")
    ):
        raise PermissionError("Authenticated change approver is required")
    reason = reason.strip()
    if not 10 <= len(reason) <= 1000:
        raise ValueError("Independent verification reason must contain 10-1000 characters")
    assert_no_inline_secrets(reason, "independent verification reason")
    require_locking_transaction(db, purpose="independent MCP verification observation")
    proposal = db.scalar(
        select(AgentActionProposal).where(AgentActionProposal.id == proposal_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if proposal is None:
        raise LookupError("Action proposal not found")
    verification = db.scalar(
        select(InvestigationToolCall).where(
            InvestigationToolCall.id == verification_tool_call_id
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )
    if verification is None:
        raise LookupError("Verification Tool call not found")
    existing = db.scalar(select(MCPWriteIndependentObservation).where(
        MCPWriteIndependentObservation.verification_tool_call_id == verification.id
    ))
    if existing is not None and _utc(existing.created_at) > utcnow() + timedelta(minutes=5):
        raise ValueError("Stored independent observation time is invalid")
    qualified = qualify_independent_mcp_verification(
        db, proposal, verification.id,
        qualified_at=existing.created_at if existing is not None else None,
    )
    if existing is not None:
        if (
            existing.proposal_id == proposal.id
            and existing.original_tool_call_id == qualified.original_tool_call_id
            and existing.verification_result_hash == verification.result_hash
            and existing.verification_kind == qualified.verification_kind
            and existing.observed_target_state == qualified.observed_target_state
            and _utc(existing.observed_at) == _utc(qualified.observed_at)
            and existing.evidence_reference == qualified.evidence_reference
            and existing.bound_value_count == qualified.bound_value_count
            and existing.recorded_by_principal_id == actor.principal_id
            and existing.reason == reason
        ):
            return existing
        raise ValueError("Verifier Tool call is already bound to another observation")
    observation = MCPWriteIndependentObservation(
        proposal_id=proposal.id,
        original_tool_call_id=qualified.original_tool_call_id,
        verification_tool_call_id=verification.id,
        verification_kind=qualified.verification_kind,
        observed_target_state=qualified.observed_target_state,
        observed_at=qualified.observed_at,
        evidence_reference=qualified.evidence_reference,
        bound_value_count=qualified.bound_value_count,
        verification_result_hash=verification.result_hash,
        recorded_by_principal_id=actor.principal_id,
        recorded_by=actor.subject,
        reason=reason,
        created_at=utcnow(),
    )
    db.add(observation)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.write.independent_observation.recorded",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="mcp_write_independent_observation",
        entity_id=observation.id,
        details={
            "proposal_id": proposal.id,
            "original_tool_call_id": qualified.original_tool_call_id,
            "verification_tool_call_id": verification.id,
            "verification_kind": qualified.verification_kind,
            "observed_target_state": qualified.observed_target_state,
            "original_action_completed": False,
            "delivery_verified": False,
        },
    )
    db.commit()
    db.refresh(observation)
    return observation


def list_independent_mcp_observations(
    db: Session, proposal_id: str, *, limit: int = 100,
) -> list[MCPWriteIndependentObservation]:
    return list(db.scalars(
        select(MCPWriteIndependentObservation)
        .where(MCPWriteIndependentObservation.proposal_id == proposal_id)
        .order_by(MCPWriteIndependentObservation.created_at, MCPWriteIndependentObservation.id)
        .limit(limit)
    ).all())


def review_independent_mcp_observation(
    db: Session,
    proposal_id: str,
    observation_id: str,
    decision: str,
    reason: str,
    *,
    actor: PrincipalContext,
) -> MCPWriteIndependentReview:
    """Review one retained observation without deciding the original action."""
    if (
        actor.principal_type != "user" or actor.principal_id is None
        or not actor.permits("changes.approve")
    ):
        raise PermissionError("Authenticated change approver is required")
    if decision not in {"accept", "reject", "inconclusive"}:
        raise ValueError("Review decision must be accept, reject or inconclusive")
    reason = reason.strip()
    if not 10 <= len(reason) <= 1000:
        raise ValueError("Independent verification review reason must contain 10-1000 characters")
    assert_no_inline_secrets(reason, "independent verification review reason")
    require_locking_transaction(db, purpose="independent MCP verification review")
    proposal = db.scalar(
        select(AgentActionProposal).where(AgentActionProposal.id == proposal_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if proposal is None:
        raise LookupError("Action proposal not found")
    packet = mcp_write_reconciliation_packet(db, proposal)
    observation = db.scalar(
        select(MCPWriteIndependentObservation).where(
            MCPWriteIndependentObservation.id == observation_id,
            MCPWriteIndependentObservation.proposal_id == proposal.id,
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )
    if observation is None:
        raise LookupError("Independent observation not found")
    if (
        observation.recorded_by_principal_id == actor.principal_id
        or observation.recorded_by == actor.subject
    ):
        raise PermissionError("Reviewer must be independent of the evidence recorder")
    if (
        observation.original_tool_call_id != packet.tool_call_id
        or (observation.tenant_id, observation.region_id)
        != (proposal.tenant_id, proposal.region_id)
        or _utc(observation.created_at) > utcnow() + timedelta(minutes=5)
    ):
        raise ValueError("Independent observation does not match the unresolved write")
    verification = db.scalar(
        select(InvestigationToolCall).where(
            InvestigationToolCall.id == observation.verification_tool_call_id
        ).with_for_update(read=True).execution_options(populate_existing=True)
    )
    if verification is None or verification.result_hash != observation.verification_result_hash:
        raise ValueError("Verifier Tool result has diverged from the retained observation")
    qualified = qualify_independent_mcp_verification(
        db, proposal, verification.id, qualified_at=observation.created_at,
    )
    if (
        qualified.original_tool_call_id != observation.original_tool_call_id
        or qualified.verification_kind != observation.verification_kind
        or qualified.observed_target_state != observation.observed_target_state
        or _utc(qualified.observed_at) != _utc(observation.observed_at)
        or qualified.evidence_reference != observation.evidence_reference
        or qualified.bound_value_count != observation.bound_value_count
    ):
        raise ValueError("Verifier result no longer matches the retained observation")
    existing = db.scalar(select(MCPWriteIndependentReview).where(
        MCPWriteIndependentReview.observation_id == observation.id
    ))
    if existing is not None:
        if (
            existing.proposal_id == proposal.id
            and existing.decision == decision
            and existing.reason == reason
            and existing.reviewed_by_principal_id == actor.principal_id
        ):
            return existing
        raise ValueError("Independent observation has already been reviewed")
    review = MCPWriteIndependentReview(
        proposal_id=proposal.id,
        observation_id=observation.id,
        decision=decision,
        reviewed_by_principal_id=actor.principal_id,
        reviewed_by=actor.subject,
        reason=reason,
        reviewed_at=utcnow(),
    )
    db.add(review)
    db.flush()
    record_audit_event(
        db,
        event_type="mcp.write.independent_observation.reviewed",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="mcp_write_independent_review",
        entity_id=review.id,
        details={
            "proposal_id": proposal.id,
            "observation_id": observation.id,
            "decision": decision,
            "original_action_completed": False,
            "delivery_verified": False,
        },
    )
    db.commit()
    db.refresh(review)
    return review


def list_independent_mcp_reviews(
    db: Session, proposal_id: str, *, limit: int = 100,
) -> list[MCPWriteIndependentReview]:
    return list(db.scalars(
        select(MCPWriteIndependentReview)
        .where(MCPWriteIndependentReview.proposal_id == proposal_id)
        .order_by(MCPWriteIndependentReview.reviewed_at, MCPWriteIndependentReview.id)
        .limit(limit)
    ).all())


def summarize_independent_mcp_evidence(
    proposal_id: str,
    observations: list[MCPWriteIndependentObservation],
    reviews: list[MCPWriteIndependentReview],
) -> MCPIndependentEvidenceSummary:
    """Summarize only caller-visible rows; never infer a write outcome."""
    if len(observations) > 1000 or len(reviews) > 1000:
        raise ValueError("Independent evidence exceeds the bounded summary; escalate for manual review")
    visible = {row.id: row for row in observations if row.proposal_id == proposal_id}
    relevant_reviews = [
        row for row in reviews
        if row.proposal_id == proposal_id and row.observation_id in visible
    ]
    accepted = [visible[row.observation_id] for row in relevant_reviews if row.decision == "accept"]
    targets = sorted({
        row.observed_target_state for row in accepted if row.verification_kind == "target_state"
    })
    recipients = sorted({
        row.observed_target_state for row in accepted if row.verification_kind == "recipient_receipt"
    })
    return MCPIndependentEvidenceSummary(
        proposal_id=proposal_id,
        observation_count=len(visible),
        reviewed_count=len(relevant_reviews),
        accepted_target_states=targets,
        accepted_recipient_receipt_states=recipients,
        divergent_determinate_target_states={"present", "absent"}.issubset(targets),
        divergent_determinate_recipient_receipts={"present", "absent"}.issubset(recipients),
    )


@dataclass(frozen=True)
class MCPWriteEvidenceSnapshot:
    """Complete bounded rows for one unknown write, never a disposition."""

    proposal: AgentActionProposal
    packet: MCPWriteReconciliationPacket
    provider_observations: tuple[MCPWriteReconciliationObservation, ...]
    provider_reviews: tuple[MCPWriteReconciliationReview, ...]
    independent_observations: tuple[MCPWriteIndependentObservation, ...]
    independent_reviews: tuple[MCPWriteIndependentReview, ...]
    evidence_investigation_ids: tuple[str, ...]
    native_locking: bool


def load_complete_mcp_write_evidence(
    db: Session,
    proposal_id: str,
) -> MCPWriteEvidenceSnapshot:
    """Lock the parent, then refuse truncated or inconsistent evidence sets.

    PostgreSQL's proposal-row FOR UPDATE lock and each evidence row's proposal
    foreign key serialize inserts with this read. SQLite is only a local preview;
    callers must not use it for a final decision.
    """
    require_locking_transaction(db, purpose="MCP write disposition evidence")
    proposal = db.scalar(
        select(AgentActionProposal).where(AgentActionProposal.id == proposal_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if proposal is None:
        raise LookupError("Action proposal not found")
    packet = mcp_write_reconciliation_packet(db, proposal)
    families = (
        (MCPWriteReconciliationObservation, "provider observations"),
        (MCPWriteReconciliationReview, "provider reviews"),
        (MCPWriteIndependentObservation, "independent observations"),
        (MCPWriteIndependentReview, "independent reviews"),
    )
    groups = []
    for model, label in families:
        rows = tuple(db.scalars(
            select(model).where(model.proposal_id == proposal.id)
            .order_by(model.id).limit(1001)
        ).all())
        if len(rows) > 1000:
            raise ValueError(f"MCP {label} exceed the complete review bound")
        groups.append(rows)
    provider_observations, provider_reviews, independent_observations, independent_reviews = groups
    namespace = (proposal.tenant_id, proposal.region_id)
    investigations = set()
    for observations, call_field in (
        (provider_observations, "lookup_tool_call_id"),
        (independent_observations, "verification_tool_call_id"),
    ):
        for row in observations:
            if (
                row.proposal_id != proposal.id
                or row.original_tool_call_id != packet.tool_call_id
                or (row.tenant_id, row.region_id) != namespace
            ):
                raise ValueError("MCP evidence is not bound to the unresolved write")
            call = db.get(InvestigationToolCall, getattr(row, call_field))
            investigation = db.get(Investigation, call.investigation_id) if call else None
            if (
                call is None or investigation is None
                or call.investigation_id == proposal.investigation_id
                or (call.tenant_id, call.region_id) != namespace
                or (investigation.tenant_id, investigation.region_id) != namespace
            ):
                raise ValueError("MCP evidence has no separate scoped Investigation")
            investigations.add(investigation.id)
    for reviews, observations in (
        (provider_reviews, provider_observations),
        (independent_reviews, independent_observations),
    ):
        observation_ids = {row.id for row in observations}
        for row in reviews:
            if (
                row.proposal_id != proposal.id
                or (row.tenant_id, row.region_id) != namespace
                or row.observation_id not in observation_ids
            ):
                raise ValueError("MCP review is not bound to the complete evidence set")
    return MCPWriteEvidenceSnapshot(
        proposal=proposal,
        packet=packet,
        provider_observations=provider_observations,
        provider_reviews=provider_reviews,
        independent_observations=independent_observations,
        independent_reviews=independent_reviews,
        evidence_investigation_ids=tuple(sorted(investigations)),
        native_locking=db.get_bind().dialect.name == "postgresql",
    )


def assess_mcp_write_evidence_contracts(
    db: Session,
    snapshot: MCPWriteEvidenceSnapshot,
    *,
    checked_at: datetime | None = None,
) -> MCPDispositionContractQualification:
    """Requalify accepted rows at one time without deciding the original write.

    The caller must have loaded the complete set and authorized every separate
    Investigation in the same transaction. Invalid accepted rows remain visible
    in the snapshot, but cannot silently count as current contract evidence.
    """
    now = _utc(checked_at) if checked_at is not None else utcnow()
    provider = {row.id: row for row in snapshot.provider_observations}
    independent = {row.id: row for row in snapshot.independent_observations}
    accepted_provider = sorted(
        (row for row in snapshot.provider_reviews if row.decision == "accept"),
        key=lambda row: row.observation_id,
    )
    accepted_independent = sorted(
        (row for row in snapshot.independent_reviews if row.decision == "accept"),
        key=lambda row: row.observation_id,
    )
    bad_provider: list[str] = []
    for review in accepted_provider:
        observation = provider.get(review.observation_id)
        try:
            if observation is None:
                raise ValueError("Accepted provider observation is absent")
            qualify_declared_provider_lookup(
                db, snapshot.proposal, observation.id, qualified_at=now,
            )
        except ValueError:
            bad_provider.append(review.observation_id)

    bad_independent: list[str] = []
    for review in accepted_independent:
        observation = independent.get(review.observation_id)
        try:
            if (
                observation is None
                or observation.recorded_by_principal_id is None
                or observation.recorded_by_principal_id == review.reviewed_by_principal_id
                or observation.recorded_by == review.reviewed_by
            ):
                raise ValueError("Independent evidence review is not separate")
            qualified = qualify_independent_mcp_verification(
                db, snapshot.proposal, observation.verification_tool_call_id,
                qualified_at=now,
            )
            call = db.get(InvestigationToolCall, observation.verification_tool_call_id)
            if (
                call is None
                or call.result_hash != observation.verification_result_hash
                or qualified.original_tool_call_id != snapshot.packet.tool_call_id
                or qualified.verification_kind != observation.verification_kind
                or qualified.observed_target_state != observation.observed_target_state
                or _utc(qualified.observed_at) != _utc(observation.observed_at)
                or qualified.evidence_reference != observation.evidence_reference
                or qualified.bound_value_count != observation.bound_value_count
            ):
                raise ValueError("Retained independent observation no longer qualifies")
        except ValueError:
            bad_independent.append(review.observation_id)

    return MCPDispositionContractQualification(
        checked_at=now,
        accepted_provider_count=len(accepted_provider),
        contract_qualified_provider_count=len(accepted_provider) - len(bad_provider),
        unqualified_provider_observation_ids=bad_provider,
        accepted_independent_count=len(accepted_independent),
        contract_qualified_independent_count=len(accepted_independent) - len(bad_independent),
        unqualified_independent_observation_ids=bad_independent,
    )


def make_mcp_write_evidence_manifest(
    db: Session,
    snapshot: MCPWriteEvidenceSnapshot,
) -> MCPDispositionEvidenceManifest:
    """Retain exact bounded evidence references without free text or new hashes."""
    original = db.get(InvestigationToolCall, snapshot.packet.tool_call_id)
    if (
        original is None
        or original.id != snapshot.proposal.tool_call_id
        or (original.tenant_id, original.region_id)
        != (snapshot.proposal.tenant_id, snapshot.proposal.region_id)
    ):
        raise ValueError("Original MCP write is not bound to the evidence manifest")
    provider_reviews = {row.observation_id: row for row in snapshot.provider_reviews}
    independent_reviews = {row.observation_id: row for row in snapshot.independent_reviews}
    provider_ids = {row.id for row in snapshot.provider_observations}
    independent_ids = {row.id for row in snapshot.independent_observations}
    if (
        any(len(group) > 1000 for group in (
            snapshot.provider_observations, snapshot.provider_reviews,
            snapshot.independent_observations, snapshot.independent_reviews,
        ))
        or len(provider_ids) != len(snapshot.provider_observations)
        or len(independent_ids) != len(snapshot.independent_observations)
        or len(provider_reviews) != len(snapshot.provider_reviews)
        or len(independent_reviews) != len(snapshot.independent_reviews)
        or not set(provider_reviews).issubset(provider_ids)
        or not set(independent_reviews).issubset(independent_ids)
    ):
        raise ValueError("MCP evidence manifest is incomplete or duplicated")
    provider = []
    for row in sorted(snapshot.provider_observations, key=lambda item: item.id):
        review = provider_reviews.get(row.id)
        provider.append(MCPDispositionProviderEvidenceRef(
            observation_id=row.id,
            lookup_tool_call_id=row.lookup_tool_call_id,
            lookup_result_hash=row.lookup_result_hash,
            provider_outcome=row.provider_outcome,
            observed_at=row.observed_at,
            recorded_at=row.created_at,
            recorded_by_principal_id=row.recorded_by_principal_id,
            review_id=review.id if review else None,
            review_decision=review.decision if review else None,
            reviewed_by_principal_id=review.reviewed_by_principal_id if review else None,
            reviewed_at=review.reviewed_at if review else None,
        ))
    independent = []
    for row in sorted(snapshot.independent_observations, key=lambda item: item.id):
        review = independent_reviews.get(row.id)
        independent.append(MCPDispositionIndependentEvidenceRef(
            observation_id=row.id,
            verification_tool_call_id=row.verification_tool_call_id,
            verification_result_hash=row.verification_result_hash,
            verification_kind=row.verification_kind,
            observed_target_state=row.observed_target_state,
            observed_at=row.observed_at,
            recorded_at=row.created_at,
            recorded_by_principal_id=row.recorded_by_principal_id,
            review_id=review.id if review else None,
            review_decision=review.decision if review else None,
            reviewed_by_principal_id=review.reviewed_by_principal_id if review else None,
            reviewed_at=review.reviewed_at if review else None,
        ))
    return MCPDispositionEvidenceManifest(
        proposal_id=snapshot.proposal.id,
        original_tool_call_id=original.id,
        plan_hash=snapshot.proposal.plan_hash,
        artifact_activation_id=original.artifact_activation_id,
        artifact_version_id=original.artifact_version_id,
        artifact_content_hash=original.artifact_content_hash,
        artifact_activation_sha256=original.artifact_activation_sha256,
        evidence_investigation_ids=sorted(snapshot.evidence_investigation_ids),
        provider_observations=provider,
        independent_observations=independent,
    )
