from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import InvestigationState
from ..collector_schemas import ArtifactCreate
from ..models import (
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationTopologyProposal,
    InvestigationTopologyProposalEvidence,
    Situation,
    utcnow,
)
from ..studio_schemas import GeneratedTopologySpec
from ..topology_proposal_schemas import (
    TOPOLOGY_PROPOSAL_CONTRACT,
    InvestigationTopologyProposalOutput,
    InvestigationTopologyProposalRead,
    TopologyProposalEvidenceRead,
)
from .agent_authorization import investigation_principal
from .audit import record_audit_event
from .collectors import (
    create_artifact,
    publish_artifact_version,
    validate_artifact_version,
)
from .situations import append_situation_event
from .topology_views import (
    topology_artifact_documents,
    validate_topology_artifact_contract,
)


def topology_proposal_query():
    return select(InvestigationTopologyProposal).options(
        selectinload(InvestigationTopologyProposal.evidence_links).selectinload(
            InvestigationTopologyProposalEvidence.evidence
        )
    )


def get_topology_proposal(
    db: Session,
    proposal_id: str,
) -> InvestigationTopologyProposal:
    proposal = db.scalar(
        topology_proposal_query().where(
            InvestigationTopologyProposal.id == proposal_id
        )
    )
    if proposal is None:
        raise LookupError("Topology proposal not found")
    return proposal


def topology_proposal_to_read(
    proposal: InvestigationTopologyProposal,
) -> InvestigationTopologyProposalRead:
    return InvestigationTopologyProposalRead(
        id=proposal.id,
        investigation_id=proposal.investigation_id,
        checkpoint_id=proposal.checkpoint_id,
        contract_version=proposal.contract_version,
        status=proposal.status,
        rationale=proposal.rationale,
        spec=proposal.spec,
        validation_report=proposal.validation_report,
        uncertainty=list(proposal.uncertainty or []),
        authorization_scope=dict(proposal.authorization_scope or {}),
        source_model_id=proposal.source_model_id,
        created_by=proposal.created_by,
        reviewed_by=proposal.reviewed_by,
        review_reason=proposal.review_reason,
        reviewed_at=proposal.reviewed_at,
        artifact_id=proposal.artifact_id,
        artifact_version_id=proposal.artifact_version_id,
        evidence=[
            TopologyProposalEvidenceRead(
                evidence_reference_id=link.evidence.id,
                evidence_type=link.evidence.evidence_type,
                evidence_id=link.evidence.evidence_id,
                summary=link.evidence.summary,
                observed_at=link.evidence.observed_at,
            )
            for link in proposal.evidence_links
        ],
        created_at=proposal.created_at,
        updated_at=proposal.updated_at,
    )


def sync_investigation_topology_proposal(
    db: Session,
    investigation: Investigation,
    checkpoint: InvestigationCheckpoint,
    state: InvestigationState,
    *,
    actor: str,
) -> None:
    if state.status != "completed":
        return
    if state.scope.get("requested_output_contract") != TOPOLOGY_PROPOSAL_CONTRACT:
        return
    document = state.structured_output
    if not isinstance(document, dict):
        raise ValueError(
            "Completed topology Investigation requires structured_output"
        )
    proposal_output = InvestigationTopologyProposalOutput.model_validate(document)
    requested_evidence_ids = set(proposal_output.supporting_evidence_ids)
    if not requested_evidence_ids <= set(state.evidence_ids):
        raise ValueError(
            "Topology proposal evidence IDs must be present in checkpoint evidence_ids"
        )
    evidence = list(
        db.scalars(
            select(InvestigationEvidence).where(
                InvestigationEvidence.id.in_(requested_evidence_ids),
                InvestigationEvidence.investigation_id == investigation.id,
            )
        ).all()
    )
    evidence_by_id = {item.id: item for item in evidence}
    if set(evidence_by_id) != requested_evidence_ids:
        raise ValueError(
            "Topology proposal evidence must belong to the same Investigation"
        )

    existing = db.scalar(
        select(InvestigationTopologyProposal).where(
            InvestigationTopologyProposal.investigation_id == investigation.id
        )
    )
    if existing is not None:
        if existing.checkpoint_id == checkpoint.id:
            return
        raise ValueError("Investigation already has a topology proposal")

    definition, implementation, tests = topology_artifact_documents(
        proposal_output.spec
    )
    validation_report = validate_topology_artifact_contract(
        db,
        definition,
        implementation,
        tests,
        principal=investigation_principal(investigation),
    )
    proposal = InvestigationTopologyProposal(
        investigation_id=investigation.id,
        checkpoint_id=checkpoint.id,
        contract_version=proposal_output.contract,
        status="proposed",
        rationale=proposal_output.rationale,
        spec=proposal_output.spec.model_dump(mode="json"),
        validation_report=validation_report,
        uncertainty=proposal_output.uncertainty,
        authorization_scope=dict(investigation.authorization_scope or {}),
        source_model_id=investigation.model_id,
        created_by=actor,
    )
    db.add(proposal)
    db.flush()
    for evidence_id in proposal_output.supporting_evidence_ids:
        db.add(
            InvestigationTopologyProposalEvidence(
                proposal_id=proposal.id,
                investigation_evidence_id=evidence_by_id[evidence_id].id,
            )
        )
    if investigation.situation_id is not None:
        situation = db.get(Situation, investigation.situation_id)
        if situation is not None:
            append_situation_event(
                db,
                situation,
                event_type="topology.proposal_created",
                actor=actor,
                details={
                    "proposal_id": proposal.id,
                    "investigation_id": investigation.id,
                    "artifact_name": proposal_output.spec.artifact_name,
                },
            )
    preview = validation_report["preview"]
    record_audit_event(
        db,
        event_type="investigation.topology_proposal.created",
        actor_type="agent",
        actor_id=actor,
        entity_type="investigation_topology_proposal",
        entity_id=proposal.id,
        details={
            "investigation_id": investigation.id,
            "checkpoint_id": checkpoint.id,
            "artifact_name": proposal_output.spec.artifact_name,
            "evidence_count": len(evidence),
            "preview_node_count": preview["node_count"],
            "preview_edge_count": preview["edge_count"],
        },
    )


def _artifact_payload(
    proposal: InvestigationTopologyProposal,
    spec: GeneratedTopologySpec,
    *,
    actor: str,
) -> ArtifactCreate:
    definition, implementation, tests = topology_artifact_documents(spec)
    return ArtifactCreate.model_validate(
        {
            "name": spec.artifact_name,
            "kind": "topology",
            "description": spec.description,
            "owner": actor,
            "labels": {
                "generated": True,
                "source": "investigation_topology_proposal",
                "investigation_id": proposal.investigation_id,
                "topology_proposal_id": proposal.id,
                "format": "icheck.topology/v1",
            },
            "initial_version": {
                "definition": definition,
                "implementation": implementation,
                "tests": tests,
                "created_by": actor,
            },
        }
    )


def publish_topology_proposal(
    db: Session,
    proposal: InvestigationTopologyProposal,
    *,
    actor: str,
    reason: str,
) -> InvestigationTopologyProposal:
    if proposal.status == "published":
        return get_topology_proposal(db, proposal.id)
    if proposal.status != "proposed":
        raise ValueError("Only a proposed topology view can be published")
    spec = GeneratedTopologySpec.model_validate(proposal.spec)
    try:
        artifact = create_artifact(
            db,
            _artifact_payload(proposal, spec, actor=actor),
            commit=False,
        )
        version = max(artifact.versions, key=lambda item: item.version)
        validate_artifact_version(db, version, actor, commit=False)
        publish_artifact_version(db, version, actor, commit=False)
        proposal.status = "published"
        proposal.reviewed_by = actor
        proposal.review_reason = reason
        proposal.reviewed_at = utcnow()
        proposal.artifact_id = artifact.id
        proposal.artifact_version_id = version.id
        proposal.updated_at = utcnow()
        record_audit_event(
            db,
            event_type="investigation.topology_proposal.published",
            actor_type="user",
            actor_id=actor,
            entity_type="investigation_topology_proposal",
            entity_id=proposal.id,
            details={
                "investigation_id": proposal.investigation_id,
                "artifact_id": artifact.id,
                "artifact_version_id": version.id,
                "reason": reason,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return get_topology_proposal(db, proposal.id)


def reject_topology_proposal(
    db: Session,
    proposal: InvestigationTopologyProposal,
    *,
    actor: str,
    reason: str,
) -> InvestigationTopologyProposal:
    if proposal.status == "rejected":
        return proposal
    if proposal.status != "proposed":
        raise ValueError("Only a proposed topology view can be rejected")
    proposal.status = "rejected"
    proposal.reviewed_by = actor
    proposal.review_reason = reason
    proposal.reviewed_at = utcnow()
    proposal.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="investigation.topology_proposal.rejected",
        actor_type="user",
        actor_id=actor,
        entity_type="investigation_topology_proposal",
        entity_id=proposal.id,
        details={
            "investigation_id": proposal.investigation_id,
            "reason": reason,
        },
    )
    db.commit()
    return get_topology_proposal(db, proposal.id)
