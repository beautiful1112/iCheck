from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..agent_schemas import InvestigationState
from ..collector_schemas import ArtifactCreate
from ..models import (
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    InvestigationVisualizationProposal,
    InvestigationVisualizationProposalEvidence,
    Situation,
    utcnow,
)
from ..studio_schemas import GeneratedVisualizationSpec
from ..visualization_proposal_schemas import (
    VISUALIZATION_PROPOSAL_CONTRACT,
    InvestigationVisualizationProposalOutput,
    InvestigationVisualizationProposalRead,
    VisualizationProposalEvidenceRead,
)
from .agent_authorization import investigation_principal
from .audit import record_audit_event
from .collectors import (
    create_artifact,
    publish_artifact_version,
    validate_artifact_version,
)
from .service_indicator_visualizations import (
    validate_visualization_artifact_contract,
    visualization_artifact_documents,
)
from .situations import append_situation_event


def visualization_proposal_query():
    return select(InvestigationVisualizationProposal).options(
        selectinload(
            InvestigationVisualizationProposal.evidence_links
        ).selectinload(InvestigationVisualizationProposalEvidence.evidence)
    )


def get_visualization_proposal(
    db: Session,
    proposal_id: str,
) -> InvestigationVisualizationProposal:
    proposal = db.scalar(
        visualization_proposal_query().where(
            InvestigationVisualizationProposal.id == proposal_id
        )
    )
    if proposal is None:
        raise LookupError("Visualization proposal not found")
    return proposal


def visualization_proposal_to_read(
    proposal: InvestigationVisualizationProposal,
) -> InvestigationVisualizationProposalRead:
    return InvestigationVisualizationProposalRead(
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
            VisualizationProposalEvidenceRead(
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


def sync_investigation_visualization_proposal(
    db: Session,
    investigation: Investigation,
    checkpoint: InvestigationCheckpoint,
    state: InvestigationState,
    *,
    actor: str,
) -> None:
    if state.status != "completed":
        return
    if (
        state.scope.get("requested_output_contract")
        != VISUALIZATION_PROPOSAL_CONTRACT
    ):
        return
    document = state.structured_output
    if not isinstance(document, dict):
        raise ValueError(
            "Completed visualization Investigation requires structured_output"
        )
    output = InvestigationVisualizationProposalOutput.model_validate(document)
    requested_evidence_ids = set(output.supporting_evidence_ids)
    if not requested_evidence_ids <= set(state.evidence_ids):
        raise ValueError(
            "Visualization proposal evidence IDs must be present in checkpoint evidence_ids"
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
            "Visualization proposal evidence must belong to the same Investigation"
        )

    existing = db.scalar(
        select(InvestigationVisualizationProposal).where(
            InvestigationVisualizationProposal.investigation_id
            == investigation.id
        )
    )
    if existing is not None:
        if existing.checkpoint_id == checkpoint.id:
            return
        raise ValueError("Investigation already has a visualization proposal")

    definition, implementation, tests = visualization_artifact_documents(
        output.spec
    )
    validation_report = validate_visualization_artifact_contract(
        db,
        definition,
        implementation,
        tests,
        principal=investigation_principal(investigation),
    )
    preview = validation_report["preview"]
    if preview["point_count"] < 1:
        raise ValueError(
            "Visualization proposal requires current service-indicator evidence"
        )
    proposal = InvestigationVisualizationProposal(
        investigation_id=investigation.id,
        checkpoint_id=checkpoint.id,
        contract_version=output.contract,
        status="proposed",
        rationale=output.rationale,
        spec=output.spec.model_dump(mode="json"),
        validation_report=validation_report,
        uncertainty=output.uncertainty,
        authorization_scope=dict(investigation.authorization_scope or {}),
        source_model_id=investigation.model_id,
        created_by=actor,
    )
    db.add(proposal)
    db.flush()
    for evidence_id in output.supporting_evidence_ids:
        db.add(
            InvestigationVisualizationProposalEvidence(
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
                event_type="visualization.proposal_created",
                actor=actor,
                details={
                    "proposal_id": proposal.id,
                    "investigation_id": investigation.id,
                    "artifact_name": output.spec.artifact_name,
                },
            )
    record_audit_event(
        db,
        event_type="investigation.visualization_proposal.created",
        actor_type="agent",
        actor_id=actor,
        entity_type="investigation_visualization_proposal",
        entity_id=proposal.id,
        details={
            "investigation_id": investigation.id,
            "checkpoint_id": checkpoint.id,
            "artifact_name": output.spec.artifact_name,
            "evidence_count": len(evidence),
            "preview_panel_count": preview["panel_count"],
            "preview_point_count": preview["point_count"],
        },
    )


def _artifact_payload(
    proposal: InvestigationVisualizationProposal,
    spec: GeneratedVisualizationSpec,
    *,
    actor: str,
) -> ArtifactCreate:
    definition, implementation, tests = visualization_artifact_documents(spec)
    return ArtifactCreate.model_validate(
        {
            "name": spec.artifact_name,
            "kind": "visualization",
            "description": spec.description,
            "owner": actor,
            "labels": {
                "generated": True,
                "source": "investigation_visualization_proposal",
                "investigation_id": proposal.investigation_id,
                "visualization_proposal_id": proposal.id,
                "format": "icheck.visualization/v1",
            },
            "initial_version": {
                "definition": definition,
                "implementation": implementation,
                "tests": tests,
                "created_by": actor,
            },
        }
    )


def publish_visualization_proposal(
    db: Session,
    proposal: InvestigationVisualizationProposal,
    *,
    actor: str,
    reason: str,
) -> InvestigationVisualizationProposal:
    if proposal.status == "published":
        return get_visualization_proposal(db, proposal.id)
    if proposal.status != "proposed":
        raise ValueError("Only a proposed visualization can be published")
    spec = GeneratedVisualizationSpec.model_validate(proposal.spec)
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
            event_type="investigation.visualization_proposal.published",
            actor_type="user",
            actor_id=actor,
            entity_type="investigation_visualization_proposal",
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
    return get_visualization_proposal(db, proposal.id)


def reject_visualization_proposal(
    db: Session,
    proposal: InvestigationVisualizationProposal,
    *,
    actor: str,
    reason: str,
) -> InvestigationVisualizationProposal:
    if proposal.status == "rejected":
        return proposal
    if proposal.status != "proposed":
        raise ValueError("Only a proposed visualization can be rejected")
    proposal.status = "rejected"
    proposal.reviewed_by = actor
    proposal.review_reason = reason
    proposal.reviewed_at = utcnow()
    proposal.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="investigation.visualization_proposal.rejected",
        actor_type="user",
        actor_id=actor,
        entity_type="investigation_visualization_proposal",
        entity_id=proposal.id,
        details={
            "investigation_id": proposal.investigation_id,
            "reason": reason,
        },
    )
    db.commit()
    return get_visualization_proposal(db, proposal.id)
