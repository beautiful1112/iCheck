from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent_schemas import InvestigationState
from ..models import (
    Investigation,
    InvestigationCheckpoint,
    InvestigationEvidence,
    Situation,
    SituationImpactAssessment,
    SituationImpactAssessmentEvidence,
    ServiceCatalogDependency,
    ServiceCatalogEntry,
    utcnow,
)
from ..situation_assessment_schemas import (
    SITUATION_IMPACT_ASSESSMENT_CONTRACT,
    SituationImpactAssessmentProposal,
)
from .agent_authorization import investigation_principal
from .audit import record_audit_event
from .situation_impact import situation_impact_graph
from .situations import append_situation_event


def sync_situation_impact_assessment(
    db: Session,
    investigation: Investigation,
    checkpoint: InvestigationCheckpoint,
    state: InvestigationState,
    *,
    actor: str,
) -> None:
    """Persist a governed proposal without changing deterministic Situation truth."""

    if investigation.situation_id is None or state.status != "completed":
        return
    requested_contract = state.scope.get("requested_output_contract")
    if requested_contract != SITUATION_IMPACT_ASSESSMENT_CONTRACT:
        return
    document = state.structured_output
    if not isinstance(document, dict):
        raise ValueError(
            "Completed Situation investigation requires an impact assessment structured_output"
        )
    if document.get("contract") != SITUATION_IMPACT_ASSESSMENT_CONTRACT:
        raise ValueError("Impact assessment structured_output contract is invalid")

    proposal = SituationImpactAssessmentProposal.model_validate(document)
    state_evidence_ids = set(state.evidence_ids)
    requested_evidence_ids = set(proposal.supporting_evidence_ids)
    if not requested_evidence_ids <= state_evidence_ids:
        raise ValueError(
            "Impact assessment evidence IDs must be present in checkpoint evidence_ids"
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
            "Impact assessment evidence must belong to the same Investigation"
        )

    situation = db.get(Situation, investigation.situation_id)
    if situation is None:
        raise RuntimeError("Investigation references a missing Situation")
    graph = situation_impact_graph(
        db,
        situation,
        investigation_principal(investigation),
    )
    allowed_node_ids = {str(item["id"]) for item in graph["nodes"]}
    affected_node_ids = set(proposal.affected_node_ids)
    if not affected_node_ids <= allowed_node_ids:
        raise ValueError(
            "Impact assessment affected nodes must be present in the current authorized impact graph"
        )
    if (
        proposal.impact_level not in {"unknown", "none"}
        and not proposal.affected_node_ids
    ):
        raise ValueError(
            "A non-empty affected_node_ids list is required for a material impact level"
        )

    affected_service_ids = {
        node_id.removeprefix("service:")
        for node_id in proposal.affected_node_ids
        if node_id.startswith("service:")
    }
    affected_services = list(
        db.scalars(
            select(ServiceCatalogEntry).where(
                ServiceCatalogEntry.id.in_(affected_service_ids)
            )
        ).all()
    ) if affected_service_ids else []
    service_context_snapshot = [
        {
            "service_id": item.id,
            "service_key": item.service_key,
            "name": item.name,
            "owner_team": item.owner_team,
            "criticality": item.criticality,
            "business_impact": item.business_impact,
            "business_impact_summary": item.business_impact_summary,
            "slo_target_percent": item.slo_target_percent,
            "recovery_time_objective_minutes": (
                item.recovery_time_objective_minutes
            ),
            "recovery_point_objective_minutes": (
                item.recovery_point_objective_minutes
            ),
            "catalog_revision": item.revision,
        }
        for item in sorted(affected_services, key=lambda service: service.service_key)
    ]
    affected_service_node_ids = {
        f"service:{service_id}" for service_id in affected_service_ids
    }
    dependency_ids = {
        str(edge["evidence_id"])
        for edge in graph["edges"]
        if edge["evidence_type"] == "service_catalog_dependency"
        and (
            edge["source"] in affected_service_node_ids
            or edge["target"] in affected_service_node_ids
        )
    }
    dependencies = list(
        db.scalars(
            select(ServiceCatalogDependency).where(
                ServiceCatalogDependency.id.in_(dependency_ids)
            )
        ).all()
    ) if dependency_ids else []
    dependency_service_ids = {
        service_id
        for dependency in dependencies
        for service_id in (
            dependency.source_service_id,
            dependency.target_service_id,
        )
    }
    dependency_services = {
        item.id: item
        for item in db.scalars(
            select(ServiceCatalogEntry).where(
                ServiceCatalogEntry.id.in_(dependency_service_ids)
            )
        ).all()
    } if dependency_service_ids else {}
    dependency_context_snapshot = [
        {
            "dependency_id": item.id,
            "source_service_id": item.source_service_id,
            "source_service_key": dependency_services[
                item.source_service_id
            ].service_key,
            "source_service_name": dependency_services[
                item.source_service_id
            ].name,
            "target_service_id": item.target_service_id,
            "target_service_key": dependency_services[
                item.target_service_id
            ].service_key,
            "target_service_name": dependency_services[
                item.target_service_id
            ].name,
            "dependency_type": item.dependency_type,
            "critical": item.critical,
            "evidence_note": item.evidence_note,
            "recorded_at": item.updated_at.isoformat(),
        }
        for item in sorted(dependencies, key=lambda value: value.id)
        if item.source_service_id in dependency_services
        and item.target_service_id in dependency_services
    ]
    indicator_nodes = {
        str(node["id"]): node
        for node in graph["nodes"]
        if node["node_type"] == "service_indicator"
    }
    selected_indicator_node_ids = {
        node_id
        for node_id in proposal.affected_node_ids
        if node_id.startswith("service_indicator:")
    }
    indicator_edges = [
        edge
        for edge in graph["edges"]
        if edge["evidence_type"] == "service_indicator_observation"
        and (
            edge["target"] in affected_service_node_ids
            or edge["source"] in selected_indicator_node_ids
        )
        and edge["source"] in indicator_nodes
    ]
    indicator_context_snapshot = [
        {
            "definition_id": node["entity_id"],
            "definition_revision": node["indicator_revision"],
            "observation_id": edge["evidence_id"],
            "service_id": node["service_id"],
            "indicator_key": node["indicator_key"],
            "name": node["label"],
            "kind": node["kind"],
            "unit": node["unit"],
            "value": node["value"],
            "source_type": node["source_type"],
            "source_ref": node["source_ref"],
            "measurement_quality": node["measurement_quality"],
            "threshold_status": node["threshold_status"],
            "freshness_status": node["freshness_status"],
            "effective_status": node["status"],
            "freshness_seconds": node["freshness_seconds"],
            "evidence_ref": node["evidence_ref"],
            "observed_at": node["observed_at"].isoformat(),
            "expires_at": node["expires_at"].isoformat(),
        }
        for edge in sorted(indicator_edges, key=lambda value: value["source"])
        for node in [indicator_nodes[edge["source"]]]
    ]

    existing = db.scalar(
        select(SituationImpactAssessment).where(
            SituationImpactAssessment.investigation_id == investigation.id
        )
    )
    if existing is not None:
        if existing.checkpoint_id == checkpoint.id:
            return
        raise ValueError("Investigation already has an impact assessment")

    assessment = SituationImpactAssessment(
        situation_id=situation.id,
        investigation_id=investigation.id,
        checkpoint_id=checkpoint.id,
        contract_version=proposal.contract,
        status="proposed",
        impact_level=proposal.impact_level,
        summary=proposal.summary,
        confidence=proposal.confidence,
        affected_node_ids=proposal.affected_node_ids,
        uncertainty=proposal.uncertainty,
        service_context_snapshot=service_context_snapshot,
        dependency_context_snapshot=dependency_context_snapshot,
        indicator_context_snapshot=indicator_context_snapshot,
        source_model_id=investigation.model_id,
        created_by=actor,
    )
    db.add(assessment)
    db.flush()
    for evidence_id in proposal.supporting_evidence_ids:
        db.add(
            SituationImpactAssessmentEvidence(
                assessment_id=assessment.id,
                investigation_evidence_id=evidence_by_id[evidence_id].id,
            )
        )
    append_situation_event(
        db,
        situation,
        event_type="impact_assessment.proposed",
        actor=actor,
        details={
            "assessment_id": assessment.id,
            "investigation_id": investigation.id,
            "impact_level": assessment.impact_level,
            "confidence": assessment.confidence,
            "affected_node_count": len(assessment.affected_node_ids),
            "evidence_count": len(proposal.supporting_evidence_ids),
        },
    )
    situation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="situation.impact_assessment.proposed",
        actor_type="agent",
        actor_id=actor,
        entity_type="situation_impact_assessment",
        entity_id=assessment.id,
        details={
            "situation_id": situation.id,
            "investigation_id": investigation.id,
            "impact_level": assessment.impact_level,
            "confidence": assessment.confidence,
            "affected_node_count": len(assessment.affected_node_ids),
            "evidence_count": len(proposal.supporting_evidence_ids),
        },
    )


def review_impact_assessment(
    db: Session,
    situation: Situation,
    assessment: SituationImpactAssessment,
    *,
    decision: str,
    actor: str,
    reason: str,
) -> SituationImpactAssessment:
    if decision not in {"accepted", "rejected"}:
        raise ValueError("Impact assessment review decision is invalid")
    if assessment.situation_id != situation.id:
        raise LookupError("Situation impact assessment not found")
    if assessment.status == decision:
        return assessment
    if assessment.status != "proposed":
        raise ValueError("Only a proposed impact assessment can be reviewed")

    assessment.status = decision
    assessment.reviewed_by = actor
    assessment.review_reason = reason
    assessment.reviewed_at = utcnow()
    assessment.updated_at = utcnow()
    append_situation_event(
        db,
        situation,
        event_type=f"impact_assessment.{decision}",
        actor=actor,
        details={
            "assessment_id": assessment.id,
            "impact_level": assessment.impact_level,
            "reason": reason,
        },
    )
    situation.updated_at = utcnow()
    record_audit_event(
        db,
        event_type=f"situation.impact_assessment.{decision}",
        actor_type="user",
        actor_id=actor,
        entity_type="situation_impact_assessment",
        entity_id=assessment.id,
        details={
            "situation_id": situation.id,
            "impact_level": assessment.impact_level,
            "reason": reason,
        },
    )
    return assessment
