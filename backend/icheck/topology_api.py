from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    InvestigationTopologyProposal,
    utcnow,
)
from .services.authorization_scope import has_global_scope, request_actor
from .services.authorization_scope import require_situation_access
from .services.control_plane_auth import PrincipalContext
from .services.situation_impact import situation_impact_graph
from .services.topology_views import (
    published_topology_spec,
    topology_runtime_graph,
)
from .services.topology_proposals import (
    get_topology_proposal,
    publish_topology_proposal,
    reject_topology_proposal,
    topology_proposal_query,
    topology_proposal_to_read,
)
from .topology_proposal_schemas import (
    InvestigationTopologyProposalRead,
    TopologyProposalReview,
)
from .topology_schemas import PublishedTopologyView, TopologyRender


router = APIRouter(prefix="/api/v1/topology", tags=["topology"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/proposals",
    response_model=list[InvestigationTopologyProposalRead],
)
def list_topology_proposals(
    db: DBSession,
    proposal_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[InvestigationTopologyProposalRead]:
    query = topology_proposal_query()
    if proposal_status is not None:
        if proposal_status not in {"proposed", "published", "rejected"}:
            raise HTTPException(status_code=422, detail="Invalid proposal status")
        query = query.where(
            InvestigationTopologyProposal.status == proposal_status
        )
    proposals = list(
        db.scalars(
            query.order_by(
                InvestigationTopologyProposal.created_at.desc()
            ).limit(limit)
        ).unique().all()
    )
    return [topology_proposal_to_read(item) for item in proposals]


@router.get(
    "/proposals/{proposal_id}",
    response_model=InvestigationTopologyProposalRead,
)
def read_topology_proposal(
    proposal_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> InvestigationTopologyProposalRead:
    try:
        proposal = get_topology_proposal(db, proposal_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return topology_proposal_to_read(proposal)


@router.post(
    "/proposals/{proposal_id}/publish",
    response_model=InvestigationTopologyProposalRead,
)
def publish_topology_proposal_route(
    proposal_id: str,
    payload: TopologyProposalReview,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> InvestigationTopologyProposalRead:
    try:
        proposal = publish_topology_proposal(
            db,
            get_topology_proposal(db, proposal_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return topology_proposal_to_read(proposal)


@router.post(
    "/proposals/{proposal_id}/reject",
    response_model=InvestigationTopologyProposalRead,
)
def reject_topology_proposal_route(
    proposal_id: str,
    payload: TopologyProposalReview,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> InvestigationTopologyProposalRead:
    try:
        proposal = reject_topology_proposal(
            db,
            get_topology_proposal(db, proposal_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return topology_proposal_to_read(proposal)


def _published_topology_query():
    return (
        select(ArtifactVersion)
        .join(Artifact, Artifact.id == ArtifactVersion.artifact_id)
        .options(joinedload(ArtifactVersion.artifact))
        .where(
            Artifact.kind == ArtifactKind.TOPOLOGY,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )


def _summary(version: ArtifactVersion) -> dict[str, object]:
    try:
        spec = published_topology_spec(
            version.definition,
            version.implementation,
            version.tests,
        )
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Published topology contract is invalid",
        ) from exc
    if version.published_at is None or version.content_hash is None:
        raise HTTPException(
            status_code=409,
            detail="Published topology provenance is incomplete",
        )
    return {
        "artifact_id": version.artifact_id,
        "name": version.artifact.name,
        "description": version.artifact.description,
        "version_id": version.id,
        "version": version.version,
        "published_at": version.published_at,
        "content_hash": version.content_hash,
        "layout": spec.layout,
        "group_by": spec.group_by,
        "node_types": spec.node_types,
        "edge_types": spec.edge_types,
        "max_nodes": spec.max_nodes,
        "max_edges": spec.max_edges,
    }


@router.get("/views", response_model=list[PublishedTopologyView])
def list_published_topology_views(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(require_permissions("assets.read")),
) -> list[dict[str, object]]:
    versions = db.scalars(
        _published_topology_query()
        .order_by(Artifact.name, ArtifactVersion.version.desc())
        .limit(limit)
    ).all()
    return [_summary(version) for version in versions]


@router.get("/views/{artifact_id}/render", response_model=TopologyRender)
def render_published_topology_view(
    artifact_id: str,
    db: DBSession,
    version: int | None = Query(default=None, ge=1),
    situation_id: str | None = Query(default=None, min_length=1, max_length=36),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
) -> dict[str, object]:
    query = _published_topology_query().where(
        ArtifactVersion.artifact_id == artifact_id
    )
    if version is not None:
        query = query.where(ArtifactVersion.version == version)
    artifact_version = db.scalar(query)
    if artifact_version is None:
        raise HTTPException(status_code=404, detail="Published topology view not found")
    summary = _summary(artifact_version)
    try:
        spec = published_topology_spec(
            artifact_version.definition,
            artifact_version.implementation,
            artifact_version.tests,
        )
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Published topology contract is invalid",
        ) from exc
    context = None
    focus_node_ids = None
    if situation_id is not None:
        if not principal.permits("alerts.read"):
            raise HTTPException(
                status_code=403,
                detail="Missing required permission: alerts.read",
            )
        situation = require_situation_access(db, principal, situation_id)
        impact = situation_impact_graph(db, situation, principal)
        focus_node_ids = {
            "device": {
                item["entity_id"]
                for item in impact["nodes"]
                if item["node_type"] == "device"
            },
            "endpoint": {
                item["entity_id"]
                for item in impact["nodes"]
                if item["node_type"] == "endpoint"
            },
            "knowledge_entity": {
                item["entity_id"]
                for item in impact["nodes"]
                if item["node_type"] == "knowledge_entity"
            },
        }
        context = {
            "situation_id": situation.id,
            "title": situation.title,
            "status": situation.status,
            "severity": situation.severity.value,
            "root_node_id": impact["root_node_id"],
            "hypothesis_boundary": impact["hypothesis_boundary"],
            **impact["summary"],
        }
    graph = topology_runtime_graph(
        db,
        spec,
        principal,
        focus_node_ids=focus_node_ids,
    )
    return {
        **summary,
        "rendered_at": utcnow(),
        "scope_applied": not has_global_scope(principal),
        "spec": spec,
        "context": context,
        **graph,
    }
