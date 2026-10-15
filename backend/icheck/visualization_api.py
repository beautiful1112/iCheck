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
    InvestigationVisualizationProposal,
)
from .services.authorization_scope import has_global_scope, request_actor
from .services.control_plane_auth import PrincipalContext
from .services.service_indicator_visualizations import (
    published_visualization_spec,
    visualization_is_fully_visible,
    visualization_runtime_render,
)
from .services.visualization_proposals import (
    get_visualization_proposal,
    publish_visualization_proposal,
    reject_visualization_proposal,
    visualization_proposal_query,
    visualization_proposal_to_read,
)
from .visualization_proposal_schemas import (
    InvestigationVisualizationProposalRead,
    VisualizationProposalReview,
)
from .visualization_schemas import PublishedVisualization, VisualizationRender


router = APIRouter(prefix="/api/v1/visualizations", tags=["visualizations"])
DBSession = Annotated[Session, Depends(get_db)]


def _published_query():
    return (
        select(ArtifactVersion)
        .join(Artifact, Artifact.id == ArtifactVersion.artifact_id)
        .options(joinedload(ArtifactVersion.artifact))
        .where(
            Artifact.kind == ArtifactKind.VISUALIZATION,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    )


def _spec(version: ArtifactVersion):
    try:
        return published_visualization_spec(
            version.definition,
            version.implementation,
            version.tests,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Published visualization contract is invalid",
        ) from exc


def _summary(version: ArtifactVersion, spec) -> dict[str, object]:
    if version.published_at is None or version.content_hash is None:
        raise HTTPException(
            status_code=409,
            detail="Published visualization provenance is incomplete",
        )
    return {
        "artifact_id": version.artifact_id,
        "name": version.artifact.name,
        "description": version.artifact.description,
        "version_id": version.id,
        "version": version.version,
        "published_at": version.published_at,
        "content_hash": version.content_hash,
        "layout_columns": spec.layout_columns,
        "refresh_seconds": spec.refresh_seconds,
        "lookback_minutes": spec.lookback_minutes,
        "panel_count": len(spec.panels),
    }


@router.get("", response_model=list[PublishedVisualization])
def list_published_visualizations(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> list[dict[str, object]]:
    versions = db.scalars(
        _published_query()
        .order_by(Artifact.name, ArtifactVersion.version.desc())
        .limit(500)
    ).all()
    visible: list[dict[str, object]] = []
    for version in versions:
        spec = _spec(version)
        if visualization_is_fully_visible(db, spec, principal):
            visible.append(_summary(version, spec))
        if len(visible) >= limit:
            break
    return visible


@router.get(
    "/proposals",
    response_model=list[InvestigationVisualizationProposalRead],
)
def list_visualization_proposals(
    db: DBSession,
    proposal_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[InvestigationVisualizationProposalRead]:
    query = visualization_proposal_query()
    if proposal_status is not None:
        if proposal_status not in {"proposed", "published", "rejected"}:
            raise HTTPException(status_code=422, detail="Invalid proposal status")
        query = query.where(
            InvestigationVisualizationProposal.status == proposal_status
        )
    proposals = list(
        db.scalars(
            query.order_by(
                InvestigationVisualizationProposal.created_at.desc()
            ).limit(limit)
        ).unique().all()
    )
    return [visualization_proposal_to_read(item) for item in proposals]


@router.get(
    "/proposals/{proposal_id}",
    response_model=InvestigationVisualizationProposalRead,
)
def read_visualization_proposal(
    proposal_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> InvestigationVisualizationProposalRead:
    try:
        proposal = get_visualization_proposal(db, proposal_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return visualization_proposal_to_read(proposal)


@router.post(
    "/proposals/{proposal_id}/publish",
    response_model=InvestigationVisualizationProposalRead,
)
def publish_visualization_proposal_route(
    proposal_id: str,
    payload: VisualizationProposalReview,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> InvestigationVisualizationProposalRead:
    try:
        proposal = publish_visualization_proposal(
            db,
            get_visualization_proposal(db, proposal_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return visualization_proposal_to_read(proposal)


@router.post(
    "/proposals/{proposal_id}/reject",
    response_model=InvestigationVisualizationProposalRead,
)
def reject_visualization_proposal_route(
    proposal_id: str,
    payload: VisualizationProposalReview,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> InvestigationVisualizationProposalRead:
    try:
        proposal = reject_visualization_proposal(
            db,
            get_visualization_proposal(db, proposal_id),
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return visualization_proposal_to_read(proposal)


@router.get("/{artifact_id}/render", response_model=VisualizationRender)
def render_published_visualization(
    artifact_id: str,
    db: DBSession,
    version: int | None = Query(default=None, ge=1),
    principal: PrincipalContext = Depends(require_permissions("services.read")),
) -> dict[str, object]:
    query = _published_query().where(ArtifactVersion.artifact_id == artifact_id)
    if version is not None:
        query = query.where(ArtifactVersion.version == version)
    else:
        query = query.order_by(ArtifactVersion.version.desc())
    artifact_version = db.scalar(query)
    if artifact_version is None:
        raise HTTPException(
            status_code=404,
            detail="Published visualization not found",
        )
    spec = _spec(artifact_version)
    if not visualization_is_fully_visible(db, spec, principal):
        raise HTTPException(
            status_code=404,
            detail="Published visualization not found",
        )
    render = visualization_runtime_render(db, spec, principal)
    return {
        **_summary(artifact_version, spec),
        **render,
        "scope_applied": not has_global_scope(principal),
        "spec": spec,
    }
