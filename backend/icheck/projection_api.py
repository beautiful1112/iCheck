from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_global_permissions, require_permissions
from .database import get_db
from .models import (
    KnowledgeEntity,
    KnowledgeProjection,
    KnowledgeProjectionStatus,
    KnowledgeProjectionWorker,
    KnowledgeRelationship,
)
from .projection_schemas import (
    KnowledgeEntityRead,
    KnowledgeRelationshipRead,
    ProjectionHealth,
    ProjectionRead,
    ProjectionRetry,
    ProjectionWorkerRead,
)
from .services.authorization_scope import (
    collector_deployment_scope_clause,
    knowledge_entity_scope_clause,
    knowledge_relationship_scope_clause,
    request_actor,
)
from .services.control_plane_auth import PrincipalContext
from .services.knowledge_projection import (
    projection_health,
    projection_scope_query,
    projection_to_dict,
    retry_projection,
)


router = APIRouter(prefix="/api/v1")
DBSession = Annotated[Session, Depends(get_db)]


@router.get(
    "/knowledge-projections/health",
    response_model=ProjectionHealth,
    tags=["knowledge-projections"],
)
def knowledge_projection_health(
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> ProjectionHealth:
    return projection_health(
        db,
        deployment_scope=collector_deployment_scope_clause(principal),
    )


@router.get(
    "/knowledge-projections",
    response_model=list[ProjectionRead],
    tags=["knowledge-projections"],
)
def list_knowledge_projections(
    db: DBSession,
    projection_status: KnowledgeProjectionStatus | None = Query(
        default=None,
        alias="status",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> list[dict[str, object]]:
    query = projection_scope_query(
        collector_deployment_scope_clause(principal)
    )
    if projection_status is not None:
        query = query.where(KnowledgeProjection.status == projection_status)
    projections = db.scalars(
        query.order_by(
            KnowledgeProjection.created_at.desc(),
            KnowledgeProjection.id,
        ).limit(limit)
    ).all()
    return [projection_to_dict(item) for item in projections]


@router.post(
    "/knowledge-projections/{projection_id}/retry",
    response_model=ProjectionRead,
    tags=["knowledge-projections"],
)
def retry_knowledge_projection(
    projection_id: str,
    payload: ProjectionRetry,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("collectors.write")
    ),
) -> dict[str, object]:
    projection = db.scalar(
        projection_scope_query(
            collector_deployment_scope_clause(principal)
        ).where(KnowledgeProjection.id == projection_id)
    )
    if projection is None:
        raise HTTPException(status_code=404, detail="Knowledge projection not found")
    try:
        updated = retry_projection(
            db,
            projection,
            actor=request_actor(principal, payload.actor),
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return projection_to_dict(updated)


@router.get(
    "/knowledge/entities",
    response_model=list[KnowledgeEntityRead],
    tags=["knowledge"],
)
def list_knowledge_entities(
    db: DBSession,
    entity_type: str | None = Query(default=None, min_length=1, max_length=64),
    namespace: str | None = Query(default=None, min_length=1, max_length=255),
    active: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
) -> list[KnowledgeEntity]:
    query = select(KnowledgeEntity).where(
        knowledge_entity_scope_clause(principal)
    )
    if entity_type is not None:
        query = query.where(KnowledgeEntity.entity_type == entity_type)
    if namespace is not None:
        query = query.where(KnowledgeEntity.namespace == namespace)
    if active is not None:
        query = query.where(KnowledgeEntity.active.is_(active))
    return list(
        db.scalars(
            query.order_by(
                KnowledgeEntity.last_seen.desc(),
                KnowledgeEntity.id,
            ).limit(limit)
        ).all()
    )


@router.get(
    "/knowledge/relationships",
    response_model=list[KnowledgeRelationshipRead],
    tags=["knowledge"],
)
def list_knowledge_relationships(
    db: DBSession,
    relationship_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=64,
    ),
    namespace: str | None = Query(default=None, min_length=1, max_length=255),
    active: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: PrincipalContext = Depends(require_permissions("assets.read")),
) -> list[KnowledgeRelationship]:
    query = select(KnowledgeRelationship).where(
        knowledge_relationship_scope_clause(principal)
    )
    if relationship_type is not None:
        query = query.where(
            KnowledgeRelationship.relationship_type == relationship_type
        )
    if namespace is not None:
        query = query.where(KnowledgeRelationship.namespace == namespace)
    if active is not None:
        query = query.where(KnowledgeRelationship.active.is_(active))
    return list(
        db.scalars(
            query.order_by(
                KnowledgeRelationship.last_seen.desc(),
                KnowledgeRelationship.id,
            ).limit(limit)
        ).all()
    )


@router.get(
    "/knowledge-projection-workers",
    response_model=list[ProjectionWorkerRead],
    tags=["knowledge-projections"],
)
def list_knowledge_projection_workers(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(
        require_global_permissions("collectors.read")
    ),
) -> list[KnowledgeProjectionWorker]:
    return list(
        db.scalars(
            select(KnowledgeProjectionWorker)
            .order_by(KnowledgeProjectionWorker.name)
            .limit(limit)
        ).all()
    )
