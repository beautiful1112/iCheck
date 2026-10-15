from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .artifact_replay_schemas import (
    ArtifactReplayCaseCreate,
    ArtifactReplayCaseRead,
    ArtifactReplayRunCreate,
    ArtifactReplayRunRead,
)
from .auth import require_global_permissions
from .database import get_db
from .models import Artifact, ArtifactReplayCase, ArtifactReplayRun
from .services.artifact_replay import (
    create_replay_case,
    replay_case_read,
    replay_run_read,
    run_replay_case,
)
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/artifact-replay", tags=["artifact-replay"])
DBSession = Annotated[Session, Depends(get_db)]


def _artifact(db: Session, artifact_id: str) -> Artifact:
    artifact = db.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact


def _case(db: Session, case_id: str) -> ArtifactReplayCase:
    case = db.get(ArtifactReplayCase, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Replay case not found")
    return case


@router.post(
    "/artifacts/{artifact_id}/cases",
    response_model=ArtifactReplayCaseRead,
    status_code=status.HTTP_201_CREATED,
)
def create_replay_case_route(
    artifact_id: str,
    payload: ArtifactReplayCaseCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> ArtifactReplayCaseRead:
    try:
        case = create_replay_case(
            db,
            _artifact(db, artifact_id),
            payload,
            actor=request_actor(principal, payload.actor),
        )
        return replay_case_read(case)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/artifacts/{artifact_id}/cases",
    response_model=list[ArtifactReplayCaseRead],
)
def list_replay_cases_route(
    artifact_id: str,
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[ArtifactReplayCaseRead]:
    _artifact(db, artifact_id)
    cases = db.scalars(
        select(ArtifactReplayCase)
        .where(ArtifactReplayCase.artifact_id == artifact_id)
        .order_by(ArtifactReplayCase.created_at.desc())
        .limit(limit)
    ).all()
    return [replay_case_read(case) for case in cases]


@router.post(
    "/cases/{case_id}/runs",
    response_model=ArtifactReplayRunRead,
    status_code=status.HTTP_201_CREATED,
)
def run_replay_case_route(
    case_id: str,
    payload: ArtifactReplayRunCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("capabilities.manage")
    ),
) -> ArtifactReplayRunRead:
    try:
        run = run_replay_case(
            db,
            _case(db, case_id),
            payload.artifact_version_id,
            actor=request_actor(principal, payload.actor),
        )
        return replay_run_read(run)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
@router.get(
    "/cases/{case_id}/runs",
    response_model=list[ArtifactReplayRunRead],
)
def list_replay_runs_route(
    case_id: str,
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    _: PrincipalContext = Depends(
        require_global_permissions("capabilities.read")
    ),
) -> list[ArtifactReplayRunRead]:
    _case(db, case_id)
    runs = db.scalars(
        select(ArtifactReplayRun)
        .where(ArtifactReplayRun.case_id == case_id)
        .order_by(ArtifactReplayRun.created_at.desc())
        .limit(limit)
    ).all()
    return [replay_run_read(run) for run in runs]
