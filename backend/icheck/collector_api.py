from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .collector_schemas import (
    ArtifactAction,
    ArtifactCreate,
    ArtifactRead,
    ArtifactVersionCreate,
    ArtifactVersionRead,
    AuditEventRead,
    CollectionEnvelopeBatch,
    CollectorAssignment,
    CollectorDeploymentCreate,
    CollectorDeploymentRead,
    CollectorDeploymentTrigger,
    CollectorHealthSummary,
    CollectorLeaseClaim,
    CollectorLeaseRenew,
    CollectorRunComplete,
    CollectorRunRead,
    CollectorWorkerHeartbeat,
    CollectorWorkerRead,
    CollectorWorkerRegister,
    CollectorWorkerRegistration,
    CredentialProfileCreate,
    CredentialProfileRead,
    EnvelopeIngestResult,
)
from .database import get_db
from .config import get_settings
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    AuditEvent,
    CollectorDeployment,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    CredentialProfile,
)
from .services.collectors import (
    artifact_query,
    claim_deployments,
    collector_health,
    complete_run,
    create_artifact,
    create_artifact_version,
    create_credential_profile,
    create_deployment,
    get_artifact,
    heartbeat_worker,
    ingest_envelopes,
    publish_artifact_version,
    register_worker,
    renew_run_lease,
    trigger_deployment,
    validate_artifact_version,
)
from .worker_auth import WorkerAuthenticationError, authenticate_worker


router = APIRouter(prefix="/api/v1")
DBSession = Annotated[Session, Depends(get_db)]
settings = get_settings()


def _artifact_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise HTTPException(status_code=404, detail="Artifact version not found")
    return version


def _worker(db: Session, worker_id: str) -> CollectorWorker:
    worker = db.get(CollectorWorker, worker_id)
    if worker is None:
        raise HTTPException(status_code=404, detail="Collector worker not found")
    return worker


def _require_registration_token(token: str | None) -> None:
    configured = settings.collector_registration_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Collector worker registration is not configured",
        )
    if token is None or not secrets.compare_digest(configured, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid collector registration token",
        )


def _authorize_worker(
    worker: CollectorWorker,
    authorization: str | None,
) -> None:
    try:
        authenticate_worker(worker, authorization)
    except WorkerAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _authorize_run(
    db: Session,
    run_id: str,
    authorization: str | None,
) -> None:
    run = db.get(CollectorRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Collector run not found")
    _authorize_worker(_worker(db, run.worker_id), authorization)


@router.post(
    "/artifacts",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def create_artifact_route(payload: ArtifactCreate, db: DBSession) -> Artifact:
    try:
        return create_artifact(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/artifacts",
    response_model=list[ArtifactRead],
    tags=["capabilities"],
)
def list_artifacts(
    db: DBSession,
    kind: ArtifactKind | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[Artifact]:
    query = artifact_query()
    if kind:
        query = query.where(Artifact.kind == kind)
    return list(
        db.scalars(query.order_by(Artifact.name).limit(limit)).unique().all()
    )


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ArtifactRead,
    tags=["capabilities"],
)
def get_artifact_route(artifact_id: str, db: DBSession) -> Artifact:
    try:
        return get_artifact(db, artifact_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/artifacts/{artifact_id}/versions",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def create_artifact_version_route(
    artifact_id: str,
    payload: ArtifactVersionCreate,
    db: DBSession,
) -> Artifact:
    try:
        artifact = get_artifact(db, artifact_id)
        return create_artifact_version(db, artifact, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/artifact-versions/{version_id}/validate",
    response_model=ArtifactVersionRead,
    tags=["capabilities"],
)
def validate_artifact_version_route(
    version_id: str,
    payload: ArtifactAction,
    db: DBSession,
) -> ArtifactVersion:
    version = _artifact_version(db, version_id)
    try:
        return validate_artifact_version(db, version, payload.actor)
    except ValueError as exc:
        code = 409 if "Only draft" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post(
    "/artifact-versions/{version_id}/publish",
    response_model=ArtifactVersionRead,
    tags=["capabilities"],
)
def publish_artifact_version_route(
    version_id: str,
    payload: ArtifactAction,
    db: DBSession,
) -> ArtifactVersion:
    version = _artifact_version(db, version_id)
    try:
        return publish_artifact_version(db, version, payload.actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-deployments",
    response_model=CollectorDeploymentRead,
    status_code=status.HTTP_201_CREATED,
    tags=["collectors"],
)
def create_deployment_route(
    payload: CollectorDeploymentCreate,
    db: DBSession,
) -> CollectorDeployment:
    try:
        return create_deployment(db, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/collector-deployments",
    response_model=list[CollectorDeploymentRead],
    tags=["collectors"],
)
def list_deployments(
    db: DBSession,
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CollectorDeployment]:
    query = select(CollectorDeployment)
    if enabled is not None:
        query = query.where(CollectorDeployment.enabled == enabled)
    return list(
        db.scalars(
            query.order_by(CollectorDeployment.name).limit(limit)
        ).all()
    )


@router.post(
    "/collector-deployments/{deployment_id}/trigger",
    response_model=CollectorDeploymentRead,
    tags=["collectors"],
)
def trigger_deployment_route(
    deployment_id: str,
    payload: CollectorDeploymentTrigger,
    db: DBSession,
) -> CollectorDeployment:
    try:
        return trigger_deployment(
            db,
            deployment_id,
            actor=payload.actor,
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/credential-profiles",
    response_model=CredentialProfileRead,
    status_code=status.HTTP_201_CREATED,
    tags=["collectors"],
)
def create_credential_profile_route(
    payload: CredentialProfileCreate,
    db: DBSession,
) -> CredentialProfile:
    try:
        return create_credential_profile(db, payload)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/credential-profiles",
    response_model=list[CredentialProfileRead],
    tags=["collectors"],
)
def list_credential_profiles(
    db: DBSession,
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CredentialProfile]:
    query = select(CredentialProfile)
    if enabled is not None:
        query = query.where(CredentialProfile.enabled == enabled)
    return list(
        db.scalars(query.order_by(CredentialProfile.name).limit(limit)).all()
    )


@router.post(
    "/collector-workers/register",
    response_model=CollectorWorkerRegistration,
    tags=["collectors"],
)
def register_worker_route(
    payload: CollectorWorkerRegister,
    db: DBSession,
    x_icheck_registration_token: Annotated[
        str | None,
        Header(alias="X-iCheck-Registration-Token"),
    ] = None,
) -> CollectorWorkerRegistration:
    _require_registration_token(x_icheck_registration_token)
    worker, access_token = register_worker(db, payload)
    return CollectorWorkerRegistration(
        worker=CollectorWorkerRead.model_validate(worker),
        access_token=access_token,
    )


@router.get(
    "/collector-workers",
    response_model=list[CollectorWorkerRead],
    tags=["collectors"],
)
def list_workers(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CollectorWorker]:
    return list(
        db.scalars(
            select(CollectorWorker)
            .order_by(CollectorWorker.name)
            .limit(limit)
        ).all()
    )


@router.post(
    "/collector-workers/{worker_id}/heartbeat",
    response_model=CollectorWorkerRead,
    tags=["collectors"],
)
def heartbeat_worker_route(
    worker_id: str,
    payload: CollectorWorkerHeartbeat,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorWorker:
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    return heartbeat_worker(db, worker, payload)


@router.post(
    "/collector-workers/{worker_id}/leases/claim",
    response_model=list[CollectorAssignment],
    tags=["collectors"],
)
def claim_deployments_route(
    worker_id: str,
    payload: CollectorLeaseClaim,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> list[CollectorAssignment]:
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    try:
        return claim_deployments(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-runs/{run_id}/lease",
    response_model=CollectorRunRead,
    tags=["collectors"],
)
def renew_run_lease_route(
    run_id: str,
    payload: CollectorLeaseRenew,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorRun:
    _authorize_run(db, run_id, authorization)
    try:
        return renew_run_lease(
            db, run_id, payload.lease_token, payload.lease_seconds
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-runs/{run_id}/envelopes",
    response_model=EnvelopeIngestResult,
    tags=["collectors"],
)
def ingest_envelopes_route(
    run_id: str,
    payload: CollectionEnvelopeBatch,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> EnvelopeIngestResult:
    _authorize_run(db, run_id, authorization)
    try:
        return ingest_envelopes(db, run_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-runs/{run_id}/complete",
    response_model=CollectorRunRead,
    tags=["collectors"],
)
def complete_run_route(
    run_id: str,
    payload: CollectorRunComplete,
    db: DBSession,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorRun:
    _authorize_run(db, run_id, authorization)
    try:
        return complete_run(db, run_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/collector-runs",
    response_model=list[CollectorRunRead],
    tags=["collectors"],
)
def list_runs(
    db: DBSession,
    run_status: CollectorRunStatus | None = Query(
        default=None, alias="status"
    ),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CollectorRun]:
    query = select(CollectorRun)
    if run_status:
        query = query.where(CollectorRun.status == run_status)
    return list(
        db.scalars(
            query.order_by(CollectorRun.started_at.desc()).limit(limit)
        ).all()
    )


@router.get(
    "/collectors/health",
    response_model=CollectorHealthSummary,
    tags=["collectors"],
)
def collector_health_route(db: DBSession) -> dict[str, int]:
    return collector_health(db)


@router.get(
    "/audit-events",
    response_model=list[AuditEventRead],
    tags=["audit"],
)
def list_audit_events(
    db: DBSession,
    event_type: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditEvent]:
    query = select(AuditEvent)
    if event_type:
        query = query.where(AuditEvent.event_type == event_type)
    if entity_type:
        query = query.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditEvent.entity_id == entity_id)
    return list(
        db.scalars(query.order_by(AuditEvent.occurred_at.desc()).limit(limit)).all()
    )
