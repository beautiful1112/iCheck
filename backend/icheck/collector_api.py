from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .auth import require_global_permissions, require_permissions
from .collector_schemas import (
    ArtifactAction,
    ArtifactCreate,
    ArtifactExportBundle,
    ArtifactImportCreate,
    ArtifactRead,
    ArtifactRestoreCreate,
    ArtifactVersionDiffRead,
    ArtifactVersionCreate,
    ArtifactVersionRead,
    ArtifactSignedImportCreate,
    ArtifactSignatureVerificationRead,
    ArtifactTrustKeyAction,
    ArtifactTrustKeyCreate,
    ArtifactTrustKeyRead,
    AuditEventRead,
    CollectionEnvelopeBatch,
    CollectorAssignment,
    CollectorDeploymentCreate,
    CollectorDeploymentRead,
    CollectorDeploymentTrigger,
    CollectorHealthSummary,
    CollectorLeaseClaim,
    CollectorLeaseRenew,
    CollectorRunAdmit,
    CollectorRunComplete,
    CollectorRunRead,
    CollectorWorkerHeartbeat,
    CollectorWorkerRead,
    CollectorWorkerRegister,
    CollectorWorkerRegistration,
    CredentialGrantRead,
    CredentialGrantRequest,
    CredentialProfileCreate,
    CredentialProfileRead,
    CredentialProfileRotate,
    EnvelopeIngestResult,
)
from .database import NamespaceViolation, get_db, validate_session_namespace
from .config import get_settings
from .models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactSignatureVerification,
    ArtifactTrustKey,
    AuditEvent,
    CollectorDeployment,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    CredentialProfile,
)
from .services.collectors import (
    artifact_query,
    admit_run_execution,
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
    issue_credential_grant,
    publish_artifact_version,
    register_worker,
    renew_run_lease,
    rotate_credential_profile,
    trigger_deployment,
    validate_artifact_version,
)
from .services.artifact_portability import (
    create_restore_candidate,
    diff_artifact_versions,
    export_artifact_bundle,
    import_artifact_bundle,
    import_signed_artifact_bundle,
    register_artifact_trust_key,
    revoke_artifact_trust_key,
)
from .services.authorization_scope import (
    collector_deployment_scope_clause,
    collector_worker_scope_clause,
    request_actor,
    require_global_scope,
    require_mapping_scope,
)
from .services.control_plane_auth import PrincipalContext
from .sandbox import SandboxUnavailable
from .worker_auth import WorkerAuthenticationError, authenticate_worker
from .worker_mtls import WorkerPeerIdentity, worker_peer_identity
from .worker_mtls_schemas import (
    WorkerMTLSLifecycleAction,
    WorkerMTLSRotationCreate,
    WorkerMTLSRotationRead,
    WorkerMTLSStateRead,
)
from .services.worker_mtls import (
    cancel_worker_mtls_rotation,
    revoke_worker_mtls_identity,
    stage_worker_mtls_rotation,
    verify_worker_peer,
)


router = APIRouter(prefix="/api/v1")
DBSession = Annotated[Session, Depends(get_db)]
WorkerPeer = Annotated[WorkerPeerIdentity | None, Depends(worker_peer_identity)]
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
    db: Session,
    worker: CollectorWorker,
    authorization: str | None,
    peer_identity: WorkerPeerIdentity | None,
) -> None:
    try:
        authenticate_worker(worker, authorization)
        verify_worker_peer(
            db,
            worker,
            peer_identity,
            kind="collector",
            mode=get_settings().worker_mtls_mode,
        )
    except (WorkerAuthenticationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _authorize_run(
    db: Session,
    run_id: str,
    authorization: str | None,
    peer_identity: WorkerPeerIdentity | None,
) -> None:
    run = db.get(CollectorRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Collector run not found")
    _authorize_worker(
        db,
        _worker(db, run.worker_id),
        authorization,
        peer_identity,
    )


@router.post(
    "/artifacts",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def create_artifact_route(
    payload: ArtifactCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> Artifact:
    actor = request_actor(principal, payload.initial_version.created_by)
    trusted_payload = payload.model_copy(
        update={
            "initial_version": payload.initial_version.model_copy(
                update={"created_by": actor}
            )
        }
    )
    try:
        return create_artifact(db, trusted_payload)
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
    _: PrincipalContext = Depends(require_permissions("capabilities.read")),
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
def get_artifact_route(
    artifact_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(require_permissions("capabilities.read")),
) -> Artifact:
    try:
        return get_artifact(db, artifact_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/artifacts/{artifact_id}/diff",
    response_model=ArtifactVersionDiffRead,
    tags=["capabilities"],
)
def diff_artifact_versions_route(
    artifact_id: str,
    db: DBSession,
    from_version: int = Query(ge=1),
    to_version: int = Query(ge=1),
    limit: int = Query(default=200, ge=1, le=500),
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> ArtifactVersionDiffRead:
    require_global_scope(principal)
    try:
        return diff_artifact_versions(
            db,
            artifact_id,
            from_version=from_version,
            to_version=to_version,
            limit=limit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/artifact-versions/{version_id}/export",
    response_model=ArtifactExportBundle,
    tags=["capabilities"],
)
def export_artifact_version_route(
    version_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> ArtifactExportBundle:
    require_global_scope(principal)
    version = _artifact_version(db, version_id)
    try:
        return export_artifact_bundle(version)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/artifact-imports",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def import_artifact_bundle_route(
    payload: ArtifactImportCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> Artifact:
    require_global_scope(principal)
    actor = request_actor(principal, payload.created_by)
    try:
        return import_artifact_bundle(db, payload, actor=actor)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/artifact-signed-imports",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def import_signed_artifact_bundle_route(
    payload: ArtifactSignedImportCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> Artifact:
    require_global_scope(principal)
    actor = request_actor(principal, payload.created_by)
    try:
        return import_signed_artifact_bundle(db, payload, actor=actor)
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/artifact-trust-keys",
    response_model=ArtifactTrustKeyRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def register_artifact_trust_key_route(
    payload: ArtifactTrustKeyCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> ArtifactTrustKey:
    try:
        return register_artifact_trust_key(
            db,
            payload,
            actor=request_actor(principal, payload.created_by),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/artifact-trust-keys",
    response_model=list[ArtifactTrustKeyRead],
    tags=["capabilities"],
)
def list_artifact_trust_keys_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[ArtifactTrustKey]:
    return list(
        db.scalars(select(ArtifactTrustKey).order_by(ArtifactTrustKey.name)).all()
    )


@router.post(
    "/artifact-trust-keys/{key_id}/revoke",
    response_model=ArtifactTrustKeyRead,
    tags=["capabilities"],
)
def revoke_artifact_trust_key_route(
    key_id: str,
    payload: ArtifactTrustKeyAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> ArtifactTrustKey:
    key = db.get(ArtifactTrustKey, key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="Artifact trust key not found")
    return revoke_artifact_trust_key(
        db,
        key,
        actor=request_actor(principal, payload.actor),
    )


@router.get(
    "/artifact-versions/{version_id}/signature-verification",
    response_model=ArtifactSignatureVerificationRead,
    tags=["capabilities"],
)
def artifact_signature_verification_route(
    version_id: str,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.read")
    ),
) -> ArtifactSignatureVerification:
    require_global_scope(principal)
    verification = db.scalar(
        select(ArtifactSignatureVerification).where(
            ArtifactSignatureVerification.artifact_version_id == version_id
        )
    )
    if verification is None:
        raise HTTPException(
            status_code=404,
            detail="Artifact version has no verified signature provenance",
        )
    return verification


@router.post(
    "/artifacts/{artifact_id}/restore-candidates",
    response_model=ArtifactVersionRead,
    status_code=status.HTTP_201_CREATED,
    tags=["capabilities"],
)
def create_restore_candidate_route(
    artifact_id: str,
    payload: ArtifactRestoreCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> ArtifactVersion:
    require_global_scope(principal)
    actor = request_actor(principal, payload.actor)
    try:
        return create_restore_candidate(
            db,
            artifact_id,
            payload,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> Artifact:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        artifact = get_artifact(db, artifact_id)
        return create_artifact_version(db, artifact, trusted_payload)
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
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> ArtifactVersion:
    version = _artifact_version(db, version_id)
    try:
        return validate_artifact_version(
            db, version, request_actor(principal, payload.actor)
        )
    except ValueError as exc:
        code = 409 if "Only draft" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except SandboxUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/artifact-versions/{version_id}/publish",
    response_model=ArtifactVersionRead,
    tags=["capabilities"],
)
def publish_artifact_version_route(
    version_id: str,
    payload: ArtifactAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("capabilities.manage")
    ),
) -> ArtifactVersion:
    version = _artifact_version(db, version_id)
    try:
        return publish_artifact_version(
            db, version, request_actor(principal, payload.actor)
        )
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
    principal: PrincipalContext = Depends(
        require_permissions("collectors.manage")
    ),
) -> CollectorDeployment:
    actor = request_actor(principal, payload.created_by)
    trusted_payload = payload.model_copy(update={"created_by": actor})
    require_mapping_scope(
        db,
        principal,
        {
            "device_id": trusted_payload.scope_device_id,
            "site": trusted_payload.scope_site,
        },
        trusted_payload.target,
        trusted_payload.worker_selector,
    )
    try:
        return create_deployment(db, trusted_payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if (
            "already exists" in str(exc) or "Device identity changed" in str(exc)
        ) else 422
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
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> list[CollectorDeployment]:
    query = select(CollectorDeployment).where(
        collector_deployment_scope_clause(principal)
    )
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
    principal: PrincipalContext = Depends(
        require_permissions("collectors.manage")
    ),
) -> CollectorDeployment:
    deployment = db.scalar(
        select(CollectorDeployment).where(
            CollectorDeployment.id == deployment_id,
            collector_deployment_scope_clause(principal),
        )
    )
    if deployment is None:
        raise HTTPException(
            status_code=404, detail="Collector deployment not found"
        )
    try:
        return trigger_deployment(
            db,
            deployment_id,
            actor=request_actor(principal, payload.actor),
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
    principal: PrincipalContext = Depends(
        require_permissions("credentials.manage")
    ),
) -> CredentialProfile:
    trusted_payload = payload.model_copy(
        update={"created_by": request_actor(principal, payload.created_by)}
    )
    try:
        return create_credential_profile(db, trusted_payload)
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
    _: PrincipalContext = Depends(require_permissions("credentials.read")),
) -> list[CredentialProfile]:
    query = select(CredentialProfile)
    if enabled is not None:
        query = query.where(CredentialProfile.enabled == enabled)
    return list(
        db.scalars(query.order_by(CredentialProfile.name).limit(limit)).all()
    )


@router.post(
    "/credential-profiles/{profile_id}/rotate",
    response_model=CredentialProfileRead,
    tags=["collectors"],
)
def rotate_credential_profile_route(
    profile_id: str,
    payload: CredentialProfileRotate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("credentials.manage")
    ),
) -> CredentialProfile:
    profile = db.get(CredentialProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    trusted_payload = payload.model_copy(
        update={"actor": request_actor(principal, payload.actor)}
    )
    try:
        return rotate_credential_profile(db, profile, trusted_payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-workers/register",
    response_model=CollectorWorkerRegistration,
    tags=["collectors"],
)
def register_worker_route(
    payload: CollectorWorkerRegister,
    db: DBSession,
    peer_identity: WorkerPeer,
    x_icheck_registration_token: Annotated[
        str | None,
        Header(alias="X-iCheck-Registration-Token"),
    ] = None,
) -> CollectorWorkerRegistration:
    _require_registration_token(x_icheck_registration_token)
    try:
        validate_session_namespace(db)
    except NamespaceViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        worker, access_token = register_worker(
            db,
            payload,
            peer_identity=peer_identity,
            mtls_mode=get_settings().worker_mtls_mode,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
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
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> list[CollectorWorker]:
    return list(
        db.scalars(
            select(CollectorWorker)
            .where(collector_worker_scope_clause(principal))
            .order_by(CollectorWorker.name)
            .limit(limit)
        ).all()
    )


@router.post(
    "/collector-workers/{worker_id}/mtls-rotation",
    response_model=WorkerMTLSRotationRead,
    tags=["collectors"],
)
def stage_collector_worker_mtls_rotation_route(
    worker_id: str,
    payload: WorkerMTLSRotationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> WorkerMTLSRotationRead:
    try:
        return stage_worker_mtls_rotation(
            db,
            _worker(db, worker_id),
            payload,
            kind="collector",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-workers/{worker_id}/mtls-rotation/cancel",
    response_model=WorkerMTLSStateRead,
    tags=["collectors"],
)
def cancel_collector_worker_mtls_rotation_route(
    worker_id: str,
    payload: WorkerMTLSLifecycleAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> WorkerMTLSStateRead:
    try:
        return cancel_worker_mtls_rotation(
            db,
            _worker(db, worker_id),
            payload,
            kind="collector",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-workers/{worker_id}/mtls-revoke",
    response_model=WorkerMTLSStateRead,
    tags=["collectors"],
)
def revoke_collector_worker_mtls_identity_route(
    worker_id: str,
    payload: WorkerMTLSLifecycleAction,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> WorkerMTLSStateRead:
    try:
        return revoke_worker_mtls_identity(
            db,
            _worker(db, worker_id),
            payload,
            kind="collector",
            actor=principal.subject,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-workers/{worker_id}/heartbeat",
    response_model=CollectorWorkerRead,
    tags=["collectors"],
)
def heartbeat_worker_route(
    worker_id: str,
    payload: CollectorWorkerHeartbeat,
    db: DBSession,
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorWorker:
    worker = _worker(db, worker_id)
    _authorize_worker(db, worker, authorization, peer_identity)
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
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> list[CollectorAssignment]:
    worker = _worker(db, worker_id)
    _authorize_worker(db, worker, authorization, peer_identity)
    try:
        return claim_deployments(db, worker, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-runs/{run_id}/admit",
    response_model=CollectorRunRead,
    tags=["collectors"],
)
def admit_run_execution_route(
    run_id: str,
    payload: CollectorRunAdmit,
    db: DBSession,
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorRun:
    _authorize_run(db, run_id, authorization, peer_identity)
    try:
        return admit_run_execution(db, run_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorRun:
    _authorize_run(db, run_id, authorization, peer_identity)
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
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> EnvelopeIngestResult:
    _authorize_run(db, run_id, authorization, peer_identity)
    try:
        return ingest_envelopes(db, run_id, payload, worker_authorization=authorization, peer_identity=peer_identity)
    except WorkerAuthenticationError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/collector-runs/{run_id}/credential-grant",
    response_model=CredentialGrantRead,
    tags=["collectors"],
)
def issue_credential_grant_route(
    run_id: str,
    payload: CredentialGrantRequest,
    db: DBSession,
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> CredentialGrantRead:
    _authorize_run(db, run_id, authorization, peer_identity)
    try:
        return issue_credential_grant(db, run_id, payload.lease_token)
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
    peer_identity: WorkerPeer,
    authorization: Annotated[str | None, Header()] = None,
) -> CollectorRun:
    _authorize_run(db, run_id, authorization, peer_identity)
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
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> list[CollectorRun]:
    query = select(CollectorRun).where(
        CollectorRun.deployment.has(
            collector_deployment_scope_clause(principal)
        )
    )
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
def collector_health_route(
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("collectors.read")
    ),
) -> dict[str, int]:
    return collector_health(
        db,
        deployment_scope=collector_deployment_scope_clause(principal),
        worker_scope=collector_worker_scope_clause(principal),
    )


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
    principal: PrincipalContext = Depends(require_permissions("audit.read")),
) -> list[AuditEvent]:
    require_global_scope(principal)
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
