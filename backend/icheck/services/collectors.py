from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import (
    ArtifactCreate,
    ArtifactVersionCreate,
    CollectionEnvelopeBatch,
    CollectorAssignment,
    CollectorDeploymentCreate,
    CredentialProfileCreate,
    CollectorLeaseClaim,
    CollectorRunComplete,
    CollectorWorkerHeartbeat,
    CollectorWorkerRegister,
    EnvelopeIngestResult,
)
from ..models import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    CollectionEnvelope,
    CollectorDefinition,
    CollectorDeployment,
    CollectorDeploymentMode,
    CollectorRun,
    CollectorRunStatus,
    CollectorWorker,
    CollectorWorkerState,
    CredentialProfile,
    EnvelopeKind,
    utcnow,
)
from ..schema_validation import validate_instance, validate_schema
from ..worker_auth import issue_worker_token
from .audit import record_audit_event


SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "community",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def assert_no_inline_secrets(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            is_reference = normalized.endswith("_ref") or normalized.endswith(
                "_reference"
            )
            if normalized in SENSITIVE_KEYS and child not in (None, "", [], {}):
                if not is_reference:
                    raise ValueError(
                        f"{path}.{key} contains an inline secret; use a secret reference"
                    )
            assert_no_inline_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_inline_secrets(child, f"{path}[{index}]")


def _collector_definition_from_payload(
    version: ArtifactVersion,
    payload: ArtifactVersionCreate,
) -> CollectorDefinition | None:
    definition = payload.collector_definition
    if definition is None:
        return None
    return CollectorDefinition(
        artifact_version=version,
        adapter_type=definition.adapter_type,
        mode=definition.mode,
        output_kinds=[item.value for item in definition.output_kinds],
        credential_profile_ref=definition.credential_profile_ref,
        config_schema=definition.config_schema,
        target_schema=definition.target_schema,
        defaults=definition.defaults,
    )


def artifact_query():
    return (
        select(Artifact)
        .options(
            selectinload(Artifact.versions).selectinload(
                ArtifactVersion.collector_definition
            )
        )
        .execution_options(populate_existing=True)
    )


def create_artifact(db: Session, payload: ArtifactCreate) -> Artifact:
    assert_no_inline_secrets(payload.labels, "labels")
    assert_no_inline_secrets(payload.initial_version.definition, "definition")
    assert_no_inline_secrets(
        payload.initial_version.implementation, "implementation"
    )
    assert_no_inline_secrets(payload.initial_version.tests, "tests")

    artifact = Artifact(
        name=payload.name,
        kind=payload.kind,
        description=payload.description,
        owner=payload.owner,
        labels=payload.labels,
    )
    version = ArtifactVersion(
        artifact=artifact,
        version=1,
        definition=payload.initial_version.definition,
        implementation=payload.initial_version.implementation,
        tests=payload.initial_version.tests,
        created_by=payload.initial_version.created_by,
    )
    collector_definition = _collector_definition_from_payload(
        version, payload.initial_version
    )
    db.add(artifact)
    if collector_definition is not None:
        db.add(collector_definition)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.created",
            actor_type="user",
            actor_id=payload.initial_version.created_by,
            entity_type="artifact",
            entity_id=artifact.id,
            details={"kind": payload.kind.value, "version": 1},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "An artifact with this kind and name already exists"
        ) from exc
    return get_artifact(db, artifact.id)


def get_artifact(db: Session, artifact_id: str) -> Artifact:
    artifact = db.scalar(
        artifact_query().where(Artifact.id == artifact_id)
    )
    if artifact is None:
        raise LookupError("Artifact not found")
    return artifact


def create_artifact_version(
    db: Session,
    artifact: Artifact,
    payload: ArtifactVersionCreate,
) -> Artifact:
    if artifact.kind == ArtifactKind.COLLECTOR:
        if payload.collector_definition is None:
            raise ValueError(
                "collector artifacts require a collector_definition"
            )
    elif payload.collector_definition is not None:
        raise ValueError(
            "collector_definition is only valid for collector artifacts"
        )

    assert_no_inline_secrets(payload.definition, "definition")
    assert_no_inline_secrets(payload.implementation, "implementation")
    assert_no_inline_secrets(payload.tests, "tests")
    latest_version = (
        db.scalar(
            select(func.max(ArtifactVersion.version)).where(
                ArtifactVersion.artifact_id == artifact.id
            )
        )
        or 0
    )
    version = ArtifactVersion(
        artifact_id=artifact.id,
        version=latest_version + 1,
        definition=payload.definition,
        implementation=payload.implementation,
        tests=payload.tests,
        created_by=payload.created_by,
    )
    collector_definition = _collector_definition_from_payload(version, payload)
    db.add(version)
    if collector_definition is not None:
        db.add(collector_definition)
    artifact.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.version.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="artifact_version",
            entity_id=version.id,
            details={"artifact_id": artifact.id, "version": version.version},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Artifact version could not be created") from exc
    return get_artifact(db, artifact.id)


def validate_artifact_version(
    db: Session, version: ArtifactVersion, actor: str
) -> ArtifactVersion:
    if version.status != ArtifactVersionStatus.DRAFT:
        raise ValueError("Only draft artifact versions can be validated")
    if version.artifact.kind == ArtifactKind.COLLECTOR:
        definition = version.collector_definition
        if definition is None:
            raise ValueError("Collector definition is missing")
        if not definition.output_kinds:
            raise ValueError("Collector must declare at least one output kind")
        invalid_kinds = set(definition.output_kinds) - {
            item.value for item in EnvelopeKind
        }
        if invalid_kinds:
            raise ValueError(
                f"Unsupported collector output kinds: {sorted(invalid_kinds)}"
            )
        assert_no_inline_secrets(definition.defaults, "collector.defaults")
        validate_schema(definition.target_schema, "collector.target_schema")
        validate_schema(definition.config_schema, "collector.config_schema")

    material = {
        "kind": version.artifact.kind.value,
        "definition": version.definition,
        "implementation": version.implementation,
        "tests": version.tests,
        "collector": (
            {
                "adapter_type": version.collector_definition.adapter_type,
                "mode": version.collector_definition.mode.value,
                "output_kinds": version.collector_definition.output_kinds,
                "credential_profile_ref": (
                    version.collector_definition.credential_profile_ref
                ),
                "config_schema": version.collector_definition.config_schema,
                "target_schema": version.collector_definition.target_schema,
                "defaults": version.collector_definition.defaults,
            }
            if version.collector_definition
            else None
        ),
    }
    version.content_hash = _canonical_hash(material)
    version.status = ArtifactVersionStatus.VALIDATED
    version.validated_at = utcnow()
    version.validated_by = actor
    record_audit_event(
        db,
        event_type="artifact.version.validated",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=version.id,
        details={
            "artifact_id": version.artifact_id,
            "content_hash": version.content_hash,
        },
    )
    db.commit()
    db.refresh(version)
    return version


def publish_artifact_version(
    db: Session, version: ArtifactVersion, actor: str
) -> ArtifactVersion:
    if version.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("Only validated artifact versions can be published")
    previous = db.scalars(
        select(ArtifactVersion).where(
            ArtifactVersion.artifact_id == version.artifact_id,
            ArtifactVersion.status == ArtifactVersionStatus.PUBLISHED,
        )
    ).all()
    for item in previous:
        item.status = ArtifactVersionStatus.DEPRECATED
    version.status = ArtifactVersionStatus.PUBLISHED
    version.published_at = utcnow()
    version.published_by = actor
    record_audit_event(
        db,
        event_type="artifact.version.published",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=version.id,
        details={
            "artifact_id": version.artifact_id,
            "deprecated_version_ids": [item.id for item in previous],
        },
    )
    db.commit()
    db.refresh(version)
    return version


def create_deployment(
    db: Session, payload: CollectorDeploymentCreate
) -> CollectorDeployment:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == payload.artifact_version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    if version.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("Only collector artifacts can be deployed")
    if version.status != ArtifactVersionStatus.PUBLISHED:
        raise ValueError("Only published collector versions can be deployed")
    if version.collector_definition is None:
        raise ValueError("Collector definition is missing")
    assert_no_inline_secrets(payload.target, "target")
    assert_no_inline_secrets(payload.configuration, "configuration")
    assert_no_inline_secrets(payload.worker_selector, "worker_selector")
    definition = version.collector_definition
    validate_instance(
        payload.target,
        definition.target_schema,
        "collector target",
    )
    validate_instance(
        {**definition.defaults, **payload.configuration},
        definition.config_schema,
        "collector configuration",
    )
    credential_ref = (
        payload.credential_profile_ref
        or definition.credential_profile_ref
    )
    if (
        definition.adapter_type == "psrp_cim"
        and payload.execution_mode != CollectorDeploymentMode.ON_DEMAND
    ):
        raise ValueError("psrp_cim deployments must use on_demand execution")
    if definition.adapter_type == "psrp_cim" and not credential_ref:
        raise ValueError(
            "psrp_cim deployments require a credential_profile_ref"
        )
    if credential_ref:
        profile = db.scalar(
            select(CredentialProfile).where(
                or_(
                    CredentialProfile.id == credential_ref,
                    CredentialProfile.name == credential_ref,
                )
            )
        )
        if profile is None:
            raise ValueError(
                f"Credential profile {credential_ref!r} does not exist"
            )
        if not profile.enabled:
            raise ValueError(
                f"Credential profile {credential_ref!r} is disabled"
            )
        if definition.adapter_type not in profile.allowed_adapters:
            raise ValueError(
                f"Credential profile {credential_ref!r} does not allow "
                f"adapter {definition.adapter_type!r}"
            )
        for key, expected in profile.worker_selector.items():
            if payload.worker_selector.get(key) != expected:
                raise ValueError(
                    f"Deployment worker_selector must include {key}={expected!r} "
                    f"for credential profile {credential_ref!r}"
                )

    deployment_values = payload.model_dump()
    deployment_values["credential_profile_ref"] = credential_ref
    deployment = CollectorDeployment(**deployment_values)
    db.add(deployment)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="collector.deployment.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="collector_deployment",
            entity_id=deployment.id,
            details={
                "artifact_version_id": version.id,
                "execution_mode": deployment.execution_mode.value,
                "credential_profile_configured": credential_ref is not None,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Collector deployment name already exists") from exc
    db.refresh(deployment)
    return deployment


def trigger_deployment(
    db: Session,
    deployment_id: str,
    *,
    actor: str,
    reason: str,
) -> CollectorDeployment:
    deployment = db.get(CollectorDeployment, deployment_id)
    if deployment is None:
        raise LookupError("Collector deployment not found")
    if deployment.execution_mode != CollectorDeploymentMode.ON_DEMAND:
        raise ValueError("Only on-demand deployments can be triggered")
    if not deployment.enabled:
        raise ValueError("Collector deployment is disabled")
    now = utcnow()
    if (
        deployment.lease_expires_at is not None
        and _as_utc(deployment.lease_expires_at) >= now
    ):
        raise ValueError("Collector deployment is already running")
    deployment.next_run_at = now
    deployment.updated_at = now
    record_audit_event(
        db,
        event_type="collector.deployment.triggered",
        actor_type="user",
        actor_id=actor,
        entity_type="collector_deployment",
        entity_id=deployment.id,
        details={"reason": reason},
    )
    db.commit()
    db.refresh(deployment)
    return deployment


def register_worker(
    db: Session, payload: CollectorWorkerRegister
) -> tuple[CollectorWorker, str]:
    worker = db.scalar(
        select(CollectorWorker).where(CollectorWorker.name == payload.name)
    )
    now = utcnow()
    access_token, access_token_hash = issue_worker_token()
    rotated = worker is not None
    if worker is None:
        worker = CollectorWorker(
            **payload.model_dump(),
            auth_token_hash=access_token_hash,
            token_issued_at=now,
        )
        db.add(worker)
    else:
        worker.site = payload.site
        worker.capabilities = payload.capabilities
        worker.labels = payload.labels
        worker.state = CollectorWorkerState.ONLINE
        worker.auth_token_hash = access_token_hash
        worker.token_issued_at = now
        worker.updated_at = now
    worker.last_heartbeat_at = now
    db.flush()
    record_audit_event(
        db,
        event_type="collector.worker.registered",
        actor_type="worker",
        actor_id=worker.name,
        entity_type="collector_worker",
        entity_id=worker.id,
        details={"token_rotated": rotated, "site": worker.site},
    )
    db.commit()
    db.refresh(worker)
    return worker, access_token


def create_credential_profile(
    db: Session,
    payload: CredentialProfileCreate,
) -> CredentialProfile:
    assert_no_inline_secrets(payload.worker_selector, "worker_selector")
    profile = CredentialProfile(**payload.model_dump())
    db.add(profile)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="credential.profile.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="credential_profile",
            entity_id=profile.id,
            details={
                "provider": profile.provider,
                "allowed_adapters": profile.allowed_adapters,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Credential profile name already exists") from exc
    db.refresh(profile)
    return profile


def heartbeat_worker(
    db: Session,
    worker: CollectorWorker,
    payload: CollectorWorkerHeartbeat,
) -> CollectorWorker:
    worker.state = payload.state
    if payload.capabilities is not None:
        worker.capabilities = list(dict.fromkeys(payload.capabilities))
    if payload.labels is not None:
        worker.labels = payload.labels
    worker.last_heartbeat_at = utcnow()
    worker.updated_at = utcnow()
    db.commit()
    db.refresh(worker)
    return worker


def claim_deployments(
    db: Session,
    worker: CollectorWorker,
    payload: CollectorLeaseClaim,
) -> list[CollectorAssignment]:
    if worker.state != CollectorWorkerState.ONLINE:
        raise ValueError("Only online workers can claim deployments")

    now = utcnow()
    lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    candidates = db.scalars(
        select(CollectorDeployment)
        .join(CollectorDeployment.artifact_version)
        .join(ArtifactVersion.collector_definition)
        .where(
            CollectorDeployment.enabled.is_(True),
            CollectorDeployment.next_run_at.is_not(None),
            CollectorDeployment.next_run_at <= now,
            or_(
                CollectorDeployment.lease_expires_at.is_(None),
                CollectorDeployment.lease_expires_at < now,
            ),
            ArtifactVersion.status.in_(
                [
                    ArtifactVersionStatus.PUBLISHED,
                    ArtifactVersionStatus.DEPRECATED,
                ]
            ),
            CollectorDefinition.adapter_type.in_(worker.capabilities),
        )
        .options(
            selectinload(CollectorDeployment.artifact_version).selectinload(
                ArtifactVersion.artifact
            ),
            selectinload(CollectorDeployment.artifact_version).selectinload(
                ArtifactVersion.collector_definition
            ),
        )
        .order_by(CollectorDeployment.next_run_at, CollectorDeployment.id)
        .limit(payload.max_assignments * 4)
    ).all()

    assignments: list[CollectorAssignment] = []
    for candidate in candidates:
        if len(assignments) >= payload.max_assignments:
            break
        worker_labels = {
            **worker.labels,
            **({"site": worker.site} if worker.site else {}),
        }
        if any(
            worker_labels.get(key) != expected
            for key, expected in candidate.worker_selector.items()
        ):
            continue
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        claimed = db.execute(
            update(CollectorDeployment)
            .execution_options(synchronize_session=False)
            .where(
                CollectorDeployment.id == candidate.id,
                CollectorDeployment.enabled.is_(True),
                CollectorDeployment.next_run_at.is_not(None),
                CollectorDeployment.next_run_at <= now,
                or_(
                    CollectorDeployment.lease_expires_at.is_(None),
                    CollectorDeployment.lease_expires_at < now,
                ),
            )
            .values(
                lease_worker_id=worker.id,
                lease_token_hash=token_hash,
                lease_expires_at=lease_expires_at,
                last_started_at=now,
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            continue

        db.execute(
            update(CollectorRun)
            .execution_options(synchronize_session=False)
            .where(
                CollectorRun.deployment_id == candidate.id,
                CollectorRun.status == CollectorRunStatus.RUNNING,
            )
            .values(
                status=CollectorRunStatus.CANCELLED,
                finished_at=now,
                error="Lease expired and the deployment was reassigned",
            )
        )
        run = CollectorRun(
            deployment_id=candidate.id,
            worker_id=worker.id,
            lease_token_hash=token_hash,
            status=CollectorRunStatus.RUNNING,
            started_at=now,
        )
        db.add(run)
        db.flush()
        record_audit_event(
            db,
            event_type="collector.run.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="collector_run",
            entity_id=run.id,
            details={"deployment_id": candidate.id},
        )
        version = candidate.artifact_version
        definition = version.collector_definition
        if definition is None:
            raise RuntimeError("Published collector has no collector definition")
        assignments.append(
            CollectorAssignment(
                run_id=run.id,
                lease_token=token,
                lease_expires_at=lease_expires_at,
                deployment_id=candidate.id,
                deployment_name=candidate.name,
                artifact_id=version.artifact.id,
                artifact_name=version.artifact.name,
                artifact_version_id=version.id,
                artifact_version=version.version,
                adapter_type=definition.adapter_type,
                mode=definition.mode,
                output_kinds=definition.output_kinds,
                target=candidate.target,
                configuration=candidate.configuration,
                definition=version.definition,
                implementation=version.implementation,
                defaults=definition.defaults,
                credential_profile_ref=(
                    candidate.credential_profile_ref
                    or definition.credential_profile_ref
                ),
            )
        )
    worker.last_heartbeat_at = now
    db.commit()
    return assignments


def _active_run_for_token(
    db: Session, run_id: str, lease_token: str
) -> CollectorRun:
    run = db.scalar(
        select(CollectorRun)
        .where(CollectorRun.id == run_id)
        .options(selectinload(CollectorRun.deployment))
    )
    if run is None:
        raise LookupError("Collector run not found")
    token_hash = _token_hash(lease_token)
    if run.status != CollectorRunStatus.RUNNING:
        raise ValueError("Collector run is no longer active")
    if not secrets.compare_digest(run.lease_token_hash, token_hash):
        raise ValueError("Invalid collector lease token")
    deployment = run.deployment
    if (
        deployment.lease_worker_id != run.worker_id
        or deployment.lease_token_hash is None
        or not secrets.compare_digest(deployment.lease_token_hash, token_hash)
    ):
        raise ValueError("Collector lease is no longer owned by this run")
    if (
        deployment.lease_expires_at is None
        or _as_utc(deployment.lease_expires_at) < utcnow()
    ):
        raise ValueError("Collector lease has expired")
    return run


def renew_run_lease(
    db: Session,
    run_id: str,
    lease_token: str,
    lease_seconds: int,
) -> CollectorRun:
    run = _active_run_for_token(db, run_id, lease_token)
    now = utcnow()
    run.deployment.lease_expires_at = now + timedelta(seconds=lease_seconds)
    run.deployment.updated_at = now
    run.worker.last_heartbeat_at = now
    db.commit()
    db.refresh(run)
    return run


def ingest_envelopes(
    db: Session,
    run_id: str,
    payload: CollectionEnvelopeBatch,
) -> EnvelopeIngestResult:
    run = _active_run_for_token(db, run_id, payload.lease_token)
    accepted = 0
    duplicates = 0
    for item in payload.envelopes:
        envelope = CollectionEnvelope(run_id=run.id, **item.model_dump())
        try:
            with db.begin_nested():
                db.add(envelope)
                db.flush()
            accepted += 1
        except IntegrityError:
            duplicates += 1
    run.records_received += accepted
    db.commit()
    return EnvelopeIngestResult(
        received=len(payload.envelopes),
        accepted=accepted,
        duplicates=duplicates,
    )


def complete_run(
    db: Session,
    run_id: str,
    payload: CollectorRunComplete,
) -> CollectorRun:
    run = _active_run_for_token(db, run_id, payload.lease_token)
    now = utcnow()
    run.status = payload.status
    run.error = payload.error
    run.stats = payload.stats
    run.finished_at = now
    deployment = run.deployment
    deployment.last_finished_at = now
    if deployment.execution_mode == CollectorDeploymentMode.ON_DEMAND:
        deployment.next_run_at = None
    else:
        deployment.next_run_at = now + timedelta(
            seconds=deployment.schedule_seconds
        )
    deployment.lease_worker_id = None
    deployment.lease_token_hash = None
    deployment.lease_expires_at = None
    deployment.updated_at = now
    record_audit_event(
        db,
        event_type="collector.run.completed",
        actor_type="worker",
        actor_id=run.worker_id,
        entity_type="collector_run",
        entity_id=run.id,
        details={
            "deployment_id": deployment.id,
            "status": payload.status.value,
            "records_received": run.records_received,
        },
    )
    db.commit()
    db.refresh(run)
    return run


def collector_health(db: Session) -> dict[str, int]:
    now = utcnow()
    stale_before = now - timedelta(seconds=90)
    hour_ago = now - timedelta(hours=1)
    workers_total = (
        db.scalar(select(func.count()).select_from(CollectorWorker)) or 0
    )
    workers_online = (
        db.scalar(
            select(func.count())
            .select_from(CollectorWorker)
            .where(
                CollectorWorker.state == CollectorWorkerState.ONLINE,
                CollectorWorker.last_heartbeat_at >= stale_before,
            )
        )
        or 0
    )
    workers_stale = (
        db.scalar(
            select(func.count())
            .select_from(CollectorWorker)
            .where(CollectorWorker.last_heartbeat_at < stale_before)
        )
        or 0
    )
    deployments_total = (
        db.scalar(select(func.count()).select_from(CollectorDeployment)) or 0
    )
    deployments_enabled = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(CollectorDeployment.enabled.is_(True))
        )
        or 0
    )
    deployments_leased = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(CollectorDeployment.lease_expires_at >= now)
        )
        or 0
    )
    deployments_due = (
        db.scalar(
            select(func.count())
            .select_from(CollectorDeployment)
            .where(
                CollectorDeployment.enabled.is_(True),
                CollectorDeployment.next_run_at.is_not(None),
                CollectorDeployment.next_run_at <= now,
                or_(
                    CollectorDeployment.lease_expires_at.is_(None),
                    CollectorDeployment.lease_expires_at < now,
                ),
            )
        )
        or 0
    )
    running_runs = (
        db.scalar(
            select(func.count())
            .select_from(CollectorRun)
            .where(CollectorRun.status == CollectorRunStatus.RUNNING)
        )
        or 0
    )
    failed_runs_last_hour = (
        db.scalar(
            select(func.count())
            .select_from(CollectorRun)
            .where(
                CollectorRun.status == CollectorRunStatus.FAILED,
                CollectorRun.finished_at >= hour_ago,
            )
        )
        or 0
    )
    return {
        "workers_total": workers_total,
        "workers_online": workers_online,
        "workers_stale": workers_stale,
        "deployments_total": deployments_total,
        "deployments_enabled": deployments_enabled,
        "deployments_leased": deployments_leased,
        "deployments_due": deployments_due,
        "running_runs": running_runs,
        "failed_runs_last_hour": failed_runs_last_hour,
    }
