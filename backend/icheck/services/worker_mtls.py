from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    AgentWorker,
    AgentWorkerState,
    CollectorWorker,
    CollectorWorkerState,
    utcnow,
)
from ..worker_auth import issue_worker_token
from ..worker_mtls import WorkerPeerIdentity
from ..worker_mtls_schemas import (
    WorkerMTLSLifecycleAction,
    WorkerMTLSRotationCreate,
    WorkerMTLSRotationRead,
    WorkerMTLSStateRead,
)
from .audit import record_audit_event


Worker = CollectorWorker | AgentWorker
WorkerKind = Literal["collector", "agent"]
MAX_CERTIFICATE_LIFETIME = timedelta(days=1825)
MAX_FUTURE_ACTIVATION = timedelta(days=30)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _worker_type(kind: WorkerKind):
    return CollectorWorker if kind == "collector" else AgentWorker


def _fingerprint_lock(db: Session, worker: Worker, fingerprint: str) -> None:
    """Serialize namespace-wide identity claims across both Worker tables."""
    if db.get_bind().dialect.name != "postgresql":
        return
    token = ":".join(
        (
            "worker-mtls",
            worker.tenant_id,
            worker.region_id,
            fingerprint,
        )
    )
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    lock_id = int(digest[:16], 16)
    if lock_id >= 2**63:
        lock_id -= 2**64
    db.execute(select(func.pg_advisory_xact_lock(lock_id)))


def _lock_worker(db: Session, worker: Worker, kind: WorkerKind) -> Worker:
    model = _worker_type(kind)
    locked = db.scalar(
        select(model)
        .where(
            model.id == worker.id,
            model.tenant_id == worker.tenant_id,
            model.region_id == worker.region_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        raise LookupError(f"{kind.title()} Worker not found")
    return locked


def _identity_in_use(
    db: Session,
    fingerprint: str,
    *,
    worker: Worker,
) -> bool:
    for model in (CollectorWorker, AgentWorker):
        query = select(model.id).where(
            model.tenant_id == worker.tenant_id,
            model.region_id == worker.region_id,
            or_(
                model.mtls_fingerprint_sha256 == fingerprint,
                model.mtls_next_fingerprint_sha256 == fingerprint,
            ),
        )
        if isinstance(worker, model):
            query = query.where(model.id != worker.id)
        if db.scalar(query.limit(1)) is not None:
            return True
    return False


def _certificate_identity(
    certificate_pem: str,
) -> tuple[str, str, str, datetime, datetime]:
    encoded = certificate_pem.encode("utf-8")
    if (
        encoded.count(b"-----BEGIN CERTIFICATE-----") != 1
        or encoded.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise ValueError("Worker rotation requires exactly one PEM certificate")
    try:
        certificate = x509.load_pem_x509_certificate(encoded)
    except ValueError as exc:
        raise ValueError("Worker rotation certificate is invalid PEM") from exc
    try:
        basic = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if basic.ca:
            raise ValueError("Worker identity certificate must not be a CA")
    except x509.ExtensionNotFound:
        pass
    try:
        usages = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
            raise ValueError("Worker certificate is not valid for client authentication")
    except x509.ExtensionNotFound:
        pass
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    now = utcnow()
    if not_after <= now:
        raise ValueError("Worker rotation certificate has expired")
    if not_after - not_before > MAX_CERTIFICATE_LIFETIME:
        raise ValueError("Worker certificate lifetime exceeds five years")
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    subject_sha256 = hashlib.sha256(
        certificate.subject.rfc4514_string().encode("utf-8")
    ).hexdigest()
    serial_sha256 = hashlib.sha256(
        str(certificate.serial_number).encode("ascii")
    ).hexdigest()
    return fingerprint, subject_sha256, serial_sha256, not_before, not_after


def _clear_next(worker: Worker) -> None:
    worker.mtls_next_fingerprint_sha256 = None
    worker.mtls_next_subject_sha256 = None
    worker.mtls_next_serial_sha256 = None
    worker.mtls_next_not_before = None
    worker.mtls_next_not_after = None


def _promote_next(
    db: Session,
    worker: Worker,
    *,
    kind: WorkerKind,
) -> None:
    fingerprint = worker.mtls_next_fingerprint_sha256
    if fingerprint is None:
        raise ValueError("Worker has no staged mTLS identity")
    previous = worker.mtls_fingerprint_sha256
    worker.mtls_fingerprint_sha256 = fingerprint
    worker.mtls_subject_sha256 = worker.mtls_next_subject_sha256
    worker.mtls_serial_sha256 = worker.mtls_next_serial_sha256
    worker.mtls_not_after = worker.mtls_next_not_after
    worker.mtls_activated_at = utcnow()
    _clear_next(worker)
    worker.mtls_revision += 1
    record_audit_event(
        db,
        event_type=f"{kind}.worker.mtls_promoted",
        actor_type="worker",
        actor_id=worker.name,
        entity_type=f"{kind}_worker",
        entity_id=worker.id,
        details={
            "revision": worker.mtls_revision,
            "previous_fingerprint_sha256": previous,
            "fingerprint_sha256": fingerprint,
        },
    )
    # SessionLocal disables autoflush. Subsequent admission/heartbeat locks
    # refresh registry state to fence capacity draining; that refresh must see
    # this promotion, not discard it. Flush identity and audit together without
    # committing: a failed request still rolls both back under the row mutex.
    db.flush()


def verify_worker_peer(
    db: Session,
    worker: Worker,
    peer: WorkerPeerIdentity | None,
    *,
    kind: WorkerKind,
    mode: Literal["disabled", "optional", "required"],
) -> None:
    if mode == "disabled":
        if worker.mtls_fingerprint_sha256 is not None or (
            worker.mtls_next_fingerprint_sha256 is not None
        ):
            raise ValueError(
                "mTLS-bound Worker cannot authenticate while Worker mTLS is disabled"
            )
        return
    if worker.mtls_fingerprint_sha256 is not None or (
        worker.mtls_next_fingerprint_sha256 is not None
    ):
        worker = _lock_worker(db, worker, kind)
    current = worker.mtls_fingerprint_sha256
    staged = worker.mtls_next_fingerprint_sha256
    if current is None and staged is None:
        if mode == "required":
            raise ValueError("Worker has no bound mTLS identity")
        if peer is not None:
            raise ValueError("Unbound Worker must re-register before using mTLS")
        return
    if peer is None:
        raise ValueError("Bound Worker requires a verified client certificate")
    now = utcnow()
    if (
        current is not None
        and secrets.compare_digest(current, peer.fingerprint_sha256)
    ):
        if worker.mtls_not_after is None or _as_utc(worker.mtls_not_after) <= now:
            raise ValueError("Bound Worker certificate has expired")
        return
    if (
        staged is not None
        and secrets.compare_digest(staged, peer.fingerprint_sha256)
        and worker.mtls_next_not_before is not None
        and worker.mtls_next_not_after is not None
        and _as_utc(worker.mtls_next_not_before) <= now
        and _as_utc(worker.mtls_next_not_after) > now
    ):
        _promote_next(db, worker, kind=kind)
        return
    raise ValueError("Worker client certificate does not match its bound identity")


def apply_registration_identity(
    db: Session,
    worker: Worker,
    peer: WorkerPeerIdentity | None,
    *,
    kind: WorkerKind,
    mode: Literal["disabled", "optional", "required"],
) -> None:
    if worker.mtls_fingerprint_sha256 is not None or (
        worker.mtls_next_fingerprint_sha256 is not None
    ):
        verify_worker_peer(db, worker, peer, kind=kind, mode=mode)
        return
    if peer is None:
        if mode == "required":
            raise ValueError("Worker registration requires a verified client certificate")
        return
    if mode == "disabled":
        raise ValueError("Worker mTLS identity forwarding is disabled")
    if peer.not_after > utcnow() + MAX_CERTIFICATE_LIFETIME:
        raise ValueError("Worker certificate expiry is more than five years away")
    _fingerprint_lock(db, worker, peer.fingerprint_sha256)
    if _identity_in_use(db, peer.fingerprint_sha256, worker=worker):
        raise ValueError("Worker certificate is already bound to another Worker")
    worker.mtls_fingerprint_sha256 = peer.fingerprint_sha256
    worker.mtls_subject_sha256 = peer.subject_sha256
    worker.mtls_serial_sha256 = peer.serial_sha256
    worker.mtls_not_after = peer.not_after
    worker.mtls_activated_at = utcnow()
    worker.mtls_revision = max(worker.mtls_revision, 0) + 1
    record_audit_event(
        db,
        event_type=f"{kind}.worker.mtls_bound",
        actor_type="worker",
        actor_id=worker.name,
        entity_type=f"{kind}_worker",
        entity_id=worker.id,
        details={
            "revision": worker.mtls_revision,
            "fingerprint_sha256": peer.fingerprint_sha256,
            "not_after": peer.not_after.isoformat(),
        },
    )


def stage_worker_mtls_rotation(
    db: Session,
    worker: Worker,
    payload: WorkerMTLSRotationCreate,
    *,
    kind: WorkerKind,
    actor: str,
) -> WorkerMTLSRotationRead:
    worker = _lock_worker(db, worker, kind)
    if worker.mtls_revision != payload.expected_revision:
        raise ValueError("Worker mTLS revision conflict")
    (
        fingerprint,
        subject_sha256,
        serial_sha256,
        certificate_not_before,
        certificate_not_after,
    ) = _certificate_identity(payload.certificate_pem)
    if worker.mtls_fingerprint_sha256 and secrets.compare_digest(
        worker.mtls_fingerprint_sha256,
        fingerprint,
    ):
        raise ValueError("Worker rotation certificate is already active")
    _fingerprint_lock(db, worker, fingerprint)
    if _identity_in_use(db, fingerprint, worker=worker):
        raise ValueError("Worker certificate is already bound to another Worker")
    now = utcnow()
    activate_after = (
        _as_utc(payload.activate_after) if payload.activate_after else now
    )
    if activate_after < certificate_not_before:
        activate_after = certificate_not_before
    if activate_after < now - timedelta(minutes=5):
        raise ValueError("Worker mTLS activation time is in the past")
    if activate_after > now + MAX_FUTURE_ACTIVATION:
        raise ValueError("Worker mTLS activation is more than 30 days away")
    if activate_after >= certificate_not_after:
        raise ValueError("Worker mTLS activation does not precede certificate expiry")
    worker.mtls_next_fingerprint_sha256 = fingerprint
    worker.mtls_next_subject_sha256 = subject_sha256
    worker.mtls_next_serial_sha256 = serial_sha256
    worker.mtls_next_not_before = activate_after
    worker.mtls_next_not_after = certificate_not_after
    worker.mtls_revision += 1
    record_audit_event(
        db,
        event_type=f"{kind}.worker.mtls_rotation_staged",
        actor_type="user",
        actor_id=actor,
        entity_type=f"{kind}_worker",
        entity_id=worker.id,
        details={
            "revision": worker.mtls_revision,
            "fingerprint_sha256": fingerprint,
            "activate_after": activate_after.isoformat(),
            "not_after": certificate_not_after.isoformat(),
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    return WorkerMTLSRotationRead(
        worker_kind=kind,
        worker_id=worker.id,
        current_fingerprint_sha256=worker.mtls_fingerprint_sha256,
        current_not_after=worker.mtls_not_after,
        next_fingerprint_sha256=fingerprint,
        next_not_before=activate_after,
        next_not_after=certificate_not_after,
        revision=worker.mtls_revision,
    )


def _state_read(worker: Worker, kind: WorkerKind) -> WorkerMTLSStateRead:
    return WorkerMTLSStateRead(
        worker_kind=kind,
        worker_id=worker.id,
        current_fingerprint_sha256=worker.mtls_fingerprint_sha256,
        current_not_after=worker.mtls_not_after,
        next_fingerprint_sha256=worker.mtls_next_fingerprint_sha256,
        next_not_before=worker.mtls_next_not_before,
        next_not_after=worker.mtls_next_not_after,
        revision=worker.mtls_revision,
    )


def cancel_worker_mtls_rotation(
    db: Session,
    worker: Worker,
    payload: WorkerMTLSLifecycleAction,
    *,
    kind: WorkerKind,
    actor: str,
) -> WorkerMTLSStateRead:
    worker = _lock_worker(db, worker, kind)
    if worker.mtls_revision != payload.expected_revision:
        raise ValueError("Worker mTLS revision conflict")
    cancelled = worker.mtls_next_fingerprint_sha256
    if cancelled is None:
        raise ValueError("Worker has no staged mTLS rotation")
    _clear_next(worker)
    worker.mtls_revision += 1
    record_audit_event(
        db,
        event_type=f"{kind}.worker.mtls_rotation_cancelled",
        actor_type="user",
        actor_id=actor,
        entity_type=f"{kind}_worker",
        entity_id=worker.id,
        details={
            "revision": worker.mtls_revision,
            "cancelled_fingerprint_sha256": cancelled,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(worker)
    return _state_read(worker, kind)


def revoke_worker_mtls_identity(
    db: Session,
    worker: Worker,
    payload: WorkerMTLSLifecycleAction,
    *,
    kind: WorkerKind,
    actor: str,
) -> WorkerMTLSStateRead:
    worker = _lock_worker(db, worker, kind)
    if worker.mtls_revision != payload.expected_revision:
        raise ValueError("Worker mTLS revision conflict")
    revoked = worker.mtls_fingerprint_sha256
    staged = worker.mtls_next_fingerprint_sha256
    if revoked is None and staged is None:
        raise ValueError("Worker has no mTLS identity to revoke")
    worker.mtls_fingerprint_sha256 = None
    worker.mtls_subject_sha256 = None
    worker.mtls_serial_sha256 = None
    worker.mtls_not_after = None
    worker.mtls_activated_at = None
    _clear_next(worker)
    worker.mtls_revision += 1
    _, worker.auth_token_hash = issue_worker_token()
    worker.token_issued_at = utcnow()
    worker.state = (
        CollectorWorkerState.OFFLINE
        if kind == "collector"
        else AgentWorkerState.OFFLINE
    )
    record_audit_event(
        db,
        event_type=f"{kind}.worker.mtls_revoked",
        actor_type="user",
        actor_id=actor,
        entity_type=f"{kind}_worker",
        entity_id=worker.id,
        details={
            "revision": worker.mtls_revision,
            "revoked_fingerprint_sha256": revoked,
            "cancelled_fingerprint_sha256": staged,
            "bearer_token_invalidated": True,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(worker)
    return _state_read(worker, kind)
