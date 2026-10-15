from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from pydantic import ValidationError
from sqlalchemy import and_, event, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..capability_promotion_schemas import (
    CapabilityPromotionAcceptCreate,
    CapabilityPromotionReceiptRead,
    SignedCapabilityPromotionAttestation,
)
from ..config import get_settings
from ..database import require_locking_transaction, session_namespace
from ..credentials import (
    CredentialProvider,
    CredentialUnavailable,
    resolve_server_secret,
)
from ..ecosystem_transport_schemas import (
    EcosystemTransportEndpointCreate,
    EcosystemTransportEndpointStateCreate,
    EcosystemTransportGossipDispatchCreate,
    EcosystemTransportTLSUpdate,
    EcosystemTransportPromotionCreate,
    EcosystemTransportWitnessDispatchCreate,
    WitnessCheckpointSignRequest,
)
from ..models import (
    CapabilityTransparencyCheckpointOffer,
    CapabilityTransparencyWitness,
    CapabilityTransparencyWitnessAttestation,
    CredentialProfile,
    EcosystemTransportEndpoint,
    EcosystemTransportEndpointKind,
    EcosystemTransportJob,
    EcosystemTransportJobKind,
    EcosystemTransportJobStatus,
    EcosystemTransportWorker,
    EcosystemTransportWorkerState,
    utcnow,
)
from ..transparency_witness_schemas import (
    SignedTransparencyWitnessAttestation,
    TransparencyAttestationIngestCreate,
    TransparencyCheckpointStatement,
    TransparencyGossipIngestCreate,
    TransparencyGossipObservationRead,
)
from .audit import record_audit_event
from .transparency_witnessing import (export_checkpoint_gossip, get_witness_policy,
    ingest_checkpoint_attestation, lock_witness_authority, lock_witness_sequence,
    _checkpoint_from_offer, _verify_witness_attestation)
from .trust_authority import lock_publisher_resource


TRANSPORT_ADAPTER = "ecosystem_transport"
TRANSPORT_STALE_SECONDS = 90


class EcosystemTransportPermanentError(ValueError):
    """A retry cannot repair this immutable delivery or endpoint binding."""


class EcosystemTransportLeaseLost(RuntimeError):
    """A stale worker may not update a job now owned by another worker."""


class EcosystemTransportUnavailable(RuntimeError):
    """A remote or credential backend failure may succeed on retry."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for ecosystem transport",
            headers,
            fp,
        )


@dataclass(frozen=True)
class EcosystemTransportAssignment:
    job_id: str
    lease_token: str
    lease_expires_at: datetime


@dataclass(frozen=True)
class EcosystemTransportTLSBinding:
    context: Any
    evidence: dict[str, Any]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        normalized = pattern.rstrip(".").lower()
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def validate_ecosystem_transport_url(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Ecosystem transport endpoints must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("Ecosystem transport URLs must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError(
            "Ecosystem transport URLs must not contain query or fragment data"
        )
    configured = (
        get_settings().ecosystem_transport_allowed_host_list
        if allowed_hosts is None
        else allowed_hosts
    )
    if not _host_allowed(parsed.hostname, configured):
        raise ValueError(
            "Ecosystem transport host is not in "
            "ICHECK_ECOSYSTEM_TRANSPORT_ALLOWED_HOSTS"
        )
    return url


def _credential_profile(
    db: Session,
    reference: str,
    *, lock: bool = False,
) -> CredentialProfile | None:
    query = select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        ).execution_options(populate_existing=True)
    if lock:
        query = query.with_for_update(read=True)
    return db.scalar(query)


def _transport_transaction(db: Session) -> None:
    require_locking_transaction(db, purpose="Ecosystem transport leases and receipts")
    if db.get_bind().dialect.name == "postgresql" and session_namespace(db) is None:
        raise ValueError("Ecosystem transport requires its bound namespace")


def _locked_endpoint(db: Session, endpoint_id: str, *, writable: bool = False) -> EcosystemTransportEndpoint:
    _transport_transaction(db)
    endpoint = db.scalar(select(EcosystemTransportEndpoint).where(EcosystemTransportEndpoint.id == endpoint_id)
        .with_for_update(read=not writable).execution_options(populate_existing=True))
    if endpoint is None:
        raise LookupError("Ecosystem transport endpoint not found")
    return endpoint


def _lock_transport_credentials(db: Session, endpoint: EcosystemTransportEndpoint) -> None:
    references = {value for value in (endpoint.credential_profile_ref, endpoint.tls_ca_certificate_ref,
        endpoint.tls_client_certificate_ref, endpoint.tls_client_private_key_ref,
        endpoint.tls_client_private_key_password_ref) if value}
    identities = {}
    for reference in references:
        profile = _credential_profile(db, reference)
        if profile is None:
            raise EcosystemTransportUnavailable("Transport credential profile is unavailable")
        identities[reference] = profile.id
    for identity in sorted(set(identities.values())):
        profile = db.scalar(select(CredentialProfile).where(CredentialProfile.id == identity)
            .with_for_update(read=True).execution_options(populate_existing=True))
        if profile is None:
            raise EcosystemTransportUnavailable("Transport credential profile disappeared")
    for reference, identity in identities.items():
        profile = _credential_profile(db, reference)
        if profile is None or profile.id != identity:
            raise EcosystemTransportPermanentError("Transport credential identity changed during locking")
        _validate_credential_reference(db, reference)


def _validate_credential_reference(
    db: Session,
    reference: str | None,
) -> None:
    if not reference:
        return
    profile = _credential_profile(db, reference)
    if profile is None:
        raise ValueError(f"Credential profile {reference!r} does not exist")
    if not profile.enabled:
        raise ValueError(f"Credential profile {reference!r} is disabled")
    if TRANSPORT_ADAPTER not in profile.allowed_adapters:
        raise ValueError(
            f"Credential profile {reference!r} does not allow "
            f"{TRANSPORT_ADAPTER!r}"
        )
    if profile.worker_selector:
        raise ValueError(
            "Ecosystem transport requires a server-side credential profile"
        )


def _validate_tls_references(
    db: Session,
    *,
    tls_mode: str,
    ca_reference: str | None,
    certificate_reference: str | None,
    private_key_reference: str | None,
    password_reference: str | None,
) -> None:
    for reference in (
        ca_reference,
        certificate_reference,
        private_key_reference,
        password_reference,
    ):
        _validate_credential_reference(db, reference)
    if tls_mode == "mutual_tls":
        if not certificate_reference or not private_key_reference:
            raise ValueError(
                "mutual_tls requires client certificate and private-key references"
            )
    elif tls_mode != "server_auth":
        raise ValueError("Unsupported ecosystem transport TLS mode")
    elif certificate_reference or private_key_reference or password_reference:
        raise ValueError(
            "Client certificate, private key, and password require mutual_tls"
        )
    if password_reference and not private_key_reference:
        raise ValueError(
            "Private-key password requires a private-key reference"
        )


def _endpoint_read(endpoint: EcosystemTransportEndpoint) -> dict[str, Any]:
    return {
        "id": endpoint.id,
        "name": endpoint.name,
        "kind": endpoint.kind,
        "url": endpoint.url,
        "credential_profile_ref": endpoint.credential_profile_ref,
        "credential_configured": bool(endpoint.credential_profile_ref),
        "tls_mode": endpoint.tls_mode,
        "tls_ca_certificate_ref": endpoint.tls_ca_certificate_ref,
        "tls_client_certificate_ref": endpoint.tls_client_certificate_ref,
        "tls_client_private_key_ref": endpoint.tls_client_private_key_ref,
        "tls_client_private_key_password_ref": (
            endpoint.tls_client_private_key_password_ref
        ),
        "custom_ca_configured": bool(endpoint.tls_ca_certificate_ref),
        "mutual_tls_configured": (
            endpoint.tls_mode == "mutual_tls"
            and bool(endpoint.tls_client_certificate_ref)
            and bool(endpoint.tls_client_private_key_ref)
        ),
        "tls_revision": endpoint.tls_revision,
        "witness_id": endpoint.witness_id,
        "target_environment_id": endpoint.target_environment_id,
        "target_stage": endpoint.target_stage,
        "target_region_id": endpoint.target_region_id,
        "auto_dispatch": endpoint.auto_dispatch,
        "enabled": endpoint.enabled,
        "request_timeout_seconds": endpoint.request_timeout_seconds,
        "max_response_bytes": endpoint.max_response_bytes,
        "created_by": endpoint.created_by,
        "created_at": endpoint.created_at,
        "updated_at": endpoint.updated_at,
    }


def transport_endpoint_document(
    endpoint: EcosystemTransportEndpoint,
) -> dict[str, Any]:
    return _endpoint_read(endpoint)


def create_transport_endpoint(
    db: Session,
    payload: EcosystemTransportEndpointCreate,
    *,
    actor: str,
    allowed_hosts: list[str] | None = None,
) -> EcosystemTransportEndpoint:
    validate_ecosystem_transport_url(payload.url, allowed_hosts=allowed_hosts)
    _validate_credential_reference(db, payload.credential_profile_ref)
    _validate_tls_references(
        db,
        tls_mode=payload.tls_mode,
        ca_reference=payload.tls_ca_certificate_ref,
        certificate_reference=payload.tls_client_certificate_ref,
        private_key_reference=payload.tls_client_private_key_ref,
        password_reference=payload.tls_client_private_key_password_ref,
    )
    if payload.kind == "transparency_witness":
        witness = db.get(CapabilityTransparencyWitness, payload.witness_id)
        if witness is None:
            raise ValueError("Transparency witness does not exist")
        if not witness.enabled:
            raise ValueError("Transparency witness is disabled")
    values = payload.model_dump(exclude={"created_by", "kind"})
    endpoint = EcosystemTransportEndpoint(
        **values,
        kind=EcosystemTransportEndpointKind(payload.kind),
        created_by=actor,
    )
    db.add(endpoint)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ecosystem.transport_endpoint.created",
            actor_type="user",
            actor_id=actor,
            entity_type="ecosystem_transport_endpoint",
            entity_id=endpoint.id,
            details={
                "name": endpoint.name,
                "kind": endpoint.kind.value,
                "hostname": urlsplit(endpoint.url).hostname,
                "credential_configured": bool(endpoint.credential_profile_ref),
                "tls_mode": endpoint.tls_mode,
                "custom_ca_configured": bool(
                    endpoint.tls_ca_certificate_ref
                ),
                "mutual_tls_configured": (
                    endpoint.tls_mode == "mutual_tls"
                ),
                "tls_revision": endpoint.tls_revision,
                "witness_id": endpoint.witness_id,
                "target_environment_id": endpoint.target_environment_id,
                "target_stage": endpoint.target_stage,
                "target_region_id": endpoint.target_region_id,
                "auto_dispatch": endpoint.auto_dispatch,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Ecosystem transport endpoint name already exists") from exc
    db.refresh(endpoint)
    return endpoint


def update_transport_endpoint_tls(
    db: Session,
    endpoint_id: str,
    payload: EcosystemTransportTLSUpdate,
    *,
    actor: str,
) -> EcosystemTransportEndpoint:
    endpoint = _locked_endpoint(db, endpoint_id, writable=True)
    if endpoint.tls_revision != payload.expected_tls_revision:
        raise ValueError("Ecosystem transport TLS revision conflict")
    _validate_tls_references(
        db,
        tls_mode=payload.tls_mode,
        ca_reference=payload.tls_ca_certificate_ref,
        certificate_reference=payload.tls_client_certificate_ref,
        private_key_reference=payload.tls_client_private_key_ref,
        password_reference=payload.tls_client_private_key_password_ref,
    )
    endpoint.tls_mode = payload.tls_mode
    endpoint.tls_ca_certificate_ref = payload.tls_ca_certificate_ref
    endpoint.tls_client_certificate_ref = payload.tls_client_certificate_ref
    endpoint.tls_client_private_key_ref = (
        payload.tls_client_private_key_ref
    )
    endpoint.tls_client_private_key_password_ref = (
        payload.tls_client_private_key_password_ref
    )
    endpoint.tls_revision += 1
    endpoint.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="ecosystem.transport_endpoint.tls_updated",
        actor_type="user",
        actor_id=actor,
        entity_type="ecosystem_transport_endpoint",
        entity_id=endpoint.id,
        details={
            "tls_mode": endpoint.tls_mode,
            "custom_ca_configured": bool(
                endpoint.tls_ca_certificate_ref
            ),
            "mutual_tls_configured": (
                endpoint.tls_mode == "mutual_tls"
            ),
            "tls_revision": endpoint.tls_revision,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(endpoint)
    return endpoint


def list_transport_endpoints(
    db: Session,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    return [
        _endpoint_read(item)
        for item in db.scalars(
            select(EcosystemTransportEndpoint)
            .order_by(EcosystemTransportEndpoint.name)
            .limit(limit)
        ).all()
    ]


def set_transport_endpoint_state(
    db: Session,
    endpoint_id: str,
    payload: EcosystemTransportEndpointStateCreate,
    *,
    actor: str,
) -> EcosystemTransportEndpoint:
    endpoint = _locked_endpoint(db, endpoint_id, writable=True)
    if (
        payload.auto_dispatch
        and endpoint.kind
        not in {
            EcosystemTransportEndpointKind.TRANSPARENCY_WITNESS,
            EcosystemTransportEndpointKind.GOSSIP_PEER,
        }
    ):
        raise ValueError(
            "Only witness and gossip endpoints support automatic dispatch"
        )
    if payload.enabled:
        validate_ecosystem_transport_url(endpoint.url)
        _validate_credential_reference(db, endpoint.credential_profile_ref)
        _validate_tls_references(
            db,
            tls_mode=endpoint.tls_mode,
            ca_reference=endpoint.tls_ca_certificate_ref,
            certificate_reference=endpoint.tls_client_certificate_ref,
            private_key_reference=endpoint.tls_client_private_key_ref,
            password_reference=endpoint.tls_client_private_key_password_ref,
        )
        if endpoint.kind == EcosystemTransportEndpointKind.TRANSPARENCY_WITNESS:
            witness = (
                db.get(CapabilityTransparencyWitness, endpoint.witness_id)
                if endpoint.witness_id
                else None
            )
            if witness is None or not witness.enabled:
                raise ValueError("Bound transparency witness is unavailable")
    endpoint.enabled = payload.enabled
    if payload.auto_dispatch is not None:
        endpoint.auto_dispatch = payload.auto_dispatch
    endpoint.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="ecosystem.transport_endpoint.state_changed",
        actor_type="user",
        actor_id=actor,
        entity_type="ecosystem_transport_endpoint",
        entity_id=endpoint.id,
        details={
            "enabled": endpoint.enabled,
            "auto_dispatch": endpoint.auto_dispatch,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(endpoint)
    return endpoint


def _stored_checkpoint(
    offer: CapabilityTransparencyCheckpointOffer,
) -> TransparencyCheckpointStatement:
    return _checkpoint_from_offer(offer)


def _validate_delivery_payload(db: Session, job: EcosystemTransportJob,
                               endpoint: EcosystemTransportEndpoint) -> None:
    """Validate immutable public material and retain its current trust fence."""
    kind = job.kind
    if kind == EcosystemTransportJobKind.PROMOTION_DELIVERY:
        if endpoint.kind != EcosystemTransportEndpointKind.PROMOTION_TARGET:
            raise EcosystemTransportPermanentError("Promotion job endpoint kind changed")
        signed = CapabilityPromotionAcceptCreate.model_validate(job.payload_snapshot).signed_attestation
        attestation = signed.attestation
        if (attestation.target_environment_id != endpoint.target_environment_id
                or attestation.target_stage != endpoint.target_stage
                or _digest(attestation.model_dump(mode="json", exclude={"digest_sha256"})) != attestation.digest_sha256
                or _as_utc(attestation.expires_at) <= utcnow()):
            raise EcosystemTransportPermanentError("Promotion envelope target, digest or expiry is invalid")
        subject = attestation.digest_sha256
    else:
        offer = db.get(CapabilityTransparencyCheckpointOffer, job.checkpoint_offer_id, populate_existing=True)
        if offer is None or _as_utc(offer.expires_at) <= utcnow():
            raise EcosystemTransportPermanentError("Transport checkpoint offer is unavailable or expired")
        checkpoint = _stored_checkpoint(offer)
        if kind == EcosystemTransportJobKind.WITNESS_CHECKPOINT:
            if endpoint.kind != EcosystemTransportEndpointKind.TRANSPARENCY_WITNESS:
                raise EcosystemTransportPermanentError("Witness job endpoint kind changed")
            request = WitnessCheckpointSignRequest.model_validate(job.payload_snapshot)
            if request.checkpoint != checkpoint or request.idempotency_key != job.dedupe_key:
                raise EcosystemTransportPermanentError("Witness request checkpoint binding changed")
            witness = db.get(CapabilityTransparencyWitness, endpoint.witness_id, populate_existing=True)
            if witness is None:
                raise EcosystemTransportPermanentError("Bound transparency witness disappeared")
            lock_witness_sequence(db, witness.witness_id, offer.log_id, offer.epoch)
            lock_witness_authority(db, [witness.witness_id])
            subject = checkpoint.digest_sha256
        elif kind == EcosystemTransportJobKind.GOSSIP_DELIVERY:
            if endpoint.kind != EcosystemTransportEndpointKind.GOSSIP_PEER:
                raise EcosystemTransportPermanentError("Gossip job endpoint kind changed")
            request = TransparencyGossipIngestCreate.model_validate(job.payload_snapshot)
            namespace = session_namespace(db)
            if (request.gossip.checkpoint != checkpoint
                    or endpoint.target_region_id == request.gossip.source_region
                    or (namespace is not None and request.gossip.source_region != namespace[1])):
                raise EcosystemTransportPermanentError("Gossip checkpoint or region binding changed")
            proofs = request.gossip.attestations
            identities = [proof.attestation.witness_id for proof in proofs]
            if len(identities) != len(set(identities)):
                raise EcosystemTransportPermanentError("Gossip witness identities are duplicated")
            lock_witness_authority(db, identities)
            for proof in proofs:
                _verify_witness_attestation(db, proof, checkpoint)
            if len(proofs) < get_witness_policy(db, create_if_missing=False).required_quorum:
                raise EcosystemTransportPermanentError("Gossip no longer satisfies current witness quorum")
            subject = _digest(request.gossip.model_dump(mode="json"))
        else:
            raise EcosystemTransportPermanentError("Unsupported ecosystem transport job kind")
    if job.dedupe_key != _job_dedupe(kind, endpoint.id, subject):
        raise EcosystemTransportPermanentError("Transport dedupe identity does not match public material")


def _commit_transport_result(db: Session, assignment: EcosystemTransportAssignment,
                             *, check=None) -> None:
    def before_commit(subject):
        subject.flush()
        if _as_utc(assignment.lease_expires_at) <= utcnow():
            raise EcosystemTransportLeaseLost("Ecosystem transport lease expired before result commit")
        if check is not None:
            check()
    event.listen(db, "before_commit", before_commit)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        event.remove(db, "before_commit", before_commit)


def _job_dedupe(
    kind: EcosystemTransportJobKind,
    endpoint_id: str,
    subject_digest: str,
) -> str:
    return hashlib.sha256(
        f"{kind.value}:{endpoint_id}:{subject_digest}".encode("ascii")
    ).hexdigest()


def _existing_or_add_job(
    db: Session,
    *,
    endpoint: EcosystemTransportEndpoint,
    kind: EcosystemTransportJobKind,
    subject_digest: str,
    payload_snapshot: dict[str, Any],
    checkpoint_offer_id: str | None,
    max_attempts: int,
    actor: str,
) -> EcosystemTransportJob:
    dedupe_key = _job_dedupe(kind, endpoint.id, subject_digest)
    lock_publisher_resource(db, "ecosystem-transport-dedupe", dedupe_key)
    existing = db.scalar(
        select(EcosystemTransportJob).where(
            EcosystemTransportJob.dedupe_key == dedupe_key
        ).execution_options(populate_existing=True)
    )
    if existing is not None:
        if existing.payload_snapshot != payload_snapshot:
            raise ValueError("Transport job dedupe key has different content")
        return existing
    job = EcosystemTransportJob(
        endpoint_id=endpoint.id,
        kind=kind,
        checkpoint_offer_id=checkpoint_offer_id,
        dedupe_key=dedupe_key,
        payload_snapshot=payload_snapshot,
        status=EcosystemTransportJobStatus.PENDING,
        max_attempts=max_attempts,
        created_by=actor,
    )
    db.add(job)
    db.flush()
    record_audit_event(
        db,
        event_type="ecosystem.transport_job.queued",
        actor_type="user" if actor != "system" else "system",
        actor_id=actor,
        entity_type="ecosystem_transport_job",
        entity_id=job.id,
        details={
            "endpoint_id": endpoint.id,
            "kind": kind.value,
            "subject_digest_sha256": subject_digest,
            "dedupe_key": dedupe_key,
        },
    )
    return job


def queue_witness_dispatch(
    db: Session,
    offer_id: str,
    payload: EcosystemTransportWitnessDispatchCreate,
    *,
    actor: str,
) -> list[EcosystemTransportJob]:
    _transport_transaction(db)
    offer = db.get(CapabilityTransparencyCheckpointOffer, offer_id)
    if offer is None:
        raise LookupError("Transparency checkpoint offer not found")
    if _as_utc(offer.expires_at) <= utcnow():
        raise ValueError("Transparency checkpoint offer has expired")
    statement = _stored_checkpoint(offer)
    query = select(EcosystemTransportEndpoint).where(
        EcosystemTransportEndpoint.kind
        == EcosystemTransportEndpointKind.TRANSPARENCY_WITNESS,
        EcosystemTransportEndpoint.enabled.is_(True),
    )
    if payload.endpoint_ids:
        query = query.where(
            EcosystemTransportEndpoint.id.in_(payload.endpoint_ids)
        )
    endpoints = list(db.scalars(query.order_by(EcosystemTransportEndpoint.id)
        .with_for_update(read=True).execution_options(populate_existing=True)).all())
    if payload.endpoint_ids and len(endpoints) != len(set(payload.endpoint_ids)):
        raise ValueError("One or more witness transport endpoints are unavailable")
    if not endpoints:
        raise ValueError("No enabled witness transport endpoints are configured")
    jobs: list[EcosystemTransportJob] = []
    try:
        for endpoint in endpoints:
            request = WitnessCheckpointSignRequest(
                checkpoint=statement,
                idempotency_key=_job_dedupe(
                    EcosystemTransportJobKind.WITNESS_CHECKPOINT,
                    endpoint.id,
                    offer.statement_digest_sha256,
                ),
            )
            jobs.append(
                _existing_or_add_job(
                    db,
                    endpoint=endpoint,
                    kind=EcosystemTransportJobKind.WITNESS_CHECKPOINT,
                    subject_digest=offer.statement_digest_sha256,
                    payload_snapshot=request.model_dump(mode="json"),
                    checkpoint_offer_id=offer.id,
                    max_attempts=payload.max_attempts,
                    actor=actor,
                )
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        return queue_witness_dispatch(db, offer_id, payload, actor=actor)
    for job in jobs:
        db.refresh(job)
    return jobs


def reconcile_automatic_witness_jobs(
    db: Session,
    *,
    limit: int = 200,
) -> int:
    endpoints = list(
        db.scalars(
            select(EcosystemTransportEndpoint).where(
                EcosystemTransportEndpoint.kind
                == EcosystemTransportEndpointKind.TRANSPARENCY_WITNESS,
                EcosystemTransportEndpoint.enabled.is_(True),
                EcosystemTransportEndpoint.auto_dispatch.is_(True),
            )
        ).all()
    )
    if not endpoints:
        return 0
    offers = list(
        db.scalars(
            select(CapabilityTransparencyCheckpointOffer)
            .where(CapabilityTransparencyCheckpointOffer.expires_at > utcnow())
            .order_by(CapabilityTransparencyCheckpointOffer.created_at.desc())
            .limit(limit)
        ).all()
    )
    created = 0
    for offer in offers:
        before = db.scalar(
            select(func.count(EcosystemTransportJob.id)).where(
                EcosystemTransportJob.checkpoint_offer_id == offer.id
            )
        ) or 0
        for offset in range(0, len(endpoints), 16):
            queue_witness_dispatch(db, offer.id, EcosystemTransportWitnessDispatchCreate(
                endpoint_ids=[item.id for item in endpoints[offset:offset + 16]], actor="system"), actor="system")
        after = db.scalar(
            select(func.count(EcosystemTransportJob.id)).where(
                EcosystemTransportJob.checkpoint_offer_id == offer.id
            )
        ) or 0
        created += max(0, after - before)
    return created


def queue_gossip_dispatch(
    db: Session,
    offer_id: str,
    payload: EcosystemTransportGossipDispatchCreate,
    *,
    actor: str,
    source_region: str | None = None,
) -> list[EcosystemTransportJob]:
    _transport_transaction(db)
    offer = db.get(CapabilityTransparencyCheckpointOffer, offer_id)
    if offer is None:
        raise LookupError("Transparency checkpoint offer not found")
    if _as_utc(offer.expires_at) <= utcnow():
        raise ValueError("Transparency checkpoint offer has expired")
    namespace = session_namespace(db)
    local_region = source_region or (namespace[1] if namespace else None)
    if not local_region:
        raise ValueError(
            "Gossip dispatch requires a bound source-region namespace"
        )
    gossip = export_checkpoint_gossip(
        db,
        offer_id,
        source_region=local_region,
    )
    gossip_digest = _digest(gossip.model_dump(mode="json"))
    query = select(EcosystemTransportEndpoint).where(
        EcosystemTransportEndpoint.kind
        == EcosystemTransportEndpointKind.GOSSIP_PEER,
        EcosystemTransportEndpoint.enabled.is_(True),
    )
    if payload.endpoint_ids:
        query = query.where(
            EcosystemTransportEndpoint.id.in_(payload.endpoint_ids)
        )
    endpoints = list(db.scalars(query.order_by(EcosystemTransportEndpoint.id)
        .with_for_update(read=True).execution_options(populate_existing=True)).all())
    if payload.endpoint_ids and len(endpoints) != len(set(payload.endpoint_ids)):
        raise ValueError("One or more gossip transport endpoints are unavailable")
    if not endpoints:
        raise ValueError("No enabled gossip transport endpoints are configured")
    request = TransparencyGossipIngestCreate(
        gossip=gossip,
        reason="Deliver a quorum-backed regional transparency checkpoint.",
        actor=f"ecosystem.transport:{local_region}"[:255],
    )
    jobs: list[EcosystemTransportJob] = []
    try:
        for endpoint in endpoints:
            if endpoint.target_region_id == local_region:
                raise ValueError("Gossip target region must differ from source")
            jobs.append(
                _existing_or_add_job(
                    db,
                    endpoint=endpoint,
                    kind=EcosystemTransportJobKind.GOSSIP_DELIVERY,
                    subject_digest=gossip_digest,
                    payload_snapshot=request.model_dump(mode="json"),
                    checkpoint_offer_id=offer.id,
                    max_attempts=payload.max_attempts,
                    actor=actor,
                )
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        return queue_gossip_dispatch(
            db,
            offer_id,
            payload,
            actor=actor,
            source_region=local_region,
        )
    for job in jobs:
        db.refresh(job)
    return jobs


def reconcile_automatic_gossip_jobs(
    db: Session,
    *,
    limit: int = 200,
    source_region: str | None = None,
) -> int:
    endpoints = list(
        db.scalars(
            select(EcosystemTransportEndpoint).where(
                EcosystemTransportEndpoint.kind
                == EcosystemTransportEndpointKind.GOSSIP_PEER,
                EcosystemTransportEndpoint.enabled.is_(True),
                EcosystemTransportEndpoint.auto_dispatch.is_(True),
            )
        ).all()
    )
    if not endpoints:
        return 0
    offers = list(
        db.scalars(
            select(CapabilityTransparencyCheckpointOffer)
            .where(CapabilityTransparencyCheckpointOffer.expires_at > utcnow())
            .order_by(CapabilityTransparencyCheckpointOffer.created_at.desc())
            .limit(limit)
        ).all()
    )
    created = 0
    for offer in offers:
        before = db.scalar(
            select(func.count(EcosystemTransportJob.id)).where(
                EcosystemTransportJob.checkpoint_offer_id == offer.id,
                EcosystemTransportJob.kind
                == EcosystemTransportJobKind.GOSSIP_DELIVERY,
            )
        ) or 0
        try:
            for offset in range(0, len(endpoints), 16):
                queue_gossip_dispatch(db, offer.id, EcosystemTransportGossipDispatchCreate(
                    endpoint_ids=[item.id for item in endpoints[offset:offset + 16]], actor="system"),
                    actor="system", source_region=source_region)
        except ValueError as exc:
            if "has not reached witness quorum" in str(exc):
                continue
            raise
        after = db.scalar(
            select(func.count(EcosystemTransportJob.id)).where(
                EcosystemTransportJob.checkpoint_offer_id == offer.id,
                EcosystemTransportJob.kind
                == EcosystemTransportJobKind.GOSSIP_DELIVERY,
            )
        ) or 0
        created += max(0, after - before)
    return created


def queue_promotion_delivery(
    db: Session,
    payload: EcosystemTransportPromotionCreate,
    *,
    actor: str,
) -> EcosystemTransportJob:
    endpoint = _locked_endpoint(db, payload.endpoint_id)
    if not endpoint.enabled:
        raise ValueError("Ecosystem transport endpoint is disabled")
    if endpoint.kind != EcosystemTransportEndpointKind.PROMOTION_TARGET:
        raise ValueError("Endpoint is not a promotion target")
    signed = payload.signed_attestation
    attestation = signed.attestation
    if (
        endpoint.target_environment_id != attestation.target_environment_id
        or endpoint.target_stage != attestation.target_stage
    ):
        raise ValueError("Promotion target does not match endpoint binding")
    if _digest(
        attestation.model_dump(mode="json", exclude={"digest_sha256"})
    ) != attestation.digest_sha256:
        raise ValueError("Promotion attestation digest does not match")
    remote_actor = f"ecosystem.transport:{endpoint.name}"[:255]
    request_payload = {
        "signed_attestation": signed.model_dump(mode="json"),
        "reason": payload.reason,
        "actor": remote_actor,
    }
    try:
        job = _existing_or_add_job(
            db,
            endpoint=endpoint,
            kind=EcosystemTransportJobKind.PROMOTION_DELIVERY,
            subject_digest=attestation.digest_sha256,
            payload_snapshot=request_payload,
            checkpoint_offer_id=None,
            max_attempts=payload.max_attempts,
            actor=actor,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        return queue_promotion_delivery(db, payload, actor=actor)
    db.refresh(job)
    return job


def _job_read(job: EcosystemTransportJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "endpoint_id": job.endpoint_id,
        "endpoint_name": job.endpoint.name,
        "kind": job.kind,
        "checkpoint_offer_id": job.checkpoint_offer_id,
        "dedupe_key": job.dedupe_key,
        "status": job.status,
        "attempt_count": job.attempt_count,
        "max_attempts": job.max_attempts,
        "next_attempt_at": job.next_attempt_at,
        "lease_worker_id": job.lease_worker_id,
        "lease_expires_at": job.lease_expires_at,
        "response_digest_sha256": job.response_digest_sha256,
        "result_summary": job.result_summary,
        "error_type": job.error_type,
        "error_sha256": job.error_sha256,
        "created_by": job.created_by,
        "completed_at": job.completed_at,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }


def transport_job_document(job: EcosystemTransportJob) -> dict[str, Any]:
    return _job_read(job)


def list_transport_jobs(
    db: Session,
    *,
    limit: int,
    status: EcosystemTransportJobStatus | None = None,
) -> list[dict[str, Any]]:
    query = select(EcosystemTransportJob)
    if status is not None:
        query = query.where(EcosystemTransportJob.status == status)
    jobs = list(
        db.scalars(
            query.order_by(EcosystemTransportJob.created_at.desc()).limit(limit)
        ).all()
    )
    return [_job_read(item) for item in jobs]


def register_transport_worker(
    db: Session,
    *,
    name: str,
) -> EcosystemTransportWorker:
    _transport_transaction(db)
    normalized = name.strip()
    if not normalized:
        raise ValueError("Ecosystem transport worker name is required")
    if len(normalized) > 255:
        raise ValueError("Ecosystem transport worker name exceeds 255 characters")
    lock_publisher_resource(db, "ecosystem-transport-worker", normalized)
    worker = db.scalar(
        select(EcosystemTransportWorker).where(
            EcosystemTransportWorker.name == normalized
        ).with_for_update().execution_options(populate_existing=True)
    )
    if worker is None:
        worker = EcosystemTransportWorker(name=normalized)
        db.add(worker)
    worker.state = EcosystemTransportWorkerState.ONLINE
    worker.last_heartbeat_at = utcnow()
    db.commit()
    db.refresh(worker)
    return worker


def claim_transport_jobs(
    db: Session,
    worker: EcosystemTransportWorker,
    *,
    limit: int,
    lease_seconds: int,
) -> list[EcosystemTransportAssignment]:
    _transport_transaction(db)
    worker = db.scalar(select(EcosystemTransportWorker).where(EcosystemTransportWorker.id == worker.id)
        .with_for_update().execution_options(populate_existing=True))
    if worker is None:
        raise LookupError("Ecosystem transport worker not found")
    if worker.state != EcosystemTransportWorkerState.ONLINE:
        raise ValueError("Ecosystem transport worker is not online")
    if not 1 <= limit <= 100:
        raise ValueError("Transport claim limit must be between 1 and 100")
    if not 15 <= lease_seconds <= 3600:
        raise ValueError("Transport lease must be between 15 and 3600 seconds")
    now = utcnow()
    worker.last_heartbeat_at = now
    ready = and_(
        EcosystemTransportJob.status.in_(
            [
                EcosystemTransportJobStatus.PENDING,
                EcosystemTransportJobStatus.RETRY,
            ]
        ),
        EcosystemTransportJob.next_attempt_at <= now,
    )
    abandoned = and_(
        EcosystemTransportJob.status
        == EcosystemTransportJobStatus.PROCESSING,
        EcosystemTransportJob.lease_expires_at.is_not(None),
        EcosystemTransportJob.lease_expires_at <= now,
    )
    jobs = list(
        db.scalars(
            select(EcosystemTransportJob)
            .where(or_(ready, abandoned))
            .order_by(
                EcosystemTransportJob.next_attempt_at,
                EcosystemTransportJob.created_at,
                EcosystemTransportJob.id,
            )
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
            .limit(limit)
        ).all()
    )
    assignments: list[EcosystemTransportAssignment] = []
    for job in jobs:
        if (
            job.status == EcosystemTransportJobStatus.PROCESSING
            and job.attempt_count >= job.max_attempts
        ):
            message = "Transport lease expired at the maximum attempt count"
            job.status = EcosystemTransportJobStatus.DEAD_LETTER
            job.error_type = "EcosystemTransportLeaseExpired"
            job.error_sha256 = hashlib.sha256(
                message.encode("utf-8")
            ).hexdigest()
            job.completed_at = now
            _clear_lease(job)
            continue
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=lease_seconds)
        job.status = EcosystemTransportJobStatus.PROCESSING
        job.attempt_count += 1
        job.lease_worker_id = worker.id
        job.lease_token_hash = _token_hash(token)
        job.lease_expires_at = expires_at
        job.completed_at = None
        assignments.append(
            EcosystemTransportAssignment(
                job_id=job.id,
                lease_token=token,
                lease_expires_at=expires_at,
            )
        )
    db.commit()
    return assignments


def _active_job(
    db: Session,
    worker: EcosystemTransportWorker,
    assignment: EcosystemTransportAssignment,
) -> EcosystemTransportJob:
    _transport_transaction(db)
    job = db.scalar(select(EcosystemTransportJob).where(EcosystemTransportJob.id == assignment.job_id)
        .with_for_update().execution_options(populate_existing=True))
    if job is None:
        raise LookupError("Ecosystem transport job not found")
    if (
        job.status != EcosystemTransportJobStatus.PROCESSING
        or job.lease_worker_id != worker.id
        or not job.lease_token_hash
        or not hmac.compare_digest(
            job.lease_token_hash,
            _token_hash(assignment.lease_token),
        )
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= utcnow()
        or _as_utc(job.lease_expires_at) != _as_utc(assignment.lease_expires_at)
    ):
        raise EcosystemTransportLeaseLost(
            "Ecosystem transport job lease changed before commit"
        )
    return job


def _clear_lease(job: EcosystemTransportJob) -> None:
    job.lease_worker_id = None
    job.lease_token_hash = None
    job.lease_expires_at = None


def _authorization_header(
    db: Session,
    endpoint: EcosystemTransportEndpoint,
    *,
    credential_providers: Mapping[str, CredentialProvider] | None,
) -> str | None:
    if not endpoint.credential_profile_ref:
        return None
    profile = _credential_profile(db, endpoint.credential_profile_ref)
    if profile is None:
        raise EcosystemTransportUnavailable(
            "Configured transport credential profile is unavailable"
        )
    try:
        token = resolve_server_secret(
            profile,
            adapter_type=TRANSPORT_ADAPTER,
            providers=credential_providers,
        )
    except CredentialUnavailable as exc:
        raise EcosystemTransportUnavailable(str(exc)) from exc
    if "\r" in token or "\n" in token:
        raise EcosystemTransportPermanentError(
            "Transport credential contains invalid header characters"
        )
    return f"Bearer {token}"


def _resolve_transport_secret(
    db: Session,
    reference: str,
    *,
    purpose: str,
    adapter_type: str = TRANSPORT_ADAPTER,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
) -> str:
    profile = _credential_profile(db, reference)
    if profile is None:
        raise EcosystemTransportUnavailable(
            f"Configured {purpose} credential profile is unavailable"
        )
    try:
        return resolve_server_secret(
            profile,
            adapter_type=adapter_type,
            providers=credential_providers,
        )
    except CredentialUnavailable as exc:
        raise EcosystemTransportUnavailable(
            f"Configured {purpose} could not be resolved"
        ) from exc


def _require_certificate_pem(value: str, *, purpose: str) -> None:
    if "\x00" in value or "-----BEGIN CERTIFICATE-----" not in value:
        raise EcosystemTransportPermanentError(
            f"Configured {purpose} is not a PEM certificate"
        )


def _require_private_key_pem(value: str) -> None:
    if (
        "\x00" in value
        or "-----BEGIN " not in value
        or "PRIVATE KEY-----" not in value
    ):
        raise EcosystemTransportPermanentError(
            "Configured TLS private key is not PEM encoded"
        )


def _memory_file_descriptor(name: str, value: str) -> int:
    if not hasattr(os, "memfd_create"):
        raise EcosystemTransportPermanentError(
            "Memory-only TLS key loading requires Linux memfd support"
        )
    flags = getattr(os, "MFD_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.memfd_create(name, flags)
        os.fchmod(descriptor, 0o400)
        encoded = value.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise EcosystemTransportUnavailable(
            "Unable to prepare memory-only TLS identity"
        ) from exc


def build_transport_tls_context(
    db: Session,
    endpoint: Any,
    *,
    adapter_type: str = TRANSPORT_ADAPTER,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
    context_factory: Any | None = None,
) -> EcosystemTransportTLSBinding:
    factory = context_factory or ssl.create_default_context
    context = factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    ca_digest: str | None = None
    if endpoint.tls_ca_certificate_ref:
        ca_certificate = _resolve_transport_secret(
            db,
            endpoint.tls_ca_certificate_ref,
            purpose="TLS CA certificate",
            adapter_type=adapter_type,
            credential_providers=credential_providers,
        )
        _require_certificate_pem(
            ca_certificate,
            purpose="TLS CA certificate",
        )
        try:
            context.load_verify_locations(cadata=ca_certificate)
        except (OSError, ValueError, ssl.SSLError) as exc:
            raise EcosystemTransportPermanentError(
                "Configured TLS CA certificate could not be loaded"
            ) from exc
        ca_digest = hashlib.sha256(
            ca_certificate.encode("utf-8")
        ).hexdigest()

    client_certificate_digest: str | None = None
    if endpoint.tls_mode == "mutual_tls":
        if (
            not endpoint.tls_client_certificate_ref
            or not endpoint.tls_client_private_key_ref
        ):
            raise EcosystemTransportPermanentError(
                "mutual_tls endpoint has an incomplete client identity"
            )
        client_certificate = _resolve_transport_secret(
            db,
            endpoint.tls_client_certificate_ref,
            purpose="TLS client certificate",
            adapter_type=adapter_type,
            credential_providers=credential_providers,
        )
        private_key = _resolve_transport_secret(
            db,
            endpoint.tls_client_private_key_ref,
            purpose="TLS private key",
            adapter_type=adapter_type,
            credential_providers=credential_providers,
        )
        password = (
            _resolve_transport_secret(
                db,
                endpoint.tls_client_private_key_password_ref,
                purpose="TLS private-key password",
                adapter_type=adapter_type,
                credential_providers=credential_providers,
            )
            if endpoint.tls_client_private_key_password_ref
            else None
        )
        _require_certificate_pem(
            client_certificate,
            purpose="TLS client certificate",
        )
        _require_private_key_pem(private_key)
        certificate_fd = _memory_file_descriptor(
            "icheck-client-certificate",
            client_certificate,
        )
        try:
            private_key_fd = _memory_file_descriptor(
                "icheck-client-private-key",
                private_key,
            )
            try:
                context.load_cert_chain(
                    certfile=f"/proc/self/fd/{certificate_fd}",
                    keyfile=f"/proc/self/fd/{private_key_fd}",
                    password=password,
                )
            except (OSError, ValueError, ssl.SSLError) as exc:
                raise EcosystemTransportPermanentError(
                    "Configured TLS client identity could not be loaded"
                ) from exc
            finally:
                os.close(private_key_fd)
        finally:
            os.close(certificate_fd)
        client_certificate_digest = hashlib.sha256(
            client_certificate.encode("utf-8")
        ).hexdigest()
    elif endpoint.tls_mode != "server_auth":
        raise EcosystemTransportPermanentError(
            "Endpoint has an unsupported TLS mode"
        )

    return EcosystemTransportTLSBinding(
        context=context,
        evidence={
            "mode": endpoint.tls_mode,
            "tls_revision": endpoint.tls_revision,
            "minimum_version": "TLSv1.2",
            "hostname_verification": True,
            "custom_ca_sha256": ca_digest,
            "client_certificate_sha256": client_certificate_digest,
        },
    )


def _post_json(
    endpoint: EcosystemTransportEndpoint,
    payload: dict[str, Any],
    *,
    authorization: str | None,
    idempotency_key: str,
    opener: Any | None,
    tls_context: Any,
    timeout_seconds: float | None = None,
) -> tuple[dict[str, Any], str]:
    validate_ecosystem_transport_url(endpoint.url)
    encoded = _canonical_bytes(payload)
    if len(encoded) > 5_000_000:
        raise EcosystemTransportPermanentError("Transport request exceeds its byte limit")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "iCheck-Ecosystem-Transport/1",
        "X-iCheck-Idempotency-Key": idempotency_key,
    }
    if authorization:
        headers["Authorization"] = authorization
    request = Request(
        endpoint.url,
        data=encoded,
        headers=headers,
        method="POST",
    )
    client = opener or build_opener(
        _NoRedirect(),
        HTTPSHandler(context=tls_context),
    ).open
    try:
        response = client(request, timeout=timeout_seconds or endpoint.request_timeout_seconds)
        with response:
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise EcosystemTransportPermanentError(
                    "Transport response must use application/json"
                )
            raw = response.read(endpoint.max_response_bytes + 1)
    except HTTPError as exc:
        if exc.code in {408, 425, 429} or exc.code >= 500:
            raise EcosystemTransportUnavailable(
                f"Transport endpoint returned HTTP {exc.code}"
            ) from exc
        raise EcosystemTransportPermanentError(
            f"Transport endpoint rejected request with HTTP {exc.code}"
        ) from exc
    except (TimeoutError, URLError, OSError) as exc:
        raise EcosystemTransportUnavailable(
            f"Transport endpoint is unavailable: {type(exc).__name__}"
        ) from exc
    if len(raw) > endpoint.max_response_bytes:
        raise EcosystemTransportPermanentError(
            "Transport response exceeds the configured byte limit"
        )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EcosystemTransportPermanentError(
            "Transport response is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise EcosystemTransportPermanentError(
            "Transport response must be a JSON object"
        )
    return document, hashlib.sha256(raw).hexdigest()


def _finish_success(
    db: Session,
    worker: EcosystemTransportWorker,
    assignment: EcosystemTransportAssignment,
    *,
    response_digest_sha256: str,
    result_summary: dict[str, Any],
    response_check: Any | None = None,
) -> EcosystemTransportJob:
    job = _active_job(db, worker, assignment)
    job.status = EcosystemTransportJobStatus.SUCCEEDED
    job.response_digest_sha256 = response_digest_sha256
    job.result_summary = result_summary
    job.error_type = None
    job.error_sha256 = None
    job.completed_at = utcnow()
    _clear_lease(job)
    record_audit_event(
        db,
        event_type="ecosystem.transport_job.succeeded",
        actor_type="service",
        actor_id=worker.name,
        entity_type="ecosystem_transport_job",
        entity_id=job.id,
        details={
            "endpoint_id": job.endpoint_id,
            "kind": job.kind.value,
            "attempt_count": job.attempt_count,
            "response_digest_sha256": response_digest_sha256,
            "result_summary": result_summary,
        },
    )
    def check():
        _validate_delivery_payload(db, job, job.endpoint)
        if response_check is not None:
            response_check()
    _commit_transport_result(db, assignment, check=check)
    db.refresh(job)
    return job


def _record_failure(
    db: Session,
    worker: EcosystemTransportWorker,
    assignment: EcosystemTransportAssignment,
    *,
    permanent: bool,
    error: Exception,
) -> EcosystemTransportJob:
    db.rollback()
    job = _active_job(db, worker, assignment)
    message = str(error) or type(error).__name__
    job.error_type = type(error).__name__[:255]
    job.error_sha256 = hashlib.sha256(message.encode("utf-8")).hexdigest()
    job.result_summary = {}
    _clear_lease(job)
    if permanent or job.attempt_count >= job.max_attempts:
        job.status = EcosystemTransportJobStatus.DEAD_LETTER
        job.completed_at = utcnow()
    else:
        job.status = EcosystemTransportJobStatus.RETRY
        delay_seconds = min(300, 2 ** min(job.attempt_count, 8))
        job.next_attempt_at = utcnow() + timedelta(seconds=delay_seconds)
        job.completed_at = None
    _commit_transport_result(db, assignment)
    db.refresh(job)
    return job


def _process_witness_response(
    db: Session,
    job: EcosystemTransportJob,
    document: dict[str, Any],
    *,
    worker: EcosystemTransportWorker,
) -> dict[str, Any]:
    if not job.checkpoint_offer_id:
        raise EcosystemTransportPermanentError(
            "Witness job has no checkpoint offer binding"
        )
    try:
        signed = SignedTransparencyWitnessAttestation.model_validate(document)
    except ValidationError as exc:
        raise EcosystemTransportPermanentError(
            "Witness response contract is invalid"
        ) from exc
    endpoint = job.endpoint
    witness = (
        db.get(CapabilityTransparencyWitness, endpoint.witness_id)
        if endpoint.witness_id
        else None
    )
    if witness is None or not witness.enabled:
        raise EcosystemTransportPermanentError(
            "Bound transparency witness is unavailable"
        )
    if signed.attestation.witness_id != witness.witness_id:
        raise EcosystemTransportPermanentError(
            "Witness response identity does not match endpoint binding"
        )
    existing = db.scalar(
        select(CapabilityTransparencyWitnessAttestation).where(
            CapabilityTransparencyWitnessAttestation.checkpoint_offer_id
            == job.checkpoint_offer_id,
            CapabilityTransparencyWitnessAttestation.witness_id == witness.id,
        )
    )
    snapshot = signed.model_dump(mode="json")
    offer = db.get(CapabilityTransparencyCheckpointOffer, job.checkpoint_offer_id, populate_existing=True)
    _verify_witness_attestation(db, signed, _stored_checkpoint(offer))
    if existing is not None:
        if existing.signed_attestation_snapshot != snapshot:
            raise EcosystemTransportPermanentError(
                "Witness returned conflicting evidence for this checkpoint"
            )
        return {
            "witness_attestation_id": existing.id,
            "witness_id": witness.witness_id,
            "attestation_digest_sha256": existing.attestation_digest_sha256,
            "idempotent": True,
        }
    try:
        row = ingest_checkpoint_attestation(
            db,
            job.checkpoint_offer_id,
            TransparencyAttestationIngestCreate(
                signed_attestation=signed,
                actor=f"ecosystem.transport:{worker.name}"[:255],
            ),
            actor=f"ecosystem.transport:{worker.name}"[:255],
            commit=False,
        )
    except (LookupError, ValueError) as exc:
        raise EcosystemTransportPermanentError(str(exc)) from exc
    return {
        "witness_attestation_id": row.id,
        "witness_id": witness.witness_id,
        "attestation_digest_sha256": row.attestation_digest_sha256,
        "idempotent": False,
    }


def _process_promotion_response(
    job: EcosystemTransportJob,
    document: dict[str, Any],
) -> dict[str, Any]:
    try:
        receipt = CapabilityPromotionReceiptRead.model_validate(document)
        signed = SignedCapabilityPromotionAttestation.model_validate(
            job.payload_snapshot["signed_attestation"]
        )
    except (KeyError, ValidationError) as exc:
        raise EcosystemTransportPermanentError(
            "Promotion receipt contract is invalid"
        ) from exc
    attestation = signed.attestation
    endpoint = job.endpoint
    expected = {
        "source_environment_id": attestation.source_environment_id,
        "target_environment_id": endpoint.target_environment_id,
        "target_stage": endpoint.target_stage,
        "promotion_sequence": attestation.promotion_sequence,
        "pack_digest_sha256": attestation.pack_digest_sha256,
        "statement_digest_sha256": attestation.digest_sha256,
    }
    actual = {
        key: getattr(receipt, key)
        for key in expected
    }
    if actual != expected:
        raise EcosystemTransportPermanentError(
            "Promotion receipt does not match the signed target binding"
        )
    return {
        "promotion_receipt_id": receipt.id,
        "source_environment_id": receipt.source_environment_id,
        "target_environment_id": receipt.target_environment_id,
        "target_stage": receipt.target_stage,
        "promotion_sequence": receipt.promotion_sequence,
        "pack_digest_sha256": receipt.pack_digest_sha256,
        "statement_digest_sha256": receipt.statement_digest_sha256,
    }


def _process_gossip_response(
    job: EcosystemTransportJob,
    document: dict[str, Any],
) -> dict[str, Any]:
    try:
        request = TransparencyGossipIngestCreate.model_validate(
            job.payload_snapshot
        )
        observation = TransparencyGossipObservationRead.model_validate(document)
    except ValidationError as exc:
        raise EcosystemTransportPermanentError(
            "Gossip observation receipt contract is invalid"
        ) from exc
    checkpoint = request.gossip.checkpoint
    expected = {
        "source_region": request.gossip.source_region,
        "log_id": checkpoint.log_id,
        "epoch": checkpoint.epoch,
        "sequence": checkpoint.sequence,
        "head_digest_sha256": checkpoint.head_digest_sha256,
        "checkpoint_statement_digest_sha256": checkpoint.digest_sha256,
        "document_digest_sha256": _digest(
            request.gossip.model_dump(mode="json")
        ),
        "witness_count": len(request.gossip.attestations),
    }
    actual = {key: getattr(observation, key) for key in expected}
    if actual != expected:
        raise EcosystemTransportPermanentError(
            "Gossip observation receipt does not match the delivered checkpoint"
        )
    expected_witnesses = sorted(
        item.attestation.witness_id for item in request.gossip.attestations
    )
    actual_witnesses = sorted(
        item.get("witness_id", "") for item in observation.witness_evidence
    )
    if actual_witnesses != expected_witnesses:
        raise EcosystemTransportPermanentError(
            "Gossip observation receipt does not match the delivered witnesses"
        )
    if observation.initial_status == "fork" and not observation.alert_id:
        raise EcosystemTransportPermanentError(
            "Remote fork receipt does not include mandatory alert evidence"
        )
    if observation.initial_status != "fork" and observation.alert_id:
        raise EcosystemTransportPermanentError(
            "Remote non-fork receipt contains unexpected alert evidence"
        )
    if not job.endpoint.target_region_id:
        raise EcosystemTransportPermanentError(
            "Gossip endpoint has no target-region binding"
        )
    return {
        "gossip_observation_id": observation.id,
        "target_region_id": job.endpoint.target_region_id,
        "source_region": observation.source_region,
        "log_id": observation.log_id,
        "epoch": observation.epoch,
        "sequence": observation.sequence,
        "head_digest_sha256": observation.head_digest_sha256,
        "document_digest_sha256": observation.document_digest_sha256,
        "initial_status": observation.initial_status,
        "current_status": observation.current_status,
        "remote_alert_id": observation.alert_id,
    }


def process_transport_assignment(
    db: Session,
    worker: EcosystemTransportWorker,
    assignment: EcosystemTransportAssignment,
    *,
    opener: Any | None = None,
    credential_providers: Mapping[str, CredentialProvider] | None = None,
    tls_context_factory: Any | None = None,
) -> EcosystemTransportJob:
    _transport_transaction(db)
    try:
        job = _active_job(db, worker, assignment)
        endpoint = _locked_endpoint(db, job.endpoint_id)
        if not endpoint.enabled:
            raise EcosystemTransportPermanentError(
                "Ecosystem transport endpoint is disabled"
            )
        _lock_transport_credentials(db, endpoint)
        _validate_delivery_payload(db, job, endpoint)
        authorization = _authorization_header(
            db,
            endpoint,
            credential_providers=credential_providers,
        )
        tls_binding = build_transport_tls_context(
            db,
            endpoint,
            credential_providers=credential_providers,
            context_factory=tls_context_factory,
        )
        _active_job(db, worker, assignment)
        remaining = (_as_utc(assignment.lease_expires_at) - utcnow()).total_seconds()
        if remaining <= 1:
            raise EcosystemTransportLeaseLost("Transport lease has insufficient time for remote I/O")
        document, response_digest = _post_json(
            endpoint,
            job.payload_snapshot,
            authorization=authorization,
            idempotency_key=job.dedupe_key,
            opener=opener,
            tls_context=tls_binding.context,
            timeout_seconds=min(endpoint.request_timeout_seconds, remaining - 1),
        )
        _active_job(db, worker, assignment)
        _validate_delivery_payload(db, job, endpoint)
        if job.kind == EcosystemTransportJobKind.WITNESS_CHECKPOINT:
            summary = _process_witness_response(
                db,
                job,
                document,
                worker=worker,
            )
        elif job.kind == EcosystemTransportJobKind.PROMOTION_DELIVERY:
            summary = _process_promotion_response(job, document)
        elif job.kind == EcosystemTransportJobKind.GOSSIP_DELIVERY:
            summary = _process_gossip_response(job, document)
        else:
            raise EcosystemTransportPermanentError(
                "Unsupported ecosystem transport job kind"
            )
        summary["transport_security"] = tls_binding.evidence
        return _finish_success(
            db,
            worker,
            assignment,
            response_digest_sha256=response_digest,
            result_summary=summary,
            response_check=(lambda: _verify_witness_attestation(db,
                SignedTransparencyWitnessAttestation.model_validate(document),
                _stored_checkpoint(db.get(CapabilityTransparencyCheckpointOffer,
                    job.checkpoint_offer_id, populate_existing=True))))
                if job.kind == EcosystemTransportJobKind.WITNESS_CHECKPOINT else None,
        )
    except EcosystemTransportLeaseLost:
        db.rollback()
        raise
    except (EcosystemTransportPermanentError, ValidationError, ValueError, KeyError, TypeError) as exc:
        return _record_failure(
            db,
            worker,
            assignment,
            permanent=True,
            error=exc,
        )
    except Exception as exc:
        return _record_failure(
            db,
            worker,
            assignment,
            permanent=False,
            error=exc,
        )


def retry_transport_job(
    db: Session,
    job_id: str,
    *,
    actor: str,
    reason: str,
) -> EcosystemTransportJob:
    _transport_transaction(db)
    job = db.scalar(select(EcosystemTransportJob).where(EcosystemTransportJob.id == job_id)
        .with_for_update().execution_options(populate_existing=True))
    if job is None:
        raise LookupError("Ecosystem transport job not found")
    if job.status in {
        EcosystemTransportJobStatus.PROCESSING,
        EcosystemTransportJobStatus.SUCCEEDED,
    }:
        raise ValueError("This transport job cannot be retried")
    job.status = EcosystemTransportJobStatus.PENDING
    job.attempt_count = 0
    job.next_attempt_at = utcnow()
    job.error_type = None
    job.error_sha256 = None
    job.result_summary = {}
    job.completed_at = None
    _clear_lease(job)
    record_audit_event(
        db,
        event_type="ecosystem.transport_job.retried",
        actor_type="user",
        actor_id=actor,
        entity_type="ecosystem_transport_job",
        entity_id=job.id,
        details={
            "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest()
        },
    )
    db.commit()
    db.refresh(job)
    return job


def cancel_transport_job(
    db: Session,
    job_id: str,
    *,
    actor: str,
    reason: str,
) -> EcosystemTransportJob:
    _transport_transaction(db)
    job = db.scalar(select(EcosystemTransportJob).where(EcosystemTransportJob.id == job_id)
        .with_for_update().execution_options(populate_existing=True))
    if job is None:
        raise LookupError("Ecosystem transport job not found")
    if job.status == EcosystemTransportJobStatus.PROCESSING:
        raise ValueError("A leased transport job cannot be cancelled")
    if job.status == EcosystemTransportJobStatus.SUCCEEDED:
        raise ValueError("A succeeded transport job cannot be cancelled")
    job.status = EcosystemTransportJobStatus.CANCELLED
    job.completed_at = utcnow()
    _clear_lease(job)
    record_audit_event(
        db,
        event_type="ecosystem.transport_job.cancelled",
        actor_type="user",
        actor_id=actor,
        entity_type="ecosystem_transport_job",
        entity_id=job.id,
        details={
            "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest()
        },
    )
    db.commit()
    db.refresh(job)
    return job


def list_transport_workers(
    db: Session,
    *,
    limit: int,
) -> list[EcosystemTransportWorker]:
    return list(
        db.scalars(
            select(EcosystemTransportWorker)
            .order_by(EcosystemTransportWorker.name)
            .limit(limit)
        ).all()
    )


def transport_health(db: Session) -> dict[str, Any]:
    now = utcnow()
    counts = {
        status.value: count
        for status, count in db.execute(
            select(
                EcosystemTransportJob.status,
                func.count(EcosystemTransportJob.id),
            ).group_by(EcosystemTransportJob.status)
        ).all()
    }
    stale_before = now - timedelta(seconds=TRANSPORT_STALE_SECONDS)
    workers_total = db.scalar(
        select(func.count()).select_from(EcosystemTransportWorker)
    ) or 0
    workers_online = db.scalar(
        select(func.count())
        .select_from(EcosystemTransportWorker)
        .where(
            EcosystemTransportWorker.state
            == EcosystemTransportWorkerState.ONLINE,
            EcosystemTransportWorker.last_heartbeat_at >= stale_before,
        )
    ) or 0
    oldest = db.scalar(
        select(func.min(EcosystemTransportJob.next_attempt_at)).where(
            EcosystemTransportJob.status.in_(
                [
                    EcosystemTransportJobStatus.PENDING,
                    EcosystemTransportJobStatus.RETRY,
                ]
            ),
            EcosystemTransportJob.next_attempt_at <= now,
        )
    )
    result: dict[str, Any] = {
        "workers_total": workers_total,
        "workers_online": workers_online,
        "workers_stale": workers_total - workers_online,
        "oldest_ready_age_seconds": (
            max(0.0, (now - _as_utc(oldest)).total_seconds())
            if oldest is not None
            else None
        ),
    }
    for status in EcosystemTransportJobStatus:
        result[status.value] = counts.get(status.value, 0)
    return result
