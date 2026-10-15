from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import require_locking_transaction
from ..models import (
    ArtifactTrustKey,
    AlertSeverity,
    CapabilityTransparencyCheckpointOffer,
    CapabilityTransparencyGossipObservation,
    CapabilityTransparencyRecord,
    CapabilityTransparencyState,
    CapabilityTransparencyWitness,
    CapabilityTransparencyWitnessAttestation,
    CapabilityTransparencyWitnessPolicy,
    utcnow,
)
from ..transparency_witness_schemas import (
    CHECKPOINT_STATEMENT_FORMAT,
    GOSSIP_FORMAT,
    SIGNED_WITNESS_ATTESTATION_FORMAT,
    TransparencyAttestationIngestCreate,
    TransparencyCheckpointOfferCreate,
    TransparencyCheckpointOfferRead,
    TransparencyCheckpointStatement,
    TransparencyGossipDocument,
    TransparencyForkAlertReconcileRead,
    TransparencyGossipIngestCreate,
    TransparencyGossipObservationRead,
    TransparencyWitnessCreate,
    TransparencyWitnessPolicyRead,
    TransparencyWitnessPolicyUpdate,
    TransparencyWitnessStateCreate,
    SignedTransparencyWitnessAttestation,
)
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .alerts import upsert_alert
from .audit import record_audit_event
from .capability_transparency import (
    get_capability_transparency_checkpoint,
    transparency_singleton_id,
)
from .promotion_authority import promotion_mutation, commit_with_promotion_authority
from .trust_authority import lock_publisher_resource, lock_trust_keys


WITNESS_CLOCK_SKEW = timedelta(minutes=5)
GOSSIP_MAX_BYTES = 1_000_000


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _json_timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def get_witness_policy(db: Session, *, create_if_missing: bool = True) -> CapabilityTransparencyWitnessPolicy:
    policy = db.get(CapabilityTransparencyWitnessPolicy, transparency_singleton_id(db))
    if policy is None:
        policy = CapabilityTransparencyWitnessPolicy(
            id=transparency_singleton_id(db),
            required_quorum=2,
            max_attestation_age_hours=168,
            updated_by="system",
        )
        if create_if_missing:
            db.add(policy)
            db.commit()
            db.refresh(policy)
    return policy


def lock_witness_authority(db: Session, external_ids: list[str]) -> None:
    """Current policy, witness pins and distributed/local public-key authority."""
    require_locking_transaction(db, purpose="Witness policy and signing authority")
    identity = transparency_singleton_id(db)
    lock_publisher_resource(db, "transparency-witness-policy", identity, shared=True)
    db.scalar(select(CapabilityTransparencyWitnessPolicy)
        .where(CapabilityTransparencyWitnessPolicy.id == identity).with_for_update(read=True)
        .execution_options(populate_existing=True))
    requirements = {}
    for external_id in sorted(set(external_ids)):
        witness = db.scalar(select(CapabilityTransparencyWitness)
            .where(CapabilityTransparencyWitness.witness_id == external_id).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if witness is None or not witness.enabled:
            raise ValueError("Transparency witness is not registered or enabled")
        requirements[witness.trust_key_id] = {"transparency_witness"}
    from .trust_authority import lock_trust_authorities
    lock_trust_authorities(db, requirements)


def lock_witness_sequence(db: Session, external_id: str, log_id: str, epoch: int) -> None:
    # Serialize the monotonic append check, including absent history. This must
    # precede shared policy/pin/key locks in every ingest/transport caller.
    lock_publisher_resource(db, "transparency-witness-sequence",
        json.dumps([external_id, log_id, epoch], separators=(",", ":")))


@promotion_mutation
def update_witness_policy(
    db: Session,
    payload: TransparencyWitnessPolicyUpdate,
    *,
    actor: str,
) -> CapabilityTransparencyWitnessPolicy:
    identity = transparency_singleton_id(db)
    lock_publisher_resource(db, "transparency-witness-policy", identity)
    policy = db.scalar(select(CapabilityTransparencyWitnessPolicy).where(
        CapabilityTransparencyWitnessPolicy.id == identity).with_for_update()
        .execution_options(populate_existing=True))
    if policy is None:
        policy = CapabilityTransparencyWitnessPolicy(id=identity, updated_by=actor)
        db.add(policy)
    policy.required_quorum = payload.required_quorum
    policy.max_attestation_age_hours = payload.max_attestation_age_hours
    policy.updated_by = actor
    policy.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="capability.transparency_witness_policy.updated",
        actor_type="user",
        actor_id=actor,
        entity_type="capability_transparency_witness_policy",
        entity_id=policy.id,
        details={
            "required_quorum": policy.required_quorum,
            "max_attestation_age_hours": policy.max_attestation_age_hours,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    def check():
        if (policy.required_quorum != payload.required_quorum
            or policy.max_attestation_age_hours != payload.max_attestation_age_hours
            or policy.updated_by != actor):
            raise ValueError("Transparency witness policy changed before commit")
    commit_with_promotion_authority(db, check)
    db.refresh(policy)
    return policy


def register_transparency_witness(
    db: Session,
    payload: TransparencyWitnessCreate,
    *,
    actor: str,
) -> CapabilityTransparencyWitness:
    key = db.get(ArtifactTrustKey, payload.trust_key_id)
    if key is None:
        raise ValueError("Transparency witness trust key does not exist")
    ensure_trust_key_usable(
        db,
        key,
        expected_purpose="transparency_witness",
    )
    witness = CapabilityTransparencyWitness(
        name=payload.name,
        witness_id=payload.witness_id,
        region=payload.region,
        trust_key_id=key.id,
        key_fingerprint_sha256=key.fingerprint_sha256,
        enabled=True,
        created_by=actor,
    )
    db.add(witness)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.transparency_witness.registered",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_transparency_witness",
            entity_id=witness.id,
            details={
                "witness_id": witness.witness_id,
                "region": witness.region,
                "key_fingerprint_sha256": witness.key_fingerprint_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Transparency witness name or identity already exists"
        ) from exc
    db.refresh(witness)
    return witness


def list_transparency_witnesses(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityTransparencyWitness]:
    return list(
        db.scalars(
            select(CapabilityTransparencyWitness)
            .order_by(CapabilityTransparencyWitness.name)
            .limit(limit)
        ).all()
    )


@promotion_mutation
def set_transparency_witness_state(
    db: Session,
    witness_id: str,
    payload: TransparencyWitnessStateCreate,
    *,
    actor: str,
) -> CapabilityTransparencyWitness:
    witness = db.scalar(select(CapabilityTransparencyWitness).where(CapabilityTransparencyWitness.id == witness_id)
        .with_for_update().execution_options(populate_existing=True))
    if witness is None:
        raise LookupError("Transparency witness not found")
    if witness.enabled == payload.enabled:
        db.commit()
        return witness
    key = None
    if payload.enabled:
        key = lock_trust_keys(db, [witness.trust_key_id], expected_purpose="transparency_witness")[witness.trust_key_id]
        if key is None:
            raise ValueError("Transparency witness trust key is unavailable")
        ensure_trust_key_usable(
            db,
            key,
            expected_purpose="transparency_witness",
        )
    witness.enabled = payload.enabled
    witness.updated_at = utcnow()
    record_audit_event(
        db,
        event_type=(
            "capability.transparency_witness.enabled"
            if witness.enabled
            else "capability.transparency_witness.disabled"
        ),
        actor_type="user",
        actor_id=actor,
        entity_type="capability_transparency_witness",
        entity_id=witness.id,
        details={
            "witness_id": witness.witness_id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    def check():
        if key is not None:
            ensure_trust_key_usable(db, key, expected_purpose="transparency_witness")
    commit_with_promotion_authority(db, check)
    db.refresh(witness)
    return witness


def _checkpoint_from_offer(
    offer: CapabilityTransparencyCheckpointOffer,
) -> TransparencyCheckpointStatement:
    checkpoint = TransparencyCheckpointStatement.model_validate(
        offer.statement_snapshot
    )
    material = checkpoint.model_dump(
        mode="json",
        exclude={"digest_sha256"},
    )
    if _canonical_hash(material) != checkpoint.digest_sha256:
        raise ValueError("Stored checkpoint statement digest does not match")
    if (
        checkpoint.log_id != offer.log_id
        or checkpoint.epoch != offer.epoch
        or checkpoint.sequence != offer.sequence
        or checkpoint.head_digest_sha256 != offer.head_digest_sha256
        or checkpoint.digest_sha256 != offer.statement_digest_sha256
        or _as_utc(checkpoint.issued_at) != _as_utc(offer.issued_at)
        or _as_utc(checkpoint.expires_at) != _as_utc(offer.expires_at)
    ):
        raise ValueError("Stored checkpoint statement binding does not match")
    return checkpoint


def _offer_read(
    db: Session,
    offer: CapabilityTransparencyCheckpointOffer,
) -> TransparencyCheckpointOfferRead:
    policy = get_witness_policy(db, create_if_missing=False)
    attestation_count = len(_valid_offer_attestations(db, offer))
    return TransparencyCheckpointOfferRead(
        id=offer.id,
        log_id=offer.log_id,
        epoch=offer.epoch,
        sequence=offer.sequence,
        head_digest_sha256=offer.head_digest_sha256,
        statement_digest_sha256=offer.statement_digest_sha256,
        statement=_checkpoint_from_offer(offer),
        issued_at=offer.issued_at,
        expires_at=offer.expires_at,
        reason=offer.reason,
        created_by=offer.created_by,
        created_at=offer.created_at,
        attestation_count=attestation_count,
        required_quorum=policy.required_quorum,
        quorum_satisfied=attestation_count >= policy.required_quorum,
    )


def create_checkpoint_offer(
    db: Session,
    payload: TransparencyCheckpointOfferCreate,
    *,
    actor: str,
) -> TransparencyCheckpointOfferRead:
    checkpoint = get_capability_transparency_checkpoint(db)
    if checkpoint.last_sequence == 0:
        raise ValueError("An empty transparency log cannot be witnessed")
    issued_at = utcnow()
    expires_at = issued_at + timedelta(hours=payload.validity_hours)
    material = {
        "format_version": CHECKPOINT_STATEMENT_FORMAT,
        "log_id": checkpoint.log_id,
        "epoch": checkpoint.epoch,
        "sequence": checkpoint.last_sequence,
        "head_digest_sha256": checkpoint.head_digest_sha256,
        "issued_at": _json_timestamp(issued_at),
        "expires_at": _json_timestamp(expires_at),
    }
    statement = TransparencyCheckpointStatement.model_validate(
        {**material, "digest_sha256": _canonical_hash(material)}
    )
    offer = CapabilityTransparencyCheckpointOffer(
        log_id=statement.log_id,
        epoch=statement.epoch,
        sequence=statement.sequence,
        head_digest_sha256=statement.head_digest_sha256,
        statement_digest_sha256=statement.digest_sha256,
        statement_snapshot=statement.model_dump(mode="json"),
        issued_at=issued_at,
        expires_at=expires_at,
        reason=payload.reason,
        created_by=actor,
    )
    db.add(offer)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.transparency_checkpoint.offered",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_transparency_checkpoint_offer",
            entity_id=offer.id,
            details={
                "log_id": offer.log_id,
                "epoch": offer.epoch,
                "sequence": offer.sequence,
                "head_digest_sha256": offer.head_digest_sha256,
                "statement_digest_sha256": offer.statement_digest_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Transparency checkpoint offer already exists") from exc
    db.refresh(offer)
    return _offer_read(db, offer)


def list_checkpoint_offers(
    db: Session,
    *,
    limit: int,
) -> list[TransparencyCheckpointOfferRead]:
    offers = list(
        db.scalars(
            select(CapabilityTransparencyCheckpointOffer)
            .order_by(
                CapabilityTransparencyCheckpointOffer.created_at.desc()
            )
            .limit(limit)
        ).all()
    )
    return [_offer_read(db, item) for item in offers]


def require_live_witnessed_checkpoint_offer(
    db: Session,
    *,
    log_id: str,
    epoch: int,
    sequence: int,
    head_digest_sha256: str,
) -> CapabilityTransparencyCheckpointOffer:
    offers = list(
        db.scalars(
            select(CapabilityTransparencyCheckpointOffer)
            .where(
                CapabilityTransparencyCheckpointOffer.log_id == log_id,
                CapabilityTransparencyCheckpointOffer.epoch == epoch,
                CapabilityTransparencyCheckpointOffer.sequence == sequence,
                CapabilityTransparencyCheckpointOffer.head_digest_sha256
                == head_digest_sha256,
                CapabilityTransparencyCheckpointOffer.expires_at > utcnow(),
            )
            .order_by(
                CapabilityTransparencyCheckpointOffer.created_at.desc()
            )
        ).all()
    )
    policy = db.get(
        CapabilityTransparencyWitnessPolicy,
        transparency_singleton_id(db),
    )
    required_quorum = policy.required_quorum if policy is not None else 2
    for offer in offers:
        if len(_valid_offer_attestations(db, offer)) >= required_quorum:
            return offer
    raise ValueError(
        "Transparency checkpoint has not reached live witness quorum"
    )


def _verify_witness_attestation(
    db: Session,
    signed: SignedTransparencyWitnessAttestation,
    checkpoint: TransparencyCheckpointStatement,
) -> tuple[CapabilityTransparencyWitness, dict[str, str]]:
    attestation = signed.attestation
    now = utcnow()
    checkpoint_issued_at = _as_utc(checkpoint.issued_at)
    checkpoint_expires_at = _as_utc(checkpoint.expires_at)
    if checkpoint_issued_at > now + WITNESS_CLOCK_SKEW:
        raise ValueError("Transparency checkpoint is issued in the future")
    if checkpoint_expires_at <= now:
        raise ValueError("Transparency checkpoint has expired")
    if checkpoint_expires_at - checkpoint_issued_at > timedelta(hours=168):
        raise ValueError("Transparency checkpoint lifetime exceeds 168 hours")
    material = attestation.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != attestation.digest_sha256:
        raise ValueError("Witness attestation digest does not match")
    if (
        attestation.checkpoint_statement_digest_sha256
        != checkpoint.digest_sha256
        or attestation.log_id != checkpoint.log_id
        or attestation.epoch != checkpoint.epoch
        or attestation.sequence != checkpoint.sequence
        or attestation.head_digest_sha256
        != checkpoint.head_digest_sha256
    ):
        raise ValueError("Witness attestation checkpoint does not match")
    witness = db.scalar(
        select(CapabilityTransparencyWitness).where(
            CapabilityTransparencyWitness.witness_id
            == attestation.witness_id,
            CapabilityTransparencyWitness.enabled.is_(True),
        )
    )
    if witness is None:
        raise ValueError("Transparency witness is not registered or enabled")
    policy = get_witness_policy(db, create_if_missing=False)
    witnessed_at = _as_utc(attestation.witnessed_at)
    expires_at = _as_utc(attestation.expires_at)
    if witnessed_at > now + WITNESS_CLOCK_SKEW:
        raise ValueError("Witness attestation is issued in the future")
    if witnessed_at + WITNESS_CLOCK_SKEW < checkpoint_issued_at:
        raise ValueError("Witness attestation predates the checkpoint")
    if expires_at <= now:
        raise ValueError("Witness attestation has expired")
    if expires_at > checkpoint_expires_at:
        raise ValueError("Witness attestation outlives the checkpoint")
    if expires_at - witnessed_at > timedelta(
        hours=policy.max_attestation_age_hours
    ):
        raise ValueError("Witness attestation exceeds the local age policy")
    verification = verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=attestation.digest_sha256,
        signed_format_version=SIGNED_WITNESS_ATTESTATION_FORMAT,
        expected_purpose="transparency_witness",
    )
    if verification["trust_key_id"] != witness.trust_key_id:
        raise ValueError("Witness attestation is not signed by its pinned key")
    if (
        verification["key_fingerprint_sha256"]
        != witness.key_fingerprint_sha256
    ):
        raise ValueError("Witness pinned fingerprint does not match")
    return witness, verification


def _valid_offer_attestations(
    db: Session,
    offer: CapabilityTransparencyCheckpointOffer,
) -> list[CapabilityTransparencyWitnessAttestation]:
    checkpoint = _checkpoint_from_offer(offer)
    rows = list(
        db.scalars(
            select(CapabilityTransparencyWitnessAttestation)
            .where(
                CapabilityTransparencyWitnessAttestation.checkpoint_offer_id
                == offer.id
            )
            .order_by(
                CapabilityTransparencyWitnessAttestation.external_witness_id
            )
        ).all()
    )
    valid: list[CapabilityTransparencyWitnessAttestation] = []
    seen_witnesses: set[str] = set()
    for row in rows:
        try:
            signed = SignedTransparencyWitnessAttestation.model_validate(
                row.signed_attestation_snapshot
            )
            witness, verification = _verify_witness_attestation(
                db,
                signed,
                checkpoint,
            )
        except (TypeError, ValueError):
            continue
        if (
            witness.id in seen_witnesses
            or witness.id != row.witness_id
            or verification["signature_sha256"] != row.signature_sha256
        ):
            continue
        seen_witnesses.add(witness.id)
        valid.append(row)
    return valid


def ingest_checkpoint_attestation(
    db: Session,
    offer_id: str,
    payload: TransparencyAttestationIngestCreate,
    *,
    actor: str,
    commit: bool = True,
) -> CapabilityTransparencyWitnessAttestation:
    require_locking_transaction(db, purpose="Witness attestation ingestion")
    offer = db.get(CapabilityTransparencyCheckpointOffer, offer_id, populate_existing=True)
    if offer is None:
        raise LookupError("Transparency checkpoint offer not found")
    if _as_utc(offer.expires_at) <= utcnow():
        raise ValueError("Transparency checkpoint offer has expired")
    checkpoint = _checkpoint_from_offer(offer)
    lock_witness_sequence(db, payload.signed_attestation.attestation.witness_id, offer.log_id, offer.epoch)
    lock_witness_authority(db, [payload.signed_attestation.attestation.witness_id])
    witness, verification = _verify_witness_attestation(
        db,
        payload.signed_attestation,
        checkpoint,
    )
    attestation = payload.signed_attestation.attestation
    newer_sequence = db.scalar(
        select(func.max(CapabilityTransparencyWitnessAttestation.sequence))
        .where(
            CapabilityTransparencyWitnessAttestation.witness_id == witness.id,
            CapabilityTransparencyWitnessAttestation.log_id == offer.log_id,
            CapabilityTransparencyWitnessAttestation.epoch == offer.epoch,
        )
    )
    if newer_sequence is not None and newer_sequence > offer.sequence:
        raise ValueError("Witness attestation sequence is stale")
    conflicting = db.scalar(
        select(CapabilityTransparencyWitnessAttestation.id).where(
            CapabilityTransparencyWitnessAttestation.witness_id == witness.id,
            CapabilityTransparencyWitnessAttestation.log_id == offer.log_id,
            CapabilityTransparencyWitnessAttestation.epoch == offer.epoch,
            CapabilityTransparencyWitnessAttestation.sequence == offer.sequence,
            CapabilityTransparencyWitnessAttestation.head_digest_sha256
            != offer.head_digest_sha256,
        )
    )
    if conflicting is not None:
        raise ValueError("Witness has attested a conflicting checkpoint")
    row = CapabilityTransparencyWitnessAttestation(
        checkpoint_offer_id=offer.id,
        witness_id=witness.id,
        external_witness_id=witness.witness_id,
        trust_key_id=witness.trust_key_id,
        key_fingerprint_sha256=verification["key_fingerprint_sha256"],
        log_id=offer.log_id,
        epoch=offer.epoch,
        sequence=offer.sequence,
        head_digest_sha256=offer.head_digest_sha256,
        checkpoint_statement_digest_sha256=offer.statement_digest_sha256,
        attestation_digest_sha256=attestation.digest_sha256,
        signature_sha256=verification["signature_sha256"],
        signed_attestation_snapshot=payload.signed_attestation.model_dump(
            mode="json"
        ),
        witnessed_at=attestation.witnessed_at,
        expires_at=attestation.expires_at,
        ingested_by=actor,
    )
    db.add(row)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.transparency_checkpoint.attested",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_transparency_witness_attestation",
            entity_id=row.id,
            details={
                "witness_id": witness.witness_id,
                "log_id": offer.log_id,
                "epoch": offer.epoch,
                "sequence": offer.sequence,
                "head_digest_sha256": offer.head_digest_sha256,
                "attestation_digest_sha256": attestation.digest_sha256,
            },
        )
        if commit:
            db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Witness already attested this checkpoint or digest"
        ) from exc
    if commit:
        db.refresh(row)
    return row


def list_checkpoint_attestations(
    db: Session,
    offer_id: str,
) -> list[CapabilityTransparencyWitnessAttestation]:
    if db.get(CapabilityTransparencyCheckpointOffer, offer_id) is None:
        raise LookupError("Transparency checkpoint offer not found")
    return list(
        db.scalars(
            select(CapabilityTransparencyWitnessAttestation)
            .where(
                CapabilityTransparencyWitnessAttestation.checkpoint_offer_id
                == offer_id
            )
            .order_by(
                CapabilityTransparencyWitnessAttestation.external_witness_id
            )
        ).all()
    )


def export_checkpoint_gossip(
    db: Session,
    offer_id: str,
    *,
    source_region: str,
) -> TransparencyGossipDocument:
    offer = db.get(CapabilityTransparencyCheckpointOffer, offer_id)
    if offer is None:
        raise LookupError("Transparency checkpoint offer not found")
    offer_read = _offer_read(db, offer)
    if not offer_read.quorum_satisfied:
        raise ValueError("Transparency checkpoint has not reached witness quorum")
    rows = _valid_offer_attestations(db, offer)
    return TransparencyGossipDocument.model_validate(
        {
            "format_version": GOSSIP_FORMAT,
            "source_region": source_region,
            "checkpoint": offer.statement_snapshot,
            "attestations": [
                row.signed_attestation_snapshot for row in rows
            ],
        }
    )


def _classify_checkpoint(
    db: Session,
    *,
    log_id: str,
    epoch: int,
    sequence: int,
    head_digest_sha256: str,
) -> str:
    state = db.get(CapabilityTransparencyState, transparency_singleton_id(db))
    if (
        state is None
        or state.log_id != log_id
        or state.epoch != epoch
    ):
        return "fork"
    if sequence > state.last_sequence:
        return "ahead"
    local_digest = db.scalar(
        select(CapabilityTransparencyRecord.record_digest_sha256).where(
            CapabilityTransparencyRecord.sequence == sequence
        )
    )
    if local_digest != head_digest_sha256:
        return "fork"
    return "consistent" if sequence == state.last_sequence else "behind"


def _route_fork_alert(
    db: Session,
    row: CapabilityTransparencyGossipObservation,
    *,
    actor: str,
) -> str:
    local_head = db.scalar(
        select(CapabilityTransparencyRecord.record_digest_sha256).where(
            CapabilityTransparencyRecord.sequence == row.sequence
        )
    )
    checkpoint_id = f"{row.log_id}:{row.epoch}:{row.sequence}"
    alert = upsert_alert(
        db,
        dedup_key=(
            "capability-transparency-fork:"
            f"{checkpoint_id}:{row.head_digest_sha256}"
        ),
        event_type="capability.transparency.fork",
        severity=AlertSeverity.CRITICAL,
        title=f"Transparency fork detected at sequence {row.sequence}",
        description=(
            "A witness-quorum-backed checkpoint from region "
            f"{row.source_region} conflicts with the immutable local log."
        ),
        entity_type="capability_transparency_checkpoint",
        entity_id=checkpoint_id,
        details={
            "observation_id": row.id,
            "source_region": row.source_region,
            "log_id": row.log_id,
            "epoch": row.epoch,
            "sequence": row.sequence,
            "local_head_digest_sha256": local_head,
            "remote_head_digest_sha256": row.head_digest_sha256,
            "checkpoint_statement_digest_sha256": (
                row.checkpoint_statement_digest_sha256
            ),
            "gossip_document_digest_sha256": row.document_digest_sha256,
            "witness_count": row.witness_count,
        },
        observed_at=row.received_at,
    )
    if alert is None:
        raise ValueError("A verified transparency fork cannot lose its Alert source episode")
    row.alert_id = alert.id
    record_audit_event(
        db,
        event_type="capability.transparency_fork.alert_routed",
        actor_type="system",
        actor_id=actor,
        entity_type="alert",
        entity_id=alert.id,
        outcome="failure",
        details={
            "observation_id": row.id,
            "source_region": row.source_region,
            "log_id": row.log_id,
            "epoch": row.epoch,
            "sequence": row.sequence,
            "remote_head_digest_sha256": row.head_digest_sha256,
            "occurrence_count": alert.occurrence_count,
        },
    )
    return alert.id


def ingest_transparency_gossip(
    db: Session,
    payload: TransparencyGossipIngestCreate,
    *,
    actor: str,
) -> TransparencyGossipObservationRead:
    gossip = payload.gossip
    encoded = json.dumps(
        gossip.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > GOSSIP_MAX_BYTES:
        raise ValueError(f"Transparency gossip exceeds {GOSSIP_MAX_BYTES} bytes")
    checkpoint = gossip.checkpoint
    checkpoint_material = checkpoint.model_dump(
        mode="json",
        exclude={"digest_sha256"},
    )
    if _canonical_hash(checkpoint_material) != checkpoint.digest_sha256:
        raise ValueError("Gossip checkpoint digest does not match")
    local = get_capability_transparency_checkpoint(db)
    if checkpoint.log_id != local.log_id or checkpoint.epoch != local.epoch:
        raise ValueError("Gossip transparency log identity does not match")
    witness_evidence: list[dict[str, str]] = []
    seen_witnesses: set[str] = set()
    for signed in gossip.attestations:
        witness, verification = _verify_witness_attestation(
            db,
            signed,
            checkpoint,
        )
        if witness.id in seen_witnesses:
            raise ValueError("Gossip contains a duplicate witness")
        seen_witnesses.add(witness.id)
        witness_evidence.append(
            {
                "witness_id": witness.witness_id,
                "region": witness.region,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "attestation_digest_sha256": (
                    signed.attestation.digest_sha256
                ),
                "signature_sha256": verification["signature_sha256"],
            }
        )
    policy = get_witness_policy(db)
    if len(witness_evidence) < policy.required_quorum:
        raise ValueError("Gossip checkpoint does not satisfy witness quorum")
    document_digest = hashlib.sha256(encoded).hexdigest()
    existing = db.scalar(
        select(CapabilityTransparencyGossipObservation).where(
            CapabilityTransparencyGossipObservation.document_digest_sha256
            == document_digest
        )
    )
    if existing is not None:
        return _gossip_read(db, existing)
    status = _classify_checkpoint(
        db,
        log_id=checkpoint.log_id,
        epoch=checkpoint.epoch,
        sequence=checkpoint.sequence,
        head_digest_sha256=checkpoint.head_digest_sha256,
    )
    row = CapabilityTransparencyGossipObservation(
        source_region=gossip.source_region,
        log_id=checkpoint.log_id,
        epoch=checkpoint.epoch,
        sequence=checkpoint.sequence,
        head_digest_sha256=checkpoint.head_digest_sha256,
        checkpoint_statement_digest_sha256=checkpoint.digest_sha256,
        document_digest_sha256=document_digest,
        witness_count=len(witness_evidence),
        witness_evidence=witness_evidence,
        initial_status=status,
        gossip_snapshot=gossip.model_dump(mode="json"),
        reason=payload.reason,
        received_by=actor,
    )
    db.add(row)
    db.flush()
    alert_id = (
        _route_fork_alert(db, row, actor=actor)
        if status == "fork"
        else None
    )
    record_audit_event(
        db,
        event_type=f"capability.transparency_gossip.{status}",
        actor_type="user",
        actor_id=actor,
        entity_type="capability_transparency_gossip_observation",
        entity_id=row.id,
        outcome="failure" if status == "fork" else "success",
        details={
            "source_region": row.source_region,
            "log_id": row.log_id,
            "epoch": row.epoch,
            "sequence": row.sequence,
            "head_digest_sha256": row.head_digest_sha256,
            "witness_count": row.witness_count,
            "alert_id": alert_id,
        },
    )
    db.commit()
    db.refresh(row)
    return _gossip_read(db, row)


def _gossip_read(
    db: Session,
    row: CapabilityTransparencyGossipObservation,
) -> TransparencyGossipObservationRead:
    return TransparencyGossipObservationRead(
        id=row.id,
        source_region=row.source_region,
        log_id=row.log_id,
        epoch=row.epoch,
        sequence=row.sequence,
        head_digest_sha256=row.head_digest_sha256,
        checkpoint_statement_digest_sha256=(
            row.checkpoint_statement_digest_sha256
        ),
        document_digest_sha256=row.document_digest_sha256,
        witness_count=row.witness_count,
        witness_evidence=row.witness_evidence,
        initial_status=row.initial_status,
        current_status=_classify_checkpoint(
            db,
            log_id=row.log_id,
            epoch=row.epoch,
            sequence=row.sequence,
            head_digest_sha256=row.head_digest_sha256,
        ),
        alert_id=row.alert_id,
        reason=row.reason,
        received_by=row.received_by,
        received_at=row.received_at,
    )


def list_transparency_gossip(
    db: Session,
    *,
    limit: int,
) -> list[TransparencyGossipObservationRead]:
    rows = list(
        db.scalars(
            select(CapabilityTransparencyGossipObservation)
            .order_by(
                CapabilityTransparencyGossipObservation.received_at.desc()
            )
            .limit(limit)
        ).all()
    )
    return [_gossip_read(db, item) for item in rows]


def reconcile_transparency_fork_alerts(
    db: Session,
    *,
    limit: int,
    actor: str,
) -> TransparencyForkAlertReconcileRead:
    rows = list(
        db.scalars(
            select(CapabilityTransparencyGossipObservation)
            .where(
                CapabilityTransparencyGossipObservation.initial_status
                == "fork",
                CapabilityTransparencyGossipObservation.alert_id.is_(None),
            )
            .order_by(
                CapabilityTransparencyGossipObservation.received_at,
                CapabilityTransparencyGossipObservation.id,
            )
            .with_for_update(skip_locked=True)
            .limit(limit)
        ).all()
    )
    for row in rows:
        _route_fork_alert(db, row, actor=actor)
    db.flush()
    remaining = db.scalar(
        select(func.count())
        .select_from(CapabilityTransparencyGossipObservation)
        .where(
            CapabilityTransparencyGossipObservation.initial_status == "fork",
            CapabilityTransparencyGossipObservation.alert_id.is_(None),
        )
    ) or 0
    db.commit()
    return TransparencyForkAlertReconcileRead(
        processed=len(rows),
        remaining=remaining,
    )
