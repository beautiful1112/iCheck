"""Planned, dual-signed promotion authority handover without private keys."""
import hashlib
import json
from datetime import timedelta

from sqlalchemy import exists, select

from ..capability_promotion_schemas import (
    PROMOTION_KEY_ROTATION_FORMAT, SIGNED_PROMOTION_KEY_ROTATION_FORMAT,
    CapabilityPromotionKeyRotationStatement, SignedCapabilityPromotionKeyRotation,
)
from ..models import CapabilityPromotionKeyRotation, CapabilityPromotionPublication, CapabilityPromotionReceipt, utcnow
from .artifact_portability import ensure_trust_key_usable, verify_trusted_digest_signature
from .audit import record_audit_event
from .capability_promotions import _as_utc, _assert_source_key_organization, _canonical_hash
from .capability_transparency import append_capability_transparency_record
from .promotion_authority import commit_with_promotion_authority, lock_promotion_policy, lock_promotion_source, promotion_mutation
from .trust_authority import assert_rotation_replay, lock_trust_keys
from .trust_namespace import selected_trust_namespace

MAX_LIFETIME = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
MAX_BYTES = 65_536


def _assert_time(statement):
    now = utcnow()
    if _as_utc(statement.issued_at) > now + CLOCK_SKEW:
        raise ValueError("Promotion key rotation is issued in the future")
    if _as_utc(statement.expires_at) <= now:
        raise ValueError("Promotion key rotation has expired")
    if _as_utc(statement.expires_at) - _as_utc(statement.issued_at) > MAX_LIFETIME:
        raise ValueError("Promotion key rotation lifetime exceeds 24 hours")


def _assert_drained(db, source):
    published = exists(select(CapabilityPromotionPublication.id).where(
        CapabilityPromotionPublication.receipt_id == CapabilityPromotionReceipt.id))
    pending = db.scalar(select(CapabilityPromotionReceipt.id).where(
        CapabilityPromotionReceipt.source_id == source.id,
        CapabilityPromotionReceipt.expires_at > utcnow(), ~published).limit(1))
    if pending:
        raise ValueError("Publish unexpired pending promotion receipts before planned key rotation")


def _lock_authority(db, source, policy, next_key_id):
    if policy is None:
        raise ValueError("Local promotion policy is not configured")
    if not source.enabled:
        raise ValueError("Promotion source is disabled")
    if source.environment_id == policy.local_environment_id:
        raise ValueError("Promotion source cannot be the local environment")
    if source.trust_key_id == next_key_id:
        raise ValueError("Promotion key rotation requires a different key")
    keys = lock_trust_keys(db, [source.trust_key_id, next_key_id], expected_purpose="environment_promotion")
    if keys[source.trust_key_id].fingerprint_sha256 != source.key_fingerprint_sha256:
        raise ValueError("Current promotion source fingerprint is not pinned")
    for key in keys.values():
        _assert_source_key_organization(db, key, source.organization_id)
    _assert_drained(db, source)
    return keys


def _check_commit(db, keys, source, policy, statement, expected_pin):
    if not source.enabled:
        raise ValueError("Promotion source is disabled")
    for key in keys.values():
        ensure_trust_key_usable(db, key, expected_purpose="environment_promotion")
    if source.trust_key_id != expected_pin or source.key_fingerprint_sha256 != keys[expected_pin].fingerprint_sha256:
        raise ValueError("Promotion key pin changed before commit")
    for name, value in {"organization_id": source.organization_id, "source_environment_id": source.environment_id,
        "source_stage": source.source_stage, "target_environment_id": policy.local_environment_id,
        "target_stage": policy.local_stage, "promotion_sequence": source.latest_sequence,
        "latest_statement_digest_sha256": source.latest_statement_digest_sha256}.items():
        if getattr(statement, name) != value:
            raise ValueError("Promotion key rotation context changed before commit")
    _assert_drained(db, source)
    _assert_time(statement)


def _assert_context(source, policy, statement, next_key):
    expected = {"organization_id": source.organization_id, "source_environment_id": source.environment_id,
        "source_stage": source.source_stage, "target_environment_id": policy.local_environment_id,
        "target_stage": policy.local_stage, "promotion_sequence": source.latest_sequence,
        "latest_statement_digest_sha256": source.latest_statement_digest_sha256,
        "current_key_fingerprint_sha256": source.key_fingerprint_sha256,
        "next_key_fingerprint_sha256": next_key.fingerprint_sha256}
    if any(getattr(statement, name) != value for name, value in expected.items()):
        raise ValueError("Promotion key rotation does not match the current source, target, keys or accepted head")
    _assert_time(statement)


@promotion_mutation
def create_promotion_key_rotation_statement(db, source_id, payload, *, actor):
    policy = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id)
    keys = _lock_authority(db, source, policy, payload.new_trust_key_id)
    now = utcnow()
    material = {"format_version": PROMOTION_KEY_ROTATION_FORMAT,
        "organization_id": source.organization_id, "source_environment_id": source.environment_id,
        "source_stage": source.source_stage, "target_environment_id": policy.local_environment_id,
        "target_stage": policy.local_stage, "promotion_sequence": source.latest_sequence,
        "latest_statement_digest_sha256": source.latest_statement_digest_sha256,
        "current_key_fingerprint_sha256": source.key_fingerprint_sha256,
        "next_key_fingerprint_sha256": keys[payload.new_trust_key_id].fingerprint_sha256,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=payload.validity_hours)).isoformat().replace("+00:00", "Z")}
    statement = CapabilityPromotionKeyRotationStatement.model_validate({**material, "digest_sha256": _canonical_hash(material)})
    record_audit_event(db, event_type="capability.promotion_key_rotation.statement_generated", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_source", entity_id=source.id,
        details={"statement_digest_sha256": statement.digest_sha256, "new_trust_key_id": payload.new_trust_key_id,
            "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
    current_pin = source.trust_key_id
    commit_with_promotion_authority(db, lambda: _check_commit(db, keys, source, policy, statement, current_pin))
    return statement


@promotion_mutation
def rotate_promotion_source_key(db, source_id, payload, *, actor):
    signed = payload.signed_rotation
    snapshot = signed.model_dump(mode="json")
    if len(json.dumps(snapshot, ensure_ascii=True).encode()) > MAX_BYTES:
        raise ValueError("Promotion key rotation document is too large")
    statement = signed.statement
    if _canonical_hash(statement.model_dump(mode="json", exclude={"digest_sha256"})) != statement.digest_sha256:
        raise ValueError("Promotion key rotation digest does not match")
    policy = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id, writable=True)
    accepted = db.scalar(select(CapabilityPromotionKeyRotation).where(
        CapabilityPromotionKeyRotation.source_id == source.id,
        CapabilityPromotionKeyRotation.statement_digest_sha256 == statement.digest_sha256)
        .execution_options(populate_existing=True))
    if accepted is not None:
        assert_rotation_replay(accepted, signed)
        if accepted.to_trust_key_id != payload.new_trust_key_id or accepted.signed_rotation_snapshot != snapshot:
            raise ValueError("Promotion key rotation retry proof does not match the accepted outcome")
        # An immutable completed handover is history, never a new pin update.
        db.commit()
        db.refresh(accepted)
        return accepted
    keys = _lock_authority(db, source, policy, payload.new_trust_key_id)
    current, successor = keys[source.trust_key_id], keys[payload.new_trust_key_id]
    _assert_context(source, policy, statement, successor)
    verified = []
    for signature, key in ((signed.current_signature, current), (signed.next_signature, successor)):
        proof = verify_trusted_digest_signature(db, signature, expected_digest_sha256=statement.digest_sha256,
            signed_format_version=SIGNED_PROMOTION_KEY_ROTATION_FORMAT, expected_purpose="environment_promotion")
        if proof["trust_key_id"] != key.id:
            raise ValueError("Promotion key rotation lacks both pinned-key signatures")
        verified.append(proof)
    rotation = CapabilityPromotionKeyRotation(source_id=source.id,
        from_trust_key_id=current.id, to_trust_key_id=successor.id,
        from_key_fingerprint_sha256=current.fingerprint_sha256, to_key_fingerprint_sha256=successor.fingerprint_sha256,
        promotion_sequence=statement.promotion_sequence, latest_statement_digest_sha256=statement.latest_statement_digest_sha256,
        statement_digest_sha256=statement.digest_sha256, current_signature_sha256=verified[0]["signature_sha256"],
        next_signature_sha256=verified[1]["signature_sha256"], signed_rotation_snapshot=snapshot,
        issued_at=statement.issued_at, expires_at=statement.expires_at, reason=payload.reason, rotated_by=actor)
    source.trust_key_id, source.key_fingerprint_sha256 = successor.id, successor.fingerprint_sha256
    source.updated_at = utcnow()
    from .promotion_recovery import retire_promotion_recovery_policies
    retire_promotion_recovery_policies(db, source, actor=actor, reason="Retired by planned promotion key handover.")
    db.add(rotation)
    db.flush()
    details = {"source_id": source.id, "promotion_sequence": statement.promotion_sequence,
        "latest_statement_digest_sha256": statement.latest_statement_digest_sha256,
        "from_key_fingerprint_sha256": current.fingerprint_sha256, "to_key_fingerprint_sha256": successor.fingerprint_sha256}
    append_capability_transparency_record(db, event_type="capability.promotion_source.key_rotated",
        entity_type="capability_promotion_key_rotation", entity_id=rotation.id,
        subject_digest_sha256=statement.digest_sha256, details=details)
    record_audit_event(db, event_type="capability.promotion_source.key_rotated", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_key_rotation", entity_id=rotation.id,
        details={**details, "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
    commit_with_promotion_authority(db, lambda: _check_commit(db, keys, source, policy, statement, successor.id))
    db.refresh(rotation)
    return rotation


def list_promotion_key_rotations(db, *, source_id=None, limit=100):
    tenant, region = selected_trust_namespace(db)
    query = select(CapabilityPromotionKeyRotation).where(CapabilityPromotionKeyRotation.tenant_id == tenant,
        CapabilityPromotionKeyRotation.region_id == region)
    if source_id:
        query = query.where(CapabilityPromotionKeyRotation.source_id == source_id)
    return list(db.scalars(query.order_by(CapabilityPromotionKeyRotation.rotated_at.desc(), CapabilityPromotionKeyRotation.id).limit(limit)))


def export_promotion_key_rotation(db, rotation_id):
    tenant, region = selected_trust_namespace(db)
    rotation = db.scalar(select(CapabilityPromotionKeyRotation).where(CapabilityPromotionKeyRotation.id == rotation_id,
        CapabilityPromotionKeyRotation.tenant_id == tenant, CapabilityPromotionKeyRotation.region_id == region))
    if rotation is None:
        raise LookupError("Promotion key rotation not found in the selected namespace")
    return SignedCapabilityPromotionKeyRotation.model_validate(rotation.signed_rotation_snapshot)
