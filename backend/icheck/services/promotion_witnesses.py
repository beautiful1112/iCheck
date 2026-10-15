"""Target-local independent source checkpoint authority, never a remote call."""
import hashlib
from datetime import timedelta

from sqlalchemy import exists, select

from ..models import (
    CapabilityPromotionSourceCheckpointBinding, CapabilityPromotionSourceWitnessDecision,
    CapabilityPromotionSourceWitnessPolicy, CapabilityPromotionPublication,
    CapabilityPromotionReceipt, CapabilityTransparencyWitness, utcnow,
)
from ..transparency_witness_schemas import SIGNED_WITNESS_ATTESTATION_FORMAT
from .artifact_portability import verify_trusted_digest_signature
from .audit import record_audit_event
from .capability_transparency import append_capability_transparency_record
from .promotion_authority import lock_promotion_policy, lock_promotion_source, promotion_mutation
from .transparency_witnessing import _as_utc, _canonical_hash
from .trust_authority import lock_trust_keys
from .trust_namespace import selected_trust_namespace

CLOCK_SKEW = timedelta(minutes=5)


def _namespace_query(db, model):
    tenant, region = selected_trust_namespace(db)
    return select(model).where(model.tenant_id == tenant, model.region_id == region)


def get_source_witness_policy(db, *, locked=False):
    query = _namespace_query(db, CapabilityPromotionSourceWitnessPolicy)
    if locked:
        query = query.with_for_update(read=True)
    return db.scalars(query.execution_options(populate_existing=True)).one_or_none()


def lock_source_checkpoint_context(db, source):
    policy = get_source_witness_policy(db, locked=True)
    binding = db.scalar(_namespace_query(db, CapabilityPromotionSourceCheckpointBinding)
        .where(CapabilityPromotionSourceCheckpointBinding.source_id == source.id)
        .with_for_update(read=True).execution_options(populate_existing=True)) if source else None
    return policy, binding


def source_witness_policy_snapshot(db):
    policy = get_source_witness_policy(db)
    return {"required_quorum": policy.required_quorum if policy else 0,
        "witness_ids": list(policy.witness_ids) if policy else [],
        "max_attestation_age_hours": policy.max_attestation_age_hours if policy else 168}


@promotion_mutation
def update_source_witness_policy(db, payload, *, actor):
    if lock_promotion_policy(db, writable=True) is None:
        raise ValueError("Local promotion policy is not configured")
    witnesses = []
    for identity in sorted(payload.witness_ids):
        witness = db.scalar(_namespace_query(db, CapabilityTransparencyWitness)
            .where(CapabilityTransparencyWitness.id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if witness is None or not witness.enabled:
            raise ValueError("Promotion witness is not enabled in the selected namespace")
        witnesses.append(witness)
    keys = lock_trust_keys(db, [w.trust_key_id for w in witnesses], expected_purpose="transparency_witness")
    if any(keys[w.trust_key_id].fingerprint_sha256 != w.key_fingerprint_sha256 for w in witnesses):
        raise ValueError("Promotion witness fingerprint is not pinned")
    if len({w.key_fingerprint_sha256 for w in witnesses}) < payload.required_quorum:
        raise ValueError("Promotion quorum requires independent witness keys")
    policy = get_source_witness_policy(db)
    if policy is None:
        policy = CapabilityPromotionSourceWitnessPolicy()
        db.add(policy)
    policy.required_quorum = payload.required_quorum
    policy.witness_ids = sorted(payload.witness_ids)
    policy.max_attestation_age_hours = payload.max_attestation_age_hours
    policy.updated_by, policy.updated_at = actor, utcnow()
    db.flush()
    record_audit_event(db, event_type="capability.promotion_source_witness_policy.updated", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_source_witness_policy", entity_id=policy.id,
        details={**source_witness_policy_snapshot(db), "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
    from .promotion_authority import commit_with_promotion_authority
    from .artifact_portability import ensure_trust_key_usable
    def check():
        if any(not witness.enabled or witness.key_fingerprint_sha256 != keys[witness.trust_key_id].fingerprint_sha256 for witness in witnesses):
            raise ValueError("Promotion witness pin changed before commit")
        for key in keys.values():
            ensure_trust_key_usable(db, key, expected_purpose="transparency_witness")
    commit_with_promotion_authority(db, check)
    db.refresh(policy)
    return policy


def list_source_checkpoint_bindings(db):
    return list(db.scalars(_namespace_query(db, CapabilityPromotionSourceCheckpointBinding)
        .order_by(CapabilityPromotionSourceCheckpointBinding.source_id)))


@promotion_mutation
def bind_source_checkpoint(db, source_id, payload, *, actor):
    lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id, writable=True)
    binding = db.scalar(_namespace_query(db, CapabilityPromotionSourceCheckpointBinding)
        .where(CapabilityPromotionSourceCheckpointBinding.source_id == source.id)
        .execution_options(populate_existing=True))
    changed = binding is None or (binding.log_id, binding.epoch) != (payload.log_id, payload.epoch)
    if changed:
        published = exists(select(CapabilityPromotionPublication.id).where(
            CapabilityPromotionPublication.receipt_id == CapabilityPromotionReceipt.id))
        if db.scalar(select(CapabilityPromotionReceipt.id).where(CapabilityPromotionReceipt.source_id == source.id,
            CapabilityPromotionReceipt.expires_at > utcnow(), ~published).limit(1)):
            raise ValueError("Publish unexpired pending receipts before changing a source checkpoint binding")
    else:
        db.commit()
        db.refresh(binding)
        return binding
    if binding is None:
        binding = CapabilityPromotionSourceCheckpointBinding(source_id=source.id)
        db.add(binding)
    binding.log_id, binding.epoch = payload.log_id, payload.epoch
    binding.reason, binding.updated_by, binding.updated_at = payload.reason, actor, utcnow()
    details = {"source_id": source.id, "log_id": payload.log_id, "epoch": payload.epoch,
        "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()}
    record_audit_event(db, event_type="capability.promotion_source.checkpoint_bound", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_source", entity_id=source.id, details=details)
    append_capability_transparency_record(db, event_type="capability.promotion_source.checkpoint_bound",
        entity_type="capability_promotion_source", entity_id=source.id, subject_digest_sha256=_canonical_hash(details), details=details)
    db.commit()
    db.refresh(binding)
    return binding


def lock_source_witnesses(db, signed):
    evidence = signed.source_checkpoint_evidence if signed else None
    return lock_checkpoint_witnesses(db, evidence)


def lock_checkpoint_witnesses(db, evidence):
    if evidence is None:
        return {}
    external_ids = [proof.attestation.witness_id for proof in evidence.attestations]
    if len(set(external_ids)) != len(external_ids):
        raise ValueError("Duplicate promotion checkpoint witness identity")
    witnesses = {}
    for identity in sorted(external_ids):
        witness = db.scalar(_namespace_query(db, CapabilityTransparencyWitness)
            .where(CapabilityTransparencyWitness.witness_id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if witness is None or not witness.enabled:
            raise ValueError("Promotion checkpoint witness is not registered or enabled")
        witnesses[identity] = witness
    return witnesses


def check_source_checkpoint(db, signed, source):
    policy = source_witness_policy_snapshot(db)
    evidence = signed.source_checkpoint_evidence
    if evidence is None:
        if policy["required_quorum"]:
            raise ValueError("Promotion requires independent source checkpoint witness evidence")
        return [], policy
    binding = db.scalar(_namespace_query(db, CapabilityPromotionSourceCheckpointBinding)
        .where(CapabilityPromotionSourceCheckpointBinding.source_id == source.id)
        .execution_options(populate_existing=True))
    checkpoint, attestation = evidence.checkpoint, signed.attestation
    if binding is None or (checkpoint.log_id, checkpoint.epoch) != (binding.log_id, binding.epoch):
        raise ValueError("Promotion source checkpoint log/epoch is not pinned")
    if (checkpoint.log_id, checkpoint.epoch, checkpoint.sequence, checkpoint.head_digest_sha256) != (
        attestation.source_transparency_log_id, attestation.source_transparency_epoch,
        attestation.source_transparency_sequence, attestation.source_transparency_head_sha256):
        raise ValueError("Witness checkpoint does not match the signed promotion source head")
    rows = verify_checkpoint_witnesses(db, evidence, policy,
        forbidden_fingerprints={source.key_fingerprint_sha256, attestation.pack_signer_fingerprint_sha256})
    return rows, policy


def verify_checkpoint_witnesses(db, evidence, policy, *, forbidden_fingerprints):
    """Pure exact-checkpoint verification; callers retain witness/key authority."""
    checkpoint = evidence.checkpoint
    if _canonical_hash(checkpoint.model_dump(mode="json", exclude={"digest_sha256"})) != checkpoint.digest_sha256:
        raise ValueError("Promotion checkpoint digest does not match")
    now = utcnow()
    issued, expires = _as_utc(checkpoint.issued_at), _as_utc(checkpoint.expires_at)
    if issued > now + CLOCK_SKEW or expires <= now or expires - issued > timedelta(hours=168):
        raise ValueError("Promotion source checkpoint time window is invalid")
    # A newly issued wrapper cannot refresh an older checkpoint into current evidence.
    if now - issued > timedelta(hours=policy["max_attestation_age_hours"]):
        raise ValueError("Promotion source checkpoint exceeds the witness age policy")
    rows, identities, fingerprints = [], set(), set()
    for proof in evidence.attestations:
        witness_statement = proof.attestation
        identity = witness_statement.witness_id
        witness = db.scalar(_namespace_query(db, CapabilityTransparencyWitness)
            .where(CapabilityTransparencyWitness.witness_id == identity).execution_options(populate_existing=True))
        if witness is None or not witness.enabled:
            raise ValueError("Promotion checkpoint witness is not registered or enabled")
        if identity in identities or witness.key_fingerprint_sha256 in fingerprints:
            raise ValueError("Promotion checkpoint witnesses must have independent identities and keys")
        identities.add(identity)
        fingerprints.add(witness.key_fingerprint_sha256)
        if witness.key_fingerprint_sha256 in forbidden_fingerprints:
            raise ValueError("Promotion or pack signer cannot count as an independent witness")
        if (witness_statement.checkpoint_statement_digest_sha256, witness_statement.log_id, witness_statement.epoch,
            witness_statement.sequence, witness_statement.head_digest_sha256) != (checkpoint.digest_sha256,
            checkpoint.log_id, checkpoint.epoch, checkpoint.sequence, checkpoint.head_digest_sha256):
            raise ValueError("Promotion witness attestation checkpoint does not match")
        witnessed, witness_expiry = _as_utc(witness_statement.witnessed_at), _as_utc(witness_statement.expires_at)
        if (witnessed > now + CLOCK_SKEW or witnessed + CLOCK_SKEW < issued or witness_expiry <= now
            or witness_expiry > expires or witness_expiry - witnessed > timedelta(hours=policy["max_attestation_age_hours"])
            or now - witnessed > timedelta(hours=policy["max_attestation_age_hours"])):
            raise ValueError("Promotion witness attestation time window is invalid")
        if _canonical_hash(witness_statement.model_dump(mode="json", exclude={"digest_sha256"})) != witness_statement.digest_sha256:
            raise ValueError("Promotion witness attestation digest does not match")
        verification = verify_trusted_digest_signature(db, proof.signature,
            expected_digest_sha256=witness_statement.digest_sha256, signed_format_version=SIGNED_WITNESS_ATTESTATION_FORMAT,
            expected_purpose="transparency_witness")
        if (verification["trust_key_id"], verification["key_fingerprint_sha256"]) != (witness.trust_key_id, witness.key_fingerprint_sha256):
            raise ValueError("Promotion witness signature is not from its pinned key")
        rows.append({"witness_id": witness.id, "external_witness_id": identity, **verification,
            "attestation_digest_sha256": witness_statement.digest_sha256})
    count = sum(row["witness_id"] in policy["witness_ids"] for row in rows)
    if count < policy["required_quorum"]:
        raise ValueError("Promotion source checkpoint has insufficient allowlisted witness quorum")
    return sorted(rows, key=lambda row: row["witness_id"])


def get_source_witness_decision(db, receipt_id):
    return db.scalar(_namespace_query(db, CapabilityPromotionSourceWitnessDecision)
        .where(CapabilityPromotionSourceWitnessDecision.receipt_id == receipt_id))


def record_source_witness_decision(db, receipt, signed, verification, *, actor):
    if signed.source_checkpoint_evidence is None:
        return
    db.add(CapabilityPromotionSourceWitnessDecision(receipt_id=receipt.id,
        checkpoint_statement_digest_sha256=signed.source_checkpoint_evidence.checkpoint.digest_sha256,
        evidence_digest_sha256=_canonical_hash(signed.source_checkpoint_evidence.model_dump(mode="json")),
        policy_snapshot=verification["source_witness_policy"], witness_evidence=verification["source_witness_evidence"], accepted_by=actor))


def assert_source_witness_decision(db, receipt, signed, verification):
    if signed.source_checkpoint_evidence is None:
        return
    decision = get_source_witness_decision(db, receipt.id)
    if decision is None or decision.evidence_digest_sha256 != _canonical_hash(signed.source_checkpoint_evidence.model_dump(mode="json")):
        raise ValueError("Promotion witness decision evidence has drifted")
    if decision.witness_evidence != verification["source_witness_evidence"]:
        raise ValueError("Promotion witness decision signer binding has drifted")
