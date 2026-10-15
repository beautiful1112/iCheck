"""Pre-authorized recovery changes only a contained source's public-key pin."""
import base64
import hashlib
import json
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import exists, select

from ..models import (ArtifactTrustKey, CapabilityTransparencyState, CapabilityTransparencyWitness,
    PromotionRecoveryPolicy, PromotionKeyRecovery, PromotionRecoveryEvent, new_id, utcnow)
from ..promotion_recovery_schemas import (POLICY_FORMAT, SIGNED_POLICY_FORMAT, CEREMONY_FORMAT,
    SIGNED_CEREMONY_FORMAT, PromotionRecoveryPolicyStatement, SignedPromotionRecoveryPolicy,
    PromotionKeyRecoveryStatement, SignedPromotionKeyRecovery, PromotionKeyRecoveryRead)
from .artifact_portability import ensure_trust_key_usable, verify_trusted_digest_signature, trusted_digest_signature_message
from .audit import record_audit_event
from .capability_transparency import append_capability_transparency_record, transparency_singleton_id
from .capability_promotions import _as_utc, _assert_source_key_organization, _canonical_hash
from .promotion_authority import promotion_mutation, lock_promotion_policy, lock_promotion_source, commit_with_promotion_authority
from .promotion_witnesses import _namespace_query, lock_checkpoint_witnesses, verify_checkpoint_witnesses
from .trust_authority import lock_trust_authorities

SKEW = timedelta(minutes=5)
MAX_BYTES = 262_144


def _bounded(value):
    if len(json.dumps(value.model_dump(mode="json"), ensure_ascii=True).encode()) > MAX_BYTES:
        raise ValueError("Promotion recovery document exceeds 256 KiB")


def _time(statement, hours):
    now = utcnow()
    if (_as_utc(statement.issued_at) > now + SKEW or _as_utc(statement.expires_at) <= now
        or _as_utc(statement.expires_at) - _as_utc(statement.issued_at) > timedelta(hours=hours)):
        raise ValueError("Promotion recovery time window is invalid or expired")


def _context(source, target):
    if target is None or source.environment_id == target.local_environment_id:
        raise ValueError("A distinct local promotion boundary is required")
    return {"source_id": source.id, "organization_id": source.organization_id,
        "source_environment_id": source.environment_id, "source_stage": source.source_stage,
        "target_environment_id": target.local_environment_id, "target_stage": target.local_stage}


def _assert_context(source, target, statement):
    if any(getattr(statement, name) != value for name, value in _context(source, target).items()):
        raise ValueError("Promotion recovery source or target identity has drifted")


def _retired(db, policy_id):
    return db.scalar(_namespace_query(db, PromotionRecoveryEvent).where(
        PromotionRecoveryEvent.recovery_policy_id == policy_id, PromotionRecoveryEvent.event_type == "policy_retired"))


def _latest_policy(db, source_id):
    return db.scalar(_namespace_query(db, PromotionRecoveryPolicy).where(PromotionRecoveryPolicy.source_id == source_id)
        .order_by(PromotionRecoveryPolicy.version.desc()).limit(1).with_for_update(read=True)
        .execution_options(populate_existing=True))


def _active_policy(db, source, target):
    policy = _latest_policy(db, source.id)
    if policy is None or _retired(db, policy.id):
        raise ValueError("No active pre-incident promotion recovery policy is authorized")
    signed = _historical_policy(policy)
    _assert_context(source, target, signed.statement)
    if signed.statement.current_key_fingerprint_sha256 != source.key_fingerprint_sha256:
        raise ValueError("Recovery policy is not authorized by the current source pin")
    return policy, signed.statement


def _historical_policy(policy):
    """Verify sealed authorization, not current usability of a lost/revoked key."""
    signed = SignedPromotionRecoveryPolicy.model_validate(policy.signed_policy_snapshot)
    _bounded(signed)
    statement, signature = signed.statement, signed.authority_signature
    try:
        public = serialization.load_pem_public_key(policy.authority_public_key_pem.encode())
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("Recovery authorization key is not Ed25519")
        fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
        body = base64.b64decode(signature.signature_base64, validate=True)
        if (_canonical_hash(statement.model_dump(mode="json", exclude={"digest_sha256"})) != statement.digest_sha256
            or statement.digest_sha256 != policy.statement_digest_sha256 or statement.policy_version != policy.version
            or statement.source_id != policy.source_id or fingerprint != statement.current_key_fingerprint_sha256
            or signature.key_fingerprint_sha256 != fingerprint or signature.signed_digest_sha256 != statement.digest_sha256
            or hashlib.sha256(body).hexdigest() != policy.authority_signature_sha256
            or _as_utc(policy.accepted_at) >= _as_utc(statement.expires_at)
            or _as_utc(statement.issued_at) > _as_utc(policy.accepted_at) + SKEW
            or _as_utc(statement.expires_at) - _as_utc(statement.issued_at) > timedelta(hours=24)):
            raise ValueError("Stored recovery authorization binding has drifted")
        public.verify(body, trusted_digest_signature_message(SIGNED_POLICY_FORMAT, statement.digest_sha256))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("Stored recovery authorization is invalid") from exc
    return signed


def _terminal(db, ceremony_id):
    return db.scalar(_namespace_query(db, PromotionRecoveryEvent).where(
        PromotionRecoveryEvent.ceremony_id == ceremony_id, PromotionRecoveryEvent.event_type.in_(["executed", "cancelled"])))


def _pending(db, source_id):
    terminal = exists(select(PromotionRecoveryEvent.id).where(
        PromotionRecoveryEvent.ceremony_id == PromotionKeyRecovery.id,
        PromotionRecoveryEvent.event_type.in_(["executed", "cancelled"])))
    return db.scalar(_namespace_query(db, PromotionKeyRecovery).where(
        PromotionKeyRecovery.source_id == source_id, ~terminal).limit(1))


def _head(db):
    # Never call the public checkpoint reader here: its initialization path
    # commits. Recovery requires an already recorded policy/containment log.
    state = db.scalar(_namespace_query(db, CapabilityTransparencyState).where(
        CapabilityTransparencyState.id == transparency_singleton_id(db)).with_for_update()
        .execution_options(populate_existing=True))
    if state is None or not state.log_id or state.last_sequence < 1:
        raise ValueError("Recovery requires an existing local transparency log")
    return state


def _checkpoint_matches(state, evidence, minimum):
    if evidence is None:
        raise ValueError("Recovery requires fresh independent checkpoint witness evidence")
    cp = evidence.checkpoint
    if (cp.log_id, cp.epoch, cp.sequence, cp.head_digest_sha256) != (
        state.log_id, state.epoch, state.last_sequence, state.head_digest_sha256) or cp.sequence < minimum:
        raise ValueError("Recovery witness checkpoint is not the current local incident head")


def _authority(db, recovery_policy, statement, next_key_id, evidence, signatures=()):
    witnesses = lock_checkpoint_witnesses(db, evidence)
    allowed = {fp: key for fp, key in zip(statement.trustee_fingerprints_sha256, recovery_policy.trustee_key_ids, strict=True)}
    requirements = {next_key_id: {"environment_promotion"}}
    for signature in signatures:
        if signature.key_fingerprint_sha256 not in allowed:
            raise ValueError("Recovery signature is not from a pre-authorized trustee")
        requirements.setdefault(allowed[signature.key_fingerprint_sha256], set()).add("trust_recovery")
    for witness in witnesses.values():
        requirements.setdefault(witness.trust_key_id, set()).add("transparency_witness")
    keys = lock_trust_authorities(db, requirements)
    successor = keys[next_key_id]
    if successor.fingerprint_sha256 in {statement.current_key_fingerprint_sha256,
        *statement.trustee_fingerprints_sha256, *statement.witness_fingerprints_sha256}:
        raise ValueError("Recovery successor must be independent of the old authority, trustees and witnesses")
    for signature in signatures:
        key = keys[allowed[signature.key_fingerprint_sha256]]
        if key.trust_source != "local" or key.fingerprint_sha256 != signature.key_fingerprint_sha256:
            raise ValueError("Recovery trustee pin is unavailable")
    return keys, requirements, witnesses


def _witnesses(db, recovery_policy, statement, evidence, next_fingerprint):
    _bounded(evidence)
    rows = verify_checkpoint_witnesses(db, evidence, {"required_quorum": statement.required_witnesses,
        "witness_ids": recovery_policy.witness_ids, "max_attestation_age_hours": statement.max_evidence_age_hours},
        forbidden_fingerprints={statement.current_key_fingerprint_sha256, next_fingerprint, *statement.trustee_fingerprints_sha256})
    pins = dict(zip(recovery_policy.witness_ids, statement.witness_fingerprints_sha256, strict=True))
    if any(row["witness_id"] in pins and pins[row["witness_id"]] != row["key_fingerprint_sha256"] for row in rows):
        raise ValueError("Recovery witness no longer matches its pre-authorized fingerprint")
    return rows


def _check_keys(db, keys, requirements):
    for identity, purposes in requirements.items():
        for purpose in purposes:
            ensure_trust_key_usable(db, keys[identity], expected_purpose=purpose)


def _check_policy_pins(keys, trustees, witnesses):
    if any(key.trust_source != "local" for key in trustees) or any(not witness.enabled or
        witness.key_fingerprint_sha256 != keys[witness.trust_key_id].fingerprint_sha256 for witness in witnesses):
        raise ValueError("Pre-incident recovery pins changed before commit")


def _event(db, policy, *, event_type, actor, reason, ceremony=None, evidence=None, verified=None):
    identity = new_id()
    record = append_capability_transparency_record(db, event_type="capability.promotion_recovery." + event_type,
        entity_type="promotion_recovery_event", entity_id=identity, subject_digest_sha256=(
            ceremony.statement_digest_sha256 if ceremony else policy.statement_digest_sha256),
        details={"source_id": policy.source_id, "policy_id": policy.id, "ceremony_id": ceremony.id if ceremony else None})
    result = PromotionRecoveryEvent(id=identity, source_id=policy.source_id, recovery_policy_id=policy.id,
        ceremony_id=ceremony.id if ceremony else None, event_type=event_type,
        checkpoint_evidence_snapshot=evidence.model_dump(mode="json") if evidence else None,
        verified_evidence=verified or {}, transparency_sequence=record.sequence, reason=reason, actor=actor, occurred_at=utcnow())
    db.add(result)
    record_audit_event(db, event_type="capability.promotion_recovery." + event_type, actor_type="user", actor_id=actor,
        entity_type="promotion_recovery_event", entity_id=identity,
        details={"source_id": policy.source_id, "reason_sha256": hashlib.sha256(reason.encode()).hexdigest()})
    db.flush()
    return result


def retire_promotion_recovery_policies(db, source, *, actor, reason):
    policy = _latest_policy(db, source.id)
    if policy is not None and not _retired(db, policy.id):
        _event(db, policy, event_type="policy_retired", actor=actor, reason=reason)


def _policy_authority(db, source, target, payload):
    if not source.enabled or _pending(db, source.id):
        raise ValueError("Authorize recovery before containing the promotion source")
    _context(source, target)
    if len(set(payload.trustee_trust_key_ids)) != len(payload.trustee_trust_key_ids) or len(set(payload.witness_ids)) != len(payload.witness_ids):
        raise ValueError("Recovery requires distinct local identities")
    witnesses = []
    for identity in sorted(payload.witness_ids):
        witness = db.scalar(_namespace_query(db, CapabilityTransparencyWitness).where(CapabilityTransparencyWitness.id == identity)
            .with_for_update(read=True).execution_options(populate_existing=True))
        if witness is None or not witness.enabled:
            raise ValueError("Recovery witness is not enabled locally")
        witnesses.append(witness)
    requirements = {source.trust_key_id: {"environment_promotion"}}
    for identity in payload.trustee_trust_key_ids:
        requirements.setdefault(identity, set()).add("trust_recovery")
    for witness in witnesses:
        requirements.setdefault(witness.trust_key_id, set()).add("transparency_witness")
    keys = lock_trust_authorities(db, requirements)
    authority = keys[source.trust_key_id]
    if authority.fingerprint_sha256 != source.key_fingerprint_sha256:
        raise ValueError("Recovery authorization is not bound to the source pin")
    _assert_source_key_organization(db, authority, source.organization_id)
    trustees = sorted([keys[identity] for identity in payload.trustee_trust_key_ids], key=lambda key: key.fingerprint_sha256)
    if any(key.trust_source != "local" for key in trustees):
        raise ValueError("Recovery trustees must be pinned locally")
    witnesses.sort(key=lambda item: item.key_fingerprint_sha256)
    if any(keys[w.trust_key_id].fingerprint_sha256 != w.key_fingerprint_sha256 for w in witnesses):
        raise ValueError("Recovery witness fingerprint is not pinned")
    return keys, requirements, trustees, witnesses


@promotion_mutation
def create_promotion_recovery_policy_statement(db, source_id, payload, *, actor):
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id)
    keys, requirements, trustees, witnesses = _policy_authority(db, source, target, payload)
    previous = _latest_policy(db, source.id)
    now = utcnow()
    material = {**_context(source, target), "format_version": POLICY_FORMAT, "policy_version": previous.version + 1 if previous else 1,
        "current_key_fingerprint_sha256": source.key_fingerprint_sha256,
        "trustee_fingerprints_sha256": [key.fingerprint_sha256 for key in trustees],
        "witness_fingerprints_sha256": [w.key_fingerprint_sha256 for w in witnesses],
        "required_approvals": payload.required_approvals, "required_witnesses": payload.required_witnesses,
        "delay_hours": payload.delay_hours, "max_evidence_age_hours": payload.max_evidence_age_hours,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=payload.validity_hours)).isoformat().replace("+00:00", "Z")}
    statement = PromotionRecoveryPolicyStatement.model_validate({**material, "digest_sha256": _canonical_hash(material)})
    record_audit_event(db, event_type="capability.promotion_recovery.policy_statement_generated", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_source", entity_id=source.id, details={"statement_digest_sha256": statement.digest_sha256})
    def check():
        _check_keys(db, keys, requirements); _time(statement, 24); _assert_context(source, target, statement)
        _check_policy_pins(keys, trustees, witnesses)
        if not source.enabled or source.key_fingerprint_sha256 != statement.current_key_fingerprint_sha256:
            raise ValueError("Recovery authorization context changed before commit")
    commit_with_promotion_authority(db, check)
    return statement


@promotion_mutation
def authorize_promotion_recovery_policy(db, source_id, payload, *, actor):
    _bounded(payload)
    signed = payload.signed_policy
    _bounded(signed)
    statement = signed.statement
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id, writable=True)
    accepted = db.scalar(_namespace_query(db, PromotionRecoveryPolicy).where(PromotionRecoveryPolicy.source_id == source.id,
        PromotionRecoveryPolicy.statement_digest_sha256 == statement.digest_sha256))
    if accepted is not None:
        if (accepted.signed_policy_snapshot != signed.model_dump(mode="json")
            or set(accepted.trustee_key_ids) != set(payload.trustee_trust_key_ids) or set(accepted.witness_ids) != set(payload.witness_ids)):
            raise ValueError("Recovery policy retry does not match the original proof")
        db.commit(); db.refresh(accepted)
        return accepted
    keys, requirements, trustees, witnesses = _policy_authority(db, source, target, payload)
    previous = _latest_policy(db, source.id)
    _assert_context(source, target, statement); _time(statement, 24)
    if (_canonical_hash(statement.model_dump(mode="json", exclude={"digest_sha256"})) != statement.digest_sha256
        or statement.policy_version != (previous.version + 1 if previous else 1)
        or statement.current_key_fingerprint_sha256 != source.key_fingerprint_sha256
        or statement.trustee_fingerprints_sha256 != [key.fingerprint_sha256 for key in trustees]
        or statement.witness_fingerprints_sha256 != [w.key_fingerprint_sha256 for w in witnesses]):
        raise ValueError("Recovery policy authorization context does not match")
    verification = verify_trusted_digest_signature(db, signed.authority_signature, expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_POLICY_FORMAT, expected_purpose="environment_promotion")
    if verification["trust_key_id"] != source.trust_key_id:
        raise ValueError("Recovery policy lacks the current pinned authority signature")
    retire_promotion_recovery_policies(db, source, actor=actor, reason="Superseded by a new signed pre-incident recovery policy.")
    identity = new_id()
    record = append_capability_transparency_record(db, event_type="capability.promotion_recovery.policy_authorized",
        entity_type="promotion_recovery_policy", entity_id=identity, subject_digest_sha256=statement.digest_sha256,
        details={"source_id": source.id, "version": statement.policy_version})
    policy = PromotionRecoveryPolicy(id=identity, source_id=source.id, version=statement.policy_version,
        trustee_key_ids=[key.id for key in trustees], witness_ids=[w.id for w in witnesses],
        authority_public_key_pem=keys[source.trust_key_id].public_key_pem, statement_digest_sha256=statement.digest_sha256,
        authority_signature_sha256=verification["signature_sha256"], signed_policy_snapshot=signed.model_dump(mode="json"),
        transparency_sequence=record.sequence, reason=payload.reason, accepted_by=actor, accepted_at=utcnow())
    db.add(policy)
    record_audit_event(db, event_type="capability.promotion_recovery.policy_authorized", actor_type="user", actor_id=actor,
        entity_type="promotion_recovery_policy", entity_id=identity,
        details={"source_id": source.id, "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
    def check():
        _check_keys(db, keys, requirements); _time(statement, 24); _assert_context(source, target, statement)
        _check_policy_pins(keys, trustees, witnesses)
        if not source.enabled or source.key_fingerprint_sha256 != statement.current_key_fingerprint_sha256:
            raise ValueError("Recovery authorization context changed before commit")
        _historical_policy(policy)
    commit_with_promotion_authority(db, check)
    db.refresh(policy)
    return policy


def _contained(db, source):
    if source.enabled:
        raise ValueError("Disable the promotion source before emergency recovery")
    # Unlike planned handover, emergency recovery must not require publishing
    # qualification made with a compromised key. The accepted head is retained;
    # old pending receipts fail the existing current-pin publication check.


def _verify_ceremony(db, source, target, policy, authorization, signed, next_key, requirements, keys):
    statement = signed.statement
    _bounded(signed); _time(statement, 168); _assert_context(source, target, statement)
    if (_canonical_hash(statement.model_dump(mode="json", exclude={"digest_sha256"})) != statement.digest_sha256
        or statement.recovery_policy_digest_sha256 != policy.statement_digest_sha256
        or statement.current_key_fingerprint_sha256 != authorization.current_key_fingerprint_sha256
        or (statement.promotion_sequence, statement.latest_statement_digest_sha256) != (source.latest_sequence, source.latest_statement_digest_sha256)
        or statement.next_key_fingerprint_sha256 != next_key.fingerprint_sha256):
        raise ValueError("Recovery signed policy, pin or accepted head has drifted")
    _assert_source_key_organization(db, next_key, source.organization_id)
    next_verification = verify_trusted_digest_signature(db, signed.next_signature, expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_CEREMONY_FORMAT, expected_purpose="environment_promotion")
    if next_verification["trust_key_id"] != next_key.id:
        raise ValueError("Recovery lacks the selected successor's signature")
    proofs, fingerprints = [], set()
    for signature in signed.trustee_signatures:
        verified = verify_trusted_digest_signature(db, signature, expected_digest_sha256=statement.digest_sha256,
            signed_format_version=SIGNED_CEREMONY_FORMAT, expected_purpose="trust_recovery")
        fingerprint = verified["key_fingerprint_sha256"]
        if fingerprint in fingerprints or fingerprint not in authorization.trustee_fingerprints_sha256:
            raise ValueError("Recovery trustee approval is duplicate or unauthorized")
        if "trust_recovery" not in requirements.get(verified["trust_key_id"], set()) or keys[verified["trust_key_id"]].trust_source != "local":
            raise ValueError("Recovery trustee authority was not retained")
        fingerprints.add(fingerprint); proofs.append(verified)
    if len(proofs) < authorization.required_approvals:
        raise ValueError("Recovery trustee quorum is insufficient")
    return {"next_signature": next_verification, "trustees": sorted(proofs, key=lambda row: row["key_fingerprint_sha256"])}


@promotion_mutation
def create_promotion_key_recovery_statement(db, source_id, payload, *, actor):
    _bounded(payload)
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id)
    _contained(db, source)
    policy, authorization = _active_policy(db, source, target)
    if _pending(db, source.id):
        raise ValueError("A promotion recovery ceremony is already pending")
    if payload.validity_hours <= authorization.delay_hours:
        raise ValueError("Recovery validity must exceed the mandatory delay")
    keys, requirements, witnesses = _authority(db, policy, authorization, payload.new_trust_key_id, payload.checkpoint_evidence)
    next_key = keys[payload.new_trust_key_id]
    _assert_source_key_organization(db, next_key, source.organization_id)
    state = _head(db); _checkpoint_matches(state, payload.checkpoint_evidence, policy.transparency_sequence)
    _witnesses(db, policy, authorization, payload.checkpoint_evidence, next_key.fingerprint_sha256)
    now = utcnow()
    material = {**_context(source, target), "format_version": CEREMONY_FORMAT,
        "current_key_fingerprint_sha256": source.key_fingerprint_sha256,
        "recovery_policy_digest_sha256": policy.statement_digest_sha256, "ceremony_id": new_id(),
        "next_key_fingerprint_sha256": next_key.fingerprint_sha256, "promotion_sequence": source.latest_sequence,
        "latest_statement_digest_sha256": source.latest_statement_digest_sha256,
        "checkpoint_statement_digest_sha256": payload.checkpoint_evidence.checkpoint.digest_sha256,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=payload.validity_hours)).isoformat().replace("+00:00", "Z")}
    statement = PromotionKeyRecoveryStatement.model_validate({**material, "digest_sha256": _canonical_hash(material)})
    record_audit_event(db, event_type="capability.promotion_recovery.statement_generated", actor_type="user", actor_id=actor,
        entity_type="capability_promotion_source", entity_id=source.id, details={"statement_digest_sha256": statement.digest_sha256})
    def check():
        _contained(db, source); _check_keys(db, keys, requirements); _time(statement, 168)
        _active_policy(db, source, target)
        _checkpoint_matches(state, payload.checkpoint_evidence, policy.transparency_sequence)
        _witnesses(db, policy, authorization, payload.checkpoint_evidence, next_key.fingerprint_sha256)
    commit_with_promotion_authority(db, check)
    return statement


def _proposal_authority(db, source, target, payload):
    signed = payload.signed_recovery
    _contained(db, source)
    policy, authorization = _active_policy(db, source, target)
    if _pending(db, source.id):
        raise ValueError("A promotion recovery ceremony is already pending")
    keys, requirements, witnesses = _authority(db, policy, authorization, payload.new_trust_key_id,
        payload.checkpoint_evidence, signed.trustee_signatures)
    successor = keys[payload.new_trust_key_id]
    verified = _verify_ceremony(db, source, target, policy, authorization, signed, successor, requirements, keys)
    now = utcnow()
    if _as_utc(signed.statement.expires_at) <= now + timedelta(hours=authorization.delay_hours):
        raise ValueError("Recovery ceremony expires before the mandatory delay")
    state = _head(db); _checkpoint_matches(state, payload.checkpoint_evidence, policy.transparency_sequence)
    if signed.statement.checkpoint_statement_digest_sha256 != payload.checkpoint_evidence.checkpoint.digest_sha256:
        raise ValueError("Recovery signed incident checkpoint does not match")
    witness_proofs = _witnesses(db, policy, authorization, payload.checkpoint_evidence, successor.fingerprint_sha256)
    return policy, authorization, keys, requirements, witnesses, successor, verified, witness_proofs, now


@promotion_mutation
def preview_promotion_key_recovery(db, source_id, payload):
    _bounded(payload)
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id)
    policy, authorization, _, _, _, successor, verified, witnesses, _ = _proposal_authority(db, source, target, payload)
    result = {"eligible": True, "source_id": source.id, "recovery_policy_id": policy.id,
        "next_key_fingerprint_sha256": successor.fingerprint_sha256, "trustee_count": len(verified["trustees"]),
        "witness_count": sum(row["witness_id"] in policy.witness_ids for row in witnesses),
        "required_approvals": authorization.required_approvals, "required_witnesses": authorization.required_witnesses,
        "delay_hours": authorization.delay_hours, "authorizes_execution": False}
    db.rollback()
    return result


@promotion_mutation
def propose_promotion_key_recovery(db, source_id, payload, *, actor):
    _bounded(payload)
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id, writable=True)
    signed = payload.signed_recovery
    existing = db.scalar(_namespace_query(db, PromotionKeyRecovery).where(PromotionKeyRecovery.source_id == source.id,
        PromotionKeyRecovery.statement_digest_sha256 == signed.statement.digest_sha256))
    if existing:
        if (existing.signed_recovery_snapshot != signed.model_dump(mode="json") or existing.to_trust_key_id != payload.new_trust_key_id
            or existing.checkpoint_evidence_snapshot != payload.checkpoint_evidence.model_dump(mode="json")):
            raise ValueError("Recovery proposal retry proof differs from the original ceremony")
        db.commit(); db.refresh(existing)
        return recovery_read(db, existing)
    policy, authorization, keys, requirements, witnesses, successor, verified, witness_proofs, now = _proposal_authority(db, source, target, payload)
    identity = new_id()
    record = append_capability_transparency_record(db, event_type="capability.promotion_recovery.proposed",
        entity_type="promotion_key_recovery", entity_id=identity, subject_digest_sha256=signed.statement.digest_sha256,
        details={"source_id": source.id, "policy_id": policy.id})
    ceremony = PromotionKeyRecovery(id=identity, source_id=source.id, recovery_policy_id=policy.id,
        to_trust_key_id=successor.id, ceremony_uuid=signed.statement.ceremony_id, statement_digest_sha256=signed.statement.digest_sha256,
        signed_recovery_snapshot=signed.model_dump(mode="json"), checkpoint_evidence_snapshot=payload.checkpoint_evidence.model_dump(mode="json"),
        verified_evidence=verified, execute_after=now + timedelta(hours=authorization.delay_hours),
        proposal_transparency_sequence=record.sequence, proposed_at=now, proposed_by=actor, reason=payload.reason)
    db.add(ceremony)
    record_audit_event(db, event_type="capability.promotion_recovery.proposed", actor_type="user", actor_id=actor,
        entity_type="promotion_key_recovery", entity_id=identity,
        details={"source_id": source.id, "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()})
    def check():
        _contained(db, source); _check_keys(db, keys, requirements); _active_policy(db, source, target)
        if _verify_ceremony(db, source, target, policy, authorization, signed, successor, requirements, keys) != verified:
            raise ValueError("Recovery signer evidence changed before commit")
        if _witnesses(db, policy, authorization, payload.checkpoint_evidence, successor.fingerprint_sha256) != witness_proofs:
            raise ValueError("Recovery witness evidence changed before commit")
        if _as_utc(signed.statement.expires_at) <= _as_utc(ceremony.execute_after):
            raise ValueError("Recovery ceremony expires before the mandatory delay")
    commit_with_promotion_authority(db, check)
    db.refresh(ceremony)
    return recovery_read(db, ceremony)


def recovery_read(db, ceremony):
    terminal = _terminal(db, ceremony.id)
    return PromotionKeyRecoveryRead.model_validate({**{name: getattr(ceremony, name) for name in PromotionKeyRecoveryRead.model_fields if name != "status"},
        "status": terminal.event_type if terminal else "pending"})


def _ceremony(db, identity):
    ceremony = db.scalar(_namespace_query(db, PromotionKeyRecovery).where(PromotionKeyRecovery.id == identity)
        .with_for_update(read=True).execution_options(populate_existing=True))
    if ceremony is None:
        raise LookupError("Promotion recovery ceremony not found in the selected namespace")
    return ceremony


@promotion_mutation
def execute_promotion_key_recovery(db, identity, payload, *, actor):
    _bounded(payload)
    metadata = db.scalar(_namespace_query(db, PromotionKeyRecovery).where(PromotionKeyRecovery.id == identity))
    if metadata is None:
        raise LookupError("Promotion recovery ceremony not found in the selected namespace")
    target = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=metadata.source_id, writable=True)
    ceremony = _ceremony(db, identity)
    terminal = _terminal(db, identity)
    if terminal:
        if terminal.event_type != "executed":
            raise ValueError("Cancelled recovery cannot execute")
        db.commit(); db.refresh(ceremony)
        return recovery_read(db, ceremony)
    _contained(db, source)
    if actor == ceremony.proposed_by:
        raise ValueError("Recovery requires a different authenticated executor")
    if utcnow() < _as_utc(ceremony.execute_after):
        raise ValueError("Mandatory promotion recovery delay has not elapsed")
    policy, authorization = _active_policy(db, source, target)
    if policy.id != ceremony.recovery_policy_id:
        raise ValueError("Recovery policy changed after proposal")
    signed = SignedPromotionKeyRecovery.model_validate(ceremony.signed_recovery_snapshot)
    keys, requirements, witnesses = _authority(db, policy, authorization, ceremony.to_trust_key_id,
        payload.checkpoint_evidence, signed.trustee_signatures)
    successor = keys[ceremony.to_trust_key_id]
    verified = _verify_ceremony(db, source, target, policy, authorization, signed, successor, requirements, keys)
    if verified != ceremony.verified_evidence or signed.statement.digest_sha256 != ceremony.statement_digest_sha256:
        raise ValueError("Recovery sealed signer evidence has drifted")
    state = _head(db); _checkpoint_matches(state, payload.checkpoint_evidence, ceremony.proposal_transparency_sequence)
    witness_proofs = _witnesses(db, policy, authorization, payload.checkpoint_evidence, successor.fingerprint_sha256)
    source.trust_key_id, source.key_fingerprint_sha256 = successor.id, successor.fingerprint_sha256
    source.updated_at = utcnow()
    _event(db, policy, event_type="executed", actor=actor, reason=payload.reason, ceremony=ceremony,
        evidence=payload.checkpoint_evidence, verified={**verified, "witnesses": witness_proofs})
    _event(db, policy, event_type="policy_retired", actor=actor, reason="Consumed by completed emergency recovery.")
    def check():
        _contained(db, source); _check_keys(db, keys, requirements)
        _assert_context(source, target, authorization); _historical_policy(policy)
        if (source.trust_key_id, source.key_fingerprint_sha256) != (successor.id, successor.fingerprint_sha256):
            raise ValueError("Recovered source pin changed before commit")
        if _verify_ceremony(db, source, target, policy, authorization, signed, successor, requirements, keys) != verified:
            raise ValueError("Recovery signer evidence changed before commit")
        if _witnesses(db, policy, authorization, payload.checkpoint_evidence, successor.fingerprint_sha256) != witness_proofs:
            raise ValueError("Recovery witness evidence changed before commit")
        if utcnow() < _as_utc(ceremony.execute_after):
            raise ValueError("Mandatory promotion recovery delay has not elapsed")
    commit_with_promotion_authority(db, check)
    db.refresh(ceremony)
    return recovery_read(db, ceremony)


@promotion_mutation
def cancel_promotion_key_recovery(db, identity, payload, *, actor):
    metadata = db.scalar(_namespace_query(db, PromotionKeyRecovery).where(PromotionKeyRecovery.id == identity))
    if metadata is None:
        raise LookupError("Promotion recovery ceremony not found in the selected namespace")
    lock_promotion_policy(db)
    lock_promotion_source(db, source_id=metadata.source_id, writable=True)
    ceremony = _ceremony(db, identity)
    terminal = _terminal(db, identity)
    if terminal:
        if terminal.event_type != "cancelled":
            raise ValueError("Executed recovery cannot be cancelled")
        db.commit(); db.refresh(ceremony)
        return recovery_read(db, ceremony)
    policy = db.scalar(_namespace_query(db, PromotionRecoveryPolicy).where(PromotionRecoveryPolicy.id == ceremony.recovery_policy_id))
    _event(db, policy, event_type="cancelled", actor=actor, reason=payload.reason, ceremony=ceremony)
    db.commit(); db.refresh(ceremony)
    return recovery_read(db, ceremony)


def prepare_source_restoration(db, source, target, evidence):
    """Called before source signer locks; the ordinary enable route is gated too."""
    if _pending(db, source.id):
        raise ValueError("Cancel the pending recovery ceremony before reenabling its source")
    executed = db.scalar(_namespace_query(db, PromotionRecoveryEvent).where(PromotionRecoveryEvent.source_id == source.id,
        PromotionRecoveryEvent.event_type == "executed").order_by(PromotionRecoveryEvent.transparency_sequence.desc()).limit(1))
    if executed is None:
        return None
    ceremony = _ceremony(db, executed.ceremony_id)
    if ceremony.to_trust_key_id != source.trust_key_id or db.scalar(_namespace_query(db, PromotionRecoveryEvent).where(
        PromotionRecoveryEvent.ceremony_id == ceremony.id, PromotionRecoveryEvent.event_type == "restored")):
        return None
    policy = db.scalar(_namespace_query(db, PromotionRecoveryPolicy).where(PromotionRecoveryPolicy.id == ceremony.recovery_policy_id)
        .with_for_update(read=True).execution_options(populate_existing=True))
    authorization = _historical_policy(policy).statement
    _assert_context(source, target, authorization)
    keys, requirements, witnesses = _authority(db, policy, authorization, ceremony.to_trust_key_id, evidence)
    successor = keys[ceremony.to_trust_key_id]
    state = _head(db); _checkpoint_matches(state, evidence, executed.transparency_sequence)
    proofs = _witnesses(db, policy, authorization, evidence, successor.fingerprint_sha256)
    def check():
        _check_keys(db, keys, requirements); _assert_context(source, target, authorization)
        if (source.trust_key_id, source.key_fingerprint_sha256) != (successor.id, successor.fingerprint_sha256):
            raise ValueError("Recovery restoration pin changed before commit")
        if _witnesses(db, policy, authorization, evidence, successor.fingerprint_sha256) != proofs:
            raise ValueError("Recovery restoration witness evidence changed before commit")
    return policy, ceremony, proofs, check, successor


def record_source_restoration(db, context, evidence, *, actor, reason):
    if context:
        policy, ceremony, proofs, _, _ = context
        _event(db, policy, event_type="restored", actor=actor, reason=reason, ceremony=ceremony,
            evidence=evidence, verified={"witnesses": proofs})


def list_promotion_recovery_policies(db, source_id=None):
    query = _namespace_query(db, PromotionRecoveryPolicy)
    if source_id: query = query.where(PromotionRecoveryPolicy.source_id == source_id)
    return list(db.scalars(query.order_by(PromotionRecoveryPolicy.accepted_at.desc()).limit(500)))


def list_promotion_key_recoveries(db, source_id=None):
    query = _namespace_query(db, PromotionKeyRecovery)
    if source_id: query = query.where(PromotionKeyRecovery.source_id == source_id)
    return [recovery_read(db, row) for row in db.scalars(query.order_by(PromotionKeyRecovery.proposed_at.desc()).limit(500))]


def list_promotion_recovery_events(db, source_id=None):
    query = _namespace_query(db, PromotionRecoveryEvent)
    if source_id: query = query.where(PromotionRecoveryEvent.source_id == source_id)
    return list(db.scalars(query.order_by(PromotionRecoveryEvent.occurred_at.desc()).limit(500)))
