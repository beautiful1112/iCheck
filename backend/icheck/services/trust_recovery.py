from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.orm import Session

from ..models import (
    ArtifactTrustKey,
    CapabilityTransparencyCheckpointOffer,
    CapabilityTransparencyState,
    CapabilityTransparencyWitness,
    CapabilityTransparencyWitnessPolicy,
    OrganizationTrustDomain,
    OrganizationTrustRecoveryPolicy,
    OrganizationTrustRootReanchor,
    new_id,
    utcnow,
)
from ..trust_recovery_schemas import (
    ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT,
    ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
    SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT,
    SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
    OrganizationTrustRecoveryPolicyCreate,
    OrganizationTrustRecoveryPolicyStatement,
    OrganizationTrustRecoveryPolicyStatementCreate,
    OrganizationTrustRootReanchorAction,
    OrganizationTrustRootReanchorPreviewCreate,
    OrganizationTrustRootReanchorPreviewRead,
    OrganizationTrustRootReanchorProposalCreate,
    OrganizationTrustRootReanchorStatement,
    OrganizationTrustRootReanchorStatementCreate,
    SignedOrganizationTrustRootReanchor,
)
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .artifact_lifecycle import prepare_artifact_mutation
from .trust_authority import lock_trust_authorities
from .trust_namespace import assert_selected_trust_namespace, selected_trust_namespace
from .capability_transparency import (
    append_capability_transparency_record,
    transparency_singleton_id,
)
from .transparency_witnessing import (
    _valid_offer_attestations,
    require_live_witnessed_checkpoint_offer,
)
from .promotion_authority import commit_with_promotion_authority


RECOVERY_CLOCK_SKEW = timedelta(minutes=5)
RECOVERY_POLICY_MAX_LIFETIME = timedelta(hours=24)
ROOT_REANCHOR_MAX_LIFETIME = timedelta(hours=168)
RECOVERY_DOCUMENT_MAX_BYTES = 256_000


def _root_mutation(operation):
    @wraps(operation)
    def guarded(db, *args, **kwargs):
        try:
            prepare_artifact_mutation(db, purpose="Organization root recovery")
            return operation(db, *args, **kwargs)
        except Exception:
            try:
                db.rollback()
            except InvalidRequestError:
                db.close()
            raise
    return guarded


def _locked_domain(db: Session, domain_id: str) -> OrganizationTrustDomain:
    tenant_id, region_id = selected_trust_namespace(db)
    domain = db.scalar(select(OrganizationTrustDomain).where(
        OrganizationTrustDomain.id == domain_id,
        OrganizationTrustDomain.tenant_id == tenant_id,
        OrganizationTrustDomain.region_id == region_id,
    ).with_for_update().execution_options(populate_existing=True))
    if domain is None:
        raise LookupError("Organization trust domain not found")
    return domain


def _root_checkpoint(db: Session, *, retain: bool = False) -> CapabilityTransparencyState:
    query = select(CapabilityTransparencyState).where(
        CapabilityTransparencyState.id == transparency_singleton_id(db))
    if retain:
        query = query.with_for_update()
    state = db.scalar(query.execution_options(populate_existing=True))
    if state is None or state.log_id is None or state.last_sequence < 1:
        raise ValueError("Root recovery requires an existing local transparency log")
    return state


def _retain_reanchor_authority(db: Session, policy: OrganizationTrustRecoveryPolicy,
                               next_key_id: str, offer: CapabilityTransparencyCheckpointOffer,
                               signed: SignedOrganizationTrustRootReanchor):
    """Retain selected policy, witness pins and one sorted signer/domain batch."""
    held_policy = db.scalar(select(OrganizationTrustRecoveryPolicy).where(
        OrganizationTrustRecoveryPolicy.id == policy.id).with_for_update(read=True)
        .execution_options(populate_existing=True))
    if held_policy is None or not held_policy.active:
        raise ValueError("Root recovery policy is no longer active")
    witness_policy = db.scalar(select(CapabilityTransparencyWitnessPolicy).where(
        CapabilityTransparencyWitnessPolicy.id == transparency_singleton_id(db))
        .with_for_update(read=True).execution_options(populate_existing=True))
    if witness_policy is None:
        raise ValueError("Root recovery requires a configured witness policy")
    held_offer = db.scalar(select(CapabilityTransparencyCheckpointOffer).where(
        CapabilityTransparencyCheckpointOffer.id == offer.id).with_for_update(read=True)
        .execution_options(populate_existing=True))
    if held_offer is None:
        raise ValueError("Root recovery witness offer is unavailable")
    valid = _valid_offer_attestations(db, held_offer)
    witness_ids = sorted({row.witness_id for row in valid})
    witnesses = {}
    for identity in witness_ids:
        row = db.scalar(select(CapabilityTransparencyWitness).where(
            CapabilityTransparencyWitness.id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if row is None:
            raise ValueError("Root recovery witness pin is unavailable")
        witnesses[identity] = row
    allowed = dict(zip(held_policy.trustee_key_fingerprints_sha256,
                       held_policy.trustee_key_ids, strict=True))
    requirements = {next_key_id: {"trust_bundle"}}
    for signature in signed.trustee_signatures:
        trustee_id = allowed.get(signature.key_fingerprint_sha256)
        if trustee_id is None:
            raise ValueError("Root recovery trustee is not pre-authorized")
        requirements.setdefault(trustee_id, set()).add("trust_recovery")
    for witness in witnesses.values():
        requirements.setdefault(witness.trust_key_id, set()).add("transparency_witness")
    keys = lock_trust_authorities(db, requirements)
    return held_policy, held_offer, witness_policy, witnesses, keys, requirements


def _check_retained_reanchor(db: Session, authority, *, delay_hours=0):
    policy, offer, witness_policy, witnesses, keys, requirements = authority
    now = utcnow()
    if _as_utc(offer.expires_at) <= now + timedelta(hours=delay_hours):
        raise ValueError("Root recovery witness checkpoint has expired")
    if witness_policy.required_quorum < 2:
        raise ValueError("Root recovery requires two independent witnesses")
    for key_id, purposes in requirements.items():
        for purpose in purposes:
            ensure_trust_key_usable(db, keys[key_id], expected_purpose=purpose)
    if any(not row.enabled or row.key_fingerprint_sha256 != keys[row.trust_key_id].fingerprint_sha256
           for row in witnesses.values()):
        raise ValueError("Root recovery witness pin changed")
    valid = _valid_offer_attestations(db, offer)
    if len({row.witness_id for row in valid if row.witness_id in witnesses}) < witness_policy.required_quorum:
        raise ValueError("Root recovery witness quorum is no longer live")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _json_timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _active_policy(
    db: Session,
    domain_id: str,
) -> OrganizationTrustRecoveryPolicy | None:
    return db.scalar(
        select(OrganizationTrustRecoveryPolicy)
        .where(
            OrganizationTrustRecoveryPolicy.trust_domain_id == domain_id,
            OrganizationTrustRecoveryPolicy.active.is_(True),
        )
        .order_by(OrganizationTrustRecoveryPolicy.version.desc())
        .limit(1)
    )


def _get_domain(db: Session, domain_id: str) -> OrganizationTrustDomain:
    domain = db.get(OrganizationTrustDomain, domain_id)
    if domain is None:
        raise LookupError("Organization trust domain not found")
    assert_selected_trust_namespace(db, domain)
    return domain


def _local_key(
    db: Session,
    key_id: str,
    *,
    purpose: str,
    label: str,
) -> ArtifactTrustKey:
    key = db.get(ArtifactTrustKey, key_id)
    if key is None:
        raise ValueError(f"{label} trust key does not exist")
    if key.trust_source != "local":
        raise ValueError(f"{label} trust key must be pinned locally")
    ensure_trust_key_usable(db, key, expected_purpose=purpose)
    return key


def _recovery_trustees(
    db: Session,
    key_ids: list[str],
    *,
    authority_fingerprint: str,
) -> list[ArtifactTrustKey]:
    if len(set(key_ids)) != len(key_ids):
        raise ValueError("Recovery trustee keys must be unique")
    trustees = [
        _local_key(
            db,
            key_id,
            purpose="trust_recovery",
            label="Recovery trustee",
        )
        for key_id in key_ids
    ]
    if any(
        item.fingerprint_sha256 == authority_fingerprint
        for item in trustees
    ):
        raise ValueError("The active root cannot also be a recovery trustee")
    return sorted(trustees, key=lambda item: item.fingerprint_sha256)


def create_recovery_policy_statement(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRecoveryPolicyStatementCreate,
    *,
    actor: str,
) -> OrganizationTrustRecoveryPolicyStatement:
    domain = _get_domain(db, domain_id)
    if not domain.enabled:
        raise ValueError(
            "Recovery policy must be authorized before the trust domain is disabled"
        )
    authority = _local_key(
        db,
        domain.authority_trust_key_id,
        purpose="trust_bundle",
        label="Organization root",
    )
    trustees = _recovery_trustees(
        db,
        payload.trustee_trust_key_ids,
        authority_fingerprint=authority.fingerprint_sha256,
    )
    latest = db.scalar(select(OrganizationTrustRecoveryPolicy).where(
        OrganizationTrustRecoveryPolicy.trust_domain_id == domain.id,
    ).order_by(OrganizationTrustRecoveryPolicy.version.desc()).limit(1))
    policy_version = latest.version + 1 if latest is not None else 1
    issued_at = utcnow()
    expires_at = issued_at + timedelta(hours=payload.validity_hours)
    material = {
        "format_version": ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT,
        "organization_id": domain.organization_id,
        "trust_domain_id": domain.id,
        "policy_version": policy_version,
        "bundle_sequence": domain.latest_sequence,
        "bundle_digest_sha256": domain.latest_bundle_digest_sha256,
        "authority_key_fingerprint_sha256": (
            authority.fingerprint_sha256
        ),
        "trustee_key_fingerprints_sha256": [
            item.fingerprint_sha256 for item in trustees
        ],
        "required_approvals": payload.required_approvals,
        "delay_hours": payload.delay_hours,
        "issued_at": _json_timestamp(issued_at),
        "expires_at": _json_timestamp(expires_at),
    }
    statement = OrganizationTrustRecoveryPolicyStatement.model_validate(
        {**material, "digest_sha256": _canonical_hash(material)}
    )
    record_audit_event(
        db,
        event_type="capability.trust_recovery_policy_statement.generated",
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_domain",
        entity_id=domain.id,
        details={
            "policy_version": policy_version,
            "trustee_count": len(trustees),
            "required_approvals": payload.required_approvals,
            "delay_hours": payload.delay_hours,
            "statement_digest_sha256": statement.digest_sha256,
        },
    )
    db.commit()
    return statement


@_root_mutation
def create_recovery_policy(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRecoveryPolicyCreate,
    *,
    actor: str,
) -> OrganizationTrustRecoveryPolicy:
    domain = _locked_domain(db, domain_id)
    signed = payload.signed_policy
    accepted = db.scalar(select(OrganizationTrustRecoveryPolicy).where(
        OrganizationTrustRecoveryPolicy.trust_domain_id == domain.id,
        OrganizationTrustRecoveryPolicy.statement_digest_sha256 == signed.statement.digest_sha256,
    ).execution_options(populate_existing=True))
    if accepted is not None:
        if (accepted.signed_policy_snapshot != signed.model_dump(mode="json")
            or sorted(accepted.trustee_key_ids) != sorted(payload.trustee_trust_key_ids)
            or accepted.reason != payload.reason):
            raise ValueError("Recovery policy retry conflicts with recorded proof")
        db.commit()
        return accepted
    if not domain.enabled:
        raise ValueError(
            "Recovery policy must be authorized before the trust domain is disabled"
        )
    pending = db.scalar(
        select(OrganizationTrustRootReanchor.id).where(
            OrganizationTrustRootReanchor.trust_domain_id == domain.id,
            OrganizationTrustRootReanchor.status == "pending",
        )
    )
    if pending is not None:
        raise ValueError("A root re-anchor proposal is already pending")
    authority = _local_key(
        db,
        domain.authority_trust_key_id,
        purpose="trust_bundle",
        label="Organization root",
    )
    trustees = _recovery_trustees(
        db,
        payload.trustee_trust_key_ids,
        authority_fingerprint=authority.fingerprint_sha256,
    )
    statement = signed.statement
    encoded = json.dumps(
        signed.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > RECOVERY_DOCUMENT_MAX_BYTES:
        raise ValueError("Recovery policy document exceeds 256000 bytes")
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != statement.digest_sha256:
        raise ValueError("Recovery policy statement digest does not match")
    latest = db.scalar(
        select(OrganizationTrustRecoveryPolicy).where(
            OrganizationTrustRecoveryPolicy.trust_domain_id == domain.id,
        ).order_by(OrganizationTrustRecoveryPolicy.version.desc()).limit(1)
        .with_for_update().execution_options(populate_existing=True)
    )
    current = db.scalar(
        select(OrganizationTrustRecoveryPolicy).where(
            OrganizationTrustRecoveryPolicy.trust_domain_id == domain.id,
            OrganizationTrustRecoveryPolicy.active.is_(True),
        ).order_by(OrganizationTrustRecoveryPolicy.version.desc()).limit(1)
        .with_for_update().execution_options(populate_existing=True)
    )
    requirements = {authority.id: {"trust_bundle"}}
    requirements.update({item.id: {"trust_recovery"} for item in trustees})
    keys = lock_trust_authorities(db, requirements)
    authority = keys[authority.id]
    trustees = sorted((keys[item.id] for item in trustees), key=lambda item: item.fingerprint_sha256)
    if (authority.trust_source != "local" or any(item.trust_source != "local" for item in trustees)
        or any(item.fingerprint_sha256 == authority.fingerprint_sha256 for item in trustees)):
        raise ValueError("Recovery policy requires independent locally pinned authority")
    expected_version = latest.version + 1 if latest is not None else 1
    if (
        statement.organization_id != domain.organization_id
        or statement.trust_domain_id != domain.id
        or statement.policy_version != expected_version
    ):
        raise ValueError("Recovery policy identity or version does not match")
    if (
        statement.bundle_sequence != domain.latest_sequence
        or statement.bundle_digest_sha256
        != domain.latest_bundle_digest_sha256
    ):
        raise ValueError("Recovery policy trust-bundle head is stale")
    if statement.authority_key_fingerprint_sha256 != (
        authority.fingerprint_sha256
    ):
        raise ValueError("Recovery policy is not bound to the active root")
    fingerprints = [item.fingerprint_sha256 for item in trustees]
    if statement.trustee_key_fingerprints_sha256 != fingerprints:
        raise ValueError("Recovery policy trustee set does not match")
    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + RECOVERY_CLOCK_SKEW:
        raise ValueError("Recovery policy is issued in the future")
    if expires_at <= now:
        raise ValueError("Recovery policy has expired")
    if expires_at - issued_at > RECOVERY_POLICY_MAX_LIFETIME:
        raise ValueError("Recovery policy lifetime exceeds 24 hours")
    verification = verify_trusted_digest_signature(
        db,
        signed.authority_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=(
            SIGNED_ORGANIZATION_TRUST_RECOVERY_POLICY_FORMAT
        ),
        expected_purpose="trust_bundle",
    )
    if verification["trust_key_id"] != authority.id:
        raise ValueError("Recovery policy lacks the active-root signature")

    policy = OrganizationTrustRecoveryPolicy(
        id=new_id(),
        trust_domain_id=domain.id,
        version=statement.policy_version,
        active=True,
        authority_trust_key_id=authority.id,
        authority_key_fingerprint_sha256=authority.fingerprint_sha256,
        trustee_key_ids=[item.id for item in trustees],
        trustee_key_fingerprints_sha256=fingerprints,
        required_approvals=statement.required_approvals,
        delay_hours=statement.delay_hours,
        bundle_sequence=domain.latest_sequence,
        bundle_digest_sha256=domain.latest_bundle_digest_sha256,
        statement_digest_sha256=statement.digest_sha256,
        authority_signature_sha256=verification["signature_sha256"],
        signed_policy_snapshot=signed.model_dump(mode="json"),
        transparency_sequence=0,
        reason=payload.reason,
        created_by=actor,
    )
    if current is not None:
        current.active = False
        current.superseded_at = now
    try:
        transparency = append_capability_transparency_record(
            db,
            event_type="capability.trust_recovery_policy.authorized",
            entity_type="organization_trust_recovery_policy",
            entity_id=policy.id,
            subject_digest_sha256=statement.digest_sha256,
            details={
                "organization_id": domain.organization_id,
                "trust_domain_id": domain.id,
                "policy_version": policy.version,
                "trustee_count": len(trustees),
                "required_approvals": policy.required_approvals,
                "delay_hours": policy.delay_hours,
                "authority_key_fingerprint_sha256": (
                    authority.fingerprint_sha256
                ),
            },
        )
        policy.transparency_sequence = transparency.sequence
        db.add(policy)
        db.flush()
        record_audit_event(
            db,
            event_type="capability.trust_recovery_policy.authorized",
            actor_type="user",
            actor_id=actor,
            entity_type="organization_trust_recovery_policy",
            entity_id=policy.id,
            details={
                "policy_version": policy.version,
                "statement_digest_sha256": statement.digest_sha256,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        def check():
            checked_at = utcnow()
            for key_id, purposes in requirements.items():
                for purpose in purposes:
                    ensure_trust_key_usable(db, keys[key_id], expected_purpose=purpose)
            if (not domain.enabled or domain.authority_trust_key_id != authority.id
                or domain.authority_key_fingerprint_sha256 != authority.fingerprint_sha256
                or domain.latest_sequence != policy.bundle_sequence
                or domain.latest_bundle_digest_sha256 != policy.bundle_digest_sha256
                or (current is not None and (current.active or current.superseded_at is None))
                or not policy.active or _as_utc(statement.issued_at) > checked_at + RECOVERY_CLOCK_SKEW
                or _as_utc(statement.expires_at) <= checked_at):
                raise ValueError("Recovery policy authority changed before commit")
        commit_with_promotion_authority(db, check)
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Recovery policy version or signed statement already exists"
        ) from exc
    db.refresh(policy)
    return policy


def list_recovery_policies(
    db: Session,
    *,
    domain_id: str | None,
    limit: int,
) -> list[OrganizationTrustRecoveryPolicy]:
    query = select(OrganizationTrustRecoveryPolicy)
    if domain_id is not None:
        query = query.where(
            OrganizationTrustRecoveryPolicy.trust_domain_id == domain_id
        )
    return list(
        db.scalars(
            query.order_by(
                OrganizationTrustRecoveryPolicy.created_at.desc()
            ).limit(limit)
        ).all()
    )


def export_recovery_policy(
    db: Session,
    policy_id: str,
) -> dict[str, Any]:
    policy = db.get(OrganizationTrustRecoveryPolicy, policy_id)
    if policy is None:
        raise LookupError("Organization trust recovery policy not found")
    return policy.signed_policy_snapshot


def create_root_reanchor_statement(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRootReanchorStatementCreate,
    *,
    actor: str,
) -> OrganizationTrustRootReanchorStatement:
    domain = _get_domain(db, domain_id)
    if domain.enabled:
        raise ValueError(
            "Disable the organization trust domain before emergency re-anchor"
        )
    policy = _active_policy(db, domain.id)
    if policy is None:
        raise ValueError("No active root-recovery policy is authorized")
    if (
        policy.authority_trust_key_id != domain.authority_trust_key_id
        or policy.authority_key_fingerprint_sha256
        != domain.authority_key_fingerprint_sha256
    ):
        raise ValueError(
            "Recovery policy was not authorized by the current root"
        )
    next_key = _local_key(
        db,
        payload.new_authority_trust_key_id,
        purpose="trust_bundle",
        label="Next organization root",
    )
    if next_key.id == domain.authority_trust_key_id:
        raise ValueError("Emergency re-anchor requires a different root")
    if payload.validity_hours <= policy.delay_hours:
        raise ValueError(
            "Root re-anchor validity must exceed the recovery delay"
        )
    checkpoint = _root_checkpoint(db)
    offer = require_live_witnessed_checkpoint_offer(
        db,
        log_id=checkpoint.log_id,
        epoch=checkpoint.epoch,
        sequence=checkpoint.last_sequence,
        head_digest_sha256=checkpoint.head_digest_sha256,
    )
    if checkpoint.last_sequence < policy.transparency_sequence:
        raise ValueError("Recovery policy is not covered by the checkpoint")
    issued_at = utcnow()
    expires_at = issued_at + timedelta(hours=payload.validity_hours)
    if _as_utc(offer.expires_at) <= issued_at + timedelta(
        hours=policy.delay_hours
    ):
        raise ValueError(
            "Witness checkpoint expires before the recovery delay"
        )
    material = {
        "format_version": ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
        "organization_id": domain.organization_id,
        "trust_domain_id": domain.id,
        "recovery_policy_version": policy.version,
        "recovery_policy_digest_sha256": (
            policy.statement_digest_sha256
        ),
        "ceremony_id": str(uuid.uuid4()),
        "bundle_sequence": domain.latest_sequence,
        "bundle_digest_sha256": domain.latest_bundle_digest_sha256,
        "current_key_fingerprint_sha256": (
            domain.authority_key_fingerprint_sha256
        ),
        "next_key_fingerprint_sha256": next_key.fingerprint_sha256,
        "witness_log_id": checkpoint.log_id,
        "witness_epoch": checkpoint.epoch,
        "witness_sequence": checkpoint.last_sequence,
        "witness_head_digest_sha256": checkpoint.head_digest_sha256,
        "issued_at": _json_timestamp(issued_at),
        "expires_at": _json_timestamp(expires_at),
    }
    statement = OrganizationTrustRootReanchorStatement.model_validate(
        {**material, "digest_sha256": _canonical_hash(material)}
    )
    record_audit_event(
        db,
        event_type="capability.trust_root_reanchor_statement.generated",
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_domain",
        entity_id=domain.id,
        details={
            "ceremony_id": statement.ceremony_id,
            "policy_version": policy.version,
            "next_key_fingerprint_sha256": next_key.fingerprint_sha256,
            "witness_checkpoint_offer_id": offer.id,
            "witness_sequence": checkpoint.last_sequence,
            "statement_digest_sha256": statement.digest_sha256,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    return statement


def _bound_offer(
    db: Session,
    statement: OrganizationTrustRootReanchorStatement,
    *,
    live: bool,
    expected_offer_id: str | None,
) -> CapabilityTransparencyCheckpointOffer:
    if live:
        return require_live_witnessed_checkpoint_offer(
            db,
            log_id=statement.witness_log_id,
            epoch=statement.witness_epoch,
            sequence=statement.witness_sequence,
            head_digest_sha256=statement.witness_head_digest_sha256,
        )
    offer = (
        db.get(CapabilityTransparencyCheckpointOffer, expected_offer_id)
        if expected_offer_id is not None
        else None
    )
    if offer is None or (
        offer.log_id != statement.witness_log_id
        or offer.epoch != statement.witness_epoch
        or offer.sequence != statement.witness_sequence
        or offer.head_digest_sha256
        != statement.witness_head_digest_sha256
    ):
        raise ValueError("Stored recovery witness checkpoint does not match")
    return offer


def _evaluate_root_reanchor(
    db: Session,
    domain: OrganizationTrustDomain,
    payload: OrganizationTrustRootReanchorPreviewCreate,
    *,
    require_current_checkpoint: bool,
    expected_offer_id: str | None = None,
) -> tuple[
    OrganizationTrustRootReanchorPreviewRead,
    OrganizationTrustRecoveryPolicy,
    ArtifactTrustKey,
    CapabilityTransparencyCheckpointOffer,
    dict[str, str],
    list[dict[str, str]],
]:
    if domain.enabled:
        raise ValueError(
            "Disable the organization trust domain before emergency re-anchor"
        )
    policy = _active_policy(db, domain.id)
    if policy is None:
        raise ValueError("No active root-recovery policy is authorized")
    if (
        policy.authority_trust_key_id != domain.authority_trust_key_id
        or policy.authority_key_fingerprint_sha256
        != domain.authority_key_fingerprint_sha256
    ):
        raise ValueError(
            "Recovery policy was not authorized by the current root"
        )
    next_key = _local_key(
        db,
        payload.new_authority_trust_key_id,
        purpose="trust_bundle",
        label="Next organization root",
    )
    signed = payload.signed_reanchor
    statement = signed.statement
    encoded = json.dumps(
        signed.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > RECOVERY_DOCUMENT_MAX_BYTES:
        raise ValueError("Root re-anchor document exceeds 256000 bytes")
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != statement.digest_sha256:
        raise ValueError("Root re-anchor statement digest does not match")
    if (
        statement.organization_id != domain.organization_id
        or statement.trust_domain_id != domain.id
    ):
        raise ValueError("Root re-anchor identity does not match")
    if (
        statement.recovery_policy_version != policy.version
        or statement.recovery_policy_digest_sha256
        != policy.statement_digest_sha256
    ):
        raise ValueError("Root re-anchor recovery policy is stale")
    if (
        statement.bundle_sequence != domain.latest_sequence
        or statement.bundle_digest_sha256
        != domain.latest_bundle_digest_sha256
    ):
        raise ValueError("Root re-anchor trust-bundle head is stale")
    if statement.current_key_fingerprint_sha256 != (
        domain.authority_key_fingerprint_sha256
    ):
        raise ValueError("Root re-anchor current root is not pinned")
    if statement.next_key_fingerprint_sha256 != next_key.fingerprint_sha256:
        raise ValueError("Root re-anchor next root does not match")
    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + RECOVERY_CLOCK_SKEW:
        raise ValueError("Root re-anchor is issued in the future")
    if expires_at <= now:
        raise ValueError("Root re-anchor has expired")
    if expires_at - issued_at > ROOT_REANCHOR_MAX_LIFETIME:
        raise ValueError("Root re-anchor lifetime exceeds 168 hours")
    if expires_at <= now + timedelta(hours=policy.delay_hours):
        raise ValueError("Root re-anchor expires before the recovery delay")
    if require_current_checkpoint:
        checkpoint = _root_checkpoint(db)
        if (
            statement.witness_log_id != checkpoint.log_id
            or statement.witness_epoch != checkpoint.epoch
            or statement.witness_sequence != checkpoint.last_sequence
            or statement.witness_head_digest_sha256
            != checkpoint.head_digest_sha256
        ):
            raise ValueError("Root re-anchor witness checkpoint is stale")
    offer = _bound_offer(
        db,
        statement,
        live=require_current_checkpoint,
        expected_offer_id=expected_offer_id,
    )
    if statement.witness_sequence < policy.transparency_sequence:
        raise ValueError("Recovery policy is not covered by the checkpoint")
    next_verification = verify_trusted_digest_signature(
        db,
        signed.next_root_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT,
        expected_purpose="trust_bundle",
    )
    if next_verification["trust_key_id"] != next_key.id:
        raise ValueError("Root re-anchor lacks the next-root signature")

    allowed_ids = set(policy.trustee_key_ids)
    seen_ids: set[str] = set()
    evidence: list[dict[str, str]] = []
    for signature in signed.trustee_signatures:
        verification = verify_trusted_digest_signature(
            db,
            signature,
            expected_digest_sha256=statement.digest_sha256,
            signed_format_version=(
                SIGNED_ORGANIZATION_TRUST_ROOT_REANCHOR_FORMAT
            ),
            expected_purpose="trust_recovery",
        )
        key_id = verification["trust_key_id"]
        if key_id not in allowed_ids:
            raise ValueError(
                "Root re-anchor signature is not from an authorized trustee"
            )
        if key_id in seen_ids:
            raise ValueError("Root re-anchor contains a duplicate trustee")
        seen_ids.add(key_id)
        evidence.append(
            {
                "trust_key_id": key_id,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "signature_sha256": verification["signature_sha256"],
            }
        )
    evidence.sort(key=lambda item: item["key_fingerprint_sha256"])
    if len(evidence) < policy.required_approvals:
        raise ValueError("Root re-anchor does not satisfy trustee quorum")

    blockers: list[str] = []
    existing = db.scalar(
        select(OrganizationTrustRootReanchor).where(
            OrganizationTrustRootReanchor.statement_digest_sha256
            == statement.digest_sha256
        )
    )
    if existing is not None:
        blockers.append("reanchor_statement_already_proposed")
    other_pending = db.scalar(
        select(OrganizationTrustRootReanchor.id).where(
            OrganizationTrustRootReanchor.trust_domain_id == domain.id,
            OrganizationTrustRootReanchor.status == "pending",
        )
    )
    if other_pending is not None:
        blockers.append("another_reanchor_is_pending")
    preview = OrganizationTrustRootReanchorPreviewRead(
        trust_domain_id=domain.id,
        recovery_policy_id=policy.id,
        recovery_policy_version=policy.version,
        ceremony_id=statement.ceremony_id,
        from_key_fingerprint_sha256=(
            statement.current_key_fingerprint_sha256
        ),
        to_key_fingerprint_sha256=statement.next_key_fingerprint_sha256,
        witness_checkpoint_offer_id=offer.id,
        witness_sequence=statement.witness_sequence,
        trustee_approval_count=len(evidence),
        required_approvals=policy.required_approvals,
        execute_delay_hours=policy.delay_hours,
        eligible=not blockers,
        blockers=blockers,
    )
    return (
        preview,
        policy,
        next_key,
        offer,
        next_verification,
        evidence,
    )


def preview_root_reanchor(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRootReanchorPreviewCreate,
) -> OrganizationTrustRootReanchorPreviewRead:
    domain = _get_domain(db, domain_id)
    preview, _, _, _, _, _ = _evaluate_root_reanchor(
        db,
        domain,
        payload,
        require_current_checkpoint=True,
    )
    return preview


@_root_mutation
def propose_root_reanchor(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRootReanchorProposalCreate,
    *,
    actor: str,
) -> OrganizationTrustRootReanchor:
    domain = _locked_domain(db, domain_id)
    preview_payload = OrganizationTrustRootReanchorPreviewCreate(
        new_authority_trust_key_id=payload.new_authority_trust_key_id,
        signed_reanchor=payload.signed_reanchor,
    )
    (
        preview,
        policy,
        next_key,
        offer,
        next_verification,
        evidence,
    ) = _evaluate_root_reanchor(
        db,
        domain,
        preview_payload,
        require_current_checkpoint=True,
    )
    if not preview.eligible:
        raise ValueError(
            "Root re-anchor proposal is not eligible: "
            + ", ".join(preview.blockers)
        )
    statement = payload.signed_reanchor.statement
    authority = _retain_reanchor_authority(db, policy, next_key.id, offer, payload.signed_reanchor)
    _check_retained_reanchor(db, authority, delay_hours=policy.delay_hours)
    head = _root_checkpoint(db, retain=True)
    if (head.log_id, head.epoch, head.last_sequence, head.head_digest_sha256) != (
        statement.witness_log_id, statement.witness_epoch, statement.witness_sequence,
        statement.witness_head_digest_sha256):
        raise ValueError("Root re-anchor incident checkpoint changed before proposal")
    checked, current_policy, current_key, current_offer, current_next, current_evidence = _evaluate_root_reanchor(
        db, domain, preview_payload, require_current_checkpoint=True)
    if (not checked.eligible or current_policy.id != policy.id or current_key.id != next_key.id
        or current_offer.id != offer.id or current_next != next_verification or current_evidence != evidence):
        raise ValueError("Root re-anchor authority changed before proposal")
    proposed_at = utcnow()
    request = OrganizationTrustRootReanchor(
        id=new_id(),
        trust_domain_id=domain.id,
        recovery_policy_id=policy.id,
        from_trust_key_id=domain.authority_trust_key_id,
        to_trust_key_id=next_key.id,
        ceremony_id=statement.ceremony_id,
        from_key_fingerprint_sha256=(
            domain.authority_key_fingerprint_sha256
        ),
        to_key_fingerprint_sha256=next_key.fingerprint_sha256,
        bundle_sequence=domain.latest_sequence,
        bundle_digest_sha256=domain.latest_bundle_digest_sha256,
        witness_checkpoint_offer_id=offer.id,
        witness_log_id=statement.witness_log_id,
        witness_epoch=statement.witness_epoch,
        witness_sequence=statement.witness_sequence,
        witness_head_digest_sha256=statement.witness_head_digest_sha256,
        statement_digest_sha256=statement.digest_sha256,
        next_signature_sha256=next_verification["signature_sha256"],
        trustee_approval_count=len(evidence),
        trustee_signature_evidence=evidence,
        signed_reanchor_snapshot=payload.signed_reanchor.model_dump(
            mode="json"
        ),
        issued_at=statement.issued_at,
        expires_at=statement.expires_at,
        status="pending",
        execute_after=proposed_at + timedelta(hours=policy.delay_hours),
        reason=payload.reason,
        proposed_by=actor,
        proposed_at=proposed_at,
    )
    try:
        transparency = append_capability_transparency_record(
            db,
            event_type="capability.trust_root_reanchor.proposed",
            entity_type="organization_trust_root_reanchor",
            entity_id=request.id,
            subject_digest_sha256=statement.digest_sha256,
            details={
                "organization_id": domain.organization_id,
                "trust_domain_id": domain.id,
                "ceremony_id": request.ceremony_id,
                "policy_version": policy.version,
                "trustee_approval_count": len(evidence),
                "execute_after": _json_timestamp(request.execute_after),
                "from_key_fingerprint_sha256": (
                    request.from_key_fingerprint_sha256
                ),
                "to_key_fingerprint_sha256": (
                    request.to_key_fingerprint_sha256
                ),
            },
        )
        request.proposal_transparency_sequence = transparency.sequence
        db.add(request)
        db.flush()
        record_audit_event(
            db,
            event_type="capability.trust_root_reanchor.proposed",
            actor_type="user",
            actor_id=actor,
            entity_type="organization_trust_root_reanchor",
            entity_id=request.id,
            details={
                "ceremony_id": request.ceremony_id,
                "statement_digest_sha256": statement.digest_sha256,
                "witness_checkpoint_offer_id": offer.id,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        def check():
            _check_retained_reanchor(db, authority, delay_hours=policy.delay_hours)
            now = utcnow()
            if (domain.enabled or domain.authority_trust_key_id != request.from_trust_key_id
                or domain.authority_key_fingerprint_sha256 != request.from_key_fingerprint_sha256
                or domain.latest_sequence != request.bundle_sequence
                or domain.latest_bundle_digest_sha256 != request.bundle_digest_sha256
                or not policy.active or _as_utc(request.expires_at) <= now + timedelta(hours=policy.delay_hours)
                or head.last_sequence < request.proposal_transparency_sequence):
                raise ValueError("Root re-anchor proposal authority changed before commit")
        commit_with_promotion_authority(db, check)
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Root re-anchor ceremony or signed statement already exists"
        ) from exc
    db.refresh(request)
    return request


@_root_mutation
def execute_root_reanchor(
    db: Session,
    request_id: str,
    payload: OrganizationTrustRootReanchorAction,
    *,
    actor: str,
) -> OrganizationTrustRootReanchor:
    tenant_id, region_id = selected_trust_namespace(db)
    domain_id = db.scalar(select(OrganizationTrustRootReanchor.trust_domain_id).where(
        OrganizationTrustRootReanchor.id == request_id,
        OrganizationTrustRootReanchor.tenant_id == tenant_id,
        OrganizationTrustRootReanchor.region_id == region_id))
    if domain_id is None:
        raise LookupError("Organization trust root re-anchor not found")
    domain = _locked_domain(db, domain_id)
    request = db.scalar(select(OrganizationTrustRootReanchor).where(
        OrganizationTrustRootReanchor.id == request_id).with_for_update()
        .execution_options(populate_existing=True))
    if request is None:
        raise LookupError("Organization trust root re-anchor not found")
    if request.status == "executed":
        return request
    if request.status != "pending":
        raise ValueError("Root re-anchor is not pending")
    if actor == request.proposed_by:
        raise ValueError("Root re-anchor requires a different executor")
    now = utcnow()
    if now < _as_utc(request.execute_after):
        raise ValueError("Root re-anchor recovery delay has not elapsed")
    if now >= _as_utc(request.expires_at):
        raise ValueError("Root re-anchor has expired")
    if request.trust_domain_id != domain.id:
        raise ValueError("Root re-anchor domain identity changed")
    if domain.enabled:
        raise ValueError("Root re-anchor trust domain must remain disabled")
    if (
        domain.authority_trust_key_id != request.from_trust_key_id
        or domain.authority_key_fingerprint_sha256
        != request.from_key_fingerprint_sha256
        or domain.latest_sequence != request.bundle_sequence
        or domain.latest_bundle_digest_sha256
        != request.bundle_digest_sha256
    ):
        raise ValueError("Root re-anchor trust-domain state has drifted")
    signed = SignedOrganizationTrustRootReanchor.model_validate(
        request.signed_reanchor_snapshot
    )
    preview_payload = OrganizationTrustRootReanchorPreviewCreate(
        new_authority_trust_key_id=request.to_trust_key_id,
        signed_reanchor=signed,
    )
    (
        _,
        policy,
        next_key,
        _,
        next_verification,
        evidence,
    ) = _evaluate_root_reanchor(
        db,
        domain,
        preview_payload,
        require_current_checkpoint=False,
        expected_offer_id=request.witness_checkpoint_offer_id,
    )
    if (
        policy.id != request.recovery_policy_id
        or next_verification["signature_sha256"]
        != request.next_signature_sha256
        or evidence != request.trustee_signature_evidence
    ):
        raise ValueError("Root re-anchor signed evidence has drifted")
    checkpoint = _root_checkpoint(db)
    if (
        request.proposal_transparency_sequence is None
        or checkpoint.last_sequence < request.proposal_transparency_sequence
    ):
        raise ValueError("Root re-anchor proposal is not in the current log")
    execution_offer = require_live_witnessed_checkpoint_offer(
        db,
        log_id=checkpoint.log_id,
        epoch=checkpoint.epoch,
        sequence=checkpoint.last_sequence,
        head_digest_sha256=checkpoint.head_digest_sha256,
    )
    authority = _retain_reanchor_authority(db, policy, next_key.id, execution_offer, signed)
    _check_retained_reanchor(db, authority)
    head = _root_checkpoint(db, retain=True)
    if (head.log_id, head.epoch, head.last_sequence, head.head_digest_sha256) != (
        execution_offer.log_id, execution_offer.epoch, execution_offer.sequence,
        execution_offer.head_digest_sha256):
        raise ValueError("Root re-anchor execution checkpoint changed")
    _, latest_policy, latest_next, _, latest_verification, latest_evidence = _evaluate_root_reanchor(
        db, domain, preview_payload, require_current_checkpoint=False,
        expected_offer_id=request.witness_checkpoint_offer_id)
    if (latest_policy.id != policy.id or latest_next.id != next_key.id
        or latest_verification != next_verification or latest_evidence != evidence):
        raise ValueError("Root re-anchor signer authority changed before execution")

    transparency = append_capability_transparency_record(
        db,
        event_type="capability.trust_root.reanchored",
        entity_type="organization_trust_root_reanchor",
        entity_id=request.id,
        subject_digest_sha256=request.statement_digest_sha256,
        details={
            "organization_id": domain.organization_id,
            "trust_domain_id": domain.id,
            "ceremony_id": request.ceremony_id,
            "policy_version": policy.version,
            "proposal_transparency_sequence": (
                request.proposal_transparency_sequence
            ),
            "execution_checkpoint_offer_id": execution_offer.id,
            "from_key_fingerprint_sha256": (
                request.from_key_fingerprint_sha256
            ),
            "to_key_fingerprint_sha256": request.to_key_fingerprint_sha256,
        },
    )
    domain.authority_trust_key_id = next_key.id
    domain.authority_key_fingerprint_sha256 = next_key.fingerprint_sha256
    domain.updated_at = now
    policy.active = False
    policy.superseded_at = now
    request.status = "executed"
    request.execution_checkpoint_offer_id = execution_offer.id
    request.execution_reason = payload.reason
    request.executed_by = actor
    request.executed_at = now
    request.execution_transparency_sequence = transparency.sequence
    record_audit_event(
        db,
        event_type="capability.trust_root.reanchored",
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_root_reanchor",
        entity_id=request.id,
        details={
            "ceremony_id": request.ceremony_id,
            "statement_digest_sha256": request.statement_digest_sha256,
            "execution_checkpoint_offer_id": execution_offer.id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    def check():
        _check_retained_reanchor(db, authority)
        now = utcnow()
        if (domain.enabled or domain.authority_trust_key_id != next_key.id
            or domain.authority_key_fingerprint_sha256 != next_key.fingerprint_sha256
            or domain.latest_sequence != request.bundle_sequence
            or domain.latest_bundle_digest_sha256 != request.bundle_digest_sha256
            or policy.active or request.status != "executed"
            or now < _as_utc(request.execute_after) or now >= _as_utc(request.expires_at)
            or head.last_sequence < request.execution_transparency_sequence):
            raise ValueError("Root re-anchor execution authority changed before commit")
    commit_with_promotion_authority(db, check)
    db.refresh(request)
    return request


@_root_mutation
def cancel_root_reanchor(
    db: Session,
    request_id: str,
    payload: OrganizationTrustRootReanchorAction,
    *,
    actor: str,
) -> OrganizationTrustRootReanchor:
    tenant_id, region_id = selected_trust_namespace(db)
    domain_id = db.scalar(select(OrganizationTrustRootReanchor.trust_domain_id).where(
        OrganizationTrustRootReanchor.id == request_id,
        OrganizationTrustRootReanchor.tenant_id == tenant_id,
        OrganizationTrustRootReanchor.region_id == region_id))
    if domain_id is None:
        raise LookupError("Organization trust root re-anchor not found")
    domain = _locked_domain(db, domain_id)
    request = db.scalar(select(OrganizationTrustRootReanchor).where(
        OrganizationTrustRootReanchor.id == request_id).with_for_update()
        .execution_options(populate_existing=True))
    if request is None:
        raise LookupError("Organization trust root re-anchor not found")
    if request.trust_domain_id != domain.id:
        raise ValueError("Root re-anchor domain identity changed")
    if request.status == "cancelled":
        return request
    if request.status != "pending":
        raise ValueError("Executed root re-anchor cannot be cancelled")
    request.status = "cancelled"
    request.cancelled_by = actor
    request.cancelled_at = utcnow()
    append_capability_transparency_record(
        db,
        event_type="capability.trust_root_reanchor.cancelled",
        entity_type="organization_trust_root_reanchor",
        entity_id=request.id,
        subject_digest_sha256=request.statement_digest_sha256,
        details={
            "trust_domain_id": request.trust_domain_id,
            "ceremony_id": request.ceremony_id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    record_audit_event(
        db,
        event_type="capability.trust_root_reanchor.cancelled",
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_root_reanchor",
        entity_id=request.id,
        details={
            "ceremony_id": request.ceremony_id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(request)
    return request


def list_root_reanchors(
    db: Session,
    *,
    domain_id: str | None,
    limit: int,
) -> list[OrganizationTrustRootReanchor]:
    query = select(OrganizationTrustRootReanchor)
    if domain_id is not None:
        query = query.where(
            OrganizationTrustRootReanchor.trust_domain_id == domain_id
        )
    return list(
        db.scalars(
            query.order_by(
                OrganizationTrustRootReanchor.proposed_at.desc()
            ).limit(limit)
        ).all()
    )


def export_root_reanchor(
    db: Session,
    request_id: str,
) -> dict[str, Any]:
    request = db.get(OrganizationTrustRootReanchor, request_id)
    if request is None:
        raise LookupError("Organization trust root re-anchor not found")
    return request.signed_reanchor_snapshot
