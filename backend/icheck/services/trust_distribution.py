from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, IntegrityError, InvalidRequestError
from sqlalchemy.orm import Session

from ..database import require_locking_transaction, set_session_namespace
from ..models import (
    ArtifactTrustKey,
    CapabilityTransparencyCheckpointOffer,
    CapabilityTransparencyState,
    CapabilityTransparencyWitness,
    CapabilityTransparencyWitnessAttestation,
    CapabilityTransparencyWitnessPolicy,
    OrganizationTrustBundleImport,
    OrganizationTrustDomain,
    OrganizationTrustDomainCreationReceipt,
    OrganizationTrustRecoveryPolicy,
    OrganizationTrustRootReanchor,
    OrganizationTrustRootRotation,
    utcnow,
)
from ..trust_distribution_schemas import (
    OrganizationTrustBundleImportCreate,
    OrganizationTrustBundlePreviewCreate,
    OrganizationTrustBundlePreviewRead,
    OrganizationTrustDomainCreate,
    OrganizationTrustDomainStateCreate,
    OrganizationTrustKeyPlan,
    OrganizationTrustRootRotationCreate,
    SignedOrganizationTrustBundle,
    SIGNED_ORGANIZATION_TRUST_BUNDLE_FORMAT,
    SIGNED_ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT,
)
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .artifact_lifecycle import prepare_artifact_mutation
from .trust_namespace import assert_selected_trust_namespace, selected_trust_namespace
from .trust_authority import (
    assert_rotation_replay, lock_publisher_resource, lock_trust_authorities, lock_trust_keys,
)
from .capability_transparency import (
    append_capability_transparency_record,
    transparency_singleton_id,
)
from .transparency_witnessing import (
    _valid_offer_attestations,
    require_live_witnessed_checkpoint_offer,
)
from .promotion_authority import commit_with_promotion_authority


TRUST_BUNDLE_MAX_BYTES = 1_000_000
TRUST_BUNDLE_CLOCK_SKEW = timedelta(minutes=5)
TRUST_ROOT_ROTATION_MAX_LIFETIME = timedelta(hours=24)


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


def _canonical_public_key(public_key_pem: str) -> tuple[str, str]:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("ascii")
        )
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise ValueError("Trust-bundle key is not valid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Trust-bundle keys must use Ed25519")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    canonical_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return canonical_pem, hashlib.sha256(raw).hexdigest()


def _get_domain(db: Session, domain_id: str) -> OrganizationTrustDomain:
    domain = db.get(OrganizationTrustDomain, domain_id)
    if domain is None:
        raise LookupError("Organization trust domain not found")
    assert_selected_trust_namespace(db, domain)
    return domain


def _lock_domain(db: Session, domain_id: str) -> OrganizationTrustDomain:
    tenant_id, region_id = selected_trust_namespace(db)
    domain = db.scalar(
        select(OrganizationTrustDomain).where(
            OrganizationTrustDomain.id == domain_id,
            OrganizationTrustDomain.tenant_id == tenant_id,
            OrganizationTrustDomain.region_id == region_id,
        ).with_for_update().execution_options(populate_existing=True)
    )
    if domain is None:
        raise LookupError("Organization trust domain not found")
    return domain


def _trust_domain_mutation(operation):
    @wraps(operation)
    def guarded(db, *args, **kwargs):
        try:
            prepare_artifact_mutation(db, purpose="Organization trust-domain mutations")
            return operation(db, *args, **kwargs)
        except Exception:
            try:
                db.rollback()
            except InvalidRequestError:
                db.close()
            raise
    return guarded


def _retain_root_restoration(db: Session, domain: OrganizationTrustDomain,
                             reanchor: OrganizationTrustRootReanchor):
    """Retain the exact witnessed post-execution head and its live quorum."""
    singleton = transparency_singleton_id(db)
    policy = db.scalar(select(CapabilityTransparencyWitnessPolicy).where(
        CapabilityTransparencyWitnessPolicy.id == singleton).with_for_update(read=True)
        .execution_options(populate_existing=True))
    if policy is None or policy.required_quorum < 2:
        raise ValueError("Root restoration requires two independent witnesses")
    state = db.scalar(select(CapabilityTransparencyState).where(
        CapabilityTransparencyState.id == singleton).execution_options(populate_existing=True))
    if (state is None or state.log_id is None or reanchor.execution_transparency_sequence is None
        or state.last_sequence < reanchor.execution_transparency_sequence):
        raise ValueError("Root re-anchor is not present in the transparency log")
    witnessed_head = (state.log_id, state.epoch, state.last_sequence, state.head_digest_sha256)
    selected = require_live_witnessed_checkpoint_offer(db,
        log_id=state.log_id, epoch=state.epoch, sequence=state.last_sequence,
        head_digest_sha256=state.head_digest_sha256)
    offer = db.scalar(select(CapabilityTransparencyCheckpointOffer).where(
        CapabilityTransparencyCheckpointOffer.id == selected.id).with_for_update(read=True)
        .execution_options(populate_existing=True))
    if offer is None:
        raise ValueError("Root restoration witness checkpoint is unavailable")
    valid = sorted(_valid_offer_attestations(db, offer), key=lambda row: (row.witness_id, row.id))
    selected_rows = valid[:policy.required_quorum]
    if len(selected_rows) < policy.required_quorum:
        raise ValueError("Root restoration witness quorum is no longer live")
    attestations = {}
    for identity in sorted(row.id for row in selected_rows):
        row = db.scalar(select(CapabilityTransparencyWitnessAttestation).where(
            CapabilityTransparencyWitnessAttestation.id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if row is None:
            raise ValueError("Root restoration witness attestation is unavailable")
        attestations[identity] = row
    witnesses = {}
    for identity in sorted({row.witness_id for row in selected_rows}):
        row = db.scalar(select(CapabilityTransparencyWitness).where(
            CapabilityTransparencyWitness.id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
        if row is None:
            raise ValueError("Root restoration witness pin is unavailable")
        witnesses[identity] = row
    requirements = {domain.authority_trust_key_id: {"trust_bundle"}}
    for witness in witnesses.values():
        requirements.setdefault(witness.trust_key_id, set()).add("transparency_witness")
    keys = lock_trust_authorities(db, requirements)
    state = db.scalar(select(CapabilityTransparencyState).where(
        CapabilityTransparencyState.id == singleton).with_for_update()
        .execution_options(populate_existing=True))
    if state is None or (state.log_id, state.epoch, state.last_sequence,
                         state.head_digest_sha256) != witnessed_head:
        raise ValueError("Root restoration witnessed head changed before enablement")
    retained = policy, offer, attestations, witnesses, keys, requirements
    _check_root_restoration(db, retained)
    return keys[domain.authority_trust_key_id], state, retained


def _check_root_restoration(db: Session, retained) -> None:
    policy, offer, attestations, witnesses, keys, requirements = retained
    if policy.required_quorum < 2 or _as_utc(offer.expires_at) <= utcnow():
        raise ValueError("Root restoration witness checkpoint has expired")
    for key_id, purposes in requirements.items():
        for purpose in purposes:
            ensure_trust_key_usable(db, keys[key_id], expected_purpose=purpose)
    if any(not witness.enabled or witness.key_fingerprint_sha256 != keys[witness.trust_key_id].fingerprint_sha256
           for witness in witnesses.values()):
        raise ValueError("Root restoration witness pin changed")
    live = {row.id for row in _valid_offer_attestations(db, offer)}
    if len(live.intersection(attestations)) < policy.required_quorum:
        raise ValueError("Root restoration witness quorum is no longer live")


@_trust_domain_mutation
def create_organization_trust_domain(
    db: Session,
    payload: OrganizationTrustDomainCreate,
    *,
    actor: str,
) -> OrganizationTrustDomain:
    receipt = None
    request_digest = None
    key_hash = None
    if payload.idempotency_key is not None:
        tenant_id, region_id = selected_trust_namespace(db)
        key_hash = hashlib.sha256(payload.idempotency_key.encode("utf-8")).hexdigest()
        request_digest = _canonical_hash({
            "name": payload.name,
            "organization_id": payload.organization_id,
            "authority_trust_key_id": payload.authority_trust_key_id,
            "allowed_purposes": sorted(payload.allowed_purposes),
            "max_bundle_lifetime_days": payload.max_bundle_lifetime_days,
            "max_key_lifetime_days": payload.max_key_lifetime_days,
            "actor": actor,
        })
        lock_publisher_resource(db, "trust-domain-creation", key_hash)
        accepted = db.scalar(select(OrganizationTrustDomainCreationReceipt).where(
            OrganizationTrustDomainCreationReceipt.tenant_id == tenant_id,
            OrganizationTrustDomainCreationReceipt.region_id == region_id,
            OrganizationTrustDomainCreationReceipt.idempotency_key_sha256 == key_hash,
        ).with_for_update(read=True).execution_options(populate_existing=True))
        if accepted is not None:
            if accepted.request_digest_sha256 != request_digest or accepted.created_by != actor:
                raise ValueError("Organization trust-domain idempotency key already exists for another request")
            domain = db.scalar(select(OrganizationTrustDomain).where(
                OrganizationTrustDomain.id == accepted.trust_domain_id,
                OrganizationTrustDomain.tenant_id == tenant_id,
                OrganizationTrustDomain.region_id == region_id,
            ).with_for_update(read=True).execution_options(populate_existing=True))
            if domain is None:
                raise ValueError("Accepted organization trust-domain creation is unavailable")
            db.commit()
            db.refresh(domain)
            return domain
    authority = lock_trust_keys(
        db, [payload.authority_trust_key_id], expected_purpose="trust_bundle"
    )[payload.authority_trust_key_id]
    if authority.trust_source != "local":
        raise ValueError(
            "Organization trust authority must be an out-of-band local key"
        )
    ensure_trust_key_usable(
        db,
        authority,
        expected_purpose="trust_bundle",
    )
    domain = OrganizationTrustDomain(
        tenant_id=authority.tenant_id,
        region_id=authority.region_id,
        name=payload.name,
        organization_id=payload.organization_id,
        authority_trust_key_id=authority.id,
        authority_key_fingerprint_sha256=authority.fingerprint_sha256,
        enabled=True,
        allowed_purposes=sorted(payload.allowed_purposes),
        max_bundle_lifetime_days=payload.max_bundle_lifetime_days,
        max_key_lifetime_days=payload.max_key_lifetime_days,
        latest_sequence=0,
        created_by=actor,
    )
    db.add(domain)
    try:
        db.flush()
        if key_hash is not None:
            receipt = OrganizationTrustDomainCreationReceipt(
                tenant_id=domain.tenant_id,
                region_id=domain.region_id,
                trust_domain_id=domain.id,
                idempotency_key_sha256=key_hash,
                request_digest_sha256=request_digest,
                created_by=actor,
            )
            db.add(receipt)
            db.flush()
        subject_digest = _canonical_hash(
            {
                "organization_id": domain.organization_id,
                "authority_key_fingerprint_sha256": (
                    domain.authority_key_fingerprint_sha256
                ),
                "allowed_purposes": domain.allowed_purposes,
                "max_bundle_lifetime_days": domain.max_bundle_lifetime_days,
                "max_key_lifetime_days": domain.max_key_lifetime_days,
            }
        )
        append_capability_transparency_record(
            db,
            event_type="capability.trust_domain.created",
            entity_type="organization_trust_domain",
            entity_id=domain.id,
            subject_digest_sha256=subject_digest,
            details={
                "organization_id": domain.organization_id,
                "authority_key_fingerprint_sha256": (
                    domain.authority_key_fingerprint_sha256
                ),
            },
        )
        record_audit_event(
            db,
            event_type="capability.trust_domain.created",
            actor_type="user",
            actor_id=actor,
            entity_type="organization_trust_domain",
            entity_id=domain.id,
            details={
                "organization_id": domain.organization_id,
                "authority_key_fingerprint_sha256": (
                    domain.authority_key_fingerprint_sha256
                ),
                "allowed_purposes": domain.allowed_purposes,
            },
        )
        def check():
            if domain.authority_trust_key_id != authority.id or (
                domain.authority_key_fingerprint_sha256 != authority.fingerprint_sha256
            ):
                raise ValueError("Organization trust authority changed before commit")
            ensure_trust_key_usable(db, authority, expected_purpose="trust_bundle")
            if receipt is not None and (
                receipt.trust_domain_id != domain.id
                or receipt.idempotency_key_sha256 != key_hash
                or receipt.request_digest_sha256 != request_digest
            ):
                raise ValueError("Organization trust-domain creation receipt changed before commit")

        commit_with_promotion_authority(db, check)
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Organization trust-domain name or identity already exists"
        ) from exc
    db.refresh(domain)
    return domain


def list_organization_trust_domains(
    db: Session,
    *,
    limit: int,
) -> list[OrganizationTrustDomain]:
    tenant_id, region_id = selected_trust_namespace(db)
    return list(
        db.scalars(
            select(OrganizationTrustDomain)
            .where(
                OrganizationTrustDomain.tenant_id == tenant_id,
                OrganizationTrustDomain.region_id == region_id,
            )
            .order_by(OrganizationTrustDomain.name)
            .limit(limit)
        ).all()
    )


@_trust_domain_mutation
def set_organization_trust_domain_state(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustDomainStateCreate,
    *,
    actor: str,
) -> OrganizationTrustDomain:
    domain = _lock_domain(db, domain_id)
    if domain.enabled == payload.enabled:
        db.commit()
        db.refresh(domain)
        return domain
    authority = restoration = state = reanchor = None
    if payload.enabled:
        reanchor = db.scalar(
            select(OrganizationTrustRootReanchor)
            .where(
                OrganizationTrustRootReanchor.trust_domain_id == domain.id,
                OrganizationTrustRootReanchor.status == "executed",
                OrganizationTrustRootReanchor.to_trust_key_id == domain.authority_trust_key_id,
            )
            .order_by(
                OrganizationTrustRootReanchor.executed_at.desc()
            )
            .limit(1)
            .with_for_update(read=True).execution_options(populate_existing=True)
        )
        if reanchor is not None:
            authority, state, restoration = _retain_root_restoration(db, domain, reanchor)
        else:
            authority = lock_trust_keys(db, [domain.authority_trust_key_id],
                expected_purpose="trust_bundle")[domain.authority_trust_key_id]
    pinned_key_id = domain.authority_trust_key_id
    domain.enabled = payload.enabled
    domain.updated_at = utcnow()
    state_digest = _canonical_hash({
        "domain_id": domain.id,
        "enabled": domain.enabled,
        "latest_sequence": domain.latest_sequence,
        "latest_bundle_digest_sha256": domain.latest_bundle_digest_sha256,
    })
    transparency = append_capability_transparency_record(
        db,
        event_type=("capability.trust_domain.enabled" if domain.enabled
                    else "capability.trust_domain.disabled"),
        entity_type="organization_trust_domain",
        entity_id=domain.id,
        subject_digest_sha256=state_digest,
        details={
            "organization_id": domain.organization_id,
            "reason_sha256": hashlib.sha256(payload.reason.encode("utf-8")).hexdigest(),
        },
    )
    record_audit_event(
        db,
        event_type=("capability.trust_domain.enabled" if domain.enabled
                    else "capability.trust_domain.disabled"),
        actor_type="user",
        actor_id=actor,
        entity_type="organization_trust_domain",
        entity_id=domain.id,
        details={"reason_sha256": hashlib.sha256(payload.reason.encode("utf-8")).hexdigest()},
    )
    def check():
        if domain.enabled != payload.enabled or domain.authority_trust_key_id != pinned_key_id:
            raise ValueError("Organization trust-domain state changed before commit")
        if authority is not None:
            ensure_trust_key_usable(db, authority, expected_purpose="trust_bundle")
        if restoration is not None:
            _check_root_restoration(db, restoration)
            if (reanchor.status != "executed" or reanchor.to_trust_key_id != pinned_key_id
                or state.last_sequence != transparency.sequence
                or state.head_digest_sha256 != transparency.record_digest_sha256):
                raise ValueError("Root restoration authority changed before commit")
    commit_with_promotion_authority(db, check)
    db.refresh(domain)
    return domain


def _verified_bundle(
    db: Session,
    domain: OrganizationTrustDomain,
    signed: SignedOrganizationTrustBundle,
) -> dict[str, str]:
    assert_selected_trust_namespace(db, domain)
    if not domain.enabled:
        raise ValueError("Organization trust domain is disabled")
    bundle = signed.bundle
    material = bundle.model_dump(mode="json", exclude={"digest_sha256"})
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > TRUST_BUNDLE_MAX_BYTES:
        raise ValueError(
            f"Organization trust bundle exceeds {TRUST_BUNDLE_MAX_BYTES} bytes"
        )
    if _canonical_hash(material) != bundle.digest_sha256:
        raise ValueError("Organization trust-bundle digest does not match")
    if bundle.organization_id != domain.organization_id:
        raise ValueError("Organization trust-bundle identity does not match")
    if bundle.sequence != domain.latest_sequence + 1:
        raise ValueError(
            "Organization trust-bundle sequence must be the exact next sequence"
        )
    _validate_bundle_time(domain, signed)
    verification = verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=bundle.digest_sha256,
        signed_format_version=SIGNED_ORGANIZATION_TRUST_BUNDLE_FORMAT,
        expected_purpose="trust_bundle",
    )
    if verification["trust_key_id"] != domain.authority_trust_key_id:
        raise ValueError(
            "Organization trust bundle is not signed by the pinned authority"
        )
    return verification


def _validate_bundle_time(
    domain: OrganizationTrustDomain,
    signed: SignedOrganizationTrustBundle,
) -> None:
    bundle = signed.bundle
    now = utcnow()
    issued_at = _as_utc(bundle.issued_at)
    expires_at = _as_utc(bundle.expires_at)
    if issued_at > now + TRUST_BUNDLE_CLOCK_SKEW:
        raise ValueError("Organization trust bundle is issued in the future")
    if expires_at <= now:
        raise ValueError("Organization trust bundle has expired")
    if expires_at - issued_at > timedelta(
        days=domain.max_bundle_lifetime_days
    ):
        raise ValueError(
            "Organization trust bundle exceeds the local lifetime policy"
        )


def _analyze_bundle(
    db: Session,
    domain: OrganizationTrustDomain,
    signed: SignedOrganizationTrustBundle,
) -> tuple[
    OrganizationTrustBundlePreviewRead,
    dict[str, str],
    dict[str, tuple[str, str]],
]:
    verification = _verified_bundle(db, domain, signed)
    bundle = signed.bundle
    existing_keys = list(db.scalars(select(ArtifactTrustKey).where(
        ArtifactTrustKey.tenant_id == domain.tenant_id,
        ArtifactTrustKey.region_id == domain.region_id,
    ).execution_options(populate_existing=True)).all())
    by_fingerprint = {item.fingerprint_sha256: item for item in existing_keys}
    by_name = {item.name: item for item in existing_keys}
    canonical_keys: dict[str, tuple[str, str]] = {}
    plans: list[OrganizationTrustKeyPlan] = []
    top_blockers: list[str] = []
    incoming_fingerprints: set[str] = set()
    allowed_purposes = set(domain.allowed_purposes)
    now = utcnow()

    for item in bundle.keys:
        canonical_pem, calculated_fingerprint = _canonical_public_key(
            item.public_key_pem
        )
        if calculated_fingerprint != item.fingerprint_sha256:
            raise ValueError(
                f"Trust-bundle key fingerprint does not match PEM: {item.name}"
            )
        canonical_keys[item.fingerprint_sha256] = (
            canonical_pem,
            calculated_fingerprint,
        )
        incoming_fingerprints.add(item.fingerprint_sha256)
        blockers: list[str] = []
        existing = by_fingerprint.get(item.fingerprint_sha256)
        name_owner = by_name.get(item.name)
        if item.fingerprint_sha256 == (
            domain.authority_key_fingerprint_sha256
        ):
            blockers.append("authority_key_cannot_be_managed")
        if not set(item.purposes).issubset(allowed_purposes):
            blockers.append("purpose_not_allowed_by_local_policy")
        if (
            _as_utc(item.expires_at) - _as_utc(item.valid_from)
            > timedelta(days=domain.max_key_lifetime_days)
        ):
            blockers.append("key_lifetime_exceeds_local_policy")
        if item.state == "active" and _as_utc(item.expires_at) <= now:
            blockers.append("active_key_already_expired")
        if (
            name_owner is not None
            and name_owner.fingerprint_sha256 != item.fingerprint_sha256
        ):
            blockers.append("key_name_conflict")
        if existing is not None and (
            existing.trust_source != "trust_bundle"
            or existing.trust_domain_id != domain.id
        ):
            blockers.append("key_owned_outside_trust_domain")

        if item.state == "active":
            if existing is None:
                action = "add"
            elif existing.revoked_at is not None or not existing.enabled:
                action = "unchanged"
                blockers.append("revoked_key_cannot_be_reactivated")
            elif (
                existing.name != item.name
                or set(existing.purposes or []) != set(item.purposes)
                or existing.public_key_pem != canonical_pem
                or (
                    existing.valid_from is None
                    or _as_utc(existing.valid_from)
                    != _as_utc(item.valid_from)
                )
                or (
                    existing.expires_at is None
                    or _as_utc(existing.expires_at)
                    != _as_utc(item.expires_at)
                )
            ):
                action = "update"
            else:
                action = "unchanged"
        elif existing is None:
            action = "tombstone"
        elif existing.enabled:
            action = "revoke"
        else:
            action = "unchanged"
        plans.append(
            OrganizationTrustKeyPlan(
                name=item.name,
                fingerprint_sha256=item.fingerprint_sha256,
                purposes=list(item.purposes),
                requested_state=item.state,
                action=action,
                blockers=sorted(set(blockers)),
            )
        )

    for existing in existing_keys:
        if (
            existing.trust_source == "trust_bundle"
            and existing.trust_domain_id == domain.id
            and existing.fingerprint_sha256 not in incoming_fingerprints
        ):
            plans.append(
                OrganizationTrustKeyPlan(
                    name=existing.name,
                    fingerprint_sha256=existing.fingerprint_sha256,
                    purposes=list(existing.purposes or []),
                    requested_state="revoked",
                    action="revoke" if existing.enabled else "unchanged",
                    blockers=[],
                )
            )

    for plan in plans:
        top_blockers.extend(plan.blockers)
    active_count = sum(
        1 for item in bundle.keys if item.state == "active"
    )
    revoked_count = len(bundle.keys) - active_count
    preview = OrganizationTrustBundlePreviewRead(
        trust_domain_id=domain.id,
        organization_id=domain.organization_id,
        sequence=bundle.sequence,
        bundle_digest_sha256=bundle.digest_sha256,
        authority_key_fingerprint_sha256=verification[
            "key_fingerprint_sha256"
        ],
        issued_at=bundle.issued_at,
        expires_at=bundle.expires_at,
        key_count=len(bundle.keys),
        active_key_count=active_count,
        revoked_key_count=revoked_count,
        installable=not top_blockers,
        blockers=sorted(set(top_blockers)),
        keys=plans,
    )
    return preview, verification, canonical_keys


def preview_organization_trust_bundle(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustBundlePreviewCreate,
) -> OrganizationTrustBundlePreviewRead:
    domain = _get_domain(db, domain_id)
    preview, _, _ = _analyze_bundle(db, domain, payload.signed_bundle)
    return preview


def import_organization_trust_bundle(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustBundleImportCreate,
    *,
    actor: str,
) -> OrganizationTrustBundleImport:
    require_locking_transaction(db, purpose="Organization trust-bundle imports")
    set_session_namespace(db, *selected_trust_namespace(db))
    domain = _lock_domain(db, domain_id)
    if not domain.enabled:
        raise ValueError("Organization trust domain is disabled")
    authority = lock_trust_keys(db, [domain.authority_trust_key_id],
        expected_purpose="trust_bundle")[domain.authority_trust_key_id]
    bundle = payload.signed_bundle.bundle
    # The exclusive domain lock precedes managed-key locks, matching publisher
    # acceptance. Refresh owned pins, including omitted keys;
    # unrelated domains/keys must not become a namespace-wide write bottleneck.
    affected_keys = list(db.scalars(select(ArtifactTrustKey).where(
        ArtifactTrustKey.tenant_id == domain.tenant_id,
        ArtifactTrustKey.region_id == domain.region_id,
        ArtifactTrustKey.trust_source == "trust_bundle",
        ArtifactTrustKey.trust_domain_id == domain.id,
    ).order_by(ArtifactTrustKey.id).with_for_update()
        .execution_options(populate_existing=True)).all())
    preview, verification, canonical_keys = _analyze_bundle(
        db,
        domain,
        payload.signed_bundle,
    )
    if not preview.installable:
        raise ValueError(
            "Organization trust bundle is not installable: "
            + ", ".join(preview.blockers)
        )
    # Only mutate the owned rows we actually locked. Concurrent foreign/local
    # pin creation is stopped by the unique constraints, not overwritten.
    existing_keys = affected_keys
    by_fingerprint = {item.fingerprint_sha256: item for item in existing_keys}
    incoming = {
        item.fingerprint_sha256: item for item in bundle.keys
    }
    now = utcnow()

    for fingerprint, item in incoming.items():
        existing = by_fingerprint.get(fingerprint)
        canonical_pem = canonical_keys[fingerprint][0]
        if existing is None:
            existing = ArtifactTrustKey(
                tenant_id=domain.tenant_id,
                region_id=domain.region_id,
                name=item.name,
                algorithm="ed25519",
                public_key_pem=canonical_pem,
                fingerprint_sha256=fingerprint,
                enabled=item.state == "active",
                purposes=sorted(item.purposes),
                trust_source="trust_bundle",
                trust_domain_id=domain.id,
                managed_bundle_sequence=bundle.sequence,
                valid_from=item.valid_from,
                expires_at=item.expires_at,
                created_by=actor,
                revoked_at=now if item.state == "revoked" else None,
                revoked_by=actor if item.state == "revoked" else None,
            )
            db.add(existing)
            by_fingerprint[fingerprint] = existing
        else:
            existing.name = item.name
            existing.public_key_pem = canonical_pem
            existing.purposes = sorted(item.purposes)
            existing.valid_from = item.valid_from
            existing.expires_at = item.expires_at
            existing.managed_bundle_sequence = bundle.sequence
            if item.state == "revoked" and existing.enabled:
                existing.enabled = False
                existing.revoked_at = now
                existing.revoked_by = actor

    for existing in existing_keys:
        if (
            existing.trust_source == "trust_bundle"
            and existing.trust_domain_id == domain.id
            and existing.fingerprint_sha256 not in incoming
        ):
            if existing.enabled:
                existing.enabled = False
                existing.revoked_at = now
                existing.revoked_by = actor
            existing.managed_bundle_sequence = bundle.sequence

    receipt = OrganizationTrustBundleImport(
        trust_domain_id=domain.id,
        sequence=bundle.sequence,
        bundle_digest_sha256=bundle.digest_sha256,
        authority_key_fingerprint_sha256=verification[
            "key_fingerprint_sha256"
        ],
        signature_sha256=verification["signature_sha256"],
        issued_at=bundle.issued_at,
        expires_at=bundle.expires_at,
        key_count=preview.key_count,
        active_key_count=preview.active_key_count,
        revoked_key_count=preview.revoked_key_count,
        signed_bundle_snapshot=payload.signed_bundle.model_dump(mode="json"),
        reason=payload.reason,
        imported_by=actor,
    )
    db.add(receipt)
    domain.latest_sequence = bundle.sequence
    domain.latest_bundle_digest_sha256 = bundle.digest_sha256
    domain.updated_at = now
    try:
        db.flush()
        append_capability_transparency_record(
            db,
            event_type="capability.trust_bundle.imported",
            entity_type="organization_trust_bundle_import",
            entity_id=receipt.id,
            subject_digest_sha256=bundle.digest_sha256,
            details={
                "organization_id": domain.organization_id,
                "trust_domain_id": domain.id,
                "sequence": bundle.sequence,
                "key_count": preview.key_count,
                "active_key_count": preview.active_key_count,
                "revoked_key_count": preview.revoked_key_count,
                "authority_key_fingerprint_sha256": (
                    verification["key_fingerprint_sha256"]
                ),
            },
        )
        record_audit_event(
            db,
            event_type="capability.trust_bundle.imported",
            actor_type="user",
            actor_id=actor,
            entity_type="organization_trust_bundle_import",
            entity_id=receipt.id,
            details={
                "organization_id": domain.organization_id,
                "sequence": bundle.sequence,
                "bundle_digest_sha256": bundle.digest_sha256,
                "key_count": preview.key_count,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        # Row locks preserve policy, not time. Recheck after all reconciliation
        # and audit work; expiration rolls back keys, head and receipt together.
        _validate_bundle_time(domain, payload.signed_bundle)
        ensure_trust_key_usable(db, authority, expected_purpose="trust_bundle")
        now = utcnow()
        if any(item.state == "active" and _as_utc(item.expires_at) <= now
               for item in bundle.keys):
            raise ValueError("Organization trust bundle active key has expired")
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Organization trust-bundle sequence, digest, key name, or "
            "fingerprint already exists"
        ) from exc
    except Exception:
        db.rollback()
        raise
    # Preserve a lost response after a durable commit for receipt reconciliation.
    try:
        db.commit()
    except DBAPIError:
        db.rollback()
        raise
    db.refresh(receipt)
    return receipt


def list_organization_trust_bundle_imports(
    db: Session,
    *,
    domain_id: str | None,
    limit: int,
) -> list[OrganizationTrustBundleImport]:
    query = select(OrganizationTrustBundleImport)
    if domain_id is not None:
        query = query.where(
            OrganizationTrustBundleImport.trust_domain_id == domain_id
        )
    return list(
        db.scalars(
            query.order_by(
                OrganizationTrustBundleImport.imported_at.desc()
            ).limit(limit)
        ).all()
    )


def export_organization_trust_bundle(
    db: Session,
    import_id: str,
) -> SignedOrganizationTrustBundle:
    receipt = db.get(OrganizationTrustBundleImport, import_id)
    if receipt is None:
        raise LookupError("Organization trust-bundle import not found")
    return SignedOrganizationTrustBundle.model_validate(
        receipt.signed_bundle_snapshot
    )


@_trust_domain_mutation
def rotate_organization_trust_root(
    db: Session,
    domain_id: str,
    payload: OrganizationTrustRootRotationCreate,
    *,
    actor: str,
) -> OrganizationTrustRootRotation:
    require_locking_transaction(db, purpose="Organization root rotations")
    set_session_namespace(db, *selected_trust_namespace(db))
    domain = db.scalar(
        select(OrganizationTrustDomain)
        .where(OrganizationTrustDomain.id == domain_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if domain is None:
        raise LookupError("Organization trust domain not found")
    assert_selected_trust_namespace(db, domain)
    if not domain.enabled:
        raise ValueError("Organization trust domain is disabled")
    signed = payload.signed_rotation
    statement = signed.statement
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != statement.digest_sha256:
        raise ValueError("Organization trust-root rotation digest does not match")
    accepted = db.scalar(select(OrganizationTrustRootRotation).where(
        OrganizationTrustRootRotation.trust_domain_id == domain.id,
        OrganizationTrustRootRotation.statement_digest_sha256 == statement.digest_sha256,
    ))
    if accepted is not None:
        assert_rotation_replay(accepted, signed)
        if (accepted.to_trust_key_id != payload.new_authority_trust_key_id
            or domain.authority_trust_key_id != accepted.to_trust_key_id
            or domain.organization_id != statement.organization_id
            or domain.latest_sequence != statement.bundle_sequence
            or domain.latest_bundle_digest_sha256 != statement.bundle_digest_sha256):
            raise ValueError("Organization root rotation retry conflicts with current state")
        db.commit()
        return accepted
    keys = lock_trust_keys(db, [domain.authority_trust_key_id, payload.new_authority_trust_key_id], expected_purpose="trust_bundle")
    current_key = keys[domain.authority_trust_key_id]
    next_key = keys[payload.new_authority_trust_key_id]
    if current_key is None:
        raise ValueError("Current organization trust authority is unavailable")
    if next_key is None:
        raise ValueError("Next organization trust authority does not exist")
    if next_key.trust_source != "local":
        raise ValueError(
            "Next organization trust authority must be an out-of-band local key"
        )
    if next_key.id == current_key.id:
        raise ValueError("Next organization trust authority must differ from the current root")
    ensure_trust_key_usable(
        db,
        current_key,
        expected_purpose="trust_bundle",
    )
    ensure_trust_key_usable(
        db,
        next_key,
        expected_purpose="trust_bundle",
    )

    if statement.organization_id != domain.organization_id:
        raise ValueError("Organization trust-root rotation identity does not match")
    if statement.bundle_sequence != domain.latest_sequence:
        raise ValueError("Organization trust-root rotation sequence is stale")
    if statement.bundle_digest_sha256 != (
        domain.latest_bundle_digest_sha256
    ):
        raise ValueError("Organization trust-root rotation bundle digest is stale")
    if statement.current_key_fingerprint_sha256 != (
        current_key.fingerprint_sha256
    ):
        raise ValueError(
            "Organization trust-root rotation current signer is not pinned"
        )
    if statement.next_key_fingerprint_sha256 != next_key.fingerprint_sha256:
        raise ValueError(
            "Organization trust-root rotation next signer does not match"
        )

    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + TRUST_BUNDLE_CLOCK_SKEW:
        raise ValueError(
            "Organization trust-root rotation is issued in the future"
        )
    if expires_at <= now:
        raise ValueError("Organization trust-root rotation has expired")
    if expires_at - issued_at > TRUST_ROOT_ROTATION_MAX_LIFETIME:
        raise ValueError(
            "Organization trust-root rotation lifetime exceeds 24 hours"
        )

    current_verification = verify_trusted_digest_signature(
        db,
        signed.current_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=(
            SIGNED_ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT
        ),
        expected_purpose="trust_bundle",
    )
    next_verification = verify_trusted_digest_signature(
        db,
        signed.next_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=(
            SIGNED_ORGANIZATION_TRUST_ROOT_ROTATION_FORMAT
        ),
        expected_purpose="trust_bundle",
    )
    if current_verification["trust_key_id"] != current_key.id:
        raise ValueError(
            "Organization trust-root rotation lacks the pinned-root signature"
        )
    if next_verification["trust_key_id"] != next_key.id:
        raise ValueError(
            "Organization trust-root rotation lacks the next-root signature"
        )

    rotation = OrganizationTrustRootRotation(
        trust_domain_id=domain.id,
        from_trust_key_id=current_key.id,
        to_trust_key_id=next_key.id,
        from_key_fingerprint_sha256=current_key.fingerprint_sha256,
        to_key_fingerprint_sha256=next_key.fingerprint_sha256,
        bundle_sequence=domain.latest_sequence,
        bundle_digest_sha256=domain.latest_bundle_digest_sha256,
        statement_digest_sha256=statement.digest_sha256,
        current_signature_sha256=current_verification["signature_sha256"],
        next_signature_sha256=next_verification["signature_sha256"],
        issued_at=statement.issued_at,
        expires_at=statement.expires_at,
        reason=payload.reason,
        rotated_by=actor,
    )
    db.add(rotation)
    recovery_policies = list(
        db.scalars(
            select(OrganizationTrustRecoveryPolicy).where(
                OrganizationTrustRecoveryPolicy.trust_domain_id == domain.id,
                OrganizationTrustRecoveryPolicy.active.is_(True),
            )
        ).all()
    )
    for recovery_policy in recovery_policies:
        recovery_policy.active = False
        recovery_policy.superseded_at = now
    domain.authority_trust_key_id = next_key.id
    domain.authority_key_fingerprint_sha256 = next_key.fingerprint_sha256
    domain.updated_at = now
    try:
        db.flush()
        append_capability_transparency_record(
            db,
            event_type="capability.trust_root.rotated",
            entity_type="organization_trust_root_rotation",
            entity_id=rotation.id,
            subject_digest_sha256=statement.digest_sha256,
            details={
                "organization_id": domain.organization_id,
                "trust_domain_id": domain.id,
                "bundle_sequence": domain.latest_sequence,
                "from_key_fingerprint_sha256": (
                    current_key.fingerprint_sha256
                ),
                "to_key_fingerprint_sha256": next_key.fingerprint_sha256,
                "retired_recovery_policy_count": len(recovery_policies),
            },
        )
        record_audit_event(
            db,
            event_type="capability.trust_root.rotated",
            actor_type="user",
            actor_id=actor,
            entity_type="organization_trust_domain",
            entity_id=domain.id,
            details={
                "statement_digest_sha256": statement.digest_sha256,
                "from_key_fingerprint_sha256": (
                    current_key.fingerprint_sha256
                ),
                "to_key_fingerprint_sha256": next_key.fingerprint_sha256,
                "retired_recovery_policy_count": len(recovery_policies),
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        def check():
            if (not domain.enabled
                or domain.authority_trust_key_id != next_key.id
                or domain.authority_key_fingerprint_sha256 != next_key.fingerprint_sha256
                or domain.latest_sequence != statement.bundle_sequence
                or domain.latest_bundle_digest_sha256 != statement.bundle_digest_sha256):
                raise ValueError("Organization trust-root rotation state changed before commit")
            ensure_trust_key_usable(db, current_key, expected_purpose="trust_bundle")
            ensure_trust_key_usable(db, next_key, expected_purpose="trust_bundle")
            if _as_utc(statement.expires_at) <= utcnow():
                raise ValueError("Organization trust-root rotation has expired")

        commit_with_promotion_authority(db, check)
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Organization trust-root rotation statement already exists"
        ) from exc
    db.refresh(rotation)
    return rotation


def list_organization_trust_root_rotations(
    db: Session,
    *,
    domain_id: str | None,
    limit: int,
) -> list[OrganizationTrustRootRotation]:
    query = select(OrganizationTrustRootRotation)
    if domain_id is not None:
        query = query.where(
            OrganizationTrustRootRotation.trust_domain_id == domain_id
        )
    return list(
        db.scalars(
            query.order_by(
                OrganizationTrustRootRotation.rotated_at.desc()
            ).limit(limit)
        ).all()
    )
