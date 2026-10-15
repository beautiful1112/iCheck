from __future__ import annotations

import hashlib
from uuid import uuid4
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..capability_promotion_schemas import (
    PROMOTION_ATTESTATION_FORMAT,
    SIGNED_PROMOTION_ATTESTATION_FORMAT,
    CapabilityPromotionAcceptCreate,
    CapabilityPromotionAttestation,
    CapabilityPromotionPublicationAction,
    CapabilityPromotionPublicationPreviewRead,
    CapabilityPromotionPolicyUpdate,
    CapabilityPromotionPreviewCreate,
    CapabilityPromotionPreviewRead,
    CapabilityPromotionSourceCreate,
    CapabilityPromotionSourceStateCreate,
    CapabilityPromotionStatementCreate,
    SignedCapabilityPromotionAttestation,
)
from ..models import (
    ArtifactTrustKey,
    ArtifactVersion,
    ArtifactVersionStatus,
    CapabilityPackInstalledArtifact,
    CapabilityPackInstallation,
    CapabilityPromotionPolicy,
    CapabilityPromotionPublication,
    CapabilityPromotionReceipt,
    CapabilityPromotionSource,
    CollectorCanaryRollout,
    OrganizationTrustDomain,
    utcnow,
)
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .capability_pack_revocations import active_pack_revocation
from .artifact_lifecycle import artifact_identities_for_versions, lock_artifact_identities, prepare_artifact_mutation
from .trust_authority import lock_publisher_resource
from .trust_authority import lock_trust_keys
from .promotion_authority import (
    commit_with_promotion_authority,
    lock_promotion_installation,
    lock_promotion_policy,
    lock_promotion_source,
    promotion_mutation,
    promotion_policy_query,
)
from .capability_transparency import (
    append_capability_transparency_record,
    get_capability_transparency_checkpoint,
)
from .collectors import publish_artifact_version
from .promotion_witnesses import (
    assert_source_witness_decision, check_source_checkpoint,
    record_source_witness_decision, source_witness_policy_snapshot,
)


PROMOTION_CLOCK_SKEW = timedelta(minutes=5)
PROMOTION_MAX_BYTES = 262_144


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


def _installation_query():
    return select(CapabilityPackInstallation).options(
        selectinload(CapabilityPackInstallation.artifacts)
    )


def _artifact_set_material(
    installation: CapabilityPackInstallation,
) -> list[dict[str, str]]:
    return sorted(
        [
            {
                "name": row.source_name,
                "kind": row.source_kind,
                "content_hash": row.source_content_hash,
                "bundle_digest_sha256": row.source_bundle_digest_sha256,
            }
            for row in installation.artifacts
        ],
        key=lambda item: (
            item["kind"],
            item["name"],
            item["content_hash"],
        ),
    )


def _artifact_set_digest(
    installation: CapabilityPackInstallation,
) -> str:
    return _canonical_hash(_artifact_set_material(installation))


def get_promotion_policy(
    db: Session,
) -> CapabilityPromotionPolicy | None:
    return db.scalars(promotion_policy_query(db).execution_options(populate_existing=True)).one_or_none()


@promotion_mutation
def update_promotion_policy(
    db: Session,
    payload: CapabilityPromotionPolicyUpdate,
    *,
    actor: str,
) -> CapabilityPromotionPolicy:
    policy = lock_promotion_policy(db, writable=True)
    if db.scalar(select(CapabilityPromotionSource.id).where(
        CapabilityPromotionSource.environment_id == payload.local_environment_id)):
        raise ValueError("Promotion local environment cannot be a registered source")
    if policy is None:
        policy = CapabilityPromotionPolicy(
            id=uuid4().hex,
            local_environment_id=payload.local_environment_id,
            local_stage=payload.local_stage,
            required_source_stage=payload.required_source_stage,
            max_attestation_age_hours=payload.max_attestation_age_hours,
            publication_mode=payload.publication_mode,
            require_distinct_publisher=(
                payload.require_distinct_publisher
            ),
            updated_by=actor,
        )
        db.add(policy)
        event_type = "capability.promotion_policy.configured"
    else:
        receipt_count = db.scalar(
            select(func.count(CapabilityPromotionReceipt.id))
        ) or 0
        identity_changed = (
            policy.local_environment_id != payload.local_environment_id
            or policy.local_stage != payload.local_stage
        )
        if receipt_count and identity_changed:
            raise ValueError(
                "Promotion environment identity is immutable after acceptance"
            )
        policy.local_environment_id = payload.local_environment_id
        policy.local_stage = payload.local_stage
        policy.required_source_stage = payload.required_source_stage
        policy.max_attestation_age_hours = (
            payload.max_attestation_age_hours
        )
        policy.publication_mode = payload.publication_mode
        policy.require_distinct_publisher = (
            payload.require_distinct_publisher
        )
        policy.updated_by = actor
        policy.updated_at = utcnow()
        event_type = "capability.promotion_policy.updated"
    record_audit_event(
        db,
        event_type=event_type,
        actor_type="user",
        actor_id=actor,
        entity_type="capability_promotion_policy",
        entity_id=policy.id,
        details={
            "local_environment_id": payload.local_environment_id,
            "local_stage": payload.local_stage,
            "required_source_stage": payload.required_source_stage,
            "max_attestation_age_hours": (
                payload.max_attestation_age_hours
            ),
            "publication_mode": payload.publication_mode,
            "require_distinct_publisher": (
                payload.require_distinct_publisher
            ),
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.commit()
    db.refresh(policy)
    return policy


def _assert_source_key_organization(
    db: Session,
    key: ArtifactTrustKey,
    organization_id: str,
) -> None:
    if key.trust_source != "trust_bundle":
        return
    if key.trust_domain_id is None:
        raise ValueError("Promotion source key has no trust domain")
    domain = db.get(OrganizationTrustDomain, key.trust_domain_id)
    if domain is None or domain.organization_id != organization_id:
        raise ValueError(
            "Promotion source organization does not match its trust domain"
        )


@promotion_mutation
def register_promotion_source(
    db: Session,
    payload: CapabilityPromotionSourceCreate,
    *,
    actor: str,
) -> CapabilityPromotionSource:
    policy = lock_promotion_policy(db)
    if (
        policy is not None
        and payload.environment_id == policy.local_environment_id
    ):
        raise ValueError("Promotion source cannot be the local environment")
    if lock_promotion_source(db, environment_id=payload.environment_id, writable=True):
        raise ValueError("Promotion source name or environment identity already exists")
    key = lock_trust_keys(db, [payload.trust_key_id], expected_purpose="environment_promotion")[payload.trust_key_id]
    _assert_source_key_organization(db, key, payload.organization_id)
    source = CapabilityPromotionSource(
        name=payload.name,
        organization_id=payload.organization_id,
        environment_id=payload.environment_id,
        source_stage=payload.source_stage,
        trust_key_id=key.id,
        key_fingerprint_sha256=key.fingerprint_sha256,
        enabled=True,
        latest_sequence=0,
        created_by=actor,
    )
    db.add(source)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="capability.promotion_source.registered",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_promotion_source",
            entity_id=source.id,
            details={
                "organization_id": source.organization_id,
                "environment_id": source.environment_id,
                "source_stage": source.source_stage,
                "key_fingerprint_sha256": source.key_fingerprint_sha256,
            },
        )
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Promotion source name or environment identity already exists"
        ) from exc
    db.flush()
    ensure_trust_key_usable(db, key, expected_purpose="environment_promotion")
    commit_with_promotion_authority(db, lambda: ensure_trust_key_usable(db, key, expected_purpose="environment_promotion"))
    db.refresh(source)
    return source


def list_promotion_sources(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityPromotionSource]:
    return list(
        db.scalars(
            select(CapabilityPromotionSource)
            .order_by(CapabilityPromotionSource.name)
            .limit(limit)
        ).all()
    )


@promotion_mutation
def set_promotion_source_state(
    db: Session,
    source_id: str,
    payload: CapabilityPromotionSourceStateCreate,
    *,
    actor: str,
) -> CapabilityPromotionSource:
    policy = lock_promotion_policy(db)
    source = lock_promotion_source(db, source_id=source_id, writable=True)
    if source is None:
        raise LookupError("Promotion source not found")
    if source.enabled == payload.enabled:
        db.commit()
        return source
    if payload.enabled:
        if policy and policy.local_environment_id == source.environment_id:
            raise ValueError("Promotion source cannot be the local environment")
        from .promotion_recovery import prepare_source_restoration, record_source_restoration
        recovery_context = prepare_source_restoration(db, source, policy, payload.checkpoint_evidence)
        key = recovery_context[4] if recovery_context else lock_trust_keys(db,
            [source.trust_key_id], expected_purpose="environment_promotion")[source.trust_key_id]
        _assert_source_key_organization(
            db,
            key,
            source.organization_id,
        )
    source.enabled = payload.enabled
    source.updated_at = utcnow()
    append_capability_transparency_record(db,
        event_type="capability.promotion_source.enabled" if source.enabled else "capability.promotion_source.disabled",
        entity_type="capability_promotion_source", entity_id=source.id,
        subject_digest_sha256=_canonical_hash({"source_id": source.id, "enabled": source.enabled,
            "reason_sha256": hashlib.sha256(payload.reason.encode()).hexdigest()}),
        details={"source_id": source.id, "enabled": source.enabled})
    if payload.enabled:
        record_source_restoration(db, recovery_context, payload.checkpoint_evidence, actor=actor, reason=payload.reason)
    record_audit_event(
        db,
        event_type=(
            "capability.promotion_source.enabled"
            if source.enabled
            else "capability.promotion_source.disabled"
        ),
        actor_type="user",
        actor_id=actor,
        entity_type="capability_promotion_source",
        entity_id=source.id,
        details={
            "environment_id": source.environment_id,
            "reason_sha256": hashlib.sha256(
                payload.reason.encode("utf-8")
            ).hexdigest(),
        },
    )
    db.flush()
    if payload.enabled:
        ensure_trust_key_usable(db, key, expected_purpose="environment_promotion")
    if payload.enabled:
        def check():
            ensure_trust_key_usable(db, key, expected_purpose="environment_promotion")
            if recovery_context:
                recovery_context[3]()
        commit_with_promotion_authority(db, check)
    else:
        db.commit()
    db.refresh(source)
    return source


def _installation_blockers(
    db: Session,
    attestation: CapabilityPromotionAttestation,
) -> tuple[CapabilityPackInstallation | None, list[str]]:
    installation = db.scalar(
        _installation_query().where(
            CapabilityPackInstallation.pack_digest_sha256
            == attestation.pack_digest_sha256
        )
    )
    blockers: list[str] = []
    if installation is None:
        return None, ["pack_not_installed"]
    if installation.lifecycle_status != "installed":
        blockers.append("pack_uninstalled")
    if active_pack_revocation(db, installation.pack_digest_sha256) is not None:
        blockers.append("pack_revoked")
    if installation.pack_name != attestation.pack_name:
        blockers.append("pack_name_mismatch")
    if installation.pack_version != attestation.pack_version:
        blockers.append("pack_version_mismatch")
    if (
        installation.key_fingerprint_sha256
        != attestation.pack_signer_fingerprint_sha256
    ):
        blockers.append("pack_signer_mismatch")
    if len(installation.artifacts) != attestation.artifact_count:
        blockers.append("artifact_count_mismatch")
    if _artifact_set_digest(installation) != (
        attestation.artifact_set_digest_sha256
    ):
        blockers.append("artifact_set_mismatch")
    latest = db.scalar(
        select(CapabilityPackInstallation)
        .where(
            CapabilityPackInstallation.pack_name == installation.pack_name,
            CapabilityPackInstallation.lifecycle_status == "installed",
        )
        .order_by(
            CapabilityPackInstallation.installed_at.desc(),
            CapabilityPackInstallation.id.desc(),
        )
        .limit(1)
    )
    if latest is None or latest.id != installation.id:
        blockers.append("pack_not_lineage_head")
    pack_key = db.get(ArtifactTrustKey, installation.trust_key_id)
    try:
        if pack_key is None:
            raise ValueError("Pack signer key is unavailable")
        ensure_trust_key_usable(
            db,
            pack_key,
            expected_purpose="capability_pack",
        )
    except ValueError:
        blockers.append("pack_signer_untrusted")
    for row in installation.artifacts:
        version = db.get(ArtifactVersion, row.artifact_version_id)
        if version is None or version.status not in {
            ArtifactVersionStatus.VALIDATED,
            ArtifactVersionStatus.PUBLISHED,
        }:
            blockers.append("artifact_version_not_eligible")
            break
    for dependency in installation.dependency_snapshot:
        if dependency.get("state") == "pack":
            continue
        version_id = dependency.get("artifact_version_id")
        version = db.get(ArtifactVersion, version_id) if version_id else None
        if (
            dependency.get("state") != "published"
            or version is None
            or version.status != ArtifactVersionStatus.PUBLISHED
        ):
            blockers.append("dependency_not_current")
            break
    return installation, list(dict.fromkeys(blockers))


@promotion_mutation
def create_promotion_statement(
    db: Session,
    payload: CapabilityPromotionStatementCreate,
    *,
    actor: str,
) -> CapabilityPromotionAttestation:
    policy = lock_promotion_policy(db)
    if policy is None:
        raise ValueError("Local promotion policy is not configured")
    if payload.target_environment_id == policy.local_environment_id:
        raise ValueError("Promotion target must differ from the local environment")
    if payload.validity_hours > policy.max_attestation_age_hours:
        raise ValueError("Promotion statement exceeds local age policy")
    authority = lock_promotion_installation(db, policy=policy, installation_id=payload.installation_id)
    installation = authority.installation
    placeholder = CapabilityPromotionAttestation.model_construct(
        pack_digest_sha256=installation.pack_digest_sha256,
        pack_name=installation.pack_name,
        pack_version=installation.pack_version,
        pack_signer_fingerprint_sha256=(
            installation.key_fingerprint_sha256
        ),
        artifact_count=len(installation.artifacts),
        artifact_set_digest_sha256=_artifact_set_digest(installation),
    )
    _, blockers = _installation_blockers(db, placeholder)
    if blockers:
        raise ValueError(
            "Capability pack is not promotion-eligible: "
            + ", ".join(blockers)
        )
    checkpoint = get_capability_transparency_checkpoint(db)
    if checkpoint.last_sequence == 0:
        raise ValueError("Empty transparency log cannot support promotion")
    issued_at = utcnow()
    expires_at = issued_at + timedelta(hours=payload.validity_hours)
    material = {
        "format_version": PROMOTION_ATTESTATION_FORMAT,
        "organization_id": payload.organization_id,
        "source_environment_id": policy.local_environment_id,
        "source_stage": policy.local_stage,
        "target_environment_id": payload.target_environment_id,
        "target_stage": payload.target_stage,
        "promotion_sequence": payload.promotion_sequence,
        "pack_name": installation.pack_name,
        "pack_version": installation.pack_version,
        "pack_digest_sha256": installation.pack_digest_sha256,
        "pack_signer_fingerprint_sha256": (
            installation.key_fingerprint_sha256
        ),
        "artifact_count": len(installation.artifacts),
        "artifact_set_digest_sha256": _artifact_set_digest(installation),
        "source_transparency_log_id": checkpoint.log_id,
        "source_transparency_epoch": checkpoint.epoch,
        "source_transparency_sequence": checkpoint.last_sequence,
        "source_transparency_head_sha256": (
            checkpoint.head_digest_sha256
        ),
        "validation_evidence_digest_sha256": (
            payload.validation_evidence_digest_sha256
        ),
        "issued_at": _json_timestamp(issued_at),
        "expires_at": _json_timestamp(expires_at),
    }
    statement = CapabilityPromotionAttestation.model_validate(
        {**material, "digest_sha256": _canonical_hash(material)}
    )
    record_audit_event(
        db,
        event_type="capability.promotion_statement.generated",
        actor_type="user",
        actor_id=actor,
        entity_type="capability_pack_installation",
        entity_id=installation.id,
        details={
            "target_environment_id": payload.target_environment_id,
            "target_stage": payload.target_stage,
            "promotion_sequence": payload.promotion_sequence,
            "pack_digest_sha256": installation.pack_digest_sha256,
            "statement_digest_sha256": statement.digest_sha256,
        },
    )
    def check_statement_authority():
        authority.check_trust(db)
        if _as_utc(statement.expires_at) <= utcnow():
            raise ValueError("Promotion statement expired before commit")
    commit_with_promotion_authority(db, check_statement_authority)
    return statement


def _preview_from_existing(
    receipt: CapabilityPromotionReceipt,
) -> CapabilityPromotionPreviewRead:
    return CapabilityPromotionPreviewRead(
        source_id=receipt.source_id,
        source_environment_id=receipt.source_environment_id,
        target_environment_id=receipt.target_environment_id,
        target_stage=receipt.target_stage,
        promotion_sequence=receipt.promotion_sequence,
        installation_id=receipt.installation_id,
        pack_name=receipt.pack_name,
        pack_version=receipt.pack_version,
        pack_digest_sha256=receipt.pack_digest_sha256,
        artifact_count=receipt.artifact_count,
        source_transparency_log_id=receipt.source_transparency_log_id,
        source_transparency_epoch=receipt.source_transparency_epoch,
        source_transparency_sequence=receipt.source_transparency_sequence,
        source_transparency_head_sha256=(
            receipt.source_transparency_head_sha256
        ),
        promotable=False,
        already_accepted=True,
        existing_receipt_id=receipt.id,
        blockers=[],
    )


def _source_attestation_authority(db, signed, source, policy):
    """Fresh source/policy and signed bytes, independent of receipt sequence."""
    attestation = signed.attestation
    if policy is None:
        raise ValueError("Local promotion policy is not configured")
    if source is None or not source.enabled:
        raise ValueError("Promotion source is not registered or enabled")
    if (source.environment_id != attestation.source_environment_id
        or source.organization_id != attestation.organization_id or source.source_stage != attestation.source_stage):
        raise ValueError("Promotion source identity does not match")
    if _canonical_hash(attestation.model_dump(mode="json", exclude={"digest_sha256"})) != attestation.digest_sha256:
        raise ValueError("Promotion attestation digest does not match")
    now = utcnow()
    if _as_utc(attestation.issued_at) > now + PROMOTION_CLOCK_SKEW:
        raise ValueError("Promotion attestation is issued in the future")
    if _as_utc(attestation.expires_at) <= now:
        raise ValueError("Promotion attestation has expired")
    if _as_utc(attestation.expires_at) - _as_utc(attestation.issued_at) > timedelta(hours=policy.max_attestation_age_hours):
        raise ValueError("Promotion attestation exceeds local age policy")
    verification = verify_trusted_digest_signature(db, signed.signature,
        expected_digest_sha256=attestation.digest_sha256, signed_format_version=SIGNED_PROMOTION_ATTESTATION_FORMAT,
        expected_purpose="environment_promotion")
    if (verification["trust_key_id"] != source.trust_key_id
        or verification["key_fingerprint_sha256"] != source.key_fingerprint_sha256):
        raise ValueError("Promotion attestation is not signed by its pinned key")
    key = db.get(ArtifactTrustKey, source.trust_key_id)
    _assert_source_key_organization(db, key, source.organization_id)
    evidence, witness_policy = check_source_checkpoint(db, signed, source)
    verification.update(source_witness_evidence=evidence, source_witness_policy=witness_policy)
    blockers = []
    if attestation.target_environment_id != policy.local_environment_id:
        blockers.append("target_environment_mismatch")
    if attestation.target_stage != policy.local_stage:
        blockers.append("target_stage_mismatch")
    if attestation.source_stage != policy.required_source_stage:
        blockers.append("source_stage_not_allowed")
    return verification, blockers


def _assert_receipt_snapshot(db, receipt, signed, verification, source):
    for name, value in signed.attestation.model_dump().items():
        if name == "format_version":
            continue
        stored = getattr(receipt, "statement_digest_sha256" if name == "digest_sha256" else name)
        if isinstance(value, datetime):
            value, stored = _as_utc(value), _as_utc(stored)
        if stored != value:
            raise ValueError("Promotion receipt fields do not match its signed snapshot")
    if (receipt.source_id != source.id or receipt.trust_key_id != verification["trust_key_id"]
        or receipt.key_fingerprint_sha256 != verification["key_fingerprint_sha256"]
        or receipt.signature_sha256 != verification["signature_sha256"]):
        raise ValueError("Promotion receipt signer binding has drifted")

    assert_source_witness_decision(db, receipt, signed, verification)


def _check_promotion_commit(db, authority, signed, *, receipt=None, publisher=None):
    authority.check_trust(db)
    verification, blockers = _source_attestation_authority(db, signed, authority.source, authority.policy)
    if any("transparency_witness" not in authority.requirements.get(row["trust_key_id"], set())
        for row in verification["source_witness_evidence"]):
        raise ValueError("Promotion witness authority changed before commit")
    if receipt is not None:
        _assert_receipt_snapshot(db, receipt, signed, verification, authority.source)
    if publisher is not None:
        if authority.policy.publication_mode != "manual":
            blockers.append("promotion_publication_disabled")
        if authority.policy.require_distinct_publisher and publisher == receipt.accepted_by:
            blockers.append("distinct_publisher_required")
    _, installation_blockers = _installation_blockers(db, signed.attestation)
    blockers.extend(installation_blockers)
    if blockers:
        raise ValueError("Promotion authority changed before commit: " + ", ".join(dict.fromkeys(blockers)))


def _evaluate_promotion(
    db: Session,
    payload: CapabilityPromotionPreviewCreate,
) -> tuple[
    CapabilityPromotionPreviewRead,
    CapabilityPromotionSource,
    CapabilityPackInstallation | None,
    dict[str, str],
]:
    signed = payload.signed_attestation
    attestation = signed.attestation
    material = attestation.model_dump(
        mode="json",
        exclude={"digest_sha256"},
    )
    encoded = json.dumps(
        signed.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > PROMOTION_MAX_BYTES:
        raise ValueError(
            f"Promotion attestation exceeds {PROMOTION_MAX_BYTES} bytes"
        )
    if _canonical_hash(material) != attestation.digest_sha256:
        raise ValueError("Promotion attestation digest does not match")
    existing = db.scalar(
        select(CapabilityPromotionReceipt).where(
            CapabilityPromotionReceipt.statement_digest_sha256
            == attestation.digest_sha256
        )
    )
    if existing is not None:
        if existing.signed_attestation_snapshot != signed.model_dump(
            mode="json"
        ):
            raise ValueError("Accepted promotion snapshot does not match")
        source = db.get(CapabilityPromotionSource, existing.source_id)
        installation = db.get(
            CapabilityPackInstallation,
            existing.installation_id,
        )
        if source is None:
            raise RuntimeError("Accepted promotion source is unavailable")
        return (
            _preview_from_existing(existing),
            source,
            installation,
            {
                "trust_key_id": existing.trust_key_id,
                "key_fingerprint_sha256": existing.key_fingerprint_sha256,
                "signature_sha256": existing.signature_sha256,
            },
        )
    policy = get_promotion_policy(db)
    if policy is None:
        raise ValueError("Local promotion policy is not configured")
    now = utcnow()
    issued_at = _as_utc(attestation.issued_at)
    expires_at = _as_utc(attestation.expires_at)
    if issued_at > now + PROMOTION_CLOCK_SKEW:
        raise ValueError("Promotion attestation is issued in the future")
    if expires_at <= now:
        raise ValueError("Promotion attestation has expired")
    if expires_at - issued_at > timedelta(
        hours=policy.max_attestation_age_hours
    ):
        raise ValueError("Promotion attestation exceeds local age policy")
    source = db.scalar(
        select(CapabilityPromotionSource).where(
            CapabilityPromotionSource.environment_id
            == attestation.source_environment_id,
            CapabilityPromotionSource.enabled.is_(True),
        )
    )
    if source is None:
        raise ValueError("Promotion source is not registered or enabled")
    if (
        source.organization_id != attestation.organization_id
        or source.source_stage != attestation.source_stage
    ):
        raise ValueError("Promotion source identity does not match")
    verification = verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=attestation.digest_sha256,
        signed_format_version=SIGNED_PROMOTION_ATTESTATION_FORMAT,
        expected_purpose="environment_promotion",
    )
    if (
        verification["trust_key_id"] != source.trust_key_id
        or verification["key_fingerprint_sha256"]
        != source.key_fingerprint_sha256
    ):
        raise ValueError("Promotion attestation is not signed by its pinned key")
    blockers: list[str] = []
    witness_evidence, witness_policy = check_source_checkpoint(db, signed, source)
    verification.update(source_witness_evidence=witness_evidence, source_witness_policy=witness_policy)
    if attestation.target_environment_id != policy.local_environment_id:
        blockers.append("target_environment_mismatch")
    if attestation.target_stage != policy.local_stage:
        blockers.append("target_stage_mismatch")
    if attestation.source_stage != policy.required_source_stage:
        blockers.append("source_stage_not_allowed")
    expected_sequence = source.latest_sequence + 1
    if attestation.promotion_sequence < expected_sequence:
        blockers.append("promotion_sequence_replay")
    elif attestation.promotion_sequence > expected_sequence:
        blockers.append("promotion_sequence_gap")
    installation, installation_blockers = _installation_blockers(
        db,
        attestation,
    )
    blockers.extend(installation_blockers)
    other_receipt = db.scalar(
        select(CapabilityPromotionReceipt.id).where(
            CapabilityPromotionReceipt.target_environment_id
            == attestation.target_environment_id,
            CapabilityPromotionReceipt.pack_digest_sha256
            == attestation.pack_digest_sha256,
        )
    )
    if other_receipt is not None:
        blockers.append("pack_already_promoted")
    blockers = list(dict.fromkeys(blockers))
    preview = CapabilityPromotionPreviewRead(
        source_id=source.id,
        source_environment_id=source.environment_id,
        target_environment_id=attestation.target_environment_id,
        target_stage=attestation.target_stage,
        promotion_sequence=attestation.promotion_sequence,
        installation_id=installation.id if installation else None,
        pack_name=attestation.pack_name,
        pack_version=attestation.pack_version,
        pack_digest_sha256=attestation.pack_digest_sha256,
        artifact_count=attestation.artifact_count,
        source_transparency_log_id=(
            attestation.source_transparency_log_id
        ),
        source_transparency_epoch=attestation.source_transparency_epoch,
        source_transparency_sequence=(
            attestation.source_transparency_sequence
        ),
        source_transparency_head_sha256=(
            attestation.source_transparency_head_sha256
        ),
        promotable=not blockers,
        source_witness_count=len([row for row in witness_evidence if row["witness_id"] in witness_policy["witness_ids"]]),
        required_source_witness_quorum=witness_policy["required_quorum"],
        already_accepted=False,
        blockers=blockers,
    )
    return preview, source, installation, verification


def preview_capability_promotion(
    db: Session,
    payload: CapabilityPromotionPreviewCreate,
) -> CapabilityPromotionPreviewRead:
    preview, _, _, _ = _evaluate_promotion(db, payload)
    return preview


@promotion_mutation
def accept_capability_promotion(
    db: Session,
    payload: CapabilityPromotionAcceptCreate,
    *,
    actor: str,
) -> CapabilityPromotionReceipt:
    policy = lock_promotion_policy(db)
    source = lock_promotion_source(db, environment_id=payload.signed_attestation.attestation.source_environment_id, writable=True)
    preview_payload = CapabilityPromotionPreviewCreate(signed_attestation=payload.signed_attestation)
    # Returning an exact existing receipt is history, not renewed authority.
    existing = db.scalar(select(CapabilityPromotionReceipt).where(
        CapabilityPromotionReceipt.statement_digest_sha256 == payload.signed_attestation.attestation.digest_sha256)
        .execution_options(populate_existing=True))
    if existing is not None:
        _evaluate_promotion(db, preview_payload)  # Exact signed snapshot binding.
        db.commit()
        return existing
    if source is None:
        raise ValueError("Promotion source is not registered or enabled")
    authority = lock_promotion_installation(db, policy=policy, source=source,
        pack_digest=payload.signed_attestation.attestation.pack_digest_sha256, signed=payload.signed_attestation)
    preview, source, installation, verification = _evaluate_promotion(db, preview_payload)
    if not preview.promotable or installation is None:
        raise ValueError("Capability promotion is not acceptable: " + ", ".join(preview.blockers))
    attestation = payload.signed_attestation.attestation
    receipt = CapabilityPromotionReceipt(
        source_id=source.id,
        installation_id=installation.id,
        organization_id=attestation.organization_id,
        source_environment_id=attestation.source_environment_id,
        source_stage=attestation.source_stage,
        target_environment_id=attestation.target_environment_id,
        target_stage=attestation.target_stage,
        promotion_sequence=attestation.promotion_sequence,
        pack_name=attestation.pack_name,
        pack_version=attestation.pack_version,
        pack_digest_sha256=attestation.pack_digest_sha256,
        pack_signer_fingerprint_sha256=(
            attestation.pack_signer_fingerprint_sha256
        ),
        artifact_count=attestation.artifact_count,
        artifact_set_digest_sha256=(
            attestation.artifact_set_digest_sha256
        ),
        source_transparency_log_id=(
            attestation.source_transparency_log_id
        ),
        source_transparency_epoch=attestation.source_transparency_epoch,
        source_transparency_sequence=(
            attestation.source_transparency_sequence
        ),
        source_transparency_head_sha256=(
            attestation.source_transparency_head_sha256
        ),
        validation_evidence_digest_sha256=(
            attestation.validation_evidence_digest_sha256
        ),
        statement_digest_sha256=attestation.digest_sha256,
        trust_key_id=verification["trust_key_id"],
        key_fingerprint_sha256=verification["key_fingerprint_sha256"],
        signature_sha256=verification["signature_sha256"],
        signed_attestation_snapshot=(
            payload.signed_attestation.model_dump(mode="json")
        ),
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        reason=payload.reason,
        accepted_by=actor,
    )
    try:
        db.add(receipt)
        source.latest_sequence = attestation.promotion_sequence
        source.latest_statement_digest_sha256 = attestation.digest_sha256
        source.updated_at = utcnow()
        db.flush()
        record_source_witness_decision(db, receipt, payload.signed_attestation, verification, actor=actor)
        append_capability_transparency_record(
            db,
            event_type="capability.pack.promotion_accepted",
            entity_type="capability_promotion_receipt",
            entity_id=receipt.id,
            subject_digest_sha256=attestation.digest_sha256,
            details={
                "source_environment_id": source.environment_id,
                "target_environment_id": attestation.target_environment_id,
                "target_stage": attestation.target_stage,
                "promotion_sequence": attestation.promotion_sequence,
                "pack_name": attestation.pack_name,
                "pack_version": attestation.pack_version,
                "pack_digest_sha256": attestation.pack_digest_sha256,
                "artifact_count": attestation.artifact_count,
            },
        )
        record_audit_event(
            db,
            event_type="capability.pack.promotion_accepted",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_promotion_receipt",
            entity_id=receipt.id,
            details={
                "source_environment_id": source.environment_id,
                "source_stage": source.source_stage,
                "target_environment_id": attestation.target_environment_id,
                "target_stage": attestation.target_stage,
                "promotion_sequence": attestation.promotion_sequence,
                "pack_digest_sha256": attestation.pack_digest_sha256,
                "statement_digest_sha256": attestation.digest_sha256,
                "source_transparency_log_id": (
                    attestation.source_transparency_log_id
                ),
                "source_transparency_sequence": (
                    attestation.source_transparency_sequence
                ),
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Promotion sequence, statement, or target pack already exists") from exc
    except Exception:
        db.rollback()
        raise
    commit_with_promotion_authority(db, lambda: _check_promotion_commit(db, authority, payload.signed_attestation, receipt=receipt))
    db.refresh(receipt)
    return receipt


def list_promotion_receipts(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityPromotionReceipt]:
    return list(
        db.scalars(
            select(CapabilityPromotionReceipt)
            .order_by(CapabilityPromotionReceipt.accepted_at.desc())
            .limit(limit)
        ).all()
    )


def export_promotion_receipt(
    db: Session,
    receipt_id: str,
) -> dict[str, Any]:
    receipt = db.get(CapabilityPromotionReceipt, receipt_id)
    if receipt is None:
        raise LookupError("Capability promotion receipt not found")
    return receipt.signed_attestation_snapshot


def _publication_policy_snapshot(
    policy: CapabilityPromotionPolicy,
) -> dict[str, Any]:
    return {
        "local_environment_id": policy.local_environment_id,
        "local_stage": policy.local_stage,
        "required_source_stage": policy.required_source_stage,
        "publication_mode": policy.publication_mode,
        "require_distinct_publisher": policy.require_distinct_publisher,
        "policy_updated_at": _json_timestamp(policy.updated_at),
    }


def _existing_publication_preview(
    publication: CapabilityPromotionPublication,
) -> CapabilityPromotionPublicationPreviewRead:
    return CapabilityPromotionPublicationPreviewRead(
        receipt_id=publication.receipt_id,
        installation_id=publication.installation_id,
        eligible=False,
        already_published=True,
        existing_publication_id=publication.id,
        artifact_version_ids=publication.artifact_version_ids,
        candidate_artifact_version_ids=[],
        already_published_version_ids=(
            publication.already_published_version_ids
            + publication.newly_published_version_ids
        ),
        reused_version_ids=publication.reused_version_ids,
        blockers=[],
    )


def _evaluate_promotion_publication(
    db: Session,
    receipt_id: str,
    *,
    actor: str,
) -> tuple[
    CapabilityPromotionPublicationPreviewRead,
    CapabilityPromotionReceipt,
    CapabilityPackInstallation,
    CapabilityPromotionPolicy | None,
]:
    receipt = db.get(CapabilityPromotionReceipt, receipt_id)
    if receipt is None:
        raise LookupError("Capability promotion receipt not found")
    existing = db.scalar(
        select(CapabilityPromotionPublication).where(
            CapabilityPromotionPublication.receipt_id == receipt.id
        )
    )
    if existing is not None:
        installation = db.get(
            CapabilityPackInstallation,
            existing.installation_id,
        )
        if installation is None:
            raise RuntimeError("Published capability installation is unavailable")
        return (
            _existing_publication_preview(existing),
            receipt,
            installation,
            get_promotion_policy(db),
        )

    installation = db.scalar(
        _installation_query().where(
            CapabilityPackInstallation.id == receipt.installation_id
        )
    )
    if installation is None:
        raise RuntimeError("Promoted capability installation is unavailable")
    policy = get_promotion_policy(db)
    blockers: list[str] = []
    if policy is None or policy.publication_mode != "manual":
        blockers.append("promotion_publication_disabled")
    elif (
        policy.local_environment_id != receipt.target_environment_id
        or policy.local_stage != receipt.target_stage
    ):
        blockers.append("target_policy_drift")
    if (
        policy is not None
        and policy.require_distinct_publisher
        and actor == receipt.accepted_by
    ):
        blockers.append("distinct_publisher_required")
    if _as_utc(receipt.expires_at) <= utcnow():
        blockers.append("promotion_receipt_expired")

    source = db.get(CapabilityPromotionSource, receipt.source_id)
    if source is None or not source.enabled:
        blockers.append("promotion_source_disabled")
    else:
        source_key = db.get(ArtifactTrustKey, source.trust_key_id)
        try:
            if source_key is None:
                raise ValueError("Promotion source key is unavailable")
            ensure_trust_key_usable(
                db,
                source_key,
                expected_purpose="environment_promotion",
            )
            if (
                source.key_fingerprint_sha256
                != receipt.key_fingerprint_sha256
                or source_key.fingerprint_sha256
                != receipt.key_fingerprint_sha256
            ):
                raise ValueError("Promotion source key has drifted")
        except ValueError:
            blockers.append("promotion_source_untrusted")

    signed = SignedCapabilityPromotionAttestation.model_validate(
        receipt.signed_attestation_snapshot
    )
    if (
        signed.attestation.digest_sha256
        != receipt.statement_digest_sha256
    ):
        blockers.append("promotion_receipt_drift")
    try:
        verification, authority_blockers = _source_attestation_authority(db, signed, source, policy)
        _assert_receipt_snapshot(db, receipt, signed, verification, source)
        blockers.extend(authority_blockers)
    except ValueError:
        blockers.append("promotion_source_untrusted")
    checked_installation, installation_blockers = _installation_blockers(
        db,
        signed.attestation,
    )
    blockers.extend(installation_blockers)
    if (
        checked_installation is None
        or checked_installation.id != installation.id
    ):
        blockers.append("promotion_installation_drift")

    artifact_version_ids: list[str] = []
    candidates: list[str] = []
    already_published: list[str] = []
    reused: list[str] = []
    for row in installation.artifacts:
        version = db.get(ArtifactVersion, row.artifact_version_id)
        artifact_version_ids.append(row.artifact_version_id)
        if version is None:
            blockers.append("artifact_version_not_eligible")
            continue
        if row.install_action == "reused":
            reused.append(version.id)
            if version.status != ArtifactVersionStatus.PUBLISHED:
                blockers.append("reused_artifact_not_published")
            continue
        if row.install_action not in {"installed", "upgraded", "retained"}:
            blockers.append("unsupported_pack_artifact_action")
            continue
        if version.status == ArtifactVersionStatus.PUBLISHED:
            already_published.append(version.id)
            continue
        if version.status != ArtifactVersionStatus.VALIDATED:
            blockers.append("artifact_version_not_eligible")
            continue
        canary = db.scalar(
            select(CollectorCanaryRollout.id).where(
                CollectorCanaryRollout.candidate_version_id == version.id
            )
        )
        if canary is not None:
            blockers.append("artifact_requires_canary_promotion")
            continue
        candidates.append(version.id)

    preview = CapabilityPromotionPublicationPreviewRead(
        receipt_id=receipt.id,
        installation_id=installation.id,
        eligible=not blockers,
        already_published=False,
        artifact_version_ids=sorted(artifact_version_ids),
        candidate_artifact_version_ids=sorted(candidates),
        already_published_version_ids=sorted(already_published),
        reused_version_ids=sorted(reused),
        blockers=list(dict.fromkeys(blockers)),
    )
    return preview, receipt, installation, policy


def preview_promotion_publication(
    db: Session,
    receipt_id: str,
    payload: CapabilityPromotionPublicationAction,
    *,
    actor: str,
) -> CapabilityPromotionPublicationPreviewRead:
    preview, _, _, _ = _evaluate_promotion_publication(
        db,
        receipt_id,
        actor=actor,
    )
    return preview


@promotion_mutation
def publish_promoted_capability(
    db: Session,
    receipt_id: str,
    payload: CapabilityPromotionPublicationAction,
    *,
    actor: str,
) -> CapabilityPromotionPublication:
    policy = lock_promotion_policy(db)
    metadata = db.execute(select(CapabilityPromotionReceipt.source_id, CapabilityPromotionReceipt.installation_id,
        CapabilityPromotionReceipt.signed_attestation_snapshot)
        .where(CapabilityPromotionReceipt.id == receipt_id)).one_or_none()
    if metadata is None:
        raise LookupError("Capability promotion receipt not found")
    source = lock_promotion_source(db, source_id=metadata.source_id)
    existing = db.scalar(select(CapabilityPromotionPublication).where(CapabilityPromotionPublication.receipt_id == receipt_id)
        .execution_options(populate_existing=True))
    if existing is not None:
        db.commit()
        db.refresh(existing)
        return existing
    authority = lock_promotion_installation(db, policy=policy, source=source,
        installation_id=metadata.installation_id, writable_artifacts=True,
        signed=SignedCapabilityPromotionAttestation.model_validate(metadata.signed_attestation_snapshot))
    receipt = db.scalar(select(CapabilityPromotionReceipt).where(CapabilityPromotionReceipt.id == receipt_id)
        .with_for_update().execution_options(populate_existing=True))
    if receipt is None or receipt.source_id != source.id or receipt.installation_id != authority.installation.id:
        raise ValueError("Promotion receipt identity changed before publication")
    if receipt.signed_attestation_snapshot != metadata.signed_attestation_snapshot:
        raise ValueError("Promotion receipt witness proof changed before publication")
    installation = authority.installation
    preview, receipt, installation, policy = _evaluate_promotion_publication(
        db,
        receipt.id,
        actor=actor,
    )
    if preview.already_published and preview.existing_publication_id:
        publication = db.get(
            CapabilityPromotionPublication,
            preview.existing_publication_id,
        )
        if publication is None:
            raise RuntimeError("Capability publication decision is unavailable")
        db.commit()
        db.refresh(publication)
        return publication
    if not preview.eligible or policy is None:
        raise ValueError(
            "Promoted capability cannot be published: "
            + ", ".join(preview.blockers)
        )
    try:
        for version_id in preview.candidate_artifact_version_ids:
            version = db.get(ArtifactVersion, version_id)
            if version is None:
                raise RuntimeError("Promotion publication Artifact is unavailable")
            publish_artifact_version(
                db,
                version,
                actor,
                commit=False,
            )
        policy_snapshot = _publication_policy_snapshot(policy)
        policy_snapshot["source_witness_policy"] = source_witness_policy_snapshot(db)
        material = {
            "receipt_id": receipt.id,
            "statement_digest_sha256": receipt.statement_digest_sha256,
            "installation_id": installation.id,
            "pack_digest_sha256": installation.pack_digest_sha256,
            "artifact_version_ids": preview.artifact_version_ids,
            "newly_published_version_ids": (
                preview.candidate_artifact_version_ids
            ),
            "already_published_version_ids": (
                preview.already_published_version_ids
            ),
            "reused_version_ids": preview.reused_version_ids,
            "policy_snapshot": policy_snapshot,
        }
        publication = CapabilityPromotionPublication(
            receipt_id=receipt.id,
            installation_id=installation.id,
            publication_digest_sha256=_canonical_hash(material),
            artifact_count=len(preview.artifact_version_ids),
            newly_published_count=len(
                preview.candidate_artifact_version_ids
            ),
            artifact_version_ids=preview.artifact_version_ids,
            newly_published_version_ids=(
                preview.candidate_artifact_version_ids
            ),
            already_published_version_ids=(
                preview.already_published_version_ids
            ),
            reused_version_ids=preview.reused_version_ids,
            policy_snapshot=policy_snapshot,
            reason=payload.reason,
            published_by=actor,
        )
        db.add(publication)
        db.flush()
        append_capability_transparency_record(
            db,
            event_type="capability.pack.promotion_published",
            entity_type="capability_promotion_publication",
            entity_id=publication.id,
            subject_digest_sha256=publication.publication_digest_sha256,
            details={
                "receipt_id": receipt.id,
                "source_environment_id": receipt.source_environment_id,
                "target_environment_id": receipt.target_environment_id,
                "target_stage": receipt.target_stage,
                "pack_name": receipt.pack_name,
                "pack_version": receipt.pack_version,
                "pack_digest_sha256": receipt.pack_digest_sha256,
                "artifact_count": publication.artifact_count,
                "newly_published_count": publication.newly_published_count,
            },
        )
        record_audit_event(
            db,
            event_type="capability.pack.promotion_published",
            actor_type="user",
            actor_id=actor,
            entity_type="capability_promotion_publication",
            entity_id=publication.id,
            details={
                "receipt_id": receipt.id,
                "pack_digest_sha256": receipt.pack_digest_sha256,
                "publication_digest_sha256": (
                    publication.publication_digest_sha256
                ),
                "artifact_count": publication.artifact_count,
                "newly_published_count": publication.newly_published_count,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Capability promotion publication already exists"
        ) from exc
    except Exception:
        db.rollback()
        raise
    try:
        commit_with_promotion_authority(db, lambda: _check_promotion_commit(db, authority,
            SignedCapabilityPromotionAttestation.model_validate(receipt.signed_attestation_snapshot), receipt=receipt, publisher=actor))
    except DBAPIError:
        db.rollback()
        raise
    db.refresh(publication)
    return publication


def list_promotion_publications(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityPromotionPublication]:
    return list(
        db.scalars(
            select(CapabilityPromotionPublication)
            .order_by(CapabilityPromotionPublication.published_at.desc())
            .limit(limit)
        ).all()
    )
