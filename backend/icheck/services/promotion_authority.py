"""Retained promotion configuration, signer and Artifact transaction authority."""
from dataclasses import dataclass
from functools import wraps

from sqlalchemy import event, select
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session, selectinload

from ..models import ArtifactTrustKey, ArtifactVersion, CapabilityPackInstallation, CapabilityPromotionPolicy, CapabilityPromotionSource
from .artifact_lifecycle import artifact_identities_for_versions, lock_artifact_identities, prepare_artifact_mutation
from .trust_authority import lock_publisher_resource, lock_trust_authorities
from .trust_namespace import selected_trust_namespace


def promotion_mutation(operation):
    """All failure paths release authority; unknown commits are not successes."""
    @wraps(operation)
    def guarded(db, *args, **kwargs):
        try:
            prepare_artifact_mutation(db, purpose="Promotion authority mutations")
            return operation(db, *args, **kwargs)
        except Exception:
            try:
                db.rollback()
            except InvalidRequestError:
                # An after-commit transport/hook failure may leave SQLAlchemy
                # in committed state. Reset the Session, not the durable result.
                db.close()
            raise
    return guarded


def commit_with_promotion_authority(db: Session, check):
    """Recheck after flush and any earlier before-commit wait/hook."""
    def before_commit(subject):
        subject.flush()
        check()
    event.listen(db, "before_commit", before_commit)
    try:
        db.commit()
    finally:
        event.remove(db, "before_commit", before_commit)


def lock_promotion_policy(db: Session, *, writable=False):
    prepare_artifact_mutation(db, purpose="Promotion authority mutations")
    # Protect absent-row configuration too. Readers do not serialize unrelated
    # pack/source decisions behind a namespace-wide exclusive policy lock.
    lock_publisher_resource(db, "promotion-policy", "global", shared=not writable)
    return db.scalars(promotion_policy_query(db).with_for_update(read=not writable)
        .execution_options(populate_existing=True)).one_or_none()


def promotion_policy_query(db):
    # Preserve legacy IDs and audit references. The namespace, not a global
    # primary key, owns the singleton; the schema enforces exactly one row.
    tenant_id, region_id = selected_trust_namespace(db)
    return select(CapabilityPromotionPolicy).where(CapabilityPromotionPolicy.tenant_id == tenant_id,
        CapabilityPromotionPolicy.region_id == region_id)


def lock_promotion_source(db: Session, *, source_id=None, environment_id=None, writable=False):
    prepare_artifact_mutation(db, purpose="Promotion authority mutations")
    if source_id:
        environment_id = db.scalar(select(CapabilityPromotionSource.environment_id).where(CapabilityPromotionSource.id == source_id))
        if environment_id is None:
            raise LookupError("Promotion source not found in the selected namespace")
    lock_publisher_resource(db, "promotion-source", environment_id, shared=not writable)
    source = db.scalar(select(CapabilityPromotionSource).where(CapabilityPromotionSource.environment_id == environment_id)
        .with_for_update(read=not writable).execution_options(populate_existing=True))
    if source_id and (source is None or source.id != source_id):
        raise ValueError("Promotion source identity changed before admission")
    return source


@dataclass
class PromotionAuthority:
    policy: CapabilityPromotionPolicy | None
    source: CapabilityPromotionSource | None
    installation: CapabilityPackInstallation
    requirements: dict[str, set[str]]
    keys: dict[str, ArtifactTrustKey]
    versions: list[ArtifactVersion]
    witnesses: dict
    source_witness_policy: object
    source_checkpoint_binding: object

    def check_trust(self, db):
        from .artifact_portability import ensure_trust_key_usable
        for identity, purposes in self.requirements.items():
            for purpose in purposes:
                ensure_trust_key_usable(db, self.keys[identity], expected_purpose=purpose)


def lock_promotion_installation(db: Session, *, policy, source=None, installation_id=None,
    pack_digest=None, writable_artifacts=False, signed=None) -> PromotionAuthority:
    metadata = db.execute(select(CapabilityPackInstallation.id, CapabilityPackInstallation.pack_name,
        CapabilityPackInstallation.pack_digest_sha256, CapabilityPackInstallation.trust_key_id).where(
        CapabilityPackInstallation.id == installation_id if installation_id
        else CapabilityPackInstallation.pack_digest_sha256 == pack_digest)).one_or_none()
    if metadata is None:
        raise LookupError("Capability pack installation not found in the selected namespace")
    # Match pack admission/removal: lineage/digest precede sorted domains/keys,
    # and the complete Artifact batch precedes any Artifact version row lock.
    lock_publisher_resource(db, "pack-lineage", metadata.pack_name)
    lock_publisher_resource(db, "pack-digest", metadata.pack_digest_sha256)
    requirements = {metadata.trust_key_id: {"capability_pack"}}
    if source:
        requirements.setdefault(source.trust_key_id, set()).add("environment_promotion")
    from .promotion_witnesses import lock_source_witnesses, lock_source_checkpoint_context
    witness_policy, checkpoint_binding = lock_source_checkpoint_context(db, source) if signed else (None, None)
    witnesses = lock_source_witnesses(db, signed)
    for witness in witnesses.values():
        requirements.setdefault(witness.trust_key_id, set()).add("transparency_witness")
    keys = lock_trust_authorities(db, requirements)
    installation = db.scalar(select(CapabilityPackInstallation).where(CapabilityPackInstallation.id == metadata.id)
        .options(selectinload(CapabilityPackInstallation.artifacts)).with_for_update()
        .execution_options(populate_existing=True))
    if installation is None or installation.trust_key_id != metadata.trust_key_id:
        raise ValueError("Promotion pack signer or installation changed before admission")
    candidates = [item.artifact_version_id for item in installation.artifacts]
    dependencies = [item["artifact_version_id"] for item in installation.dependency_snapshot or []
        if isinstance(item, dict) and item.get("artifact_version_id")]
    candidate_identities = artifact_identities_for_versions(db, candidates)
    dependency_identities = artifact_identities_for_versions(db, dependencies)
    lock_artifact_identities(db,
        writable=candidate_identities if writable_artifacts else (),
        readable=dependency_identities + ([] if writable_artifacts else candidate_identities))
    versions = list(db.scalars(select(ArtifactVersion).where(ArtifactVersion.id.in_(candidates))
        .order_by(ArtifactVersion.id).with_for_update(read=not writable_artifacts)
        .execution_options(populate_existing=True)))
    dependency_versions = list(db.scalars(select(ArtifactVersion).where(ArtifactVersion.id.in_(dependencies))
        .order_by(ArtifactVersion.id).with_for_update(read=True).execution_options(populate_existing=True)))
    if len(versions) != len(set(candidates)) or len(dependency_versions) != len(set(dependencies)):
        raise ValueError("Promotion Artifact or dependency state disappeared")
    return PromotionAuthority(policy, source, installation, requirements, keys, versions + dependency_versions,
        witnesses, witness_policy, checkpoint_binding)
