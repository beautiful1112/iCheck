"""Namespace-local, transaction-held coordination for Artifact consumers."""
from collections.abc import Iterable
import json

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..database import require_locking_transaction, set_session_namespace
from ..models import Artifact, ArtifactVersion, CapabilityPackInstallation, CapabilityPackInstalledArtifact
from .trust_authority import lock_publisher_resource
from .trust_namespace import selected_trust_namespace


def prepare_artifact_mutation(db: Session, *, purpose: str) -> None:
    require_locking_transaction(db, purpose=purpose)
    set_session_namespace(db, *selected_trust_namespace(db))


def lock_artifact_identities(
    db: Session, *, writable: Iterable[tuple] = (), readable: Iterable[tuple] = (),
) -> None:
    """Sort the entire batch; reads share, while any write wins over a read."""
    prepare_artifact_mutation(db, purpose="Artifact lifecycle mutations")
    modes = {}
    for shared, identities in ((True, readable), (False, writable)):
        for kind, name in identities:
            identity = (getattr(kind, "value", kind), name)
            modes[identity] = modes.get(identity, True) and shared
    for identity, shared in sorted(modes.items()):
        lock_publisher_resource(db, "artifact-identity", json.dumps(identity, separators=(",", ":")), shared=shared)


def artifact_identities_for_versions(db: Session, version_ids: Iterable[str]) -> list[tuple]:
    tenant, region = selected_trust_namespace(db)
    return list(db.execute(select(Artifact.kind, Artifact.name).join(
        ArtifactVersion, ArtifactVersion.artifact_id == Artifact.id).where(
        ArtifactVersion.id.in_(list(version_ids)), Artifact.tenant_id == tenant,
        Artifact.region_id == region, ArtifactVersion.tenant_id == tenant,
        ArtifactVersion.region_id == region)).all())


def lock_artifact_version(db: Session, version_id: str) -> ArtifactVersion:
    prepare_artifact_mutation(db, purpose="Artifact lifecycle mutations")
    identities = artifact_identities_for_versions(db, [version_id])
    if not identities:
        raise LookupError("Artifact version not found in the selected namespace")
    lock_artifact_identities(db, writable=identities)
    version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == version_id)
        .options(selectinload(ArtifactVersion.artifact), selectinload(ArtifactVersion.collector_definition))
        .with_for_update().execution_options(populate_existing=True))
    if version is None:
        raise LookupError("Artifact version not found in the selected namespace")
    return version


def assert_version_retirement_allowed(db: Session, version_ids: Iterable[str]) -> None:
    """Do not retire exact versions still consumed by an active pack head."""
    identities = set(version_ids)
    if not identities:
        return
    heads = {}
    for installation in db.scalars(select(CapabilityPackInstallation).where(
        CapabilityPackInstallation.lifecycle_status == "installed").order_by(
        CapabilityPackInstallation.installed_at.desc(), CapabilityPackInstallation.id.desc())
        .execution_options(populate_existing=True)):
        heads.setdefault(installation.pack_name, installation)
    reused = set(db.scalars(select(CapabilityPackInstalledArtifact.installation_id).where(
        CapabilityPackInstalledArtifact.artifact_version_id.in_(identities),
        CapabilityPackInstalledArtifact.install_action == "reused")))
    if any(installation.id in reused or any(
        isinstance(item, dict) and item.get("artifact_version_id") in identities
        for item in installation.dependency_snapshot or []) for installation in heads.values()):
        raise ValueError("Published Artifact version has active pack consumers")
