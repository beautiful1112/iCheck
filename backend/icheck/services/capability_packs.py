from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..capability_pack_schemas import (
    PLATFORM_API,
    SIGNED_PACK_SIGNER_ROTATION_FORMAT,
    SIGNED_PACK_FORMAT,
    CapabilityPackArtifactPlan,
    CapabilityPackDependencyPlan,
    CapabilityPackInstallCreate,
    CapabilityPackInstallationRead,
    CapabilityPackPreviewCreate,
    CapabilityPackPreviewRead,
)
from ..collector_schemas import ArtifactImportCreate
from ..database import require_locking_transaction, set_session_namespace
from ..models import (
    Artifact,
    ArtifactTrustKey,
    ArtifactVersionStatus,
    CapabilityPackInstallation,
    CapabilityPackInstalledArtifact,
)
from .artifact_portability import (
    import_artifact_bundle,
    import_artifact_bundle_version,
    ensure_trust_key_usable,
    validate_artifact_export_bundle,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .capability_pack_revocations import active_pack_revocation, artifact_version_revocation
from .artifact_lifecycle import lock_artifact_identities
from .capability_transparency import append_capability_transparency_record
from .trust_authority import lock_publisher_resource, lock_trust_authorities
from .trust_namespace import selected_trust_namespace


PACK_MAX_BYTES = 25_000_000
PACK_ROTATION_CLOCK_SKEW = timedelta(minutes=5)
PACK_ROTATION_MAX_LIFETIME = timedelta(hours=24)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _pack_payload(pack: Any) -> dict[str, Any]:
    material = pack.model_dump(mode="json", exclude={"digest_sha256"})
    if material.get("predecessor_digest_sha256") is None:
        material.pop("predecessor_digest_sha256", None)
    if material.get("signer_rotation") is None:
        material.pop("signer_rotation", None)
    return material


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _pack_signer_rotation_snapshot(
    db: Session,
    payload: CapabilityPackPreviewCreate,
    predecessor: CapabilityPackInstallation,
    verification: dict[str, str],
) -> dict[str, str]:
    rotation = payload.signed_pack.pack.signer_rotation
    if rotation is None:
        raise ValueError("Capability pack signer rotation proof is missing")
    statement = rotation.statement
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != statement.digest_sha256:
        raise ValueError("Capability pack signer rotation digest does not match")
    pack = payload.signed_pack.pack
    if (
        statement.pack_name != pack.name
        or statement.predecessor_digest_sha256
        != predecessor.pack_digest_sha256
        or statement.current_key_fingerprint_sha256
        != predecessor.key_fingerprint_sha256
        or statement.next_key_fingerprint_sha256
        != verification["key_fingerprint_sha256"]
    ):
        raise ValueError("Capability pack signer rotation identity does not match")
    now = datetime.now(UTC)
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + PACK_ROTATION_CLOCK_SKEW:
        raise ValueError("Capability pack signer rotation is issued in the future")
    if expires_at <= now:
        raise ValueError("Capability pack signer rotation has expired")
    if expires_at - issued_at > PACK_ROTATION_MAX_LIFETIME:
        raise ValueError("Capability pack signer rotation exceeds 24 hours")
    current_verification = verify_trusted_digest_signature(
        db,
        rotation.current_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_PACK_SIGNER_ROTATION_FORMAT,
        expected_purpose="capability_pack",
    )
    next_verification = verify_trusted_digest_signature(
        db,
        rotation.next_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_PACK_SIGNER_ROTATION_FORMAT,
        expected_purpose="capability_pack",
    )
    if current_verification["trust_key_id"] != predecessor.trust_key_id:
        raise ValueError("Pack rotation lacks the predecessor-key signature")
    if next_verification["trust_key_id"] != verification["trust_key_id"]:
        raise ValueError("Pack rotation lacks the successor-key signature")
    return {
        "statement_digest_sha256": statement.digest_sha256,
        "from_trust_key_id": predecessor.trust_key_id,
        "to_trust_key_id": verification["trust_key_id"],
        "from_key_fingerprint_sha256": predecessor.key_fingerprint_sha256,
        "to_key_fingerprint_sha256": verification[
            "key_fingerprint_sha256"
        ],
        "current_signature_sha256": current_verification[
            "signature_sha256"
        ],
        "next_signature_sha256": next_verification["signature_sha256"],
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


def _semver_parts(
    version: str,
) -> tuple[tuple[int, int, int], list[str] | None]:
    match = re.fullmatch(
        r"([0-9]+)\.([0-9]+)\.([0-9]+)"
        r"(?:-([A-Za-z0-9.-]+))?(?:\+[A-Za-z0-9.-]+)?",
        version,
    )
    if match is None:
        raise ValueError("Capability pack version is not valid semantic versioning")
    core = tuple(int(match.group(index)) for index in range(1, 4))
    prerelease = match.group(4)
    return core, prerelease.split(".") if prerelease else None


def _semver_is_greater(candidate: str, current: str) -> bool:
    candidate_core, candidate_pre = _semver_parts(candidate)
    current_core, current_pre = _semver_parts(current)
    if candidate_core != current_core:
        return candidate_core > current_core
    if candidate_pre is None:
        return current_pre is not None
    if current_pre is None:
        return False
    for candidate_item, current_item in zip(
        candidate_pre,
        current_pre,
        strict=False,
    ):
        if candidate_item == current_item:
            continue
        candidate_numeric = candidate_item.isdigit()
        current_numeric = current_item.isdigit()
        if candidate_numeric and current_numeric:
            return int(candidate_item) > int(current_item)
        if candidate_numeric != current_numeric:
            return not candidate_numeric
        return candidate_item > current_item
    return len(candidate_pre) > len(current_pre)


def _latest_lineage_installation(
    db: Session,
    pack_name: str,
) -> CapabilityPackInstallation | None:
    order = (
        CapabilityPackInstallation.installed_at.desc(),
        CapabilityPackInstallation.id.desc(),
    )
    active = db.scalar(
        select(CapabilityPackInstallation)
        .where(
            CapabilityPackInstallation.pack_name == pack_name,
            CapabilityPackInstallation.lifecycle_status == "installed",
        )
        .order_by(*order)
        .limit(1)
        .execution_options(populate_existing=True)
    )
    if active is not None:
        return active
    return db.scalar(
        select(CapabilityPackInstallation)
        .where(CapabilityPackInstallation.pack_name == pack_name)
        .order_by(*order)
        .limit(1)
        .execution_options(populate_existing=True)
    )


def _lineage_plan(
    db: Session,
    payload: CapabilityPackPreviewCreate,
    verification: dict[str, str],
) -> tuple[str, CapabilityPackInstallation | None, list[str]]:
    pack = payload.signed_pack.pack
    installed = db.scalar(
        select(CapabilityPackInstallation).where(
            CapabilityPackInstallation.pack_digest_sha256 == pack.digest_sha256
        ).execution_options(populate_existing=True)
    )
    if installed is not None:
        predecessor = (
            db.get(
                CapabilityPackInstallation,
                installed.predecessor_installation_id,
            )
            if installed.predecessor_installation_id
            else None
        )
        blockers = (
            ["pack_previously_uninstalled"]
            if installed.lifecycle_status == "uninstalled"
            else []
        )
        return installed.operation, predecessor, blockers
    latest = _latest_lineage_installation(db, pack.name)
    if latest is None:
        blockers = (
            ["pack_predecessor_unknown"]
            if pack.predecessor_digest_sha256
            else []
        )
        return "install", None, blockers

    blockers: list[str] = []
    predecessor = None
    if not pack.predecessor_digest_sha256:
        blockers.append("pack_predecessor_required")
    else:
        predecessor = db.scalar(
            select(CapabilityPackInstallation).where(
                CapabilityPackInstallation.pack_digest_sha256
                == pack.predecessor_digest_sha256,
                CapabilityPackInstallation.pack_name == pack.name,
            ).execution_options(populate_existing=True)
        )
        if predecessor is None:
            blockers.append("pack_predecessor_unknown")
        elif predecessor.id != latest.id:
            blockers.append("pack_predecessor_not_latest")
    if not _semver_is_greater(pack.version, latest.pack_version):
        blockers.append("pack_version_not_newer")
    signer_changed = (
        verification["key_fingerprint_sha256"]
        != latest.key_fingerprint_sha256
    )
    if signer_changed:
        if pack.signer_rotation is None:
            blockers.append("pack_signer_changed")
        else:
            try:
                _pack_signer_rotation_snapshot(
                    db,
                    payload,
                    latest,
                    verification,
                )
            except ValueError:
                blockers.append("pack_signer_rotation_invalid")
    elif pack.signer_rotation is not None:
        blockers.append("pack_signer_rotation_unnecessary")
    return "upgrade", predecessor, blockers


def _verified_pack(
    db: Session,
    payload: CapabilityPackPreviewCreate,
) -> dict[str, str]:
    signed = payload.signed_pack
    pack = signed.pack
    material = _pack_payload(pack)
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) > PACK_MAX_BYTES:
        raise ValueError(f"Capability pack exceeds {PACK_MAX_BYTES} bytes")
    if _canonical_hash(material) != pack.digest_sha256:
        raise ValueError("Capability pack digest does not match its contents")
    for bundle in pack.artifacts:
        validate_artifact_export_bundle(bundle)
    return verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=pack.digest_sha256,
        signed_format_version=SIGNED_PACK_FORMAT,
        expected_purpose="capability_pack",
    )


def _artifact_by_identity(
    db: Session,
    *,
    kind: Any,
    name: str,
) -> Artifact | None:
    return db.scalar(
        select(Artifact)
        .where(Artifact.kind == kind, Artifact.name == name)
        .options(selectinload(Artifact.versions))
        .execution_options(populate_existing=True)
    )


def _artifact_plans(
    db: Session,
    payload: CapabilityPackPreviewCreate,
    *,
    predecessor: CapabilityPackInstallation | None,
    predecessor_is_latest: bool,
) -> list[CapabilityPackArtifactPlan]:
    owned_artifact_ids: set[str] = set()
    if predecessor is not None and predecessor_is_latest:
        owned_artifact_ids = set(
            db.scalars(
                select(CapabilityPackInstalledArtifact.artifact_id).where(
                    CapabilityPackInstalledArtifact.installation_id
                    == predecessor.id,
                    CapabilityPackInstalledArtifact.install_action.in_(
                        ["installed", "upgraded", "retained"]
                    ),
                )
            ).all()
        )
    result: list[CapabilityPackArtifactPlan] = []
    for bundle in payload.signed_pack.pack.artifacts:
        artifact = _artifact_by_identity(
            db,
            kind=bundle.artifact.kind,
            name=bundle.artifact.name,
        )
        matching = None
        unavailable = False
        if artifact is not None:
            matching = next(
                (
                    version
                    for version in reversed(artifact.versions)
                    if version.content_hash == bundle.source.content_hash
                    and version.status != ArtifactVersionStatus.DRAFT
                ),
                None,
            )
            if matching is not None:
                revoked = artifact_version_revocation(db, matching.id) is not None
                if revoked:
                    unavailable = True
                elif matching.status == ArtifactVersionStatus.DEPRECATED:
                    if artifact.id in owned_artifact_ids:
                        # A higher same-lineage release revalidates a new copy;
                        # it must not silently retain a retired candidate.
                        matching = None
                    else:
                        unavailable = True
        if unavailable:
            state = "unavailable"
        elif matching is not None and artifact.id in owned_artifact_ids:
            state = "retain"
        elif matching is not None:
            state = "already_present"
        elif artifact is not None and artifact.id in owned_artifact_ids:
            state = "upgrade"
        elif artifact is not None:
            state = "name_conflict"
        else:
            state = "install"
        result.append(
            CapabilityPackArtifactPlan(
                name=bundle.artifact.name,
                kind=bundle.artifact.kind,
                content_hash=bundle.source.content_hash,
                bundle_digest_sha256=bundle.digest_sha256,
                state=state,
                existing_artifact_id=artifact.id if artifact else None,
                existing_artifact_version_id=(
                    matching.id if matching is not None else None
                ),
            )
        )
    return result


def _dependency_plans(
    db: Session,
    payload: CapabilityPackPreviewCreate,
) -> list[CapabilityPackDependencyPlan]:
    pack = payload.signed_pack.pack
    embedded = {
        (
            bundle.artifact.kind,
            bundle.artifact.name,
            bundle.source.content_hash,
        )
        for bundle in pack.artifacts
    }
    result: list[CapabilityPackDependencyPlan] = []
    for dependency in pack.dependencies:
        key = (dependency.kind, dependency.name, dependency.content_hash)
        if key in embedded:
            result.append(
                CapabilityPackDependencyPlan(
                    **dependency.model_dump(),
                    state="pack",
                )
            )
            continue
        artifact = _artifact_by_identity(
            db,
            kind=dependency.kind,
            name=dependency.name,
        )
        if artifact is None:
            state = "missing"
            version = None
        else:
            exact = [
                version
                for version in artifact.versions
                if version.content_hash == dependency.content_hash
                and version.status != ArtifactVersionStatus.DRAFT
            ]
            published = next(
                (
                    version
                    for version in reversed(exact)
                    if version.status == ArtifactVersionStatus.PUBLISHED
                ),
                None,
            )
            if published is not None:
                state = "published"
                version = published
            elif exact:
                state = "not_published"
                version = exact[-1]
            else:
                state = "hash_mismatch"
                version = None
        result.append(
            CapabilityPackDependencyPlan(
                **dependency.model_dump(),
                state=state,
                artifact_version_id=version.id if version is not None else None,
            )
        )
    return result


def preview_capability_pack(
    db: Session,
    payload: CapabilityPackPreviewCreate,
) -> CapabilityPackPreviewRead:
    verification = _verified_pack(db, payload)
    pack = payload.signed_pack.pack
    operation, predecessor, lineage_blockers = _lineage_plan(
        db,
        payload,
        verification,
    )
    predecessor_is_latest = (
        predecessor is not None
        and "pack_predecessor_not_latest" not in lineage_blockers
        and "pack_predecessor_unknown" not in lineage_blockers
    )
    artifacts = _artifact_plans(
        db,
        payload,
        predecessor=predecessor,
        predecessor_is_latest=predecessor_is_latest,
    )
    dependencies = _dependency_plans(db, payload)
    blockers: list[str] = list(lineage_blockers)
    if pack.platform_api != PLATFORM_API:
        blockers.append("platform_api_incompatible")
    if active_pack_revocation(db, pack.digest_sha256) is not None:
        blockers.append("pack_revoked")
    if any(item.state == "name_conflict" for item in artifacts):
        blockers.append("artifact_name_conflict")
    if any(item.state == "unavailable" for item in artifacts):
        blockers.append("artifact_version_unavailable")
    dependency_blockers = {
        "missing": "dependency_missing",
        "hash_mismatch": "dependency_hash_mismatch",
        "not_published": "dependency_not_published",
    }
    for item in dependencies:
        blocker = dependency_blockers.get(item.state)
        if blocker:
            blockers.append(blocker)
    installed = db.scalar(
        select(CapabilityPackInstallation).where(
            CapabilityPackInstallation.pack_digest_sha256 == pack.digest_sha256
        )
    )
    version_installation = db.scalar(
        select(CapabilityPackInstallation).where(
            CapabilityPackInstallation.pack_name == pack.name,
            CapabilityPackInstallation.pack_version == pack.version,
        )
    )
    if (
        version_installation is not None
        and version_installation.pack_digest_sha256 != pack.digest_sha256
    ):
        blockers.append("pack_version_conflict")
    blockers = list(dict.fromkeys(blockers))
    return CapabilityPackPreviewRead(
        pack_name=pack.name,
        pack_version=pack.version,
        platform_api=pack.platform_api,
        pack_digest_sha256=pack.digest_sha256,
        key_fingerprint_sha256=verification["key_fingerprint_sha256"],
        operation=operation,
        predecessor_installation_id=(predecessor.id if predecessor else None),
        predecessor_digest_sha256=(
            predecessor.pack_digest_sha256 if predecessor else None
        ),
        signer_rotation=pack.signer_rotation is not None,
        artifact_count=len(artifacts),
        dependency_count=len(dependencies),
        installable=not blockers,
        already_installed=installed is not None,
        blockers=blockers,
        artifacts=artifacts,
        dependencies=dependencies,
    )


def _installation_query():
    return select(CapabilityPackInstallation).options(
        selectinload(CapabilityPackInstallation.artifacts)
    ).execution_options(populate_existing=True)


def get_capability_pack_installation(
    db: Session,
    installation_id: str,
) -> CapabilityPackInstallation:
    installation = db.scalar(
        _installation_query().where(
            CapabilityPackInstallation.id == installation_id
        )
    )
    if installation is None:
        raise LookupError("Capability pack installation not found")
    return installation


def list_capability_pack_installations(
    db: Session,
    *,
    limit: int,
) -> list[CapabilityPackInstallation]:
    return list(
        db.scalars(
            _installation_query()
            .order_by(CapabilityPackInstallation.installed_at.desc())
            .limit(limit)
        ).unique().all()
    )


def lock_pack_resources(db: Session, pack) -> None:
    lock_publisher_resource(db, "pack-lineage", pack.name)
    for digest in sorted({pack.digest_sha256, pack.predecessor_digest_sha256} - {None}):
        lock_publisher_resource(db, "pack-digest", digest)


def pack_trust_requirements(db: Session, signed) -> dict[str, set[str]]:
    tenant_id, region_id = selected_trust_namespace(db)
    signatures = [signed.signature]
    if signed.pack.signer_rotation is not None:
        signatures.extend([signed.pack.signer_rotation.current_signature, signed.pack.signer_rotation.next_signature])
    requirements = {}
    for signature in signatures:
        identity = db.scalar(select(ArtifactTrustKey.id).where(
            ArtifactTrustKey.tenant_id == tenant_id, ArtifactTrustKey.region_id == region_id,
            ArtifactTrustKey.fingerprint_sha256 == signature.key_fingerprint_sha256))
        if identity is None:
            raise ValueError("Artifact signing key is not trusted or has been revoked")
        requirements[identity] = {"capability_pack"}
    return requirements


def install_capability_pack(
    db: Session,
    payload: CapabilityPackInstallCreate,
    *,
    actor: str,
    distribution_channel: str = "upload",
    distribution_snapshot: dict[str, str | int] | None = None,
    before_commit_validation: Callable[[], None] | None = None,
) -> CapabilityPackInstallationRead:
    if distribution_channel not in {"upload", "remote_catalog"}:
        raise ValueError("Capability pack distribution channel is invalid")
    if distribution_channel == "remote_catalog" and before_commit_validation is None:
        raise ValueError("Remote catalog installation requires current distribution validation")
    require_locking_transaction(db, purpose="Capability pack installations")
    set_session_namespace(db, *selected_trust_namespace(db))
    pack = payload.signed_pack.pack
    lock_pack_resources(db, pack)
    authorities = lock_trust_authorities(db, pack_trust_requirements(db, payload.signed_pack))
    lock_artifact_identities(db,
        writable=[(item.artifact.kind, item.artifact.name) for item in pack.artifacts],
        readable=[(item.kind, item.name) for item in pack.dependencies])
    preview = preview_capability_pack(db, payload)
    existing = db.scalar(
        _installation_query().where(
            CapabilityPackInstallation.pack_digest_sha256 == pack.digest_sha256
        )
    )
    if existing is not None:
        if existing.lifecycle_status == "uninstalled":
            raise ValueError(
                "Capability pack is not installable: pack_previously_uninstalled"
            )
        if "pack_revoked" in preview.blockers:
            raise ValueError("Capability pack is not installable: pack_revoked")
        if before_commit_validation is not None:
            before_commit_validation()
        result = CapabilityPackInstallationRead.model_validate(existing)
        db.commit()
        return result
    if not preview.installable:
        raise ValueError(
            "Capability pack is not installable: " + ", ".join(preview.blockers)
        )
    verification = _verified_pack(db, payload)
    signer_rotation_snapshot: dict[str, str] = {}
    if pack.signer_rotation is not None:
        predecessor = (
            db.get(
                CapabilityPackInstallation,
                preview.predecessor_installation_id,
            )
            if preview.predecessor_installation_id
            else None
        )
        if predecessor is None:
            raise RuntimeError("Capability pack signer rotation lost predecessor")
        signer_rotation_snapshot = _pack_signer_rotation_snapshot(
            db,
            payload,
            predecessor,
            verification,
        )
    trusted_container = {
        "pack_name": pack.name,
        "pack_version": pack.version,
        "pack_digest_sha256": pack.digest_sha256,
        "key_fingerprint_sha256": verification["key_fingerprint_sha256"],
    }
    dependency_snapshot = [
        {
            "name": item.name,
            "kind": item.kind.value,
            "content_hash": item.content_hash,
            "state": item.state,
            **(
                {"artifact_version_id": item.artifact_version_id}
                if item.artifact_version_id
                else {}
            ),
        }
        for item in preview.dependencies
    ]
    installation = CapabilityPackInstallation(
        pack_name=pack.name,
        pack_version=pack.version,
        platform_api=pack.platform_api,
        pack_digest_sha256=pack.digest_sha256,
        trust_key_id=verification["trust_key_id"],
        key_fingerprint_sha256=verification["key_fingerprint_sha256"],
        signature_sha256=verification["signature_sha256"],
        operation=preview.operation,
        predecessor_installation_id=preview.predecessor_installation_id,
        dependency_snapshot=dependency_snapshot,
        distribution_channel=distribution_channel,
        distribution_snapshot=distribution_snapshot or {},
        signer_rotation_snapshot=signer_rotation_snapshot,
        reason=payload.reason,
        installed_by=actor,
    )
    try:
        if preview.predecessor_installation_id:
            locked_predecessor = db.scalar(
                select(CapabilityPackInstallation)
                .where(
                    CapabilityPackInstallation.id
                    == preview.predecessor_installation_id
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            latest = _latest_lineage_installation(db, pack.name)
            if locked_predecessor is None or latest is None or (
                latest.id != locked_predecessor.id
            ):
                raise RuntimeError("Capability pack lineage drifted before install")
        db.add(installation)
        db.flush()
        for bundle, plan in zip(pack.artifacts, preview.artifacts, strict=True):
            if plan.state in {"already_present", "retain"}:
                artifact = _artifact_by_identity(
                    db,
                    kind=bundle.artifact.kind,
                    name=bundle.artifact.name,
                )
                if artifact is None or plan.existing_artifact_version_id is None:
                    raise RuntimeError("Capability pack preview drifted before install")
                version = next(
                    (
                        item
                        for item in artifact.versions
                        if item.id == plan.existing_artifact_version_id
                    ),
                    None,
                )
                if version is None:
                    raise RuntimeError("Capability pack preview drifted before install")
                action = "retained" if plan.state == "retain" else "reused"
            elif plan.state == "install":
                artifact = import_artifact_bundle(
                    db,
                    ArtifactImportCreate(
                        bundle=bundle,
                        created_by=actor,
                    ),
                    actor=actor,
                    trusted_container=trusted_container,
                    commit=False,
                )
                version = artifact.versions[0]
                action = "installed"
            elif plan.state == "upgrade":
                artifact = _artifact_by_identity(
                    db,
                    kind=bundle.artifact.kind,
                    name=bundle.artifact.name,
                )
                if artifact is None or plan.existing_artifact_id != artifact.id:
                    raise RuntimeError("Capability pack preview drifted before install")
                version = import_artifact_bundle_version(
                    db,
                    artifact=artifact,
                    bundle=bundle,
                    actor=actor,
                    trusted_container=trusted_container,
                    commit=False,
                )
                action = "upgraded"
            else:
                raise RuntimeError("Capability pack preview drifted before install")
            db.add(
                CapabilityPackInstalledArtifact(
                    installation_id=installation.id,
                    artifact_id=artifact.id,
                    artifact_version_id=version.id,
                    source_name=bundle.artifact.name,
                    source_kind=bundle.artifact.kind.value,
                    source_content_hash=bundle.source.content_hash,
                    source_bundle_digest_sha256=bundle.digest_sha256,
                    install_action=action,
                )
            )
        db.flush()
        transparency_event_type = (
            "capability.pack.upgraded"
            if preview.operation == "upgrade"
            else "capability.pack.installed"
        )
        append_capability_transparency_record(
            db,
            event_type=transparency_event_type,
            entity_type="capability_pack_installation",
            entity_id=installation.id,
            subject_digest_sha256=pack.digest_sha256,
            details={
                "pack_name": pack.name,
                "pack_version": pack.version,
                "operation": preview.operation,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "artifact_count": len(pack.artifacts),
                "dependency_count": len(pack.dependencies),
                "distribution_channel": distribution_channel,
                "signer_rotation": bool(signer_rotation_snapshot),
            },
        )
        record_audit_event(
            db,
            event_type=transparency_event_type,
            actor_type="user",
            actor_id=actor,
            entity_type="capability_pack_installation",
            entity_id=installation.id,
            details={
                "pack_name": pack.name,
                "pack_version": pack.version,
                "pack_digest_sha256": pack.digest_sha256,
                "key_fingerprint_sha256": verification[
                    "key_fingerprint_sha256"
                ],
                "operation": preview.operation,
                "predecessor_installation_id": (
                    preview.predecessor_installation_id
                ),
                "artifact_count": len(pack.artifacts),
                "dependency_count": len(pack.dependencies),
                "distribution_channel": distribution_channel,
                "distribution_snapshot": distribution_snapshot or {},
                "signer_rotation_snapshot": signer_rotation_snapshot,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        # Locks stop revocation updates, not time passing during validation.
        for key in authorities.values():
            ensure_trust_key_usable(db, key, expected_purpose="capability_pack")
        if pack.signer_rotation is not None and _as_utc(pack.signer_rotation.statement.expires_at) <= datetime.now(UTC):
            raise ValueError("Capability pack signer rotation has expired")
        if before_commit_validation is not None:
            before_commit_validation()
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        # Exact contenders already serialize at the digest/lineage boundary.
        # An unrelated constraint conflict must not become unchecked success
        # after rollback releases all authority and lifecycle locks.
        raise ValueError(
            "Capability pack name/version or Artifact identity already exists"
        ) from exc
    except Exception:
        db.rollback()
        raise
    # A response-path exception after a successful commit is not a rollback.
    # Preserve it for an exact retry rather than masking it with Session state.
    try:
        db.commit()
    except DBAPIError:
        db.rollback()
        raise
    installed = get_capability_pack_installation(db, installation.id)
    return CapabilityPackInstallationRead.model_validate(installed)
