from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import (
    ArtifactBundleSignature,
    ArtifactCreate,
    ArtifactExportBundle,
    ArtifactImportCreate,
    ArtifactRestoreCreate,
    ArtifactSemanticChange,
    ArtifactVersionCreate,
    ArtifactVersionDiffRead,
    ArtifactSignedImportCreate,
    ArtifactTrustKeyCreate,
)
from ..config import get_settings
from ..models import (
    Artifact,
    ArtifactSignatureVerification,
    ArtifactTrustKey,
    ArtifactVersion,
    ArtifactVersionStatus,
    OrganizationTrustDomain,
    utcnow,
)
from .audit import record_audit_event
from .trust_namespace import assert_selected_trust_namespace, selected_trust_namespace
from .collectors import (
    artifact_content_hash,
    artifact_version_content_material,
    create_artifact,
    create_artifact_version,
    get_artifact,
    validate_artifact_version,
)


BUNDLE_FORMAT = "icheck.artifact.bundle/v1"
SIGNED_BUNDLE_FORMAT = "icheck.artifact.signed-bundle/v1"
BUNDLE_MAX_BYTES = 5_000_000
MAX_DIFF_DEPTH = 30
MAX_DIFF_VALUE_BYTES = 2048


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def get_artifact_version(
    db: Session,
    version_id: str,
) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("Artifact version not found")
    return version


def _version_by_number(
    db: Session,
    artifact_id: str,
    version_number: int,
) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(
            ArtifactVersion.artifact_id == artifact_id,
            ArtifactVersion.version == version_number,
        )
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError(
            f"Artifact version {version_number} was not found"
        )
    return version


def export_artifact_bundle(version: ArtifactVersion) -> ArtifactExportBundle:
    if version.status == ArtifactVersionStatus.DRAFT or not version.content_hash:
        raise ValueError("Only validated Artifact versions can be exported")
    collector_definition = None
    if version.collector_definition is not None:
        collector_definition = {
            "adapter_type": version.collector_definition.adapter_type,
            "mode": version.collector_definition.mode.value,
            "output_kinds": version.collector_definition.output_kinds,
            "credential_profile_ref": (
                version.collector_definition.credential_profile_ref
            ),
            "config_schema": version.collector_definition.config_schema,
            "target_schema": version.collector_definition.target_schema,
            "defaults": version.collector_definition.defaults,
        }
    payload = {
        "format_version": BUNDLE_FORMAT,
        "artifact": {
            "name": version.artifact.name,
            "kind": version.artifact.kind.value,
            "description": version.artifact.description,
            "labels": version.artifact.labels,
        },
        "version": {
            "definition": version.definition,
            "implementation": version.implementation,
            "tests": version.tests,
            "collector_definition": collector_definition,
        },
        "source": {
            "artifact_id": version.artifact_id,
            "version_id": version.id,
            "version": version.version,
            "content_hash": version.content_hash,
        },
    }
    if len(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ) > BUNDLE_MAX_BYTES:
        raise ValueError(f"Artifact bundle exceeds {BUNDLE_MAX_BYTES} bytes")
    return ArtifactExportBundle.model_validate(
        {**payload, "digest_sha256": _hash(payload)}
    )


def _bundle_payload(bundle: ArtifactExportBundle) -> dict[str, Any]:
    return bundle.model_dump(mode="json", exclude={"digest_sha256"})


def artifact_signature_message(digest_sha256: str) -> bytes:
    return trusted_digest_signature_message(SIGNED_BUNDLE_FORMAT, digest_sha256)


def trusted_digest_signature_message(
    format_version: str,
    digest_sha256: str,
) -> bytes:
    if len(digest_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in digest_sha256
    ):
        raise ValueError("Signed content digest is invalid")
    return f"{format_version}\n{digest_sha256}".encode("ascii")


def validate_artifact_export_bundle(bundle: ArtifactExportBundle) -> None:
    bundle_payload = _bundle_payload(bundle)
    if len(
        json.dumps(
            bundle_payload,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ) > BUNDLE_MAX_BYTES:
        raise ValueError(f"Artifact bundle exceeds {BUNDLE_MAX_BYTES} bytes")
    if _hash(bundle_payload) != bundle.digest_sha256:
        raise ValueError("Artifact bundle digest does not match its contents")
    calculated_content_hash = artifact_content_hash(
        kind=bundle.artifact.kind,
        definition=bundle.version.definition,
        implementation=bundle.version.implementation,
        tests=bundle.version.tests,
        collector_definition=bundle.version.collector_definition,
    )
    if calculated_content_hash != bundle.source.content_hash:
        raise ValueError("Artifact bundle content hash does not match its version")


def verify_trusted_digest_signature(
    db: Session,
    signature: ArtifactBundleSignature,
    *,
    expected_digest_sha256: str,
    signed_format_version: str,
    expected_purpose: str,
) -> dict[str, str]:
    if signature.signed_digest_sha256 != expected_digest_sha256:
        raise ValueError("Signed digest does not match the declared content")
    tenant_id, region_id = selected_trust_namespace(db)
    key = db.scalar(
        select(ArtifactTrustKey).where(
            ArtifactTrustKey.tenant_id == tenant_id,
            ArtifactTrustKey.region_id == region_id,
            ArtifactTrustKey.fingerprint_sha256
            == signature.key_fingerprint_sha256,
            ArtifactTrustKey.enabled.is_(True),
        )
    )
    if key is None:
        raise ValueError("Artifact signing key is not trusted or has been revoked")
    ensure_trust_key_usable(
        db,
        key,
        expected_purpose=expected_purpose,
    )
    try:
        signature_bytes = base64.b64decode(
            signature.signature_base64,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Artifact signature is not valid base64") from exc
    if len(signature_bytes) != 64:
        raise ValueError("Artifact Ed25519 signature has an invalid length")
    public_key = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Trusted Artifact key has an invalid algorithm")
    try:
        public_key.verify(
            signature_bytes,
            trusted_digest_signature_message(
                signed_format_version,
                expected_digest_sha256,
            ),
        )
    except InvalidSignature as exc:
        raise ValueError("Artifact signature verification failed") from exc
    return {
        "trust_key_id": key.id,
        "algorithm": "ed25519",
        "key_fingerprint_sha256": key.fingerprint_sha256,
        "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def ensure_trust_key_usable(
    db: Session,
    key: ArtifactTrustKey,
    *,
    expected_purpose: str,
) -> None:
    assert_selected_trust_namespace(db, key)
    if not key.enabled:
        raise ValueError("Artifact signing key is not trusted or has been revoked")
    if expected_purpose not in (key.purposes or []):
        raise ValueError(
            f"Artifact signing key is not authorized for {expected_purpose}"
        )
    now = utcnow()
    if key.valid_from is not None and _as_utc(key.valid_from) > now:
        raise ValueError("Artifact signing key is not valid yet")
    if key.expires_at is not None and _as_utc(key.expires_at) <= now:
        raise ValueError("Artifact signing key has expired")
    if key.trust_source == "trust_bundle":
        if key.trust_domain_id is None:
            raise ValueError("Distributed trust key has no trust domain")
        domain = db.get(OrganizationTrustDomain, key.trust_domain_id)
        if domain is None or not domain.enabled:
            raise ValueError("Distributed trust key domain is disabled")
        assert_selected_trust_namespace(db, domain)
        if key.managed_bundle_sequence != domain.latest_sequence:
            raise ValueError("Distributed trust key is stale")
    elif key.trust_source != "local":
        raise ValueError("Artifact signing key has an unknown trust source")


def register_artifact_trust_key(
    db: Session,
    payload: ArtifactTrustKeyCreate,
    *,
    actor: str,
) -> ArtifactTrustKey:
    tenant_id, region_id = selected_trust_namespace(db)
    now = utcnow()
    if payload.valid_from is not None and _as_utc(payload.valid_from) > now:
        raise ValueError("Local trust key is not valid yet")
    if payload.expires_at is not None and _as_utc(payload.expires_at) <= now:
        raise ValueError("Local trust key has already expired")
    try:
        public_key = serialization.load_pem_public_key(
            payload.public_key_pem.encode("ascii")
        )
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise ValueError("Artifact trust key is not valid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Artifact trust keys must use Ed25519")
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    canonical_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    key = ArtifactTrustKey(
        tenant_id=tenant_id,
        region_id=region_id,
        name=payload.name,
        algorithm="ed25519",
        public_key_pem=canonical_pem,
        fingerprint_sha256=hashlib.sha256(raw_key).hexdigest(),
        enabled=True,
        purposes=list(payload.purposes),
        trust_source="local",
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
        created_by=actor,
    )
    db.add(key)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="artifact.trust_key.registered",
            actor_type="user",
            actor_id=actor,
            entity_type="artifact_trust_key",
            entity_id=key.id,
            details={
                "name": key.name,
                "algorithm": key.algorithm,
                "fingerprint_sha256": key.fingerprint_sha256,
                "purposes": key.purposes,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Artifact trust key name or fingerprint already exists") from exc
    db.refresh(key)
    return key


def revoke_artifact_trust_key(
    db: Session,
    key: ArtifactTrustKey,
    *,
    actor: str,
) -> ArtifactTrustKey:
    from .artifact_lifecycle import prepare_artifact_mutation
    prepare_artifact_mutation(db, purpose="Publisher key revocation")
    assert_selected_trust_namespace(db, key)
    key = db.scalar(select(ArtifactTrustKey).where(ArtifactTrustKey.id == key.id)
        .with_for_update().execution_options(populate_existing=True))
    if key is None:
        raise ValueError("Artifact signing key is unavailable in the selected namespace")
    if not key.enabled:
        db.commit()
        return key
    key.enabled = False
    key.revoked_at = utcnow()
    key.revoked_by = actor
    record_audit_event(
        db,
        event_type="artifact.trust_key.revoked",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_trust_key",
        entity_id=key.id,
        details={"fingerprint_sha256": key.fingerprint_sha256},
    )
    db.commit()
    db.refresh(key)
    return key


def _verify_signed_bundle(
    db: Session,
    payload: ArtifactSignedImportCreate,
) -> dict[str, str]:
    envelope = payload.signed_bundle
    signature = envelope.signature
    bundle = envelope.bundle
    verification = verify_trusted_digest_signature(
        db,
        signature,
        expected_digest_sha256=bundle.digest_sha256,
        signed_format_version=SIGNED_BUNDLE_FORMAT,
        expected_purpose="artifact_bundle",
    )
    return {
        **verification,
        "bundle_digest_sha256": bundle.digest_sha256,
    }


def import_artifact_bundle(
    db: Session,
    payload: ArtifactImportCreate,
    *,
    actor: str,
    signature_verification: dict[str, str] | None = None,
    trusted_container: dict[str, str] | None = None,
    commit: bool = True,
) -> Artifact:
    if (
        get_settings().artifact_signature_policy == "required"
        and signature_verification is None
        and trusted_container is None
    ):
        raise ValueError("Artifact import requires a trusted signed bundle")
    bundle = payload.bundle
    validate_artifact_export_bundle(bundle)
    name = payload.name_override or bundle.artifact.name
    labels = {
        **bundle.artifact.labels,
        "imported": True,
        "source_content_hash": bundle.source.content_hash,
    }
    if signature_verification is not None:
        labels.update(
            {
                "signature_verified": True,
                "signing_key_fingerprint": signature_verification[
                    "key_fingerprint_sha256"
                ],
                "signed_bundle_digest": signature_verification[
                    "bundle_digest_sha256"
                ],
            }
        )
    if trusted_container is not None:
        labels.update(
            {
                "pack_signature_verified": True,
                "pack_name": trusted_container["pack_name"],
                "pack_version": trusted_container["pack_version"],
                "pack_digest": trusted_container["pack_digest_sha256"],
                "signing_key_fingerprint": trusted_container[
                    "key_fingerprint_sha256"
                ],
            }
        )
    artifact_payload = ArtifactCreate(
        name=name,
        kind=bundle.artifact.kind,
        description=bundle.artifact.description,
        owner=actor,
        labels=labels,
        initial_version=ArtifactVersionCreate(
            definition=bundle.version.definition,
            implementation=bundle.version.implementation,
            tests=bundle.version.tests,
            collector_definition=bundle.version.collector_definition,
            created_by=actor,
        ),
    )
    artifact = create_artifact(db, artifact_payload, commit=False)
    version = artifact.versions[0]
    version = validate_artifact_version(db, version, actor, commit=False)
    if version.content_hash != bundle.source.content_hash:
        raise RuntimeError("Imported Artifact changed during deterministic validation")
    if signature_verification is not None:
        db.add(
            ArtifactSignatureVerification(
                artifact_version_id=version.id,
                verified_by=actor,
                **signature_verification,
            )
        )
    record_audit_event(
        db,
        event_type="artifact.imported",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact",
        entity_id=artifact.id,
        details={
            "source_artifact_id": bundle.source.artifact_id,
            "source_version_id": bundle.source.version_id,
            "source_version": bundle.source.version,
            "content_hash": bundle.source.content_hash,
            "bundle_digest": bundle.digest_sha256,
            "signature_verification": signature_verification,
            "trusted_container": trusted_container,
        },
    )
    if commit:
        db.commit()
    else:
        db.flush()
    return get_artifact(db, artifact.id)


def import_artifact_bundle_version(
    db: Session,
    *,
    artifact: Artifact,
    bundle: ArtifactExportBundle,
    actor: str,
    trusted_container: dict[str, str],
    commit: bool = True,
) -> ArtifactVersion:
    if (
        get_settings().artifact_signature_policy == "required"
        and not trusted_container
    ):
        raise ValueError("Artifact import requires a trusted signed bundle")
    validate_artifact_export_bundle(bundle)
    if (
        artifact.name != bundle.artifact.name
        or artifact.kind != bundle.artifact.kind
    ):
        raise ValueError("Artifact upgrade identity does not match its target")
    artifact = create_artifact_version(
        db,
        artifact,
        ArtifactVersionCreate(
            definition=bundle.version.definition,
            implementation=bundle.version.implementation,
            tests=bundle.version.tests,
            collector_definition=bundle.version.collector_definition,
            created_by=actor,
        ),
        commit=False,
    )
    version = max(artifact.versions, key=lambda item: item.version)
    version = validate_artifact_version(db, version, actor, commit=False)
    if version.content_hash != bundle.source.content_hash:
        raise RuntimeError("Imported Artifact changed during deterministic validation")
    record_audit_event(
        db,
        event_type="artifact.version.imported",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=version.id,
        details={
            "artifact_id": artifact.id,
            "source_artifact_id": bundle.source.artifact_id,
            "source_version_id": bundle.source.version_id,
            "source_content_hash": bundle.source.content_hash,
            "bundle_digest_sha256": bundle.digest_sha256,
            "pack_name": trusted_container["pack_name"],
            "pack_version": trusted_container["pack_version"],
            "pack_digest_sha256": trusted_container["pack_digest_sha256"],
            "key_fingerprint_sha256": trusted_container[
                "key_fingerprint_sha256"
            ],
        },
    )
    if commit:
        db.commit()
        db.refresh(version)
    else:
        db.flush()
    return version


def import_signed_artifact_bundle(
    db: Session,
    payload: ArtifactSignedImportCreate,
    *,
    actor: str,
) -> Artifact:
    verification = _verify_signed_bundle(db, payload)
    return import_artifact_bundle(
        db,
        ArtifactImportCreate(
            bundle=payload.signed_bundle.bundle,
            name_override=payload.name_override,
            created_by=actor,
        ),
        actor=actor,
        signature_verification=verification,
    )


def create_restore_candidate(
    db: Session,
    artifact_id: str,
    payload: ArtifactRestoreCreate,
    *,
    actor: str,
    commit: bool = True,
) -> ArtifactVersion:
    artifact = get_artifact(db, artifact_id)
    source = _version_by_number(db, artifact_id, payload.source_version)
    if source.status == ArtifactVersionStatus.DRAFT or not source.content_hash:
        raise ValueError("Only a validated Artifact version can be restored")
    collector_definition = None
    if source.collector_definition is not None:
        collector_definition = {
            "adapter_type": source.collector_definition.adapter_type,
            "mode": source.collector_definition.mode.value,
            "output_kinds": source.collector_definition.output_kinds,
            "credential_profile_ref": (
                source.collector_definition.credential_profile_ref
            ),
            "config_schema": source.collector_definition.config_schema,
            "target_schema": source.collector_definition.target_schema,
            "defaults": source.collector_definition.defaults,
        }
    artifact = create_artifact_version(
        db,
        artifact,
        ArtifactVersionCreate.model_validate(
            {
                "definition": source.definition,
                "implementation": source.implementation,
                "tests": source.tests,
                "collector_definition": collector_definition,
                "created_by": actor,
            }
        ),
        commit=commit,
    )
    candidate = artifact.versions[-1]
    candidate = validate_artifact_version(db, candidate, actor, commit=commit)
    if candidate.content_hash != source.content_hash:
        raise RuntimeError("Restore candidate does not match its source version")
    record_audit_event(
        db,
        event_type="artifact.restore_candidate.created",
        actor_type="user",
        actor_id=actor,
        entity_type="artifact_version",
        entity_id=candidate.id,
        details={
            "artifact_id": artifact_id,
            "source_version_id": source.id,
            "source_version": source.version,
            "candidate_version": candidate.version,
            "content_hash": candidate.content_hash,
            "reason": payload.reason,
        },
    )
    if commit:
        db.commit()
        db.refresh(candidate)
    else:
        db.flush()
    return candidate


def _summary(value: Any) -> Any:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded) <= MAX_DIFF_VALUE_BYTES:
        return value
    return {
        "summary": "value omitted from bounded diff",
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "type": type(value).__name__,
    }


def _list_identity(value: list[Any]) -> str | None:
    if not value or not all(isinstance(item, dict) for item in value):
        return None
    for key in ("node_id", "name", "tool_name", "destination_field"):
        identifiers = [item.get(key) for item in value]
        if all(isinstance(item, str) and item for item in identifiers):
            if len(identifiers) == len(set(identifiers)):
                return key
    return None


def _semantic_changes(
    before: Any,
    after: Any,
    *,
    path: str,
    changes: list[ArtifactSemanticChange],
    limit: int,
    depth: int,
) -> bool:
    if len(changes) >= limit:
        return True
    if before == after:
        return False
    if depth >= MAX_DIFF_DEPTH:
        changes.append(
            ArtifactSemanticChange(
                path=path,
                change_type="changed",
                before=_summary(before),
                after=_summary(after),
            )
        )
        return False
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            child_path = f"{path}/{key}"
            if key not in before:
                changes.append(
                    ArtifactSemanticChange(
                        path=child_path,
                        change_type="added",
                        after=_summary(after[key]),
                    )
                )
            elif key not in after:
                changes.append(
                    ArtifactSemanticChange(
                        path=child_path,
                        change_type="removed",
                        before=_summary(before[key]),
                    )
                )
            else:
                truncated = _semantic_changes(
                    before[key],
                    after[key],
                    path=child_path,
                    changes=changes,
                    limit=limit,
                    depth=depth + 1,
                )
                if truncated:
                    return True
            if len(changes) >= limit:
                return True
        return False
    if isinstance(before, list) and isinstance(after, list):
        identity = _list_identity(before) or _list_identity(after)
        if identity and all(
            isinstance(item, dict) and isinstance(item.get(identity), str)
            for item in [*before, *after]
        ):
            before_map = {item[identity]: item for item in before}
            after_map = {item[identity]: item for item in after}
            return _semantic_changes(
                before_map,
                after_map,
                path=f"{path}[by={identity}]",
                changes=changes,
                limit=limit,
                depth=depth + 1,
            )
        for index in range(max(len(before), len(after))):
            child_path = f"{path}/{index}"
            if index >= len(before):
                changes.append(
                    ArtifactSemanticChange(
                        path=child_path,
                        change_type="added",
                        after=_summary(after[index]),
                    )
                )
            elif index >= len(after):
                changes.append(
                    ArtifactSemanticChange(
                        path=child_path,
                        change_type="removed",
                        before=_summary(before[index]),
                    )
                )
            else:
                truncated = _semantic_changes(
                    before[index],
                    after[index],
                    path=child_path,
                    changes=changes,
                    limit=limit,
                    depth=depth + 1,
                )
                if truncated:
                    return True
            if len(changes) >= limit:
                return True
        return False
    changes.append(
        ArtifactSemanticChange(
            path=path,
            change_type="changed",
            before=_summary(before),
            after=_summary(after),
        )
    )
    return False


def diff_artifact_versions(
    db: Session,
    artifact_id: str,
    *,
    from_version: int,
    to_version: int,
    limit: int,
) -> ArtifactVersionDiffRead:
    _ = db.get(Artifact, artifact_id)
    if _ is None:
        raise LookupError("Artifact not found")
    before = _version_by_number(db, artifact_id, from_version)
    after = _version_by_number(db, artifact_id, to_version)
    changes: list[ArtifactSemanticChange] = []
    truncated = _semantic_changes(
        artifact_version_content_material(before),
        artifact_version_content_material(after),
        path="$",
        changes=changes,
        limit=limit + 1,
        depth=0,
    )
    truncated = truncated or len(changes) > limit
    changes = changes[:limit]
    return ArtifactVersionDiffRead(
        artifact_id=artifact_id,
        from_version=from_version,
        to_version=to_version,
        from_content_hash=before.content_hash,
        to_content_hash=after.content_hash,
        change_count=len(changes),
        truncated=truncated,
        changes=changes,
    )
