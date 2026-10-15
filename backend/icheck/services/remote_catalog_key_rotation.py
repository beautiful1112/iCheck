from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import require_locking_transaction, set_session_namespace
from ..models import (
    ArtifactTrustKey,
    RemoteCapabilityCatalogKeyRotation,
    RemoteCapabilityCatalogSource,
    utcnow,
)
from ..remote_catalog_schemas import (
    SIGNED_REMOTE_CATALOG_KEY_ROTATION_FORMAT,
    RemoteCatalogKeyRotationCreate,
)
from .artifact_portability import verify_trusted_digest_signature
from .audit import record_audit_event
from .capability_transparency import append_capability_transparency_record
from .remote_capability_catalogs import get_remote_catalog_source
from .trust_authority import assert_rotation_replay, lock_trust_keys
from .trust_namespace import selected_trust_namespace


ROTATION_CLOCK_SKEW = timedelta(minutes=5)
ROTATION_MAX_LIFETIME = timedelta(hours=24)


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


def list_remote_catalog_key_rotations(
    db: Session,
    *,
    source_id: str | None,
    limit: int,
) -> list[RemoteCapabilityCatalogKeyRotation]:
    query = select(RemoteCapabilityCatalogKeyRotation)
    if source_id:
        query = query.where(
            RemoteCapabilityCatalogKeyRotation.source_id == source_id
        )
    return list(
        db.scalars(
            query.order_by(
                RemoteCapabilityCatalogKeyRotation.rotated_at.desc()
            ).limit(limit)
        ).all()
    )


def rotate_remote_catalog_key(
    db: Session,
    source_id: str,
    payload: RemoteCatalogKeyRotationCreate,
    *,
    actor: str,
) -> RemoteCapabilityCatalogSource:
    require_locking_transaction(db, purpose="Catalog rotations")
    set_session_namespace(db, *selected_trust_namespace(db))
    get_remote_catalog_source(db, source_id)
    source = db.scalar(select(RemoteCapabilityCatalogSource).where(
        RemoteCapabilityCatalogSource.id == source_id,
    ).with_for_update().execution_options(populate_existing=True))
    if source is None:
        raise LookupError("Remote capability catalog source not found")
    if not source.enabled:
        raise ValueError("Remote capability catalog source is disabled")
    signed = payload.signed_rotation
    statement = signed.statement
    material = statement.model_dump(mode="json", exclude={"digest_sha256"})
    if _canonical_hash(material) != statement.digest_sha256:
        raise ValueError("Remote catalog key rotation digest does not match")
    accepted = db.scalar(select(RemoteCapabilityCatalogKeyRotation).where(
        RemoteCapabilityCatalogKeyRotation.source_id == source.id,
        RemoteCapabilityCatalogKeyRotation.statement_digest_sha256 == statement.digest_sha256,
    ))
    if accepted is not None:
        assert_rotation_replay(accepted, signed)
        if (accepted.to_trust_key_id != payload.new_trust_key_id
            or source.trust_key_id != accepted.to_trust_key_id
            or source.catalog_id != statement.catalog_id
            or (source.latest_sequence or 0) != statement.catalog_sequence
            or source.latest_index_digest_sha256 != statement.index_digest_sha256):
            raise ValueError("Remote catalog rotation retry conflicts with current state")
        db.commit()
        return source
    keys = lock_trust_keys(db, [source.trust_key_id, payload.new_trust_key_id], expected_purpose="remote_catalog")
    current_key = keys[source.trust_key_id]
    next_key = keys[payload.new_trust_key_id]
    if current_key is None or not current_key.enabled:
        raise ValueError("Current remote catalog trust key is unavailable")
    if next_key is None or not next_key.enabled:
        raise ValueError("Next remote catalog trust key is unavailable")
    if next_key.id == current_key.id:
        raise ValueError("Remote catalog key rotation requires a different key")

    if statement.catalog_id != source.catalog_id:
        raise ValueError("Remote catalog key rotation identity does not match")
    expected_sequence = source.latest_sequence or 0
    if statement.catalog_sequence != expected_sequence:
        raise ValueError("Remote catalog key rotation sequence is stale")
    if statement.index_digest_sha256 != source.latest_index_digest_sha256:
        raise ValueError("Remote catalog key rotation index digest is stale")
    if statement.current_key_fingerprint_sha256 != (
        current_key.fingerprint_sha256
    ):
        raise ValueError("Remote catalog key rotation current signer is not pinned")
    if statement.next_key_fingerprint_sha256 != next_key.fingerprint_sha256:
        raise ValueError("Remote catalog key rotation next signer does not match")

    now = utcnow()
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if issued_at > now + ROTATION_CLOCK_SKEW:
        raise ValueError("Remote catalog key rotation is issued in the future")
    if expires_at <= now:
        raise ValueError("Remote catalog key rotation has expired")
    if expires_at - issued_at > ROTATION_MAX_LIFETIME:
        raise ValueError("Remote catalog key rotation lifetime exceeds 24 hours")

    current_verification = verify_trusted_digest_signature(
        db,
        signed.current_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_REMOTE_CATALOG_KEY_ROTATION_FORMAT,
        expected_purpose="remote_catalog",
    )
    next_verification = verify_trusted_digest_signature(
        db,
        signed.next_signature,
        expected_digest_sha256=statement.digest_sha256,
        signed_format_version=SIGNED_REMOTE_CATALOG_KEY_ROTATION_FORMAT,
        expected_purpose="remote_catalog",
    )
    if current_verification["trust_key_id"] != current_key.id:
        raise ValueError("Remote catalog rotation lacks the pinned-key signature")
    if next_verification["trust_key_id"] != next_key.id:
        raise ValueError("Remote catalog rotation lacks the next-key signature")

    locked = source
    if (
        locked.trust_key_id != current_key.id
        or (locked.latest_sequence or 0) != statement.catalog_sequence
        or locked.latest_index_digest_sha256 != statement.index_digest_sha256
    ):
        raise ValueError("Remote catalog source changed before key rotation")

    rotation = RemoteCapabilityCatalogKeyRotation(
        source_id=locked.id,
        from_trust_key_id=current_key.id,
        to_trust_key_id=next_key.id,
        from_key_fingerprint_sha256=current_key.fingerprint_sha256,
        to_key_fingerprint_sha256=next_key.fingerprint_sha256,
        catalog_sequence=statement.catalog_sequence,
        index_digest_sha256=statement.index_digest_sha256,
        statement_digest_sha256=statement.digest_sha256,
        current_signature_sha256=current_verification["signature_sha256"],
        next_signature_sha256=next_verification["signature_sha256"],
        issued_at=issued_at,
        expires_at=expires_at,
        reason=payload.reason,
        rotated_by=actor,
    )
    locked.trust_key_id = next_key.id
    locked.updated_at = utcnow()
    db.add(rotation)
    try:
        db.flush()
        append_capability_transparency_record(
            db,
            event_type="capability.remote_catalog.key_rotated",
            entity_type="remote_capability_catalog_key_rotation",
            entity_id=rotation.id,
            subject_digest_sha256=statement.digest_sha256,
            details={
                "source_id": locked.id,
                "catalog_id": locked.catalog_id,
                "catalog_sequence": statement.catalog_sequence,
                "from_key_fingerprint_sha256": current_key.fingerprint_sha256,
                "to_key_fingerprint_sha256": next_key.fingerprint_sha256,
            },
        )
        record_audit_event(
            db,
            event_type="capability.remote_catalog.key_rotated",
            actor_type="user",
            actor_id=actor,
            entity_type="remote_capability_catalog_key_rotation",
            entity_id=rotation.id,
            details={
                "source_id": locked.id,
                "catalog_id": locked.catalog_id,
                "catalog_sequence": statement.catalog_sequence,
                "index_digest_sha256": statement.index_digest_sha256,
                "statement_digest_sha256": statement.digest_sha256,
                "from_trust_key_id": current_key.id,
                "to_trust_key_id": next_key.id,
                "from_key_fingerprint_sha256": current_key.fingerprint_sha256,
                "to_key_fingerprint_sha256": next_key.fingerprint_sha256,
                "reason_sha256": hashlib.sha256(
                    payload.reason.encode("utf-8")
                ).hexdigest(),
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Remote catalog key rotation statement was already accepted"
        ) from exc
    db.refresh(locked)
    return locked
