from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, NamespaceViolation, session_namespace
from ..capability_transparency_schemas import (
    CapabilityTransparencyCheckpointRead,
    CapabilityTransparencyRecordListRead,
    CapabilityTransparencyRecordRead,
    CapabilityTransparencyVerificationRead,
)
from ..models import (
    CapabilityTransparencyRecord,
    CapabilityTransparencyState,
    new_id,
    utcnow,
)


TRANSPARENCY_STATE_ID = "global"
TRANSPARENCY_GENESIS_DIGEST = "0" * 64
TRANSPARENCY_RECORD_FORMAT = "icheck.capability-transparency-record/v1"
TRANSPARENCY_DETAILS_MAX_BYTES = 16_384


def transparency_singleton_id(db: Session) -> str:
    """Preserve the legacy default log while isolating other namespaces."""
    namespace = session_namespace(db)
    if namespace is None:
        if db.info.get("namespace_enforced"):
            raise NamespaceViolation("A namespace is required for transparency state")
        return TRANSPARENCY_STATE_ID
    if namespace == (DEFAULT_TENANT_ID, DEFAULT_REGION_ID):
        return TRANSPARENCY_STATE_ID
    encoded = json.dumps(namespace, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:32]


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


def _validate_digest(value: str, *, name: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _record_material(
    *,
    sequence: int,
    previous_digest_sha256: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    subject_digest_sha256: str,
    details: dict[str, Any],
    occurred_at: datetime,
) -> dict[str, Any]:
    return {
        "format_version": TRANSPARENCY_RECORD_FORMAT,
        "sequence": sequence,
        "previous_digest_sha256": previous_digest_sha256,
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "subject_digest_sha256": subject_digest_sha256,
        "details": details,
        "occurred_at": _as_utc(occurred_at).isoformat(),
    }


def _locked_state(db: Session) -> tuple[CapabilityTransparencyState, bool]:
    state_id = transparency_singleton_id(db)
    query = select(CapabilityTransparencyState).where(
        CapabilityTransparencyState.id == state_id
    ).with_for_update()
    state = db.scalar(query)
    created_or_repaired = False
    if state is None:
        namespace = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
        dialect = db.get_bind().dialect.name
        if dialect == "postgresql":
            insert = postgresql_insert(CapabilityTransparencyState)
        elif dialect == "sqlite":
            insert = sqlite_insert(CapabilityTransparencyState)
        else:
            raise RuntimeError("Transparency state requires PostgreSQL or SQLite")
        db.execute(insert.values(
            id=state_id, tenant_id=namespace[0], region_id=namespace[1],
            log_id=new_id(), epoch=1, last_sequence=0,
            head_digest_sha256=TRANSPARENCY_GENESIS_DIGEST, updated_at=utcnow(),
        ).on_conflict_do_nothing(index_elements=["id"]))
        state = db.scalar(query)
        if state is None:
            raise RuntimeError("Transparency state could not be initialized")
        created_or_repaired = True
    if state.log_id is None:
        state.log_id = new_id()
        state.epoch = max(state.epoch, 1)
        db.flush()
        created_or_repaired = True
    return state, created_or_repaired


def append_capability_transparency_record(
    db: Session,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    subject_digest_sha256: str,
    details: dict[str, Any] | None = None,
) -> CapabilityTransparencyRecord:
    _validate_digest(subject_digest_sha256, name="Transparency subject")
    bounded_details = details or {}
    encoded_details = json.dumps(
        bounded_details,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if len(encoded_details) > TRANSPARENCY_DETAILS_MAX_BYTES:
        raise ValueError(
            "Capability transparency details exceed 16384 bytes"
        )
    state, _ = _locked_state(db)
    sequence = state.last_sequence + 1
    occurred_at = utcnow()
    material = _record_material(
        sequence=sequence,
        previous_digest_sha256=state.head_digest_sha256,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        subject_digest_sha256=subject_digest_sha256,
        details=bounded_details,
        occurred_at=occurred_at,
    )
    record = CapabilityTransparencyRecord(
        sequence=sequence,
        previous_digest_sha256=state.head_digest_sha256,
        record_digest_sha256=_canonical_hash(material),
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        subject_digest_sha256=subject_digest_sha256,
        details=bounded_details,
        occurred_at=occurred_at,
    )
    db.add(record)
    state.last_sequence = sequence
    state.head_digest_sha256 = record.record_digest_sha256
    state.updated_at = occurred_at
    db.flush()
    return record


def get_capability_transparency_checkpoint(
    db: Session,
) -> CapabilityTransparencyCheckpointRead:
    state, changed = _locked_state(db)
    if changed:
        db.commit()
        db.refresh(state)
    if state.log_id is None:
        raise RuntimeError("Capability transparency log identity is unavailable")
    return CapabilityTransparencyCheckpointRead.model_validate(state)


def list_capability_transparency_records(
    db: Session,
    *,
    after_sequence: int,
    event_type: str | None,
    limit: int,
) -> CapabilityTransparencyRecordListRead:
    query = select(CapabilityTransparencyRecord).where(
        CapabilityTransparencyRecord.sequence > after_sequence
    )
    if event_type:
        query = query.where(
            CapabilityTransparencyRecord.event_type == event_type
        )
    records = list(
        db.scalars(
            query.order_by(CapabilityTransparencyRecord.sequence).limit(limit)
        ).all()
    )
    checkpoint = get_capability_transparency_checkpoint(db)
    return CapabilityTransparencyRecordListRead(
        items=[
            CapabilityTransparencyRecordRead.model_validate(item)
            for item in records
        ],
        head_sequence=checkpoint.last_sequence,
        head_digest_sha256=checkpoint.head_digest_sha256,
        after_sequence=after_sequence,
        limit=limit,
    )


def verify_capability_transparency_chain(
    db: Session,
) -> CapabilityTransparencyVerificationRead:
    records = db.scalars(
        select(CapabilityTransparencyRecord)
        .order_by(CapabilityTransparencyRecord.sequence)
        .execution_options(yield_per=1000)
    )
    checkpoint = get_capability_transparency_checkpoint(db)
    previous = TRANSPARENCY_GENESIS_DIGEST
    expected_sequence = 1
    failure_sequence: int | None = None
    record_count = 0
    first_sequence: int | None = None
    for record in records:
        record_count += 1
        if first_sequence is None:
            first_sequence = record.sequence
        calculated = _canonical_hash(
            _record_material(
                sequence=record.sequence,
                previous_digest_sha256=record.previous_digest_sha256,
                event_type=record.event_type,
                entity_type=record.entity_type,
                entity_id=record.entity_id,
                subject_digest_sha256=record.subject_digest_sha256,
                details=record.details,
                occurred_at=record.occurred_at,
            )
        )
        if (
            record.sequence != expected_sequence
            or record.previous_digest_sha256 != previous
            or record.record_digest_sha256 != calculated
        ):
            failure_sequence = record.sequence
            break
        previous = calculated
        expected_sequence += 1
    valid = (
        failure_sequence is None
        and checkpoint.last_sequence == record_count
        and checkpoint.head_digest_sha256 == previous
    )
    if not valid and failure_sequence is None:
        failure_sequence = checkpoint.last_sequence or None
    return CapabilityTransparencyVerificationRead(
        valid=valid,
        record_count=record_count,
        first_sequence=first_sequence,
        last_sequence=checkpoint.last_sequence,
        calculated_head_digest_sha256=previous,
        stored_head_digest_sha256=checkpoint.head_digest_sha256,
        failure_sequence=failure_sequence,
    )
