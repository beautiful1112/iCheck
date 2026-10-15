"""Controller-local snapshot admission and conservative absence semantics."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, require_locking_transaction, session_namespace
from ..models import AlertConditionState, Device, WirelessClientSession, WirelessSnapshotState, new_id, utcnow
from ..schemas import WirelessSnapshot
from .alert_conditions import as_utc, observe_unknown_condition, state_identity

if TYPE_CHECKING:
    from .control_plane_auth import PrincipalContext


def admit_snapshot(db: Session, snapshot: WirelessSnapshot, *, principal: PrincipalContext | None = None) -> tuple[Device, str]:
    """Lock this controller, then compare the exact bounded normalized body.

    The caller owns the transaction, including any eventual inventory writes.
    Keeping the last body avoids introducing standalone cryptographic hashing.
    """
    require_locking_transaction(db, purpose="Wireless snapshot ingestion")
    if snapshot.observed_at > utcnow() + timedelta(minutes=5):
        raise ValueError("Wireless snapshot exceeds the five-minute future clock bound")
    payload = json.dumps(snapshot.model_dump(mode="json") | {
        "clients": [client.model_dump(mode="json") for client in sorted(snapshot.clients, key=lambda row: row.mac_address)]
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(payload.encode("utf-8")) > 8 * 1024 * 1024:
        raise ValueError("Normalized wireless snapshot exceeds the eight-MiB body bound")
    if any(isinstance(row, (Device, WirelessSnapshotState))
           and (getattr(row, "controller_id", None) == snapshot.controller_id or getattr(row, "id", None) == snapshot.controller_id)
           and (row in db.new or row in db.deleted or db.is_modified(row, include_collections=False))
           for row in (*db.new, *db.dirty, *db.deleted)):
        raise ValueError("Persist pending wireless controller or snapshot edits before ingestion")
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    with db.no_autoflush:
        controller = db.scalar(select(Device).where(Device.id == snapshot.controller_id,
            Device.tenant_id == tenant, Device.region_id == region).with_for_update().execution_options(populate_existing=True))
    if controller is None:
        raise LookupError("Wireless controller was not found")
    if principal is not None:
        from .authorization_scope import require_device_access
        require_device_access(db, principal, controller.id)
    if controller.kind != "wireless_controller" or not controller.enabled:
        raise ValueError("The selected device is not an enabled wireless controller")
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise ValueError("Wireless snapshot ordering requires PostgreSQL or SQLite")
    with db.no_autoflush:
        db.execute(insert(WirelessSnapshotState).values(id=new_id(), tenant_id=tenant, region_id=region,
            controller_id=controller.id, state="unobserved", payload="", revision=1,
            created_at=utcnow(), updated_at=utcnow()).on_conflict_do_nothing(
                index_elements=["tenant_id", "region_id", "controller_id"]))
        state = db.scalar(select(WirelessSnapshotState).where(WirelessSnapshotState.tenant_id == tenant,
            WirelessSnapshotState.region_id == region, WirelessSnapshotState.controller_id == controller.id)
            .with_for_update().execution_options(populate_existing=True))
    if state is None:
        raise ValueError("Wireless snapshot state is unavailable in this namespace")
    if state.state == "unobserved":
        # Also protects create_all fixtures/legacy importers; never invent a
        # complete-snapshot body or a quiet verdict from historical sessions.
        session_time = case((WirelessClientSession.disconnected_at > WirelessClientSession.last_seen,
            WirelessClientSession.disconnected_at), else_=WirelessClientSession.last_seen)
        history = db.scalar(select(func.max(session_time)).where(WirelessClientSession.controller_id == controller.id,
            WirelessClientSession.tenant_id == tenant, WirelessClientSession.region_id == region))
        condition_time = db.scalar(select(func.max(AlertConditionState.observed_at)).where(
            AlertConditionState.tenant_id == tenant, AlertConditionState.region_id == region,
            AlertConditionState.event_type == "wireless.rssi.low", AlertConditionState.entity_type == "endpoint",
            AlertConditionState.dedup_key == AlertConditionState.source_rule_id + ":" + AlertConditionState.entity_id + f":{controller.id}"))
        known = [as_utc(value) for value in (history, condition_time) if value is not None]
        if known:
            state.state, state.observed_at = "legacy_unknown", max(known)
            state.revision += 1
            state.updated_at = utcnow()
            db.flush()
    if state.observed_at is not None:
        if snapshot.observed_at < as_utc(state.observed_at):
            return controller, "stale"
        if snapshot.observed_at == as_utc(state.observed_at):
            if state.state == "legacy_unknown":
                return controller, "legacy_unknown"
            if state.state == "conflict":
                return controller, "conflict"
            if payload == state.payload:
                return controller, "duplicate"
            state.state = "conflict"
            state.revision += 1
            state.updated_at = utcnow()
            db.flush()
            unknown_controller_conditions(db, controller.id, snapshot.observed_at)
            return controller, "conflict"
    state.observed_at, state.payload, state.state = snapshot.observed_at, payload, "accepted"
    state.revision += 1
    state.updated_at = utcnow()
    db.flush()
    return controller, "accepted"


def unknown_controller_conditions(db: Session, controller_id: str, observed_at: datetime, *, seen_endpoint_ids: set[str] | None = None) -> None:
    """Absence/contradiction is unknown, including disabled or deleted Rules.

    Walk retained logical pins, not only currently active sessions/Rules. This
    prevents a late recovery after the client has already disappeared. This is
    not a source-transport or independently qualified observer attestation.
    """
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    rows = db.scalars(select(AlertConditionState).where(AlertConditionState.tenant_id == tenant,
        AlertConditionState.region_id == region, AlertConditionState.event_type == "wireless.rssi.low",
        AlertConditionState.entity_type == "endpoint",
        AlertConditionState.dedup_key == AlertConditionState.source_rule_id + ":" + AlertConditionState.entity_id + f":{controller_id}")
        .order_by(AlertConditionState.dedup_key).execution_options(yield_per=250, populate_existing=True))
    for row in rows:
        if seen_endpoint_ids is None or row.entity_id not in seen_endpoint_ids:
            observe_unknown_condition(db, row.dedup_key, observed_at, source_identity=state_identity(row))
