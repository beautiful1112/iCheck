"""Serialize one namespace/source key and preserve its ordering across episodes."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, require_locking_transaction, session_namespace
from ..models import Alert, AlertConditionState, new_id, utcnow


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def identity(alert: Alert) -> tuple:
    return alert.event_type, alert.entity_type, alert.entity_id, alert.rule_id


def state_identity(state: AlertConditionState) -> tuple:
    return state.event_type, state.entity_type, state.entity_id, state.source_rule_id


def pin_identity(state: AlertConditionState, values: tuple) -> None:
    if state.event_type is not None and state_identity(state) != values:
        raise ValueError("Alert condition key belongs to a different source identity")
    state.event_type, state.entity_type, state.entity_id, state.source_rule_id = values


def latest_alert(db: Session, state: AlertConditionState) -> Alert | None:
    if state.latest_alert_id is None:
        return None
    row = db.scalar(select(Alert).where(Alert.id == state.latest_alert_id,
        Alert.tenant_id == state.tenant_id, Alert.region_id == state.region_id,
        Alert.dedup_key == state.dedup_key).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise ValueError("Alert condition source history is unavailable")
    expected = state_identity(state)
    actual = identity(row)
    # Deleting a Rule clears the Alert FK, not the original source-key pin.
    if state.event_type is not None and (actual[:3] != expected[:3]
        or actual[3] not in (None, expected[3])):
        raise ValueError("Alert condition source identity has drifted")
    return row


def lock_condition(db: Session, dedup_key: str) -> AlertConditionState:
    require_locking_transaction(db, purpose="Alert condition mutations")
    if not dedup_key or len(dedup_key) > 512:
        raise ValueError("Alert condition key must contain 1 to 512 characters")
    if any(isinstance(row, (Alert, AlertConditionState)) and row.dedup_key == dedup_key
           and (row in db.new or row in db.deleted or db.is_modified(row, include_collections=False))
           for row in (*db.new, *db.dirty, *db.deleted)):
        raise ValueError("Persist pending Alert source edits before condition mutations")
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise ValueError("Alert condition ordering requires PostgreSQL or SQLite")
    # ON CONFLICT also serializes the absent-row case; no fleet-wide mutex and
    # no uniqueness exception that would poison the caller's transaction.
    with db.no_autoflush:
        db.execute(insert(AlertConditionState).values(id=new_id(), tenant_id=tenant,
            region_id=region, dedup_key=dedup_key, state="unobserved", revision=1,
            created_at=utcnow(), updated_at=utcnow()).on_conflict_do_nothing(
                index_elements=["tenant_id", "region_id", "dedup_key"]))
        state = db.scalar(select(AlertConditionState).where(
            AlertConditionState.tenant_id == tenant, AlertConditionState.region_id == region,
            AlertConditionState.dedup_key == dedup_key).with_for_update().execution_options(populate_existing=True))
    if state is None:
        raise ValueError("Alert condition is unavailable in this namespace")
    if state.state == "unobserved":
        history_time = case((Alert.resolved_at > Alert.last_seen, Alert.resolved_at), else_=Alert.last_seen)
        with db.no_autoflush:
            old = db.scalar(select(Alert).where(Alert.tenant_id == tenant, Alert.region_id == region,
                Alert.dedup_key == dedup_key).order_by(history_time.desc(), Alert.id).limit(1))
        if old is not None:
            identities = list(db.execute(select(Alert.event_type, Alert.entity_type,
                Alert.entity_id, Alert.rule_id).where(Alert.tenant_id == tenant,
                Alert.region_id == region, Alert.dedup_key == dedup_key).distinct().limit(2)).all())
            if len(identities) == 1:
                pin_identity(state, identity(old))
                state.latest_alert_id = old.id
            state.observed_at = max(as_utc(old.last_seen), as_utc(old.resolved_at or old.last_seen))
            state.state = "legacy_unknown"
            state.revision += 1
            state.updated_at = utcnow()
            db.flush()
    return state


def observation_disposition(state: AlertConditionState, observed_at: datetime, *, active: bool | None) -> str:
    if as_utc(observed_at) > utcnow() + timedelta(minutes=5):
        raise ValueError("Alert source observation exceeds the five-minute future clock bound")
    if state.state == "legacy_unknown" and state.event_type is None:
        raise ValueError("Ambiguous legacy Alert source requires a distinct reconciled condition key")
    if state.observed_at is None or as_utc(observed_at) > as_utc(state.observed_at):
        return "accepted"
    if as_utc(observed_at) < as_utc(state.observed_at):
        return "stale"
    if state.state == "legacy_unknown":
        return "duplicate"
    if state.state == "conflict":
        return "duplicate"
    desired = "unknown" if active is None else "active" if active else "quiet"
    if state.state == desired:
        return "duplicate"
    return "conflict"


def record_observation(state: AlertConditionState, observed_at: datetime, *, active: bool | None,
                       disposition: str, alert: Alert | None) -> None:
    if disposition not in {"accepted", "conflict"}:
        return
    state.state = "conflict" if disposition == "conflict" else "unknown" if active is None else "active" if active else "quiet"
    state.observed_at = as_utc(observed_at)
    if alert is not None:
        state.latest_alert_id = alert.id
    state.revision += 1
    state.updated_at = utcnow()


def observe_unknown_condition(db: Session, key: str, observed_at: datetime, *, source_identity: tuple) -> None:
    from .collector_condition_authority import assert_collector_condition_writer
    assert_collector_condition_writer(db, key)
    state = lock_condition(db, key)
    if state.event_type is not None:
        pin_identity(state, source_identity)
    disposition = observation_disposition(state, observed_at, active=None)
    prior = latest_alert(db, state)
    if disposition in {"accepted", "conflict"}:
        pin_identity(state, source_identity)
        record_observation(state, observed_at, active=None, disposition=disposition, alert=prior)
        db.flush()
