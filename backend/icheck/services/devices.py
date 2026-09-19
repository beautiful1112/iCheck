from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..device_schemas import (
    DeviceConnectionInput,
    DeviceOnboardCreate,
    DevicePreflightAssignment,
    DevicePreflightClaim,
    DevicePreflightComplete,
)
from ..models import (
    CollectorWorker,
    CollectorWorkerState,
    CredentialProfile,
    Device,
    DeviceConnection,
    DeviceConnectionPreflight,
    utcnow,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


PROTOCOL_ADAPTERS = {
    "snmp": "snmp_exporter",
    "https_api": "http_json",
    "ssh": "ssh",
    "windows_exporter": "windows_exporter",
    "winrm_https": "psrp_cim",
    "icmp": "icmp",
}

DEFAULT_PORTS = {
    "snmp": 161,
    "https_api": 443,
    "ssh": 22,
    "windows_exporter": 9182,
    "winrm_https": 5986,
    "icmp": None,
}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _credential_profile(
    db: Session,
    reference: str,
) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        )
    )


def _connection_values(
    db: Session,
    payload: DeviceConnectionInput,
    *,
    site: str,
    actor: str,
) -> dict[str, object]:
    adapter_type = PROTOCOL_ADAPTERS[payload.protocol]
    worker_selector = dict(payload.worker_selector)
    selector_site = worker_selector.get("site")
    if selector_site and selector_site != site:
        raise ValueError(
            "connection worker_selector site must match the device site"
        )
    worker_selector.setdefault("site", site)
    assert_no_inline_secrets(worker_selector, "worker_selector")
    assert_no_inline_secrets(payload.configuration, "connection.configuration")

    if payload.credential_profile_ref:
        profile = _credential_profile(db, payload.credential_profile_ref)
        if profile is None:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} "
                "does not exist"
            )
        if not profile.enabled:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} is disabled"
            )
        if adapter_type not in profile.allowed_adapters:
            raise ValueError(
                f"Credential profile {payload.credential_profile_ref!r} does not "
                f"allow adapter {adapter_type!r}"
            )
        for key, expected in profile.worker_selector.items():
            if worker_selector.get(key) != expected:
                raise ValueError(
                    f"Connection worker_selector must include {key}={expected!r} "
                    f"for credential profile {payload.credential_profile_ref!r}"
                )

    return {
        "protocol": payload.protocol,
        "adapter_type": adapter_type,
        "port": (
            payload.port
            if payload.port is not None
            else DEFAULT_PORTS[payload.protocol]
        ),
        "credential_profile_ref": payload.credential_profile_ref,
        "worker_selector": worker_selector,
        "configuration": payload.configuration,
        "enabled": payload.enabled,
        "verification_status": "pending" if payload.enabled else "disabled",
        "next_verification_at": utcnow() if payload.enabled else None,
        "created_by": actor,
    }


def onboard_device(db: Session, payload: DeviceOnboardCreate) -> Device:
    connection_values = [
        _connection_values(
            db,
            connection,
            site=payload.site,
            actor=payload.created_by,
        )
        for connection in payload.connections
    ]
    device = Device(
        name=payload.name,
        kind=payload.kind,
        management_ip=payload.management_ip,
        vendor=payload.vendor,
        model=payload.model,
        site=payload.site,
        labels=payload.labels,
        onboarding_status="pending_verification",
        enabled=payload.enabled,
        created_by=payload.created_by,
    )
    db.add(device)
    try:
        db.flush()
        connections = [
            DeviceConnection(device_id=device.id, **values)
            for values in connection_values
        ]
        db.add_all(connections)
        db.flush()
        record_audit_event(
            db,
            event_type="device.onboarded",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="device",
            entity_id=device.id,
            details={
                "kind": device.kind,
                "site": device.site,
                "management_ip": device.management_ip,
                "protocols": [item.protocol for item in connections],
                "credential_profile_count": sum(
                    item.credential_profile_ref is not None for item in connections
                ),
                "status": device.onboarding_status,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Device name or management IP already exists") from exc
    return get_onboarded_device(db, device.id)


def get_onboarded_device(db: Session, device_id: str) -> Device:
    device = db.scalar(
        select(Device)
        .where(Device.id == device_id)
        .options(
            selectinload(Device.connections).selectinload(
                DeviceConnection.activation
            )
        )
        .execution_options(populate_existing=True)
    )
    if device is None:
        raise LookupError("Device not found")
    return device


def _refresh_device_status(db: Session, device_id: str) -> Device:
    db.flush()
    device = db.get(Device, device_id)
    if device is None:
        raise LookupError("Device not found")
    enabled_statuses = list(
        db.scalars(
            select(DeviceConnection.verification_status).where(
                DeviceConnection.device_id == device_id,
                DeviceConnection.enabled.is_(True),
            )
        ).all()
    )
    if not device.enabled or not enabled_statuses:
        status = "disabled"
    elif all(item == "verified" for item in enabled_statuses):
        status = "verified"
    elif any(item == "running" for item in enabled_statuses):
        status = "verifying"
    elif all(item == "failed" for item in enabled_statuses):
        status = "verification_failed"
    elif "verified" in enabled_statuses and "failed" in enabled_statuses:
        status = "partially_verified"
    else:
        status = "pending_verification"
    device.onboarding_status = status
    device.updated_at = utcnow()
    return device


def claim_device_preflights(
    db: Session,
    worker: CollectorWorker,
    payload: DevicePreflightClaim,
) -> list[DevicePreflightAssignment]:
    if worker.state != CollectorWorkerState.ONLINE:
        raise ValueError("Only online workers can claim device preflights")

    now = utcnow()
    lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    eligible = or_(
        DeviceConnection.verification_status == "pending",
        and_(
            DeviceConnection.verification_status == "running",
            DeviceConnection.verification_lease_expires_at.is_not(None),
            DeviceConnection.verification_lease_expires_at < now,
        ),
    )
    candidates = db.scalars(
        select(DeviceConnection)
        .join(DeviceConnection.device)
        .where(
            Device.enabled.is_(True),
            DeviceConnection.enabled.is_(True),
            DeviceConnection.adapter_type.in_(worker.capabilities),
            eligible,
            or_(
                DeviceConnection.next_verification_at.is_(None),
                DeviceConnection.next_verification_at <= now,
            ),
        )
        .options(selectinload(DeviceConnection.device))
        .order_by(
            DeviceConnection.next_verification_at,
            DeviceConnection.created_at,
            DeviceConnection.id,
        )
        .limit(payload.max_assignments * 4)
    ).all()

    worker_labels = {
        **worker.labels,
        **({"site": worker.site} if worker.site else {}),
    }
    assignments: list[DevicePreflightAssignment] = []
    for candidate in candidates:
        if len(assignments) >= payload.max_assignments:
            break
        if any(
            worker_labels.get(key) != expected
            for key, expected in candidate.worker_selector.items()
        ):
            continue

        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        claimed = db.execute(
            update(DeviceConnection)
            .execution_options(synchronize_session=False)
            .where(
                DeviceConnection.id == candidate.id,
                DeviceConnection.enabled.is_(True),
                eligible,
            )
            .values(
                verification_status="running",
                verification_worker_id=worker.id,
                verification_lease_token_hash=token_hash,
                verification_lease_expires_at=lease_expires_at,
                next_verification_at=None,
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            continue

        db.execute(
            update(DeviceConnectionPreflight)
            .where(
                DeviceConnectionPreflight.connection_id == candidate.id,
                DeviceConnectionPreflight.status == "running",
            )
            .values(
                status="expired",
                finished_at=now,
                error="Verification lease expired and was reassigned",
            )
        )
        preflight = DeviceConnectionPreflight(
            connection_id=candidate.id,
            worker_id=worker.id,
            status="running",
            lease_token_hash=token_hash,
            lease_expires_at=lease_expires_at,
            started_at=now,
        )
        db.add(preflight)
        db.flush()
        db.execute(
            update(Device)
            .where(Device.id == candidate.device_id)
            .values(onboarding_status="verifying", updated_at=now)
        )
        record_audit_event(
            db,
            event_type="device.connection.preflight.claimed",
            actor_type="worker",
            actor_id=worker.id,
            entity_type="device_connection",
            entity_id=candidate.id,
            details={
                "preflight_id": preflight.id,
                "device_id": candidate.device_id,
                "protocol": candidate.protocol,
                "adapter_type": candidate.adapter_type,
            },
        )
        assignments.append(
            DevicePreflightAssignment(
                preflight_id=preflight.id,
                lease_token=token,
                lease_expires_at=lease_expires_at,
                connection_id=candidate.id,
                device_id=candidate.device_id,
                device_name=candidate.device.name,
                target_host=candidate.device.management_ip or "",
                protocol=candidate.protocol,
                adapter_type=candidate.adapter_type,
                port=candidate.port,
                configuration=candidate.configuration,
                credential_profile_ref=candidate.credential_profile_ref,
            )
        )
    worker.last_heartbeat_at = now
    db.commit()
    return assignments


def complete_device_preflight(
    db: Session,
    worker: CollectorWorker,
    preflight_id: str,
    payload: DevicePreflightComplete,
) -> DeviceConnectionPreflight:
    preflight = db.scalar(
        select(DeviceConnectionPreflight)
        .where(DeviceConnectionPreflight.id == preflight_id)
        .options(
            selectinload(DeviceConnectionPreflight.connection).selectinload(
                DeviceConnection.device
            )
        )
    )
    if preflight is None:
        raise LookupError("Device preflight not found")
    if preflight.worker_id != worker.id:
        raise ValueError("Device preflight belongs to another worker")
    if preflight.status != "running":
        raise ValueError("Device preflight is no longer active")
    if not secrets.compare_digest(
        preflight.lease_token_hash,
        _token_hash(payload.lease_token),
    ):
        raise ValueError("Invalid device preflight lease token")

    connection = preflight.connection
    if (
        connection.verification_worker_id != worker.id
        or connection.verification_lease_token_hash is None
        or not secrets.compare_digest(
            connection.verification_lease_token_hash,
            _token_hash(payload.lease_token),
        )
    ):
        raise ValueError("Device preflight lease is no longer owned by this worker")
    now = utcnow()
    if (
        connection.verification_lease_expires_at is None
        or _as_utc(connection.verification_lease_expires_at) < now
        or _as_utc(preflight.lease_expires_at) < now
    ):
        raise ValueError("Device preflight lease has expired")

    assert_no_inline_secrets(payload.evidence, "preflight.evidence")
    evidence_size = len(
        json.dumps(payload.evidence, separators=(",", ":")).encode("utf-8")
    )
    if evidence_size > 32_768:
        raise ValueError("preflight evidence exceeds 32768 bytes")

    preflight.status = payload.status
    preflight.finished_at = now
    preflight.latency_ms = payload.latency_ms
    preflight.evidence = payload.evidence
    preflight.error = payload.error
    connection.verification_status = payload.status
    connection.last_verified_at = now
    connection.last_verification_error = payload.error
    connection.last_verification_worker_id = worker.id
    connection.last_verification_latency_ms = payload.latency_ms
    connection.last_verification_evidence = payload.evidence
    connection.verification_worker_id = None
    connection.verification_lease_token_hash = None
    connection.verification_lease_expires_at = None
    connection.next_verification_at = None
    connection.updated_at = now
    worker.last_heartbeat_at = now
    _refresh_device_status(db, connection.device_id)
    record_audit_event(
        db,
        event_type="device.connection.preflight.completed",
        actor_type="worker",
        actor_id=worker.id,
        entity_type="device_connection",
        entity_id=connection.id,
        outcome=payload.status,
        details={
            "preflight_id": preflight.id,
            "device_id": connection.device_id,
            "protocol": connection.protocol,
            "latency_ms": payload.latency_ms,
            "evidence_fields": sorted(payload.evidence),
        },
    )
    db.commit()
    db.refresh(preflight)
    return preflight


def retry_device_connection(
    db: Session,
    device_id: str,
    connection_id: str,
    *,
    actor: str,
    reason: str,
) -> Device:
    connection = db.scalar(
        select(DeviceConnection).where(
            DeviceConnection.id == connection_id,
            DeviceConnection.device_id == device_id,
        )
    )
    if connection is None:
        raise LookupError("Device connection not found")
    if not connection.enabled:
        raise ValueError("Disabled device connections cannot be verified")

    now = utcnow()
    previous_status = connection.verification_status
    if previous_status == "running":
        expires_at = connection.verification_lease_expires_at
        if expires_at is not None and _as_utc(expires_at) >= now:
            raise ValueError("Device connection verification is already running")
        db.execute(
            update(DeviceConnectionPreflight)
            .where(
                DeviceConnectionPreflight.connection_id == connection.id,
                DeviceConnectionPreflight.status == "running",
            )
            .values(
                status="expired",
                finished_at=now,
                error="Verification lease expired before operator retry",
            )
        )
    elif previous_status == "pending":
        raise ValueError("Device connection is already pending verification")

    connection.verification_status = "pending"
    connection.verification_worker_id = None
    connection.verification_lease_token_hash = None
    connection.verification_lease_expires_at = None
    connection.next_verification_at = now
    connection.last_verification_error = None
    connection.updated_at = now
    _refresh_device_status(db, device_id)
    record_audit_event(
        db,
        event_type="device.connection.preflight.retried",
        actor_type="user",
        actor_id=actor,
        entity_type="device_connection",
        entity_id=connection.id,
        details={
            "device_id": device_id,
            "protocol": connection.protocol,
            "previous_status": previous_status,
            "reason": reason,
        },
    )
    db.commit()
    return get_onboarded_device(db, device_id)
