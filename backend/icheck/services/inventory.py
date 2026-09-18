from __future__ import annotations

import ipaddress
from datetime import datetime

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import Session, selectinload

from ..models import (
    Device,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    ObservationSource,
    WirelessClientSession,
)
from ..schemas import (
    IngestResult,
    NetworkObservation,
    NetworkObservationBatch,
    WirelessClientObservation,
    WirelessSnapshot,
)
from .alerts import emit_for_rules


def _collector_condition(column: object, collector_id: str | None) -> object:
    return column == collector_id if collector_id else column.is_(None)  # type: ignore[attr-defined]


def upsert_endpoint(
    db: Session,
    *,
    mac_address: str,
    observed_at: datetime,
    hostname: str | None = None,
    username: str | None = None,
    vendor: str | None = None,
) -> tuple[Endpoint, bool]:
    endpoint = db.scalar(select(Endpoint).where(Endpoint.mac_address == mac_address))
    created = endpoint is None
    if endpoint is None:
        endpoint = Endpoint(
            mac_address=mac_address,
            hostname=hostname,
            username=username,
            vendor=vendor,
            first_seen=observed_at,
            last_seen=observed_at,
        )
        db.add(endpoint)
        db.flush()
    else:
        endpoint.last_seen = observed_at
        endpoint.hostname = hostname or endpoint.hostname
        endpoint.username = username or endpoint.username
        endpoint.vendor = vendor or endpoint.vendor

    if created:
        emit_for_rules(
            db,
            event_type="endpoint.new",
            entity_type="endpoint",
            entity_id=endpoint.id,
            title=f"New endpoint {endpoint.mac_address}",
            description="A MAC address not previously present in inventory was observed.",
            details={"mac_address": endpoint.mac_address, "hostname": endpoint.hostname},
            observed_at=observed_at,
        )
    return endpoint, created


def upsert_ip_observation(
    db: Session,
    *,
    endpoint: Endpoint,
    ip_address: str,
    source: ObservationSource,
    collector_device_id: str | None,
    vlan_id: int | None,
    observed_at: datetime,
) -> tuple[IPAddressObservation, list[str]]:
    ip_version = ipaddress.ip_address(ip_address).version
    active_rows = db.scalars(
        select(IPAddressObservation).where(
            IPAddressObservation.endpoint_id == endpoint.id,
            IPAddressObservation.source == source,
            _collector_condition(
                IPAddressObservation.collector_device_id, collector_device_id
            ),
            IPAddressObservation.active.is_(True),
        )
    ).all()

    changed_from: list[str] = []
    for row in active_rows:
        if (
            (row.ip_address != ip_address or row.vlan_id != vlan_id)
            and ipaddress.ip_address(row.ip_address).version == ip_version
        ):
            row.active = False
            row.last_seen = observed_at
            if row.ip_address != ip_address:
                changed_from.append(row.ip_address)

    observation = db.scalar(
        select(IPAddressObservation)
        .where(
            IPAddressObservation.endpoint_id == endpoint.id,
            IPAddressObservation.ip_address == ip_address,
            IPAddressObservation.source == source,
            _collector_condition(
                IPAddressObservation.collector_device_id, collector_device_id
            ),
            IPAddressObservation.vlan_id == vlan_id,
        )
        .order_by(IPAddressObservation.last_seen.desc())
    )
    if observation is None:
        observation = IPAddressObservation(
            endpoint_id=endpoint.id,
            ip_address=ip_address,
            source=source,
            collector_device_id=collector_device_id,
            vlan_id=vlan_id,
            first_seen=observed_at,
            last_seen=observed_at,
            observed_at=observed_at,
            active=True,
        )
        db.add(observation)
    else:
        observation.last_seen = observed_at
        observation.observed_at = observed_at
        observation.active = True

    if changed_from:
        emit_for_rules(
            db,
            event_type="endpoint.ip.changed",
            entity_type="endpoint",
            entity_id=endpoint.id,
            title=f"IP address changed for {endpoint.mac_address}",
            description=f"{', '.join(changed_from)} changed to {ip_address}.",
            details={
                "mac_address": endpoint.mac_address,
                "previous_ips": changed_from,
                "ip_address": ip_address,
                "source": source.value,
            },
            observed_at=observed_at,
            dedup_suffix=source.value,
        )
    return observation, changed_from


def upsert_attachment(
    db: Session,
    *,
    endpoint: Endpoint,
    source: ObservationSource,
    collector_device_id: str | None,
    interface_name: str | None,
    vlan_id: int | None,
    observed_at: datetime,
    raw_data: dict[str, object],
) -> EndpointAttachment:
    active_rows = db.scalars(
        select(EndpointAttachment).where(
            EndpointAttachment.endpoint_id == endpoint.id,
            EndpointAttachment.source == source,
            _collector_condition(
                EndpointAttachment.collector_device_id, collector_device_id
            ),
            EndpointAttachment.active.is_(True),
        )
    ).all()
    attachment = next(
        (
            row
            for row in active_rows
            if row.interface_name == interface_name and row.vlan_id == vlan_id
        ),
        None,
    )
    for row in active_rows:
        if row is not attachment:
            row.active = False
            row.last_seen = observed_at

    if attachment is None:
        attachment = EndpointAttachment(
            endpoint_id=endpoint.id,
            source=source,
            collector_device_id=collector_device_id,
            interface_name=interface_name,
            vlan_id=vlan_id,
            first_seen=observed_at,
            last_seen=observed_at,
            observed_at=observed_at,
            raw_data=raw_data,
        )
        db.add(attachment)
    else:
        attachment.last_seen = observed_at
        attachment.observed_at = observed_at
        attachment.raw_data = raw_data
    return attachment


def ingest_network_observations(
    db: Session, batch: NetworkObservationBatch
) -> IngestResult:
    created = updated = ip_written = attachments_written = 0
    alert_ids: set[str] = set()

    for item in batch.observations:
        endpoint, was_created = upsert_endpoint(
            db,
            mac_address=item.mac_address,
            observed_at=item.observed_at,
            hostname=item.hostname,
            username=item.username,
            vendor=item.vendor,
        )
        created += int(was_created)
        updated += int(not was_created)

        if item.ip_address:
            _, _ = upsert_ip_observation(
                db,
                endpoint=endpoint,
                ip_address=item.ip_address,
                source=item.source,
                collector_device_id=item.collector_device_id,
                vlan_id=item.vlan_id,
                observed_at=item.observed_at,
            )
            ip_written += 1

        if item.collector_device_id or item.interface_name:
            upsert_attachment(
                db,
                endpoint=endpoint,
                source=item.source,
                collector_device_id=item.collector_device_id,
                interface_name=item.interface_name,
                vlan_id=item.vlan_id,
                observed_at=item.observed_at,
                raw_data=item.raw_data,
            )
            attachments_written += 1

    db.flush()
    db.commit()

    return IngestResult(
        observations_received=len(batch.observations),
        endpoints_created=created,
        endpoints_updated=updated,
        ip_observations_written=ip_written,
        attachments_written=attachments_written,
        alert_ids=sorted(alert_ids),
    )


def upsert_wireless_session(
    db: Session,
    *,
    endpoint: Endpoint,
    controller_id: str,
    client: WirelessClientObservation,
    snapshot_observed_at: datetime,
) -> tuple[WirelessClientSession, int, list[str]]:
    observed_at = client.observed_at or snapshot_observed_at
    ip_alert_ids: list[str] = []
    if client.ip_address:
        _, changed_from = upsert_ip_observation(
            db,
            endpoint=endpoint,
            ip_address=client.ip_address,
            source=ObservationSource.WIFI_CONTROLLER,
            collector_device_id=controller_id,
            vlan_id=client.vlan_id,
            observed_at=observed_at,
        )
        if changed_from:
            ip_alert_ids.extend([])

    sessions = db.scalars(
        select(WirelessClientSession).where(
            WirelessClientSession.endpoint_id == endpoint.id,
            WirelessClientSession.controller_id == controller_id,
            WirelessClientSession.active.is_(True),
        )
    ).all()
    current = next(
        (
            session
            for session in sessions
            if session.access_point == client.access_point and session.ssid == client.ssid
        ),
        None,
    )
    closed = 0
    for session in sessions:
        if session is not current:
            session.active = False
            session.disconnected_at = observed_at
            session.last_seen = observed_at
            closed += 1

    if current is None:
        current = WirelessClientSession(
            endpoint_id=endpoint.id,
            controller_id=controller_id,
            first_seen=observed_at,
            connected_at=client.connected_at or observed_at,
        )
        db.add(current)

    current.ip_address = client.ip_address
    current.access_point = client.access_point
    current.ssid = client.ssid
    current.bssid = client.bssid
    current.radio = client.radio
    current.band = client.band
    current.channel = client.channel
    current.vlan_id = client.vlan_id
    current.rssi = client.rssi
    current.snr = client.snr
    current.last_seen = observed_at
    current.observed_at = observed_at
    current.raw_data = client.raw_data
    current.active = True
    current.disconnected_at = None
    db.flush()

    alerts = emit_for_rules(
        db,
        event_type="wireless.rssi.low",
        entity_type="endpoint",
        entity_id=endpoint.id,
        title=f"Weak Wi-Fi signal for {endpoint.hostname or endpoint.mac_address}",
        description=(
            f"Client signal is {client.rssi} dBm on {client.access_point or 'an unknown AP'}."
        ),
        details={
            "mac_address": endpoint.mac_address,
            "rssi": client.rssi,
            "snr": client.snr,
            "access_point": client.access_point,
            "ssid": client.ssid,
            "controller_id": controller_id,
        },
        observed_at=observed_at,
        dedup_suffix=controller_id,
    )
    return current, closed, [alert.id for alert in alerts] + ip_alert_ids


def ingest_wireless_snapshot(db: Session, snapshot: WirelessSnapshot) -> IngestResult:
    controller = db.get(Device, snapshot.controller_id)
    if controller is None:
        raise LookupError("Wireless controller was not found")
    if controller.kind != "wireless_controller":
        raise ValueError("The selected device is not a wireless controller")

    created = updated = ip_written = sessions_written = sessions_closed = 0
    seen_endpoint_ids: set[str] = set()
    alert_ids: set[str] = set()

    for client in snapshot.clients:
        endpoint, was_created = upsert_endpoint(
            db,
            mac_address=client.mac_address,
            observed_at=client.observed_at,
            hostname=client.hostname,
            username=client.username,
            vendor=client.vendor,
        )
        created += int(was_created)
        updated += int(not was_created)
        seen_endpoint_ids.add(endpoint.id)
        ip_written += int(client.ip_address is not None)

        _, closed, emitted_alert_ids = upsert_wireless_session(
            db,
            endpoint=endpoint,
            controller_id=controller.id,
            client=client,
            snapshot_observed_at=snapshot.observed_at,
        )
        sessions_written += 1
        sessions_closed += closed
        alert_ids.update(emitted_alert_ids)

    if snapshot.complete_snapshot:
        active_sessions = db.scalars(
            select(WirelessClientSession).where(
                WirelessClientSession.controller_id == controller.id,
                WirelessClientSession.active.is_(True),
            )
        ).all()
        for session in active_sessions:
            if session.endpoint_id not in seen_endpoint_ids:
                session.active = False
                session.disconnected_at = snapshot.observed_at
                session.last_seen = snapshot.observed_at
                sessions_closed += 1

    db.commit()
    return IngestResult(
        observations_received=len(snapshot.clients),
        endpoints_created=created,
        endpoints_updated=updated,
        ip_observations_written=ip_written,
        wireless_sessions_written=sessions_written,
        sessions_closed=sessions_closed,
        alert_ids=sorted(alert_ids),
    )


def endpoint_query(search: str | None = None) -> Select[tuple[Endpoint]]:
    query = select(Endpoint).options(
        selectinload(Endpoint.ip_observations),
        selectinload(Endpoint.attachments),
        selectinload(Endpoint.wireless_sessions),
    )
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Endpoint.mac_address.ilike(pattern),
                Endpoint.hostname.ilike(pattern),
                Endpoint.username.ilike(pattern),
                Endpoint.ip_observations.any(IPAddressObservation.ip_address.ilike(pattern)),
            )
        )
    return query.order_by(Endpoint.last_seen.desc())


def endpoint_to_dict(endpoint: Endpoint) -> dict[str, object]:
    return {
        "id": endpoint.id,
        "mac_address": endpoint.mac_address,
        "hostname": endpoint.hostname,
        "username": endpoint.username,
        "vendor": endpoint.vendor,
        "first_seen": endpoint.first_seen,
        "last_seen": endpoint.last_seen,
        "current_ips": [
            {
                "address": row.ip_address,
                "source": row.source,
                "vlan_id": row.vlan_id,
                "collector_device_id": row.collector_device_id,
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
            }
            for row in endpoint.ip_observations
            if row.active
        ],
        "current_attachments": [
            {
                "source": row.source,
                "collector_device_id": row.collector_device_id,
                "interface_name": row.interface_name,
                "vlan_id": row.vlan_id,
                "last_seen": row.last_seen,
            }
            for row in endpoint.attachments
            if row.active
        ],
        "current_wireless_sessions": [
            {
                "id": row.id,
                "controller_id": row.controller_id,
                "ip_address": row.ip_address,
                "access_point": row.access_point,
                "ssid": row.ssid,
                "band": row.band,
                "channel": row.channel,
                "vlan_id": row.vlan_id,
                "rssi": row.rssi,
                "snr": row.snr,
                "connected_at": row.connected_at,
                "last_seen": row.last_seen,
            }
            for row in endpoint.wireless_sessions
            if row.active
        ],
    }

