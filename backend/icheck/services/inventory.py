from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Select, and_, or_, select, func
from sqlalchemy.orm import Session, selectinload

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, require_locking_transaction, session_namespace
from ..models import (
    Device,
    Endpoint,
    EndpointAttachment,
    IPAddressObservation,
    NetworkObservationState,
    ObservationSource,
    WirelessClientSession,
    new_id,
    utcnow,
)
from ..schemas import (
    IngestResult,
    NetworkObservation,
    NetworkObservationBatch,
    WirelessClientObservation,
    WirelessSnapshot,
)
from .alerts import emit_for_rules
from .alert_conditions import as_utc
from .wireless_snapshots import admit_snapshot, unknown_controller_conditions
from ..network_binding_schemas import NetworkObservationBatchV2, NetworkObservationV2

if TYPE_CHECKING:
    from .control_plane_auth import PrincipalContext


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
    update_metadata: bool = True,
    emit_new: bool = True,
) -> tuple[Endpoint, bool]:
    require_locking_transaction(db, purpose="Endpoint inventory ingestion")
    if any(isinstance(row, Endpoint) and row.mac_address == mac_address
           and (row in db.new or row in db.deleted or db.is_modified(row, include_collections=False))
           for row in (*db.new, *db.dirty, *db.deleted)):
        raise ValueError("Persist pending Endpoint edits before inventory ingestion")
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise ValueError("Endpoint inventory ingestion requires PostgreSQL or SQLite")
    observed_at = as_utc(observed_at)
    with db.no_autoflush:
        inserted_id = db.scalar(insert(Endpoint).values(id=new_id(), tenant_id=tenant, region_id=region,
            mac_address=mac_address, hostname=hostname, username=username, vendor=vendor,
            first_seen=observed_at, last_seen=observed_at, created_at=utcnow(), updated_at=utcnow())
            .on_conflict_do_nothing(index_elements=["tenant_id", "region_id", "mac_address"]).returning(Endpoint.id))
        endpoint = db.scalar(select(Endpoint).where(Endpoint.tenant_id == tenant, Endpoint.region_id == region,
            Endpoint.mac_address == mac_address).with_for_update().execution_options(populate_existing=True))
    if endpoint is None:
        raise ValueError("Endpoint is unavailable in this namespace")
    created = inserted_id is not None
    if not created and update_metadata:
        endpoint.first_seen = min(as_utc(endpoint.first_seen), as_utc(observed_at))
        if as_utc(observed_at) > as_utc(endpoint.last_seen):
            endpoint.last_seen = observed_at
            endpoint.hostname = hostname or endpoint.hostname
            endpoint.username = username or endpoint.username
            endpoint.vendor = vendor or endpoint.vendor
    db.flush()

    if created and emit_new:
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
    db: Session,
    batch: NetworkObservationBatch | NetworkObservationBatchV2,
    *,
    commit: bool = True,
    principal: PrincipalContext | None = None,
) -> IngestResult:
    from .network_observations import admit_channel, channels, prepare_batch
    batch_model = NetworkObservationBatchV2 if isinstance(batch, NetworkObservationBatchV2) else NetworkObservationBatch
    batch = batch_model.model_validate(batch.model_dump(mode="python"))
    prepare_batch(db, batch, principal=principal)
    created = updated = ip_written = attachments_written = 0
    alert_ids: set[str] = set()
    dispositions = []
    ordered = sorted(enumerate(batch.observations), key=lambda pair: (pair[1].mac_address,
        pair[1].collector_device_id or "", pair[1].source.value, pair[1].observed_at, pair[0]))
    for index, item in ordered:
        endpoint, was_created = upsert_endpoint(
            db,
            mac_address=item.mac_address,
            observed_at=item.observed_at,
            update_metadata=False,
            emit_new=False,
        )
        per_channel = {}
        for dimension, value in sorted(channels(item).items(), key=lambda pair: (pair[0] != "metadata", pair[0])):
            if (dimension == "attachment" and not isinstance(item, NetworkObservationV2)
                and item.attachment_present is None and item.interface_name is None):
                known = db.scalar(select(EndpointAttachment.id).where(EndpointAttachment.endpoint_id == endpoint.id,
                    EndpointAttachment.source == item.source, EndpointAttachment.collector_device_id == item.collector_device_id).limit(1))
                cursor = db.scalar(select(NetworkObservationState.id).where(NetworkObservationState.endpoint_id == endpoint.id,
                    NetworkObservationState.source == item.source, NetworkObservationState.collector_key == (item.collector_device_id or "unbound"),
                    NetworkObservationState.dimension == "attachment").limit(1))
                if known or cursor:
                    per_channel[dimension] = "not_observed"
                    continue
            disposition = admit_channel(db, endpoint, item, dimension, value)
            per_channel[dimension] = disposition
            if disposition != "accepted":
                continue
            if dimension == "metadata":
                before_first = as_utc(endpoint.first_seen)
                endpoint.first_seen = min(before_first, item.observed_at)
                if was_created or item.observed_at > as_utc(endpoint.last_seen):
                    endpoint.last_seen = item.observed_at
                    endpoint.hostname = item.hostname or endpoint.hostname
                    endpoint.username = item.username or endpoint.username
                    endpoint.vendor = item.vendor or endpoint.vendor
                    updated += int(not was_created)
                elif endpoint.first_seen != before_first:
                    updated += 1
                if was_created:
                    created += 1
                    alerts = emit_for_rules(db, event_type="endpoint.new", entity_type="endpoint", entity_id=endpoint.id,
                        title=f"New endpoint {endpoint.mac_address}",
                        description="A MAC address not previously present in inventory was observed.",
                        details={"mac_address": endpoint.mac_address, "hostname": endpoint.hostname}, observed_at=item.observed_at)
                    alert_ids.update(alert.id for alert in alerts)
            elif dimension == "attachment":
                if isinstance(item, NetworkObservationV2):
                    attachments_written += apply_network_attachment_set(db, endpoint, item)
                elif item.attachment_present is False:
                    rows = db.scalars(select(EndpointAttachment).where(EndpointAttachment.endpoint_id == endpoint.id,
                        EndpointAttachment.source == item.source, EndpointAttachment.collector_device_id == item.collector_device_id,
                        EndpointAttachment.active.is_(True)).with_for_update().execution_options(populate_existing=True))
                    for row in rows:
                        row.active = False
                        row.last_seen = item.observed_at
                        attachments_written += 1
                else:
                    upsert_attachment(db, endpoint=endpoint, source=item.source, collector_device_id=item.collector_device_id,
                        interface_name=item.interface_name, vlan_id=item.vlan_id, observed_at=item.observed_at, raw_data=item.raw_data)
                    attachments_written += 1
            else:
                if isinstance(item, NetworkObservationV2):
                    count, alerts = apply_network_ip_binding_set(db, endpoint, item, int(dimension[-1]), value["bindings"])
                else:
                    count, alerts = apply_network_ip_set(db, endpoint, item, int(dimension[-1]), value["addresses"])
                ip_written += count
                alert_ids.update(alert.id for alert in alerts)
        db.flush()
        dispositions.append({"index": index, "mac_address": item.mac_address, "source": item.source.value,
            "collector_device_id": item.collector_device_id, "channels": per_channel})

    db.flush()
    if commit:
        db.commit()

    return IngestResult(
        observations_received=len(batch.observations),
        endpoints_created=created,
        endpoints_updated=updated,
        ip_observations_written=ip_written,
        attachments_written=attachments_written,
        alert_ids=sorted(alert_ids),
        network_dispositions=sorted(dispositions, key=lambda row: row["index"]),
    )


def apply_network_attachment_set(db, endpoint, item):
    """Replace one explicit collector/source cohort, retaining old episodes."""
    rows = list(db.scalars(select(EndpointAttachment).where(EndpointAttachment.endpoint_id == endpoint.id,
        EndpointAttachment.source == item.source, EndpointAttachment.collector_device_id == item.collector_device_id,
        EndpointAttachment.active.is_(True)).order_by(EndpointAttachment.last_seen.desc(), EndpointAttachment.id)
        .with_for_update().execution_options(populate_existing=True)))
    wanted = {(binding.interface_name, binding.vlan_id) for binding in item.attachments}
    chosen = {}
    for row in rows:
        key = (row.interface_name, row.vlan_id)
        if key in wanted:
            chosen.setdefault(key, row)
    removed = 0
    for row in rows:
        if chosen.get((row.interface_name, row.vlan_id)) is not row:
            row.active = False
            row.last_seen = item.observed_at
            removed += 1
    for binding in item.attachments:
        current = chosen.get((binding.interface_name, binding.vlan_id))
        if current is None:
            db.add(EndpointAttachment(endpoint_id=endpoint.id, source=item.source,
                collector_device_id=item.collector_device_id, interface_name=binding.interface_name,
                vlan_id=binding.vlan_id, first_seen=item.observed_at, last_seen=item.observed_at,
                observed_at=item.observed_at, active=True, raw_data=item.raw_data))
        else:
            current.last_seen = current.observed_at = item.observed_at
            current.raw_data = item.raw_data
    return len(item.attachments) + removed


def apply_network_ip_binding_set(db, endpoint, item, family, bindings):
    """Only declared families change; the same address on two VLANs is two bindings."""
    rows = list(db.scalars(select(IPAddressObservation).where(IPAddressObservation.endpoint_id == endpoint.id,
        IPAddressObservation.source == item.source, IPAddressObservation.collector_device_id == item.collector_device_id,
        IPAddressObservation.active.is_(True)).order_by(IPAddressObservation.last_seen.desc(), IPAddressObservation.id)
        .with_for_update().execution_options(populate_existing=True)))
    rows = [row for row in rows if ipaddress.ip_address(row.ip_address).version == family]
    wanted = {(binding["ip_address"], binding["vlan_id"]) for binding in bindings}
    chosen = {}
    for row in rows:
        key = (row.ip_address, row.vlan_id)
        if key in wanted:
            chosen.setdefault(key, row)
    removed = []
    for row in rows:
        if chosen.get((row.ip_address, row.vlan_id)) is not row:
            row.active = False
            row.last_seen = item.observed_at
            if (row.ip_address, row.vlan_id) not in wanted:
                removed.append({"ip_address": row.ip_address, "vlan_id": row.vlan_id})
    for binding in bindings:
        current = chosen.get((binding["ip_address"], binding["vlan_id"]))
        if current is None:
            db.add(IPAddressObservation(endpoint_id=endpoint.id, ip_address=binding["ip_address"], source=item.source,
                collector_device_id=item.collector_device_id, vlan_id=binding["vlan_id"], active=True,
                first_seen=item.observed_at, last_seen=item.observed_at, observed_at=item.observed_at))
        else:
            current.last_seen = current.observed_at = item.observed_at
    alerts = []
    if removed:
        alerts = emit_for_rules(db, event_type="endpoint.ip.changed", entity_type="endpoint", entity_id=endpoint.id,
            title=f"IP/VLAN bindings changed for {endpoint.mac_address}",
            description="An explicit source-local address/VLAN set replaced previously observed bindings.",
            details={"mac_address": endpoint.mac_address, "previous_bindings": removed, "ip_bindings": bindings,
                "source": item.source.value, "collector_device_id": item.collector_device_id},
            observed_at=item.observed_at, dedup_suffix=f"{item.source.value}:{item.collector_device_id or 'unbound'}:ipv{family}")
    db.flush()
    return len(bindings), alerts


def apply_network_ip_set(db, endpoint, item, family, addresses):
    """Replace only this collector/source/family, retaining all history."""
    scope = (IPAddressObservation.endpoint_id == endpoint.id, IPAddressObservation.source == item.source,
        IPAddressObservation.collector_device_id == item.collector_device_id)
    ranked = select(IPAddressObservation.id, func.row_number().over(
        partition_by=(IPAddressObservation.ip_address, IPAddressObservation.vlan_id),
        order_by=(IPAddressObservation.last_seen.desc(), IPAddressObservation.id)).label("position")).where(
            *scope, IPAddressObservation.ip_address.in_(addresses), IPAddressObservation.vlan_id == item.vlan_id).subquery()
    selected = select(ranked.c.id).where(ranked.c.position == 1)
    rows = list(db.scalars(select(IPAddressObservation).where(*scope,
        or_(IPAddressObservation.active.is_(True), IPAddressObservation.id.in_(selected)))
        .order_by(IPAddressObservation.last_seen.desc(), IPAddressObservation.id).with_for_update()
        .execution_options(populate_existing=True)))
    rows = [row for row in rows if ipaddress.ip_address(row.ip_address).version == family]
    wanted = set(addresses)
    chosen = {}
    for row in rows:
        if row.ip_address in wanted and row.vlan_id == item.vlan_id:
            chosen.setdefault(row.ip_address, row)
    removed = []
    for row in rows:
        if row.active and (row.ip_address not in wanted or row.vlan_id != item.vlan_id or chosen.get(row.ip_address) is not row):
            row.active = False
            row.last_seen = item.observed_at
            if row.ip_address not in wanted:
                removed.append(row.ip_address)
    for address in addresses:
        current = chosen.get(address)
        if current is None:
            db.add(IPAddressObservation(endpoint_id=endpoint.id, ip_address=address, source=item.source,
                collector_device_id=item.collector_device_id, vlan_id=item.vlan_id, active=True,
                first_seen=item.observed_at, last_seen=item.observed_at, observed_at=item.observed_at))
        else:
            current.active = True
            current.last_seen = current.observed_at = item.observed_at
    alerts = []
    if removed:
        alerts = emit_for_rules(db, event_type="endpoint.ip.changed", entity_type="endpoint", entity_id=endpoint.id,
            title=f"IP address changed for {endpoint.mac_address}",
            description=f"{', '.join(sorted(set(removed)))} changed to {', '.join(addresses) or 'an explicitly empty address set'}.",
            details={"mac_address": endpoint.mac_address, "previous_ips": sorted(set(removed)),
                "ip_addresses": addresses, "source": item.source.value, "collector_device_id": item.collector_device_id},
            observed_at=item.observed_at, dedup_suffix=f"{item.source.value}:{item.collector_device_id or 'unbound'}:ipv{family}")
    db.flush()
    return len(addresses), alerts


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


def ingest_wireless_snapshot(
    db: Session,
    snapshot: WirelessSnapshot,
    *,
    commit: bool = True,
    principal: PrincipalContext | None = None,
) -> IngestResult:
    # Revalidate service inputs too; model_construct/mutation must not bypass
    # duplicate MAC, measurement, or coherent collection-clock checks.
    snapshot = WirelessSnapshot.model_validate(snapshot.model_dump())
    macs = {client.mac_address for client in snapshot.clients}
    if any(isinstance(row, Endpoint) and row.mac_address in macs
           and (row in db.new or row in db.deleted or db.is_modified(row, include_collections=False))
           for row in (*db.new, *db.dirty, *db.deleted)):
        raise ValueError("Persist pending Endpoint edits before inventory ingestion")
    controller, disposition = admit_snapshot(db, snapshot, principal=principal)
    if disposition != "accepted":
        if commit:
            db.commit()
        return IngestResult(observations_received=len(snapshot.clients), endpoints_created=0,
            endpoints_updated=0, ip_observations_written=0, snapshot_disposition=disposition)

    created = updated = ip_written = sessions_written = sessions_closed = 0
    seen_endpoint_ids: set[str] = set()
    alert_ids: set[str] = set()

    for client in sorted(snapshot.clients, key=lambda row: row.mac_address):
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
        unknown_controller_conditions(db, controller.id, snapshot.observed_at, seen_endpoint_ids=seen_endpoint_ids)
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
                # Do not leave a vanished controller association represented
                # as a current Wi-Fi IP. Other collectors' evidence is retained.
                for address in db.scalars(select(IPAddressObservation).where(
                    IPAddressObservation.endpoint_id == session.endpoint_id,
                    IPAddressObservation.collector_device_id == controller.id,
                    IPAddressObservation.source == ObservationSource.WIFI_CONTROLLER,
                    IPAddressObservation.active.is_(True))).all():
                    address.active = False
                    address.last_seen = snapshot.observed_at

    db.flush()
    if commit:
        db.commit()
    return IngestResult(
        observations_received=len(snapshot.clients),
        endpoints_created=created,
        endpoints_updated=updated,
        ip_observations_written=ip_written,
        wireless_sessions_written=sessions_written,
        sessions_closed=sessions_closed,
        alert_ids=sorted(alert_ids),
        snapshot_disposition=disposition,
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


def endpoint_to_dict(
    endpoint: Endpoint,
    *,
    allowed_device_ids: set[str] | None = None,
) -> dict[str, object]:
    def allowed(device_id: str | None) -> bool:
        return allowed_device_ids is None or (
            device_id is not None and device_id in allowed_device_ids
        )
    quality = {(row.source, row.collector_key, row.dimension): row
        for row in endpoint.network_observation_states if allowed(row.collector_device_id)}

    def network_quality(row, dimension):
        if row.source == ObservationSource.WIFI_CONTROLLER:
            return {}
        state = quality.get((row.source, row.collector_device_id or "unbound", dimension))
        return {"network_observation_state": state.state if state else "legacy_unknown",
            "network_observed_at": state.observed_at if state else row.last_seen,
            "independently_verified": False, "authorizes_incident_closure": False}

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
                **network_quality(row, f"ipv{ipaddress.ip_address(row.ip_address).version}"),
            }
            for row in endpoint.ip_observations
            if row.active and allowed(row.collector_device_id)
        ],
        "current_attachments": [
            {
                "source": row.source,
                "collector_device_id": row.collector_device_id,
                "interface_name": row.interface_name,
                "vlan_id": row.vlan_id,
                "last_seen": row.last_seen,
                **network_quality(row, "attachment"),
            }
            for row in endpoint.attachments
            if row.active and allowed(row.collector_device_id)
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
            if row.active and allowed(row.controller_id)
        ],
    }
