from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from .database import SessionLocal, init_db, set_session_namespace
from .builtin_artifacts import (
    ensure_psrp_cim_artifact,
    ensure_snmp_exporter_artifact,
    ensure_snmp_topology_artifact,
    ensure_windows_exporter_artifact,
)
from .builtin_activation_policies import ensure_builtin_activation_policies
from .builtin_agent_tools import ensure_builtin_agent_tools
from .models import AlertSeverity, Device
from .schemas import (
    AlertEvent,
    NetworkObservation,
    NetworkObservationBatch,
    WirelessClientObservation,
    WirelessSnapshot,
)
from .services.alerts import ensure_default_rules, upsert_alert
from .services.control_plane_auth import ensure_builtin_roles
from .services.inventory import ingest_network_observations, ingest_wireless_snapshot
from .services.tenancy import ensure_default_namespace


def seed() -> None:
    init_db()
    with SessionLocal() as db:
        tenant, region = ensure_default_namespace(db)
        set_session_namespace(db, tenant.id, region.id)
        ensure_default_rules(db)
        ensure_builtin_roles(db)
        snmp_artifact = ensure_snmp_exporter_artifact(db)
        snmp_topology_artifact = ensure_snmp_topology_artifact(db)
        windows_exporter_artifact = ensure_windows_exporter_artifact(db)
        psrp_cim_artifact = ensure_psrp_cim_artifact(db)
        ensure_builtin_activation_policies(
            db,
            snmp_artifact=snmp_artifact,
            snmp_topology_artifact=snmp_topology_artifact,
            windows_exporter_artifact=windows_exporter_artifact,
            psrp_cim_artifact=psrp_cim_artifact,
        )
        ensure_builtin_agent_tools(db)
        if (db.scalar(select(func.count()).select_from(Device)) or 0) > 0:
            return

        devices = [
            Device(
                name="core-hk-01",
                kind="switch",
                management_ip="10.0.0.11",
                vendor="Cisco",
                model="C9500",
                site="Hong Kong",
            ),
            Device(
                name="wlc-hk-01",
                kind="wireless_controller",
                management_ip="10.0.0.21",
                vendor="Cisco",
                model="Catalyst 9800",
                site="Hong Kong",
            ),
            Device(
                name="edge-sg-01",
                kind="router",
                management_ip="10.1.0.11",
                vendor="Arista",
                model="7280R3",
                site="Singapore",
            ),
            Device(
                name="win-app-01",
                kind="windows_server",
                management_ip="10.20.7.42",
                vendor="Dell",
                model="PowerEdge R760",
                site="Hong Kong",
            ),
        ]
        db.add_all(devices)
        db.commit()

        now = datetime.now(UTC)
        ingest_network_observations(
            db,
            NetworkObservationBatch(
                observations=[
                    NetworkObservation(
                        mac_address="00:1b:44:11:3a:b7",
                        ip_address="10.20.17.21",
                        source="arp",
                        collector_device_id=devices[0].id,
                        interface_name="Vlan120",
                        vlan_id=120,
                        hostname="ops-laptop-17",
                        username="alex.chen",
                        vendor="Lenovo",
                        observed_at=now - timedelta(minutes=2),
                    ),
                    NetworkObservation(
                        mac_address="6c:4b:90:8d:2c:11",
                        ip_address="10.20.40.88",
                        source="mac_table",
                        collector_device_id=devices[0].id,
                        interface_name="TenGigabitEthernet1/0/18",
                        vlan_id=140,
                        hostname="warehouse-scanner-08",
                        vendor="Zebra",
                        observed_at=now - timedelta(minutes=4),
                    ),
                ]
            ),
        )

        ingest_wireless_snapshot(
            db,
            WirelessSnapshot(
                controller_id=devices[1].id,
                observed_at=now,
                clients=[
                    WirelessClientObservation(
                        mac_address="a4:83:e7:10:2f:91",
                        ip_address="10.20.31.54",
                        hostname="mira-iphone",
                        username="mira.patel",
                        vendor="Apple",
                        access_point="AP-HK-17F-03",
                        ssid="CORP",
                        band="5 GHz",
                        channel=44,
                        vlan_id=131,
                        rssi=-82,
                        snr=13,
                        observed_at=now,
                    ),
                    WirelessClientObservation(
                        mac_address="38:f9:d3:2b:a1:06",
                        ip_address="10.20.31.72",
                        hostname="finance-mbp-04",
                        username="sam.wong",
                        vendor="Apple",
                        access_point="AP-HK-18F-01",
                        ssid="CORP",
                        band="6 GHz",
                        channel=69,
                        vlan_id=131,
                        rssi=-51,
                        snr=36,
                        observed_at=now,
                    ),
                ],
            ),
        )

        upsert_alert(
            db,
            dedup_key="demo:core-uplink-errors",
            event_type="interface.errors.high",
            severity=AlertSeverity.CRITICAL,
            title="Core uplink error rate rising",
            description="CRC errors on core-hk-01 Te1/0/48 exceeded the operational baseline.",
            entity_type="device",
            entity_id=devices[0].id,
            details={"interface": "Te1/0/48", "crc_errors": 14839, "site": "Hong Kong"},
            observed_at=now - timedelta(minutes=7),
        )
        db.commit()


if __name__ == "__main__":
    seed()
