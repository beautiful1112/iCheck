"""Normalize complete bounded SNMP table reads into inventory observations.

FDB IDs are not VLAN IDs. Bridge ports are not ifIndex values. Missing mappings
are reported as errors rather than inventing endpoint attachment information.
No raw per-MAC samples are exported to Prometheus by this adapter mode.
"""
from collections import defaultdict
import ipaddress
import math
import re

from ..network_binding_schemas import NETWORK_OBSERVATION_V2, NetworkObservationFieldsV2
from ..schemas import normalize_mac


def _integer(value, name):
    try:
        number = float(value)
        if not math.isfinite(number) or not number.is_integer() or number < 0:
            raise ValueError()
        return int(number)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"SNMP inventory {name} must be a nonnegative integer") from None


def _mac(value):
    if not isinstance(value, str):
        raise ValueError("SNMP inventory MAC address is missing")
    value = value.removeprefix("0x").removeprefix("0X")
    mac = normalize_mac(value)
    octets = bytes.fromhex(mac.replace(":", ""))
    if not any(octets) or octets[0] & 1:
        return None  # Incomplete/multicast/broadcast rows are not endpoints.
    return mac


def _put(mapping, key, value, name):
    if key in mapping and mapping[key] != value:
        raise ValueError(f"SNMP inventory has conflicting {name} mappings")
    mapping[key] = value


def normalize_tables(samples, *, target, source, context_vlan=None, max_endpoints=2000):
    if context_vlan is not None and (type(context_vlan) is not int or not 1 <= context_vlan <= 4094):
        raise ValueError("A reviewed VLAN context must be between 1 and 4094")
    if type(max_endpoints) is not int or not 1 <= max_endpoints <= 2000 or len(samples) > 20000:
        raise ValueError("SNMP inventory sample/endpoint limit exceeded")
    by_name = defaultdict(list)
    for envelope in samples:
        payload = envelope.get("payload", {})
        by_name[payload.get("metric")].append((payload.get("labels", {}), payload.get("value"), envelope.get("observed_at")))
    # The exporter completes its walk before returning this bounded snapshot.
    if not by_name.get("snmp_scrape_walk_duration_seconds"):
        raise ValueError("SNMP inventory requires exporter walk-completion evidence")
    names, bridge_ports, vlans = {}, {}, defaultdict(set)
    for labels, _, _ in by_name["ifName"]:
        name = labels.get("ifName")
        if not isinstance(name, str) or not name or len(name) > 255:
            raise ValueError("SNMP inventory interface name is missing")
        _put(names, str(_integer(labels.get("ifIndex"), "ifIndex")), name, "interface")
    for labels, value, _ in by_name["dot1dBasePortIfIndex"]:
        _put(bridge_ports, str(_integer(labels.get("dot1dBasePort"), "bridge port")),
             str(_integer(value, "ifIndex")), "bridge port")
    for labels, value, _ in by_name["dot1qVlanFdbId"]:
        vlan = _integer(labels.get("dot1qVlanIndex"), "VLAN index")
        if not 1 <= vlan <= 4094:
            raise ValueError("SNMP inventory VLAN index is out of range")
        vlans[str(_integer(value, "FDB ID"))].add(vlan)
    addresses, attachments, stamps = defaultdict(set), defaultdict(set), {}
    # Preserve all observed IPs for a MAC within the same collector and family;
    # do not join observations across devices or invent a VRF/VLAN association.
    for family, metric, mac_label, ip_label, state_metric, rejected in (
        ("ipv4", "ipNetToMediaPhysAddress", "ipNetToMediaPhysAddress", "ipNetToMediaNetAddress", "ipNetToMediaType", {2}),
        ("dual_stack", "ipNetToPhysicalPhysAddress", "ipNetToPhysicalPhysAddress", "ipNetToPhysicalNetAddress", "ipNetToPhysicalState", {5, 6, 7}),
    ):
        state = {}
        interface_label = "ipNetToMediaIfIndex" if family == "ipv4" else "ipNetToPhysicalIfIndex"
        for labels, value, _ in by_name[state_metric]:
            key = (labels.get(interface_label), labels.get(ip_label))
            _put(state, key, _integer(value, "neighbor state"), "neighbor state")
        for labels, _, stamp in by_name[metric]:
            key = (labels.get(interface_label), labels.get(ip_label))
            if state.get(key) in rejected:
                continue
            mac = _mac(labels.get(mac_label))
            if mac is None:
                continue
            try:
                address = ipaddress.ip_address(labels[ip_label])
            except (ValueError, KeyError):
                raise ValueError("SNMP inventory neighbor address is invalid") from None
            if address.is_multicast or address.is_unspecified or (family == "ipv4" and address.version != 4):
                continue
            addresses[mac].add((str(address), context_vlan))
            stamps[("arp", mac)] = stamp
    for metric, address_label, fdb_label, status_metric in (
        ("dot1dTpFdbPort", "dot1dTpFdbAddress", None, "dot1dTpFdbStatus"),
        ("dot1qTpFdbPort", "dot1qTpFdbAddress", "dot1qFdbId", "dot1qTpFdbStatus"),
    ):
        statuses = {}
        for labels, value, _ in by_name[status_metric]:
            _put(statuses, (labels.get(address_label), labels.get(fdb_label)), _integer(value, "FDB state"), "FDB state")
        for labels, value, stamp in by_name[metric]:
            if statuses.get((labels.get(address_label), labels.get(fdb_label))) in {2, 4}:
                continue  # invalid / self, not a learned endpoint attachment
            mac = _mac(labels.get(address_label))
            port = str(_integer(value, "FDB bridge port"))
            if mac is None or port == "0":
                continue
            if port not in bridge_ports or bridge_ports[port] not in names:
                raise ValueError("MAC table requires bridge-port to ifIndex to ifName mapping")
            selected_vlans = {context_vlan}
            if fdb_label:
                fdb = str(_integer(labels.get(fdb_label), "FDB ID"))
                if len(vlans[fdb]) != 1:
                    raise ValueError("Q-BRIDGE FDB ID needs an unambiguous observed VLAN mapping; it is not a VLAN ID")
                selected_vlans = vlans[fdb]
            for vlan in selected_vlans:
                attachments[mac].add((names[bridge_ports[port]], vlan))
            stamps[("mac_table", mac)] = stamp
    if len(set(addresses) | set(attachments)) > max_endpoints:
        raise ValueError("SNMP inventory endpoint limit exceeded; no partial snapshot was emitted")
    result = []
    for kind, rows in (("arp", addresses), ("mac_table", attachments)):
        for mac, values in sorted(rows.items()):
            payload = {"mac_address": mac, "source": kind,
                       "raw_data": {"snmp_table_snapshot": True, "vlan_context": context_vlan}}
            if kind == "arp":
                payload.update(ip_family_scope="dual_stack" if by_name["ipNetToPhysicalPhysAddress"] else "ipv4",
                    ip_bindings=[{"ip_address": address, "vlan_id": vlan} for address, vlan in sorted(values, key=str)])
            else:
                payload["attachments"] = [{"interface_name": interface, "vlan_id": vlan} for interface, vlan in sorted(values, key=str)]
            payload = NetworkObservationFieldsV2.model_validate(payload).model_dump(mode="json", exclude_none=True)
            result.append({"kind": "observation", "type": NETWORK_OBSERVATION_V2, "source": source,
                "subject": mac, "observed_at": stamps[(kind, mac)], "payload": payload, "idempotency_key": None})
    return result
