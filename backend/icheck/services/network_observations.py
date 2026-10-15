"""Logical source-local inventory clocks and explicit address-set semantics."""
from __future__ import annotations

import ipaddress
import json
from datetime import timedelta

from sqlalchemy import func, select

from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, require_locking_transaction, session_namespace
from ..models import (Device, Endpoint, EndpointAttachment, IPAddressObservation, NetworkObservationState,
    ObservationSource, new_id, utcnow)
from ..network_binding_schemas import (NetworkObservationV2, NetworkAddressBinding,
    NetworkAttachmentBinding, address_binding_key)
from .alert_conditions import as_utc


def canonical(value):
    pending = [(value, 0, False)]
    ancestors = set()
    nodes = 0
    while pending:
        item, depth, leaving = pending.pop()
        if leaving:
            ancestors.remove(id(item))
            continue
        nodes += 1
        if depth > 32 or nodes > 1_000_000:
            raise ValueError("Network JSON exceeds its depth/node bound")
        if isinstance(item, (dict, list)):
            if id(item) in ancestors:
                raise ValueError("Network JSON cannot contain cycles")
            ancestors.add(id(item))
            pending.append((item, depth, True))
            pending.extend((child, depth+1, False) for child in (item.values() if isinstance(item, dict) else item))
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def channels(item):
    result = {"metadata": {"hostname": item.hostname, "username": item.username, "vendor": item.vendor}}
    if isinstance(item, NetworkObservationV2):
        if item.ip_bindings is not None:
            families = {"ipv4": (4,), "ipv6": (6,), "dual_stack": (4, 6)}[item.ip_family_scope]
            for family in families:
                result[f"ipv{family}"] = {"bindings": [binding.model_dump(mode="json")
                    for binding in item.ip_bindings if ipaddress.ip_address(binding.ip_address).version == family]}
        if item.attachments is not None:
            result["attachment"] = {"attachments": [binding.model_dump(mode="json") for binding in item.attachments],
                "raw_data": item.raw_data}
        return result
    if item.ip_addresses is not None:
        for family in (4, 6):
            result[f"ipv{family}"] = {"addresses": [address for address in item.ip_addresses
                if ipaddress.ip_address(address).version == family], "vlan_id": item.vlan_id}
    elif item.ip_address is not None:
        family = ipaddress.ip_address(item.ip_address).version
        result[f"ipv{family}"] = {"addresses": [item.ip_address], "vlan_id": item.vlan_id}
    if item.collector_device_id is not None or item.interface_name is not None or item.attachment_present is not None:
        result["attachment"] = {"attached": item.attachment_present is not False,
            "interface_name": item.interface_name, "vlan_id": item.vlan_id, "raw_data": item.raw_data}
    return result


def _cohort_body(dimension, value):
    """Interpret only the exact known v1/v2 shapes, without inferring unknowns."""
    if not isinstance(value, dict):
        raise ValueError("Unknown network channel shape")
    if dimension in ("ipv4", "ipv6"):
        if set(value) == {"addresses", "vlan_id"} and isinstance(value["addresses"], list):
            vlan = value["vlan_id"]
            if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094):
                raise ValueError("Invalid legacy address VLAN")
            values = [{"ip_address": address, "vlan_id": value["vlan_id"]} for address in value["addresses"]]
        elif set(value) == {"bindings"} and isinstance(value["bindings"], list):
            values = value["bindings"]
        else:
            raise ValueError("Unknown address channel shape")
        if len(values) > 256:
            raise ValueError("Unbounded address channel")
        bindings = [NetworkAddressBinding.model_validate(item) for item in values]
        if any(ipaddress.ip_address(item.ip_address).version != int(dimension[-1]) for item in bindings):
            raise ValueError("Address channel family mismatch")
        if len({(item.ip_address, item.vlan_id) for item in bindings}) != len(bindings):
            raise ValueError("Duplicate address channel binding")
        return {"bindings": [item.model_dump(mode="json") for item in sorted(bindings, key=address_binding_key)]}
    if dimension == "attachment":
        if set(value) == {"attached", "interface_name", "vlan_id", "raw_data"}:
            if type(value["attached"]) is not bool:
                raise ValueError("Unknown attachment presence")
            vlan = value["vlan_id"]
            if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094):
                raise ValueError("Invalid legacy attachment VLAN")
            if not value["attached"]:
                if value["interface_name"] is not None:
                    raise ValueError("Contradictory legacy detach")
                values = []
            else:
                if value["interface_name"] is None:
                    raise ValueError("An unknown-port observer is not an explicit attachment set")
                values = [{"interface_name": value["interface_name"], "vlan_id": vlan}]
        elif set(value) == {"attachments", "raw_data"} and isinstance(value["attachments"], list):
            values = value["attachments"]
        else:
            raise ValueError("Unknown attachment channel shape")
        if not isinstance(value["raw_data"], dict) or len(values) > 64:
            raise ValueError("Invalid attachment channel")
        bindings = [NetworkAttachmentBinding.model_validate(item) for item in values]
        if len({(item.interface_name, item.vlan_id) for item in bindings}) != len(bindings):
            raise ValueError("Duplicate attachment channel binding")
        return {"attachments": [item.model_dump(mode="json") for item in
            sorted(bindings, key=lambda item: (item.interface_name, item.vlan_id or 0))], "raw_data": value["raw_data"]}
    raise ValueError("Unknown network dimension")


def equivalent_versioned_body(dimension, previous, current):
    """Lost-response retries across versions may compare exact observed sets.

    Within one format, retain the original exact-body comparison. Unknown or
    legacy-unknown history never becomes qualified or manufactured completeness.
    """
    if dimension not in ("ipv4", "ipv6", "attachment"):
        return False
    try:
        old = json.loads(previous)
        marker = "bindings" if dimension.startswith("ipv") else "attachments"
        if not isinstance(old, dict) or (marker in old) == (marker in current):
            return False
        return canonical(_cohort_body(dimension, old)) == canonical(_cohort_body(dimension, current))
    except (ValueError, TypeError, OverflowError, RecursionError):
        return False


def prepare_batch(db, batch, *, principal=None):
    """Reject incoherent input/pending edits before any admission flush."""
    require_locking_transaction(db, purpose="Network inventory ingestion")
    if len(canonical(batch.model_dump(mode="json")).encode()) > 8*1024*1024:
        raise ValueError("Normalized network batch exceeds the eight-MiB bound")
    seen = {}
    for item in batch.observations:
        if item.source == ObservationSource.WIFI_CONTROLLER:
            raise ValueError("Wi-Fi controller observations require the wireless snapshot contract")
        if item.observed_at > utcnow()+timedelta(minutes=5):
            raise ValueError("Network observation exceeds the five-minute future clock bound")
        for dimension, value in channels(item).items():
            body = canonical(value)
            if len(body) > 65536:
                raise ValueError("Network observation channel exceeds the 64-KiB bound")
            key = (item.mac_address, item.source, item.collector_device_id, dimension, item.observed_at)
            if key in seen and seen[key] != body:
                raise ValueError("One network batch cannot assert different values for the same source/channel clock")
            seen[key] = body
    macs = {item.mac_address for item in batch.observations}
    collector_ids = {item.collector_device_id for item in batch.observations if item.collector_device_id is not None}
    with db.no_autoflush:
        endpoint_ids = set(db.scalars(select(Endpoint.id).where(Endpoint.mac_address.in_(macs))))
    for row in (*db.new, *db.dirty, *db.deleted):
        relevant = (isinstance(row, Device) and row.id in collector_ids) or (
            isinstance(row, Endpoint) and row.mac_address in macs) or (
            isinstance(row, (NetworkObservationState, IPAddressObservation, EndpointAttachment)) and row.endpoint_id in endpoint_ids)
        if relevant and (row in db.new or row in db.deleted or db.is_modified(row, include_collections=False)):
            raise ValueError("Persist pending network inventory/source edits before ingestion")
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    with db.no_autoflush:
        for collector_id in sorted(collector_ids):
            collector = db.scalar(select(Device).where(Device.id == collector_id,
                Device.tenant_id == tenant, Device.region_id == region).with_for_update().execution_options(populate_existing=True))
            if collector is None:
                raise LookupError("Network collector device was not found")
            if principal is not None:
                from .authorization_scope import require_device_access
                require_device_access(db, principal, collector.id)
            if not collector.enabled:
                raise ValueError("Network collector device must be enabled")
    if principal is not None and any(item.collector_device_id is None for item in batch.observations):
        from .authorization_scope import has_global_scope
        if not has_global_scope(principal):
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Every scoped observation requires an authorized collector device")


def admit_channel(db, endpoint, item, dimension, value):
    tenant, region = session_namespace(db) or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    collector_key = item.collector_device_id or "unbound"
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise ValueError("Network ordering requires PostgreSQL or SQLite")
    keys = dict(tenant_id=tenant, region_id=region, endpoint_id=endpoint.id,
        source=item.source, collector_key=collector_key, dimension=dimension)
    db.execute(insert(NetworkObservationState).values(**keys, id=new_id(), collector_device_id=item.collector_device_id,
        state="unobserved", payload="", revision=1, created_at=utcnow(), updated_at=utcnow())
        .on_conflict_do_nothing(index_elements=list(keys)))
    state = db.scalar(select(NetworkObservationState).filter_by(**keys).with_for_update().execution_options(populate_existing=True))
    if state is None:
        raise ValueError("Network source is unavailable in this namespace")
    if state.state == "unobserved":
        known = legacy_clock(db, endpoint, item.source, item.collector_device_id, dimension)
        if known is not None:
            state.state, state.observed_at = "legacy_unknown", known
            state.revision += 1
            state.updated_at = utcnow()
            db.flush()
    stamp = as_utc(item.observed_at)
    body = canonical(value)
    if state.observed_at is not None:
        if stamp < as_utc(state.observed_at):
            return "stale"
        if stamp == as_utc(state.observed_at):
            if state.state == "legacy_unknown":
                return "legacy_unknown"
            if state.state == "conflict":
                return "conflict"
            if state.payload == body or equivalent_versioned_body(dimension, state.payload, value):
                return "duplicate"
            state.state = "conflict"
            state.revision += 1
            state.updated_at = utcnow()
            db.flush()
            return "conflict"
    state.state, state.observed_at, state.payload = "accepted", stamp, body
    state.revision += 1
    state.updated_at = utcnow()
    db.flush()
    return "accepted"


def legacy_clock(db, endpoint, source, collector_id, dimension):
    """Retain historical watermarks without inventing accepted bodies."""
    if dimension == "metadata":
        known = [legacy_clock(db, endpoint, source, collector_id, channel) for channel in ("ipv4", "ipv6", "attachment")]
        known = [value for value in known if value is not None]
        # Never attribute the global Endpoint clock to this particular source.
        return max(known) if known else None
    model = EndpointAttachment if dimension == "attachment" else IPAddressObservation
    rows = select(model.observed_at, model.last_seen)
    if model is IPAddressObservation:
        rows = rows.add_columns(model.ip_address)
    rows = rows.where(model.endpoint_id == endpoint.id, model.source == source,
        model.collector_device_id == collector_id).execution_options(yield_per=250)
    latest = None
    for row in db.execute(rows):
        if model is IPAddressObservation and ipaddress.ip_address(row[2]).version != int(dimension[-1]):
            continue
        stamp = max(as_utc(row[0]), as_utc(row[1]))
        latest = stamp if latest is None else max(latest, stamp)
    return latest
