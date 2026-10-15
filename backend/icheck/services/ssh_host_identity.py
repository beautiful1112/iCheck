"""Human-confirmed SSH identity on the existing connection, without passwords.

Discovery performs a bounded SSH key exchange only. It is not authentication or
proof of ownership. A human explicitly trusts the displayed fingerprint; saved
keys remain strictly checked by the existing Netmiko runtime. No auto-add policy.
"""
import base64
import hashlib
import json
import socket

from sqlalchemy import select

from ..models import Device, DeviceConnection, utcnow
from ..ssh_compatibility import (CONFIG_KEY as PROFILE_KEY, LEGACY, MODERN, TARGET_FIELDS, transport_factory)
from .audit import record_audit_event
from .authorization_scope import namespace_clause
from .managed_extensions import (
    ExtensionReviewConflict, _connection_binding, _current_actor, _public_key, human,
)

CONFIG_KEY = "studio_ssh_identity"
IDENTITY_FIELDS = ("device_id", "connection_id", "host", "port", "identity_revision")


def fingerprint(key):
    blob = base64.b64decode(_public_key(key).split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _record(db, binding):
    connection = db.get(DeviceConnection, binding["connection_id"])
    value = connection.configuration.get(CONFIG_KEY)
    return value if isinstance(value, dict) else None


def _matches(record, binding):
    return all(record.get(field) == binding[field] for field in IDENTITY_FIELDS)


def saved_key(db, binding):
    record = _record(db, binding)
    if not record:
        return None
    if not _matches(record, binding):
        raise ExtensionReviewConflict("SSH target identity changed; read and confirm its fingerprint again")
    return _public_key(record["host_public_key"])


def _digest(binding):
    return hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()


def _view(db, binding, observed=None):
    record = _record(db, binding)
    saved = _public_key(record["host_public_key"]) if record else None
    current = bool(record and _matches(record, binding))
    state = ("confirmed" if current else "target_changed") if record else "unconfirmed"
    if observed:
        state = "matches" if current and observed == saved else "changed" if record else "first_use"
    return {"connection_id": binding["connection_id"], "host": binding["host"], "port": binding["port"],
        "ssh_profile": binding["ssh_profile"], "ssh_profile_current": binding["ssh_profile_current"],
        "state": state, "binding_hash": _digest(binding),
        "host_public_key": observed or (saved if current else None),
        "fingerprint": fingerprint(observed or saved) if observed or saved else None,
        "saved_fingerprint": fingerprint(saved) if saved else None,
        "confirmed_at": record.get("confirmed_at") if record else None}


def status(db, actor, connection_id):
    human(db, actor)
    return _view(db, _connection_binding(db, actor, connection_id))


def read_public_key(host, port, profile=MODERN):
    """Literal inventory IP only; no credentials, SSH agent or shell channel."""
    factory = transport_factory(profile)
    with socket.create_connection((host, port), timeout=5) as sock:
        transport = factory(sock)
        try:
            transport.banner_timeout = 5
            transport.start_client(timeout=8)
            key = transport.get_remote_server_key()
            return _public_key(f"{key.get_name()} {key.get_base64()}")
        finally:
            transport.close()


def probe(db, actor, connection_id):
    from paramiko.ssh_exception import IncompatiblePeer
    human(db, actor)
    binding = _connection_binding(db, actor, connection_id)
    if not binding["ssh_profile_current"]:
        raise ExtensionReviewConflict("SSH target changed; review and save its compatibility profile again")
    # Release the read transaction across network I/O; no locks or credentials
    # are retained. Current authority and exact context are checked afterward.
    db.commit()
    try:
        observed = read_public_key(binding["host"], binding["port"], binding["ssh_profile"])
    except IncompatiblePeer:
        raise ExtensionReviewConflict("SSH algorithms do not match this device. Review its SSH compatibility profile; no login was attempted.") from None
    except Exception:
        raise ExtensionReviewConflict("Could not read the SSH fingerprint. Check the address, port and SSH service; no login was attempted.") from None
    _current_actor(db, actor, binding["device_id"])
    if _connection_binding(db, actor, connection_id) != binding:
        raise ExtensionReviewConflict("Target or credential changed during discovery; refresh and try again")
    return _view(db, binding, observed)


def change_profile(db, actor, connection_id, payload):
    """Human-only, exact-target exception. Does not connect, trust or authenticate."""
    human(db, actor)
    before = _connection_binding(db, actor, connection_id)
    device = db.scalar(select(Device).where(Device.id == before["device_id"], namespace_clause(Device, actor))
        .with_for_update().execution_options(populate_existing=True))
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        namespace_clause(DeviceConnection, actor)).with_for_update().execution_options(populate_existing=True))
    binding = _connection_binding(db, actor, connection_id)
    if payload.binding_hash != _digest(binding):
        raise ExtensionReviewConflict("Target or SSH settings changed; refresh before saving the profile")
    if payload.profile == LEGACY and not payload.accept_legacy_risk:
        raise ExtensionReviewConflict("Explicitly accept legacy SSH risk for this device before enabling compatibility")
    if payload.profile == binding["ssh_profile"] and binding["ssh_profile_current"]:
        return _view(db, binding)
    connection.configuration = {**connection.configuration, PROFILE_KEY: {
        **{field: binding[field] for field in TARGET_FIELDS}, "profile": payload.profile,
        "selected_by": actor.subject, "selected_at": utcnow().isoformat()}}
    device.revision += 1
    record_audit_event(db, event_type="device.ssh_compatibility.changed", actor_type="user", actor_id=actor.subject,
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "previous_profile": binding["ssh_profile"],
            "profile": payload.profile, "accepted_legacy_risk": payload.accept_legacy_risk,
            "login_attempted": False})
    db.commit()
    return _view(db, _connection_binding(db, actor, connection_id))


def confirm(db, actor, connection_id, payload):
    human(db, actor)
    before = _connection_binding(db, actor, connection_id)
    # Same device-first lock order as inventory changes. No SSH I/O while locked.
    device = db.scalar(select(Device).where(Device.id == before["device_id"], namespace_clause(Device, actor))
        .with_for_update().execution_options(populate_existing=True))
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        namespace_clause(DeviceConnection, actor)).with_for_update().execution_options(populate_existing=True))
    binding = _connection_binding(db, actor, connection_id)
    if payload.binding_hash != _digest(binding):
        raise ExtensionReviewConflict("Device, credential or saved identity changed; refresh and review the fingerprint again")
    key = _public_key(payload.host_public_key)
    record = _record(db, binding)
    changed = bool(record and (not _matches(record, binding) or record.get("host_public_key") != key))
    if changed and not payload.accept_changed:
        raise ExtensionReviewConflict("SSH identity changed. Explicitly confirm the replacement fingerprint")
    if record and not changed:
        return _view(db, binding)
    connection.configuration = {**connection.configuration, CONFIG_KEY: {
        **{field: binding[field] for field in IDENTITY_FIELDS}, "host_public_key": key,
        "confirmed_at": utcnow().isoformat(), "confirmed_by": actor.subject}}
    device.revision += 1
    record_audit_event(db, event_type="device.ssh_identity.confirmed", actor_type="user", actor_id=actor.subject,
        entity_type="device_connection", entity_id=connection.id,
        details={"device_id": device.id, "fingerprint": fingerprint(key), "replacement": changed,
            "trust_method": "human_confirmation", "login_attempted": False})
    db.commit()
    return _view(db, _connection_binding(db, actor, connection_id))
