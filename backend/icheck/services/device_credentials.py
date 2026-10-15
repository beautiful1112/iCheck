"""Write-only encrypted device credentials, released only to authorized collectors."""
import json
import os
import stat
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from ..config import get_settings
from ..database import validate_session_namespace
from ..models import CredentialProfile, ManagedDeviceCredential, new_id
from .audit import record_audit_event

ADAPTERS = {"snmp_v2c": ["snmp_exporter", "snmp_topology"], "windows_password": ["psrp_cim"],
            "https_token": ["http_json", "http_json_sandbox", "node_exporter", "windows_exporter", "cadvisor", "vmware_exporter"],
            "http_basic": ["http_json", "http_json_sandbox", "node_exporter", "windows_exporter", "cadvisor", "vmware_exporter"],
            "ssh_password": ["ssh", "ssh_command_sandbox"], "ssh_key": ["ssh", "ssh_command_sandbox"]}
# Rotating an existing HTTP credential never silently expands its consumers.
# Pre-exporter profiles remain valid with their original, exact adapter scope.
LEGACY_HTTP_ADAPTERS = ["http_json", "http_json_sandbox"]
PRIOR_HTTP_SCOPES = [LEGACY_HTTP_ADAPTERS, ["http_json", "http_json_sandbox", "node_exporter", "windows_exporter"],
    ["http_json", "http_json_sandbox", "node_exporter", "windows_exporter", "cadvisor"]]


class DeviceCredentialUnavailable(ValueError):
    pass


def key():
    path = get_settings().device_managed_secret_key_file
    if not path or not Path(path).is_absolute():
        raise DeviceCredentialUnavailable("Managed device credential storage is not provisioned")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o440}):
                raise DeviceCredentialUnavailable("Device credential key custody is unsafe")
            value = handle.read(33)
    except OSError:
        raise DeviceCredentialUnavailable("Device credential key is unavailable") from None
    if len(value) != 32:
        raise DeviceCredentialUnavailable("Device credential key is invalid")
    return value


def aad(row):
    return json.dumps(["icheck.managed-device/v1", row.id, row.tenant_id, row.region_id,
                       row.credential_profile_id, row.kind, row.site, row.revision], separators=(",", ":")).encode()


def secret_values(payload):
    return {k: (v.get_secret_value() if hasattr(v, "get_secret_value") else v)
            for k in ("username", "community", "password", "token", "private_key", "private_key_passphrase")
            if (v := getattr(payload, k)) is not None}


def encrypt(row, payload):
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(key()).encrypt(nonce, json.dumps(secret_values(payload)).encode(), aad(row))


def profile(db, reference, *, lock=False):
    q = select(CredentialProfile).where(or_(CredentialProfile.id == reference, CredentialProfile.name == reference)).execution_options(populate_existing=True)
    return db.scalar(q.with_for_update() if lock else q)


def read(row, p):
    return {"id": p.id, "name": p.name, "kind": row.kind, "site": row.site,
            "revision": row.revision, "enabled": p.enabled, "allowed_adapters": p.allowed_adapters}


def list_credentials(db):
    return [read(row, p) for row, p in db.execute(select(ManagedDeviceCredential, CredentialProfile)
        .join(CredentialProfile, CredentialProfile.id == ManagedDeviceCredential.credential_profile_id)
        .order_by(CredentialProfile.name))]


def create(db, payload, actor):
    tenant, region = validate_session_namespace(db)
    key()
    p = CredentialProfile(id=new_id(), name=payload.name, provider="managed_device",
        secret_ref="managed-device://" + new_id(), allowed_adapters=ADAPTERS[payload.kind],
        worker_selector={"site": payload.site}, enabled=True, revision=1, created_by=actor)
    row = ManagedDeviceCredential(id=p.secret_ref.removeprefix("managed-device://"), credential_profile_id=p.id,
        kind=payload.kind, site=payload.site, revision=1, tenant_id=tenant, region_id=region)
    row.encrypted_secret = encrypt(row, payload)
    try:
        db.add(p); db.flush(); db.add(row); db.flush()
        record_audit_event(db, event_type="credential.device.created", actor_type="user", actor_id=actor,
            entity_type="credential_profile", entity_id=p.id, details={"kind": row.kind, "site": row.site, "revision": 1})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ValueError("Credential profile name already exists") from None
    return read(row, p)


def update(db, profile_id, payload, actor, *, revoke=False):
    p = profile(db, profile_id, lock=True)
    row = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == profile_id).with_for_update())
    if p is None or row is None:
        raise LookupError("Managed device credential not found")
    if row.revision != payload.expected_revision:
        raise ValueError("Credential changed; refresh before updating")
    values = resolve(db, p, allow_disabled=True)  # Authenticate existing custody before revising it.
    if not revoke and (payload.name != p.name or payload.kind != row.kind or payload.site != row.site):
        raise ValueError("Credential name, kind and site are immutable; create a new profile instead")
    row.revision += 1
    nonce = os.urandom(12)
    row.encrypted_secret = (b"\x01" + nonce + AESGCM(key()).encrypt(nonce, json.dumps(values).encode(), aad(row))
                           if revoke else encrypt(row, payload))
    p.revision += 1
    p.enabled = False if revoke else payload.enabled
    record_audit_event(db, event_type="credential.device.revoked" if revoke else "credential.device.rotated",
        actor_type="user", actor_id=actor, entity_type="credential_profile", entity_id=p.id,
        details={"revision": row.revision, "enabled": p.enabled, "reason": payload.reason})
    db.commit()
    return read(row, p)


def resolve(db, p, *, allow_disabled=False):
    row = db.scalar(select(ManagedDeviceCredential).where(ManagedDeviceCredential.credential_profile_id == p.id))
    if (row is None or p.provider != "managed_device" or (not p.enabled and not allow_disabled) or p.secret_ref != "managed-device://" + row.id
            or p.worker_selector != {"site": row.site}
            or (p.allowed_adapters != ADAPTERS[row.kind] and not (
                row.kind in {"https_token", "http_basic"} and p.allowed_adapters in PRIOR_HTTP_SCOPES))
            or p.revision != row.revision):
        raise DeviceCredentialUnavailable("Managed device credential binding is unavailable")
    raw = row.encrypted_secret
    try:
        if raw[:1] != b"\x01" or len(raw) < 30:
            raise ValueError()
        result = json.loads(AESGCM(key()).decrypt(raw[1:13], raw[13:], aad(row)))
    except (InvalidTag, ValueError, UnicodeError):
        raise DeviceCredentialUnavailable("Managed device credential cannot be decrypted") from None
    if not isinstance(result, dict) or not all(isinstance(v, str) for v in result.values()):
        raise DeviceCredentialUnavailable("Managed device credential payload is invalid")
    return result
