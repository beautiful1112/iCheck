"""Protected configuration custody. Models/tools receive receipts, never bodies."""
from datetime import UTC
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from ..config import get_settings
from ..database import validate_session_namespace
from ..extension_schemas import GeneratedExtensionSpec, EXTENSION_FORMAT
from ..models import (ArtifactVersion, ArtifactVersionStatus, DeviceConnection,
    ExtensionConfigurationBackup, new_id, utcnow)
from .audit import record_audit_event
from .authorization_scope import namespace_clause, require_device_access
from .current_authority import current_human_authority
from .device_credentials import key


def _timestamp(value):
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)).isoformat()


def _aad(row):
    return json.dumps(["icheck.configuration-backup/v1", row.id, row.tenant_id, row.region_id,
        row.artifact_version_id, row.device_id, row.connection_id, row.tool_name, row.sha256,
        row.byte_count, row.created_by, _timestamp(row.created_at)], separators=(",", ":")).encode()


def receipt(row):
    return {"backup_id": row.id, "created_at": _timestamp(row.created_at),
        "sha256": row.sha256, "bytes": row.byte_count}


def store_configuration_backup(db, actor, *, version_id, connection_id, tool_name, target, body):
    """Trusted host callback only; no public upload accepts device configurations."""
    if not actor.permits("assets.read") or not isinstance(body, bytes) or not 1 <= len(body) <= 1_000_000:
        raise PermissionError("Configuration backup custody is not authorized")
    tenant, region = validate_session_namespace(db)
    if (tenant, region) != (actor.tenant_id, actor.region_id):
        raise PermissionError("Configuration backup namespace mismatch")
    target.revalidate()
    device = require_device_access(db, actor, target.device_id)
    db.refresh(device)
    connection = db.scalar(select(DeviceConnection).where(DeviceConnection.id == connection_id,
        DeviceConnection.device_id == device.id, namespace_clause(DeviceConnection, actor))
        .execution_options(populate_existing=True))
    version = db.scalar(select(ArtifactVersion).where(ArtifactVersion.id == version_id,
        namespace_clause(ArtifactVersion, actor)))
    if (connection is None or not connection.enabled or not device.enabled or connection.protocol != "ssh"
            or target.host != device.management_ip or target.port != (connection.port or 22)
            or version is None or version.status not in {ArtifactVersionStatus.VALIDATED, ArtifactVersionStatus.PUBLISHED}
            or version.definition.get("format_version") != EXTENSION_FORMAT):
        raise PermissionError("Reviewed configuration backup target is unavailable")
    spec = GeneratedExtensionSpec.model_validate(version.definition["spec"])
    tool = next((item for item in spec.tools if item.name == tool_name), None)
    if (tool is None or tool.operation != "backup" or tuple(tool.commands) != target.commands
            or spec.device_type != target.device_type):
        raise PermissionError("Reviewed configuration backup tool is unavailable")
    row = ExtensionConfigurationBackup(id=new_id(), tenant_id=tenant, region_id=region,
        artifact_version_id=version.id, device_id=device.id, connection_id=connection.id,
        tool_name=tool.name, sha256=hashlib.sha256(body).hexdigest(), byte_count=len(body),
        created_by=actor.subject, created_at=utcnow())
    nonce = os.urandom(12)
    row.encrypted_body = b"\x01" + nonce + AESGCM(key()).encrypt(nonce, body, _aad(row))
    db.add(row)
    db.flush()
    record_audit_event(db, event_type="extension.configuration.saved", actor_type="user",
        actor_id=actor.subject, entity_type="extension_configuration_backup", entity_id=row.id,
        details={"device_id": row.device_id, "artifact_version_id": version.id, "bytes": row.byte_count})
    return receipt(row)


def download_configuration_backup(db, actor, backup_id):
    # Deliberately not an Agent Tool: even an agent with the initiating user's
    # permissions cannot use an investigation snapshot to retrieve raw configs.
    if not actor.permits("assets.read", "capabilities.manage"):
        raise PermissionError("Configuration downloads require capability-management permission")
    development = (get_settings().control_plane_auth_mode == "disabled"
        and actor.principal_type == "development" and actor.auth_method == "disabled")
    if not development:
        current_human_authority(db, actor, permissions=("assets.read", "capabilities.manage"),
            tenant_id=actor.tenant_id, region_id=actor.region_id)
    row = db.scalar(select(ExtensionConfigurationBackup).where(ExtensionConfigurationBackup.id == backup_id,
        namespace_clause(ExtensionConfigurationBackup, actor)))
    if row is None:
        raise LookupError("Configuration backup not found")
    require_device_access(db, actor, row.device_id)
    raw = row.encrypted_body
    try:
        if raw[:1] != b"\x01" or len(raw) < 30:
            raise ValueError()
        body = AESGCM(key()).decrypt(raw[1:13], raw[13:], _aad(row))
        if len(body) != row.byte_count or hashlib.sha256(body).hexdigest() != row.sha256:
            raise ValueError()
    except (ValueError, InvalidTag):
        raise ValueError("Configuration backup failed its custody check") from None
    record_audit_event(db, event_type="extension.configuration.downloaded", actor_type="user",
        actor_id=actor.subject, entity_type="extension_configuration_backup", entity_id=row.id,
        details={"device_id": row.device_id})
    db.commit()
    return body
