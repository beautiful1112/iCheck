from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AgentToolRegistration,
    Investigation,
    InvestigationToolCall,
    Situation,
    SituationIntegrationBinding,
    SituationIntegrationEvent,
    SituationIntegrationInboundEvent,
    SituationIntegrationRemoteReference,
    utcnow,
)
from ..workflow_runtime_schemas import (
    SituationIntegrationInboundPayload,
    SituationIntegrationWebhookAck,
)
from .audit import record_audit_event
from .situations import append_situation_event


MAX_WEBHOOK_BYTES = 65_536
WEBHOOK_CLOCK_SKEW = timedelta(minutes=5)
REMOTE_REFERENCE_FIELDS = {"remote_id", "remote_url", "remote_status"}


class WebhookAuthenticationError(ValueError):
    pass


class WebhookConflictError(ValueError):
    pass


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _public_key(value: str) -> Ed25519PublicKey:
    try:
        loaded = serialization.load_pem_public_key(value.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Inbound public key is not valid PEM") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Inbound public key must be Ed25519")
    return loaded


def validate_inbound_public_key(value: str) -> str:
    raw = _public_key(value).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _schema_at_path(schema: dict[str, Any], path: str) -> dict[str, Any]:
    current: Any = schema
    for part in path.split("."):
        if not part or len(part) > 128 or not isinstance(current, dict):
            raise ValueError(f"Remote reference path {path!r} is invalid")
        properties = current.get("properties")
        if not isinstance(properties, dict) or part not in properties:
            raise ValueError(
                f"Remote reference path {path!r} is absent from Tool output schema"
            )
        current = properties[part]
    if not isinstance(current, dict):
        raise ValueError(f"Remote reference path {path!r} is invalid")
    value_type = current.get("type")
    accepts_string = value_type == "string" or (
        isinstance(value_type, list) and "string" in value_type
    )
    if not accepts_string:
        raise ValueError(f"Remote reference path {path!r} must resolve to a string")
    return current


def validate_remote_reference_contract(
    db: Session,
    *,
    dependencies: list[dict[str, Any]],
    tool_name: str | None,
    mapping: dict[str, str],
) -> None:
    if tool_name is None:
        if mapping:
            raise ValueError("Remote reference mapping requires a Tool")
        return
    if set(mapping) - REMOTE_REFERENCE_FIELDS:
        raise ValueError("Remote reference mapping contains unsupported fields")
    if "remote_id" not in mapping:
        raise ValueError("Remote reference mapping requires remote_id")
    dependency = next(
        (item for item in dependencies if item.get("name") == tool_name), None
    )
    if dependency is None or dependency.get("transport") != "mcp":
        raise ValueError("Remote reference Tool must be a pinned MCP dependency")
    tool = db.scalar(
        select(AgentToolRegistration).where(
            AgentToolRegistration.name == tool_name,
            AgentToolRegistration.enabled.is_(True),
            AgentToolRegistration.transport == "mcp",
        )
    )
    if tool is None:
        raise ValueError("Remote reference Tool is unavailable")
    for path in mapping.values():
        _schema_at_path(tool.output_schema, path)


def _extract_path(document: Any, path: str) -> Any:
    current = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"Remote reference result path {path!r} is missing")
        current = current[part]
    return current


def _optional_string(value: Any, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} is empty or too long")
    return normalized


def _safe_remote_url(value: Any) -> str | None:
    normalized = _optional_string(value, "remote_url", 2048)
    if normalized is None:
        return None
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "remote_url must be an HTTP(S) URL without credentials, query, or fragment"
        )
    return normalized


def sync_situation_integration_remote_reference(
    db: Session,
    investigation: Investigation,
    *,
    actor: str,
) -> SituationIntegrationRemoteReference | None:
    if (
        investigation.status != "completed"
        or not investigation.situation_integration_event_id
    ):
        return None
    integration_event = db.get(
        SituationIntegrationEvent, investigation.situation_integration_event_id
    )
    if integration_event is None:
        raise LookupError("Situation integration event not found")
    binding = db.get(SituationIntegrationBinding, integration_event.binding_id)
    if binding is None:
        raise LookupError("Situation integration binding not found")
    if not binding.remote_reference_tool_name:
        return None
    existing = db.scalar(
        select(SituationIntegrationRemoteReference).where(
            SituationIntegrationRemoteReference.integration_event_id
            == integration_event.id
        )
    )
    calls = list(
        db.scalars(
            select(InvestigationToolCall)
            .join(
                AgentToolRegistration,
                AgentToolRegistration.id == InvestigationToolCall.tool_id,
            )
            .where(
                InvestigationToolCall.investigation_id == investigation.id,
                InvestigationToolCall.status == "succeeded",
                AgentToolRegistration.name == binding.remote_reference_tool_name,
            )
            .order_by(InvestigationToolCall.finished_at, InvestigationToolCall.id)
        ).all()
    )
    if len(calls) != 1:
        raise ValueError(
            "Remote reference contract requires exactly one successful producing Tool call"
        )
    call = calls[0]
    mapping = dict(binding.remote_reference_mapping or {})
    values = {
        target: _extract_path(call.result, path)
        for target, path in mapping.items()
    }
    remote_id = _optional_string(values.get("remote_id"), "remote_id", 255)
    if remote_id is None:
        raise ValueError("remote_id is required")
    remote_url = _safe_remote_url(values.get("remote_url"))
    remote_status = _optional_string(
        values.get("remote_status"), "remote_status", 128
    )
    if existing is not None:
        if (
            existing.remote_id == remote_id
            and existing.remote_url == remote_url
            and existing.remote_status == remote_status
            and existing.source_tool_call_id == call.id
        ):
            return existing
        raise ValueError("Remote reference replay conflicts with stored identity")

    situation = db.scalar(
        select(Situation)
        .where(Situation.id == integration_event.situation_id)
        .with_for_update()
    )
    if situation is None:
        raise LookupError("Situation not found")
    reference = SituationIntegrationRemoteReference(
        integration_event_id=integration_event.id,
        binding_id=binding.id,
        situation_id=situation.id,
        investigation_id=investigation.id,
        provider_key=binding.provider_key,
        remote_id=remote_id,
        remote_url=remote_url,
        remote_status=remote_status,
        remote_updated_at=call.finished_at,
        source_tool_call_id=call.id,
    )
    db.add(reference)
    db.flush()
    append_situation_event(
        db,
        situation,
        event_type="situation.external_reference_linked",
        actor=actor,
        details={
            "reference_id": reference.id,
            "provider_key": reference.provider_key,
            "remote_id": reference.remote_id,
            "remote_status": reference.remote_status,
            "integration_event_id": integration_event.id,
            "source_tool_call_id": call.id,
        },
    )
    record_audit_event(
        db,
        event_type="situation.integration.remote_reference_linked",
        actor_type="agent",
        actor_id=actor,
        entity_type="situation_integration_remote_reference",
        entity_id=reference.id,
        details={
            "binding_id": binding.id,
            "situation_id": situation.id,
            "investigation_id": investigation.id,
            "provider_key": reference.provider_key,
            "remote_id_sha256": hashlib.sha256(
                remote_id.encode("utf-8")
            ).hexdigest(),
            "source_tool_call_id": call.id,
        },
    )
    return reference


def _verify_signature(
    binding: SituationIntegrationBinding,
    *,
    raw_body: bytes,
    timestamp: str,
    provider_event_id: str,
    key_id: str,
    signature: str,
) -> tuple[str, str]:
    if (
        not binding.enabled
        or not binding.inbound_enabled
        or not binding.inbound_public_key_pem
    ):
        raise WebhookAuthenticationError("Inbound reconciliation is disabled")
    if not binding.inbound_key_id or not secrets.compare_digest(
        binding.inbound_key_id, key_id
    ):
        raise WebhookAuthenticationError("Webhook key is not recognized")
    try:
        timestamp_value = int(timestamp)
        signed_at = datetime.fromtimestamp(timestamp_value, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise WebhookAuthenticationError("Webhook timestamp is invalid") from exc
    if abs(utcnow() - signed_at) > WEBHOOK_CLOCK_SKEW:
        raise WebhookAuthenticationError("Webhook timestamp is outside the allowed window")
    if not provider_event_id or len(provider_event_id) > 255:
        raise WebhookAuthenticationError("Webhook event ID is invalid")
    if len(raw_body) > MAX_WEBHOOK_BYTES:
        raise WebhookAuthenticationError("Webhook payload exceeds the size limit")
    payload_sha256 = hashlib.sha256(raw_body).hexdigest()
    material = f"{timestamp}\n{provider_event_id}\n{payload_sha256}".encode("utf-8")
    encoded_signature = signature[3:] if signature.startswith("v1=") else signature
    try:
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
        _public_key(binding.inbound_public_key_pem).verify(
            signature_bytes, material
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise WebhookAuthenticationError("Webhook signature is invalid") from exc
    return payload_sha256, hashlib.sha256(signature_bytes).hexdigest()


def reconcile_situation_webhook(
    db: Session,
    binding: SituationIntegrationBinding,
    *,
    raw_body: bytes,
    timestamp: str,
    provider_event_id: str,
    key_id: str,
    signature: str,
) -> SituationIntegrationWebhookAck:
    payload_sha256, signature_sha256 = _verify_signature(
        binding,
        raw_body=raw_body,
        timestamp=timestamp,
        provider_event_id=provider_event_id,
        key_id=key_id,
        signature=signature,
    )
    locked_binding = db.scalar(
        select(SituationIntegrationBinding)
        .where(SituationIntegrationBinding.id == binding.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked_binding is None:
        raise LookupError("Situation integration binding not found")
    binding = locked_binding
    payload_sha256, signature_sha256 = _verify_signature(
        binding,
        raw_body=raw_body,
        timestamp=timestamp,
        provider_event_id=provider_event_id,
        key_id=key_id,
        signature=signature,
    )
    try:
        payload = SituationIntegrationInboundPayload.model_validate_json(raw_body)
    except ValidationError as exc:
        raise ValueError("Webhook payload does not match the inbound contract") from exc
    if payload.provider_event_id != provider_event_id:
        raise WebhookAuthenticationError("Webhook event ID does not match its payload")
    if _as_utc(payload.remote_updated_at) > utcnow() + WEBHOOK_CLOCK_SKEW:
        raise ValueError("remote_updated_at is too far in the future")

    existing = db.scalar(
        select(SituationIntegrationInboundEvent).where(
            SituationIntegrationInboundEvent.binding_id == binding.id,
            SituationIntegrationInboundEvent.provider_event_id
            == provider_event_id,
        )
    )
    if existing is not None:
        if existing.payload_sha256 != payload_sha256:
            raise WebhookConflictError(
                "Provider event ID was replayed with different content"
            )
        acknowledgement = SituationIntegrationWebhookAck(
            event_id=existing.id,
            reference_id=existing.reference_id,
            outcome=existing.outcome,
            replayed=True,
        )
        db.rollback()
        return acknowledgement

    reference = db.scalar(
        select(SituationIntegrationRemoteReference)
        .where(
            SituationIntegrationRemoteReference.binding_id == binding.id,
            SituationIntegrationRemoteReference.remote_id == payload.remote_id,
        )
        .with_for_update()
    )
    if reference is None:
        raise LookupError("Remote reference not found")
    remote_updated_at = _as_utc(payload.remote_updated_at)
    stale = (
        reference.remote_updated_at is not None
        and remote_updated_at <= _as_utc(reference.remote_updated_at)
    )
    outcome = "ignored_stale" if stale else "accepted"
    event = SituationIntegrationInboundEvent(
        binding_id=binding.id,
        reference_id=reference.id,
        provider_event_id=provider_event_id,
        event_type=payload.event_type,
        remote_status=payload.remote_status,
        remote_updated_at=remote_updated_at,
        payload_sha256=payload_sha256,
        signature_sha256=signature_sha256,
        signature_key_id=key_id,
        outcome=outcome,
    )
    db.add(event)
    db.flush()
    previous_status = reference.remote_status
    if not stale:
        reference.remote_status = payload.remote_status
        reference.remote_updated_at = remote_updated_at
        reference.updated_at = utcnow()
        situation = db.scalar(
            select(Situation)
            .where(Situation.id == reference.situation_id)
            .with_for_update()
        )
        if situation is None:
            raise LookupError("Situation not found")
        append_situation_event(
            db,
            situation,
            event_type="situation.external_status_observed",
            actor=f"integration.webhook.{binding.provider_key}",
            details={
                "reference_id": reference.id,
                "provider_key": binding.provider_key,
                "remote_id": reference.remote_id,
                "previous_remote_status": previous_status,
                "remote_status": payload.remote_status,
                "remote_updated_at": remote_updated_at.isoformat(),
                "provider_event_id": provider_event_id,
                "inbound_event_id": event.id,
                "local_lifecycle_changed": False,
            },
        )
    record_audit_event(
        db,
        event_type="situation.integration.webhook_reconciled",
        actor_type="service",
        actor_id=f"integration.webhook.{binding.provider_key}",
        entity_type="situation_integration_inbound_event",
        entity_id=event.id,
        outcome="success",
        details={
            "binding_id": binding.id,
            "reference_id": reference.id,
            "provider_event_id_sha256": hashlib.sha256(
                provider_event_id.encode("utf-8")
            ).hexdigest(),
            "payload_sha256": payload_sha256,
            "signature_sha256": signature_sha256,
            "signature_key_id": key_id,
            "outcome": outcome,
            "local_lifecycle_changed": False,
        },
    )
    db.commit()
    return SituationIntegrationWebhookAck(
        event_id=event.id,
        reference_id=reference.id,
        outcome=outcome,
        replayed=False,
    )
