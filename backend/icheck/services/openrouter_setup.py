"""Managed AI onboarding; legacy OpenRouter API and custody remain compatible."""
from __future__ import annotations

from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import re
import stat
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..ai_schemas import AIModelRead, AIModelRouteRead, AIProviderHealth
from ..config import get_settings
from ..database import session_namespace, validate_session_namespace
from ..models import AIManagedConnection, AIModelConfig, AIModelRoute, AIProviderConfig, CredentialProfile, new_id, utcnow
from ..openrouter_schemas import (
    OpenRouterCheckRead, OpenRouterConfiguredRead, OpenRouterConnectionRead,
    OpenRouterModelRead, OpenRouterSetupRead,
)
from .audit import record_audit_event
from ..ai_failure_diagnostics import batch_model, provider_diagnostic, diagnostic, diagnostic_text
from .ai_catalog_mutex import catalog_lock
from ..ai_wire_format import graph_response_format
from ..ai_provider_presets import PRESETS, preset_catalog
from ..ai_provider_transport import prepare_completion, normalize_completion

BASE = "https://openrouter.ai/api/v1"
CATALOG_LIMIT = 8_000_000
MODEL_ID = re.compile(r"[A-Za-z0-9_.:+-]+/[A-Za-z0-9_./:+-]+\Z")
DIRECT_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:+-]*\Z")


def _event(connection, action):
    return f"ai.{'openrouter' if connection.preset == 'openrouter' else 'managed'}.{action}"


class ManagedAIUnavailable(ValueError):
    pass


class ManagedAIConflict(ValueError):
    pass


def _key() -> bytes:
    path = get_settings().ai_managed_secret_key_file
    if not path or not Path(path).is_absolute():
        raise ManagedAIUnavailable("Managed AI key storage is not provisioned on this server")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            # Root:API 0440 and API-owned 0400 are supported. No write/shared-other authority.
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in {0o400, 0o440}):
                raise ManagedAIUnavailable("Managed AI encryption key custody is unsafe")
            value = handle.read(33)
    except OSError:
        raise ManagedAIUnavailable("Managed AI encryption key is unavailable") from None
    if len(value) != 32:
        raise ManagedAIUnavailable("Managed AI encryption key is invalid")
    return value


def _aad(connection: AIManagedConnection) -> bytes:
    return json.dumps(["icheck.managed-ai/v1", connection.id, connection.tenant_id,
                       connection.region_id, connection.provider_id,
                       connection.credential_profile_id, connection.preset], separators=(",", ":")).encode()


def _encrypt(connection: AIManagedConnection, secret: str) -> bytes:
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(_key()).encrypt(nonce, secret.encode("ascii"), _aad(connection))


def connection_for(db: Session, provider_id: str, *, lock=False) -> AIManagedConnection | None:
    namespace = session_namespace(db)
    if namespace is None:
        return None
    query = select(AIManagedConnection).where(
        AIManagedConnection.provider_id == provider_id,
        AIManagedConnection.tenant_id == namespace[0], AIManagedConnection.region_id == namespace[1],
    ).execution_options(populate_existing=True)
    return db.scalar(query.with_for_update() if lock else query)


def validate_managed_url(db: Session, provider: AIProviderConfig) -> str | None:
    connection = connection_for(db, provider.id)
    if connection is None:
        return None
    if not provider.enabled:
        raise ManagedAIUnavailable("AI provider is retired. Restore it in Guided provider setup before verifying the key or using models.")
    if not connection.outbound_enabled:
        raise ManagedAIUnavailable("AI provider outbound access is disabled for this connection")
    preset = PRESETS.get(connection.preset)
    if (preset is None or provider.base_url != preset.base_url or provider.auth_type != preset.auth_type
            or provider.provider_type != preset.provider_type
            or provider.privacy_tier != "external"):
        raise ManagedAIUnavailable("Managed AI connection settings do not match their approved endpoint")
    return preset.base_url


@contextmanager
def resolved_managed_key(db: Session, provider: AIProviderConfig, profile: CredentialProfile):
    connection = connection_for(db, provider.id)
    if (connection is None or validate_managed_url(db, provider) is None
            or profile.id != connection.credential_profile_id
            or provider.credential_profile_ref not in {profile.id, profile.name}
            or profile.provider != "managed_ai" or profile.secret_ref != "managed-ai://" + connection.id
            or not profile.enabled or profile.worker_selector or profile.allowed_adapters != ["ai_provider"]):
        raise ManagedAIUnavailable("Managed AI credential is not bound to this provider and namespace")
    raw = connection.encrypted_secret
    if len(raw) < 30 or raw[:1] != b"\x01":
        raise ManagedAIUnavailable("Managed AI credential custody is invalid")
    try:
        secret = AESGCM(_key()).decrypt(raw[1:13], raw[13:], _aad(connection)).decode("ascii")
    except (InvalidTag, ValueError, UnicodeError):
        raise ManagedAIUnavailable("Managed AI credential cannot be decrypted") from None
    try:
        yield secret
    finally:
        secret = None  # Never retain/export a process-global plaintext cache.


def _read(connection, provider):
    return OpenRouterConnectionRead(
        provider_id=provider.id, name=provider.name, credential_profile_id=connection.credential_profile_id,
        preset=connection.preset, base_url=provider.base_url,
        provider_enabled=provider.enabled,
        outbound_enabled=connection.outbound_enabled, revision=connection.revision,
        request_timeout_seconds=provider.request_timeout_seconds,
        last_health_status=provider.last_health_status, last_checked_at=provider.last_checked_at,
    )


def setup_status(db: Session):
    try:
        _key()
        ready = True
    except ManagedAIUnavailable:
        ready = False
    connections = db.scalars(select(AIManagedConnection).order_by(AIManagedConnection.created_at)).all()
    return OpenRouterSetupRead(storage_ready=ready, presets=preset_catalog(), connections=[
        _read(c, p) for c in connections if (p := db.get(AIProviderConfig, c.provider_id)) is not None
    ])


def connect(db: Session, payload, *, actor: str):
    catalog_lock(db)
    tenant, region = validate_session_namespace(db)
    _key()  # Fail before creating any metadata when native custody is unavailable.
    preset = PRESETS[getattr(payload, "preset", "openrouter")]
    provider_id, profile_id, connection_id = new_id(), new_id(), new_id()
    profile = CredentialProfile(id=profile_id, name=payload.name + "-managed-key", provider="managed_ai",
                                secret_ref="managed-ai://" + connection_id, allowed_adapters=["ai_provider"],
                                worker_selector={}, enabled=True, created_by=actor)
    provider = AIProviderConfig(id=provider_id, name=payload.name, provider_type=preset.provider_type,
                                base_url=preset.base_url, auth_type=preset.auth_type, credential_profile_ref=profile_id,
                                privacy_tier="external", data_residency="unspecified", created_by=actor)
    provider.request_timeout_seconds = payload.request_timeout_seconds
    connection = AIManagedConnection(id=connection_id, provider_id=provider_id, credential_profile_id=profile_id,
                                    tenant_id=tenant, region_id=region, preset=preset.id, revision=1,
                                    outbound_enabled=True, created_by=actor, updated_by=actor)
    connection.encrypted_secret = _encrypt(connection, payload.api_key.get_secret_value())
    try:
        db.add_all([profile, provider])
        db.flush()  # PostgreSQL binding guard requires both namespace-local parents.
        db.add(connection)
        db.flush()
        record_audit_event(db, event_type=_event(connection, "connected"), actor_type="user", actor_id=actor,
                           entity_type="ai_provider", entity_id=provider.id,
                           details={"outbound_origin": preset.base_url, "preset": preset.id, "credential_storage": "aes-256-gcm", "revision": 1})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ManagedAIConflict("Provider or credential profile name already exists") from None
    return _read(connection, provider)


def _locked(db, provider_id):
    connection = connection_for(db, provider_id, lock=True)
    provider = db.scalar(select(AIProviderConfig).where(AIProviderConfig.id == provider_id).with_for_update())
    if connection is None or provider is None:
        raise LookupError("Managed AI connection not found")
    return connection, provider


def update_connection(db: Session, provider_id: str, payload, *, actor: str):
    catalog_lock(db)
    connection, provider = _locked(db, provider_id)
    if connection.revision != payload.expected_revision:
        raise ManagedAIConflict("Connection changed; refresh before updating its key or outbound access")
    if payload.outbound_enabled and not provider.enabled:
        raise ManagedAIConflict("AI provider is retired. Restore it before approving outbound access; the saved key has not been changed.")
    if payload.api_key is not None:
        connection.encrypted_secret = _encrypt(connection, payload.api_key.get_secret_value())
    connection.outbound_enabled = payload.outbound_enabled
    connection.revision += 1
    connection.updated_by, connection.updated_at = actor, utcnow()
    provider.last_health_status = provider.last_health_error = provider.last_checked_at = None
    record_audit_event(db, event_type=_event(connection, "connection_updated"), actor_type="user", actor_id=actor,
                       entity_type="ai_provider", entity_id=provider.id,
                       details={"revision": connection.revision, "outbound_enabled": connection.outbound_enabled,
                                "key_rotated": payload.api_key is not None})
    db.commit()
    return _read(connection, provider)


def _json(opener, path, headers, *, limit, timeout, base_url=BASE, label="OpenRouter"):
    from .ai_settings import AIProviderUnavailable
    try:
        with opener.open(Request(base_url + path, headers=headers, method="GET"), timeout=timeout) as response:
            if response.status != 200:
                raise AIProviderUnavailable(f"{label} returned an unexpected HTTP status")
            raw = response.read(limit + 1)
    except HTTPError as error:
        status = error.code
        error.close()
        raise AIProviderUnavailable(f"{label} API key was rejected" if status == 401 else f"{label} returned HTTP {status}") from None
    except (OSError, URLError):
        raise AIProviderUnavailable(f"{label} connection failed; check server DNS, TLS and connectivity") from None
    if len(raw) > limit:
        raise AIProviderUnavailable(f"{label} response exceeded its size limit")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise AIProviderUnavailable(f"{label} returned invalid JSON") from None
    if not isinstance(result, dict):
        raise AIProviderUnavailable(f"{label} returned an invalid response envelope")
    return result


def fetch_catalog(db, provider):
    from .ai_settings import _models_request_headers, _NoRedirect, AIProviderUnavailable
    base_url = validate_managed_url(db, provider)
    connection = connection_for(db, provider.id)
    if connection is None or base_url is None:
        raise ManagedAIUnavailable("Managed AI connection not found")
    preset = PRESETS[connection.preset]
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with _models_request_headers(db, provider) as headers:
        if preset.id != "openrouter":
            path = "/models?limit=1000" if preset.id == "anthropic" else "/models"
            document = _json(opener, path, headers, limit=CATALOG_LIMIT, timeout=provider.request_timeout_seconds,
                             base_url=base_url, label=preset.label)
            items = document.get("data")
            if not isinstance(items, list) or len(items) > 5000 or document.get("has_more") is True:
                raise AIProviderUnavailable("Provider returned an invalid or incomplete model catalog")
            candidates = {}
            for item in items:
                if not isinstance(item, dict):
                    continue
                model_id = item.get("id")
                if (not isinstance(model_id, str) or len(model_id) > 255 or not DIRECT_MODEL_ID.fullmatch(model_id)
                        or batch_model(model_id) or item.get("lifecycle") == "retired"):
                    continue
                # A catalog entry is not proof of Agent compatibility. Direct
                # providers require a successful schema/usage probe before saving.
                candidates[model_id] = OpenRouterModelRead(id=model_id, name=model_id, capabilities=["chat"])
            return len(items), sorted(candidates.values(), key=lambda m: m.id)
        key_info = _json(opener, "/key", headers, limit=32_000, timeout=provider.request_timeout_seconds)
        if not isinstance(key_info.get("data"), dict) or key_info["data"].get("is_management_key") is True:
            raise AIProviderUnavailable("OpenRouter requires a valid inference API key")
        # Do not return key labels, fingerprints, usage or any raw key metadata.
        document = _json(opener, "/models", headers, limit=CATALOG_LIMIT, timeout=provider.request_timeout_seconds)
    items = document.get("data")
    if not isinstance(items, list) or len(items) > 5000:
        raise AIProviderUnavailable("OpenRouter returned an invalid model catalog")
    models = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        model_id, parameters = item.get("id"), item.get("supported_parameters")
        if (not isinstance(model_id, str) or len(model_id) > 255 or not MODEL_ID.fullmatch(model_id)
                or not isinstance(parameters, list) or not all(isinstance(p, str) for p in parameters)
                or batch_model(model_id)
                or not {"response_format", "structured_outputs"} <= set(parameters)):
            continue
        capabilities = ["chat", "json_schema"] + (["tools"] if "tools" in parameters else [])
        context = item.get("context_length")
        top = item.get("top_provider") if isinstance(item.get("top_provider"), dict) else {}
        output = top.get("max_completion_tokens")
        reasoning = item.get("reasoning") if isinstance(item.get("reasoning"), dict) else {}
        efforts = reasoning.get("supported_efforts")
        safe_efforts = [effort for effort in efforts if isinstance(effort, str) and effort in
            {"none", "minimal", "low", "medium", "high", "xhigh", "max"}] if isinstance(efforts, list) else []
        models[model_id] = OpenRouterModelRead(
            id=model_id, name=model_id, capabilities=capabilities,
            supported_parameters=parameters,
            context_window=context if type(context) is int and 0 < context <= 10_000_000 else None,
            max_output_tokens=output if type(output) is int and 0 < output <= 1_000_000 else None,
            reasoning_mandatory=reasoning.get("mandatory") if type(reasoning.get("mandatory")) is bool else None,
            reasoning_supported_efforts=list(dict.fromkeys(safe_efforts)),
            reasoning_effort_unrestricted="supported_efforts" in reasoning and efforts is None,
        )
    return len(items), sorted(models.values(), key=lambda m: m.id)


def check_connection(db: Session, provider_id: str, *, actor: str):
    catalog_lock(db)
    from .ai_settings import AIProviderUnavailable
    connection, provider = _locked(db, provider_id)
    models, count, error = [], 0, None
    try:
        count, models = fetch_catalog(db, provider)
    except (AIProviderUnavailable, ManagedAIUnavailable) as failure:
        error = str(failure)
    provider.last_health_status = "unhealthy" if error else "healthy"
    provider.last_health_error, provider.last_checked_at = error, utcnow()
    record_audit_event(db, event_type=_event(connection, "checked"), actor_type="user", actor_id=actor,
                       entity_type="ai_provider", entity_id=provider.id, outcome="failure" if error else "success",
                       details={"status": provider.last_health_status, "model_count": count, "compatible_models": len(models)})
    db.commit()
    return OpenRouterCheckRead(connection_revision=connection.revision, models=models,
        configuration_hash=configuration_hash(db, provider_id), health=AIProviderHealth(
        provider_id=provider.id, status=provider.last_health_status, checked_at=provider.last_checked_at,
        model_count=count, error=error,
    ))


def configure(db: Session, provider_id: str, payload, *, actor: str):
    catalog_lock(db)
    from .ai_settings import AIProviderUnavailable
    connection, provider = _locked(db, provider_id)
    if connection.revision != payload.expected_connection_revision:
        raise ManagedAIConflict("Connection changed; check the key and model catalog again")
    if connection.preset != "openrouter" and (not payload.probe_reservation_id or not payload.expected_configuration_hash):
        raise ManagedAIConflict("Test the selected model and review the current routing plan before saving")
    if payload.probe_reservation_id:
        from ..models import AuditEvent
        evidence = db.scalar(select(AuditEvent).where(AuditEvent.event_type == _event(connection, "model_probed"),
            AuditEvent.entity_type == "ai_provider", AuditEvent.entity_id == provider_id,
            AuditEvent.actor_id == actor, AuditEvent.outcome == "success")
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(1))
        # Bind a GUI's validation to the exact model, credential revision and actor.
        if (evidence is None or evidence.details.get("quota_reservation_id") != payload.probe_reservation_id
                or evidence.details.get("model_name") != payload.model_id
                or evidence.details.get("connection_revision") != connection.revision):
            raise ManagedAIConflict("The selected model has no matching successful inference test for this connection revision. Test it again before saving.")
    if batch_model(payload.model_id):
        raise AIProviderUnavailable("Batch-only models cannot run interactive Agents or Studio. Select the model without :batch.")
    # Check the actual provider catalog, not capabilities asserted by the browser.
    _, catalog = fetch_catalog(db, provider)
    chosen = next((item for item in catalog if item.id == payload.model_id), None)
    if chosen is None:
        raise AIProviderUnavailable("Selected model is unavailable in the eligible model catalog")
    purposes = list(dict.fromkeys(payload.purposes))
    routes = list(db.scalars(select(AIModelRoute).where(AIModelRoute.purpose.in_(purposes)).with_for_update()).all())
    if payload.expected_configuration_hash and payload.expected_configuration_hash != configuration_hash(db, provider_id):
        raise ManagedAIConflict("Model or route configuration changed after review. Verify again and review the new plan before saving.")
    if routes and not payload.replace_existing_routes:
        raise ManagedAIConflict("A selected purpose already has a route; explicitly approve replacement or choose another purpose")
    model = db.scalar(select(AIModelConfig).where(AIModelConfig.provider_id == provider_id,
                                                 AIModelConfig.model_name == chosen.id))
    owner = db.scalar(select(AIModelConfig).where(AIModelConfig.display_name == payload.display_name))
    previous_display_model = None
    if owner is not None and (model is None or owner.id != model.id):
        if (not payload.replace_existing_routes or owner.provider_id != provider_id
                or not any(r.primary_model_id == owner.id for r in routes)):
            raise ManagedAIConflict("Display name is already used by another model. Choose a different name, or explicitly replace the selected routes that currently use that model. No configuration was changed.")
        # Retain the old model identity/configuration for pinned investigations and
        # unselected routes. Transfer only the display label, never rewrite its slug.
        previous_display_model = owner.id
        owner.display_name = payload.display_name[:190] + " (previous " + owner.id + ")"
        db.flush()
    try:
        if model is None:
            model = AIModelConfig(id=new_id(), provider_id=provider_id, created_by=actor)
            db.add(model)
        model.display_name, model.model_name = payload.display_name, chosen.id
        model.capabilities = list(dict.fromkeys([*chosen.capabilities, "json_schema"]))
        model.context_window = chosen.context_window
        model.max_output_tokens = chosen.max_output_tokens if connection.preset == "openrouter" else 4096
        model.cost_class, model.enabled = payload.cost_class, True
        # Ensure OpenRouter selects an upstream endpoint that honors response_format.
        model.default_parameters = {"provider": {"require_parameters": True}} if connection.preset == "openrouter" else {}
        from ..ai_runtime_policy import qwen_runtime_parameters, QWEN_OUTPUT_LIMIT
        if connection.preset == "openrouter" and chosen.id.lower().startswith("qwen/"):
            model.max_output_tokens = min(chosen.max_output_tokens or QWEN_OUTPUT_LIMIT, QWEN_OUTPUT_LIMIT)
            model.default_parameters = qwen_runtime_parameters(BASE, chosen.id, model.default_parameters, QWEN_OUTPUT_LIMIT)
        db.flush()
        by_purpose = {route.purpose: route for route in routes}
        result = []
        for purpose in purposes:
            route = by_purpose.get(purpose)
            if route is None:
                route = AIModelRoute(id=new_id(), purpose=purpose, created_by=actor)
                db.add(route)
            route.primary_model_id, route.fallback_model_ids, route.enabled = model.id, [], True
            for field in ("max_iterations", "max_tool_calls", "timeout_seconds", "token_budget"):
                setattr(route, field, getattr(payload, field))
            result.append(route)
        db.flush()
        record_audit_event(db, event_type=_event(connection, "configured"), actor_type="user", actor_id=actor,
                           entity_type="ai_provider", entity_id=provider.id,
                           details={"model_id": model.id, "model_name": model.model_name, "purposes": purposes,
                                    "replaced_routes": bool(routes), "previous_display_model_id": previous_display_model,
                                    "connection_revision": connection.revision})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ManagedAIConflict("Configuration changed concurrently or a retained model name conflicts. Refresh and choose a unique display name; no partial route change was committed.") from None
    return OpenRouterConfiguredRead(model=AIModelRead.model_validate(model),
                                    routes=[AIModelRouteRead.model_validate(route) for route in result])


def configuration_hash(db, provider_id):
    models = db.scalars(select(AIModelConfig).where(AIModelConfig.provider_id == provider_id)
        .order_by(AIModelConfig.id).execution_options(populate_existing=True)).all()
    routes = db.scalars(select(AIModelRoute).order_by(AIModelRoute.purpose)
        .execution_options(populate_existing=True)).all()
    document = {"namespace": session_namespace(db), "provider_id": provider_id,
        "models": [{k: getattr(m, k) for k in ("id", "model_name", "display_name", "enabled", "default_parameters")} for m in models],
        "routes": [{k: getattr(r, k) for k in ("purpose", "primary_model_id", "fallback_model_ids", "enabled",
            "max_iterations", "max_tool_calls", "timeout_seconds", "token_budget")} for r in routes]}
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def probe_model(db, provider_id, payload, *, actor):
    """Opt-in, fixed-input GraphDecision self-test. No inventory, tools or route writes."""
    from .ai_authoring_quota import reserve_authoring_tokens, settle_authoring_tokens
    from .ai_settings import _models_request_headers, _NoRedirect, AIProviderUnavailable
    from ..langgraph_runtime import GraphDecision
    from ..openrouter_schemas import OpenRouterProbeRead
    # Read-only snapshot: do not hold catalog/row locks across a paid network call.
    connection = connection_for(db, provider_id)
    provider = db.get(AIProviderConfig, provider_id)
    if connection is None or provider is None:
        raise LookupError("Managed AI connection not found")
    if connection.revision != payload.expected_connection_revision:
        raise ManagedAIConflict("Connection changed; verify it again before testing inference")
    revision = connection.revision
    _, catalog = fetch_catalog(db, provider)
    chosen = next((m for m in catalog if m.id == payload.model_id), None)
    if chosen is None:
        raise AIProviderUnavailable("Select a synchronous JSON-schema model from the current catalog; batch variants are not eligible")
    # Resolve once while checking approval; admission commits before inference I/O.
    with _models_request_headers(db, provider) as resolved:
        headers = dict(resolved)
    timeout = min(provider.request_timeout_seconds, 30)
    receipt = reserve_authoring_tokens(db, actor=actor, entity_type="ai_model_probe", entity_id=new_id(),
        token_budget=4096, source_entity_type="ai_provider", source_entity_id=provider_id)
    document = {"model": payload.model_id, "max_tokens": 512, "stream": False,
        "messages": [{"role": "user", "content": 'Readiness test only. Return only JSON with action="complete", conclusion="Model inference verified". Omit optional fields. Do not request operational tools.'}],
        "response_format": graph_response_format(provider.base_url, payload.model_id)}
    if connection.preset == "openrouter":
        document["provider"] = {"require_parameters": True}
    # Support for reasoning is NOT permission to disable mandatory reasoning.
    # Use documented low effort only when effort support is explicitly advertised.
    # Keep the output/transport cap and do not retry or increase budgets implicitly.
    if {"reasoning", "reasoning_effort"} <= set(chosen.supported_parameters):
        permitted = {"minimal", "low", "medium", "high", "xhigh", "max"} if chosen.reasoning_effort_unrestricted else set(chosen.reasoning_supported_efforts)
        effort = next((value for value in ["minimal", "low", "medium", "high", "xhigh", "max"] if value in permitted), None)
        if effort:
            document["reasoning"] = {"enabled": True, "effort": effort}
    headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    passed, failure, usage, unknown = False, None, 0, True
    try:
        url, wire_document = prepare_completion(provider.provider_type, provider.base_url, document)
        request = Request(url, headers=headers, data=json.dumps(wire_document).encode(), method="POST")
        with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=timeout) as response:
            raw = response.read(1000001)
        if len(raw) > 1000000:
            raise ValueError("bounded response")
        result = normalize_completion(provider.provider_type, json.loads(raw))
        if not isinstance(result, dict):
            raise ValueError("readiness response shape")
        reported = result["usage"].get("total_tokens") if isinstance(result.get("usage"), dict) else None
        if type(reported) is int and 0 <= reported <= 1_000_000_000:
            usage, unknown = reported, False
        if isinstance(result.get("error"), dict):
            code = result["error"].get("code")
            status = code if type(code) is int and 400 <= code <= 599 else 502
            failure = provider_diagnostic(status, raw, model_name=payload.model_id)
            failure["transport_status"] = response.status
        else:
            decision = GraphDecision.model_validate_json(result["choices"][0]["message"]["content"])
            if decision.action != "complete" or decision.tool_requests or unknown:
                raise ValueError("readiness contract")
            passed = True
    except HTTPError as error:
        try: raw = error.read(16385)
        except OSError: raw = b""
        failure = provider_diagnostic(error.code, raw, model_name=payload.model_id); error.close()
    except (OSError, URLError):
        failure = diagnostic("provider_connection_failed", "Inference could not reach the AI provider.",
            "DNS, TLS, timeout or provider connectivity failed.", "Review connectivity and provider availability, then test again.")
    except (ValueError, TypeError, KeyError, IndexError):
        failure = diagnostic("model_schema_invalid", "Model failed the Agent decision-schema test.",
            "The response was missing valid usage or a complete GraphDecision JSON object.", "Select another synchronous structured-output model; no routes were changed.")
    finally:
        headers.clear()
    settle_authoring_tokens(db, receipt, known_tokens=usage, external_charge_unknown=unknown)
    record_audit_event(db, event_type=_event(connection, "model_probed"), actor_type="user", actor_id=actor,
        entity_type="ai_provider", entity_id=provider_id, outcome="success" if passed else "failure",
        details={"model_name": payload.model_id, "diagnostic": failure, "quota_reservation_id": receipt,
            "reasoning_mandatory": chosen.reasoning_mandatory,
            "reasoning_effort": document.get("reasoning", {}).get("effort"),
            "provider_type": provider.provider_type, "preset": connection.preset,
            "wire_profile": ("anthropic_result_envelope" if provider.provider_type == "anthropic"
                else "json_mode_local_schema" if connection.preset in {"deepseek", "qwen_cn", "qwen_sg"}
                else "qwen_strict_graph" if document["response_format"]["json_schema"]["strict"] else "flexible_graph"),
            "token_usage": usage, "external_charge_unknown": unknown, "connection_revision": revision})
    db.commit()
    return OpenRouterProbeRead(passed=passed, model_id=payload.model_id, checked_at=utcnow(),
        diagnostic=failure, quota_reservation_id=receipt)
