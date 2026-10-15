from __future__ import annotations

import json
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..ai_schemas import (
    AIModelCreate,
    AIModelRouteCreate,
    AIProviderCreate,
    AIProviderHealth,
    AIProviderUpdate,
)
from ..config import get_settings
from ..credentials import CredentialUnavailable, resolved_server_secret
from ..models import (
    AIModelConfig,
    AIModelRoute,
    AIProviderConfig,
    CredentialProfile,
    utcnow,
)
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


MAX_MODEL_LIST_BYTES = 1_000_000


class AIProviderUnavailable(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for AI providers",
            headers,
            fp,
        )


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for pattern in allowed_hosts:
        normalized = pattern.rstrip(".").lower()
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


def _validate_base_url(url: str, allowed_hosts: list[str]) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query or fragment")
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError(
            f"base_url host {parsed.hostname!r} is not in the AI provider allowlist"
        )
    return url.rstrip("/")


def _credential_profile(
    db: Session,
    reference: str,
) -> CredentialProfile | None:
    return db.scalar(
        select(CredentialProfile).where(
            or_(
                CredentialProfile.id == reference,
                CredentialProfile.name == reference,
            )
        )
    )


def _validate_credential(
    db: Session,
    auth_type: str,
    credential_profile_ref: str | None,
    *, owner_provider_id: str | None = None,
) -> None:
    if auth_type == "none":
        return
    if not credential_profile_ref:
        raise ValueError("Authenticated AI providers require a credential profile")
    profile = _credential_profile(db, credential_profile_ref)
    if profile is None:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} does not exist"
        )
    if not profile.enabled:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} is disabled"
        )
    if "ai_provider" not in profile.allowed_adapters:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} does not allow "
            "adapter 'ai_provider'"
        )
    if profile.worker_selector:
        raise ValueError(
            "AI provider credentials must not be scoped to collector workers"
        )
    if profile.provider == "managed_ai":
        from .openrouter_setup import connection_for
        connection = connection_for(db, owner_provider_id) if owner_provider_id else None
        if connection is None or connection.credential_profile_id != profile.id:
            raise ValueError("Managed AI keys can only be used by their owning provider")


def validated_provider_url(db: Session, provider: AIProviderConfig) -> str:
    """Database approvals stay provider-bound; never widen the environment allowlist."""
    from .openrouter_setup import validate_managed_url
    managed = validate_managed_url(db, provider)
    return managed if managed is not None else _validate_base_url(provider.base_url, get_settings().ai_allowed_host_list)


def create_ai_provider(
    db: Session,
    payload: AIProviderCreate,
    *,
    allowed_hosts: list[str],
) -> AIProviderConfig:
    from .ai_catalog_mutex import catalog_lock
    catalog_lock(db)
    base_url = _validate_base_url(payload.base_url, allowed_hosts)
    _validate_credential(
        db,
        payload.auth_type,
        payload.credential_profile_ref,
    )
    provider = AIProviderConfig(
        **payload.model_dump(exclude={"base_url"}),
        base_url=base_url,
    )
    db.add(provider)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ai.provider.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="ai_provider",
            entity_id=provider.id,
            details={
                "provider_type": provider.provider_type,
                "base_host": urlsplit(base_url).hostname,
                "auth_type": provider.auth_type,
                "credential_configured": provider.credential_profile_ref is not None,
                "privacy_tier": provider.privacy_tier,
                "data_residency": provider.data_residency,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AI provider name already exists") from exc
    db.refresh(provider)
    return provider


def get_ai_provider(db: Session, provider_id: str) -> AIProviderConfig:
    provider = db.get(AIProviderConfig, provider_id)
    if provider is None:
        raise LookupError("AI provider not found")
    return provider


class AIProviderRuntimeConflict(ValueError):
    pass


def update_ai_provider_runtime_settings(db: Session, provider_id: str, payload, *, actor: str):
    """Timeout-only change: no key/endpoint/route edits or provider inference."""
    from .ai_catalog_mutex import catalog_lock
    from .openrouter_setup import connection_for
    catalog_lock(db)
    provider = db.scalar(select(AIProviderConfig).where(AIProviderConfig.id == provider_id)
        .with_for_update().execution_options(populate_existing=True))
    if provider is None:
        raise LookupError("AI provider not found")
    if not provider.enabled:
        raise AIProviderRuntimeConflict("Provider is retired; restore it before changing runtime settings")
    connection = connection_for(db, provider_id, lock=True)
    if provider.request_timeout_seconds != payload.expected_request_timeout_seconds or (
        connection is not None and connection.revision != payload.expected_connection_revision
    ):
        raise AIProviderRuntimeConflict("Provider runtime settings changed; refresh before saving")
    if connection is None and payload.expected_connection_revision is not None:
        raise AIProviderRuntimeConflict("Provider connection changed; refresh before saving")
    old_timeout = provider.request_timeout_seconds
    if old_timeout == payload.request_timeout_seconds:
        return provider
    provider.request_timeout_seconds = payload.request_timeout_seconds
    provider.updated_at = utcnow()
    if connection is not None:
        connection.revision += 1
        connection.updated_by, connection.updated_at = actor, utcnow()
    record_audit_event(db, event_type="ai.provider.runtime_settings_updated", actor_type="user", actor_id=actor,
        entity_type="ai_provider", entity_id=provider_id, details={
            "previous_request_timeout_seconds": old_timeout, "request_timeout_seconds": provider.request_timeout_seconds,
            "connection_revision": connection.revision if connection else None,
            "key_rotated": False, "outbound_approval_changed": False, "inference_performed": False})
    db.commit()
    return provider


def update_ai_provider(
    db: Session,
    provider: AIProviderConfig,
    payload: AIProviderUpdate,
    *,
    allowed_hosts: list[str],
) -> AIProviderConfig:
    from .ai_catalog_mutex import catalog_lock
    catalog_lock(db)
    from .openrouter_setup import connection_for
    from ..ai_provider_presets import PRESETS
    managed = connection_for(db, provider.id)
    if managed is not None:
        preset = PRESETS[managed.preset]
        if (payload.base_url != preset.base_url or payload.auth_type != preset.auth_type
                or payload.provider_type != preset.provider_type or payload.privacy_tier != "external"):
            raise ValueError("Managed AI providers require their approved HTTPS endpoint, protocol, authentication and external privacy tier")
        profile = db.get(CredentialProfile, managed.credential_profile_id)
        if profile is None or payload.credential_profile_ref not in {profile.id, profile.name}:
            raise ValueError("Managed AI providers must retain their bound credential profile")
        base_url = preset.base_url
    else:
        base_url = _validate_base_url(payload.base_url, allowed_hosts)
    _validate_credential(
        db,
        payload.auth_type,
        payload.credential_profile_ref,
        owner_provider_id=provider.id,
    )
    values = payload.model_dump(exclude={"actor", "base_url"})
    for field, value in values.items():
        setattr(provider, field, value)
    provider.base_url = base_url
    provider.last_checked_at = None
    provider.last_health_status = None
    provider.last_health_error = None
    provider.updated_at = utcnow()
    record_audit_event(
        db,
        event_type="ai.provider.updated",
        actor_type="user",
        actor_id=payload.actor,
        entity_type="ai_provider",
        entity_id=provider.id,
        details={
            "provider_type": provider.provider_type,
            "base_host": urlsplit(base_url).hostname,
            "auth_type": provider.auth_type,
            "credential_configured": provider.credential_profile_ref is not None,
            "privacy_tier": provider.privacy_tier,
            "data_residency": provider.data_residency,
        },
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AI provider name already exists") from exc
    db.refresh(provider)
    return provider


def create_ai_model(db: Session, payload: AIModelCreate) -> AIModelConfig:
    from .ai_catalog_mutex import catalog_lock
    from ..ai_failure_diagnostics import batch_model
    catalog_lock(db)
    parent = db.get(AIProviderConfig, payload.provider_id)
    if parent is None:
        raise ValueError("AI provider does not exist")
    if payload.enabled and not parent.enabled:
        raise ValueError("Enable the provider before adding an active model")
    if parent.base_url.rstrip("/") == "https://openrouter.ai/api/v1" and batch_model(payload.model_name):
        raise ValueError("Batch-only models cannot run interactive Agents or Studio; choose a synchronous model")
    assert_no_inline_secrets(payload.default_parameters, "default_parameters")
    model = AIModelConfig(**payload.model_dump())
    db.add(model)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ai.model.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="ai_model",
            entity_id=model.id,
            details={
                "provider_id": model.provider_id,
                "model_name": model.model_name,
                "capabilities": model.capabilities,
                "cost_class": model.cost_class,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AI model display name or provider model name already exists") from exc
    db.refresh(model)
    return model


def _model(db: Session, model_id: str) -> AIModelConfig:
    model = db.get(AIModelConfig, model_id)
    if model is None:
        raise ValueError(f"AI model {model_id!r} does not exist")
    return model


def create_ai_model_route(
    db: Session,
    payload: AIModelRouteCreate,
) -> AIModelRoute:
    from .ai_catalog_mutex import catalog_lock
    from ..ai_failure_diagnostics import batch_model
    catalog_lock(db)
    models = [
        _model(db, model_id)
        for model_id in [payload.primary_model_id, *payload.fallback_model_ids]
    ]
    for model in models:
        if not model.enabled:
            raise ValueError(f"AI model {model.id!r} is disabled")
        provider = db.get(AIProviderConfig, model.provider_id)
        if provider is None or not provider.enabled:
            raise ValueError(
                f"AI model {model.id!r} does not have an enabled provider"
            )
        if provider.base_url.rstrip("/") == "https://openrouter.ai/api/v1" and batch_model(model.model_name):
            raise ValueError("Batch-only OpenRouter models cannot be used by interactive routes")
        if not {"chat", "json_schema"} <= set(model.capabilities):
            raise ValueError(
                f"AI model {model.id!r} requires chat and json_schema capabilities"
            )
    route = AIModelRoute(**payload.model_dump())
    db.add(route)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ai.route.created",
            actor_type="user",
            actor_id=payload.created_by,
            entity_type="ai_model_route",
            entity_id=route.id,
            details={
                "purpose": route.purpose,
                "primary_model_id": route.primary_model_id,
                "fallback_count": len(route.fallback_model_ids),
                "max_iterations": route.max_iterations,
                "max_tool_calls": route.max_tool_calls,
                "timeout_seconds": route.timeout_seconds,
                "token_budget": route.token_budget,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AI model route purpose already exists") from exc
    db.refresh(route)
    return route


@contextmanager
def _models_request_headers(
    db: Session,
    provider: AIProviderConfig,
) -> Iterator[dict[str, str]]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "iCheck-ai-provider-check/0.1",
    }
    if provider.provider_type == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    if provider.auth_type == "none":
        yield headers
        return
    if not provider.credential_profile_ref:
        raise AIProviderUnavailable("AI provider has no credential profile")
    profile = _credential_profile(db, provider.credential_profile_ref)
    if profile is None:
        raise AIProviderUnavailable("AI provider credential profile is missing")
    if profile.provider == "managed_ai":
        from .openrouter_setup import ManagedAIUnavailable, resolved_managed_key
        try:
            with resolved_managed_key(db, provider, profile) as secret:
                yield {**headers, **({"X-API-Key": secret} if provider.auth_type == "api_key"
                                     else {"Authorization": "Bearer " + secret})}
        except ManagedAIUnavailable as exc:
            raise AIProviderUnavailable(str(exc)) from exc
        return
    try:
        with resolved_server_secret(
            profile,
            adapter_type="ai_provider",
        ) as secret:
            if provider.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {secret}"
            elif provider.auth_type == "api_key":
                headers["X-API-Key"] = secret
            else:
                raise AIProviderUnavailable("AI provider auth type is unsupported")
            yield headers
    except CredentialUnavailable as exc:
        raise AIProviderUnavailable(str(exc)) from exc


def _request_models(db: Session, provider: AIProviderConfig) -> int:
    if not provider.enabled:
        raise AIProviderUnavailable("AI provider is disabled")
    from .openrouter_setup import connection_for, fetch_catalog, ManagedAIUnavailable
    if connection_for(db, provider.id) is not None:
        try:
            count, _ = fetch_catalog(db, provider)
            return count
        except ManagedAIUnavailable as exc:
            raise AIProviderUnavailable(str(exc)) from exc
    try:
        base_url = validated_provider_url(db, provider)
    except ValueError as exc:
        raise AIProviderUnavailable(str(exc)) from exc
    with _models_request_headers(db, provider) as headers:
        request = Request(
            f"{base_url}/models",
            headers=headers,
            method="GET",
        )
        try:
            with build_opener(_NoRedirect()).open(
                request,
                timeout=provider.request_timeout_seconds,
            ) as response:
                body = response.read(MAX_MODEL_LIST_BYTES + 1)
        except HTTPError as exc:
            raise AIProviderUnavailable(
                f"AI provider returned HTTP {exc.code}"
            ) from exc
        except (OSError, URLError) as exc:
            raise AIProviderUnavailable("AI provider request failed") from exc
    if len(body) > MAX_MODEL_LIST_BYTES:
        raise AIProviderUnavailable(
            "AI provider response exceeded the 1000000 byte limit"
        )
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIProviderUnavailable("AI provider returned invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise AIProviderUnavailable(
            "AI provider returned an invalid OpenAI-compatible model list"
        )
    return len(document["data"])


def check_ai_provider(
    db: Session,
    provider: AIProviderConfig,
    *,
    actor: str,
) -> AIProviderHealth:
    checked_at = utcnow()
    error: str | None = None
    model_count = 0
    try:
        model_count = _request_models(db, provider)
        health_status = "healthy"
    except AIProviderUnavailable as exc:
        health_status = "unhealthy"
        error = str(exc)[:1000]
    provider.last_checked_at = checked_at
    provider.last_health_status = health_status
    provider.last_health_error = error
    provider.updated_at = checked_at
    record_audit_event(
        db,
        event_type="ai.provider.health_checked",
        actor_type="user",
        actor_id=actor,
        entity_type="ai_provider",
        entity_id=provider.id,
        outcome="success" if health_status == "healthy" else "failure",
        details={
            "status": health_status,
            "model_count": model_count,
            "error": error,
        },
    )
    db.commit()
    return AIProviderHealth(
        provider_id=provider.id,
        status=health_status,
        checked_at=checked_at,
        model_count=model_count,
        error=error,
    )
