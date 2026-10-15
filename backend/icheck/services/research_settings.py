"""Human-managed search setup with encrypted, namespace-bound key custody."""
import json
import os
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import case, or_, select, update
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..database import session_namespace, validate_session_namespace
from ..models import ResearchSettings, new_id, utcnow
from ..public_research_http import ResearchUnavailable, public_url
from ..research_schemas import ResearchSettingsRead
from .audit import record_audit_event
from .openrouter_setup import _key, ManagedAIUnavailable


class ResearchSettingsConflict(ValueError):
    pass


def connection(db, *, lock=False):
    namespace = session_namespace(db) if db is not None else None
    if namespace is None:
        return None
    query = select(ResearchSettings).where(ResearchSettings.tenant_id == namespace[0],
        ResearchSettings.region_id == namespace[1]).execution_options(populate_existing=True)
    return db.scalar(query.with_for_update() if lock else query)


def aad(row):
    return json.dumps(["icheck.research-key/v1", row.id, row.tenant_id, row.region_id, row.provider],
                      separators=(",", ":")).encode()


def encrypt(row, key):
    nonce = os.urandom(12)
    return b"\x01" + nonce + AESGCM(_key()).encrypt(nonce, key.encode("ascii"), aad(row))


def decrypt(row):
    raw = row.encrypted_secret or b""
    if row.provider != "brave" or len(raw) < 30 or raw[:1] != b"\x01":
        raise ResearchUnavailable("Search API key is not configured")
    try:
        return AESGCM(_key()).decrypt(raw[1:13], raw[13:], aad(row)).decode("ascii")
    except (InvalidTag, ValueError, UnicodeError):
        raise ResearchUnavailable("Search API key cannot be decrypted; ask an administrator to check key storage") from None


def setup_status(db):
    config = get_settings()
    row = connection(db)
    try:
        _key()
        ready = True
    except ManagedAIUnavailable:
        ready = False
    return ResearchSettingsRead(source="managed" if row else "environment" if config.research_provider != "unconfigured" else "default",
        provider=row.provider if row else config.research_provider,
        enabled=row.enabled if row else config.research_enabled and config.research_provider != "unconfigured",
        server_enabled=config.research_enabled, storage_ready=ready,
        key_configured=bool(row.encrypted_secret) if row else bool(config.research_api_key_file) and config.research_provider == "brave",
        searxng_url=row.searxng_url if row else config.research_searxng_url,
        revision=row.revision if row else 0, daily_limit=row.daily_limit if row else None,
        calls_today=row.calls_today if row and row.quota_day == utcnow().date().isoformat() else 0,
        last_test_status=row.last_test_status if row else None, last_test_at=row.last_test_at if row else None)


def save(db, payload, *, actor):
    from .ai_catalog_mutex import catalog_lock
    catalog_lock(db)
    tenant, region = validate_session_namespace(db)
    row = connection(db, lock=True)
    if payload.expected_revision != (row.revision if row else 0):
        raise ResearchSettingsConflict("Search settings changed; refresh before saving")
    if payload.provider == "searxng":
        if payload.api_key is not None:
            raise ValueError("SearXNG does not use the Brave API key field")
        if not payload.searxng_url:
            raise ValueError("Enter the SearXNG HTTPS search endpoint")
        url = public_url(payload.searxng_url)
        if urlsplit(payload.searxng_url).fragment or urlsplit(url).query:
            raise ValueError("SearXNG endpoint must not contain a query or fragment")
    else:
        if payload.searxng_url:
            raise ValueError("Brave uses its fixed official API endpoint")
        url = None
    created = row is None
    if created:
        row = ResearchSettings(id=new_id(), tenant_id=tenant, region_id=region, provider=payload.provider,
            revision=0, quota_day="", calls_today=0)
    if row.provider != payload.provider:
        row.encrypted_secret = None  # Never carry a provider key to another endpoint.
    row.provider = payload.provider
    if payload.api_key is not None:
        row.encrypted_secret = encrypt(row, payload.api_key.get_secret_value())
    if payload.enabled and payload.provider == "brave" and not row.encrypted_secret:
        raise ValueError("Enter a Brave API key before enabling search")
    row.enabled, row.searxng_url, row.daily_limit = payload.enabled, url, payload.daily_limit
    row.revision += 1
    row.updated_by, row.updated_at = actor, utcnow()
    row.last_test_at = row.last_test_status = None
    if created:
        db.add(row)
    try:
        db.flush()
        record_audit_event(db, event_type="research.settings.saved", actor_type="user", actor_id=actor,
            entity_type="research_settings", entity_id=row.id, details={"provider": row.provider,
                "enabled": row.enabled, "revision": row.revision, "daily_limit": row.daily_limit,
                "key_changed": payload.api_key is not None, "network_called": False})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ResearchSettingsConflict("Search settings changed; refresh before saving") from None
    return setup_status(db)


def reserve(db, row):
    """Commit admission before external I/O; failures count, never auto-retry."""
    day = utcnow().date().isoformat()
    result = db.execute(update(ResearchSettings).where(ResearchSettings.id == row.id,
        ResearchSettings.tenant_id == row.tenant_id, ResearchSettings.region_id == row.region_id,
        ResearchSettings.revision == row.revision, ResearchSettings.enabled.is_(True),
        or_(ResearchSettings.quota_day != day, ResearchSettings.calls_today < ResearchSettings.daily_limit)
    ).values(quota_day=day, calls_today=case((ResearchSettings.quota_day == day, ResearchSettings.calls_today + 1), else_=1))
        .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        db.rollback()
        raise ResearchUnavailable("Search is disabled, its settings changed, or its daily request limit was reached")
    db.commit()


def test_connection(db, payload, *, actor):
    from . import research
    row = connection(db)
    if row is None or row.revision != payload.expected_revision:
        raise ResearchSettingsConflict("Search settings changed; save and refresh before testing")
    # Fixed public query, no user prompt, private inventory or model call.
    result = research.search({"query": "Prometheus SNMP exporter official documentation", "limit": 1},
                             db=db, expected_revision=payload.expected_revision)
    outcome = "passed" if result["status"] in {"ok", "no_results"} else "failed"
    message = ("Search API responded successfully. No device or AI model was contacted."
               if outcome == "passed" else result.get("warning") or "Search connection failed")
    updated = db.execute(update(ResearchSettings).where(ResearchSettings.id == row.id,
        ResearchSettings.tenant_id == row.tenant_id, ResearchSettings.region_id == row.region_id,
        ResearchSettings.revision == payload.expected_revision).values(last_test_status=outcome, last_test_at=utcnow())
        .execution_options(synchronize_session=False))
    if updated.rowcount != 1:
        db.rollback()
        raise ResearchSettingsConflict("Search settings changed while testing; the result was not applied to the new configuration")
    record_audit_event(db, event_type="research.settings.tested", actor_type="user", actor_id=actor,
        entity_type="research_settings", entity_id=row.id, details={"revision": payload.expected_revision, "status": outcome})
    db.commit()
    return {"status": outcome, "message": message, "revision": payload.expected_revision, "settings": setup_status(db)}
