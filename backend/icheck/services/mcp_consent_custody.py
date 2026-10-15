"""Consent admission and retained history; never credentials or Tool authority."""
from pydantic import ValidationError
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import MCPOAuthConsentAttempt, MCPOAuthFamilyLocalExecution, MCPOAuthFamilyRecovery, MCPServer, CredentialProfile
from ..oauth_consent import (
    OPEN_CONSENT_STATUSES, OAuthConsentAuthority, OAuthConsentProfile, OAuthConsentSnapshot,
)
from .control_plane_auth import PrincipalContext
from .current_authority import current_human_authority


def assert_no_open_consent(db: Session, server: MCPServer):
    from .mcp_oauth import MCPOAuthError
    contained = exists(select(MCPOAuthFamilyLocalExecution.id).join(MCPOAuthFamilyRecovery,
        MCPOAuthFamilyLocalExecution.recovery_id == MCPOAuthFamilyRecovery.id).where(
        MCPOAuthFamilyRecovery.id == MCPOAuthConsentAttempt.family_recovery_id,
        MCPOAuthFamilyRecovery.attempt_id == MCPOAuthConsentAttempt.id,
        MCPOAuthFamilyRecovery.status == "issuer_verified",
        MCPOAuthFamilyLocalExecution.status == "complete",
        MCPOAuthFamilyLocalExecution.completed_at == MCPOAuthConsentAttempt.family_contained_at,
        MCPOAuthFamilyLocalExecution.tenant_id == MCPOAuthConsentAttempt.tenant_id,
        MCPOAuthFamilyLocalExecution.region_id == MCPOAuthConsentAttempt.region_id))
    if db.scalar(select(MCPOAuthConsentAttempt.id).where(
            MCPOAuthConsentAttempt.server_id == server.id,
            MCPOAuthConsentAttempt.tenant_id == server.tenant_id,
            MCPOAuthConsentAttempt.region_id == server.region_id,
            MCPOAuthConsentAttempt.status.in_(OPEN_CONSENT_STATUSES),
            or_(MCPOAuthConsentAttempt.family_contained_at.is_(None), ~contained)).limit(1)) is not None:
        raise MCPOAuthError("An admitted consent outcome needs independent family recovery before reconnect or cleanup", code="consent_recovery_required")


def assert_consent_eligible(db: Session, server: MCPServer):
    from .mcp_oauth import MCPOAuthError
    from ..oauth_recovery import OAuthRecoveryCustody
    assert_no_open_consent(db, server)
    if not server.enabled or server.auth_mode != "oauth_authorization_code":
        raise MCPOAuthError("MCP OAuth server is unavailable")
    if server.oauth_status == "revocation_pending" or server.oauth_revocation_intent is not None:
        raise MCPOAuthError("MCP OAuth cleanup must finish before reconnect", code="revocation_pending")
    if server.oauth_status not in {"disconnected", "connected", "expired", "revoked"}:
        raise MCPOAuthError("MCP OAuth consent state is unavailable")
    if server.oauth_recovery_custody is not None:
        try:
            recovery = OAuthRecoveryCustody.model_validate(server.oauth_recovery_custody)
        except ValidationError as exc:
            raise MCPOAuthError("OAuth recovery custody is invalid; execution remains fenced", code="revocation_pending") from exc
        if recovery.status != "complete":
            raise MCPOAuthError("OAuth recovery must finish before fresh consent", code="revocation_pending")


def _profile_snapshot(profile: CredentialProfile) -> OAuthConsentProfile:
    return OAuthConsentProfile(id=profile.id, revision=profile.revision,
        provider=profile.provider, secret_ref=profile.secret_ref)


def snapshot_authority(db: Session, snapshot: OAuthConsentSnapshot, settings: Settings):
    from .mcp_oauth import MCPOAuthError
    source = snapshot.authority
    if source.auth_method == "development":
        if settings.control_plane_auth_mode != "disabled" or settings.environment == "production":
            raise MCPOAuthError("Consent requires a currently authenticated human", code="authorization_withdrawn")
        return None
    actor = PrincipalContext(principal_id=source.principal_id, subject=source.subject, principal_type="user",
        permissions=frozenset({"tools.admin"}), role_names=(), authorization_scope={"all": True},
        auth_method=source.auth_method, tenant_id=snapshot.tenant_id, region_id=snapshot.region_id,
        access_token_id=source.credential_id if source.auth_method == "bearer" else None,
        session_id=source.credential_id if source.auth_method == "browser_session" else None)
    try:
        return current_human_authority(db, actor, permissions=("tools.admin",),
            tenant_id=snapshot.tenant_id, region_id=snapshot.region_id)
    except PermissionError as exc:
        raise MCPOAuthError("Consent administrator authority was withdrawn or expired", code="authorization_withdrawn") from exc


def assert_live_authority(db: Session, authority):
    from .mcp_oauth import MCPOAuthError
    if authority is not None:
        try:
            authority.assert_live(db)
        except PermissionError as exc:
            raise MCPOAuthError("Consent administrator authority expired during a wait", code="authorization_withdrawn") from exc


def build_consent_snapshot(db: Session, server: MCPServer, *, actor: str,
                           principal: PrincipalContext | None, settings: Settings) -> OAuthConsentSnapshot:
    from .mcp_oauth import MCPOAuthError, _profile, _token_profile
    if principal is not None and principal.principal_type == "user":
        try:
            live = current_human_authority(db, principal, permissions=("tools.admin",),
                tenant_id=server.tenant_id, region_id=server.region_id)
        except PermissionError as exc:
            raise MCPOAuthError("Consent requires a currently authorized human", code="authorization_withdrawn") from exc
        source = OAuthConsentAuthority(auth_method=live.actor.auth_method,
            principal_id=live.actor.principal_id, subject=live.actor.subject,
            credential_id=live.actor.access_token_id if live.actor.auth_method == "bearer" else live.actor.session_id)
    elif (settings.control_plane_auth_mode == "disabled" and settings.environment != "production"
            and (principal is None or principal.principal_type == "development")):
        source = OAuthConsentAuthority(auth_method="development", subject=actor)
    else:
        raise MCPOAuthError("Consent requires authenticated human provenance", code="authorization_withdrawn")
    profile = _token_profile(db, server)
    client = _profile(db, server.oauth_client_secret_profile_ref) if server.oauth_client_secret_profile_ref else None
    if (profile.tenant_id, profile.region_id) != (server.tenant_id, server.region_id) or (
            client is not None and (client.tenant_id, client.region_id) != (server.tenant_id, server.region_id)):
        raise MCPOAuthError("Consent credential profile is unavailable in this namespace")
    if not server.oauth_client_id:
        raise MCPOAuthError("Consent client identity is not configured")
    if client is not None and not client.enabled:
        raise MCPOAuthError("MCP OAuth client secret profile is unavailable")
    if server.oauth_client_secret_profile_ref and client is None:
        raise MCPOAuthError("MCP OAuth client secret profile is unavailable")
    if not settings.server_secret_vault_address or not settings.mcp_oauth_redirect_uri:
        raise MCPOAuthError("MCP OAuth storage and callback are not configured")
    return OAuthConsentSnapshot(server_id=server.id, tenant_id=server.tenant_id, region_id=server.region_id,
        server_name=server.name, endpoint_url=server.endpoint_url, client_id=server.oauth_client_id,
        generation=server.oauth_generation, token_profile=_profile_snapshot(profile),
        client_profile=_profile_snapshot(client) if client else None,
        vault_address=settings.server_secret_vault_address, vault_namespace=settings.server_secret_vault_namespace,
        redirect_uri=settings.mcp_oauth_redirect_uri, authority=source)


def current_consent_snapshot(db: Session, server: MCPServer, snapshot: OAuthConsentSnapshot, settings: Settings):
    from .mcp_oauth import MCPOAuthError, _profile, _token_profile
    if (not server.enabled or server.auth_mode != "oauth_authorization_code"
            or (server.id, server.tenant_id, server.region_id, server.name, server.endpoint_url,
                server.oauth_client_id, server.oauth_generation) !=
               (snapshot.server_id, snapshot.tenant_id, snapshot.region_id, snapshot.server_name,
                snapshot.endpoint_url, snapshot.client_id, snapshot.generation)
            or (settings.server_secret_vault_address, settings.server_secret_vault_namespace,
                settings.mcp_oauth_redirect_uri) != (snapshot.vault_address, snapshot.vault_namespace, snapshot.redirect_uri)):
        raise MCPOAuthError("Consent configuration was superseded; original custody is retained", code="consent_superseded")
    profile = _token_profile(db, server)
    client = _profile(db, server.oauth_client_secret_profile_ref) if server.oauth_client_secret_profile_ref else None
    if (profile.tenant_id, profile.region_id) != (server.tenant_id, server.region_id) or _profile_snapshot(profile) != snapshot.token_profile:
        raise MCPOAuthError("Consent token profile changed; original target is retained", code="consent_superseded")
    if (snapshot.client_profile is None) != (client is None) or (client is not None and (
            not client.enabled or (client.tenant_id, client.region_id) != (server.tenant_id, server.region_id)
            or _profile_snapshot(client) != snapshot.client_profile)):
        raise MCPOAuthError("Consent client profile changed; original target is retained", code="consent_superseded")
    return profile
