from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..auth_schemas import (
    AccessTokenCreate,
    BootstrapRequest,
    PrincipalCreate,
    PrincipalUpdate,
    RoleBindingCreate,
    RoleCreate,
)
from ..database import (
    DEFAULT_REGION_ID,
    DEFAULT_TENANT_ID,
    set_session_namespace,
)
from ..models import (
    ControlPlaneAccessToken,
    ControlPlaneBrowserSession,
    ControlPlanePrincipal,
    ControlPlaneRole,
    ControlPlaneRoleBinding,
    ControlPlaneWorkloadIdentity,
    Region,
    Tenant,
)
from ..tenancy_schemas import TenantAdminCreate
from ..worker_auth import hash_token
from ..passwords import hash_password
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .tenancy import (
    DEFAULT_REGION_CODE,
    DEFAULT_TENANT_SLUG,
    ensure_default_namespace,
    resolve_region,
    resolve_tenant,
)


BUILTIN_ROLES: dict[str, tuple[str, list[str]]] = {
    "viewer": (
        "Read inventory, alerts, metrics, logs, and investigations.",
        [
            "assets.read",
            "endpoints.read",
            "alerts.read",
            "metrics.read",
            "logs.read",
            "investigations.read",
            "operations.read",
            "collectors.read",
            "agent.workers.read",
            "scaling.read",
            "services.read",
        ],
    ),
    "operator": (
        "Operate scoped assets, alerts, collectors, and investigations.",
        [
            "assets.read",
            "assets.write",
            "assets.activate",
            "endpoints.read",
            "alerts.read",
            "alerts.manage",
            "metrics.read",
            "logs.read",
            "investigations.read",
            "investigations.create",
            "investigations.cancel",
            "ai.profiles.read",
            "changes.plan",
            "changes.policy.read",
            "operations.read",
            "collectors.read",
            "agent.workers.read",
            "scaling.read",
            "credentials.read",
            "services.read",
        ],
    ),
    "approver": (
        "Review and approve state-changing agent proposals.",
        [
            "assets.read",
            "alerts.read",
            "investigations.read",
            "changes.approve",
            "changes.policy.read",
        ],
    ),
    "capability_author": (
        "Design, validate, and publish governed platform capabilities.",
        [
            "capabilities.read",
            "capabilities.manage",
            "credentials.read",
        ],
    ),
    "service_owner": (
        "Maintain governed service ownership, objectives, and component bindings.",
        [
            "assets.read",
            "endpoints.read",
            "services.read",
            "services.manage",
            "capabilities.read",
            "metrics.read",
            "logs.read",
            "alerts.read",
            "investigations.read",
        ],
    ),
    "admin": ("Full control-plane administration.", ["*"]),
}


class ControlPlaneAuthenticationError(ValueError):
    pass


class ControlPlaneAuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class PrincipalContext:
    principal_id: str | None
    subject: str
    principal_type: str
    permissions: frozenset[str]
    role_names: tuple[str, ...]
    authorization_scope: dict[str, Any]
    auth_method: str
    session_id: str | None = None
    tenant_id: str = DEFAULT_TENANT_ID
    tenant_slug: str = DEFAULT_TENANT_SLUG
    region_id: str = DEFAULT_REGION_ID
    region_code: str = DEFAULT_REGION_CODE
    platform_admin: bool = False
    # Internal provenance from authentication, never supplied by an API payload.
    access_token_id: str | None = None

    def permits(self, *required: str) -> bool:
        return "*" in self.permissions or all(
            permission in self.permissions for permission in required
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def development_principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id=None,
        subject="development",
        principal_type="development",
        permissions=frozenset({"*"}),
        role_names=("development-admin",),
        authorization_scope={"all": True},
        auth_method="disabled",
        tenant_id=DEFAULT_TENANT_ID,
        tenant_slug=DEFAULT_TENANT_SLUG,
        region_id=DEFAULT_REGION_ID,
        region_code=DEFAULT_REGION_CODE,
        platform_admin=True,
    )


def ensure_builtin_roles(db: Session) -> None:
    changed = False
    for name, (description, permissions) in BUILTIN_ROLES.items():
        role = db.scalar(select(ControlPlaneRole).where(ControlPlaneRole.name == name))
        if role is None:
            db.add(
                ControlPlaneRole(
                    name=name,
                    description=description,
                    permissions=permissions,
                    system=True,
                    created_by="system.bootstrap",
                )
            )
            changed = True
            continue
        if (
            role.description != description
            or role.permissions != permissions
            or not role.system
        ):
            role.description = description
            role.permissions = permissions
            role.system = True
            changed = True
    if changed:
        db.commit()


def _merge_authorization_scopes(
    bindings: list[ControlPlaneRoleBinding],
) -> dict[str, Any]:
    scopes = [binding.scope or {} for binding in bindings]
    if any(scope.get("all") is True for scope in scopes):
        return {"all": True}

    merged: dict[str, Any] = {}
    for key in ("sites", "device_ids"):
        values = {
            str(item)
            for scope in scopes
            for item in scope.get(key, [])
            if isinstance(item, (str, int))
        }
        if values:
            merged[key] = sorted(values)
    return merged


def principal_context(
    principal: ControlPlanePrincipal,
    *,
    db: Session | None = None,
    tenant_selector: str | None = None,
    region_selector: str | None = None,
    auth_method: str = "bearer",
    session_id: str | None = None,
    access_token_id: str | None = None,
) -> PrincipalContext:
    if db is None:
        tenant_id = principal.tenant_id
        tenant_slug = principal.tenant_id
        region_id = principal.region_id
        region_code = principal.region_id
    else:
        tenant = db.get(Tenant, principal.tenant_id)
        if tenant is None or not tenant.enabled:
            raise ControlPlaneAuthorizationError(
                "The principal tenant is unavailable"
            )
        if tenant_selector:
            requested_tenant = resolve_tenant(db, tenant_selector)
            if requested_tenant is None or requested_tenant.id != tenant.id:
                raise ControlPlaneAuthorizationError(
                    "The selected tenant is not assigned to this principal"
                )
        region = resolve_region(
            db,
            tenant.id,
            region_selector or principal.region_id or tenant.default_region_id,
        )
        if region is None or not region.enabled:
            raise ControlPlaneAuthorizationError(
                "The selected region is unavailable"
            )
        allowed_regions = set(principal.allowed_region_ids or [])
        if allowed_regions and region.id not in allowed_regions:
            raise ControlPlaneAuthorizationError(
                "The selected region is not assigned to this principal"
            )
        tenant_id = tenant.id
        tenant_slug = tenant.slug
        region_id = region.id
        region_code = region.code

    bindings = [
        binding
        for binding in principal.role_bindings
        if binding.tenant_id == tenant_id and binding.region_id == region_id
    ]
    permissions = {
        permission
        for binding in bindings
        for permission in (binding.role.permissions or [])
    }
    return PrincipalContext(
        principal_id=principal.id,
        subject=principal.subject,
        principal_type=principal.principal_type,
        permissions=frozenset(permissions),
        role_names=tuple(sorted({binding.role.name for binding in bindings})),
        authorization_scope=_merge_authorization_scopes(bindings),
        auth_method=auth_method,
        session_id=session_id,
        access_token_id=access_token_id,
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
        region_id=region_id,
        region_code=region_code,
        platform_admin=principal.platform_admin,
    )


def authenticate_access_token(
    db: Session,
    authorization: str | None,
    *,
    tenant_selector: str | None = None,
    region_selector: str | None = None,
) -> PrincipalContext:
    scheme, _, raw_token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not raw_token:
        raise ControlPlaneAuthenticationError("Control-plane bearer token is required")
    workload_token = raw_token.startswith("icw_")
    if (
        not workload_token
        and not raw_token.startswith("icp_")
    ) or len(raw_token) < 20:
        raise ControlPlaneAuthenticationError("Invalid control-plane bearer token")

    token = db.scalar(
        select(ControlPlaneAccessToken)
        .options(
            selectinload(ControlPlaneAccessToken.principal)
            .selectinload(ControlPlanePrincipal.role_bindings)
            .selectinload(ControlPlaneRoleBinding.role)
        )
        .where(ControlPlaneAccessToken.token_prefix == raw_token[:16])
    )
    now = datetime.now(UTC)
    workload_identity = (
        db.get(ControlPlaneWorkloadIdentity, token.workload_identity_id)
        if token is not None and workload_token and token.workload_identity_id
        else None
    )
    if (
        token is None
        or not secrets.compare_digest(token.token_hash, hash_token(raw_token))
        or token.revoked_at is not None
        or _as_utc(token.expires_at) <= now
        or not token.principal.enabled
        or (
            workload_token
            and (
                workload_identity is None
                or not workload_identity.enabled
                or workload_identity.principal_id != token.principal_id
                or workload_identity.tenant_id != token.tenant_id
                or workload_identity.region_id != token.region_id
            )
        )
        or (not workload_token and token.workload_identity_id is not None)
    ):
        raise ControlPlaneAuthenticationError("Invalid or expired control-plane token")

    token.last_used_at = now
    db.commit()
    return principal_context(
        token.principal,
        db=db,
        tenant_selector=tenant_selector,
        region_selector=region_selector,
        auth_method="workload" if workload_token else "bearer",
        access_token_id=token.id,
    )


def _new_access_token(
    db: Session,
    *,
    principal: ControlPlanePrincipal,
    name: str,
    expires_in_hours: int,
    actor: str,
) -> tuple[ControlPlaneAccessToken, str]:
    if not 1 <= expires_in_hours <= 8760:
        raise ValueError("expires_in_hours must be between 1 and 8760")
    for _ in range(5):
        raw_token = f"icp_{secrets.token_urlsafe(32)}"
        prefix = raw_token[:16]
        exists = db.scalar(
            select(ControlPlaneAccessToken.id).where(
                ControlPlaneAccessToken.token_prefix == prefix
            )
        )
        if exists is None:
            break
    else:
        raise RuntimeError("Unable to allocate a unique access-token prefix")

    token = ControlPlaneAccessToken(
        principal=principal,
        tenant_id=principal.tenant_id,
        region_id=principal.region_id,
        name=name,
        token_prefix=prefix,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=expires_in_hours),
        created_by=actor,
    )
    db.add(token)
    return token, raw_token


def issue_workload_access_token(
    db: Session,
    *,
    principal: ControlPlanePrincipal,
    workload_identity_id: str,
    expires_at: datetime,
) -> tuple[ControlPlaneAccessToken, str]:
    now = datetime.now(UTC)
    expires_at = _as_utc(expires_at)
    if expires_at <= now or expires_at > now + timedelta(minutes=60):
        raise ValueError(
            "Workload access-token expiry must be within the next 60 minutes"
        )
    for _ in range(5):
        raw_token = f"icw_{secrets.token_urlsafe(32)}"
        prefix = raw_token[:16]
        exists = db.scalar(
            select(ControlPlaneAccessToken.id).where(
                ControlPlaneAccessToken.token_prefix == prefix
            )
        )
        if exists is None:
            break
    else:
        raise RuntimeError("Unable to allocate a unique workload-token prefix")
    token = ControlPlaneAccessToken(
        principal=principal,
        workload_identity_id=workload_identity_id,
        tenant_id=principal.tenant_id,
        region_id=principal.region_id,
        name="federated-workload",
        token_prefix=prefix,
        token_hash=hash_token(raw_token),
        expires_at=expires_at,
        created_by="workload-federation",
    )
    db.add(token)
    db.flush()
    return token, raw_token


def bootstrap_admin(
    db: Session,
    payload: BootstrapRequest,
    *,
    default_token_ttl_hours: int,
) -> tuple[ControlPlanePrincipal, ControlPlaneAccessToken, str]:
    if (db.scalar(select(func.count()).select_from(ControlPlanePrincipal)) or 0) > 0:
        raise ValueError("Control-plane bootstrap has already been completed")
    tenant, region = ensure_default_namespace(db)
    set_session_namespace(db, tenant.id, region.id)
    ensure_builtin_roles(db)
    admin_role = db.scalar(
        select(ControlPlaneRole).where(ControlPlaneRole.name == "admin")
    )
    if admin_role is None:
        raise RuntimeError("Built-in admin role is unavailable")

    principal = ControlPlanePrincipal(
        subject=payload.subject,
        display_name=payload.display_name,
        principal_type=payload.principal_type,
        enabled=payload.enabled,
        allowed_region_ids=payload.allowed_region_ids,
        platform_admin=True,
        tenant_id=tenant.id,
        region_id=region.id,
        created_by="system.bootstrap",
    )
    if payload.password is not None:
        if payload.principal_type != "user":
            raise ValueError("Passwords can only be assigned to human users")
        principal.password_hash = hash_password(payload.password.get_secret_value())
    db.add(principal)
    db.flush()
    db.add(
        ControlPlaneRoleBinding(
            principal=principal,
            role=admin_role,
            scope={"all": True},
            tenant_id=tenant.id,
            region_id=region.id,
            created_by="system.bootstrap",
        )
    )
    token, raw_token = _new_access_token(
        db,
        principal=principal,
        name=payload.token_name,
        expires_in_hours=payload.expires_in_hours or default_token_ttl_hours,
        actor="system.bootstrap",
    )
    record_audit_event(
        db,
        event_type="auth.control_plane.bootstrapped",
        actor_type="system",
        actor_id="system.bootstrap",
        entity_type="principal",
        entity_id=principal.id,
        details={"subject": principal.subject, "token_prefix": token.token_prefix},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Principal subject already exists") from exc
    db.refresh(principal)
    db.refresh(token)
    return principal, token, raw_token


def create_principal(
    db: Session,
    payload: PrincipalCreate,
    *,
    actor: PrincipalContext,
) -> ControlPlanePrincipal:
    principal = ControlPlanePrincipal(
        **payload.model_dump(),
        tenant_id=actor.tenant_id,
        region_id=actor.region_id,
        platform_admin=False,
        created_by=actor.subject,
    )
    if principal.allowed_region_ids:
        valid_region_ids = set(
            db.scalars(
                select(Region.id).where(
                    Region.tenant_id == actor.tenant_id,
                    Region.id.in_(principal.allowed_region_ids),
                    Region.enabled.is_(True),
                )
            ).all()
        )
        if valid_region_ids != set(principal.allowed_region_ids):
            raise ValueError(
                "allowed_region_ids must reference enabled regions in this tenant"
            )
    db.add(principal)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.principal.created",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="principal",
            entity_id=principal.id,
            details={
                "subject": principal.subject,
                "principal_type": principal.principal_type,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Principal subject already exists") from exc
    db.refresh(principal)
    return principal


def update_principal(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: PrincipalUpdate,
    *,
    actor: PrincipalContext,
) -> ControlPlanePrincipal:
    stored = db.scalar(
        select(ControlPlanePrincipal)
        .where(
            ControlPlanePrincipal.id == principal.id,
            ControlPlanePrincipal.tenant_id == actor.tenant_id,
        )
        .with_for_update()
    )
    if stored is None:
        raise LookupError("Principal not found")
    if (
        not payload.enabled
        and stored.id == actor.principal_id
        and stored.enabled
    ):
        raise ValueError(
            "The current principal cannot disable itself; use another administrator"
        )

    previous_enabled = stored.enabled
    revoked_tokens = 0
    revoked_sessions = 0
    reason_sha256 = hash_token(payload.reason)
    if previous_enabled and not payload.enabled:
        now = datetime.now(UTC)
        token_result = db.execute(
            update(ControlPlaneAccessToken)
            .where(
                ControlPlaneAccessToken.principal_id == stored.id,
                ControlPlaneAccessToken.revoked_at.is_(None),
            )
            .values(
                revoked_at=now,
                revoked_by=actor.subject,
                revocation_reason="principal_disabled",
            )
        )
        session_result = db.execute(
            update(ControlPlaneBrowserSession)
            .where(
                ControlPlaneBrowserSession.tenant_id == actor.tenant_id,
                ControlPlaneBrowserSession.principal_id == stored.id,
                ControlPlaneBrowserSession.revoked_at.is_(None),
            )
            .values(
                revoked_at=now,
                revoked_by=actor.subject,
                revocation_reason_sha256=reason_sha256,
            )
        )
        revoked_tokens = max(0, int(token_result.rowcount or 0))
        revoked_sessions = max(0, int(session_result.rowcount or 0))

    stored.enabled = payload.enabled
    record_audit_event(
        db,
        event_type="auth.principal.updated",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="principal",
        entity_id=stored.id,
        details={
            "previous_enabled": previous_enabled,
            "enabled": stored.enabled,
            "revoked_tokens": revoked_tokens,
            "revoked_browser_sessions": revoked_sessions,
            "reason_sha256": reason_sha256,
        },
    )
    db.commit()
    db.refresh(stored)
    return stored


def provision_tenant_admin(
    db: Session,
    tenant: Tenant,
    region: Region,
    payload: TenantAdminCreate,
    *,
    actor: PrincipalContext,
    default_token_ttl_hours: int,
) -> tuple[ControlPlanePrincipal, ControlPlaneAccessToken, str]:
    if not actor.platform_admin:
        raise ControlPlaneAuthorizationError(
            "Platform administration is required"
        )
    admin_role = db.scalar(
        select(ControlPlaneRole).where(
            ControlPlaneRole.name == "admin",
            ControlPlaneRole.system.is_(True),
        )
    )
    if admin_role is None:
        raise RuntimeError("Built-in admin role is unavailable")
    principal_values = payload.model_dump(
        exclude={"token_name", "expires_in_hours"}
    )
    principal = ControlPlanePrincipal(
        **principal_values,
        tenant_id=tenant.id,
        region_id=region.id,
        platform_admin=False,
        created_by=actor.subject,
    )
    db.add(principal)
    try:
        db.flush()
        db.add(
            ControlPlaneRoleBinding(
                principal=principal,
                role=admin_role,
                scope={"all": True},
                tenant_id=tenant.id,
                region_id=region.id,
                created_by=actor.subject,
            )
        )
        token, raw_token = _new_access_token(
            db,
            principal=principal,
            name=payload.token_name,
            expires_in_hours=(
                payload.expires_in_hours or default_token_ttl_hours
            ),
            actor=actor.subject,
        )
        record_audit_event(
            db,
            event_type="tenancy.admin.provisioned",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="principal",
            entity_id=principal.id,
            details={
                "tenant_id": tenant.id,
                "region_id": region.id,
                "subject": principal.subject,
                "token_prefix": token.token_prefix,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Principal subject already exists in this tenant"
        ) from exc
    db.refresh(principal)
    db.refresh(token)
    return principal, token, raw_token


def create_role(
    db: Session,
    payload: RoleCreate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneRole:
    if payload.name in BUILTIN_ROLES:
        raise ValueError("Built-in role names are reserved")
    role = ControlPlaneRole(
        **payload.model_dump(),
        system=False,
        tenant_id=actor.tenant_id,
        region_id=actor.region_id,
        created_by=actor.subject,
    )
    db.add(role)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.role.created",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="role",
            entity_id=role.id,
            details={"name": role.name, "permissions": role.permissions},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Role name already exists") from exc
    db.refresh(role)
    return role


def create_role_binding(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: RoleBindingCreate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneRoleBinding:
    role = db.get(ControlPlaneRole, payload.role_id)
    if role is None:
        raise LookupError("Role not found")
    if principal.tenant_id != actor.tenant_id:
        raise LookupError("Principal not found")
    if not role.system and (
        role.tenant_id != actor.tenant_id or role.region_id != actor.region_id
    ):
        raise LookupError("Role not found")
    assert_no_inline_secrets(payload.scope, "role_binding.scope")
    binding = ControlPlaneRoleBinding(
        principal=principal,
        role=role,
        scope=payload.scope,
        tenant_id=actor.tenant_id,
        region_id=actor.region_id,
        created_by=actor.subject,
    )
    db.add(binding)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.role_binding.created",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="role_binding",
            entity_id=binding.id,
            details={
                "principal_id": principal.id,
                "role_id": role.id,
                "scope": payload.scope,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("Principal already has this role") from exc
    db.refresh(binding)
    return binding


def revoke_role_binding(
    db: Session,
    binding_id: str,
    *,
    reason: str,
    actor: PrincipalContext,
) -> None:
    binding = db.scalar(
        select(ControlPlaneRoleBinding)
        .where(
            ControlPlaneRoleBinding.id == binding_id,
            ControlPlaneRoleBinding.tenant_id == actor.tenant_id,
            ControlPlaneRoleBinding.region_id == actor.region_id,
        )
        .with_for_update()
    )
    if binding is None:
        raise LookupError("Role binding not found")
    if binding.principal_id == actor.principal_id:
        raise ValueError(
            "The current principal cannot revoke its own role binding; "
            "use another administrator"
        )
    principal_id = binding.principal_id
    role_id = binding.role_id
    record_audit_event(
        db,
        event_type="auth.role_binding.revoked",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="role_binding",
        entity_id=binding.id,
        details={
            "principal_id": principal_id,
            "role_id": role_id,
            "reason_sha256": hash_token(reason),
        },
    )
    db.delete(binding)
    db.commit()


def issue_access_token(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: AccessTokenCreate,
    *,
    actor: PrincipalContext,
    default_token_ttl_hours: int,
) -> tuple[ControlPlaneAccessToken, str]:
    if not principal.enabled:
        raise ValueError("Cannot issue an access token for a disabled principal")
    token, raw_token = _new_access_token(
        db,
        principal=principal,
        name=payload.name,
        expires_in_hours=payload.expires_in_hours or default_token_ttl_hours,
        actor=actor.subject,
    )
    db.flush()
    record_audit_event(
        db,
        event_type="auth.access_token.issued",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="access_token",
        entity_id=token.id,
        details={"principal_id": principal.id, "token_prefix": token.token_prefix},
    )
    db.commit()
    db.refresh(token)
    return token, raw_token


def revoke_access_token(
    db: Session,
    token: ControlPlaneAccessToken,
    *,
    reason: str,
    actor: PrincipalContext,
) -> ControlPlaneAccessToken:
    if token.revoked_at is not None:
        raise ValueError("Access token is already revoked")
    token.revoked_at = datetime.now(UTC)
    token.revoked_by = actor.subject
    token.revocation_reason = reason
    record_audit_event(
        db,
        event_type="auth.access_token.revoked",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="access_token",
        entity_id=token.id,
        details={"principal_id": token.principal_id, "token_prefix": token.token_prefix},
    )
    db.commit()
    db.refresh(token)
    return token


def create_browser_session(
    db: Session,
    principal: ControlPlanePrincipal,
    *,
    ttl_hours: int,
    actor: PrincipalContext,
    commit: bool = True,
    auth_source: Literal[
        "local_token",
        "local_password",
        "oidc",
        "trusted_proxy",
    ] = "local_token",
    federated_identity_id: str | None = None,
) -> tuple[ControlPlaneBrowserSession, str, str]:
    if not 1 <= ttl_hours <= 168:
        raise ValueError("Browser-session TTL must be between 1 and 168 hours")
    if (auth_source in {"local_token", "local_password"}) != (federated_identity_id is None):
        raise ValueError(
            "Federated browser sessions require an identity binding"
        )
    for _ in range(5):
        raw_token = f"icb_{secrets.token_urlsafe(32)}"
        prefix = raw_token[:16]
        exists = db.scalar(
            select(ControlPlaneBrowserSession.id).where(
                ControlPlaneBrowserSession.token_prefix == prefix
            )
        )
        if exists is None:
            break
    else:
        raise RuntimeError("Unable to allocate a unique browser session")
    csrf_token = f"icc_{secrets.token_urlsafe(32)}"
    session = ControlPlaneBrowserSession(
        principal=principal,
        tenant_id=actor.tenant_id,
        region_id=actor.region_id,
        token_prefix=prefix,
        token_hash=hash_token(raw_token),
        csrf_token_hash=hash_token(csrf_token),
        auth_source=auth_source,
        federated_identity_id=federated_identity_id,
        expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
    )
    db.add(session)
    db.flush()
    record_audit_event(
        db,
        event_type="auth.browser_session.created",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="browser_session",
        entity_id=session.id,
        details={
            "principal_id": principal.id,
            "token_prefix": session.token_prefix,
            "auth_source": session.auth_source,
            "federated_identity_id": session.federated_identity_id,
            "expires_at": session.expires_at.isoformat(),
        },
    )
    if commit:
        db.commit()
        db.refresh(session)
    return session, raw_token, csrf_token


def authenticate_browser_session(
    db: Session,
    raw_token: str | None,
    *,
    csrf_token: str | None = None,
    require_csrf: bool = False,
    tenant_selector: str | None = None,
    region_selector: str | None = None,
) -> PrincipalContext:
    if not raw_token or not raw_token.startswith("icb_") or len(raw_token) < 20:
        raise ControlPlaneAuthenticationError(
            "Control-plane browser session is required"
        )
    session = db.scalar(
        select(ControlPlaneBrowserSession)
        .options(
            selectinload(ControlPlaneBrowserSession.principal)
            .selectinload(ControlPlanePrincipal.role_bindings)
            .selectinload(ControlPlaneRoleBinding.role)
        )
        .where(ControlPlaneBrowserSession.token_prefix == raw_token[:16])
    )
    now = datetime.now(UTC)
    if (
        session is None
        or not secrets.compare_digest(
            session.token_hash, hash_token(raw_token)
        )
        or session.revoked_at is not None
        or _as_utc(session.expires_at) <= now
        or not session.principal.enabled
    ):
        raise ControlPlaneAuthenticationError(
            "Invalid or expired control-plane browser session"
        )
    if require_csrf and (
        not csrf_token
        or not secrets.compare_digest(
            session.csrf_token_hash, hash_token(csrf_token)
        )
    ):
        raise ControlPlaneAuthorizationError(
            "Valid X-Icheck-CSRF-Token header is required"
        )
    session.last_used_at = now
    db.commit()
    return principal_context(
        session.principal,
        db=db,
        tenant_selector=tenant_selector,
        region_selector=region_selector,
        auth_method="browser_session",
        session_id=session.id,
    )


def rotate_browser_csrf(
    db: Session,
    session_id: str,
) -> str:
    session = db.get(ControlPlaneBrowserSession, session_id)
    if session is None or session.revoked_at is not None:
        raise ControlPlaneAuthenticationError("Browser session is unavailable")
    csrf_token = f"icc_{secrets.token_urlsafe(32)}"
    session.csrf_token_hash = hash_token(csrf_token)
    db.commit()
    return csrf_token


def revoke_browser_session(
    db: Session,
    session_id: str,
    *,
    actor: PrincipalContext,
    reason: str = "user_logout",
    commit: bool = True,
) -> ControlPlaneBrowserSession:
    session = db.scalar(
        select(ControlPlaneBrowserSession)
        .where(ControlPlaneBrowserSession.id == session_id)
        .with_for_update()
    )
    if session is None:
        raise ControlPlaneAuthenticationError("Browser session is unavailable")
    if session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
        session.revoked_by = actor.subject
        session.revocation_reason_sha256 = hash_token(reason)
        record_audit_event(
            db,
            event_type="auth.browser_session.revoked",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="browser_session",
            entity_id=session.id,
            details={
                "principal_id": session.principal_id,
                "auth_source": session.auth_source,
                "federated_identity_id": session.federated_identity_id,
                "reason_sha256": session.revocation_reason_sha256,
            },
        )
        if commit:
            db.commit()
            db.refresh(session)
    return session


def revoke_federated_browser_sessions(
    db: Session,
    *,
    auth_source: Literal["oidc", "trusted_proxy"],
    federated_identity_id: str,
    reason: str,
    actor: PrincipalContext,
) -> int:
    now = datetime.now(UTC)
    reason_sha256 = hash_token(reason)
    result = db.execute(
        update(ControlPlaneBrowserSession)
        .where(
            ControlPlaneBrowserSession.tenant_id == actor.tenant_id,
            ControlPlaneBrowserSession.auth_source == auth_source,
            ControlPlaneBrowserSession.federated_identity_id
            == federated_identity_id,
            ControlPlaneBrowserSession.revoked_at.is_(None),
        )
        .values(
            revoked_at=now,
            revoked_by=actor.subject,
            revocation_reason_sha256=reason_sha256,
        )
    )
    revoked_count = max(0, int(result.rowcount or 0))
    if revoked_count:
        record_audit_event(
            db,
            event_type="auth.browser_sessions.revoked_by_identity",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type=f"{auth_source}_identity",
            entity_id=federated_identity_id,
            details={
                "auth_source": auth_source,
                "revoked_count": revoked_count,
                "reason_sha256": reason_sha256,
            },
        )
    return revoked_count


def revoke_principal_browser_sessions(
    db: Session,
    *,
    principal_id: str,
    reason: str,
    actor: PrincipalContext,
) -> int:
    now = datetime.now(UTC)
    reason_sha256 = hash_token(reason)
    result = db.execute(
        update(ControlPlaneBrowserSession)
        .where(
            ControlPlaneBrowserSession.tenant_id == actor.tenant_id,
            ControlPlaneBrowserSession.principal_id == principal_id,
            ControlPlaneBrowserSession.revoked_at.is_(None),
        )
        .values(
            revoked_at=now,
            revoked_by=actor.subject,
            revocation_reason_sha256=reason_sha256,
        )
    )
    revoked_count = max(0, int(result.rowcount or 0))
    record_audit_event(
        db,
        event_type="auth.browser_sessions.revoked_by_principal",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="principal",
        entity_id=principal_id,
        details={
            "revoked_count": revoked_count,
            "reason_sha256": reason_sha256,
        },
    )
    db.commit()
    return revoked_count
