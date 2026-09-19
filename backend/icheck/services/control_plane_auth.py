from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..auth_schemas import (
    AccessTokenCreate,
    BootstrapRequest,
    PrincipalCreate,
    RoleBindingCreate,
    RoleCreate,
)
from ..models import (
    ControlPlaneAccessToken,
    ControlPlanePrincipal,
    ControlPlaneRole,
    ControlPlaneRoleBinding,
)
from ..worker_auth import hash_token
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets


BUILTIN_ROLES: dict[str, tuple[str, list[str]]] = {
    "viewer": (
        "Read inventory, alerts, metrics, and investigations.",
        [
            "assets.read",
            "endpoints.read",
            "alerts.read",
            "metrics.read",
            "investigations.read",
        ],
    ),
    "operator": (
        "Run bounded investigations and cancel owned operations.",
        [
            "assets.read",
            "endpoints.read",
            "alerts.read",
            "metrics.read",
            "investigations.read",
            "investigations.create",
            "investigations.cancel",
        ],
    ),
    "approver": (
        "Review and approve state-changing agent proposals.",
        [
            "assets.read",
            "alerts.read",
            "investigations.read",
            "changes.approve",
        ],
    ),
    "admin": ("Full control-plane administration.", ["*"]),
}


class ControlPlaneAuthenticationError(ValueError):
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
    auth_method: str = "bearer",
) -> PrincipalContext:
    bindings = list(principal.role_bindings)
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
    )


def authenticate_access_token(
    db: Session,
    authorization: str | None,
) -> PrincipalContext:
    scheme, _, raw_token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not raw_token:
        raise ControlPlaneAuthenticationError("Control-plane bearer token is required")
    if not raw_token.startswith("icp_") or len(raw_token) < 20:
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
    if (
        token is None
        or not secrets.compare_digest(token.token_hash, hash_token(raw_token))
        or token.revoked_at is not None
        or _as_utc(token.expires_at) <= now
        or not token.principal.enabled
    ):
        raise ControlPlaneAuthenticationError("Invalid or expired control-plane token")

    token.last_used_at = now
    db.commit()
    return principal_context(token.principal)


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
        name=name,
        token_prefix=prefix,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(hours=expires_in_hours),
        created_by=actor,
    )
    db.add(token)
    return token, raw_token


def bootstrap_admin(
    db: Session,
    payload: BootstrapRequest,
    *,
    default_token_ttl_hours: int,
) -> tuple[ControlPlanePrincipal, ControlPlaneAccessToken, str]:
    if (db.scalar(select(func.count()).select_from(ControlPlanePrincipal)) or 0) > 0:
        raise ValueError("Control-plane bootstrap has already been completed")
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
        created_by="system.bootstrap",
    )
    db.add(principal)
    db.flush()
    db.add(
        ControlPlaneRoleBinding(
            principal=principal,
            role=admin_role,
            scope={"all": True},
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
        created_by=actor.subject,
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


def create_role(
    db: Session,
    payload: RoleCreate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneRole:
    role = ControlPlaneRole(
        **payload.model_dump(),
        system=False,
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
    assert_no_inline_secrets(payload.scope, "role_binding.scope")
    binding = ControlPlaneRoleBinding(
        principal=principal,
        role=role,
        scope=payload.scope,
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


def issue_access_token(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: AccessTokenCreate,
    *,
    actor: PrincipalContext,
    default_token_ttl_hours: int,
) -> tuple[ControlPlaneAccessToken, str]:
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
