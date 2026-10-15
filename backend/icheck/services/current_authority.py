"""Transaction-bound human authority for sensitive control-plane decisions.

Authentication proves a credential once. This check reloads current authority
after waits and holds the grants it actually uses until the decision commits.
It does not renew credentials or authorize receipts for already-admitted I/O.
"""
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    ControlPlaneAccessToken, ControlPlaneBrowserSession, ControlPlaneOIDCIdentity,
    ControlPlanePrincipal, ControlPlaneRole, ControlPlaneRoleBinding,
    ControlPlaneTrustedProxyIdentity, Region, Tenant,
)
from .control_plane_auth import PrincipalContext, _as_utc, _merge_authorization_scopes


DENIED = "Current authenticated human authority is unavailable for this decision"


@dataclass(frozen=True)
class CurrentHumanAuthority:
    actor: PrincipalContext
    transaction: object
    expires_at: datetime

    def assert_live(self, db: Session) -> None:
        # Locks protect revocation, not wall-clock expiry during later waits.
        if (db.get_transaction() is not self.transaction
                or not self.transaction.is_active
                or datetime.now(UTC) >= self.expires_at):
            raise PermissionError(DENIED)


def current_human_authority(
    db: Session, actor: PrincipalContext, *, permissions: tuple[str, ...],
    tenant_id: str, region_id: str,
) -> CurrentHumanAuthority:
    if (actor.principal_type != "user" or actor.principal_id is None
            or actor.auth_method not in {"bearer", "browser_session"}
            or (actor.tenant_id, actor.region_id) != (tenant_id, region_id)):
        raise PermissionError(DENIED)
    if (db.bind.dialect.name == "postgresql"
            and db.connection().get_isolation_level() != "READ COMMITTED"):
        raise PermissionError(DENIED)

    def locked(model, *predicates):
        return db.scalar(select(model).where(*predicates).with_for_update(read=True)
                         .execution_options(populate_existing=True))

    # Parent-first, deterministic locking; refreshed rows defeat identity-map
    # and request-context staleness. No grant is inferred from platform_admin.
    tenant = locked(Tenant, Tenant.id == tenant_id)
    region = locked(Region, Region.id == region_id, Region.tenant_id == tenant_id)
    principal = locked(ControlPlanePrincipal, ControlPlanePrincipal.id == actor.principal_id)
    if (tenant is None or not tenant.enabled or region is None or not region.enabled
            or principal is None or not principal.enabled or principal.principal_type != "user"
            or principal.tenant_id != tenant_id
            or not isinstance(principal.allowed_region_ids, list)
            or (principal.allowed_region_ids and region_id not in principal.allowed_region_ids)):
        raise PermissionError(DENIED)

    if actor.auth_method == "bearer":
        credential = locked(ControlPlaneAccessToken,
                            ControlPlaneAccessToken.id == actor.access_token_id)
        if credential is None or credential.workload_identity_id is not None:
            raise PermissionError(DENIED)
    else:
        # Look up the identity before locking the session to match identity
        # disable -> session revocation ordering. Recheck the locked binding.
        preliminary = db.get(ControlPlaneBrowserSession, actor.session_id, populate_existing=True)
        if preliminary is None:
            raise PermissionError(DENIED)
        expected_source = preliminary.auth_source
        expected_identity_id = preliminary.federated_identity_id
        identity = None
        identities = {"oidc": ControlPlaneOIDCIdentity,
                      "trusted_proxy": ControlPlaneTrustedProxyIdentity}
        local_sources = {"local_token", "local_password"}
        model = identities.get(preliminary.auth_source)
        if model is not None:
            identity = locked(model, model.id == preliminary.federated_identity_id)
        credential = locked(ControlPlaneBrowserSession,
                            ControlPlaneBrowserSession.id == actor.session_id)
        if (credential is None or credential.auth_source not in {*local_sources, *identities}
                or (credential.auth_source, credential.federated_identity_id) != (expected_source, expected_identity_id)):
            raise PermissionError(DENIED)
        if credential.auth_source not in local_sources and (
                identity is None or not identity.enabled
                or identity.id != credential.federated_identity_id
                or identity.principal_id != principal.id or identity.tenant_id != tenant_id):
            raise PermissionError(DENIED)
        if credential.auth_source in local_sources and credential.federated_identity_id is not None:
            raise PermissionError(DENIED)
    # Credentials belong to a tenant; humans may select another allowed region
    # in that tenant. The selected region's grants, not the issuing region's,
    # must authorize this operation.
    if (credential.principal_id != principal.id or credential.tenant_id != tenant_id
            or credential.revoked_at is not None):
        raise PermissionError(DENIED)

    candidates = db.execute(select(ControlPlaneRoleBinding.id, ControlPlaneRoleBinding.role_id).where(
        ControlPlaneRoleBinding.principal_id == principal.id,
        ControlPlaneRoleBinding.tenant_id == tenant_id,
        ControlPlaneRoleBinding.region_id == region_id,
    )).all()
    roles = {}
    for role_id in sorted({row.role_id for row in candidates}):
        role = locked(ControlPlaneRole, ControlPlaneRole.id == role_id)
        if (role is not None and (role.system or (role.tenant_id, role.region_id) == (tenant_id, region_id))
                and isinstance(role.permissions, list)
                and all(isinstance(item, str) for item in role.permissions)):
            roles[role.id] = role
    bindings = []
    for binding_id in sorted(row.id for row in candidates):
        binding = locked(ControlPlaneRoleBinding, ControlPlaneRoleBinding.id == binding_id)
        if (binding is not None and binding.principal_id == principal.id
                and (binding.tenant_id, binding.region_id) == (tenant_id, region_id)
                and binding.role_id in roles and isinstance(binding.scope, dict)
                and all(isinstance(binding.scope.get(key, []), list) for key in ("sites", "device_ids"))):
            bindings.append(binding)
    fresh = replace(actor, subject=principal.subject, platform_admin=principal.platform_admin,
        tenant_slug=tenant.slug, region_code=region.code,
        permissions=frozenset(permission for binding in bindings for permission in roles[binding.role_id].permissions),
        role_names=tuple(sorted({roles[binding.role_id].name for binding in bindings})),
        authorization_scope=_merge_authorization_scopes(bindings))
    if not fresh.permits(*permissions) or fresh.authorization_scope.get("all") is not True:
        raise PermissionError(DENIED)
    result = CurrentHumanAuthority(fresh, db.get_transaction(), _as_utc(credential.expires_at))
    result.assert_live(db)  # AFTER every credential/role/binding lock wait.
    return result
