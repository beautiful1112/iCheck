"""Local human authentication using the existing principal and session boundary."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..database import set_session_namespace
from ..models import ControlPlaneBrowserSession, ControlPlanePrincipal
from ..passwords import hash_password, verify_password
from ..worker_auth import hash_token
from .audit import record_audit_event
from .control_plane_auth import (
    ControlPlaneAuthenticationError, ControlPlaneAuthorizationError,
    PrincipalContext, principal_context,
)
from .tenancy import resolve_tenant

DENIED = "Invalid username or password"
MAX_FAILURES = 5
LOCK_SECONDS = 300


def authenticate_password(
    db: Session, *, username: str, password: str, tenant_selector: str,
) -> tuple[ControlPlanePrincipal, PrincipalContext]:
    tenant = resolve_tenant(db, tenant_selector)
    principal = None if tenant is None else db.scalar(
        select(ControlPlanePrincipal).where(
            ControlPlanePrincipal.tenant_id == tenant.id,
            ControlPlanePrincipal.subject == username.strip(),
        ).with_for_update().execution_options(populate_existing=True)
    )
    correct = verify_password(password, principal.password_hash if principal else None)
    if principal is None or principal.principal_type != "user" or not principal.enabled:
        raise ControlPlaneAuthenticationError(DENIED)
    try:
        context = principal_context(principal, db=db, auth_method="browser_session")
    except ControlPlaneAuthorizationError as exc:
        raise ControlPlaneAuthenticationError(DENIED) from exc
    set_session_namespace(db, context.tenant_id, context.region_id)
    now = datetime.now(UTC)
    locked_until = principal.password_locked_until
    if locked_until is not None:
        locked_until = locked_until.replace(tzinfo=UTC) if locked_until.tzinfo is None else locked_until
        if locked_until > now:
            raise ControlPlaneAuthenticationError(DENIED)
        principal.password_failed_attempts = 0
        principal.password_locked_until = None
    if not correct:
        principal.password_failed_attempts += 1
        if principal.password_failed_attempts >= MAX_FAILURES:
            principal.password_locked_until = now + timedelta(seconds=LOCK_SECONDS)
        record_audit_event(
            db, event_type="auth.password_login.denied", actor_type="user",
            actor_id=principal.id, entity_type="principal", entity_id=principal.id,
            outcome="denied", details={"auth_source": "local_password"},
        )
        db.commit()
        raise ControlPlaneAuthenticationError(DENIED)
    principal.password_failed_attempts = 0
    principal.password_locked_until = None
    return principal, context


def set_principal_password(
    db: Session, *, principal_id: str, password: str,
    actor: PrincipalContext, reason: str, commit: bool = True,
) -> ControlPlanePrincipal:
    principal = db.scalar(select(ControlPlanePrincipal).where(
        ControlPlanePrincipal.id == principal_id,
        ControlPlanePrincipal.tenant_id == actor.tenant_id,
    ).with_for_update().execution_options(populate_existing=True))
    if principal is None:
        raise LookupError("Principal not found")
    if principal.principal_type != "user":
        raise ValueError("Passwords can only be assigned to human users")
    principal.password_hash = hash_password(password)
    principal.password_failed_attempts = 0
    principal.password_locked_until = None
    db.execute(update(ControlPlaneBrowserSession).where(
        ControlPlaneBrowserSession.principal_id == principal.id,
        ControlPlaneBrowserSession.tenant_id == actor.tenant_id,
        ControlPlaneBrowserSession.revoked_at.is_(None),
    ).values(
        revoked_at=datetime.now(UTC), revoked_by=actor.subject,
        revocation_reason_sha256=hash_token("password_changed"),
    ))
    record_audit_event(
        db, event_type="auth.password.changed", actor_type=actor.principal_type,
        actor_id=actor.subject, entity_type="principal", entity_id=principal.id,
        details={"reason_sha256": hash_token(reason)},
    )
    if commit:
        db.commit()
        db.refresh(principal)
    return principal
