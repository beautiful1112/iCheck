from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
import stat
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..auth_schemas import (
    TrustedProxyIdentityCreate,
    TrustedProxyIdentityUpdate,
)
from ..config import Settings, get_settings
from ..database import DEFAULT_REGION_ID, DEFAULT_TENANT_ID, set_session_namespace
from ..models import (
    ControlPlanePrincipal,
    ControlPlaneRoleBinding,
    ControlPlaneTrustedProxyIdentity,
    ControlPlaneTrustedProxyLoginAttempt,
    utcnow,
)
from .audit import record_audit_event
from .control_plane_auth import (
    ControlPlaneAuthorizationError,
    PrincipalContext,
    create_browser_session,
    principal_context,
    revoke_federated_browser_sessions,
)


class TrustedProxyFederationError(ValueError):
    def __init__(self, message: str, *, code: str = "authentication_failed"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TrustedProxyLoginResult:
    context: PrincipalContext
    session_token: str
    csrf_token: str
    return_to: str


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_return_to(value: str) -> str:
    if len(value) > 2048:
        raise TrustedProxyFederationError(
            "Trusted-proxy return path is oversized",
            code="invalid_return_path",
        )
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise TrustedProxyFederationError(
            "Trusted-proxy return path must be a local absolute path",
            code="invalid_return_path",
        )
    return value


def trusted_proxy_browser_location(
    settings: Settings,
    *,
    return_to: str | None = None,
    error_code: str | None = None,
) -> str:
    base = (settings.control_plane_trusted_proxy_success_url or "").rstrip("/")
    parsed = urlsplit(base)
    if not parsed.hostname:
        raise TrustedProxyFederationError(
            "Trusted-proxy browser success URL is unavailable",
            code="configuration_error",
        )
    if error_code:
        return base + "/login?" + urlencode({"proxy_error": error_code})
    return base + _validate_return_to(return_to or "/")


def _trusted_source(address: str | None, allowed: list[str]) -> bool:
    try:
        peer = ipaddress.ip_address(address or "")
    except ValueError:
        return False
    return any(
        peer in ipaddress.ip_network(value, strict=False)
        for value in allowed
    )


def _read_shared_secret(path: str) -> str:
    try:
        metadata = os.stat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise TrustedProxyFederationError(
                "Trusted-proxy shared-secret path must be a regular file",
                code="configuration_error",
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise TrustedProxyFederationError(
                "Trusted-proxy shared-secret file must not be accessible "
                "by group or others",
                code="configuration_error",
            )
        if metadata.st_size > 4096:
            raise TrustedProxyFederationError(
                "Trusted-proxy shared-secret file is oversized",
                code="configuration_error",
            )
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise TrustedProxyFederationError(
            "Unable to read trusted-proxy shared-secret file",
            code="configuration_error",
        ) from exc
    if len(value.encode("utf-8")) < 32:
        raise TrustedProxyFederationError(
            "Trusted-proxy shared secret must contain at least 32 bytes",
            code="configuration_error",
        )
    return value


def _valid_subject(subject: str | None) -> bool:
    return bool(
        subject
        and subject == subject.strip()
        and len(subject.encode("utf-8")) <= 1024
        and all(ord(character) >= 0x20 for character in subject)
    )


def _record_denial(
    db: Session,
    settings: Settings,
    *,
    code: str,
    subject: str | None,
    source_address: str | None,
    identity: ControlPlaneTrustedProxyIdentity | None = None,
) -> None:
    db.add(
        ControlPlaneTrustedProxyLoginAttempt(
            identity_id=identity.id if identity is not None else None,
            principal_id=identity.principal_id if identity is not None else None,
            issuer_sha256=_sha256(
                settings.control_plane_trusted_proxy_issuer or ""
            ),
            subject_sha256=(
                _sha256(subject) if _valid_subject(subject) else None
            ),
            source_address_sha256=(
                _sha256(source_address) if source_address else None
            ),
            outcome="denied",
            failure_code=code,
            tenant_id=(
                identity.tenant_id if identity is not None else DEFAULT_TENANT_ID
            ),
            region_id=(
                identity.region_id if identity is not None else DEFAULT_REGION_ID
            ),
        )
    )
    db.commit()


def _deny(
    db: Session,
    settings: Settings,
    *,
    code: str,
    message: str,
    subject: str | None,
    source_address: str | None,
    identity: ControlPlaneTrustedProxyIdentity | None = None,
) -> None:
    _record_denial(
        db,
        settings,
        code=code,
        subject=subject,
        source_address=source_address,
        identity=identity,
    )
    raise TrustedProxyFederationError(message, code=code)


def _identity_for_subject(
    db: Session,
    settings: Settings,
    subject: str,
) -> ControlPlaneTrustedProxyIdentity | None:
    issuer = settings.control_plane_trusted_proxy_issuer or ""
    return db.scalar(
        select(ControlPlaneTrustedProxyIdentity)
        .options(
            selectinload(ControlPlaneTrustedProxyIdentity.principal)
            .selectinload(ControlPlanePrincipal.role_bindings)
            .selectinload(ControlPlaneRoleBinding.role)
        )
        .where(
            ControlPlaneTrustedProxyIdentity.issuer_sha256 == _sha256(issuer),
            ControlPlaneTrustedProxyIdentity.subject_sha256 == _sha256(subject),
        )
        .with_for_update()
    )


def finish_trusted_proxy_login(
    db: Session,
    *,
    source_address: str | None,
    verified: str | None,
    subject: str | None,
    shared_secret: str | None,
    return_to: str,
    settings: Settings | None = None,
) -> TrustedProxyLoginResult:
    settings = settings or get_settings()
    if not settings.control_plane_trusted_proxy_enabled:
        raise TrustedProxyFederationError(
            "Trusted-proxy browser federation is disabled",
            code="disabled",
        )
    try:
        return_to = _validate_return_to(return_to)
    except TrustedProxyFederationError as exc:
        _deny(
            db,
            settings,
            code=exc.code,
            message=str(exc),
            subject=subject,
            source_address=source_address,
        )
    if not _trusted_source(
        source_address,
        settings.control_plane_trusted_proxy_network_list,
    ):
        _deny(
            db,
            settings,
            code="untrusted_source",
            message="Trusted identity headers came from an untrusted source",
            subject=subject,
            source_address=source_address,
        )
    if verified != "SUCCESS" or not _valid_subject(subject) or not shared_secret:
        _deny(
            db,
            settings,
            code="invalid_assertion",
            message="Trusted identity headers are incomplete or invalid",
            subject=subject,
            source_address=source_address,
        )
    assert subject is not None
    if len(shared_secret.encode("utf-8")) > 4096:
        _deny(
            db,
            settings,
            code="invalid_assertion",
            message="Trusted identity assertion is invalid",
            subject=subject,
            source_address=source_address,
        )
    try:
        expected_secrets = [
            _read_shared_secret(path)
            for path in settings.control_plane_trusted_proxy_shared_secret_file_list
        ]
    except TrustedProxyFederationError as exc:
        _deny(
            db,
            settings,
            code=exc.code,
            message=str(exc),
            subject=subject,
            source_address=source_address,
        )
    matched = False
    for expected in expected_secrets:
        matched |= secrets.compare_digest(expected, shared_secret)
    if not matched:
        _deny(
            db,
            settings,
            code="invalid_assertion",
            message="Trusted identity assertion is invalid",
            subject=subject,
            source_address=source_address,
        )

    identity = _identity_for_subject(db, settings, subject)
    issuer = settings.control_plane_trusted_proxy_issuer or ""
    if (
        identity is None
        or identity.issuer != issuer
        or not identity.enabled
        or not identity.principal.enabled
        or identity.tenant_id != identity.principal.tenant_id
        or identity.region_id != identity.principal.region_id
    ):
        _deny(
            db,
            settings,
            code="identity_not_enrolled",
            message="Trusted identity is not enrolled or enabled",
            subject=subject,
            source_address=source_address,
            identity=identity,
        )

    set_session_namespace(
        db,
        identity.principal.tenant_id,
        identity.principal.region_id,
    )
    try:
        context = principal_context(
            identity.principal,
            db=db,
            auth_method="trusted_proxy",
        )
    except ControlPlaneAuthorizationError as exc:
        _deny(
            db,
            settings,
            code="identity_not_authorized",
            message=str(exc),
            subject=subject,
            source_address=source_address,
            identity=identity,
        )
    identity.last_login_at = utcnow()
    record_audit_event(
        db,
        event_type="auth.trusted_proxy.login_succeeded",
        actor_type="user",
        actor_id=context.subject,
        entity_type="trusted_proxy_identity",
        entity_id=identity.id,
        details={
            "principal_id": identity.principal_id,
            "issuer_sha256": identity.issuer_sha256,
            "subject_sha256": identity.subject_sha256,
            "source_address_sha256": (
                _sha256(source_address) if source_address else None
            ),
        },
    )
    session, session_token, csrf_token = create_browser_session(
        db,
        identity.principal,
        ttl_hours=settings.control_plane_browser_session_ttl_hours,
        actor=context,
        commit=False,
        auth_source="trusted_proxy",
        federated_identity_id=identity.id,
    )
    db.add(
        ControlPlaneTrustedProxyLoginAttempt(
            identity_id=identity.id,
            principal_id=identity.principal_id,
            session_id=session.id,
            issuer_sha256=identity.issuer_sha256,
            subject_sha256=identity.subject_sha256,
            source_address_sha256=(
                _sha256(source_address) if source_address else None
            ),
            outcome="succeeded",
            failure_code=None,
            tenant_id=identity.tenant_id,
            region_id=identity.region_id,
        )
    )
    db.commit()
    db.refresh(session)
    return TrustedProxyLoginResult(
        context=context,
        session_token=session_token,
        csrf_token=csrf_token,
        return_to=return_to,
    )


def create_trusted_proxy_identity(
    db: Session,
    principal: ControlPlanePrincipal,
    payload: TrustedProxyIdentityCreate,
    *,
    actor: PrincipalContext,
    settings: Settings | None = None,
) -> ControlPlaneTrustedProxyIdentity:
    settings = settings or get_settings()
    if not settings.control_plane_trusted_proxy_enabled:
        raise ValueError("Trusted-proxy browser federation is disabled")
    issuer = settings.control_plane_trusted_proxy_issuer or ""
    identity = ControlPlaneTrustedProxyIdentity(
        principal=principal,
        issuer=issuer,
        issuer_sha256=_sha256(issuer),
        subject_sha256=_sha256(payload.subject),
        enabled=True,
        tenant_id=principal.tenant_id,
        region_id=principal.region_id,
        created_by=actor.subject,
    )
    db.add(identity)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="auth.trusted_proxy.identity_bound",
            actor_type=actor.principal_type,
            actor_id=actor.subject,
            entity_type="trusted_proxy_identity",
            entity_id=identity.id,
            details={
                "principal_id": principal.id,
                "issuer_sha256": identity.issuer_sha256,
                "subject_sha256": identity.subject_sha256,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Trusted-proxy identity or principal/issuer binding already exists"
        ) from exc
    db.refresh(identity)
    return identity


def update_trusted_proxy_identity(
    db: Session,
    identity: ControlPlaneTrustedProxyIdentity,
    payload: TrustedProxyIdentityUpdate,
    *,
    actor: PrincipalContext,
) -> ControlPlaneTrustedProxyIdentity:
    locked = db.scalar(
        select(ControlPlaneTrustedProxyIdentity)
        .where(
            ControlPlaneTrustedProxyIdentity.id == identity.id,
            ControlPlaneTrustedProxyIdentity.tenant_id == actor.tenant_id,
        )
        .with_for_update()
    )
    if locked is None:
        raise LookupError("Trusted-proxy identity not found")
    locked.enabled = payload.enabled
    revoked_sessions = 0
    if not payload.enabled:
        revoked_sessions = revoke_federated_browser_sessions(
            db,
            auth_source="trusted_proxy",
            federated_identity_id=locked.id,
            reason=payload.reason,
            actor=actor,
        )
    record_audit_event(
        db,
        event_type="auth.trusted_proxy.identity_updated",
        actor_type=actor.principal_type,
        actor_id=actor.subject,
        entity_type="trusted_proxy_identity",
        entity_id=locked.id,
        details={
            "principal_id": locked.principal_id,
            "enabled": locked.enabled,
            "revoked_sessions": revoked_sessions,
            "reason_sha256": _sha256(payload.reason),
        },
    )
    db.commit()
    db.refresh(locked)
    return locked
