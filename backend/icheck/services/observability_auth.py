from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..credentials import (
    CredentialUnavailable,
    SecretRedactor,
    resolve_server_secret,
)
from ..models import CredentialProfile


AUTH_TYPES = {"none", "bearer", "basic", "header"}
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_PROTECTED_HEADERS = {
    "accept",
    "authorization",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "expect",
    "forwarded",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}


@dataclass(frozen=True)
class ResolvedBackendAuth:
    headers: dict[str, str]
    redactor: SecretRedactor


def validate_backend_auth_contract(
    *,
    auth_type: str,
    auth_header_name: str | None,
    credential_profile_ref: str | None,
) -> str | None:
    if auth_type not in AUTH_TYPES:
        raise ValueError(f"Unsupported observability backend auth type {auth_type!r}")
    header_name = auth_header_name.strip() if auth_header_name else None
    credential_ref = (
        credential_profile_ref.strip() if credential_profile_ref else None
    )
    if auth_type == "none":
        if credential_ref:
            raise ValueError(
                "credential_profile_ref must be empty when auth_type is 'none'"
            )
        if header_name:
            raise ValueError(
                "auth_header_name must be empty when auth_type is not 'header'"
            )
        return None
    if not credential_ref:
        raise ValueError(
            "credential_profile_ref is required for authenticated backends"
        )
    if auth_type != "header":
        if header_name:
            raise ValueError(
                "auth_header_name must be empty when auth_type is not 'header'"
            )
        return None
    if not header_name:
        raise ValueError("auth_header_name is required when auth_type is 'header'")
    if _HEADER_NAME.fullmatch(header_name) is None:
        raise ValueError("auth_header_name must be a valid HTTP header name")
    if header_name.lower() in _PROTECTED_HEADERS:
        raise ValueError("auth_header_name is a protected HTTP header")
    return header_name


def credential_profile(
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


def validate_backend_credential_profile(
    db: Session,
    *,
    auth_type: str,
    auth_header_name: str | None,
    credential_profile_ref: str | None,
    adapter_type: str,
) -> None:
    validate_backend_auth_contract(
        auth_type=auth_type,
        auth_header_name=auth_header_name,
        credential_profile_ref=credential_profile_ref,
    )
    if auth_type == "none":
        return
    assert credential_profile_ref is not None
    profile = credential_profile(db, credential_profile_ref)
    if profile is None:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} does not exist"
        )
    if not profile.enabled:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} is disabled"
        )
    if adapter_type not in profile.allowed_adapters:
        raise ValueError(
            f"Credential profile {credential_profile_ref!r} does not allow "
            f"adapter {adapter_type!r}"
        )
    if profile.worker_selector:
        raise ValueError(
            "Observability backend credentials must not be scoped to workers"
        )


def resolve_backend_auth(
    db: Session,
    *,
    auth_type: str,
    auth_header_name: str | None,
    credential_profile_ref: str | None,
    adapter_type: str,
) -> ResolvedBackendAuth:
    header_name = validate_backend_auth_contract(
        auth_type=auth_type,
        auth_header_name=auth_header_name,
        credential_profile_ref=credential_profile_ref,
    )
    redactor = SecretRedactor()
    if auth_type == "none":
        return ResolvedBackendAuth(headers={}, redactor=redactor)
    assert credential_profile_ref is not None
    profile = credential_profile(db, credential_profile_ref)
    if profile is None:
        raise CredentialUnavailable("Backend credential profile is missing")
    secret = resolve_server_secret(profile, adapter_type=adapter_type)
    if "\r" in secret or "\n" in secret:
        raise CredentialUnavailable("Backend credential contains unsafe characters")
    redactor.add(secret)
    if auth_type == "bearer":
        authorization = f"Bearer {secret}"
        redactor.add(authorization)
        return ResolvedBackendAuth(
            headers={"Authorization": authorization},
            redactor=redactor,
        )
    if auth_type == "basic":
        username, separator, password = secret.partition(":")
        if not separator or not username or not password:
            raise CredentialUnavailable(
                "Basic authentication credential must use username:password"
            )
        encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        authorization = f"Basic {encoded}"
        redactor.add(encoded)
        redactor.add(authorization)
        return ResolvedBackendAuth(
            headers={"Authorization": authorization},
            redactor=redactor,
        )
    assert auth_type == "header" and header_name is not None
    return ResolvedBackendAuth(
        headers={header_name: secret},
        redactor=redactor,
    )
