from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping, Protocol

from .models import CredentialProfile


@dataclass(frozen=True)
class CredentialContext:
    worker_id: str
    deployment_id: str
    adapter_type: str


class CredentialUnavailable(RuntimeError):
    pass


class CredentialBroker(Protocol):
    """Worker-side boundary for resolving secret references at execution time."""

    def resolve(
        self,
        profile: CredentialProfile,
        context: CredentialContext,
    ) -> Mapping[str, str]: ...


class DisabledCredentialBroker:
    """Fail-closed default until an external provider adapter is configured."""

    def resolve(
        self,
        profile: CredentialProfile,
        context: CredentialContext,
    ) -> Mapping[str, str]:
        raise CredentialUnavailable(
            f"Credential provider {profile.provider!r} is not configured"
        )


ENVIRONMENT_SECRET_REF = re.compile(r"^env://([A-Za-z_][A-Za-z0-9_]*)$")


def resolve_server_secret(
    profile: CredentialProfile,
    *,
    adapter_type: str,
) -> str:
    """Resolve a server-side secret without returning it through an API.

    The environment adapter is intentionally narrow. External vault/KMS
    providers will implement the same boundary later; unknown providers fail
    closed instead of interpreting their references locally.
    """

    if not profile.enabled:
        raise CredentialUnavailable("Credential profile is disabled")
    if adapter_type not in profile.allowed_adapters:
        raise CredentialUnavailable(
            f"Credential profile does not allow adapter {adapter_type!r}"
        )
    if profile.worker_selector:
        raise CredentialUnavailable(
            "Worker-scoped credential profiles cannot be used by the control plane"
        )
    if profile.provider != "environment":
        raise CredentialUnavailable(
            f"Credential provider {profile.provider!r} is not configured"
        )
    match = ENVIRONMENT_SECRET_REF.fullmatch(profile.secret_ref)
    if match is None:
        raise CredentialUnavailable(
            "Environment secret references must use env://VARIABLE_NAME"
        )
    value = os.environ.get(match.group(1))
    if not value:
        raise CredentialUnavailable("Referenced environment secret is unavailable")
    return value
