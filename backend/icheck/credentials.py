from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from collections.abc import Iterator
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .models import CredentialProfile
from .oauth_observation import OAuthCredentialObservation
from .oauth_recovery import OAuthRecoveryTarget
from .oauth_consent import OAuthConsentTarget


LOGGER = logging.getLogger("icheck.credentials")


@dataclass(frozen=True)
class CredentialContext:
    worker_id: str
    deployment_id: str
    adapter_type: str


@dataclass(frozen=True)
class CredentialGrant:
    profile_id: str
    profile_name: str
    provider: str
    secret_ref: str
    adapter_type: str
    deployment_id: str
    expires_at: datetime
    profile_revision: int = 0
    oauth_generation: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CredentialGrant:
        expires_at = value.get("expires_at")
        if not isinstance(expires_at, str):
            raise CredentialUnavailable("Credential grant expiry is missing")
        try:
            parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CredentialUnavailable("Credential grant expiry is invalid") from exc
        if parsed_expiry.tzinfo is None:
            parsed_expiry = parsed_expiry.replace(tzinfo=UTC)
        fields = {
            key: value.get(key)
            for key in (
                "profile_id",
                "profile_name",
                "provider",
                "secret_ref",
                "adapter_type",
                "deployment_id",
            )
        }
        if any(not isinstance(item, str) or not item for item in fields.values()):
            raise CredentialUnavailable("Credential grant is incomplete")
        profile_revision = value.get("profile_revision", 0)
        if (
            isinstance(profile_revision, bool)
            or not isinstance(profile_revision, int)
            or profile_revision < 0
        ):
            raise CredentialUnavailable(
                "Credential grant profile revision is invalid"
            )
        generation = value.get("oauth_generation")
        if generation is not None and (
            not isinstance(generation, str)
            or re.fullmatch(r"[0-9a-f]{32}", generation) is None
            or fields["provider"] != "mcp_oauth_vault"
        ):
            raise CredentialUnavailable("Credential grant OAuth generation is invalid")
        return cls(
            **fields,
            expires_at=parsed_expiry.astimezone(UTC),
            profile_revision=profile_revision,
            oauth_generation=generation,
        )


@dataclass
class ProviderCredentialLease:
    values: Mapping[str, str]
    expires_at: datetime
    renewable: bool = False
    oauth_observation: OAuthCredentialObservation | None = None
    renew_callback: Callable[[int], datetime] | None = field(
        default=None,
        repr=False,
    )
    revoke_callback: Callable[[], None] | None = field(
        default=None,
        repr=False,
    )


@dataclass
class ResolvedCredential:
    values: dict[str, str]
    expires_at: datetime
    grant_expires_at: datetime | None = None
    oauth_observation: OAuthCredentialObservation | None = None
    _provider_lease: ProviderCredentialLease | None = field(
        default=None,
        repr=False,
    )
    _closed: bool = field(default=False, init=False, repr=False)

    def __enter__(self) -> ResolvedCredential:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @property
    def renewable(self) -> bool:
        return bool(
            not self._closed
            and self._provider_lease is not None
            and self._provider_lease.renewable
            and self._provider_lease.renew_callback is not None
        )

    def renew(self, increment_seconds: int = 300) -> datetime:
        if self._closed:
            raise CredentialUnavailable("Credential lease is closed")
        if not 15 <= increment_seconds <= 3600:
            raise CredentialUnavailable(
                "Credential renewal increment must be between 15 and 3600 seconds"
            )
        if not self.renewable or self._provider_lease is None:
            raise CredentialUnavailable("Credential lease is not renewable")
        grant_expires_at = self.grant_expires_at or self.expires_at
        remaining = int((grant_expires_at - datetime.now(UTC)).total_seconds())
        if remaining < 1:
            raise CredentialUnavailable("Credential grant has expired")
        provider_expiry = self._provider_lease.renew_callback(
            min(increment_seconds, remaining)
        )
        self._provider_lease.expires_at = provider_expiry
        self.expires_at = min(provider_expiry, grant_expires_at)
        if self.expires_at <= datetime.now(UTC):
            raise CredentialUnavailable("Renewed credential lease is expired")
        return self.expires_at

    def close(self) -> None:
        if self._closed:
            return
        if (
            self._provider_lease is not None
            and self._provider_lease.revoke_callback is not None
        ):
            try:
                self._provider_lease.revoke_callback()
            except Exception:
                LOGGER.warning(
                    "Unable to revoke provider credential lease",
                    exc_info=True,
                )
        for key in list(self.values):
            self.values[key] = ""
        self.values.clear()
        self._closed = True


class CredentialUnavailable(RuntimeError):
    pass


class OAuthCredentialUnavailable(CredentialUnavailable):
    def __init__(self, message: str, observation: OAuthCredentialObservation):
        super().__init__(message)
        self.oauth_observation = observation


class VaultRequestError(CredentialUnavailable):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class _NoVaultRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for Vault",
            headers,
            fp,
        )


class _NoOAuthRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(
            newurl,
            code,
            "HTTP redirects are disabled for OAuth token endpoints",
            headers,
            fp,
        )


class CredentialProvider(Protocol):
    def resolve(
        self,
        secret_ref: str,
    ) -> Mapping[str, str] | ProviderCredentialLease: ...


class CredentialBroker(Protocol):
    """Worker-side boundary for resolving a lease-bounded grant."""

    def resolve(
        self,
        grant: CredentialGrant,
        context: CredentialContext,
    ) -> ResolvedCredential: ...


class DisabledCredentialBroker:
    """Fail-closed default until a worker provider adapter is configured."""

    def resolve(
        self,
        grant: CredentialGrant,
        context: CredentialContext,
    ) -> ResolvedCredential:
        raise CredentialUnavailable(
            f"Credential provider {grant.provider!r} is not configured"
        )


class WorkerCredentialBroker:
    def __init__(self, providers: Mapping[str, CredentialProvider]):
        self.providers = dict(providers)

    def resolve(
        self,
        grant: CredentialGrant,
        context: CredentialContext,
    ) -> ResolvedCredential:
        if grant.expires_at <= datetime.now(UTC):
            raise CredentialUnavailable("Credential grant has expired")
        if grant.adapter_type != context.adapter_type:
            raise CredentialUnavailable("Credential grant adapter mismatch")
        if grant.deployment_id != context.deployment_id:
            raise CredentialUnavailable("Credential grant deployment mismatch")
        provider = self.providers.get(grant.provider)
        if provider is None:
            raise CredentialUnavailable(
                f"Credential provider {grant.provider!r} is not configured"
            )
        if grant.oauth_generation is not None:
            if not isinstance(provider, MCPOAuthVaultCredentialProvider):
                raise CredentialUnavailable("OAuth grant requires a generation-aware provider")
            result = provider.resolve(
                grant.secret_ref, expected_generation=grant.oauth_generation,
            )
        else:
            result = provider.resolve(grant.secret_ref)
        provider_lease = (
            result if isinstance(result, ProviderCredentialLease) else None
        )
        values = provider_lease.values if provider_lease is not None else result
        normalized = _normalize_credential_values(values)
        expires_at = (
            min(provider_lease.expires_at, grant.expires_at)
            if provider_lease is not None
            else grant.expires_at
        )
        if expires_at <= datetime.now(UTC):
            if provider_lease and provider_lease.revoke_callback:
                provider_lease.revoke_callback()
            raise CredentialUnavailable("Resolved credential lease has expired")
        return ResolvedCredential(
            values=normalized,
            expires_at=expires_at,
            grant_expires_at=grant.expires_at,
            oauth_observation=provider_lease.oauth_observation if provider_lease else None,
            _provider_lease=provider_lease,
        )


class SecretRedactor:
    """Redact resolved values before logs, control-plane errors, or envelopes."""

    replacement = "[REDACTED]"

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str) -> None:
        if value:
            self._values.add(value)

    def add_mapping(self, values: Mapping[str, str]) -> None:
        for value in values.values():
            self.add(value)
        token = values.get("bearer_token") or values.get("token")
        if token:
            self.add(f"Bearer {token}")
        authorization = values.get("authorization")
        if authorization:
            self.add(authorization)
        username = values.get("username")
        password = values.get("password")
        if username and password:
            encoded = base64.b64encode(
                f"{username}:{password}".encode("utf-8")
            ).decode("ascii")
            self.add(encoded)
            self.add(f"Basic {encoded}")

    def redact_text(self, value: str) -> str:
        result = value
        for secret in sorted(self._values, key=len, reverse=True):
            result = result.replace(secret, self.replacement)
        return result

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {
                key: self.redact_value(child)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [self.redact_value(child) for child in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(child) for child in value)
        return value


ENVIRONMENT_SECRET_REF = re.compile(r"^env://([A-Za-z_][A-Za-z0-9_]*)$")
VAULT_SECRET_REF = re.compile(
    r"^(?:(?:vault|vault-kv2)://)?"
    r"(?P<mount>[A-Za-z0-9_.-]+)/(?P<path>[^#]+?)"
    r"(?:#(?P<field>[A-Za-z0-9_.-]+))?$"
)
VAULT_DYNAMIC_SECRET_REF = re.compile(
    r"^vault-dynamic://(?P<mount>[A-Za-z0-9_.-]+)/(?P<path>[^#]+)$"
)
MCP_OAUTH_VAULT_SECRET_REF = re.compile(
    r"^mcp-oauth-vault://(?P<mount>[A-Za-z0-9_.-]+)/(?P<path>[^#]+)$"
)
SAFE_CREDENTIAL_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
GENERIC_SECRET_REF = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s]+$")


def validate_secret_reference(provider: str, secret_ref: str) -> str:
    provider = provider.strip().lower()
    secret_ref = secret_ref.strip()
    if not provider or not secret_ref:
        raise ValueError("Credential provider and secret reference are required")
    if provider == "environment":
        valid = ENVIRONMENT_SECRET_REF.fullmatch(secret_ref) is not None
    elif provider in {"vault", "vault_kv2"}:
        match = VAULT_SECRET_REF.fullmatch(secret_ref)
        valid = match is not None and ".." not in match.group("path").split("/")
    elif provider == "vault_dynamic":
        match = VAULT_DYNAMIC_SECRET_REF.fullmatch(secret_ref)
        valid = match is not None and ".." not in match.group("path").split("/")
    elif provider == "mcp_oauth_vault":
        match = MCP_OAUTH_VAULT_SECRET_REF.fullmatch(secret_ref)
        valid = match is not None and ".." not in match.group("path").split("/")
    else:
        valid = GENERIC_SECRET_REF.fullmatch(secret_ref) is not None
    if not valid:
        raise ValueError(
            f"Credential secret reference is invalid for provider {provider!r}"
        )
    return secret_ref


def _normalize_credential_values(values: Mapping[str, Any]) -> dict[str, str]:
    if not values or len(values) > 32:
        raise CredentialUnavailable(
            "Credential provider must return between 1 and 32 values"
        )
    normalized: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or SAFE_CREDENTIAL_KEY.fullmatch(key) is None:
            raise CredentialUnavailable("Credential provider returned an invalid key")
        if not isinstance(value, str) or not value:
            raise CredentialUnavailable(
                f"Credential value {key!r} must be a non-empty string"
            )
        if len(value.encode("utf-8")) > 65_536:
            raise CredentialUnavailable(f"Credential value {key!r} is too large")
        normalized[key] = value
    return normalized


def _secret_document(value: str) -> Mapping[str, str]:
    if value.lstrip().startswith("{"):
        try:
            document = json.loads(value)
        except json.JSONDecodeError as exc:
            raise CredentialUnavailable(
                "Environment credential JSON is invalid"
            ) from exc
        if not isinstance(document, dict):
            raise CredentialUnavailable(
                "Environment credential JSON must be an object"
            )
        return _normalize_credential_values(document)
    return {"token": value}


class EnvironmentCredentialProvider:
    """Explicitly opt-in development adapter; disabled by worker default."""

    def resolve(self, secret_ref: str) -> Mapping[str, str]:
        match = ENVIRONMENT_SECRET_REF.fullmatch(secret_ref)
        if match is None:
            raise CredentialUnavailable(
                "Environment secret references must use env://VARIABLE_NAME"
            )
        value = os.environ.get(match.group(1))
        if not value:
            raise CredentialUnavailable("Referenced environment secret is unavailable")
        return _secret_document(value)


class VaultKV2CredentialProvider:
    """Resolve a Vault KV v2 reference using a worker-local token file."""

    def __init__(
        self,
        *,
        address: str,
        token_file: str,
        namespace: str | None = None,
        timeout_seconds: int = 5,
        opener: Any | None = None,
    ) -> None:
        parsed = urlsplit(address)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and loopback
        ):
            raise ValueError("Vault address must use HTTPS (HTTP is loopback-only)")
        if parsed.username or parsed.password or not parsed.hostname:
            raise ValueError("Vault address must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Vault address must not contain a query or fragment")
        if not os.path.isabs(token_file):
            raise ValueError("Vault token file path must be absolute")
        if timeout_seconds < 1 or timeout_seconds > 30:
            raise ValueError("Vault timeout must be between 1 and 30 seconds")
        self.address = address.rstrip("/")
        self.token_file = token_file
        self.namespace = namespace
        self.timeout_seconds = timeout_seconds
        self.opener = opener or build_opener(_NoVaultRedirect())

    def _token(self) -> str:
        try:
            with open(self.token_file, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise CredentialUnavailable("Vault token file is unavailable") from exc
        if not token:
            raise CredentialUnavailable("Vault token file is empty")
        return token

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        allow_empty: bool = False,
    ) -> dict[str, Any]:
        request = Request(
            f"{self.address}/v1/{path.lstrip('/')}",
            data=(
                json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if payload is not None
                else None
            ),
            headers={
                "Accept": "application/json",
                **(
                    {"Content-Type": "application/json"}
                    if payload is not None
                    else {}
                ),
                "X-Vault-Token": self._token(),
                **(
                    {"X-Vault-Namespace": self.namespace}
                    if self.namespace
                    else {}
                ),
            },
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read(1_048_577)
        except HTTPError as exc:
            raise VaultRequestError(
                f"Vault returned HTTP {exc.code} while resolving the reference",
                status_code=exc.code,
            ) from exc
        except (OSError, URLError) as exc:
            raise CredentialUnavailable("Vault is unavailable") from exc
        if len(body) > 1_048_576:
            raise CredentialUnavailable("Vault response exceeded 1 MiB")
        if not body and allow_empty:
            return {}
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialUnavailable("Vault returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise CredentialUnavailable("Vault response must be an object")
        return document

    @staticmethod
    def _kv2_location(
        secret_ref: str,
        *,
        pattern: re.Pattern[str] = VAULT_SECRET_REF,
    ) -> tuple[str, str, str | None]:
        match = pattern.fullmatch(secret_ref)
        if match is None or ".." in match.group("path").split("/"):
            raise CredentialUnavailable("Vault KV v2 secret reference is invalid")
        return (
            quote(match.group("mount"), safe=""),
            quote(match.group("path").strip("/"), safe="/"),
            match.groupdict().get("field"),
        )

    def read_kv2_document(
        self,
        secret_ref: str,
        *,
        pattern: re.Pattern[str] = VAULT_SECRET_REF,
        version: int | None = None,
        require_version: bool = True,
    ) -> tuple[dict[str, Any], int]:
        mount, path, _field = self._kv2_location(secret_ref, pattern=pattern)
        if version is not None and (type(version) is not int or not 1 <= version <= 2_147_483_647):
            raise CredentialUnavailable("Vault secret version is invalid")
        suffix = f"?version={version}" if version is not None else ""
        document = self._request_json("GET", f"{mount}/data/{path}{suffix}")
        try:
            values = document["data"]["data"]
        except (KeyError, TypeError) as exc:
            raise CredentialUnavailable(
                "Vault returned an invalid KV v2 response"
            ) from exc
        metadata = document.get("data", {}).get("metadata", {})
        returned_version = metadata.get("version", 0) if isinstance(metadata, dict) else 0
        if not isinstance(values, dict) or (
            require_version
            and (
                isinstance(returned_version, bool)
                or not isinstance(returned_version, int)
                or returned_version < 1
            )
        ):
            raise CredentialUnavailable("Vault returned an invalid KV v2 response")
        if version is not None and (type(returned_version) is not int or returned_version != version):
            raise CredentialUnavailable("Vault returned a different secret version")
        return dict(values), returned_version

    def write_kv2_document(
        self,
        secret_ref: str,
        values: Mapping[str, Any],
        *,
        cas: int,
        pattern: re.Pattern[str] = VAULT_SECRET_REF,
    ) -> int:
        mount, path, field = self._kv2_location(secret_ref, pattern=pattern)
        if field is not None:
            raise CredentialUnavailable("Vault writes cannot target one field")
        document = self._request_json(
            "POST",
            f"{mount}/data/{path}",
            {"data": dict(values), "options": {"cas": cas}},
        )
        try:
            version = document["data"]["version"]
        except (KeyError, TypeError) as exc:
            raise CredentialUnavailable(
                "Vault returned an invalid KV v2 write response"
            ) from exc
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise CredentialUnavailable("Vault returned an invalid KV v2 write response")
        return version

    def delete_kv2_document(
        self,
        secret_ref: str,
        *,
        pattern: re.Pattern[str] = VAULT_SECRET_REF,
    ) -> None:
        mount, path, field = self._kv2_location(secret_ref, pattern=pattern)
        if field is not None:
            raise CredentialUnavailable("Vault deletes cannot target one field")
        self._request_json(
            "DELETE",
            f"{mount}/data/{path}",
            allow_empty=True,
        )

    def delete_kv2_version(
        self,
        secret_ref: str,
        version: int,
        *,
        pattern: re.Pattern[str] = VAULT_SECRET_REF,
    ) -> None:
        """Soft-delete one observed version, never a concurrently newer secret."""
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise CredentialUnavailable("Vault deletion version is invalid")
        mount, path, field = self._kv2_location(secret_ref, pattern=pattern)
        if field is not None:
            raise CredentialUnavailable("Vault deletes cannot target one field")
        self._request_json(
            "POST", f"{mount}/delete/{path}", {"versions": [version]}, allow_empty=True,
        )

    def resolve(self, secret_ref: str) -> Mapping[str, str]:
        values, _version = self.read_kv2_document(
            secret_ref,
            require_version=False,
        )
        _mount, _path, field_name = self._kv2_location(secret_ref)
        if field_name:
            if field_name not in values:
                raise CredentialUnavailable("Requested Vault credential field was not found")
            return {field_name: values[field_name]}
        return _normalize_credential_values(values)


class OAuthConsentStoreRejected(CredentialUnavailable):
    """Eligibility failed before any publication request; new tokens are unstored."""


class MCPOAuthVaultCredentialProvider(VaultKV2CredentialProvider):
    """Reserve the exact KV key before redeeming a rotating OAuth grant.

    A reservation that outlives its owner is uncertain, not available for
    takeover. Preserve it until verified recovery; fresh consent cannot erase
    an expired reservation's unknown issuer-family outcome.
    Legacy Workers that ignore this metadata must be drained before rollout.
    """

    GENERATION_KEY = "icheck_oauth_generation"
    COORDINATION_KEY = "icheck_oauth_coordination"
    _IDENTITY_KEYS = (
        "issuer", "resource", "client_id", "token_endpoint", "revocation_endpoint",
        "client_secret", "metadata_sha256",
    )

    def __init__(
        self,
        *,
        oauth_allowed_hosts: list[str],
        oauth_opener: Any | None = None,
        refresh_skew_seconds: int = 60,
        refresh_wait_seconds: int = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not 5 <= refresh_skew_seconds <= 300:
            raise ValueError("OAuth refresh skew must be between 5 and 300 seconds")
        if (isinstance(refresh_wait_seconds, bool)
                or not isinstance(refresh_wait_seconds, int)
                or not 1 <= refresh_wait_seconds <= 30):
            raise ValueError("OAuth refresh wait must be between 1 and 30 seconds")
        self.oauth_allowed_hosts = [
            value.rstrip(".").lower() for value in oauth_allowed_hosts if value
        ]
        if oauth_opener is None:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            oauth_opener = build_opener(
                _NoOAuthRedirect(),
                HTTPSHandler(context=context),
            )
        self.oauth_opener = oauth_opener
        self.refresh_skew_seconds = refresh_skew_seconds
        self.refresh_wait_seconds = refresh_wait_seconds

    def _oauth_url(self, value: Any) -> str:
        if not isinstance(value, str) or len(value) > 4096:
            raise CredentialUnavailable("OAuth token endpoint is invalid")
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        loopback = host in {"127.0.0.1", "::1", "localhost"}
        allowed = any(
            host == pattern
            or (
                pattern.startswith("*.")
                and host.endswith(pattern[1:])
                and host != pattern[2:]
            )
            for pattern in self.oauth_allowed_hosts
        )
        if (
            not host
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not (parsed.scheme == "https" or (parsed.scheme == "http" and loopback))
            or not allowed
        ):
            raise CredentialUnavailable("OAuth token endpoint is not allowlisted")
        return value

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if not isinstance(value, str):
            raise CredentialUnavailable("OAuth token expiry is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, OverflowError) as exc:
            raise CredentialUnavailable("OAuth token expiry is invalid") from exc
        if parsed.tzinfo is None:
            raise CredentialUnavailable("OAuth token expiry must include a timezone")
        try:
            return parsed.astimezone(UTC)
        except (ValueError, OverflowError) as exc:
            raise CredentialUnavailable("OAuth token expiry is invalid") from exc

    @staticmethod
    def _bounded_string(
        document: Mapping[str, Any],
        key: str,
        *,
        maximum: int = 65_536,
    ) -> str:
        value = document.get(key)
        if not isinstance(value, str) or not 1 <= len(value) <= maximum:
            raise CredentialUnavailable(f"OAuth token bundle {key!r} is invalid")
        return value

    def _validate_bundle(self, document: Mapping[str, Any]) -> dict[str, Any]:
        bundle = dict(document)
        if "icheck_oauth_family_reservation" in bundle:
            raise CredentialUnavailable("OAuth credentials are reserved for independent family recovery")
        if "icheck_oauth_family_restoration" in bundle:
            from .oauth_family_local import FamilyRestoreWitness
            try:
                FamilyRestoreWitness.model_validate(bundle["icheck_oauth_family_restoration"])
            except ValueError as exc:
                raise CredentialUnavailable("OAuth family restoration witness is invalid") from exc
        if self._bounded_string(bundle, "token_type", maximum=32).lower() != "bearer":
            raise CredentialUnavailable("MCP OAuth requires Bearer access tokens")
        self._bounded_string(bundle, "access_token")
        self._bounded_string(bundle, "client_id", maximum=2048)
        self._bounded_string(bundle, "issuer", maximum=2048)
        self._bounded_string(bundle, "resource", maximum=2048)
        self._oauth_url(self._bounded_string(bundle, "token_endpoint", maximum=4096))
        self._timestamp(bundle.get("expires_at"))
        scope = bundle.get("scope", "")
        if not isinstance(scope, str) or len(scope) > 8192:
            raise CredentialUnavailable("OAuth token scope is invalid")
        refresh_token = bundle.get("refresh_token")
        if refresh_token is not None and (
            not isinstance(refresh_token, str) or not 1 <= len(refresh_token) <= 65_536
        ):
            raise CredentialUnavailable("OAuth refresh token is invalid")
        client_secret = bundle.get("client_secret")
        if client_secret is not None and (
            not isinstance(client_secret, str) or not 1 <= len(client_secret) <= 65_536
        ):
            raise CredentialUnavailable("OAuth client secret is invalid")
        revocation_endpoint = bundle.get("revocation_endpoint")
        if revocation_endpoint is not None:
            self._oauth_url(revocation_endpoint)
        if "icheck_oauth_authorization_locator" in bundle:
            from .oauth_consent import OAuthAuthorizationLocator
            try:
                OAuthAuthorizationLocator.model_validate(bundle["icheck_oauth_authorization_locator"])
            except ValueError as exc:
                raise CredentialUnavailable("OAuth authorization locator is invalid") from exc
        self._coordination(bundle)
        return bundle

    def _coordination(
        self, bundle: Mapping[str, Any], version: int | None = None,
    ) -> dict[str, Any] | None:
        generation = bundle.get(self.GENERATION_KEY)
        if self.GENERATION_KEY in bundle and (
            not isinstance(generation, str)
            or re.fullmatch(r"[0-9a-f]{32}", generation) is None
        ):
            raise CredentialUnavailable("OAuth credential generation is invalid")
        if self.COORDINATION_KEY not in bundle:
            return None
        state = bundle[self.COORDINATION_KEY]
        if (not isinstance(state, dict)
                or set(state) != {"format_version", "status", "owner", "generation",
                                  "base_version", "deadline"}
                or type(state.get("format_version")) is not int
                or state["format_version"] != 1
                or not isinstance(state.get("status"), str)
                or state["status"] not in {"refreshing", "ready", "revoking"}
                or not isinstance(state.get("owner"), str)
                or re.fullmatch(r"[0-9a-f]{32}", state["owner"]) is None
                or generation is None or state.get("generation") != generation
                or type(state.get("base_version")) is not int
                or state["base_version"] < 1
                or not isinstance(state.get("deadline"), str)
                or len(state["deadline"]) > 64):
            raise CredentialUnavailable("OAuth coordination metadata is invalid")
        self._timestamp(state["deadline"])
        if version is not None:
            offset = 2 if state["status"] == "ready" else 1
            if version != state["base_version"] + offset:
                raise CredentialUnavailable("OAuth coordination version is invalid")
        return dict(state)

    def inspect_recovery_target(
        self, secret_ref: str, *, expected_generation: str | None,
    ) -> OAuthRecoveryTarget:
        """Observe a target only. Never redeem, revoke, or release a reservation."""
        raw, version = self.read_kv2_document(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        bundle = self._validate_bundle(raw)
        state = self._coordination(bundle, version)
        if bundle.get(self.GENERATION_KEY) != expected_generation:
            raise CredentialUnavailable("OAuth recovery generation differs from the original consent")
        if (state and state["status"] == "refreshing"
                and self._timestamp(state["deadline"]) > datetime.now(UTC)):
            raise CredentialUnavailable("OAuth refresh still has a live owner; recovery cannot take over")
        return OAuthRecoveryTarget(
            generation=expected_generation, vault_version=version,
            issuer=bundle["issuer"], client_id=bundle["client_id"], resource=bundle["resource"],
            coordination_owner=state["owner"] if state else None,
        )

    def cleanup_contained_recovery(
        self, secret_ref: str, target: OAuthRecoveryTarget, *, recovery_id: str,
        fence_verified: bool, retain_fence: Callable[[int], None],
        authorize_mutation: Callable[[str], None],
    ) -> int:
        """After independently verified containment, CAS-fence and delete ONE version.

        The caller durably retains the expected fence before calling this. A
        timed-out CAS/delete is read back, not interpreted as success. No issuer
        request occurs here: known old tokens cannot prove an unknown family
        was contained. A newer generation or KV head is never deleted.
        """
        if not isinstance(recovery_id, str) or re.fullmatch(r"[0-9a-f]{32}", recovery_id) is None:
            raise CredentialUnavailable("OAuth recovery identity is invalid")
        if type(fence_verified) is not bool:
            raise CredentialUnavailable("OAuth recovery fence proof is invalid")
        fenced_version = target.vault_version + 1
        fenced_generation = target.generation or recovery_id

        def read():
            try:
                raw, version = self.read_kv2_document(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
            except VaultRequestError as exc:
                if (exc.status_code == 404 and fence_verified
                        and self._missing_bundle_version(secret_ref) == fenced_version):
                    return None, fenced_version
                raise
            bundle = self._validate_bundle(raw)
            state = self._coordination(bundle, version)
            same_identity = all(bundle[key] == getattr(target, key)
                                for key in ("issuer", "client_id", "resource"))
            own_fence = (
                same_identity and version == fenced_version and state is not None
                and state["status"] == "revoking" and state["owner"] == recovery_id
                and state["base_version"] == target.vault_version
                and bundle.get(self.GENERATION_KEY) == fenced_generation
            )
            original = (
                not fence_verified and same_identity and version == target.vault_version
                and bundle.get(self.GENERATION_KEY) == target.generation
                and (state["owner"] if state else None) == target.coordination_owner
            )
            if not (original or own_fence):
                raise CredentialUnavailable("OAuth recovery target was superseded; no version was deleted")
            return bundle, version

        bundle, version = read()
        if bundle is None:
            return fenced_version
        if version == target.vault_version:
            state = {
                "format_version": 1, "status": "revoking", "owner": recovery_id,
                "generation": fenced_generation, "base_version": target.vault_version,
                "deadline": (datetime.now(UTC) + timedelta(seconds=max(30, self.timeout_seconds * 4))).isoformat(),
            }
            authorize_mutation("fence")
            try:
                written = self.write_kv2_document(secret_ref, {
                    **bundle, self.GENERATION_KEY: fenced_generation, self.COORDINATION_KEY: state,
                }, cas=version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
                if written != fenced_version:
                    raise CredentialUnavailable("OAuth recovery fence version is invalid")
            except CredentialUnavailable:
                # Ambiguous persistence is recoverable only from this exact
                # deterministic owner and expected version. Never issue again.
                recovered, recovered_version = read()
                if recovered is None:
                    return fenced_version
                if recovered_version != fenced_version:
                    raise
        bundle, version = read()
        if bundle is None:
            return fenced_version
        if version != fenced_version:
            raise CredentialUnavailable("OAuth recovery fence was not retained")
        if not fence_verified:
            # Persist exact owner verification before deletion. A mere expected
            # version cannot distinguish our fence from a late Worker's commit.
            retain_fence(fenced_version)
            fence_verified = True
        # Even a retry with a retained fence needs a new current admission.
        # An authorization failure is not a Vault error or deletion receipt.
        authorize_mutation("delete")
        try:
            self.delete_kv2_version(secret_ref, fenced_version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        except CredentialUnavailable:
            # A lost delete response is not proof. The read below must establish
            # absence at precisely the fenced metadata head.
            absent, _version = read()
            if absent is not None:
                raise
        absent, _version = read()
        if absent is not None:
            raise CredentialUnavailable("OAuth recovery deletion is not verified")
        return fenced_version

    def _claim(
        self, secret_ref: str, bundle: dict[str, Any], version: int, *, status: str,
    ) -> tuple[dict[str, Any], int]:
        generation = bundle.get(self.GENERATION_KEY) or secrets.token_hex(16)
        state = {
            "format_version": 1, "status": status, "owner": secrets.token_hex(16),
            "generation": generation, "base_version": version,
            "deadline": (datetime.now(UTC) + timedelta(
                seconds=max(30, self.timeout_seconds * 4),
            )).isoformat(),
        }
        claimed = {**bundle, self.GENERATION_KEY: generation, self.COORDINATION_KEY: state}
        claimed_version = self.write_kv2_document(
            secret_ref, claimed, cas=version, pattern=MCP_OAUTH_VAULT_SECRET_REF,
        )
        if claimed_version != version + 1:
            raise CredentialUnavailable("Vault returned an invalid reservation version")
        return claimed, claimed_version

    def _wait_for_refresh(
        self, secret_ref: str, baseline: dict[str, Any], version: int,
    ) -> tuple[dict[str, Any], int]:
        initial_state = self._coordination(baseline, version)
        base_version = (initial_state["base_version"]
                        if initial_state and initial_state["status"] == "refreshing"
                        else version)
        owner = (initial_state["owner"]
                 if initial_state and initial_state["status"] == "refreshing" else None)
        generation = baseline.get(self.GENERATION_KEY)
        deadline = time.monotonic() + self.refresh_wait_seconds
        # Both elapsed time and request count are bounded. A final Vault request
        # may take up to its configured HTTP timeout; never retry redemption.
        for _ in range(64):
            current, current_version = self.read_kv2_document(
                secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF,
            )
            current = self._validate_bundle(current)
            state = self._coordination(current, current_version)
            if (any(current.get(key) != baseline.get(key) for key in self._IDENTITY_KEYS)
                    or not set(current.get("scope", "").split()).issubset(
                        set(baseline.get("scope", "").split()))
                    or (generation is not None
                        and current.get(self.GENERATION_KEY) != generation)
                    or not state or state["base_version"] != base_version
                    or (owner is not None and state["owner"] != owner)):
                raise CredentialUnavailable("OAuth credential changed during refresh")
            if state["status"] == "ready":
                if self._timestamp(current["expires_at"]) <= datetime.now(UTC):
                    raise CredentialUnavailable("Concurrent OAuth refresh result has expired")
                return current, current_version
            if state["status"] != "refreshing":
                raise CredentialUnavailable("OAuth credential revocation is pending")
            if self._timestamp(state["deadline"]) <= datetime.now(UTC):
                raise CredentialUnavailable("OAuth refresh outcome is uncertain; verified recovery is required before fresh consent")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.25, remaining))
        raise CredentialUnavailable("OAuth refresh is still pending")

    def _missing_bundle_version(self, secret_ref: str) -> int:
        # KV v2 soft deletion hides data, not its version. Reconnect must use
        # the exact key's metadata rather than treating every data 404 as new.
        mount, path, field = self._kv2_location(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        if field is not None:
            raise CredentialUnavailable("OAuth bundle metadata cannot target one field")
        try:
            document = self._request_json("GET", f"{mount}/metadata/{path}")
        except VaultRequestError as exc:
            if exc.status_code != 404:
                raise
            return 0
        try:
            version = document["data"]["current_version"]
            oldest_version = document["data"].get("oldest_version")
        except (KeyError, TypeError) as exc:
            raise CredentialUnavailable("Vault returned invalid OAuth bundle metadata") from exc
        if (type(version) is not int or version < 0
                or (version == 0 and (type(oldest_version) is not int or oldest_version != 0
                                     or document["data"].get("versions") != {}))):
            raise CredentialUnavailable("Vault returned invalid OAuth bundle metadata")
        return version

    def inspect_consent_target(self, secret_ref: str, *, expected_generation: str | None,
                               require_present: bool = False) -> OAuthConsentTarget:
        """Read-only exact target admission, before authorization-code redemption."""
        try:
            document, version = self.read_kv2_document(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        except VaultRequestError as exc:
            if exc.status_code != 404:
                raise
            if require_present:
                raise CredentialUnavailable("Existing consent credentials are missing; verified recovery is required") from exc
            return OAuthConsentTarget(present=False, vault_version=self._missing_bundle_version(secret_ref))
        bundle = self._validate_bundle(document)
        state = self._coordination(bundle, version)
        if (bundle.get(self.GENERATION_KEY) != expected_generation
                or (state is not None and state["status"] != "ready")):
            raise CredentialUnavailable("Consent target is superseded or uncertain; no code may be redeemed")
        return OAuthConsentTarget(present=True, vault_version=version, generation=bundle.get(self.GENERATION_KEY),
            issuer=bundle["issuer"], client_id=bundle["client_id"], resource=bundle["resource"],
            coordination_owner=state["owner"] if state else None)

    def store_consent_bundle(self, secret_ref: str, bundle: Mapping[str, Any], *,
                             generation: str, target: OAuthConsentTarget) -> int:
        """Publish only against the pre-redemption target; never reread and rebase."""
        if not isinstance(generation, str) or re.fullmatch(r"[0-9a-f]{32}", generation) is None:
            raise CredentialUnavailable("Consent generation is invalid")
        if self.GENERATION_KEY in bundle or self.COORDINATION_KEY in bundle:
            raise CredentialUnavailable("Consent cannot supply coordination metadata")
        validated = self._validate_bundle(bundle)
        try:
            observed = self.inspect_consent_target(secret_ref, expected_generation=target.generation,
                require_present=target.present)
        except CredentialUnavailable as exc:
            raise OAuthConsentStoreRejected("Consent eligibility failed before any publication request") from exc
        if observed != target:
            raise OAuthConsentStoreRejected("Consent target changed before publication; no credential was stored")
        validated[self.GENERATION_KEY] = generation
        try:
            written = self.write_kv2_document(secret_ref, validated, cas=target.vault_version,
                pattern=MCP_OAUTH_VAULT_SECRET_REF)
            if type(written) is not int or written != target.vault_version + 1:
                raise CredentialUnavailable("Consent publication returned an invalid version")
            return written
        except CredentialUnavailable:
            # One exact readback can establish our owned commit. Never retry
            # the grant/CAS or compensate a possibly published credential.
            try:
                actual, version = self.read_kv2_document(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
                if version == target.vault_version + 1 and self._validate_bundle(actual) == validated:
                    return version
            except CredentialUnavailable:
                pass
            raise CredentialUnavailable("Consent publication outcome is unknown; custody remains fenced") from None

    def compensate_unstored_consent(self, bundle: Mapping[str, Any]) -> None:
        """Request revocation of known unstored tokens, never touch the active KV key.

        Acknowledgement is not independent proof of issuer-family containment.
        The caller must retain its unresolved attempt and fence.
        """
        validated = self._validate_bundle(bundle)
        if not validated.get("revocation_endpoint"):
            raise CredentialUnavailable("Unstored consent has no revocation endpoint")
        if validated.get("refresh_token"):
            self._revoke_remote_token(validated, validated["refresh_token"], "refresh_token")
        self._revoke_remote_token(validated, validated["access_token"], "access_token")

    def store_bundle(
        self, secret_ref: str, bundle: Mapping[str, Any], *, generation: str | None = None,
    ) -> int:
        if generation is not None and (
            not isinstance(generation, str) or re.fullmatch(r"[0-9a-f]{32}", generation) is None
        ):
            raise CredentialUnavailable("Fresh consent generation is invalid")
        if self.GENERATION_KEY in bundle or self.COORDINATION_KEY in bundle:
            raise CredentialUnavailable("Fresh consent cannot supply internal OAuth coordination metadata")
        validated = self._validate_bundle(bundle)
        try:
            current, version = self.read_kv2_document(
                secret_ref,
                pattern=MCP_OAUTH_VAULT_SECRET_REF,
            )
        except VaultRequestError as exc:
            if exc.status_code != 404:
                raise
            version = self._missing_bundle_version(secret_ref)
        else:
            state = self._coordination(current, version)
            if state and state["status"] in {"revoking", "refreshing"}:
                raise CredentialUnavailable("OAuth credential operation is pending; fresh consent was not stored")
        validated[self.GENERATION_KEY] = generation or secrets.token_hex(16)
        return self.write_kv2_document(
            secret_ref,
            validated,
            cas=version,
            pattern=MCP_OAUTH_VAULT_SECRET_REF,
        )

    def delete_bundle(self, secret_ref: str) -> None:
        # No unfenced DELETE-latest escape hatch for OAuth credentials.
        self.revoke_bundle(secret_ref)

    def _revoke_remote_token(
        self,
        bundle: Mapping[str, Any],
        token: str,
        token_type_hint: str,
    ) -> None:
        fields = {
            "token": token,
            "token_type_hint": token_type_hint,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "iCheck-mcp-oauth/0.1",
        }
        client_secret = bundle.get("client_secret")
        if client_secret:
            encoded = base64.b64encode(
                (
                    f"{quote(bundle['client_id'], safe='')}:"
                    f"{quote(client_secret, safe='')}"
                ).encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            fields["client_id"] = bundle["client_id"]
        request = Request(
            self._oauth_url(bundle["revocation_endpoint"]),
            data=urlencode(fields).encode("ascii"),
            headers=headers,
            method="POST",
        )
        try:
            with self.oauth_opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(1_048_577)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise CredentialUnavailable("OAuth upstream token revocation failed") from exc
        if len(body) > 1_048_576:
            raise CredentialUnavailable("OAuth revocation response exceeded 1 MiB")

    def revoke_bundle(self, secret_ref: str, *, expected_generation: str | None = None) -> None:
        document, version = self.read_kv2_document(
            secret_ref,
            pattern=MCP_OAUTH_VAULT_SECRET_REF,
        )
        bundle = self._validate_bundle(document)
        self._check_generation(bundle, expected_generation)
        state = self._coordination(bundle, version)
        if state and state["status"] == "refreshing":
            bundle, version = self._wait_for_refresh(secret_ref, bundle, version)
        self._check_generation(bundle, expected_generation)
        # An explicit retry may fence an older revoker. Its version-targeted
        # delete cannot remove this reservation or a later fresh consent.
        bundle, version = self._claim(secret_ref, bundle, version, status="revoking")
        if bundle.get("revocation_endpoint"):
            refresh_token = bundle.get("refresh_token")
            if refresh_token:
                self._revoke_remote_token(bundle, refresh_token, "refresh_token")
            self._revoke_remote_token(
                bundle,
                bundle["access_token"],
                "access_token",
            )
        self.delete_kv2_version(secret_ref, version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        try:
            self.read_kv2_document(secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
        except VaultRequestError as exc:
            if exc.status_code != 404:
                raise
            if self._missing_bundle_version(secret_ref) == version:
                return
        raise CredentialUnavailable("OAuth revocation was superseded; cleanup remains pending")

    def _token_response(self, request: Request) -> dict[str, Any]:
        try:
            with self.oauth_opener.open(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                body = response.read(1_048_577)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise CredentialUnavailable("OAuth token refresh failed") from exc
        if len(body) > 1_048_576:
            raise CredentialUnavailable("OAuth token response exceeded 1 MiB")
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialUnavailable("OAuth token endpoint returned invalid JSON") from exc
        if not isinstance(document, dict) or "error" in document:
            raise CredentialUnavailable("OAuth token refresh was rejected")
        return document

    def _refreshed_bundle(
        self, claimed: dict[str, Any], response: Mapping[str, Any], started_at: datetime,
    ) -> dict[str, Any]:
        access_token = self._bounded_string(response, "access_token")
        token_type = self._bounded_string(response, "token_type", maximum=32)
        if token_type.lower() != "bearer":
            raise CredentialUnavailable("MCP OAuth refresh did not return Bearer")
        expires_in = response.get("expires_in")
        if (isinstance(expires_in, bool) or not isinstance(expires_in, int)
                or not 1 <= expires_in <= 86_400):
            raise CredentialUnavailable("OAuth refreshed token lifetime is invalid")
        expires_at = started_at + timedelta(seconds=expires_in)
        if expires_at <= datetime.now(UTC):
            raise CredentialUnavailable("OAuth refresh response arrived after token expiry")
        scope = claimed.get("scope", "")
        returned_scope = response.get("scope", scope)
        if not isinstance(returned_scope, str) or len(returned_scope) > 8192:
            raise CredentialUnavailable("OAuth refreshed token scope is invalid")
        if not set(returned_scope.split()).issubset(set(scope.split())):
            raise CredentialUnavailable("OAuth refresh returned unrequested scopes")
        updated = {
            **claimed, "access_token": access_token, "token_type": "Bearer",
            "expires_at": expires_at.isoformat(), "scope": returned_scope,
            self.COORDINATION_KEY: {**claimed[self.COORDINATION_KEY], "status": "ready"},
        }
        new_refresh = response.get("refresh_token")
        if new_refresh is not None:
            if not isinstance(new_refresh, str) or not 1 <= len(new_refresh) <= 65_536:
                raise CredentialUnavailable("OAuth rotated refresh token is invalid")
            updated["refresh_token"] = new_refresh
        return updated

    def _discard_rotated_tokens(
        self, secret_ref: str, claimed: dict[str, Any], reserved_version: int,
        response: Mapping[str, Any],
    ) -> None:
        # Never revoke on an ambiguous commit alone: another Worker may already
        # be using its published result. Fence this exact still-pending owner
        # with CAS before cleanup; a reconnect/newer refresh must be untouched.
        if not claimed.get("revocation_endpoint"):
            return
        access = response.get("access_token")
        if not isinstance(access, str) or not 1 <= len(access) <= 65_536:
            return
        cleanup = {**claimed, "access_token": access}
        refresh = response.get("refresh_token")
        if isinstance(refresh, str) and 1 <= len(refresh) <= 65_536:
            cleanup["refresh_token"] = refresh
        elif "refresh_token" in response:
            cleanup.pop("refresh_token", None)
        try:
            current, current_version = self.read_kv2_document(
                secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF,
            )
            if current_version != reserved_version or current != claimed:
                return
            cleanup, cleanup_version = self._claim(
                secret_ref, cleanup, reserved_version, status="revoking",
            )
        except CredentialUnavailable:
            return
        failed = False
        for key in ("refresh_token", "access_token"):
            token = cleanup.get(key)
            if isinstance(token, str) and 1 <= len(token) <= 65_536:
                try:
                    self._revoke_remote_token(cleanup, token, key)
                except CredentialUnavailable:
                    failed = True
        if not failed:
            try:
                self.delete_kv2_version(
                    secret_ref, cleanup_version, pattern=MCP_OAUTH_VAULT_SECRET_REF,
                )
            except CredentialUnavailable:
                pass  # Durable revoking state requires explicit cleanup retry.

    def _refresh(
        self,
        secret_ref: str,
        bundle: dict[str, Any],
        version: int,
    ) -> tuple[dict[str, Any], int]:
        refresh_token = bundle.get("refresh_token")
        if not refresh_token:
            raise CredentialUnavailable(
                "MCP OAuth access token is expiring and no refresh token is available"
            )
        try:
            claimed, reserved_version = self._claim(
                secret_ref, bundle, version, status="refreshing",
            )
        except VaultRequestError as exc:
            if exc.status_code not in {400, 409}:
                raise
            return self._wait_for_refresh(secret_ref, bundle, version)
        observed, observed_version = self.read_kv2_document(
            secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF,
        )
        observed = self._validate_bundle(observed)
        state = self._coordination(observed, observed_version)
        if (observed_version != reserved_version
                or state != claimed[self.COORDINATION_KEY]
                or self._timestamp(state["deadline"]) <= datetime.now(UTC)):
            raise CredentialUnavailable("OAuth refresh reservation is no longer current")
        fields = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": bundle["resource"],
        }
        scope = bundle.get("scope", "")
        if scope:
            fields["scope"] = scope
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "iCheck-mcp-oauth/0.1",
        }
        client_secret = bundle.get("client_secret")
        if client_secret:
            encoded = base64.b64encode(
                (
                    f"{quote(bundle['client_id'], safe='')}:"
                    f"{quote(client_secret, safe='')}"
                ).encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            fields["client_id"] = bundle["client_id"]
        refresh_started_at = datetime.now(UTC)
        response = self._token_response(
            Request(
                self._oauth_url(bundle["token_endpoint"]),
                data=urlencode(fields).encode("ascii"),
                headers=headers,
                method="POST",
            )
        )
        try:
            if self._timestamp(claimed[self.COORDINATION_KEY]["deadline"]) <= datetime.now(UTC):
                raise CredentialUnavailable("OAuth refresh owner deadline elapsed")
            updated = self._refreshed_bundle(claimed, response, refresh_started_at)
        except CredentialUnavailable:
            self._discard_rotated_tokens(secret_ref, claimed, reserved_version, response)
            raise
        try:
            new_version = self.write_kv2_document(
                secret_ref,
                updated,
                cas=reserved_version,
                pattern=MCP_OAUTH_VAULT_SECRET_REF,
            )
            if new_version != reserved_version + 1:
                raise CredentialUnavailable("Vault returned an invalid OAuth commit version")
            return updated, new_version
        except CredentialUnavailable:
            # Read back one ambiguous commit; never repeat the token request or
            # CAS write. Only this exact observed commit can release the lease.
            try:
                current, current_version = self.read_kv2_document(
                    secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF,
                )
                current = self._validate_bundle(current)
                if current_version == reserved_version + 1 and current == updated:
                    return current, current_version
            except CredentialUnavailable:
                pass
            self._discard_rotated_tokens(secret_ref, claimed, reserved_version, updated)
            raise CredentialUnavailable("OAuth refresh commit is uncertain or fenced") from None

    def _check_generation(self, bundle: Mapping[str, Any], expected: str | None) -> None:
        if expected is not None and (
            not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{32}", expected) is None
            or bundle.get(self.GENERATION_KEY) != expected
        ):
            raise CredentialUnavailable("OAuth consent generation no longer matches the grant")

    def _observation(
        self, bundle: Mapping[str, Any], version: int, *, failed: bool = False,
    ) -> OAuthCredentialObservation | None:
        generation = bundle.get(self.GENERATION_KEY)
        if generation is None:
            return None  # Legacy data must be reconnected; never invent a receipt.
        state = self._coordination(bundle, version)
        status = state["status"] if state else "ready"
        if failed and status == "ready":
            status = "uncertain"
        return OAuthCredentialObservation(
            generation=generation, vault_version=version,
            token_expires_at=self._timestamp(bundle["expires_at"]),
            observed_at=datetime.now(UTC), coordination_state=status,
        )

    def resolve(
        self, secret_ref: str, *, expected_generation: str | None = None,
    ) -> ProviderCredentialLease:
        document, version = self.read_kv2_document(
            secret_ref,
            pattern=MCP_OAUTH_VAULT_SECRET_REF,
        )
        bundle = self._validate_bundle(document)
        # Fence before refresh I/O, not merely before returning a bearer token.
        self._check_generation(bundle, expected_generation)
        try:
            state = self._coordination(bundle, version)
            expires_at = self._timestamp(bundle["expires_at"])
            if state and state["status"] == "revoking":
                raise CredentialUnavailable("OAuth credential revocation is pending")
            if state and state["status"] == "refreshing":
                bundle, version = self._wait_for_refresh(secret_ref, bundle, version)
            elif expires_at <= datetime.now(UTC) + timedelta(seconds=self.refresh_skew_seconds):
                bundle, version = self._refresh(secret_ref, bundle, version)
            self._check_generation(bundle, expected_generation)
        except CredentialUnavailable as exc:
            # One bounded readback reports uncertainty without exposing any token,
            # replaying refresh, or attributing a newer consent to this assignment.
            try:
                latest, latest_version = self.read_kv2_document(
                    secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF,
                )
                latest = self._validate_bundle(latest)
                self._check_generation(latest, expected_generation)
                observation = self._observation(latest, latest_version, failed=True)
            except CredentialUnavailable:
                observation = None
            if observation is not None:
                raise OAuthCredentialUnavailable(str(exc), observation) from exc
            raise
        return ProviderCredentialLease(
            values={"bearer_token": bundle["access_token"]},
            expires_at=self._timestamp(bundle["expires_at"]),
            oauth_observation=self._observation(bundle, version),
        )


class VaultDynamicCredentialProvider(VaultKV2CredentialProvider):
    """Resolve, renew, and revoke a bounded Vault dynamic-secret lease."""

    def resolve(self, secret_ref: str) -> ProviderCredentialLease:
        match = VAULT_DYNAMIC_SECRET_REF.fullmatch(secret_ref)
        if match is None or ".." in match.group("path").split("/"):
            raise CredentialUnavailable("Vault dynamic secret reference is invalid")
        mount = quote(match.group("mount"), safe="")
        path = quote(match.group("path").strip("/"), safe="/")
        document = self._request_json("GET", f"{mount}/{path}")
        values = document.get("data")
        lease_id = document.get("lease_id")
        lease_duration = document.get("lease_duration")
        renewable = document.get("renewable")
        if (
            not isinstance(values, dict)
            or not isinstance(lease_id, str)
            or not 1 <= len(lease_id) <= 4096
            or isinstance(lease_duration, bool)
            or not isinstance(lease_duration, int)
            or not 1 <= lease_duration <= 86_400
            or not isinstance(renewable, bool)
        ):
            raise CredentialUnavailable(
                "Vault returned an invalid dynamic credential lease"
            )
        expires_at = datetime.now(UTC) + timedelta(seconds=lease_duration)

        def renew(increment_seconds: int) -> datetime:
            response = self._request_json(
                "PUT",
                "sys/leases/renew",
                {"lease_id": lease_id, "increment": increment_seconds},
            )
            duration = response.get("lease_duration")
            if (
                isinstance(duration, bool)
                or not isinstance(duration, int)
                or not 1 <= duration <= 86_400
            ):
                raise CredentialUnavailable(
                    "Vault returned an invalid renewed lease duration"
                )
            return datetime.now(UTC) + timedelta(seconds=duration)

        def revoke() -> None:
            self._request_json(
                "PUT",
                "sys/leases/revoke",
                {"lease_id": lease_id},
                allow_empty=True,
            )

        return ProviderCredentialLease(
            values=_normalize_credential_values(values),
            expires_at=expires_at,
            renewable=renewable,
            renew_callback=renew if renewable else None,
            revoke_callback=revoke,
        )


def build_server_credential_providers(
    *,
    settings: Any | None = None,
    vault_opener: Any | None = None,
) -> dict[str, CredentialProvider]:
    """Build control-plane resolvers from process-local configuration.

    Device and infrastructure credentials remain worker-resolved. This provider
    set is only for explicitly unscoped profiles used by control-plane clients
    such as AI provider health checks and MCP Tool attestation.
    """

    if settings is None:
        from .config import get_settings

        settings = get_settings()
    providers: dict[str, CredentialProvider] = {
        "environment": EnvironmentCredentialProvider(),
    }
    address = settings.server_secret_vault_address
    token_file = settings.server_secret_vault_token_file
    if address and token_file:
        vault = VaultKV2CredentialProvider(
            address=address,
            token_file=token_file,
            namespace=settings.server_secret_vault_namespace,
            timeout_seconds=settings.server_secret_vault_timeout_seconds,
            opener=vault_opener,
        )
        providers["vault"] = vault
        providers["vault_kv2"] = vault
        providers["vault_dynamic"] = VaultDynamicCredentialProvider(
            address=address,
            token_file=token_file,
            namespace=settings.server_secret_vault_namespace,
            timeout_seconds=settings.server_secret_vault_timeout_seconds,
            opener=vault_opener,
        )
        providers["mcp_oauth_vault"] = MCPOAuthVaultCredentialProvider(
            address=address,
            token_file=token_file,
            namespace=settings.server_secret_vault_namespace,
            timeout_seconds=settings.server_secret_vault_timeout_seconds,
            opener=vault_opener,
            oauth_allowed_hosts=getattr(
                settings,
                "mcp_oauth_allowed_host_list",
                [],
            ),
        )
    return providers


@contextmanager
def resolved_server_secret(
    profile: CredentialProfile,
    *,
    adapter_type: str,
    providers: Mapping[str, CredentialProvider] | None = None,
) -> Iterator[str]:
    """Resolve one control-plane secret for the lifetime of one operation.

    Dynamic provider leases are revoked on every success or failure path. The
    yielded value must not escape the context or be persisted by the caller.
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
    configured = (
        build_server_credential_providers()
        if providers is None
        else providers
    )
    provider = configured.get(profile.provider)
    if provider is None:
        raise CredentialUnavailable(
            f"Credential provider {profile.provider!r} is not configured"
        )
    result = provider.resolve(profile.secret_ref)
    lease = result if isinstance(result, ProviderCredentialLease) else None
    normalized: dict[str, str] = {}
    try:
        values = lease.values if lease is not None else result
        normalized = _normalize_credential_values(values)
        if len(normalized) != 1:
            raise CredentialUnavailable(
                "Server-side credential profiles must resolve exactly one value"
            )
        if lease is not None and lease.expires_at <= datetime.now(UTC):
            raise CredentialUnavailable("Resolved server credential lease is expired")
        yield next(iter(normalized.values()))
    finally:
        if lease is not None and lease.revoke_callback is not None:
            try:
                lease.revoke_callback()
            except Exception:
                LOGGER.warning(
                    "Unable to revoke server credential lease",
                    exc_info=True,
                )
        for key in list(normalized):
            normalized[key] = ""
        normalized.clear()


def resolve_server_secret(
    profile: CredentialProfile,
    *,
    adapter_type: str,
    providers: Mapping[str, CredentialProvider] | None = None,
) -> str:
    """Resolve one control-plane secret without returning it through an API."""

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
    configured = (
        build_server_credential_providers()
        if providers is None
        else providers
    )
    provider = configured.get(profile.provider)
    if provider is None:
        raise CredentialUnavailable(
            f"Credential provider {profile.provider!r} is not configured"
        )
    result = provider.resolve(profile.secret_ref)
    if isinstance(result, ProviderCredentialLease):
        if result.revoke_callback is not None:
            result.revoke_callback()
        raise CredentialUnavailable(
            "Dynamic server credentials require lease-scoped resolution"
        )
    values = _normalize_credential_values(result)
    if len(values) != 1:
        raise CredentialUnavailable(
            "Server-side credential profiles must resolve exactly one value"
        )
    return next(iter(values.values()))
