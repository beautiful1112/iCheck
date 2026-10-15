from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, SecretStr, field_validator

from .schemas import APIModel


class AuthStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    @field_validator("password", "current_password", "new_password", check_fields=False)
    @classmethod
    def valid_password_unicode(cls, value: SecretStr | None):
        if value is not None:
            try:
                value.get_secret_value().encode("utf-8")
            except UnicodeError:
                raise ValueError("Password must contain valid Unicode") from None
        return value


class PrincipalCreate(AuthStrictModel):
    subject: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9@._:/-]*$",
    )
    display_name: str = Field(min_length=1, max_length=255)
    principal_type: Literal["user", "service"] = "user"
    enabled: bool = True
    allowed_region_ids: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("allowed_region_ids")
    @classmethod
    def normalize_region_ids(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 36 for item in normalized):
            raise ValueError("region IDs must not exceed 36 characters")
        return list(dict.fromkeys(normalized))


class PrincipalRead(PrincipalCreate):
    id: str
    tenant_id: str
    region_id: str
    platform_admin: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    password_login_configured: bool


class PrincipalUpdate(AuthStrictModel):
    enabled: bool
    reason: str = Field(min_length=1, max_length=4000)


class RoleCreate(AuthStrictModel):
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(default="", max_length=4000)
    permissions: list[str] = Field(default_factory=list, max_length=128)

    @field_validator("permissions")
    @classmethod
    def normalize_permissions(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 128 for item in normalized):
            raise ValueError("permissions must not exceed 128 characters")
        return list(dict.fromkeys(normalized))


class RoleRead(RoleCreate):
    id: str
    tenant_id: str
    region_id: str
    system: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class RoleBindingCreate(AuthStrictModel):
    role_id: str
    scope: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = set(value) - {"all", "sites", "device_ids"}
        if unknown:
            raise ValueError(
                f"unsupported authorization scope keys: {', '.join(sorted(unknown))}"
            )
        if "all" in value and not isinstance(value["all"], bool):
            raise ValueError("scope.all must be a boolean")
        if value.get("all") is True and len(value) > 1:
            raise ValueError("scope.all cannot be combined with target constraints")
        normalized = dict(value)
        for key in ("sites", "device_ids"):
            if key not in value:
                continue
            items = value[key]
            if not isinstance(items, list) or len(items) > 1000:
                raise ValueError(f"scope.{key} must be a list of at most 1000 values")
            if any(
                not isinstance(item, str)
                or not item.strip()
                or len(item.strip()) > 255
                for item in items
            ):
                raise ValueError(
                    f"scope.{key} values must contain 1 to 255 characters"
                )
            normalized[key] = list(dict.fromkeys(item.strip() for item in items))
        return normalized


class RoleBindingRead(RoleBindingCreate):
    id: str
    principal_id: str
    tenant_id: str
    region_id: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class AccessTokenCreate(AuthStrictModel):
    name: str = Field(min_length=1, max_length=255)
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)


class AccessTokenRead(AuthStrictModel):
    id: str
    principal_id: str
    name: str
    token_prefix: str
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    revocation_reason: str | None
    created_by: str
    created_at: datetime


class AccessTokenIssue(AuthStrictModel):
    token: AccessTokenRead
    access_token: str


class TokenRevoke(AuthStrictModel):
    reason: str = Field(min_length=1, max_length=4000)


class BootstrapRequest(PrincipalCreate):
    token_name: str = Field(default="initial-admin", min_length=1, max_length=255)
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)
    password: SecretStr | None = Field(default=None, min_length=15, max_length=256)


class BootstrapResult(AuthStrictModel):
    principal: PrincipalRead
    token: AccessTokenIssue


class PrincipalContextRead(AuthStrictModel):
    principal_id: str | None
    subject: str
    principal_type: str
    permissions: list[str]
    role_names: list[str]
    authorization_scope: dict[str, Any]
    auth_method: str
    tenant_id: str
    tenant_slug: str
    region_id: str
    region_code: str
    platform_admin: bool


class BrowserSessionIssue(AuthStrictModel):
    principal: PrincipalContextRead
    expires_at: datetime
    csrf_token: str


class PasswordLogin(AuthStrictModel):
    username: str = Field(min_length=1, max_length=255)
    password: SecretStr = Field(min_length=1, max_length=256)
    tenant: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        return value.strip() if isinstance(value, str) else value


class PasswordLoginConfig(AuthStrictModel):
    enabled: bool


class PrincipalPasswordSet(AuthStrictModel):
    password: SecretStr = Field(min_length=15, max_length=256)
    reason: str = Field(min_length=1, max_length=4000)


class PasswordChange(AuthStrictModel):
    current_password: SecretStr = Field(min_length=1, max_length=256)
    new_password: SecretStr = Field(min_length=15, max_length=256)


class BrowserCsrfToken(AuthStrictModel):
    csrf_token: str


class BrowserSessionRead(AuthStrictModel):
    id: str
    principal_id: str
    tenant_id: str
    region_id: str
    auth_source: str
    federated_identity_id: str | None
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    revocation_reason_sha256: str | None
    created_at: datetime


class BrowserSessionRevoke(AuthStrictModel):
    reason: str = Field(min_length=1, max_length=4000)


class BrowserSessionsRevokeResult(AuthStrictModel):
    principal_id: str
    revoked_count: int


class OIDCFederationConfigRead(AuthStrictModel):
    enabled: bool
    display_name: str | None
    start_url: str | None
    local_token_login_enabled: bool


class OIDCIdentityCreate(AuthStrictModel):
    subject: str = Field(min_length=1, max_length=1024)


class OIDCIdentityUpdate(AuthStrictModel):
    enabled: bool
    reason: str = Field(min_length=1, max_length=4000)


class OIDCIdentityRead(AuthStrictModel):
    id: str
    principal_id: str
    tenant_id: str
    region_id: str
    issuer: str
    issuer_sha256: str
    subject_sha256: str
    enabled: bool
    last_login_at: datetime | None
    last_claims_sha256: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class TrustedProxyFederationConfigRead(AuthStrictModel):
    enabled: bool
    display_name: str | None
    start_url: str | None


class TrustedProxyIdentityCreate(AuthStrictModel):
    subject: str = Field(min_length=1, max_length=1024)

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 0x20 for character in value):
            raise ValueError(
                "trusted-proxy subject must contain printable characters "
                "without surrounding whitespace"
            )
        return value


class TrustedProxyIdentityUpdate(AuthStrictModel):
    enabled: bool
    reason: str = Field(min_length=1, max_length=4000)


class TrustedProxyIdentityRead(AuthStrictModel):
    id: str
    principal_id: str
    tenant_id: str
    region_id: str
    issuer: str
    issuer_sha256: str
    subject_sha256: str
    enabled: bool
    last_login_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class WorkloadFederationConfigRead(AuthStrictModel):
    enabled: bool
    issuer: str | None
    audience: str | None
    token_ttl_minutes: int | None


class WorkloadIdentityCreate(AuthStrictModel):
    subject: str = Field(min_length=1, max_length=1024)
    max_token_ttl_minutes: int | None = Field(default=None, ge=1, le=60)

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 0x20 for character in value):
            raise ValueError(
                "workload subject must contain printable characters "
                "without surrounding whitespace"
            )
        return value


class WorkloadIdentityUpdate(AuthStrictModel):
    enabled: bool
    max_token_ttl_minutes: int = Field(ge=1, le=60)
    reason: str = Field(min_length=1, max_length=4000)


class WorkloadIdentityRead(AuthStrictModel):
    id: str
    principal_id: str
    tenant_id: str
    region_id: str
    issuer: str
    issuer_sha256: str
    subject_sha256: str
    audience_sha256: str
    enabled: bool
    max_token_ttl_minutes: int
    last_exchange_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class WorkloadTokenExchange(AuthStrictModel):
    grant_type: Literal[
        "urn:ietf:params:oauth:grant-type:token-exchange"
    ]
    subject_token_type: Literal["urn:ietf:params:oauth:token-type:jwt"]
    subject_token: str = Field(min_length=1, max_length=65_536)
    requested_token_type: Literal[
        "urn:ietf:params:oauth:token-type:access_token"
    ] = "urn:ietf:params:oauth:token-type:access_token"


class WorkloadTokenIssue(AuthStrictModel):
    access_token: str
    issued_token_type: Literal[
        "urn:ietf:params:oauth:token-type:access_token"
    ]
    token_type: Literal["Bearer"]
    expires_in: int
