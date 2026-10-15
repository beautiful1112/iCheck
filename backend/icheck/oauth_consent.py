"""Private, typed consent custody and secret-free public generation history."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OAuthConsentTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    present: bool = Field(strict=True)
    vault_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    issuer: str | None = Field(default=None, min_length=1, max_length=2048)
    client_id: str | None = Field(default=None, min_length=1, max_length=2048)
    resource: str | None = Field(default=None, min_length=1, max_length=2048)
    coordination_owner: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")

    @model_validator(mode="after")
    def consistent_target(self):
        if self.present:
            if self.vault_version < 1 or any(value is None for value in (self.issuer, self.client_id, self.resource)):
                raise ValueError("A present consent target requires exact identity and version")
        elif any(value is not None for value in (self.generation, self.issuer, self.client_id, self.resource, self.coordination_owner)):
            raise ValueError("Absent consent data cannot claim a credential identity")
        return self


class OAuthConsentAuthority(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    auth_method: Literal["bearer", "browser_session", "development"]
    principal_id: str | None = Field(default=None, min_length=1, max_length=36)
    credential_id: str | None = Field(default=None, min_length=1, max_length=36)
    subject: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def proven_credential(self):
        if self.auth_method == "development":
            if self.principal_id is not None or self.credential_id is not None:
                raise ValueError("Development consent cannot impersonate a credential")
        elif self.principal_id is None or self.credential_id is None:
            raise ValueError("Human consent requires authenticated credential provenance")
        return self


class OAuthConsentProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=36)
    revision: int = Field(strict=True, ge=0)
    provider: str = Field(min_length=1, max_length=64)
    secret_ref: str = Field(min_length=1, max_length=1024)


class OAuthAuthorizationLocator(BaseModel):
    """Public protocol identifiers, never the code, state or PKCE verifier."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    transaction_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pkce_s256: str = Field(pattern=r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")


class OAuthConsentSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format_version: int = Field(default=1, strict=True, ge=1, le=1)
    server_id: str = Field(min_length=1, max_length=36)
    tenant_id: str = Field(min_length=1, max_length=36)
    region_id: str = Field(min_length=1, max_length=36)
    server_name: str = Field(min_length=1, max_length=255)
    endpoint_url: str = Field(min_length=1, max_length=2048)
    client_id: str = Field(min_length=1, max_length=2048)
    generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    token_profile: OAuthConsentProfile
    client_profile: OAuthConsentProfile | None = None
    vault_address: str = Field(min_length=1, max_length=2048)
    vault_namespace: str | None = Field(default=None, max_length=255)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    authority: OAuthConsentAuthority
    # Older retained snapshots cannot acquire a guessed issuer-family locator.
    authorization_locator: OAuthAuthorizationLocator | None = None


ConsentStatus = Literal[
    "redemption_admitted", "storage_admitted", "connected", "superseded",
    "outcome_unknown", "compensation_pending", "compensation_acknowledged",
    "stored_unpublished", "revoked",
]
OPEN_CONSENT_STATUSES = (
    "redemption_admitted", "storage_admitted", "outcome_unknown",
    "compensation_pending", "compensation_acknowledged", "stored_unpublished",
)


class MCPOAuthConsentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    server_id: str
    transaction_id: str
    generation: str
    previous_generation: str | None
    status: ConsentStatus
    issuer: str
    client_id: str
    resource: str
    target_version: int
    stored_version: int | None
    actor_id: str
    admitted_at: datetime
    updated_at: datetime
    failure_code: str | None
    refresh_token_received: bool
    family_recovery_id: str | None
    family_contained_at: datetime | None = None
