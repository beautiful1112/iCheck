"""Private exact-key plans and secret-free receipts for family finalization."""
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .oauth_consent import OAuthAuthorizationLocator, OAuthConsentTarget

Version = Annotated[int, Field(strict=True, ge=1, le=2_147_483_647)]


class FamilyLocalScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    attempt_id: str = Field(min_length=1, max_length=36)
    generation: str = Field(pattern=r"^[0-9a-f]{32}$")
    locator: OAuthAuthorizationLocator
    issuer: str = Field(min_length=1, max_length=2048)
    client_id: str = Field(min_length=1, max_length=2048)
    resource: str = Field(min_length=1, max_length=2048)
    target: OAuthConsentTarget
    historical: bool = Field(strict=True)
    vault_address: str = Field(min_length=1, max_length=2048)
    vault_namespace: str | None = Field(default=None, max_length=255)
    secret_ref: str = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def distinct_family(self):
        if self.generation == self.target.generation:
            raise ValueError("Recovery must distinguish new and previous consent families")
        return self


LocalMode = Literal["preserve_previous", "reserve_empty", "retire_head", "retired_elsewhere"]


class FamilyLocalPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format_version: int = Field(default=1, strict=True, ge=1, le=1)
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    scope: FamilyLocalScope
    mode: LocalMode
    head_version: int = Field(strict=True, ge=0, le=2_147_483_645)
    head_generation: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    owned_versions: tuple[Version, ...] = Field(default=(), max_length=256)
    allow_late_publish: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def bounded_plan(self):
        if (any(type(v) is not int or not 1 <= v <= self.head_version for v in self.owned_versions)
                or tuple(sorted(set(self.owned_versions))) != self.owned_versions):
            raise ValueError("Owned version inventory must be sorted, unique and bounded by the observed head")
        if self.head_version < self.scope.target.vault_version:
            raise ValueError("Vault history regressed behind the original target")
        if self.mode == "preserve_previous" and (self.scope.historical or not self.scope.target.present):
            raise ValueError("Only pending consent with an original bundle may preserve the previous family")
        if self.mode == "reserve_empty" and (self.scope.historical or self.scope.target.present):
            raise ValueError("Only originally absent pending consent may reserve an empty key")
        if self.mode == "retire_head" and not self.scope.historical:
            raise ValueError("Pending consent must preserve its exact previous target")
        if self.mode == "retired_elsewhere" and (self.head_version <= self.scope.target.vault_version
                or self.head_generation == self.scope.generation):
            raise ValueError("External fencing requires a newer head belonging to a different family")
        if self.allow_late_publish and (self.head_version != self.scope.target.vault_version
                or self.mode not in {"preserve_previous", "reserve_empty"}):
            raise ValueError("Only the original admitted publication may race an original-head reservation")
        if self.allow_late_publish and self.mode == "preserve_previous" and self.head_version > 2_147_483_644:
            raise ValueError("Late publication must leave room for reservation and previous-family restore")
        return self


class FamilyLocalReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    mode: LocalMode
    source_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    fence_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    reservation_version: int | None = Field(default=None, strict=True, ge=1, le=2_147_483_647)
    owned_versions: tuple[Version, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def exact_receipt(self):
        if (any(type(v) is not int or not 1 <= v <= self.source_version for v in self.owned_versions)
                or tuple(sorted(set(self.owned_versions))) != self.owned_versions):
            raise ValueError("Receipt version inventory must be exact and bounded")
        if self.mode == "retired_elsewhere":
            if self.reservation_version is not None or self.fence_version != self.source_version:
                raise ValueError("An external fence cannot claim an owned reservation")
        elif self.reservation_version != self.source_version + 1 or self.fence_version != self.reservation_version:
            raise ValueError("Owned reservation must be the exact next CAS version")
        return self


class FamilyRestoreWitness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    reservation_version: int = Field(strict=True, ge=1, le=2_147_483_646)


class FamilyLocalCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    fence_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    head_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    restored_previous: bool = Field(strict=True)
    previous_expires_at: datetime | None = None
    deleted_versions: tuple[Version, ...] = Field(default=(), max_length=257)

    @model_validator(mode="after")
    def complete_receipt(self):
        if self.head_version < self.fence_version:
            raise ValueError("Completion cannot undo the publication fence")
        if self.restored_previous != (self.previous_expires_at is not None):
            raise ValueError("Only a restored original bundle may claim its expiry")
        if self.previous_expires_at is not None and self.previous_expires_at.tzinfo is None:
            raise ValueError("Restored expiry requires a timezone")
        if (any(type(v) is not int or not 1 <= v <= self.head_version for v in self.deleted_versions)
                or tuple(sorted(set(self.deleted_versions))) != self.deleted_versions):
            raise ValueError("Completion must retain exact deleted versions")
        return self


class MCPOAuthFamilyLocalStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    reason: str = Field(min_length=10, max_length=1000)


class MCPOAuthFamilyLocalExecute(MCPOAuthFamilyLocalStart):
    expected_plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class MCPOAuthFamilyLocalRead(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server_id: str
    attempt_id: str
    recovery_id: str
    plan_id: str
    status: Literal["admitted", "fenced", "complete"]
    mode: LocalMode
    planned_head_version: int
    affected_versions: tuple[int, ...]
    admitted_by: str
    admitted_at: datetime
    receipt: FamilyLocalReceipt | None
    deleted_versions: tuple[int, ...]
    completion: FamilyLocalCompletion | None
    completed_at: datetime | None
    local_cleanup_verified: bool
    reconnect_allowed: Literal[False] = False
