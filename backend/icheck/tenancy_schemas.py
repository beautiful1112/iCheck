from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field

from .auth_schemas import AccessTokenIssue, PrincipalCreate, PrincipalRead
from .schemas import APIModel


class TenancyStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class TenantCreate(TenancyStrictModel):
    slug: str = Field(
        min_length=2,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
    )
    name: str = Field(min_length=1, max_length=255)
    default_region_code: str = Field(
        default="primary",
        min_length=2,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
    )
    default_region_name: str = Field(
        default="Primary region",
        min_length=1,
        max_length=255,
    )


class TenantRead(TenancyStrictModel):
    id: str
    slug: str
    name: str
    enabled: bool
    default_region_id: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class RegionCreate(TenancyStrictModel):
    code: str = Field(
        min_length=2,
        max_length=63,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
    )
    name: str = Field(min_length=1, max_length=255)
    enabled: bool = True


class RegionRead(TenancyStrictModel):
    id: str
    tenant_id: str
    code: str
    name: str
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class NamespaceContextRead(TenancyStrictModel):
    tenant: TenantRead
    region: RegionRead
    allowed_region_ids: list[str]
    platform_admin: bool


class TenantAdminCreate(PrincipalCreate):
    token_name: str = Field(
        default="initial-tenant-admin",
        min_length=1,
        max_length=255,
    )
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)


class TenantAdminIssue(TenancyStrictModel):
    principal: PrincipalRead
    token: AccessTokenIssue
