from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field

from .models import ArtifactKind
from .schemas import APIModel


class CapabilityCatalogModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CapabilityProvenanceRead(CapabilityCatalogModel):
    source: Literal["local", "artifact_bundle", "capability_pack"] = "local"
    signed: bool
    algorithm: str | None = None
    key_fingerprint_sha256: str | None = None
    verified_at: datetime | None = None
    pack_name: str | None = None
    pack_version: str | None = None
    pack_digest_sha256: str | None = None


class CapabilityCatalogItemRead(CapabilityCatalogModel):
    artifact_id: str
    artifact_version_id: str
    name: str
    kind: ArtifactKind
    description: str
    owner: str
    tags: list[str] = Field(default_factory=list)
    version: int
    content_hash: str
    published_at: datetime | None
    runtime: str
    readiness: Literal["ready", "blocked", "declarative"]
    activation_state: Literal["active", "inactive", "not_required"]
    activation_count: int = Field(ge=0)
    dependency_count: int = Field(ge=0)
    required_permissions: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    provenance: CapabilityProvenanceRead
    summary: dict[str, Any] = Field(default_factory=dict)


class CapabilityCatalogCounts(CapabilityCatalogModel):
    ready: int = 0
    blocked: int = 0
    declarative: int = 0
    active: int = 0
    inactive: int = 0
    not_required: int = 0


class CapabilityCatalogRead(CapabilityCatalogModel):
    items: list[CapabilityCatalogItemRead]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    truncated: bool
    scan_truncated: bool
    counts: CapabilityCatalogCounts
