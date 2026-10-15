from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


REMOTE_CATALOG_FORMAT = "icheck.capability-catalog-index/v1"
SIGNED_REMOTE_CATALOG_FORMAT = "icheck.capability-catalog-index.signed/v1"
REMOTE_CATALOG_KEY_ROTATION_FORMAT = (
    "icheck.capability-catalog-key-rotation/v1"
)
SIGNED_REMOTE_CATALOG_KEY_ROTATION_FORMAT = (
    "icheck.capability-catalog-key-rotation.signed/v1"
)


class RemoteCatalogModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class RemoteCatalogIndexEntry(RemoteCatalogModel):
    pack_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    pack_version: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    platform_api: str = Field(min_length=1, max_length=64)
    pack_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pack_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    download_url: str = Field(min_length=1, max_length=2048)
    artifact_count: int = Field(ge=1, le=20)
    dependency_count: int = Field(ge=0, le=200)


class RemoteCatalogIndex(RemoteCatalogModel):
    format_version: Literal[
        "icheck.capability-catalog-index/v1"
    ] = REMOTE_CATALOG_FORMAT
    catalog_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    entries: list[RemoteCatalogIndexEntry] = Field(
        min_length=1,
        max_length=2000,
    )
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_index(self) -> "RemoteCatalogIndex":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Remote catalog timestamps require timezone offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Remote catalog expiry must follow its issue time")
        identities = [
            (entry.pack_name, entry.pack_version) for entry in self.entries
        ]
        if len(set(identities)) != len(identities):
            raise ValueError(
                "Remote catalog pack name/version entries must be unique"
            )
        digests = [entry.pack_digest_sha256 for entry in self.entries]
        if len(set(digests)) != len(digests):
            raise ValueError("Remote catalog pack digests must be unique")
        return self


class SignedRemoteCatalogIndex(RemoteCatalogModel):
    format_version: Literal[
        "icheck.capability-catalog-index.signed/v1"
    ] = SIGNED_REMOTE_CATALOG_FORMAT
    index: RemoteCatalogIndex
    signature: ArtifactBundleSignature


class RemoteCatalogSourceCreate(RemoteCatalogModel):
    name: str = Field(min_length=1, max_length=255)
    catalog_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    index_url: str = Field(min_length=1, max_length=2048)
    trust_key_id: str = Field(min_length=1, max_length=36)
    created_by: str = Field(min_length=1, max_length=255)


class RemoteCatalogSourceStateCreate(RemoteCatalogModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class RemoteCatalogRefreshCreate(RemoteCatalogModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class RemoteCatalogPackActionCreate(RemoteCatalogModel):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class RemoteCatalogKeyRotationStatement(RemoteCatalogModel):
    format_version: Literal[
        "icheck.capability-catalog-key-rotation/v1"
    ] = REMOTE_CATALOG_KEY_ROTATION_FORMAT
    catalog_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    catalog_sequence: int = Field(ge=0)
    index_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_rotation(self) -> "RemoteCatalogKeyRotationStatement":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Catalog key rotation timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Catalog key rotation expiry must follow issue time")
        if self.current_key_fingerprint_sha256 == (
            self.next_key_fingerprint_sha256
        ):
            raise ValueError("Catalog key rotation requires a different key")
        if (self.catalog_sequence == 0) != (
            self.index_digest_sha256 is None
        ):
            raise ValueError(
                "Catalog key rotation sequence and index digest are inconsistent"
            )
        return self


class SignedRemoteCatalogKeyRotation(RemoteCatalogModel):
    format_version: Literal[
        "icheck.capability-catalog-key-rotation.signed/v1"
    ] = SIGNED_REMOTE_CATALOG_KEY_ROTATION_FORMAT
    statement: RemoteCatalogKeyRotationStatement
    current_signature: ArtifactBundleSignature
    next_signature: ArtifactBundleSignature


class RemoteCatalogKeyRotationCreate(RemoteCatalogModel):
    new_trust_key_id: str = Field(min_length=1, max_length=36)
    signed_rotation: SignedRemoteCatalogKeyRotation
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class RemoteCatalogKeyRotationRead(RemoteCatalogModel):
    id: str
    source_id: str
    from_trust_key_id: str
    to_trust_key_id: str
    from_key_fingerprint_sha256: str
    to_key_fingerprint_sha256: str
    catalog_sequence: int
    index_digest_sha256: str | None
    statement_digest_sha256: str
    current_signature_sha256: str
    next_signature_sha256: str
    issued_at: datetime
    expires_at: datetime
    reason: str
    rotated_by: str
    rotated_at: datetime


class RemoteCatalogSourceRead(RemoteCatalogModel):
    id: str
    name: str
    catalog_id: str
    index_url: str
    trust_key_id: str
    enabled: bool
    latest_sequence: int | None
    latest_index_digest_sha256: str | None
    last_refresh_status: Literal["never", "succeeded", "failed"]
    last_refresh_at: datetime | None
    last_error_sha256: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class RemoteCatalogEntryRead(RemoteCatalogModel):
    id: str
    source_id: str
    source_name: str
    snapshot_id: str
    sequence: int
    issued_at: datetime
    expires_at: datetime
    pack_name: str
    pack_version: str
    platform_api: str
    pack_digest_sha256: str
    pack_key_fingerprint_sha256: str
    predecessor_digest_sha256: str | None
    download_url: str
    artifact_count: int
    dependency_count: int
    installation_state: Literal["not_installed", "installed", "uninstalled"]
    revoked: bool
    pack_signer_trusted: bool
    platform_compatible: bool


class RemoteCatalogEntryListRead(RemoteCatalogModel):
    items: list[RemoteCatalogEntryRead]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)


class RemoteCatalogSnapshotRead(RemoteCatalogModel):
    id: str
    source_id: str
    sequence: int
    issued_at: datetime
    expires_at: datetime
    index_digest_sha256: str
    key_fingerprint_sha256: str
    signature_sha256: str
    entry_count: int
    refresh_reason: str
    refreshed_by: str
    refreshed_at: datetime
    entries: list[RemoteCatalogEntryRead]
