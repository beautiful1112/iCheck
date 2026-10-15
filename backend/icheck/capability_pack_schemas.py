from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature, ArtifactExportBundle
from .models import ArtifactKind
from .schemas import APIModel


PACK_FORMAT = "icheck.capability-pack/v1"
SIGNED_PACK_FORMAT = "icheck.capability-pack.signed/v1"
PACK_SIGNER_ROTATION_FORMAT = "icheck.capability-pack-signer-rotation/v1"
SIGNED_PACK_SIGNER_ROTATION_FORMAT = (
    "icheck.capability-pack-signer-rotation.signed/v1"
)
PLATFORM_API = "icheck/0.1"


class CapabilityPackModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CapabilityPackDependency(CapabilityPackModel):
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    kind: ArtifactKind
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class CapabilityPackSignerRotationStatement(CapabilityPackModel):
    format_version: Literal[
        "icheck.capability-pack-signer-rotation/v1"
    ] = PACK_SIGNER_ROTATION_FORMAT
    pack_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    predecessor_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    next_key_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_rotation(self) -> "CapabilityPackSignerRotationStatement":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Pack signer rotation timestamps require offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("Pack signer rotation expiry must follow issue time")
        if self.current_key_fingerprint_sha256 == (
            self.next_key_fingerprint_sha256
        ):
            raise ValueError("Pack signer rotation requires a different key")
        return self


class SignedCapabilityPackSignerRotation(CapabilityPackModel):
    format_version: Literal[
        "icheck.capability-pack-signer-rotation.signed/v1"
    ] = SIGNED_PACK_SIGNER_ROTATION_FORMAT
    statement: CapabilityPackSignerRotationStatement
    current_signature: ArtifactBundleSignature
    next_signature: ArtifactBundleSignature


class CapabilityPack(CapabilityPackModel):
    format_version: Literal["icheck.capability-pack/v1"] = PACK_FORMAT
    name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    version: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    platform_api: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9/_.-]*$",
    )
    predecessor_digest_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    signer_rotation: SignedCapabilityPackSignerRotation | None = None
    artifacts: list[ArtifactExportBundle] = Field(min_length=1, max_length=20)
    dependencies: list[CapabilityPackDependency] = Field(
        default_factory=list,
        max_length=200,
    )
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_unique_entries(self) -> CapabilityPack:
        if self.predecessor_digest_sha256 == self.digest_sha256:
            raise ValueError("Capability pack cannot name itself as predecessor")
        if self.signer_rotation is not None:
            statement = self.signer_rotation.statement
            if statement.pack_name != self.name:
                raise ValueError("Pack signer rotation name does not match pack")
            if statement.predecessor_digest_sha256 != (
                self.predecessor_digest_sha256
            ):
                raise ValueError(
                    "Pack signer rotation predecessor does not match pack"
                )
        artifact_keys = [
            (item.artifact.kind, item.artifact.name)
            for item in self.artifacts
        ]
        if len(set(artifact_keys)) != len(artifact_keys):
            raise ValueError("Capability pack artifact names must be unique per kind")
        dependency_keys = [(item.kind, item.name) for item in self.dependencies]
        if len(set(dependency_keys)) != len(dependency_keys):
            raise ValueError("Capability pack dependencies must be unique per kind")
        return self


class SignedCapabilityPack(CapabilityPackModel):
    format_version: Literal[
        "icheck.capability-pack.signed/v1"
    ] = SIGNED_PACK_FORMAT
    pack: CapabilityPack
    signature: ArtifactBundleSignature


class CapabilityPackPreviewCreate(CapabilityPackModel):
    signed_pack: SignedCapabilityPack


class CapabilityPackInstallCreate(CapabilityPackPreviewCreate):
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPackUninstallCreate(CapabilityPackModel):
    expected_pack_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class CapabilityPackUninstallPreviewRead(CapabilityPackModel):
    installation_id: str
    pack_name: str
    pack_version: str
    pack_digest_sha256: str
    lifecycle_status: Literal["installed", "uninstalled"]
    uninstallable: bool
    already_uninstalled: bool
    blockers: list[str] = Field(default_factory=list)
    active_successor_installation_id: str | None = None
    dependent_pack_installation_ids: list[str] = Field(default_factory=list)
    introduced_artifact_version_ids: list[str] = Field(default_factory=list)
    impact_summary: dict[str, int] = Field(default_factory=dict)


class CapabilityPackArtifactPlan(CapabilityPackModel):
    name: str
    kind: ArtifactKind
    content_hash: str
    bundle_digest_sha256: str
    state: Literal[
        "install",
        "upgrade",
        "retain",
        "already_present",
        "name_conflict",
        "unavailable",
    ]
    existing_artifact_id: str | None = None
    existing_artifact_version_id: str | None = None


class CapabilityPackDependencyPlan(CapabilityPackModel):
    name: str
    kind: ArtifactKind
    content_hash: str
    state: Literal[
        "pack",
        "published",
        "not_published",
        "hash_mismatch",
        "missing",
    ]
    artifact_version_id: str | None = None


class CapabilityPackPreviewRead(CapabilityPackModel):
    pack_name: str
    pack_version: str
    platform_api: str
    pack_digest_sha256: str
    key_fingerprint_sha256: str
    operation: Literal["install", "upgrade"]
    predecessor_installation_id: str | None = None
    predecessor_digest_sha256: str | None = None
    signer_rotation: bool = False
    artifact_count: int = Field(ge=1)
    dependency_count: int = Field(ge=0)
    installable: bool
    already_installed: bool
    blockers: list[str] = Field(default_factory=list)
    artifacts: list[CapabilityPackArtifactPlan]
    dependencies: list[CapabilityPackDependencyPlan]


class CapabilityPackInstalledArtifactRead(CapabilityPackModel):
    id: str
    artifact_id: str
    artifact_version_id: str
    source_name: str
    source_kind: str
    source_content_hash: str
    source_bundle_digest_sha256: str
    install_action: Literal["installed", "upgraded", "retained", "reused"]
    created_at: datetime


class CapabilityPackInstallationRead(CapabilityPackModel):
    id: str
    pack_name: str
    pack_version: str
    platform_api: str
    pack_digest_sha256: str
    trust_key_id: str
    key_fingerprint_sha256: str
    signature_sha256: str
    operation: Literal["install", "upgrade"]
    lifecycle_status: Literal["installed", "uninstalled"]
    predecessor_installation_id: str | None
    dependency_snapshot: list[dict[str, str]]
    distribution_channel: Literal["upload", "remote_catalog"]
    distribution_snapshot: dict[str, str | int]
    signer_rotation_snapshot: dict[str, str]
    reason: str
    installed_by: str
    installed_at: datetime
    uninstall_reason: str | None
    uninstalled_by: str | None
    uninstalled_at: datetime | None
    uninstall_summary: dict[str, int]
    artifacts: list[CapabilityPackInstalledArtifactRead]
