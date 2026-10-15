from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .collector_schemas import ArtifactBundleSignature
from .schemas import APIModel


SNMP_EXPORTER_ATTESTATION_FORMAT = "icheck.snmp-exporter-attestation/v1"
SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT = (
    "icheck.snmp-exporter-attestation.signed/v1"
)


class SNMPAttestationModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class SNMPExporterAttestationStatement(SNMPAttestationModel):
    format_version: Literal[
        "icheck.snmp-exporter-attestation/v1"
    ] = SNMP_EXPORTER_ATTESTATION_FORMAT
    proposal_artifact_id: str = Field(min_length=1, max_length=36)
    proposal_version_id: str = Field(min_length=1, max_length=36)
    proposal_version: int = Field(ge=1)
    proposal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mib_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generator_module_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exporter_module_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    generator_name: Literal["prometheus/snmp_exporter/generator"]
    generator_version: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$",
    )
    generator_binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exporter_version: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$",
    )
    exporter_binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installation_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    auth_module_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    successful_scrapes: int = Field(ge=3, le=100)
    sample_count: int = Field(ge=1, le=10_000_000)
    series_count: int = Field(ge=1, le=1_000_000)
    label_name_count: int = Field(ge=0, le=10_000)
    maximum_scrape_duration_ms: int = Field(ge=1, le=120_000)
    timed_out_scrapes: Literal[0] = 0
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tested_at: datetime
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )

    @model_validator(mode="after")
    def validate_evidence(self) -> "SNMPExporterAttestationStatement":
        if (
            self.tested_at.tzinfo is None
            or self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
        ):
            raise ValueError("SNMP attestation timestamps require offsets")
        if self.tested_at > self.issued_at:
            raise ValueError("SNMP attestation test time must not follow issue time")
        if self.expires_at <= self.issued_at:
            raise ValueError("SNMP attestation expiry must follow issue time")
        if self.generated_config_sha256 != self.installed_config_sha256:
            raise ValueError(
                "Installed SNMP Exporter configuration must match generated output"
            )
        if self.series_count > self.sample_count:
            raise ValueError("SNMP attestation series count cannot exceed samples")
        return self


class SignedSNMPExporterAttestation(SNMPAttestationModel):
    format_version: Literal[
        "icheck.snmp-exporter-attestation.signed/v1"
    ] = SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT
    statement: SNMPExporterAttestationStatement
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: ArtifactBundleSignature


class SNMPExporterAttestationCreate(SNMPAttestationModel):
    signed_attestation: SignedSNMPExporterAttestation
    actor: str = Field(min_length=1, max_length=255)


class SNMPExporterAttestorInput(SNMPAttestationModel):
    proposal_artifact_id: str = Field(min_length=1, max_length=36)
    proposal_version_id: str = Field(min_length=1, max_length=36)
    proposal_version: int = Field(ge=1)
    proposal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mib_document_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generator_module_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exporter_module_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    generator_module: dict[str, object]


class SNMPExporterAttestationRead(SNMPAttestationModel):
    id: str
    proposal_version_id: str
    deployable_version_id: str
    trust_key_id: str
    key_fingerprint_sha256: str
    digest_sha256: str
    signature_sha256: str
    nonce: str
    statement: SNMPExporterAttestationStatement
    verified_by: str
    verified_at: datetime
    expires_at: datetime
