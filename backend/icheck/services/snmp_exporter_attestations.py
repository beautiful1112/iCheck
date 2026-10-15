from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..collector_schemas import (
    ArtifactVersionCreate,
    CollectorDefinitionInput,
)
from ..models import (
    ArtifactKind,
    ArtifactVersion,
    ArtifactVersionStatus,
    SNMPExporterAttestation,
    new_id,
    utcnow,
)
from ..snmp_attestation_schemas import (
    SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
    SNMPExporterAttestationCreate,
    SNMPExporterAttestationStatement,
    SNMPExporterAttestorInput,
)
from ..studio_schemas import GeneratedSNMPExporterProposalSpec
from .artifact_portability import (
    ensure_trust_key_usable,
    verify_trusted_digest_signature,
)
from .audit import record_audit_event
from .collectors import create_artifact_version, validate_artifact_version
from .snmp_exporter_proposals import validate_snmp_exporter_proposal_contract


ATTESTED_SCHEMA = "icheck.snmp-exporter-attested/v1"
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_TEST_AGE = timedelta(hours=24)
MAX_ATTESTATION_LIFETIME = timedelta(days=7)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def attestation_statement_digest(
    statement: SNMPExporterAttestationStatement,
) -> str:
    return canonical_hash(statement.model_dump(mode="json"))


def _proposal_version(db: Session, version_id: str) -> ArtifactVersion:
    version = db.scalar(
        select(ArtifactVersion)
        .where(ArtifactVersion.id == version_id)
        .options(
            selectinload(ArtifactVersion.artifact),
            selectinload(ArtifactVersion.collector_definition),
        )
    )
    if version is None:
        raise LookupError("SNMP Exporter proposal version not found")
    return version


def build_snmp_exporter_attestor_input(
    db: Session,
    proposal_version_id: str,
) -> SNMPExporterAttestorInput:
    proposal = _proposal_version(db, proposal_version_id)
    if proposal.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("SNMP attestor input requires a validated proposal")
    if proposal.collector_definition is None:
        raise ValueError("SNMP exporter proposal collector definition is missing")
    report = validate_snmp_exporter_proposal_contract(
        proposal.definition,
        proposal.implementation,
        proposal.tests,
        proposal.collector_definition,
    )
    if not proposal.content_hash:
        raise ValueError("SNMP exporter proposal content hash is missing")
    spec = GeneratedSNMPExporterProposalSpec.model_validate(
        proposal.definition.get("spec")
    )
    return SNMPExporterAttestorInput(
        proposal_artifact_id=proposal.artifact_id,
        proposal_version_id=proposal.id,
        proposal_version=proposal.version,
        proposal_content_hash=proposal.content_hash,
        mib_document_sha256=report["mib_document_sha256"],
        generator_module_sha256=report["generator_module_sha256"],
        exporter_module_name=spec.exporter_module_name,
        generator_module=proposal.definition["generator_module"],
    )


def _validate_times(statement: SNMPExporterAttestationStatement) -> None:
    now = utcnow()
    tested_at = _as_utc(statement.tested_at)
    issued_at = _as_utc(statement.issued_at)
    expires_at = _as_utc(statement.expires_at)
    if tested_at > now + MAX_CLOCK_SKEW or issued_at > now + MAX_CLOCK_SKEW:
        raise ValueError("SNMP attestation timestamp is in the future")
    if issued_at - tested_at > MAX_TEST_AGE:
        raise ValueError("SNMP live-device evidence is older than 24 hours at issue time")
    if expires_at - issued_at > MAX_ATTESTATION_LIFETIME:
        raise ValueError("SNMP attestation lifetime exceeds seven days")
    if expires_at <= now:
        raise ValueError("SNMP attestation has expired")


def _validate_proposal_binding(
    proposal: ArtifactVersion,
    statement: SNMPExporterAttestationStatement,
) -> GeneratedSNMPExporterProposalSpec:
    if proposal.artifact.kind != ArtifactKind.COLLECTOR:
        raise ValueError("SNMP attestation source must be a Collector Artifact")
    if proposal.status != ArtifactVersionStatus.VALIDATED:
        raise ValueError("SNMP attestation source must be a validated proposal")
    if proposal.definition.get("schema") != "icheck.snmp-exporter-proposal/v1":
        raise ValueError("SNMP attestation source is not an exporter proposal")
    if not proposal.content_hash:
        raise ValueError("SNMP exporter proposal content hash is missing")
    expected = {
        "proposal_artifact_id": proposal.artifact_id,
        "proposal_version_id": proposal.id,
        "proposal_version": proposal.version,
        "proposal_content_hash": proposal.content_hash,
        "mib_document_sha256": proposal.validation_report.get(
            "mib_document_sha256"
        ),
        "generator_module_sha256": proposal.validation_report.get(
            "generator_module_sha256"
        ),
    }
    actual = {
        key: getattr(statement, key)
        for key in expected
    }
    if actual != expected:
        raise ValueError("SNMP attestation does not bind the exact proposal evidence")
    spec = GeneratedSNMPExporterProposalSpec.model_validate(
        proposal.definition.get("spec")
    )
    if statement.exporter_module_name != spec.exporter_module_name:
        raise ValueError("SNMP attestation exporter module name drifted")
    return spec


def _attested_definition(
    statement: SNMPExporterAttestationStatement,
    *,
    attestation_id: str,
    digest_sha256: str,
    key_fingerprint_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": ATTESTED_SCHEMA,
        "source_proposal": {
            "artifact_id": statement.proposal_artifact_id,
            "artifact_version_id": statement.proposal_version_id,
            "version": statement.proposal_version,
            "content_hash": statement.proposal_content_hash,
            "mib_document_sha256": statement.mib_document_sha256,
            "generator_module_sha256": statement.generator_module_sha256,
        },
        "attestation": {
            "id": attestation_id,
            "digest_sha256": digest_sha256,
            "key_fingerprint_sha256": key_fingerprint_sha256,
            "generator_name": statement.generator_name,
            "generator_version": statement.generator_version,
            "generator_binary_sha256": statement.generator_binary_sha256,
            "generated_config_sha256": statement.generated_config_sha256,
            "installed_config_sha256": statement.installed_config_sha256,
            "exporter_version": statement.exporter_version,
            "exporter_binary_sha256": statement.exporter_binary_sha256,
            "installation_id": statement.installation_id,
            "target_sha256": statement.target_sha256,
            "auth_module_sha256": statement.auth_module_sha256,
            "successful_scrapes": statement.successful_scrapes,
            "sample_count": statement.sample_count,
            "series_count": statement.series_count,
            "label_name_count": statement.label_name_count,
            "maximum_scrape_duration_ms": statement.maximum_scrape_duration_ms,
            "timed_out_scrapes": statement.timed_out_scrapes,
            "evidence_sha256": statement.evidence_sha256,
            "tested_at": statement.tested_at.isoformat(),
            "issued_at": statement.issued_at.isoformat(),
            "expires_at": statement.expires_at.isoformat(),
            "nonce": statement.nonce,
        },
        "publication_gate": {
            "required": "collector_canary_v1",
            "satisfied": False,
        },
    }


def _attested_test(
    statement: SNMPExporterAttestationStatement,
    digest_sha256: str,
) -> dict[str, Any]:
    return {
        "name": "Signed external generator and live-device attestation",
        "attestation_digest_sha256": digest_sha256,
        "evidence_sha256": statement.evidence_sha256,
        "successful_scrapes": statement.successful_scrapes,
        "sample_count": statement.sample_count,
        "series_count": statement.series_count,
    }


def accept_snmp_exporter_attestation(
    db: Session,
    payload: SNMPExporterAttestationCreate,
    *,
    actor: str,
) -> SNMPExporterAttestation:
    signed = payload.signed_attestation
    statement = signed.statement
    digest_sha256 = attestation_statement_digest(statement)
    if signed.digest_sha256 != digest_sha256:
        raise ValueError("SNMP attestation digest does not match its statement")
    _validate_times(statement)
    proposal = _proposal_version(db, statement.proposal_version_id)
    _validate_proposal_binding(proposal, statement)
    trusted = verify_trusted_digest_signature(
        db,
        signed.signature,
        expected_digest_sha256=digest_sha256,
        signed_format_version=SIGNED_SNMP_EXPORTER_ATTESTATION_FORMAT,
        expected_purpose="snmp_exporter_attestation",
    )
    source_definition = proposal.collector_definition
    if source_definition is None:
        raise ValueError("SNMP exporter proposal collector definition is missing")
    attestation_id = new_id()
    definition = _attested_definition(
        statement,
        attestation_id=attestation_id,
        digest_sha256=digest_sha256,
        key_fingerprint_sha256=trusted["key_fingerprint_sha256"],
    )
    collector_definition = CollectorDefinitionInput.model_validate(
        {
            "adapter_type": source_definition.adapter_type,
            "mode": source_definition.mode,
            "output_kinds": source_definition.output_kinds,
            "credential_profile_ref": source_definition.credential_profile_ref,
            "config_schema": source_definition.config_schema,
            "target_schema": source_definition.target_schema,
            "defaults": source_definition.defaults,
        }
    )
    artifact = create_artifact_version(
        db,
        proposal.artifact,
        ArtifactVersionCreate(
            definition=definition,
            implementation={"runtime": "builtin", "adapter": "snmp_exporter"},
            tests=[_attested_test(statement, digest_sha256)],
            created_by=actor,
            collector_definition=collector_definition,
        ),
        commit=False,
    )
    deployable = max(artifact.versions, key=lambda item: item.version)
    row = SNMPExporterAttestation(
        id=attestation_id,
        proposal_version_id=proposal.id,
        deployable_version_id=deployable.id,
        trust_key_id=trusted["trust_key_id"],
        key_fingerprint_sha256=trusted["key_fingerprint_sha256"],
        digest_sha256=digest_sha256,
        signature_sha256=trusted["signature_sha256"],
        nonce=statement.nonce,
        statement=statement.model_dump(mode="json"),
        verified_by=actor,
        expires_at=statement.expires_at,
    )
    db.add(row)
    try:
        db.flush()
        validate_artifact_version(
            db,
            deployable,
            actor,
            commit=False,
        )
        record_audit_event(
            db,
            event_type="snmp_exporter.attestation.accepted",
            actor_type="user",
            actor_id=actor,
            entity_type="snmp_exporter_attestation",
            entity_id=row.id,
            details={
                "proposal_version_id": proposal.id,
                "deployable_version_id": deployable.id,
                "digest_sha256": digest_sha256,
                "key_fingerprint_sha256": row.key_fingerprint_sha256,
                "evidence_sha256": statement.evidence_sha256,
                "successful_scrapes": statement.successful_scrapes,
                "sample_count": statement.sample_count,
                "series_count": statement.series_count,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("SNMP attestation digest or nonce has already been used") from exc
    except Exception:
        db.rollback()
        raise
    db.refresh(row)
    return row


def validate_snmp_exporter_attested_contract(
    db: Session,
    version: ArtifactVersion,
) -> dict[str, Any]:
    if version.definition.get("schema") != ATTESTED_SCHEMA:
        raise ValueError("Unsupported attested SNMP Exporter schema")
    if version.implementation != {"runtime": "builtin", "adapter": "snmp_exporter"}:
        raise ValueError("Attested SNMP Exporter versions require the builtin adapter")
    row = db.scalar(
        select(SNMPExporterAttestation).where(
            SNMPExporterAttestation.deployable_version_id == version.id
        )
    )
    if row is None:
        raise ValueError("Attested SNMP Exporter version has no local attestation ledger row")
    statement = SNMPExporterAttestationStatement.model_validate(row.statement)
    expected_definition = _attested_definition(
        statement,
        attestation_id=row.id,
        digest_sha256=row.digest_sha256,
        key_fingerprint_sha256=row.key_fingerprint_sha256,
    )
    if version.definition != expected_definition:
        raise ValueError("Attested SNMP Exporter definition drifted from signed evidence")
    if version.tests != [_attested_test(statement, row.digest_sha256)]:
        raise ValueError("Attested SNMP Exporter tests drifted from signed evidence")
    proposal = _proposal_version(db, row.proposal_version_id)
    spec = _validate_proposal_binding(proposal, statement)
    collector = version.collector_definition
    if collector is None or collector.adapter_type != "snmp_exporter":
        raise ValueError("Attested SNMP Exporter collector definition is invalid")
    if collector.defaults.get("modules") != [spec.exporter_module_name]:
        raise ValueError("Attested SNMP Exporter module default drifted")
    module_schema = (
        collector.config_schema.get("properties", {}).get("modules", {})
    )
    if module_schema != {"const": [spec.exporter_module_name]}:
        raise ValueError("Attested SNMP Exporter module must remain schema-pinned")
    return {
        "runtime": "builtin",
        "isolation": "signed_external_generator_attestation",
        "tests_declared": 1,
        "attestation_contract": ATTESTED_SCHEMA,
        "attestation_id": row.id,
        "attestation_digest_sha256": row.digest_sha256,
        "key_fingerprint_sha256": row.key_fingerprint_sha256,
        "evidence_sha256": statement.evidence_sha256,
        "successful_scrapes": statement.successful_scrapes,
        "sample_count": statement.sample_count,
        "series_count": statement.series_count,
        "canary_required": True,
        "publication_blocked": True,
        "publication_blocker": "collector_canary_required",
    }


def assert_snmp_exporter_attested_publication_ready(
    db: Session,
    version: ArtifactVersion,
    *,
    canary_promotion: bool,
) -> None:
    if version.definition.get("schema") != ATTESTED_SCHEMA:
        return
    if not canary_promotion:
        raise ValueError(
            "Attested SNMP Exporter versions must pass a live collector canary "
            "and be published through canary promotion"
        )
    row = db.scalar(
        select(SNMPExporterAttestation).where(
            SNMPExporterAttestation.deployable_version_id == version.id
        )
    )
    if row is None:
        raise ValueError("SNMP Exporter attestation ledger row is missing")
    if _as_utc(row.expires_at) <= utcnow():
        raise ValueError("SNMP Exporter attestation expired before canary promotion")
    from ..models import ArtifactTrustKey

    key = db.get(ArtifactTrustKey, row.trust_key_id)
    if key is None:
        raise ValueError("SNMP Exporter attestation trust key is missing")
    ensure_trust_key_usable(
        db,
        key,
        expected_purpose="snmp_exporter_attestation",
    )
