"""governed cross-environment capability promotions

Revision ID: o5e7a9b1d346
Revises: n4d6f8a0c235
Create Date: 2026-09-30 11:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "o5e7a9b1d346"
down_revision: str | None = "n4d6f8a0c235"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capability_promotion_policy",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column(
            "local_environment_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("local_stage", sa.String(length=32), nullable=False),
        sa.Column(
            "required_source_stage",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "max_attestation_age_hours",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_attestation_age_hours BETWEEN 1 AND 168",
            name="ck_capability_promotion_attestation_age",
        ),
        sa.CheckConstraint(
            "local_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_local_stage",
        ),
        sa.CheckConstraint(
            "required_source_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_required_source_stage",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "local_environment_id",
            name="uq_capability_promotion_local_environment",
        ),
    )

    op.create_table(
        "capability_promotion_sources",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "organization_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "environment_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("source_stage", sa.String(length=32), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("latest_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "latest_statement_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "latest_sequence >= 0",
            name="ck_capability_promotion_source_sequence_nonnegative",
        ),
        sa.CheckConstraint(
            "source_stage IN "
            "('development', 'test', 'staging', 'production')",
            name="ck_capability_promotion_source_stage",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "environment_id",
            name="uq_capability_promotion_source_environment",
        ),
        sa.UniqueConstraint(
            "name",
            name="uq_capability_promotion_source_name",
        ),
    )
    for name, columns in (
        ("ix_capability_promotion_sources_enabled", ["enabled"]),
        (
            "ix_capability_promotion_sources_environment_id",
            ["environment_id"],
        ),
        (
            "ix_capability_promotion_sources_key_fingerprint_sha256",
            ["key_fingerprint_sha256"],
        ),
        (
            "ix_capability_promotion_sources_organization_id",
            ["organization_id"],
        ),
        (
            "ix_capability_promotion_sources_source_stage",
            ["source_stage"],
        ),
        (
            "ix_capability_promotion_sources_trust_key_id",
            ["trust_key_id"],
        ),
    ):
        op.create_index(
            name,
            "capability_promotion_sources",
            columns,
            unique=False,
        )

    op.create_table(
        "capability_promotion_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column(
            "organization_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "source_environment_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("source_stage", sa.String(length=32), nullable=False),
        sa.Column(
            "target_environment_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("target_stage", sa.String(length=32), nullable=False),
        sa.Column("promotion_sequence", sa.Integer(), nullable=False),
        sa.Column("pack_name", sa.String(length=255), nullable=False),
        sa.Column("pack_version", sa.String(length=64), nullable=False),
        sa.Column(
            "pack_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "pack_signer_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("artifact_count", sa.Integer(), nullable=False),
        sa.Column(
            "artifact_set_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "source_transparency_log_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "source_transparency_epoch",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "source_transparency_sequence",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "source_transparency_head_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "validation_evidence_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signed_attestation_snapshot", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("accepted_by", sa.String(length=255), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "artifact_count > 0",
            name="ck_capability_promotion_artifact_count_positive",
        ),
        sa.CheckConstraint(
            "promotion_sequence > 0",
            name="ck_capability_promotion_sequence_positive",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["capability_pack_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["capability_promotion_sources.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_id",
            "promotion_sequence",
            name="uq_capability_promotion_source_sequence",
        ),
        sa.UniqueConstraint(
            "statement_digest_sha256",
            name="uq_capability_promotion_statement_digest",
        ),
        sa.UniqueConstraint(
            "target_environment_id",
            "pack_digest_sha256",
            name="uq_capability_promotion_target_pack",
        ),
    )
    for name, columns in (
        ("ix_capability_promotion_accepted_at", ["accepted_at"]),
        (
            "ix_capability_promotion_receipts_installation_id",
            ["installation_id"],
        ),
        (
            "ix_capability_promotion_receipts_key_fingerprint_sha256",
            ["key_fingerprint_sha256"],
        ),
        (
            "ix_capability_promotion_receipts_organization_id",
            ["organization_id"],
        ),
        (
            "ix_capability_promotion_receipts_pack_digest_sha256",
            ["pack_digest_sha256"],
        ),
        ("ix_capability_promotion_receipts_pack_name", ["pack_name"]),
        (
            "ix_capability_promotion_receipts_source_environment_id",
            ["source_environment_id"],
        ),
        ("ix_capability_promotion_receipts_source_id", ["source_id"]),
        (
            "ix_capability_promotion_receipts_statement_digest_sha256",
            ["statement_digest_sha256"],
        ),
        (
            "ix_capability_promotion_receipts_target_environment_id",
            ["target_environment_id"],
        ),
        (
            "ix_capability_promotion_receipts_trust_key_id",
            ["trust_key_id"],
        ),
    ):
        op.create_index(
            name,
            "capability_promotion_receipts",
            columns,
            unique=False,
        )


def downgrade() -> None:
    op.drop_table("capability_promotion_receipts")
    op.drop_table("capability_promotion_sources")
    op.drop_table("capability_promotion_policy")
