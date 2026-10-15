"""organization trust distribution

Revision ID: l2b4d6f8a013
Revises: k1a3c5d7f902
Create Date: 2026-09-30 04:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "l2b4d6f8a013"
down_revision: str | None = "k1a3c5d7f902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_ALL_PURPOSES = (
    '["artifact_bundle","capability_pack","capability_revocation",'
    '"remote_catalog","trust_bundle"]'
)


def upgrade() -> None:
    op.add_column(
        "artifact_trust_keys",
        sa.Column(
            "purposes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text(f"'{_ALL_PURPOSES}'"),
        ),
    )
    op.add_column(
        "artifact_trust_keys",
        sa.Column(
            "trust_source",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'local'"),
        ),
    )
    op.add_column(
        "artifact_trust_keys",
        sa.Column("trust_domain_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "artifact_trust_keys",
        sa.Column("managed_bundle_sequence", sa.Integer(), nullable=True),
    )
    op.add_column(
        "artifact_trust_keys",
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "artifact_trust_keys",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_artifact_trust_keys_trust_source",
        "artifact_trust_keys",
        ["trust_source"],
        unique=False,
    )
    op.create_index(
        "ix_artifact_trust_keys_trust_domain_id",
        "artifact_trust_keys",
        ["trust_domain_id"],
        unique=False,
    )

    op.create_table(
        "organization_trust_domains",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("organization_id", sa.String(length=255), nullable=False),
        sa.Column(
            "authority_trust_key_id",
            sa.String(length=36),
            nullable=False,
        ),
        sa.Column(
            "authority_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("allowed_purposes", sa.JSON(), nullable=False),
        sa.Column("max_bundle_lifetime_days", sa.Integer(), nullable=False),
        sa.Column("max_key_lifetime_days", sa.Integer(), nullable=False),
        sa.Column("latest_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "latest_bundle_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "latest_sequence >= 0",
            name="ck_organization_trust_domain_sequence_nonnegative",
        ),
        sa.CheckConstraint(
            "max_bundle_lifetime_days BETWEEN 1 AND 366",
            name="ck_organization_trust_bundle_lifetime",
        ),
        sa.CheckConstraint(
            "max_key_lifetime_days BETWEEN 1 AND 3650",
            name="ck_organization_trust_key_lifetime",
        ),
        sa.ForeignKeyConstraint(
            ["authority_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "name",
            name="uq_organization_trust_domain_name",
        ),
        sa.UniqueConstraint(
            "organization_id",
            name="uq_organization_trust_domain_organization",
        ),
    )
    op.create_index(
        "ix_organization_trust_domains_organization_id",
        "organization_trust_domains",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_domains_authority_trust_key_id",
        "organization_trust_domains",
        ["authority_trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_domains_authority_key_fingerprint_sha256",
        "organization_trust_domains",
        ["authority_key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_domains_enabled",
        "organization_trust_domains",
        ["enabled"],
        unique=False,
    )

    op.create_table(
        "organization_trust_bundle_imports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("trust_domain_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "bundle_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "authority_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_count", sa.Integer(), nullable=False),
        sa.Column("active_key_count", sa.Integer(), nullable=False),
        sa.Column("revoked_key_count", sa.Integer(), nullable=False),
        sa.Column("signed_bundle_snapshot", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("imported_by", sa.String(length=255), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_organization_trust_bundle_sequence_positive",
        ),
        sa.CheckConstraint(
            "key_count > 0",
            name="ck_organization_trust_bundle_key_count_positive",
        ),
        sa.ForeignKeyConstraint(
            ["trust_domain_id"],
            ["organization_trust_domains.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "trust_domain_id",
            "bundle_digest_sha256",
            name="uq_organization_trust_bundle_digest",
        ),
        sa.UniqueConstraint(
            "trust_domain_id",
            "sequence",
            name="uq_organization_trust_bundle_sequence",
        ),
    )
    op.create_index(
        "ix_organization_trust_bundle_imports_trust_domain_id",
        "organization_trust_bundle_imports",
        ["trust_domain_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_bundle_imports_bundle_digest_sha256",
        "organization_trust_bundle_imports",
        ["bundle_digest_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_organization_trust_bundle_imports_authority_key_fingerprint_sha256"),
        "organization_trust_bundle_imports",
        ["authority_key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_bundle_imported",
        "organization_trust_bundle_imports",
        ["trust_domain_id", "imported_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("organization_trust_bundle_imports")
    op.drop_table("organization_trust_domains")
    op.drop_index(
        "ix_artifact_trust_keys_trust_domain_id",
        table_name="artifact_trust_keys",
    )
    op.drop_index(
        "ix_artifact_trust_keys_trust_source",
        table_name="artifact_trust_keys",
    )
    op.drop_column("artifact_trust_keys", "expires_at")
    op.drop_column("artifact_trust_keys", "valid_from")
    op.drop_column("artifact_trust_keys", "managed_bundle_sequence")
    op.drop_column("artifact_trust_keys", "trust_domain_id")
    op.drop_column("artifact_trust_keys", "trust_source")
    op.drop_column("artifact_trust_keys", "purposes")
