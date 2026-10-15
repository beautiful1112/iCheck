"""add signed SNMP exporter attestation ledger

Revision ID: d0b2c4e6f8a1
Revises: c9a1b3d5e790
Create Date: 2026-09-30 02:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "d0b2c4e6f8a1"
down_revision: str | None = "c9a1b3d5e790"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLE = "snmp_exporter_attestations"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("proposal_version_id", sa.String(length=36), nullable=False),
        sa.Column("deployable_version_id", sa.String(length=36), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("key_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("statement", sa.JSON(), nullable=False),
        sa.Column("verified_by", sa.String(length=255), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["proposal_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["deployable_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "deployable_version_id",
            name="uq_snmp_attestation_namespace_deployable",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "digest_sha256",
            name="uq_snmp_attestation_namespace_digest",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "nonce",
            name="uq_snmp_attestation_namespace_nonce",
        ),
    )
    op.create_index(f"ix_{TABLE}_tenant_id", TABLE, ["tenant_id"])
    op.create_index(f"ix_{TABLE}_region_id", TABLE, ["region_id"])
    op.create_index(
        f"ix_{TABLE}_proposal_version_id",
        TABLE,
        ["proposal_version_id"],
    )
    op.create_index(
        f"ix_{TABLE}_deployable_version_id",
        TABLE,
        ["deployable_version_id"],
    )
    op.create_index(f"ix_{TABLE}_trust_key_id", TABLE, ["trust_key_id"])
    op.create_index(f"ix_{TABLE}_expires_at", TABLE, ["expires_at"])
    op.create_index(
        "ix_snmp_exporter_attestation_proposal",
        TABLE,
        ["proposal_version_id", "verified_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_snmp_exporter_attestation_proposal", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_expires_at", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_trust_key_id", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_deployable_version_id", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_proposal_version_id", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_region_id", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_tenant_id", table_name=TABLE)
    op.drop_table(TABLE)
