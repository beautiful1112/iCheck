"""organization trust root rotation

Revision ID: m3c5e7a9b124
Revises: l2b4d6f8a013
Create Date: 2026-09-30 06:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "m3c5e7a9b124"
down_revision: str | None = "l2b4d6f8a013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_trust_root_rotations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("trust_domain_id", sa.String(length=36), nullable=False),
        sa.Column("from_trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("to_trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "from_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "to_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("bundle_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "bundle_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "statement_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "current_signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "next_signature_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("rotated_by", sa.String(length=255), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "bundle_sequence >= 0",
            name="ck_organization_trust_root_rotation_sequence_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["from_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["to_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["trust_domain_id"],
            ["organization_trust_domains.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "trust_domain_id",
            "statement_digest_sha256",
            name="uq_organization_trust_root_rotation_statement",
        ),
    )
    op.create_index(
        "ix_organization_trust_root_rotations_trust_domain_id",
        "organization_trust_root_rotations",
        ["trust_domain_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_root_rotations_from_trust_key_id",
        "organization_trust_root_rotations",
        ["from_trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_root_rotations_to_trust_key_id",
        "organization_trust_root_rotations",
        ["to_trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_root_rotations_statement_digest_sha256",
        "organization_trust_root_rotations",
        ["statement_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_organization_trust_root_rotation_time",
        "organization_trust_root_rotations",
        ["trust_domain_id", "rotated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("organization_trust_root_rotations")
