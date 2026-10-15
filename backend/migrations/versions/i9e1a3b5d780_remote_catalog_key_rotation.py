"""remote catalog key rotation ledger

Revision ID: i9e1a3b5d780
Revises: h8d0f2a4c679
Create Date: 2026-09-30 01:10:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "i9e1a3b5d780"
down_revision: str | None = "h8d0f2a4c679"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remote_capability_catalog_key_rotations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
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
        sa.Column("catalog_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "index_digest_sha256",
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
            "catalog_sequence >= 0",
            name="ck_remote_catalog_key_rotation_sequence_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["from_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["remote_capability_catalog_sources.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["to_trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_id",
            "statement_digest_sha256",
            name="uq_remote_catalog_key_rotation_statement",
        ),
    )
    op.create_index(
        "ix_remote_capability_catalog_key_rotations_from_trust_key_id",
        "remote_capability_catalog_key_rotations",
        ["from_trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_key_rotations_source_id",
        "remote_capability_catalog_key_rotations",
        ["source_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_remote_capability_catalog_key_rotations_statement_digest_sha256"),
        "remote_capability_catalog_key_rotations",
        ["statement_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_key_rotations_to_trust_key_id",
        "remote_capability_catalog_key_rotations",
        ["to_trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_catalog_key_rotation_source_time",
        "remote_capability_catalog_key_rotations",
        ["source_id", "rotated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("remote_capability_catalog_key_rotations")
