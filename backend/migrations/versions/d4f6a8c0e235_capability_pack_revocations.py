"""capability pack revocation feeds

Revision ID: d4f6a8c0e235
Revises: c3e5a7b9d124
Create Date: 2026-09-29 22:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "d4f6a8c0e235"
down_revision: str | None = "c3e5a7b9d124"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capability_pack_revocation_feeds",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("feed_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("quarantine_summary", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ingested_by", sa.String(length=255), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "entry_count > 0",
            name="ck_capability_pack_revocation_entries_positive",
        ),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_capability_pack_revocation_sequence_positive",
        ),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "trust_key_id",
            "sequence",
            name="uq_capability_pack_revocation_key_sequence",
        ),
    )
    op.create_index(
        "ix_capability_pack_revocation_feeds_trust_key_id",
        "capability_pack_revocation_feeds",
        ["trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocation_feeds_issued_at",
        "capability_pack_revocation_feeds",
        ["issued_at"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocation_feeds_feed_digest_sha256",
        "capability_pack_revocation_feeds",
        ["feed_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocation_feeds_key_fingerprint_sha256",
        "capability_pack_revocation_feeds",
        ["key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocation_feed_ingested_at",
        "capability_pack_revocation_feeds",
        ["ingested_at"],
        unique=False,
    )

    op.create_table(
        "capability_pack_revocations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("feed_id", sa.String(length=36), nullable=False),
        sa.Column("pack_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["feed_id"],
            ["capability_pack_revocation_feeds.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "feed_id",
            "pack_digest_sha256",
            name="uq_capability_pack_revocation_feed_pack",
        ),
    )
    op.create_index(
        "ix_capability_pack_revocations_feed_id",
        "capability_pack_revocations",
        ["feed_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocations_pack_digest_sha256",
        "capability_pack_revocations",
        ["pack_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocations_reason_code",
        "capability_pack_revocations",
        ["reason_code"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocations_effective_at",
        "capability_pack_revocations",
        ["effective_at"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_revocation_pack_effective",
        "capability_pack_revocations",
        ["pack_digest_sha256", "effective_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_capability_pack_revocation_pack_effective",
        table_name="capability_pack_revocations",
    )
    op.drop_index(
        "ix_capability_pack_revocations_effective_at",
        table_name="capability_pack_revocations",
    )
    op.drop_index(
        "ix_capability_pack_revocations_reason_code",
        table_name="capability_pack_revocations",
    )
    op.drop_index(
        "ix_capability_pack_revocations_pack_digest_sha256",
        table_name="capability_pack_revocations",
    )
    op.drop_index(
        "ix_capability_pack_revocations_feed_id",
        table_name="capability_pack_revocations",
    )
    op.drop_table("capability_pack_revocations")
    op.drop_index(
        "ix_capability_pack_revocation_feed_ingested_at",
        table_name="capability_pack_revocation_feeds",
    )
    op.drop_index(
        "ix_capability_pack_revocation_feeds_key_fingerprint_sha256",
        table_name="capability_pack_revocation_feeds",
    )
    op.drop_index(
        "ix_capability_pack_revocation_feeds_feed_digest_sha256",
        table_name="capability_pack_revocation_feeds",
    )
    op.drop_index(
        "ix_capability_pack_revocation_feeds_issued_at",
        table_name="capability_pack_revocation_feeds",
    )
    op.drop_index(
        "ix_capability_pack_revocation_feeds_trust_key_id",
        table_name="capability_pack_revocation_feeds",
    )
    op.drop_table("capability_pack_revocation_feeds")
