"""remote capability catalogs

Revision ID: g7c9e1f3b568
Revises: f6b8d0e2a457
Create Date: 2026-09-29 23:50:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "g7c9e1f3b568"
down_revision: str | None = "f6b8d0e2a457"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remote_capability_catalog_sources",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("catalog_id", sa.String(length=255), nullable=False),
        sa.Column("index_url", sa.String(length=2048), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("latest_sequence", sa.Integer(), nullable=True),
        sa.Column(
            "latest_index_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column(
            "last_refresh_status",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column("last_refresh_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "index_url",
            name="uq_remote_capability_catalog_index_url",
        ),
        sa.UniqueConstraint(
            "name",
            name="uq_remote_capability_catalog_name",
        ),
    )
    op.create_index(
        "ix_remote_capability_catalog_sources_catalog_id",
        "remote_capability_catalog_sources",
        ["catalog_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_sources_enabled",
        "remote_capability_catalog_sources",
        ["enabled"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_sources_trust_key_id",
        "remote_capability_catalog_sources",
        ["trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_status",
        "remote_capability_catalog_sources",
        ["enabled", "last_refresh_status"],
        unique=False,
    )
    op.create_table(
        "remote_capability_catalog_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "index_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("refresh_reason", sa.Text(), nullable=False),
        sa.Column("refreshed_by", sa.String(length=255), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "entry_count > 0",
            name="ck_remote_capability_catalog_entry_count_positive",
        ),
        sa.CheckConstraint(
            "sequence > 0",
            name="ck_remote_capability_catalog_sequence_positive",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["remote_capability_catalog_sources.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_id",
            "index_digest_sha256",
            name="uq_remote_capability_catalog_source_digest",
        ),
        sa.UniqueConstraint(
            "source_id",
            "sequence",
            name="uq_remote_capability_catalog_source_sequence",
        ),
    )
    op.create_index(
        "ix_remote_capability_catalog_snapshots_index_digest_sha256",
        "remote_capability_catalog_snapshots",
        ["index_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_snapshots_key_fingerprint_sha256",
        "remote_capability_catalog_snapshots",
        ["key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_snapshots_source_id",
        "remote_capability_catalog_snapshots",
        ["source_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_snapshot_refreshed",
        "remote_capability_catalog_snapshots",
        ["source_id", "refreshed_at"],
        unique=False,
    )
    op.create_table(
        "remote_capability_catalog_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("pack_name", sa.String(length=255), nullable=False),
        sa.Column("pack_version", sa.String(length=64), nullable=False),
        sa.Column("platform_api", sa.String(length=64), nullable=False),
        sa.Column(
            "pack_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "pack_key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "predecessor_digest_sha256",
            sa.String(length=64),
            nullable=True,
        ),
        sa.Column("download_url", sa.String(length=2048), nullable=False),
        sa.Column("artifact_count", sa.Integer(), nullable=False),
        sa.Column("dependency_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "artifact_count > 0",
            name="ck_remote_capability_catalog_artifact_count_positive",
        ),
        sa.CheckConstraint(
            "dependency_count >= 0",
            name="ck_remote_capability_catalog_dependency_count_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["remote_capability_catalog_snapshots.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["remote_capability_catalog_sources.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "pack_digest_sha256",
            name="uq_remote_capability_catalog_entry_digest",
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "pack_name",
            "pack_version",
            name="uq_remote_capability_catalog_entry_version",
        ),
    )
    op.create_index(
        "ix_remote_capability_catalog_entries_pack_digest_sha256",
        "remote_capability_catalog_entries",
        ["pack_digest_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_remote_capability_catalog_entries_pack_key_fingerprint_sha256"),
        "remote_capability_catalog_entries",
        ["pack_key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_entries_pack_name",
        "remote_capability_catalog_entries",
        ["pack_name"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_entries_snapshot_id",
        "remote_capability_catalog_entries",
        ["snapshot_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_entries_source_id",
        "remote_capability_catalog_entries",
        ["source_id"],
        unique=False,
    )
    op.create_index(
        "ix_remote_capability_catalog_entry_lookup",
        "remote_capability_catalog_entries",
        ["source_id", "pack_name", "pack_version"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("remote_capability_catalog_entries")
    op.drop_table("remote_capability_catalog_snapshots")
    op.drop_table("remote_capability_catalog_sources")
