"""capability pack installations

Revision ID: c3e5a7b9d124
Revises: b2d4f6a8c013
Create Date: 2026-09-29 20:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c3e5a7b9d124"
down_revision: str | None = "b2d4f6a8c013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capability_pack_installations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("pack_name", sa.String(length=255), nullable=False),
        sa.Column("pack_version", sa.String(length=64), nullable=False),
        sa.Column("platform_api", sa.String(length=64), nullable=False),
        sa.Column("pack_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column(
            "key_fingerprint_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("dependency_snapshot", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("installed_by", sa.String(length=255), nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["trust_key_id"],
            ["artifact_trust_keys.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "pack_name",
            "pack_version",
            name="uq_capability_pack_name_version",
        ),
        sa.UniqueConstraint(
            "pack_digest_sha256",
            name="uq_capability_pack_digest",
        ),
    )
    op.create_index(
        "ix_capability_pack_installations_pack_name",
        "capability_pack_installations",
        ["pack_name"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_installations_pack_digest_sha256",
        "capability_pack_installations",
        ["pack_digest_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_installations_trust_key_id",
        "capability_pack_installations",
        ["trust_key_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_installations_key_fingerprint_sha256",
        "capability_pack_installations",
        ["key_fingerprint_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_installed_at",
        "capability_pack_installations",
        ["installed_at"],
        unique=False,
    )

    op.create_table(
        "capability_pack_installed_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("source_kind", sa.String(length=32), nullable=False),
        sa.Column("source_content_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "source_bundle_digest_sha256",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("install_action", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["capability_pack_installations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "installation_id",
            "artifact_version_id",
            name="uq_capability_pack_installed_version",
        ),
    )
    op.create_index(
        "ix_capability_pack_installed_artifacts_installation_id",
        "capability_pack_installed_artifacts",
        ["installation_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_installed_artifacts_artifact_id",
        "capability_pack_installed_artifacts",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(
        "ix_capability_pack_artifact_version",
        "capability_pack_installed_artifacts",
        ["artifact_version_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_capability_pack_artifact_version",
        table_name="capability_pack_installed_artifacts",
    )
    op.drop_index(
        "ix_capability_pack_installed_artifacts_artifact_id",
        table_name="capability_pack_installed_artifacts",
    )
    op.drop_index(
        "ix_capability_pack_installed_artifacts_installation_id",
        table_name="capability_pack_installed_artifacts",
    )
    op.drop_table("capability_pack_installed_artifacts")
    op.drop_index(
        "ix_capability_pack_installed_at",
        table_name="capability_pack_installations",
    )
    op.drop_index(
        "ix_capability_pack_installations_key_fingerprint_sha256",
        table_name="capability_pack_installations",
    )
    op.drop_index(
        "ix_capability_pack_installations_trust_key_id",
        table_name="capability_pack_installations",
    )
    op.drop_index(
        "ix_capability_pack_installations_pack_digest_sha256",
        table_name="capability_pack_installations",
    )
    op.drop_index(
        "ix_capability_pack_installations_pack_name",
        table_name="capability_pack_installations",
    )
    op.drop_table("capability_pack_installations")
