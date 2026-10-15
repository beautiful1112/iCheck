"""artifact signature trust and provenance

Revision ID: g2d9f7b4c685
Revises: f1c8e6a3b574
Create Date: 2026-09-24 10:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "g2d9f7b4c685"
down_revision: str | None = "f1c8e6a3b574"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "artifact_trust_keys",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("fingerprint_sha256"),
    )
    op.create_index("ix_artifact_trust_keys_name", "artifact_trust_keys", ["name"])
    op.create_index("ix_artifact_trust_keys_fingerprint_sha256", "artifact_trust_keys", ["fingerprint_sha256"])
    op.create_index("ix_artifact_trust_keys_enabled", "artifact_trust_keys", ["enabled"])

    op.create_table(
        "artifact_signature_verifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("trust_key_id", sa.String(length=36), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("key_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("bundle_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("verified_by", sa.String(length=255), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_version_id"], ["artifact_versions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["trust_key_id"], ["artifact_trust_keys.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_version_id", name="uq_artifact_signature_verification_version"),
    )
    op.create_index("ix_artifact_signature_verifications_artifact_version_id", "artifact_signature_verifications", ["artifact_version_id"])
    op.create_index("ix_artifact_signature_verifications_trust_key_id", "artifact_signature_verifications", ["trust_key_id"])
    op.create_index("ix_artifact_signature_verifications_key_fingerprint_sha256", "artifact_signature_verifications", ["key_fingerprint_sha256"])
    op.create_index("ix_artifact_signature_verifications_bundle_digest_sha256", "artifact_signature_verifications", ["bundle_digest_sha256"])


def downgrade() -> None:
    op.drop_index("ix_artifact_signature_verifications_bundle_digest_sha256", table_name="artifact_signature_verifications")
    op.drop_index("ix_artifact_signature_verifications_key_fingerprint_sha256", table_name="artifact_signature_verifications")
    op.drop_index("ix_artifact_signature_verifications_trust_key_id", table_name="artifact_signature_verifications")
    op.drop_index("ix_artifact_signature_verifications_artifact_version_id", table_name="artifact_signature_verifications")
    op.drop_table("artifact_signature_verifications")
    op.drop_index("ix_artifact_trust_keys_enabled", table_name="artifact_trust_keys")
    op.drop_index("ix_artifact_trust_keys_fingerprint_sha256", table_name="artifact_trust_keys")
    op.drop_index("ix_artifact_trust_keys_name", table_name="artifact_trust_keys")
    op.drop_table("artifact_trust_keys")
