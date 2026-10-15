"""add governed OIDC identities and one-time login transactions

Revision ID: f2d4e6a8b0c3
Revises: e1c3d5f7a9b2
Create Date: 2026-09-30 05:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f2d4e6a8b0c3"
down_revision: str | None = "e1c3d5f7a9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_REGION_ID = "00000000-0000-0000-0000-000000000002"


def _namespace_columns() -> list[sa.Column]:
    return [
        sa.Column(
            "tenant_id",
            sa.String(36),
            server_default=DEFAULT_TENANT_ID,
            nullable=False,
        ),
        sa.Column(
            "region_id",
            sa.String(36),
            server_default=DEFAULT_REGION_ID,
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "control_plane_oidc_identities",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("issuer_sha256", sa.String(64), nullable=False),
        sa.Column("subject_sha256", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("last_claims_sha256", sa.String(64)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["control_plane_principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer_sha256",
            "subject_sha256",
            name="uq_control_plane_oidc_external_identity",
        ),
        sa.UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_oidc_principal_issuer",
        ),
    )
    for column in (
        "principal_id",
        "issuer_sha256",
        "subject_sha256",
        "enabled",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_control_plane_oidc_identities_{column}",
            "control_plane_oidc_identities",
            [column],
        )

    op.create_table(
        "control_plane_oidc_transactions",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("browser_token_hash", sa.String(64), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("metadata_sha256", sa.String(64), nullable=False),
        sa.Column("return_to", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("failure_sha256", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in (
        ("state_hash", True),
        ("browser_token_hash", True),
        ("expires_at", False),
        ("consumed_at", False),
        ("tenant_id", False),
        ("region_id", False),
    ):
        op.create_index(
            f"ix_control_plane_oidc_transactions_{column}",
            "control_plane_oidc_transactions",
            [column],
            unique=unique,
        )


def downgrade() -> None:
    for column in (
        "region_id",
        "tenant_id",
        "consumed_at",
        "expires_at",
        "browser_token_hash",
        "state_hash",
    ):
        op.drop_index(
            f"ix_control_plane_oidc_transactions_{column}",
            table_name="control_plane_oidc_transactions",
        )
    op.drop_table("control_plane_oidc_transactions")
    for column in (
        "region_id",
        "tenant_id",
        "enabled",
        "subject_sha256",
        "issuer_sha256",
        "principal_id",
    ):
        op.drop_index(
            f"ix_control_plane_oidc_identities_{column}",
            table_name="control_plane_oidc_identities",
        )
    op.drop_table("control_plane_oidc_identities")
