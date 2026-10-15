"""add governed trusted-proxy browser federation

Revision ID: q3p5j7l9g1h4
Revises: p2o4i6k8f0g3
Create Date: 2026-09-30 22:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "q3p5j7l9g1h4"
down_revision: str | None = "p2o4i6k8f0g3"
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
        "control_plane_trusted_proxy_identities",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("issuer_sha256", sa.String(64), nullable=False),
        sa.Column("subject_sha256", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
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
            name="uq_control_plane_trusted_proxy_external_identity",
        ),
        sa.UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_trusted_proxy_principal_issuer",
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
            f"ix_control_plane_trusted_proxy_identities_{column}",
            "control_plane_trusted_proxy_identities",
            [column],
        )

    op.create_table(
        "control_plane_trusted_proxy_login_attempts",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("identity_id", sa.String(36)),
        sa.Column("principal_id", sa.String(36)),
        sa.Column("session_id", sa.String(36)),
        sa.Column("issuer_sha256", sa.String(64), nullable=False),
        sa.Column("subject_sha256", sa.String(64)),
        sa.Column("source_address_sha256", sa.String(64)),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND failure_code IS NULL "
            "AND identity_id IS NOT NULL AND principal_id IS NOT NULL "
            "AND session_id IS NOT NULL) OR "
            "(outcome = 'denied' AND failure_code IS NOT NULL "
            "AND session_id IS NULL)",
            name="ck_control_plane_trusted_proxy_attempt_outcome",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "identity_id",
        "principal_id",
        "session_id",
        "issuer_sha256",
        "subject_sha256",
        "outcome",
        "failure_code",
        "occurred_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_control_plane_trusted_proxy_login_attempts_{column}",
            "control_plane_trusted_proxy_login_attempts",
            [column],
        )


def downgrade() -> None:
    for column in (
        "region_id",
        "tenant_id",
        "occurred_at",
        "failure_code",
        "outcome",
        "subject_sha256",
        "issuer_sha256",
        "session_id",
        "principal_id",
        "identity_id",
    ):
        op.drop_index(
            f"ix_control_plane_trusted_proxy_login_attempts_{column}",
            table_name="control_plane_trusted_proxy_login_attempts",
        )
    op.drop_table("control_plane_trusted_proxy_login_attempts")
    for column in (
        "region_id",
        "tenant_id",
        "enabled",
        "subject_sha256",
        "issuer_sha256",
        "principal_id",
    ):
        op.drop_index(
            f"ix_control_plane_trusted_proxy_identities_{column}",
            table_name="control_plane_trusted_proxy_identities",
        )
    op.drop_table("control_plane_trusted_proxy_identities")
