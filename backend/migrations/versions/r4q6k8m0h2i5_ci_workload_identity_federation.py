"""add governed CI workload identity federation

Revision ID: r4q6k8m0h2i5
Revises: q3p5j7l9g1h4
Create Date: 2026-09-30 23:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "r4q6k8m0h2i5"
down_revision: str | None = "q3p5j7l9g1h4"
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
        "control_plane_workload_identities",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("issuer_sha256", sa.String(64), nullable=False),
        sa.Column("subject_sha256", sa.String(64), nullable=False),
        sa.Column("audience_sha256", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("max_token_ttl_minutes", sa.Integer(), nullable=False),
        sa.Column("last_exchange_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.CheckConstraint(
            "max_token_ttl_minutes >= 1 AND max_token_ttl_minutes <= 60",
            name="ck_control_plane_workload_identity_ttl",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["control_plane_principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer_sha256",
            "subject_sha256",
            name="uq_control_plane_workload_external_identity",
        ),
        sa.UniqueConstraint(
            "principal_id",
            "issuer_sha256",
            name="uq_control_plane_workload_principal_issuer",
        ),
    )
    for column in (
        "principal_id",
        "issuer_sha256",
        "subject_sha256",
        "audience_sha256",
        "enabled",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_control_plane_workload_identities_{column}",
            "control_plane_workload_identities",
            [column],
        )

    with op.batch_alter_table("control_plane_access_tokens") as batch_op:
        batch_op.add_column(
            sa.Column(
                "workload_identity_id",
                sa.String(36),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            "fk_control_plane_access_token_workload_identity",
            "control_plane_workload_identities",
            ["workload_identity_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index(
            "ix_control_plane_access_tokens_workload_identity_id",
            ["workload_identity_id"],
        )

    op.create_table(
        "control_plane_workload_exchanges",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("identity_id", sa.String(36)),
        sa.Column("principal_id", sa.String(36)),
        sa.Column("assertion_jti_sha256", sa.String(64)),
        sa.Column("issuer_sha256", sa.String(64), nullable=False),
        sa.Column("subject_sha256", sa.String(64)),
        sa.Column("audience_sha256", sa.String(64), nullable=False),
        sa.Column("claims_sha256", sa.String(64)),
        sa.Column("source_address_sha256", sa.String(64)),
        sa.Column("assertion_expires_at", sa.DateTime(timezone=True)),
        sa.Column("issued_token_id", sa.String(36)),
        sa.Column("issued_token_prefix", sa.String(32)),
        sa.Column("issued_token_expires_at", sa.DateTime(timezone=True)),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.CheckConstraint(
            "(outcome = 'succeeded' AND failure_code IS NULL "
            "AND identity_id IS NOT NULL AND principal_id IS NOT NULL "
            "AND issued_token_id IS NOT NULL "
            "AND issued_token_prefix IS NOT NULL "
            "AND issued_token_expires_at IS NOT NULL) OR "
            "(outcome = 'denied' AND failure_code IS NOT NULL "
            "AND issued_token_id IS NULL AND issued_token_prefix IS NULL "
            "AND issued_token_expires_at IS NULL)",
            name="ck_control_plane_workload_exchange_outcome",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column, unique in (
        ("identity_id", False),
        ("principal_id", False),
        ("assertion_jti_sha256", True),
        ("issuer_sha256", False),
        ("subject_sha256", False),
        ("audience_sha256", False),
        ("issued_token_id", False),
        ("outcome", False),
        ("failure_code", False),
        ("occurred_at", False),
        ("tenant_id", False),
        ("region_id", False),
    ):
        op.create_index(
            f"ix_control_plane_workload_exchanges_{column}",
            "control_plane_workload_exchanges",
            [column],
            unique=unique,
        )


def downgrade() -> None:
    for column in (
        "region_id",
        "tenant_id",
        "occurred_at",
        "failure_code",
        "outcome",
        "issued_token_id",
        "audience_sha256",
        "subject_sha256",
        "issuer_sha256",
        "assertion_jti_sha256",
        "principal_id",
        "identity_id",
    ):
        op.drop_index(
            f"ix_control_plane_workload_exchanges_{column}",
            table_name="control_plane_workload_exchanges",
        )
    op.drop_table("control_plane_workload_exchanges")

    with op.batch_alter_table("control_plane_access_tokens") as batch_op:
        batch_op.drop_index(
            "ix_control_plane_access_tokens_workload_identity_id"
        )
        batch_op.drop_constraint(
            "fk_control_plane_access_token_workload_identity",
            type_="foreignkey",
        )
        batch_op.drop_column("workload_identity_id")

    for column in (
        "region_id",
        "tenant_id",
        "enabled",
        "audience_sha256",
        "subject_sha256",
        "issuer_sha256",
        "principal_id",
    ):
        op.drop_index(
            f"ix_control_plane_workload_identities_{column}",
            table_name="control_plane_workload_identities",
        )
    op.drop_table("control_plane_workload_identities")
