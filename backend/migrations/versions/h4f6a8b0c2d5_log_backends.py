"""add namespace-isolated log backends

Revision ID: h4f6a8b0c2d5
Revises: g3e5f7a9b1c4
Create Date: 2026-09-29 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "h4f6a8b0c2d5"
down_revision: str | None = "g3e5f7a9b1c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "log_backends",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("query_base_url", sa.String(length=2048), nullable=False),
        sa.Column("credential_profile_ref", sa.String(length=255), nullable=True),
        sa.Column("device_label", sa.String(length=128), nullable=False),
        sa.Column("allowed_labels", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_health_status", sa.String(length=32), nullable=True),
        sa.Column("last_health_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "name",
            name="uq_log_backend_namespace_name",
        ),
    )
    for column in ("name", "provider", "enabled", "tenant_id", "region_id"):
        op.create_index(
            f"ix_log_backends_{column}",
            "log_backends",
            [column],
            unique=False,
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "log_backends" ENABLE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                'CREATE POLICY icheck_namespace_isolation ON "log_backends" '
                "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                "AND region_id = current_setting('icheck.region_id', true))"
            )
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                'DROP POLICY IF EXISTS icheck_namespace_isolation ON "log_backends"'
            )
        )
        op.execute(sa.text('ALTER TABLE "log_backends" DISABLE ROW LEVEL SECURITY'))
    for column in reversed(
        ("name", "provider", "enabled", "tenant_id", "region_id")
    ):
        op.drop_index(f"ix_log_backends_{column}", table_name="log_backends")
    op.drop_table("log_backends")
