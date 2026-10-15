"""immutable scaling-provider application events

Revision ID: u1e3f5a7b912
Revises: t0d2f4a6b801
Create Date: 2026-10-04 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "u1e3f5a7b912"
down_revision: str | None = "t0d2f4a6b801"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLE = "worker_scaling_application_events"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("provider_subject", sa.String(length=255), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("observed_replicas", sa.Integer(), nullable=False),
        sa.Column("detail_code", sa.String(length=128), nullable=False),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "status IN ('accepted', 'applying', 'applied', 'failed', 'rejected')",
            name="ck_scaling_application_event_status",
        ),
        sa.CheckConstraint(
            "observed_replicas >= 0",
            name="ck_scaling_application_event_observed_replicas",
        ),
        sa.ForeignKeyConstraint(
            ["decision_id"],
            ["worker_scaling_decisions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "provider_subject",
            "idempotency_key",
            name="uq_scaling_application_event_namespace_provider_key",
        ),
    )
    for column in (
        "decision_id",
        "provider_subject",
        "status",
        "created_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_{TABLE}_{column}",
            TABLE,
            [column],
            unique=False,
        )
    op.create_index(
        "ix_scaling_application_event_decision_provider_time",
        TABLE,
        ["decision_id", "provider_subject", "created_at"],
        unique=False,
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text(f'ALTER TABLE "{TABLE}" ENABLE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY icheck_namespace_isolation ON "{TABLE}" '
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
                f'DROP POLICY IF EXISTS icheck_namespace_isolation ON "{TABLE}"'
            )
        )
        op.execute(sa.text(f'ALTER TABLE "{TABLE}" DISABLE ROW LEVEL SECURITY'))

    op.drop_index(
        "ix_scaling_application_event_decision_provider_time",
        table_name=TABLE,
    )
    for column in reversed(
        (
            "decision_id",
            "provider_subject",
            "status",
            "created_at",
            "tenant_id",
            "region_id",
        )
    ):
        op.drop_index(f"ix_{TABLE}_{column}", table_name=TABLE)
    op.drop_table(TABLE)
