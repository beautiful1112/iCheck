"""worker autoscaling policies and recommendation ledger

Revision ID: t0d2f4a6b801
Revises: s9c1e3f5a790
Create Date: 2026-10-03 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "t0d2f4a6b801"
down_revision: str | None = "s9c1e3f5a790"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLES = ("worker_scaling_policies", "worker_scaling_decisions")


def _namespace_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "worker_scaling_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "pool",
            sa.Enum("collector", "agent", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column("selector", sa.JSON(), nullable=False),
        sa.Column("required_capabilities", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("min_replicas", sa.Integer(), nullable=False),
        sa.Column("max_replicas", sa.Integer(), nullable=False),
        sa.Column("target_queue_per_replica", sa.Integer(), nullable=False),
        sa.Column("scale_out_step", sa.Integer(), nullable=False),
        sa.Column("scale_in_step", sa.Integer(), nullable=False),
        sa.Column("queue_age_target_seconds", sa.Integer(), nullable=False),
        sa.Column("heartbeat_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("update_reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        *_namespace_columns(),
        sa.CheckConstraint(
            "min_replicas >= 0 AND max_replicas >= min_replicas",
            name="ck_worker_scaling_policy_replica_bounds",
        ),
        sa.CheckConstraint(
            "target_queue_per_replica > 0",
            name="ck_worker_scaling_policy_queue_target",
        ),
        sa.CheckConstraint(
            "scale_out_step > 0 AND scale_in_step > 0",
            name="ck_worker_scaling_policy_steps",
        ),
        sa.CheckConstraint(
            "queue_age_target_seconds > 0 AND heartbeat_timeout_seconds > 0 "
            "AND cooldown_seconds >= 0",
            name="ck_worker_scaling_policy_time_bounds",
        ),
        sa.CheckConstraint(
            "revision > 0", name="ck_worker_scaling_policy_revision"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "region_id",
            "pool",
            "name",
            name="uq_worker_scaling_policy_namespace_pool_name",
        ),
    )
    for column in ("name", "pool", "enabled", "tenant_id", "region_id"):
        op.create_index(
            f"ix_worker_scaling_policies_{column}",
            "worker_scaling_policies",
            [column],
            unique=False,
        )

    op.create_table(
        "worker_scaling_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("queue_depth", sa.Integer(), nullable=False),
        sa.Column("oldest_queue_age_seconds", sa.Float(), nullable=True),
        sa.Column("current_replicas", sa.Integer(), nullable=False),
        sa.Column("ready_replicas", sa.Integer(), nullable=False),
        sa.Column("busy_replicas", sa.Integer(), nullable=False),
        sa.Column("stale_replicas", sa.Integer(), nullable=False),
        sa.Column("desired_replicas", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        *_namespace_columns(),
        sa.CheckConstraint(
            "queue_depth >= 0 AND current_replicas >= 0 "
            "AND ready_replicas >= 0 AND busy_replicas >= 0 "
            "AND stale_replicas >= 0 AND desired_replicas >= 0",
            name="ck_worker_scaling_decision_counts",
        ),
        sa.CheckConstraint(
            "direction IN ('scale_out', 'scale_in', 'hold')",
            name="ck_worker_scaling_decision_direction",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["worker_scaling_policies.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "policy_id",
        "direction",
        "observed_at",
        "tenant_id",
        "region_id",
    ):
        op.create_index(
            f"ix_worker_scaling_decisions_{column}",
            "worker_scaling_decisions",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_worker_scaling_decision_policy_time",
        "worker_scaling_decisions",
        ["policy_id", "observed_at"],
        unique=False,
    )

    if op.get_bind().dialect.name == "postgresql":
        for table_name in TABLES:
            op.execute(sa.text(f'ALTER TABLE "{table_name}" ENABLE ROW LEVEL SECURITY'))
            op.execute(
                sa.text(
                    f'CREATE POLICY icheck_namespace_isolation ON "{table_name}" '
                    "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                    "AND region_id = current_setting('icheck.region_id', true)) "
                    "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                    "AND region_id = current_setting('icheck.region_id', true))"
                )
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in reversed(TABLES):
            op.execute(
                sa.text(
                    f'DROP POLICY IF EXISTS icheck_namespace_isolation ON "{table_name}"'
                )
            )
            op.execute(sa.text(f'ALTER TABLE "{table_name}" DISABLE ROW LEVEL SECURITY'))

    op.drop_index(
        "ix_worker_scaling_decision_policy_time",
        table_name="worker_scaling_decisions",
    )
    for column in reversed(
        ("policy_id", "direction", "observed_at", "tenant_id", "region_id")
    ):
        op.drop_index(
            f"ix_worker_scaling_decisions_{column}",
            table_name="worker_scaling_decisions",
        )
    op.drop_table("worker_scaling_decisions")
    for column in reversed(("name", "pool", "enabled", "tenant_id", "region_id")):
        op.drop_index(
            f"ix_worker_scaling_policies_{column}",
            table_name="worker_scaling_policies",
        )
    op.drop_table("worker_scaling_policies")
