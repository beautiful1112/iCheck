"""add automatic health-gated collector rollout rings

Revision ID: a7e9f1b3c578
Revises: z6d8f0a2b467
Create Date: 2026-09-29 22:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a7e9f1b3c578"
down_revision: str | None = "z6d8f0a2b467"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


ROLLOUTS = "collector_fleet_rollouts"
ITEMS = "collector_fleet_rollout_items"
RINGS = "collector_fleet_rollout_rings"


def _enable_namespace_rls(table_name: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
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


def _disable_namespace_rls(table_name: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        sa.text(
            f'DROP POLICY IF EXISTS icheck_namespace_isolation ON "{table_name}"'
        )
    )
    op.execute(sa.text(f'ALTER TABLE "{table_name}" DISABLE ROW LEVEL SECURITY'))


def upgrade() -> None:
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "progression_mode",
            sa.String(length=16),
            nullable=False,
            server_default="manual",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "ring_percentages",
            sa.JSON(),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "observation_seconds",
            sa.Integer(),
            nullable=False,
            server_default="300",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "min_successful_runs_per_deployment",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "max_failed_runs_per_ring",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column(
            "automation_state",
            sa.String(length=16),
            nullable=False,
            server_default="manual",
        ),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column("current_ring_index", sa.Integer(), nullable=True),
    )
    op.add_column(
        ROLLOUTS,
        sa.Column("automation_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        f"ix_{ROLLOUTS}_progression_mode",
        ROLLOUTS,
        ["progression_mode"],
    )
    op.create_index(
        f"ix_{ROLLOUTS}_automation_state",
        ROLLOUTS,
        ["automation_state"],
    )
    if op.get_bind().dialect.name != "sqlite":
        op.create_check_constraint(
            "ck_collector_fleet_rollout_progression_mode",
            ROLLOUTS,
            "progression_mode IN ('manual', 'automatic')",
        )
        op.create_check_constraint(
            "ck_collector_fleet_rollout_automation_state",
            ROLLOUTS,
            "automation_state IN ('manual', 'armed', 'observing', 'paused', "
            "'aborted', 'completed', 'failed')",
        )
        op.create_check_constraint(
            "ck_collector_fleet_rollout_observation_seconds",
            ROLLOUTS,
            "observation_seconds >= 30 AND observation_seconds <= 86400",
        )
        op.create_check_constraint(
            "ck_collector_fleet_rollout_min_successful_runs",
            ROLLOUTS,
            "min_successful_runs_per_deployment > 0 AND "
            "min_successful_runs_per_deployment <= 20",
        )
        op.create_check_constraint(
            "ck_collector_fleet_rollout_max_failed_runs",
            ROLLOUTS,
            "max_failed_runs_per_ring >= 0 AND max_failed_runs_per_ring <= 500",
        )
    op.add_column(
        ITEMS,
        sa.Column("ring_index", sa.Integer(), nullable=True),
    )
    op.create_index(f"ix_{ITEMS}_ring_index", ITEMS, ["ring_index"])

    op.create_table(
        RINGS,
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("rollout_id", sa.String(length=36), nullable=False),
        sa.Column("ring_index", sa.Integer(), nullable=False),
        sa.Column("target_percent", sa.Integer(), nullable=False),
        sa.Column("target_count", sa.Integer(), nullable=False),
        sa.Column("cohort_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "healthy_deployments", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "missing_evidence_deployments",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("successful_runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_gate_result", sa.String(length=64), nullable=True),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "observation_started_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("passed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'applying', 'observing', 'passed', "
            "'paused', 'aborted', 'failed')",
            name="ck_collector_fleet_rollout_ring_status",
        ),
        sa.CheckConstraint(
            "ring_index >= 0",
            name="ck_collector_fleet_rollout_ring_index",
        ),
        sa.CheckConstraint(
            "target_percent > 0 AND target_percent <= 100",
            name="ck_collector_fleet_rollout_ring_percent",
        ),
        sa.CheckConstraint(
            "target_count > 0",
            name="ck_collector_fleet_rollout_ring_target_count",
        ),
        sa.ForeignKeyConstraint(
            ["rollout_id"],
            [f"{ROLLOUTS}.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "rollout_id",
            "ring_index",
            name="uq_collector_fleet_rollout_ring_index",
        ),
    )
    for column in ("rollout_id", "status", "tenant_id", "region_id"):
        op.create_index(f"ix_{RINGS}_{column}", RINGS, [column])
    _enable_namespace_rls(RINGS)


def downgrade() -> None:
    _disable_namespace_rls(RINGS)
    op.drop_table(RINGS)
    op.drop_index(f"ix_{ITEMS}_ring_index", table_name=ITEMS)
    op.drop_column(ITEMS, "ring_index")
    op.drop_index(f"ix_{ROLLOUTS}_automation_state", table_name=ROLLOUTS)
    op.drop_index(f"ix_{ROLLOUTS}_progression_mode", table_name=ROLLOUTS)
    if op.get_bind().dialect.name != "sqlite":
        for constraint in (
            "ck_collector_fleet_rollout_max_failed_runs",
            "ck_collector_fleet_rollout_min_successful_runs",
            "ck_collector_fleet_rollout_observation_seconds",
            "ck_collector_fleet_rollout_automation_state",
            "ck_collector_fleet_rollout_progression_mode",
        ):
            op.drop_constraint(constraint, ROLLOUTS, type_="check")
    for column in (
        "automation_updated_at",
        "current_ring_index",
        "automation_state",
        "max_failed_runs_per_ring",
        "min_successful_runs_per_deployment",
        "observation_seconds",
        "ring_percentages",
        "progression_mode",
    ):
        op.drop_column(ROLLOUTS, column)
