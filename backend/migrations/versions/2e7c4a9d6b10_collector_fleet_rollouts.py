"""governed collector fleet replacement and rollback

Revision ID: 2e7c4a9d6b10
Revises: 1d5b9f7a4c82
Create Date: 2026-09-27 02:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "2e7c4a9d6b10"
down_revision: str | None = "1d5b9f7a4c82"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "collector_fleet_rollouts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("canary_rollout_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("from_version_id", sa.String(length=36), nullable=False),
        sa.Column("to_version_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("scope_site", sa.String(length=128), nullable=True),
        sa.Column("include_disabled", sa.Boolean(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("max_failures", sa.Integer(), nullable=False),
        sa.Column("plan_sha256", sa.String(length=64), nullable=False),
        sa.Column("planned_count", sa.Integer(), nullable=False),
        sa.Column("pending_count", sa.Integer(), nullable=False),
        sa.Column("blocked_count", sa.Integer(), nullable=False),
        sa.Column("deferred_count", sa.Integer(), nullable=False),
        sa.Column("migrated_count", sa.Integer(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("rolled_back_count", sa.Integer(), nullable=False),
        sa.Column("rollback_failed_count", sa.Integer(), nullable=False),
        sa.Column("last_batch_result", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('planned', 'running', 'completed', 'failed', "
            "'rolling_back', 'rolled_back', 'rollback_failed')",
            name="ck_collector_fleet_rollout_status",
        ),
        sa.CheckConstraint(
            "batch_size > 0 AND batch_size <= 500",
            name="ck_collector_fleet_rollout_batch_size",
        ),
        sa.CheckConstraint(
            "max_failures > 0",
            name="ck_collector_fleet_rollout_max_failures",
        ),
        sa.ForeignKeyConstraint(
            ["canary_rollout_id"],
            ["collector_canary_rollouts.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["from_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["to_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "canary_rollout_id",
        "artifact_id",
        "from_version_id",
        "to_version_id",
        "status",
        "scope_site",
        "plan_sha256",
    ):
        op.create_index(
            f"ix_collector_fleet_rollouts_{column}",
            "collector_fleet_rollouts",
            [column],
        )
    op.create_index(
        "uq_collector_fleet_active_canary",
        "collector_fleet_rollouts",
        ["canary_rollout_id"],
        unique=True,
        sqlite_where=sa.text(
            "status IN ('planned', 'running', 'rolling_back')"
        ),
        postgresql_where=sa.text(
            "status IN ('planned', 'running', 'rolling_back')"
        ),
    )

    op.create_table(
        "collector_fleet_rollout_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("rollout_id", sa.String(length=36), nullable=False),
        sa.Column("deployment_id", sa.String(length=36), nullable=False),
        sa.Column("deployment_name", sa.String(length=255), nullable=False),
        sa.Column("pre_change_sha256", sa.String(length=64), nullable=False),
        sa.Column("post_change_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("block_reason_code", sa.String(length=64), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_sha256", sa.String(length=64), nullable=True),
        sa.Column("migrated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'blocked', 'deferred', 'migrated', "
            "'failed', 'rollback_deferred', 'rolled_back', 'rollback_failed')",
            name="ck_collector_fleet_rollout_item_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_collector_fleet_rollout_item_attempts",
        ),
        sa.ForeignKeyConstraint(
            ["rollout_id"], ["collector_fleet_rollouts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"], ["collector_deployments.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "rollout_id",
            "deployment_id",
            name="uq_collector_fleet_rollout_deployment",
        ),
    )
    for column in ("rollout_id", "deployment_id", "status"):
        op.create_index(
            f"ix_collector_fleet_rollout_items_{column}",
            "collector_fleet_rollout_items",
            [column],
        )


def downgrade() -> None:
    op.drop_table("collector_fleet_rollout_items")
    op.drop_index(
        "uq_collector_fleet_active_canary",
        table_name="collector_fleet_rollouts",
    )
    op.drop_table("collector_fleet_rollouts")
