"""collector canary rollout health gates

Revision ID: c8f5b3d0e241
Revises: b7e4a2c9d130
Create Date: 2026-09-24 18:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c8f5b3d0e241"
down_revision: Union[str, Sequence[str], None] = "b7e4a2c9d130"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "collector_canary_rollouts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("candidate_version_id", sa.String(length=36), nullable=False),
        sa.Column("baseline_version_id", sa.String(length=36), nullable=True),
        sa.Column("deployment_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("worker_selector", sa.JSON(), nullable=False),
        sa.Column("credential_profile_ref", sa.String(length=255), nullable=True),
        sa.Column("schedule_seconds", sa.Integer(), nullable=False),
        sa.Column("min_successful_runs", sa.Integer(), nullable=False),
        sa.Column("max_failed_runs", sa.Integer(), nullable=False),
        sa.Column("min_records_per_run", sa.Integer(), nullable=False),
        sa.Column("successful_runs", sa.Integer(), nullable=False),
        sa.Column("qualifying_runs", sa.Integer(), nullable=False),
        sa.Column("failed_runs", sa.Integer(), nullable=False),
        sa.Column("records_received", sa.Integer(), nullable=False),
        sa.Column("evidence_batches", sa.Integer(), nullable=False),
        sa.Column("last_evidence_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_run_id", sa.String(length=36), nullable=True),
        sa.Column("last_gate_result", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("passed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("aborted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("abort_reason", sa.Text(), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_by", sa.String(length=255), nullable=True),
        sa.Column("promotion_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('running', 'passed', 'aborted', 'promoted')",
            name="ck_collector_canary_status",
        ),
        sa.CheckConstraint(
            "min_successful_runs > 0",
            name="ck_collector_canary_min_success_positive",
        ),
        sa.CheckConstraint(
            "max_failed_runs > 0",
            name="ck_collector_canary_max_failures_positive",
        ),
        sa.CheckConstraint(
            "min_records_per_run >= 0",
            name="ck_collector_canary_min_records_nonnegative",
        ),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["candidate_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["baseline_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"], ["collector_deployments.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["last_run_id"], ["collector_runs.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("deployment_id"),
        sa.UniqueConstraint("name"),
    )
    for column in [
        "name",
        "artifact_id",
        "candidate_version_id",
        "baseline_version_id",
        "deployment_id",
        "status",
        "last_run_id",
        "deadline_at",
    ]:
        op.create_index(
            op.f(f"ix_collector_canary_rollouts_{column}"),
            "collector_canary_rollouts",
            [column],
            unique=False,
        )
    op.create_index(
        "uq_collector_canary_active_artifact",
        "collector_canary_rollouts",
        ["artifact_id"],
        unique=True,
        sqlite_where=sa.text("status = 'running'"),
        postgresql_where=sa.text("status = 'running'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_collector_canary_active_artifact",
        table_name="collector_canary_rollouts",
    )
    for column in reversed(
        [
            "name",
            "artifact_id",
            "candidate_version_id",
            "baseline_version_id",
            "deployment_id",
            "status",
            "last_run_id",
            "deadline_at",
        ]
    ):
        op.drop_index(
            op.f(f"ix_collector_canary_rollouts_{column}"),
            table_name="collector_canary_rollouts",
        )
    op.drop_table("collector_canary_rollouts")
