"""durable prometheus service indicator polling

Revision ID: d3b7e1a9f406
Revises: c29a0f8d4e75
Create Date: 2026-09-28 14:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "d3b7e1a9f406"
down_revision: str | None = "c29a0f8d4e75"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_indicator_prometheus_bindings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("metric_backend_id", sa.String(length=36), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("reduction", sa.String(length=16), nullable=False),
        sa.Column("dimension_labels", sa.JSON(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_succeeded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("last_error_type", sa.String(length=255), nullable=True),
        sa.Column("last_error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "reduction IN ('single', 'sum', 'avg', 'min', 'max')",
            name="ck_indicator_prom_binding_reduction",
        ),
        sa.CheckConstraint(
            "interval_seconds >= 60 AND interval_seconds <= 86400",
            name="ck_indicator_prom_binding_interval",
        ),
        sa.CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 60",
            name="ck_indicator_prom_binding_timeout",
        ),
        sa.CheckConstraint(
            "revision > 0 AND consecutive_failures >= 0",
            name="ck_indicator_prom_binding_revision_failures",
        ),
        sa.ForeignKeyConstraint(
            ["definition_id"],
            ["service_indicator_definitions.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["metric_backend_id"], ["metric_backends.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_service_indicator_prometheus_bindings_definition_id",
        "service_indicator_prometheus_bindings",
        ["definition_id"],
        unique=True,
    )
    op.create_index(
        "ix_service_indicator_prometheus_bindings_metric_backend_id",
        "service_indicator_prometheus_bindings",
        ["metric_backend_id"],
    )
    op.create_index(
        "ix_service_indicator_prometheus_bindings_enabled",
        "service_indicator_prometheus_bindings",
        ["enabled"],
    )
    op.create_index(
        "ix_service_indicator_prometheus_bindings_next_run_at",
        "service_indicator_prometheus_bindings",
        ["next_run_at"],
    )
    op.create_index(
        "ix_indicator_prom_binding_due",
        "service_indicator_prometheus_bindings",
        ["enabled", "next_run_at"],
    )

    op.create_table(
        "service_indicator_workers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        "ix_service_indicator_workers_name",
        "service_indicator_workers",
        ["name"],
        unique=True,
    )
    op.create_index(
        "ix_service_indicator_workers_state",
        "service_indicator_workers",
        ["state"],
    )
    op.create_index(
        "ix_service_indicator_workers_last_heartbeat_at",
        "service_indicator_workers",
        ["last_heartbeat_at"],
    )

    op.create_table(
        "service_indicator_poll_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_worker_id", sa.String(length=36), nullable=True),
        sa.Column("lease_token_hash", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation_id", sa.String(length=36), nullable=True),
        sa.Column("result_type", sa.String(length=32), nullable=True),
        sa.Column("series_count", sa.Integer(), nullable=True),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts > 0",
            name="ck_indicator_poll_run_attempts",
        ),
        sa.CheckConstraint(
            "series_count IS NULL OR series_count >= 0",
            name="ck_indicator_poll_run_series_count",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"],
            ["service_indicator_prometheus_bindings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lease_worker_id"],
            ["service_indicator_workers.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["service_indicator_observations.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binding_id", "scheduled_for", name="uq_indicator_poll_run_schedule"
        ),
    )
    for column in (
        "binding_id",
        "scheduled_for",
        "status",
        "next_attempt_at",
        "lease_worker_id",
        "lease_expires_at",
        "observation_id",
        "created_at",
    ):
        op.create_index(
            f"ix_service_indicator_poll_runs_{column}",
            "service_indicator_poll_runs",
            [column],
        )
    op.create_index(
        "ix_indicator_poll_run_queue",
        "service_indicator_poll_runs",
        ["status", "next_attempt_at", "lease_expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_indicator_poll_run_queue", table_name="service_indicator_poll_runs"
    )
    for column in reversed(
        (
            "binding_id",
            "scheduled_for",
            "status",
            "next_attempt_at",
            "lease_worker_id",
            "lease_expires_at",
            "observation_id",
            "created_at",
        )
    ):
        op.drop_index(
            f"ix_service_indicator_poll_runs_{column}",
            table_name="service_indicator_poll_runs",
        )
    op.drop_table("service_indicator_poll_runs")
    op.drop_index(
        "ix_service_indicator_workers_last_heartbeat_at",
        table_name="service_indicator_workers",
    )
    op.drop_index(
        "ix_service_indicator_workers_state",
        table_name="service_indicator_workers",
    )
    op.drop_index(
        "ix_service_indicator_workers_name",
        table_name="service_indicator_workers",
    )
    op.drop_table("service_indicator_workers")
    op.drop_index(
        "ix_indicator_prom_binding_due",
        table_name="service_indicator_prometheus_bindings",
    )
    op.drop_index(
        "ix_service_indicator_prometheus_bindings_next_run_at",
        table_name="service_indicator_prometheus_bindings",
    )
    op.drop_index(
        "ix_service_indicator_prometheus_bindings_enabled",
        table_name="service_indicator_prometheus_bindings",
    )
    op.drop_index(
        "ix_service_indicator_prometheus_bindings_metric_backend_id",
        table_name="service_indicator_prometheus_bindings",
    )
    op.drop_index(
        "ix_service_indicator_prometheus_bindings_definition_id",
        table_name="service_indicator_prometheus_bindings",
    )
    op.drop_table("service_indicator_prometheus_bindings")
