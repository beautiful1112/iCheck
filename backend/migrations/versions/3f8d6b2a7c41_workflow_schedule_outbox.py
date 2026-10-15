"""workflow schedule activation and durable occurrence outbox

Revision ID: 3f8d6b2a7c41
Revises: 2e7c4a9d6b10
Create Date: 2026-09-27 05:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "3f8d6b2a7c41"
down_revision: str | None = "2e7c4a9d6b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_schedule_activations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("cron_expression", sa.String(length=255), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("route_purpose", sa.String(length=128), nullable=False),
        sa.Column("run_as_principal_id", sa.String(length=36), nullable=True),
        sa.Column("authorization_scope", sa.JSON(), nullable=False),
        sa.Column("workflow_input", sa.JSON(), nullable=False),
        sa.Column("misfire_grace_seconds", sa.Integer(), nullable=False),
        sa.Column("next_fire_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_fire_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_misfire_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("missed_runs", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "misfire_grace_seconds >= 60 AND misfire_grace_seconds <= 86400",
            name="ck_workflow_schedule_misfire_grace",
        ),
        sa.CheckConstraint(
            "missed_runs >= 0",
            name="ck_workflow_schedule_missed_runs",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"], ["artifact_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["run_as_principal_id"],
            ["control_plane_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_version_id",
            name="uq_workflow_schedule_activation_version",
        ),
    )
    for column in (
        "artifact_version_id",
        "run_as_principal_id",
        "next_fire_at",
        "enabled",
    ):
        op.create_index(
            f"ix_workflow_schedule_activations_{column}",
            "workflow_schedule_activations",
            [column],
        )
    op.create_index(
        "ix_workflow_schedule_due",
        "workflow_schedule_activations",
        ["enabled", "next_fire_at"],
    )

    op.create_table(
        "workflow_schedule_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("activation_id", sa.String(length=36), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_workflow_schedule_event_attempts",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'failed')",
            name="ck_workflow_schedule_event_status",
        ),
        sa.ForeignKeyConstraint(
            ["activation_id"],
            ["workflow_schedule_activations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "activation_id",
            "scheduled_for",
            name="uq_workflow_schedule_event_occurrence",
        ),
    )
    for column in ("activation_id", "scheduled_for", "status"):
        op.create_index(
            f"ix_workflow_schedule_events_{column}",
            "workflow_schedule_events",
            [column],
        )

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column("workflow_schedule_event_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_investigations_workflow_schedule_event_id",
            "workflow_schedule_events",
            ["workflow_schedule_event_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_workflow_schedule_event_id",
            ["workflow_schedule_event_id"],
            unique=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_workflow_schedule_event_id")
        batch_op.drop_constraint(
            "fk_investigations_workflow_schedule_event_id",
            type_="foreignkey",
        )
        batch_op.drop_column("workflow_schedule_event_id")
    op.drop_table("workflow_schedule_events")
    op.drop_index(
        "ix_workflow_schedule_due",
        table_name="workflow_schedule_activations",
    )
    op.drop_table("workflow_schedule_activations")
