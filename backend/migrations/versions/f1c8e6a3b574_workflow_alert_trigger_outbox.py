"""workflow alert trigger activation and outbox

Revision ID: f1c8e6a3b574
Revises: e0b7d5f2a463
Create Date: 2026-09-24 09:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "f1c8e6a3b574"
down_revision: str | None = "e0b7d5f2a463"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_trigger_activations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("route_purpose", sa.String(length=128), nullable=False),
        sa.Column("run_as_principal_id", sa.String(length=36), nullable=True),
        sa.Column("authorization_scope", sa.JSON(), nullable=False),
        sa.Column("input_mapping", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_version_id"], ["artifact_versions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_as_principal_id"], ["control_plane_principals.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_version_id", name="uq_workflow_trigger_activation_version"),
    )
    op.create_index("ix_workflow_trigger_activations_artifact_version_id", "workflow_trigger_activations", ["artifact_version_id"])
    op.create_index("ix_workflow_trigger_activations_event_type", "workflow_trigger_activations", ["event_type"])
    op.create_index("ix_workflow_trigger_activations_run_as_principal_id", "workflow_trigger_activations", ["run_as_principal_id"])
    op.create_index("ix_workflow_trigger_activations_enabled", "workflow_trigger_activations", ["enabled"])

    op.create_table(
        "workflow_trigger_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("activation_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("attempt_count >= 0", name="ck_workflow_trigger_event_attempts"),
        sa.ForeignKeyConstraint(["activation_id"], ["workflow_trigger_activations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("activation_id", "alert_id", name="uq_workflow_trigger_event_activation_alert"),
    )
    op.create_index("ix_workflow_trigger_events_activation_id", "workflow_trigger_events", ["activation_id"])
    op.create_index("ix_workflow_trigger_events_alert_id", "workflow_trigger_events", ["alert_id"])
    op.create_index("ix_workflow_trigger_events_status", "workflow_trigger_events", ["status"])

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(sa.Column("workflow_trigger_event_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_investigations_workflow_trigger_event_id",
            "workflow_trigger_events",
            ["workflow_trigger_event_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_workflow_trigger_event_id",
            ["workflow_trigger_event_id"],
            unique=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_workflow_trigger_event_id")
        batch_op.drop_constraint("fk_investigations_workflow_trigger_event_id", type_="foreignkey")
        batch_op.drop_column("workflow_trigger_event_id")
    op.drop_index("ix_workflow_trigger_events_status", table_name="workflow_trigger_events")
    op.drop_index("ix_workflow_trigger_events_alert_id", table_name="workflow_trigger_events")
    op.drop_index("ix_workflow_trigger_events_activation_id", table_name="workflow_trigger_events")
    op.drop_table("workflow_trigger_events")
    op.drop_index("ix_workflow_trigger_activations_enabled", table_name="workflow_trigger_activations")
    op.drop_index("ix_workflow_trigger_activations_run_as_principal_id", table_name="workflow_trigger_activations")
    op.drop_index("ix_workflow_trigger_activations_event_type", table_name="workflow_trigger_activations")
    op.drop_index("ix_workflow_trigger_activations_artifact_version_id", table_name="workflow_trigger_activations")
    op.drop_table("workflow_trigger_activations")
