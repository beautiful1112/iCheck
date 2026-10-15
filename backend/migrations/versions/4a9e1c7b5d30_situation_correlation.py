"""durable situation correlation and investigation binding

Revision ID: 4a9e1c7b5d30
Revises: 3f8d6b2a7c41
Create Date: 2026-09-27 09:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "4a9e1c7b5d30"
down_revision: str | None = "3f8d6b2a7c41"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "situations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("correlation_key", sa.String(length=64), nullable=False),
        sa.Column("correlation_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("primary_entity_type", sa.String(length=64), nullable=False),
        sa.Column("primary_entity_id", sa.String(length=255), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("active_alert_count", sa.Integer(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("correlation_confidence", sa.Float(), nullable=False),
        sa.Column("event_sequence", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved')",
            name="ck_situation_status",
        ),
        sa.CheckConstraint("alert_count > 0", name="ck_situation_alert_count"),
        sa.CheckConstraint(
            "active_alert_count >= 0 AND active_alert_count <= alert_count",
            name="ck_situation_active_alert_count",
        ),
        sa.CheckConstraint(
            "occurrence_count >= alert_count",
            name="ck_situation_occurrence_count",
        ),
        sa.CheckConstraint(
            "priority_score >= 0",
            name="ck_situation_priority_score",
        ),
        sa.CheckConstraint(
            "event_sequence >= 0",
            name="ck_situation_event_sequence",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_situation_active_correlation_key",
        "situations",
        ["correlation_key"],
        unique=True,
        postgresql_where=sa.text("status != 'resolved'"),
        sqlite_where=sa.text("status != 'resolved'"),
    )
    op.create_index(
        "ix_situation_queue",
        "situations",
        ["status", "priority_score", "last_seen"],
    )
    op.create_index(
        "ix_situation_primary_entity",
        "situations",
        ["primary_entity_type", "primary_entity_id"],
    )

    op.create_table(
        "situation_alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("correlation_reason", sa.String(length=64), nullable=False),
        sa.Column("severity_snapshot", sa.String(length=16), nullable=False),
        sa.Column("status_snapshot", sa.String(length=16), nullable=False),
        sa.Column("occurrence_count_snapshot", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["situation_id"], ["situations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", name="uq_situation_alert_alert"),
    )
    op.create_index(
        "ix_situation_alerts_alert_id",
        "situation_alerts",
        ["alert_id"],
    )
    op.create_index(
        "ix_situation_alerts_situation_id",
        "situation_alerts",
        ["situation_id"],
    )
    op.create_index(
        "ix_situation_alert_situation_added",
        "situation_alerts",
        ["situation_id", "added_at"],
    )

    op.create_table(
        "situation_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence > 0", name="ck_situation_event_sequence"),
        sa.ForeignKeyConstraint(
            ["situation_id"], ["situations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "situation_id",
            "sequence",
            name="uq_situation_event_sequence",
        ),
    )
    op.create_index(
        "ix_situation_events_created_at",
        "situation_events",
        ["created_at"],
    )
    op.create_index(
        "ix_situation_events_event_type",
        "situation_events",
        ["event_type"],
    )
    op.create_index(
        "ix_situation_events_situation_id",
        "situation_events",
        ["situation_id"],
    )
    op.create_index(
        "ix_situation_event_situation_created",
        "situation_events",
        ["situation_id", "created_at"],
    )

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column("situation_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_investigations_situation_id",
            "situations",
            ["situation_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_situation_id",
            ["situation_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_situation_id")
        batch_op.drop_constraint(
            "fk_investigations_situation_id",
            type_="foreignkey",
        )
        batch_op.drop_column("situation_id")
    op.drop_table("situation_events")
    op.drop_table("situation_alerts")
    op.drop_table("situations")
