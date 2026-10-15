"""situation integration workflow bindings and durable outbox

Revision ID: b18f9e7c3d64
Revises: a06c8d4e2b97
Create Date: 2026-09-28 08:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b18f9e7c3d64"
down_revision: str | None = "a06c8d4e2b97"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "situation_integration_bindings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_version_id", sa.String(length=36), nullable=False),
        sa.Column("channel_kind", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("route_purpose", sa.String(length=128), nullable=False),
        sa.Column("run_as_principal_id", sa.String(length=36), nullable=True),
        sa.Column("authorization_scope", sa.JSON(), nullable=False),
        sa.Column("input_mapping", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "channel_kind IN ('ticket', 'collaboration')",
            name="ck_situation_integration_binding_channel",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"],
            ["artifact_versions.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_as_principal_id"],
            ["control_plane_principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_version_id",
            name="uq_situation_integration_binding_version",
        ),
    )
    for column in (
        "artifact_version_id",
        "channel_kind",
        "event_type",
        "run_as_principal_id",
        "enabled",
    ):
        op.create_index(
            op.f(f"ix_situation_integration_bindings_{column}"),
            "situation_integration_bindings",
            [column],
        )

    op.create_table(
        "situation_integration_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("situation_event_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_situation_integration_event_attempts",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'failed')",
            name="ck_situation_integration_event_status",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"],
            ["situation_integration_bindings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["situation_id"],
            ["situations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["situation_event_id"],
            ["situation_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binding_id",
            "situation_event_id",
            name="uq_situation_integration_event_delivery",
        ),
    )
    for column in (
        "binding_id",
        "situation_id",
        "situation_event_id",
        "event_type",
        "status",
    ):
        op.create_index(
            op.f(f"ix_situation_integration_events_{column}"),
            "situation_integration_events",
            [column],
        )

    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "situation_integration_event_id",
                sa.String(length=36),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            "fk_investigations_situation_integration_event_id",
            "situation_integration_events",
            ["situation_integration_event_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_investigations_situation_integration_event_id",
            ["situation_integration_event_id"],
            unique=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index(
            "ix_investigations_situation_integration_event_id"
        )
        batch_op.drop_constraint(
            "fk_investigations_situation_integration_event_id",
            type_="foreignkey",
        )
        batch_op.drop_column("situation_integration_event_id")
    op.drop_table("situation_integration_events")
    op.drop_table("situation_integration_bindings")
