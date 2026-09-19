"""activation_runtime_health

Revision ID: e84b7a2d19c3
Revises: d72a9f4c6b18
Create Date: 2026-09-18 20:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e84b7a2d19c3"
down_revision: Union[str, Sequence[str], None] = "d72a9f4c6b18"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("device_connection_activations") as batch_op:
        batch_op.add_column(sa.Column(
            "expected_deployment_hash",
            sa.String(length=64),
            nullable=False,
            server_default="",
        ))
        batch_op.add_column(sa.Column(
            "runtime_status",
            sa.String(length=32),
            nullable=False,
            server_default="awaiting_first_run",
        ))
        batch_op.add_column(sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ))
        batch_op.add_column(
            sa.Column("last_run_id", sa.String(length=36), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_run_status", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(sa.Column(
            "last_run_finished_at", sa.DateTime(timezone=True), nullable=True
        ))
        batch_op.add_column(sa.Column(
            "last_success_at", sa.DateTime(timezone=True), nullable=True
        ))
        batch_op.add_column(sa.Column(
            "last_failure_at", sa.DateTime(timezone=True), nullable=True
        ))
        batch_op.add_column(sa.Column(
            "last_evaluated_at", sa.DateTime(timezone=True), nullable=True
        ))
        batch_op.add_column(
            sa.Column("health_reason", sa.Text(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_device_activation_last_run",
            "collector_runs",
            ["last_run_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_index(
        op.f("ix_device_connection_activations_runtime_status"),
        "device_connection_activations",
        ["runtime_status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_device_connection_activations_last_run_id"),
        "device_connection_activations",
        ["last_run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_device_connection_activations_last_run_id"),
        table_name="device_connection_activations",
    )
    op.drop_index(
        op.f("ix_device_connection_activations_runtime_status"),
        table_name="device_connection_activations",
    )
    with op.batch_alter_table("device_connection_activations") as batch_op:
        batch_op.drop_constraint(
            "fk_device_activation_last_run",
            type_="foreignkey",
        )
        for column in [
            "health_reason",
            "last_evaluated_at",
            "last_failure_at",
            "last_success_at",
            "last_run_finished_at",
            "last_run_status",
            "last_run_id",
            "consecutive_failures",
            "runtime_status",
            "expected_deployment_hash",
        ]:
            batch_op.drop_column(column)
