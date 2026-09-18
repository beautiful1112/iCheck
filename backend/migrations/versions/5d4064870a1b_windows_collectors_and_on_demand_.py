"""windows_collectors_and_on_demand_deployments

Revision ID: 5d4064870a1b
Revises: 68a0bf0b2d4f
Create Date: 2026-09-18 04:04:07.001653
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '5d4064870a1b'
down_revision: Union[str, Sequence[str], None] = '68a0bf0b2d4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("collector_deployments") as batch_op:
        batch_op.add_column(
            sa.Column(
                "execution_mode",
                sa.Enum(
                    "SCHEDULED",
                    "ON_DEMAND",
                    name="collectordeploymentmode",
                    native_enum=False,
                    length=16,
                ),
                nullable=False,
                server_default="SCHEDULED",
            )
        )
        batch_op.add_column(
            sa.Column(
                "credential_profile_ref",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch_op.alter_column(
            "next_run_at",
            existing_type=sa.DateTime(),
            nullable=True,
        )
        batch_op.create_index(
            op.f("ix_collector_deployments_execution_mode"),
            ["execution_mode"],
            unique=False,
        )


def downgrade() -> None:
    op.execute(
        "UPDATE collector_deployments "
        "SET next_run_at = CURRENT_TIMESTAMP WHERE next_run_at IS NULL"
    )
    with op.batch_alter_table("collector_deployments") as batch_op:
        batch_op.drop_index(
            op.f("ix_collector_deployments_execution_mode")
        )
        batch_op.alter_column(
            "next_run_at",
            existing_type=sa.DateTime(),
            nullable=False,
        )
        batch_op.drop_column("credential_profile_ref")
        batch_op.drop_column("execution_mode")
