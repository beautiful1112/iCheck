"""collector_deployment_scope

Revision ID: b17e4c8d2a63
Revises: 9a4e1c6b8d32
Create Date: 2026-09-20 09:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b17e4c8d2a63"
down_revision: Union[str, Sequence[str], None] = "9a4e1c6b8d32"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "collector_deployments",
        sa.Column("scope_device_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "collector_deployments",
        sa.Column("scope_site", sa.String(length=128), nullable=True),
    )
    op.create_index(
        op.f("ix_collector_deployments_scope_device_id"),
        "collector_deployments",
        ["scope_device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_collector_deployments_scope_site"),
        "collector_deployments",
        ["scope_site"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_collector_deployments_scope_site"),
        table_name="collector_deployments",
    )
    op.drop_index(
        op.f("ix_collector_deployments_scope_device_id"),
        table_name="collector_deployments",
    )
    op.drop_column("collector_deployments", "scope_site")
    op.drop_column("collector_deployments", "scope_device_id")
