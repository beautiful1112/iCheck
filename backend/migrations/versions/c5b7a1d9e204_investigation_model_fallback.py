"""investigation_model_fallback

Revision ID: c5b7a1d9e204
Revises: a47d8e5c1b90
Create Date: 2026-09-19 08:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c5b7a1d9e204"
down_revision: Union[str, Sequence[str], None] = "a47d8e5c1b90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(
            sa.Column(
                "fallback_model_ids",
                sa.JSON(),
                server_default=sa.text("'[]'"),
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_column("fallback_model_ids")
