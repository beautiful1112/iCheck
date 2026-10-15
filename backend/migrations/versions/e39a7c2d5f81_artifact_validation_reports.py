"""artifact validation reports

Revision ID: e39a7c2d5f81
Revises: d28f5b9e3c74
Create Date: 2026-09-21 03:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e39a7c2d5f81"
down_revision: Union[str, Sequence[str], None] = "d28f5b9e3c74"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "artifact_versions",
        sa.Column(
            "validation_report",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("artifact_versions", "validation_report")
