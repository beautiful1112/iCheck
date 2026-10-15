"""add optimistic credential profile reference revisions

Revision ID: g3e5f7a9b1c4
Revises: f2d4e6a8b0c3
Create Date: 2026-09-30 06:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "g3e5f7a9b1c4"
down_revision: str | None = "f2d4e6a8b0c3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("credential_profiles") as batch:
        batch.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.create_check_constraint(
            "ck_credential_profile_revision",
            "revision >= 0",
        )


def downgrade() -> None:
    with op.batch_alter_table("credential_profiles") as batch:
        batch.drop_constraint(
            "ck_credential_profile_revision",
            type_="check",
        )
        batch.drop_column("revision")
