"""Add an optimistic revision for operator-managed device metadata.

Revision ID: i8k0m2p4r6t9
Revises: h7k9m1p3r5t8
"""

from alembic import op
import sqlalchemy as sa


revision = "i8k0m2p4r6t9"
down_revision = "h7k9m1p3r5t8"
branch_labels = depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    edited = op.get_bind().execute(
        sa.text("SELECT COUNT(*) FROM devices WHERE revision <> 1")
    ).scalar_one()
    if edited:
        raise RuntimeError("Cannot discard edited device metadata revisions")
    op.drop_column("devices", "revision")
