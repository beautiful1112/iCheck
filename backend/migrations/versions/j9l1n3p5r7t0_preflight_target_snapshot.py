"""Bind preflight history to the target and site used by its claim.

Revision ID: j9l1n3p5r7t0
Revises: i8k0m2p4r6t9
"""

from alembic import op
import sqlalchemy as sa


revision = "j9l1n3p5r7t0"
down_revision = "i8k0m2p4r6t9"
branch_labels = depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_connection_preflights",
        sa.Column("target_host", sa.String(length=45), nullable=True),
    )
    op.add_column(
        "device_connection_preflights",
        sa.Column("site_snapshot", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    snapshots = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM device_connection_preflights "
        "WHERE target_host IS NOT NULL OR site_snapshot IS NOT NULL"
    )).scalar_one()
    if snapshots:
        raise RuntimeError("Cannot discard preflight target history")
    op.drop_column("device_connection_preflights", "site_snapshot")
    op.drop_column("device_connection_preflights", "target_host")
