"""Preserve known token usage versus unverified provider charge.

Revision ID: x7z9b1d3f5h8
Revises: w6y8a0c2e5g8
"""

from alembic import op
import sqlalchemy as sa


revision = "x7z9b1d3f5h8"
down_revision = "w6y8a0c2e5g8"
branch_labels = depends_on = None


def upgrade() -> None:
    # Existing rows have no reliable charge-uncertainty receipt. NULL means
    # unverified legacy history; never silently reclassify it as charge-free.
    op.add_column(
        "activation_policy_proposals",
        sa.Column("external_charge_unknown", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    if op.get_bind().execute(sa.text(
        "SELECT 1 FROM activation_policy_proposals "
        "WHERE external_charge_unknown IS NOT NULL LIMIT 1"
    )).first():
        raise RuntimeError("Cannot downgrade recorded proposal charge status")
    op.drop_column("activation_policy_proposals", "external_charge_unknown")
