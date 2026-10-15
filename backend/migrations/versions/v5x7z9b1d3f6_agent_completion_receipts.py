"""Persist the bound receipt for a committed Agent Worker completion.

Revision ID: v5x7z9b1d3f6
Revises: u3w5y7a9c1e4
"""

from alembic import op
import sqlalchemy as sa


revision = "v5x7z9b1d3f6"
down_revision = "u3w5y7a9c1e4"
branch_labels = depends_on = None


def upgrade() -> None:
    for column in (
        "completion_worker_id",
        "completion_token_hash",
        "completion_request_hash",
    ):
        op.add_column(
            "agent_executions",
            sa.Column(column, sa.String(64 if column.endswith("hash") else 36)),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text(
            "SELECT 1 FROM agent_executions "
            "WHERE completion_worker_id IS NOT NULL LIMIT 1"
        )
    ).first():
        raise RuntimeError("Cannot downgrade recorded Agent completion receipts")
    for column in (
        "completion_request_hash",
        "completion_token_hash",
        "completion_worker_id",
    ):
        op.drop_column("agent_executions", column)
