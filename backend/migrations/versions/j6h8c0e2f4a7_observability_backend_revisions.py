"""add optimistic revisions to observability backends

Revision ID: j6h8c0e2f4a7
Revises: i5g7b9d1e3f6
Create Date: 2026-09-29 18:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "j6h8c0e2f4a7"
down_revision: str | None = "i5g7b9d1e3f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _upgrade_backend(table_name: str, constraint_name: str) -> None:
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.create_check_constraint(constraint_name, "revision >= 0")


def _downgrade_backend(table_name: str, constraint_name: str) -> None:
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.drop_column("revision")


def upgrade() -> None:
    _upgrade_backend("metric_backends", "ck_metric_backend_revision")
    _upgrade_backend("log_backends", "ck_log_backend_revision")


def downgrade() -> None:
    _downgrade_backend("log_backends", "ck_log_backend_revision")
    _downgrade_backend("metric_backends", "ck_metric_backend_revision")
