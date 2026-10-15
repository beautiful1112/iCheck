"""add observability backend authentication contracts

Revision ID: i5g7b9d1e3f6
Revises: h4f6a8b0c2d5
Create Date: 2026-09-29 16:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "i5g7b9d1e3f6"
down_revision: str | None = "h4f6a8b0c2d5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _upgrade_backend(table_name: str, constraint_name: str) -> None:
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.add_column(
            sa.Column(
                "auth_type",
                sa.String(length=32),
                server_default="none",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column("auth_header_name", sa.String(length=128), nullable=True)
        )
        batch_op.create_check_constraint(
            constraint_name,
            "auth_type IN ('none', 'bearer', 'basic', 'header')",
        )


def _downgrade_backend(table_name: str, constraint_name: str) -> None:
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.drop_constraint(constraint_name, type_="check")
        batch_op.drop_column("auth_header_name")
        batch_op.drop_column("auth_type")


def upgrade() -> None:
    _upgrade_backend("metric_backends", "ck_metric_backend_auth_type")
    _upgrade_backend("log_backends", "ck_log_backend_auth_type")


def downgrade() -> None:
    _downgrade_backend("log_backends", "ck_log_backend_auth_type")
    _downgrade_backend("metric_backends", "ck_metric_backend_auth_type")
