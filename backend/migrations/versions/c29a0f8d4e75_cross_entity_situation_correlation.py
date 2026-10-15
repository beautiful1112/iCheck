"""evidence-backed cross-entity Situation correlation

Revision ID: c29a0f8d4e75
Revises: b18f9e7c3d64
Create Date: 2026-09-28 10:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c29a0f8d4e75"
down_revision: str | None = "b18f9e7c3d64"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("situation_alerts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "correlation_confidence",
                sa.Float(),
                nullable=False,
                server_default="1.0",
            )
        )
        batch_op.add_column(
            sa.Column(
                "correlation_evidence",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.create_check_constraint(
            "ck_situation_alert_correlation_confidence",
            "correlation_confidence >= 0 AND correlation_confidence <= 1",
        )


def downgrade() -> None:
    with op.batch_alter_table("situation_alerts") as batch_op:
        batch_op.drop_constraint(
            "ck_situation_alert_correlation_confidence",
            type_="check",
        )
        batch_op.drop_column("correlation_evidence")
        batch_op.drop_column("correlation_confidence")
