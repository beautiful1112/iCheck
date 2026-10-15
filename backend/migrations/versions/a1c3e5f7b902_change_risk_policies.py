"""governed change risk policies

Revision ID: a1c3e5f7b902
Revises: f7b2d8e0a415
Create Date: 2026-09-29 16:00:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa


revision: str = "a1c3e5f7b902"
down_revision: str | None = "f7b2d8e0a415"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "change_risk_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("risk_class", sa.String(length=16), nullable=False),
        sa.Column("execution_enabled", sa.Boolean(), nullable=False),
        sa.Column("maintenance_window_required", sa.Boolean(), nullable=False),
        sa.Column("max_window_minutes", sa.Integer(), nullable=False),
        sa.Column("require_evidence_summary", sa.Boolean(), nullable=False),
        sa.Column("require_authorization_binding", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("update_reason", sa.String(length=4000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "risk_class IN ('low', 'medium', 'high', 'critical')",
            name="ck_change_risk_policy_risk_class",
        ),
        sa.CheckConstraint(
            "revision > 0",
            name="ck_change_risk_policy_revision",
        ),
        sa.CheckConstraint(
            "max_window_minutes >= 5 AND max_window_minutes <= 480",
            name="ck_change_risk_policy_max_window",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_change_risk_policies_risk_class",
        "change_risk_policies",
        ["risk_class"],
        unique=True,
    )
    now = datetime.now(UTC)
    policy_table = sa.table(
        "change_risk_policies",
        sa.column("id", sa.String),
        sa.column("risk_class", sa.String),
        sa.column("execution_enabled", sa.Boolean),
        sa.column("maintenance_window_required", sa.Boolean),
        sa.column("max_window_minutes", sa.Integer),
        sa.column("require_evidence_summary", sa.Boolean),
        sa.column("require_authorization_binding", sa.Boolean),
        sa.column("revision", sa.Integer),
        sa.column("updated_by", sa.String),
        sa.column("update_reason", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    rows = [
        ("low", False, 480, False, False),
        ("medium", True, 240, False, False),
        ("high", True, 120, False, False),
        ("critical", True, 60, True, True),
    ]
    op.bulk_insert(
        policy_table,
        [
            {
                "id": f"10000000-0000-4000-8000-{index:012d}",
                "risk_class": risk_class,
                "execution_enabled": True,
                "maintenance_window_required": window_required,
                "max_window_minutes": max_window,
                "require_evidence_summary": require_summary,
                "require_authorization_binding": require_binding,
                "revision": 1,
                "updated_by": "system.migration",
                "update_reason": "Built-in governed change risk policy.",
                "created_at": now,
                "updated_at": now,
            }
            for index, (
                risk_class,
                window_required,
                max_window,
                require_summary,
                require_binding,
            ) in enumerate(rows, start=1)
        ],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_change_risk_policies_risk_class",
        table_name="change_risk_policies",
    )
    op.drop_table("change_risk_policies")
