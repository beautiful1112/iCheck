"""Index namespace-local Investigation history keyset traversal.

Revision ID: r6t8v0x2z4b7
Revises: q5s7u9w1y3a6
"""

from alembic import op
import sqlalchemy as sa


revision = "r6t8v0x2z4b7"
down_revision = "q5s7u9w1y3a6"
branch_labels = depends_on = None

INDEX = "ix_investigations_history"


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("SET LOCAL lock_timeout = '10s'"))
    op.create_index(
        INDEX, "investigations",
        ["tenant_id", "region_id", "created_at", "id"],
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("SET LOCAL lock_timeout = '10s'"))
    op.drop_index(INDEX, table_name="investigations")
