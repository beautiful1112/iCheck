"""Seal contradictory or late model-call settlement reports.

Revision ID: b1d3f5h7j9l2
Revises: a0c2e4g6i8k1
"""

from alembic import op
import sqlalchemy as sa


revision = "b1d3f5h7j9l2"
down_revision = "a0c2e4g6i8k1"
branch_labels = depends_on = None

TABLE = "ai_authoring_quota_settlement_conflicts"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("reservation_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_reservations.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("reported_known_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reported_external_charge_unknown", sa.Boolean(), nullable=False),
        sa.Column("settled_known_tokens_snapshot", sa.BigInteger(), nullable=False),
        sa.Column("settled_external_charge_unknown_snapshot", sa.Boolean(), nullable=False),
        sa.Column("settled_charged_tokens_snapshot", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "region_id", "reservation_id", "reported_known_tokens",
            "reported_external_charge_unknown", name="uq_ai_quota_settlement_conflict_report",
        ),
        sa.CheckConstraint(
            "reported_known_tokens >= 0 AND settled_known_tokens_snapshot >= 0 "
            "AND settled_charged_tokens_snapshot >= 0",
            name="ck_ai_quota_settlement_conflict_tokens",
        ),
    )
    op.create_index(
        "ix_ai_quota_settlement_conflict_recorded", TABLE,
        ["tenant_id", "region_id", "recorded_at", "id"],
    )
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            f"CREATE POLICY icheck_namespace_isolation ON {TABLE} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true))"
        ))
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_quota_settlement_conflict() "
            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            "RAISE EXCEPTION 'AI quota settlement conflict is append-only'; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_settlement_conflict "
            f"BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_ai_quota_settlement_conflict()"
        ))
    elif dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(sa.text(
                f"CREATE TRIGGER icheck_sealed_ai_quota_settlement_conflict_{action.lower()} "
                f"BEFORE {action} ON {TABLE} "
                "BEGIN SELECT RAISE(ABORT, 'AI quota settlement conflict is append-only'); END"
            ))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard AI quota settlement conflict history")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_settlement_conflict()"))
