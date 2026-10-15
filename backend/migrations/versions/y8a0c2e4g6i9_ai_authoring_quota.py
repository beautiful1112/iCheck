"""Durable namespace and actor UTC-day admission for structured authoring.

Revision ID: y8a0c2e4g6i9
Revises: x7z9b1d3f5h8
"""

from alembic import op
import sqlalchemy as sa


revision = "y8a0c2e4g6i9"
down_revision = "x7z9b1d3f5h8"
branch_labels = depends_on = None

POLICY = "ai_authoring_quota_policies"
BUCKET = "ai_authoring_quota_buckets"
RESERVATION = "ai_authoring_quota_reservations"


def _namespace_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("tenant_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
                  server_default="00000000-0000-0000-0000-000000000002"),
    )


def _rls(table: str) -> None:
    op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(
        f"CREATE POLICY icheck_namespace_isolation ON {table} "
        "USING (tenant_id = current_setting('icheck.tenant_id', true) "
        "AND region_id = current_setting('icheck.region_id', true)) "
        "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
        "AND region_id = current_setting('icheck.region_id', true))"
    ))


def upgrade() -> None:
    op.create_table(
        POLICY,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("daily_token_limit", sa.BigInteger(), nullable=True),
        sa.Column("actor_daily_token_limit", sa.BigInteger(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", name="uq_ai_authoring_quota_namespace"),
        sa.CheckConstraint("revision > 0", name="ck_ai_authoring_quota_revision"),
        sa.CheckConstraint("daily_token_limit IS NULL OR daily_token_limit > 0",
                           name="ck_ai_authoring_quota_daily_limit"),
        sa.CheckConstraint("actor_daily_token_limit IS NULL OR actor_daily_token_limit > 0",
                           name="ck_ai_authoring_quota_actor_limit"),
    )
    op.create_table(
        BUCKET,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("scope_kind", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(255), nullable=False),
        sa.Column("used_tokens", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "period_start", "scope_kind", "scope_key",
                            name="uq_ai_authoring_quota_bucket"),
        sa.CheckConstraint("scope_kind IN ('namespace', 'actor')",
                           name="ck_ai_authoring_quota_scope_kind"),
        sa.CheckConstraint("used_tokens >= 0", name="ck_ai_authoring_quota_used"),
    )
    op.create_index("ix_ai_authoring_quota_period", BUCKET,
                    ["tenant_id", "region_id", "period_start"])
    op.create_table(
        RESERVATION,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("reserved_tokens", sa.BigInteger(), nullable=False),
        sa.Column("known_tokens", sa.BigInteger(), nullable=False),
        sa.Column("charged_tokens", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("external_charge_unknown", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "region_id", "entity_type", "entity_id",
                            name="uq_ai_authoring_quota_entity"),
        sa.CheckConstraint("status IN ('reserved', 'settled')",
                           name="ck_ai_authoring_quota_reservation_status"),
        sa.CheckConstraint("reserved_tokens > 0 AND known_tokens >= 0 AND charged_tokens >= 0",
                           name="ck_ai_authoring_quota_reservation_tokens"),
    )
    op.create_index("ix_ai_authoring_quota_reservation_period", RESERVATION,
                    ["tenant_id", "region_id", "period_start", "status"])
    if op.get_bind().dialect.name == "postgresql":
        for table in (POLICY, BUCKET, RESERVATION):
            _rls(table)
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_authoring_quota_reservation() "
            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AI quota reservation cannot be deleted'; END IF; "
            "IF OLD.status = 'settled' OR OLD.status != 'reserved' OR NEW.status != 'settled' "
            "OR OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id "
            "OR OLD.region_id IS DISTINCT FROM NEW.region_id "
            "OR OLD.entity_type IS DISTINCT FROM NEW.entity_type OR OLD.entity_id IS DISTINCT FROM NEW.entity_id "
            "OR OLD.actor IS DISTINCT FROM NEW.actor OR OLD.period_start IS DISTINCT FROM NEW.period_start "
            "OR OLD.reserved_tokens IS DISTINCT FROM NEW.reserved_tokens "
            "OR OLD.created_at IS DISTINCT FROM NEW.created_at "
            "THEN RAISE EXCEPTION 'AI quota reservation is sealed'; END IF; "
            "RETURN NEW; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_authoring_quota_reservation "
            f"BEFORE UPDATE OR DELETE ON {RESERVATION} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_ai_authoring_quota_reservation()"
        ))
    elif op.get_bind().dialect.name == "sqlite":
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_authoring_quota_reservation_update "
            f"BEFORE UPDATE ON {RESERVATION} WHEN OLD.status != 'reserved' "
            "OR NEW.status != 'settled' OR OLD.id IS NOT NEW.id "
            "OR OLD.tenant_id IS NOT NEW.tenant_id OR OLD.region_id IS NOT NEW.region_id "
            "OR OLD.entity_type IS NOT NEW.entity_type OR OLD.entity_id IS NOT NEW.entity_id "
            "OR OLD.actor IS NOT NEW.actor OR OLD.period_start IS NOT NEW.period_start "
            "OR OLD.reserved_tokens IS NOT NEW.reserved_tokens OR OLD.created_at IS NOT NEW.created_at "
            "BEGIN SELECT RAISE(ABORT, 'AI quota reservation is sealed'); END"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_authoring_quota_reservation_delete "
            f"BEFORE DELETE ON {RESERVATION} "
            "BEGIN SELECT RAISE(ABORT, 'AI quota reservation cannot be deleted'); END"
        ))


def downgrade() -> None:
    bind = op.get_bind()
    for table in (RESERVATION, BUCKET, POLICY):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot downgrade recorded AI authoring quota history")
    op.drop_table(RESERVATION)
    op.drop_table(BUCKET)
    op.drop_table(POLICY)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_authoring_quota_reservation()"))
