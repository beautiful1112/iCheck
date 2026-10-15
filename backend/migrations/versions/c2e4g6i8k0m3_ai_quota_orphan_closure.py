"""Independent review before converting an abandoned hold to unknown charge.

Revision ID: c2e4g6i8k0m3
Revises: b1d3f5h7j9l2
"""

from alembic import op
import sqlalchemy as sa


revision = "c2e4g6i8k0m3"
down_revision = "b1d3f5h7j9l2"
branch_labels = depends_on = None

CASE = "ai_authoring_quota_orphan_cases"
CLOSURE = "ai_authoring_quota_orphan_closures"


def _namespace_columns():
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
        CASE,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("reservation_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_reservations.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("source_entity_type", sa.String(64), nullable=False),
        sa.Column("source_entity_id", sa.String(36), nullable=False),
        sa.Column("source_step", sa.Integer(), nullable=True),
        sa.Column("source_status_snapshot", sa.String(32), nullable=False),
        sa.Column("source_terminal_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reserved_tokens_snapshot", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("proposed_by_principal_id", sa.String(36), nullable=False),
        sa.Column("proposed_by", sa.String(255), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reviewed_by_principal_id", sa.String(36), nullable=True),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("review_reason", sa.String(1000), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('proposed', 'closed', 'rejected')",
                           name="ck_ai_quota_orphan_case_status"),
        sa.CheckConstraint("reserved_tokens_snapshot > 0",
                           name="ck_ai_quota_orphan_case_tokens"),
        sa.CheckConstraint(
            "(status = 'proposed' AND reviewed_by_principal_id IS NULL AND reviewed_at IS NULL) "
            "OR (status != 'proposed' AND reviewed_by_principal_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_ai_quota_orphan_case_review",
        ),
    )
    op.create_index("ix_ai_quota_orphan_case_receipt", CASE,
                    ["tenant_id", "region_id", "reservation_id"])
    op.create_index("ix_ai_quota_orphan_case_status", CASE,
                    ["tenant_id", "region_id", "status", "proposed_at"])
    op.create_table(
        CLOSURE,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("reservation_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_reservations.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("orphan_case_id", sa.String(36), sa.ForeignKey(
            f"{CASE}.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("reserved_tokens", sa.BigInteger(), nullable=False),
        sa.Column("closed_by_principal_id", sa.String(36), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "reservation_id",
                            name="uq_ai_quota_orphan_closure_receipt"),
        sa.UniqueConstraint("tenant_id", "region_id", "orphan_case_id",
                            name="uq_ai_quota_orphan_closure_case"),
        sa.CheckConstraint("reserved_tokens > 0", name="ck_ai_quota_orphan_closure_tokens"),
    )
    op.create_index("ix_ai_quota_orphan_closure_period", CLOSURE,
                    ["tenant_id", "region_id", "period_start"])
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        _rls(CASE)
        _rls(CLOSURE)
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_quota_orphan_case() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            "IF TG_OP = 'INSERT' THEN IF NEW.status != 'proposed' "
            "THEN RAISE EXCEPTION 'AI quota orphan case must be proposed'; END IF; RETURN NEW; END IF; "
            "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AI quota orphan case cannot be deleted'; END IF; "
            "IF OLD.status != 'proposed' OR NEW.status NOT IN ('closed', 'rejected') "
            "OR OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id "
            "OR OLD.region_id IS DISTINCT FROM NEW.region_id "
            "OR OLD.reservation_id IS DISTINCT FROM NEW.reservation_id "
            "OR OLD.actor IS DISTINCT FROM NEW.actor OR OLD.period_start IS DISTINCT FROM NEW.period_start "
            "OR OLD.source_entity_type IS DISTINCT FROM NEW.source_entity_type "
            "OR OLD.source_entity_id IS DISTINCT FROM NEW.source_entity_id "
            "OR OLD.source_step IS DISTINCT FROM NEW.source_step "
            "OR OLD.source_status_snapshot IS DISTINCT FROM NEW.source_status_snapshot "
            "OR OLD.source_terminal_at IS DISTINCT FROM NEW.source_terminal_at "
            "OR OLD.reserved_tokens_snapshot IS DISTINCT FROM NEW.reserved_tokens_snapshot "
            "OR OLD.reason IS DISTINCT FROM NEW.reason "
            "OR OLD.proposed_by_principal_id IS DISTINCT FROM NEW.proposed_by_principal_id "
            "OR OLD.proposed_by IS DISTINCT FROM NEW.proposed_by "
            "OR OLD.proposed_at IS DISTINCT FROM NEW.proposed_at "
            "OR NEW.reviewed_by_principal_id IS NULL "
            "OR NEW.reviewed_by_principal_id = OLD.proposed_by_principal_id "
            "OR NEW.reviewed_by IS NULL OR NEW.reviewed_by = OLD.actor "
            "OR NEW.review_reason IS NULL OR NEW.reviewed_at IS NULL "
            "THEN RAISE EXCEPTION 'AI quota orphan case is sealed'; END IF; RETURN NEW; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_case "
            f"BEFORE INSERT OR UPDATE OR DELETE ON {CASE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_ai_quota_orphan_case()"
        ))
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_quota_orphan_closure() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'AI quota orphan closure is append-only'; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_closure "
            f"BEFORE UPDATE OR DELETE ON {CLOSURE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_ai_quota_orphan_closure()"
        ))
    elif dialect == "sqlite":
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_ai_quota_orphan_case_insert BEFORE INSERT ON {CASE} "
            "WHEN NEW.status != 'proposed' "
            "BEGIN SELECT RAISE(ABORT, 'AI quota orphan case must be proposed'); END"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_case_update BEFORE UPDATE ON {CASE} "
            "WHEN OLD.status != 'proposed' OR NEW.status NOT IN ('closed', 'rejected') "
            "OR OLD.id IS NOT NEW.id OR OLD.tenant_id IS NOT NEW.tenant_id "
            "OR OLD.region_id IS NOT NEW.region_id "
            "OR OLD.reservation_id IS NOT NEW.reservation_id "
            "OR OLD.actor IS NOT NEW.actor OR OLD.period_start IS NOT NEW.period_start "
            "OR OLD.source_entity_type IS NOT NEW.source_entity_type "
            "OR OLD.source_entity_id IS NOT NEW.source_entity_id "
            "OR OLD.source_step IS NOT NEW.source_step "
            "OR OLD.source_status_snapshot IS NOT NEW.source_status_snapshot "
            "OR OLD.source_terminal_at IS NOT NEW.source_terminal_at "
            "OR OLD.reserved_tokens_snapshot IS NOT NEW.reserved_tokens_snapshot "
            "OR OLD.reason IS NOT NEW.reason "
            "OR OLD.proposed_by_principal_id IS NOT NEW.proposed_by_principal_id "
            "OR OLD.proposed_by IS NOT NEW.proposed_by OR OLD.proposed_at IS NOT NEW.proposed_at "
            "OR NEW.reviewed_by_principal_id IS NULL "
            "OR NEW.reviewed_by_principal_id = OLD.proposed_by_principal_id "
            "OR NEW.reviewed_by IS NULL OR NEW.reviewed_by = OLD.actor "
            "OR NEW.review_reason IS NULL OR NEW.reviewed_at IS NULL "
            "BEGIN SELECT RAISE(ABORT, 'AI quota orphan case is sealed'); END"
        ))
        for table, label in ((CASE, "case"), (CLOSURE, "closure")):
            op.execute(sa.text(
                f"CREATE TRIGGER icheck_no_delete_ai_quota_orphan_{label} "
                f"BEFORE DELETE ON {table} "
                f"BEGIN SELECT RAISE(ABORT, 'AI quota orphan {label} cannot be deleted'); END"
            ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_closure_update "
            f"BEFORE UPDATE ON {CLOSURE} "
            "BEGIN SELECT RAISE(ABORT, 'AI quota orphan closure is append-only'); END"
        ))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {CLOSURE} LIMIT 1")).first() or bind.execute(
        sa.text(f"SELECT 1 FROM {CASE} LIMIT 1")
    ).first():
        raise RuntimeError("Cannot discard AI quota orphan recovery history")
    op.drop_table(CLOSURE)
    op.drop_table(CASE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_orphan_closure()"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_orphan_case()"))
