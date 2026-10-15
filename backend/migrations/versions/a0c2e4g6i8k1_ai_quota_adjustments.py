"""Independent manual billing review and append-only quota adjustment ledger.

Revision ID: a0c2e4g6i8k1
Revises: z9b1d3f5h7j0
"""

from alembic import op
import sqlalchemy as sa


revision = "a0c2e4g6i8k1"
down_revision = "z9b1d3f5h7j0"
branch_labels = depends_on = None

CASE = "ai_authoring_quota_reconciliation_cases"
ADJUSTMENT = "ai_authoring_quota_adjustments"


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
        CASE,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("reservation_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_reservations.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("source_entity_type", sa.String(64), nullable=True),
        sa.Column("source_entity_id", sa.String(36), nullable=True),
        sa.Column("source_step", sa.Integer(), nullable=True),
        sa.Column("known_tokens_snapshot", sa.BigInteger(), nullable=False),
        sa.Column("original_charged_tokens", sa.BigInteger(), nullable=False),
        sa.Column("confirmed_total_tokens", sa.BigInteger(), nullable=False),
        sa.Column("delta_tokens", sa.BigInteger(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_reference", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("proposed_by_principal_id", sa.String(36), nullable=False),
        sa.Column("proposed_by", sa.String(255), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reviewed_by_principal_id", sa.String(36), nullable=True),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("review_reason", sa.String(1000), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('proposed', 'applied', 'rejected')",
                           name="ck_ai_quota_reconciliation_status"),
        sa.CheckConstraint(
            "known_tokens_snapshot >= 0 AND original_charged_tokens >= 0 "
            "AND confirmed_total_tokens >= known_tokens_snapshot",
            name="ck_ai_quota_reconciliation_tokens",
        ),
        sa.CheckConstraint(
            "delta_tokens = confirmed_total_tokens - original_charged_tokens",
            name="ck_ai_quota_reconciliation_delta",
        ),
        sa.CheckConstraint(
            "(status = 'proposed' AND reviewed_by_principal_id IS NULL AND reviewed_at IS NULL) "
            "OR (status != 'proposed' AND reviewed_by_principal_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="ck_ai_quota_reconciliation_review",
        ),
    )
    op.create_index("ix_ai_quota_reconciliation_reservation", CASE,
                    ["tenant_id", "region_id", "reservation_id"])
    op.create_index("ix_ai_quota_reconciliation_status", CASE,
                    ["tenant_id", "region_id", "status", "proposed_at"])
    op.create_table(
        ADJUSTMENT,
        sa.Column("id", sa.String(36), primary_key=True),
        *_namespace_columns(),
        sa.Column("reservation_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_reservations.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("reconciliation_case_id", sa.String(36), sa.ForeignKey(
            f"{CASE}.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("original_charged_tokens", sa.BigInteger(), nullable=False),
        sa.Column("confirmed_total_tokens", sa.BigInteger(), nullable=False),
        sa.Column("delta_tokens", sa.BigInteger(), nullable=False),
        sa.Column("applied_by_principal_id", sa.String(36), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "reservation_id",
                            name="uq_ai_quota_adjustment_receipt"),
        sa.UniqueConstraint("tenant_id", "region_id", "reconciliation_case_id",
                            name="uq_ai_quota_adjustment_case"),
        sa.CheckConstraint(
            "confirmed_total_tokens >= 0 AND delta_tokens = confirmed_total_tokens - original_charged_tokens",
            name="ck_ai_quota_adjustment_delta",
        ),
    )
    op.create_index("ix_ai_quota_adjustment_period", ADJUSTMENT,
                    ["tenant_id", "region_id", "period_start"])
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        _rls(CASE)
        _rls(ADJUSTMENT)
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_quota_case() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AI quota case cannot be deleted'; END IF; "
            "IF OLD.status != 'proposed' OR NEW.status NOT IN ('applied', 'rejected') "
            "OR OLD.id IS DISTINCT FROM NEW.id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id "
            "OR OLD.region_id IS DISTINCT FROM NEW.region_id "
            "OR OLD.reservation_id IS DISTINCT FROM NEW.reservation_id "
            "OR OLD.actor IS DISTINCT FROM NEW.actor "
            "OR OLD.period_start IS DISTINCT FROM NEW.period_start "
            "OR OLD.source_entity_type IS DISTINCT FROM NEW.source_entity_type "
            "OR OLD.source_entity_id IS DISTINCT FROM NEW.source_entity_id "
            "OR OLD.source_step IS DISTINCT FROM NEW.source_step "
            "OR OLD.known_tokens_snapshot IS DISTINCT FROM NEW.known_tokens_snapshot "
            "OR OLD.original_charged_tokens IS DISTINCT FROM NEW.original_charged_tokens "
            "OR OLD.confirmed_total_tokens IS DISTINCT FROM NEW.confirmed_total_tokens "
            "OR OLD.delta_tokens IS DISTINCT FROM NEW.delta_tokens "
            "OR OLD.evidence_sha256 IS DISTINCT FROM NEW.evidence_sha256 "
            "OR OLD.evidence_reference IS DISTINCT FROM NEW.evidence_reference "
            "OR OLD.reason IS DISTINCT FROM NEW.reason "
            "OR OLD.proposed_by_principal_id IS DISTINCT FROM NEW.proposed_by_principal_id "
            "OR OLD.proposed_by IS DISTINCT FROM NEW.proposed_by "
            "OR OLD.proposed_at IS DISTINCT FROM NEW.proposed_at "
            "OR NEW.reviewed_by_principal_id IS NULL "
            "OR NEW.reviewed_by_principal_id = OLD.proposed_by_principal_id "
            "OR NEW.reviewed_by IS NULL OR NEW.review_reason IS NULL OR NEW.reviewed_at IS NULL "
            "THEN RAISE EXCEPTION 'AI quota case is sealed'; END IF; RETURN NEW; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_case BEFORE UPDATE OR DELETE ON {CASE} "
            "FOR EACH ROW EXECUTE FUNCTION icheck_guard_ai_quota_case()"
        ))
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_ai_quota_adjustment() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'AI quota adjustment is append-only'; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_adjustment BEFORE UPDATE OR DELETE ON {ADJUSTMENT} "
            "FOR EACH ROW EXECUTE FUNCTION icheck_guard_ai_quota_adjustment()"
        ))
    elif dialect == "sqlite":
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_case_update BEFORE UPDATE ON {CASE} "
            "WHEN OLD.status != 'proposed' OR NEW.status NOT IN ('applied', 'rejected') "
            "OR OLD.id IS NOT NEW.id OR OLD.tenant_id IS NOT NEW.tenant_id "
            "OR OLD.region_id IS NOT NEW.region_id OR OLD.reservation_id IS NOT NEW.reservation_id "
            "OR OLD.actor IS NOT NEW.actor "
            "OR OLD.period_start IS NOT NEW.period_start "
            "OR OLD.source_entity_type IS NOT NEW.source_entity_type "
            "OR OLD.source_entity_id IS NOT NEW.source_entity_id "
            "OR OLD.source_step IS NOT NEW.source_step "
            "OR OLD.known_tokens_snapshot IS NOT NEW.known_tokens_snapshot "
            "OR OLD.original_charged_tokens IS NOT NEW.original_charged_tokens "
            "OR OLD.confirmed_total_tokens IS NOT NEW.confirmed_total_tokens "
            "OR OLD.delta_tokens IS NOT NEW.delta_tokens "
            "OR OLD.evidence_sha256 IS NOT NEW.evidence_sha256 "
            "OR OLD.evidence_reference IS NOT NEW.evidence_reference "
            "OR OLD.reason IS NOT NEW.reason "
            "OR OLD.proposed_by_principal_id IS NOT NEW.proposed_by_principal_id "
            "OR OLD.proposed_by IS NOT NEW.proposed_by OR OLD.proposed_at IS NOT NEW.proposed_at "
            "OR NEW.reviewed_by_principal_id IS NULL "
            "OR NEW.reviewed_by_principal_id = OLD.proposed_by_principal_id "
            "OR NEW.reviewed_by IS NULL OR NEW.review_reason IS NULL OR NEW.reviewed_at IS NULL "
            "BEGIN SELECT RAISE(ABORT, 'AI quota case is sealed'); END"
        ))
        for table, label in ((CASE, "case"), (ADJUSTMENT, "adjustment")):
            op.execute(sa.text(
                f"CREATE TRIGGER icheck_no_delete_ai_quota_{label} BEFORE DELETE ON {table} "
                f"BEGIN SELECT RAISE(ABORT, 'AI quota {label} cannot be deleted'); END"
            ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_adjustment_update BEFORE UPDATE ON {ADJUSTMENT} "
            "BEGIN SELECT RAISE(ABORT, 'AI quota adjustment is append-only'); END"
        ))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {ADJUSTMENT} LIMIT 1")).first() or bind.execute(
        sa.text(f"SELECT 1 FROM {CASE} LIMIT 1")
    ).first():
        raise RuntimeError("Cannot discard reviewed AI quota adjustment history")
    op.drop_table(ADJUSTMENT)
    op.drop_table(CASE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_adjustment()"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_case()"))
