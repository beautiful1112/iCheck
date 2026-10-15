"""Seal model-audit usage evidence for abandoned hold review.

Revision ID: e4g6i8k0m2n5
Revises: d3f5h7j9l1n4
"""

from alembic import op
import sqlalchemy as sa


revision = "e4g6i8k0m2n5"
down_revision = "d3f5h7j9l1n4"
branch_labels = depends_on = None

TABLE = "ai_authoring_quota_orphan_audit_evidence"


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
        sa.Column("orphan_case_id", sa.String(36), sa.ForeignKey(
            "ai_authoring_quota_orphan_cases.id", ondelete="RESTRICT",
        ), nullable=False),
        sa.Column("known_tokens", sa.BigInteger(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("audit_sha256", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "orphan_case_id",
                            name="uq_ai_quota_orphan_audit_case"),
        sa.CheckConstraint("known_tokens >= 0 AND known_tokens <= 1000000000 "
                           "AND event_count >= 0 AND event_count <= 500",
                           name="ck_ai_quota_orphan_audit_usage"),
        sa.CheckConstraint("length(audit_sha256) = 64",
                           name="ck_ai_quota_orphan_audit_digest"),
    )
    op.create_index("ix_ai_quota_orphan_audit_receipt", TABLE,
                    ["tenant_id", "region_id", "reservation_id"])
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
            "CREATE FUNCTION icheck_guard_ai_quota_orphan_audit_evidence() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'AI quota orphan audit evidence is append-only'; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_audit_evidence "
            f"BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_ai_quota_orphan_audit_evidence()"
        ))
    elif dialect == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(sa.text(
                f"CREATE TRIGGER icheck_sealed_ai_quota_orphan_audit_{operation.lower()} "
                f"BEFORE {operation} ON {TABLE} "
                "BEGIN SELECT RAISE(ABORT, 'AI quota orphan audit evidence is append-only'); END"
            ))


def downgrade() -> None:
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot discard AI quota orphan audit evidence history")
    op.drop_table(TABLE)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_ai_quota_orphan_audit_evidence()"))
