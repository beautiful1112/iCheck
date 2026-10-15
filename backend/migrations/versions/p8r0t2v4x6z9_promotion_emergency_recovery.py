"""Sealed pre-incident policy, ceremony and append-only recovery events."""
from alembic import op
import sqlalchemy as sa

revision = "p8r0t2v4x6z9"
down_revision = "o7q9s1u3w5y8"
branch_labels = depends_on = None
POLICY = "promotion_recovery_policies"
CEREMONY = "promotion_key_recoveries"
EVENT = "promotion_recovery_events"
TABLES = (POLICY, CEREMONY, EVENT)


def _base():
    return [sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), nullable=False)]


def _column(name, kind, nullable=False):
    return sa.Column(name, kind, nullable=nullable)


def upgrade():
    op.create_table(POLICY, *_base(),
        _column("version", sa.Integer()), _column("trustee_key_ids", sa.JSON()), _column("witness_ids", sa.JSON()),
        _column("authority_public_key_pem", sa.Text()), _column("statement_digest_sha256", sa.String(64)),
        _column("authority_signature_sha256", sa.String(64)), _column("signed_policy_snapshot", sa.JSON()),
        _column("transparency_sequence", sa.Integer()), _column("reason", sa.Text()),
        _column("accepted_by", sa.String(255)), _column("accepted_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("source_id", "version", name="uq_promotion_recovery_policy_version"),
        sa.UniqueConstraint("source_id", "statement_digest_sha256", name="uq_promotion_recovery_policy_statement"),
        sa.CheckConstraint("version > 0", name="ck_promotion_recovery_policy_version"))
    op.create_table(CEREMONY, *_base(),
        sa.Column("recovery_policy_id", sa.String(36), sa.ForeignKey(POLICY + ".id", ondelete="RESTRICT"), nullable=False),
        sa.Column("to_trust_key_id", sa.String(36), sa.ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), nullable=False),
        _column("ceremony_uuid", sa.String(36)), _column("statement_digest_sha256", sa.String(64)),
        _column("signed_recovery_snapshot", sa.JSON()), _column("checkpoint_evidence_snapshot", sa.JSON()),
        _column("verified_evidence", sa.JSON()), _column("execute_after", sa.DateTime(timezone=True)),
        _column("proposal_transparency_sequence", sa.Integer()), _column("reason", sa.Text()),
        _column("proposed_by", sa.String(255)), _column("proposed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("source_id", "statement_digest_sha256", name="uq_promotion_key_recovery_statement"),
        sa.UniqueConstraint("source_id", "ceremony_uuid", name="uq_promotion_key_recovery_ceremony"),
        sa.CheckConstraint("execute_after > proposed_at", name="ck_promotion_key_recovery_delay"))
    op.create_table(EVENT, *_base(),
        sa.Column("recovery_policy_id", sa.String(36), sa.ForeignKey(POLICY + ".id", ondelete="RESTRICT"), nullable=False),
        sa.Column("ceremony_id", sa.String(36), sa.ForeignKey(CEREMONY + ".id", ondelete="RESTRICT"), nullable=True),
        _column("event_type", sa.String(32)), _column("checkpoint_evidence_snapshot", sa.JSON(), nullable=True),
        _column("verified_evidence", sa.JSON()), _column("transparency_sequence", sa.Integer()),
        _column("reason", sa.Text()), _column("actor", sa.String(255)), _column("occurred_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("event_type IN ('policy_retired', 'executed', 'cancelled', 'restored')", name="ck_promotion_recovery_event_type"),
        sa.CheckConstraint("(event_type = 'policy_retired' AND ceremony_id IS NULL) OR (event_type <> 'policy_retired' AND ceremony_id IS NOT NULL)", name="ck_promotion_recovery_event_subject"),
        sa.UniqueConstraint("ceremony_id", "event_type", name="uq_promotion_recovery_ceremony_event"))
    op.create_index("uq_promotion_recovery_terminal", EVENT, ["ceremony_id"], unique=True,
        postgresql_where=sa.text("event_type IN ('executed', 'cancelled')"), sqlite_where=sa.text("event_type IN ('executed', 'cancelled')"))
    op.create_index("uq_promotion_recovery_retired_policy", EVENT, ["recovery_policy_id"], unique=True,
        postgresql_where=sa.text("event_type = 'policy_retired'"), sqlite_where=sa.text("event_type = 'policy_retired'"))
    for table in TABLES:
        for field in ("tenant_id", "region_id", "source_id"):
            op.create_index(f"ix_{table}_{field}", table, [field])
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text("CREATE FUNCTION icheck_guard_promotion_recovery_history() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'Promotion recovery history is immutable'; END; $$"))
        for table in TABLES:
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} "
                "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
                "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
            op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION icheck_guard_promotion_recovery_history()"))
    elif dialect == "sqlite":
        for table in TABLES:
            for operation in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_{table}_{operation.lower()} BEFORE {operation} ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'Promotion recovery history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if any(bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar() for table in TABLES):
            raise RuntimeError("Promotion recovery downgrade requires visibility of all namespaces")
        bind.execute(sa.text("LOCK TABLE " + ", ".join(sorted(TABLES)) + " IN ACCESS EXCLUSIVE MODE"))
    if any(bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() for table in TABLES):
        raise RuntimeError("Cannot downgrade recorded promotion recovery history")
    for table in reversed(TABLES):
        op.drop_table(table)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_promotion_recovery_history()"))
