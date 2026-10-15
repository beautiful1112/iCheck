"""Immutable, namespace-local dual-signed promotion key handover history."""
from alembic import op
import sqlalchemy as sa

revision = "n6p8r0t2v4x7"
down_revision = "m5o7q9s1u3w6"
branch_labels = None
depends_on = None
TABLE = "capability_promotion_key_rotations"


def upgrade():
    op.create_table(TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("capability_promotion_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("from_trust_key_id", sa.String(36), sa.ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("to_trust_key_id", sa.String(36), sa.ForeignKey("artifact_trust_keys.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("from_key_fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("to_key_fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_sequence", sa.Integer(), nullable=False),
        sa.Column("latest_statement_digest_sha256", sa.String(64), nullable=True),
        sa.Column("statement_digest_sha256", sa.String(64), nullable=False),
        sa.Column("current_signature_sha256", sa.String(64), nullable=False),
        sa.Column("next_signature_sha256", sa.String(64), nullable=False),
        sa.Column("signed_rotation_snapshot", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("rotated_by", sa.String(255), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "statement_digest_sha256", name="uq_promotion_rotation_namespace_statement"),
        sa.CheckConstraint("promotion_sequence >= 0", name="ck_promotion_rotation_sequence"),
        sa.CheckConstraint("from_trust_key_id <> to_trust_key_id", name="ck_promotion_rotation_distinct_keys"),
        sa.CheckConstraint("expires_at > issued_at", name="ck_promotion_rotation_lifetime"),
        sa.CheckConstraint("(promotion_sequence = 0 AND latest_statement_digest_sha256 IS NULL) OR "
            "(promotion_sequence > 0 AND latest_statement_digest_sha256 IS NOT NULL)", name="ck_promotion_rotation_head"))
    for field in ("tenant_id", "region_id", "source_id", "rotated_at"):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) AND region_id = current_setting('icheck.region_id', true))"))
        op.execute(sa.text("CREATE FUNCTION icheck_guard_promotion_key_rotation_history() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'Promotion key rotation history is immutable'; END; $$"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_immutable_promotion_key_rotation BEFORE UPDATE OR DELETE ON {TABLE} "
            "FOR EACH ROW EXECUTE FUNCTION icheck_guard_promotion_key_rotation_history()"))
    elif bind.dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_promotion_rotation_{operation.lower()} BEFORE {operation} ON {TABLE} "
                "BEGIN SELECT RAISE(ABORT, 'Promotion key rotation history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
            raise RuntimeError("Promotion rotation downgrade requires visibility of all namespaces")
        bind.execute(sa.text(f"LOCK TABLE {TABLE} IN ACCESS EXCLUSIVE MODE"))
    if bind.execute(sa.text(f"SELECT id FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded promotion key rotation history")
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_promotion_key_rotation_history()"))
