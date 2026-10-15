"""Record namespace-local, immutable trust-domain bootstrap retries."""
from alembic import op
import sqlalchemy as sa


revision = "u3w5y7a9c1e4"
down_revision = "r2t4v6x8z0b3"
branch_labels = depends_on = None

TABLE = "organization_trust_domain_creation_receipts"
ERROR = "Trust-domain creation receipts are immutable"


def upgrade():
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False,
            server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False,
            server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("trust_domain_id", sa.String(36),
            sa.ForeignKey("organization_trust_domains.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("idempotency_key_sha256", sa.String(64), nullable=False),
        sa.Column("request_digest_sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "region_id", "idempotency_key_sha256",
            name="uq_trust_domain_creation_namespace_key"),
        sa.UniqueConstraint("trust_domain_id", name="uq_trust_domain_creation_receipt_domain"),
    )
    op.create_index(f"ix_{TABLE}_trust_domain_id", TABLE, ["trust_domain_id"])
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true))"))
        op.execute(sa.text("CREATE FUNCTION icheck_guard_trust_domain_creation_receipt() "
            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            f"RAISE EXCEPTION '{ERROR}'; END; $$"))
        op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{TABLE} "
            f"BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_trust_domain_creation_receipt()"))
    elif dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{TABLE}_{action.lower()} "
                f"BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT, '{ERROR}'); END"))


def downgrade():
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar():
            raise RuntimeError("Trust-domain creation receipt downgrade requires all-namespace visibility")
        bind.execute(sa.text(f"LOCK TABLE {TABLE} IN ACCESS EXCLUSIVE MODE"))
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded trust-domain creation receipts")
    if dialect == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_seal_{TABLE} ON {TABLE}"))
        op.execute(sa.text(f"DROP POLICY icheck_namespace_isolation ON {TABLE}"))
        op.execute(sa.text(f"ALTER TABLE {TABLE} DISABLE ROW LEVEL SECURITY"))
    elif dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(sa.text(f"DROP TRIGGER icheck_seal_{TABLE}_{action.lower()}"))
    op.drop_index(f"ix_{TABLE}_trust_domain_id", table_name=TABLE)
    op.drop_table(TABLE)
    if dialect == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_trust_domain_creation_receipt()"))
