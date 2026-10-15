"""Make recorded transparency checkpoint offers and attestations append-only."""
from alembic import op
import sqlalchemy as sa

revision = "r2t4v6x8z0b3"
down_revision = "q1s3u5w7y9a2"
branch_labels = depends_on = None

TABLES = (
    "capability_transparency_checkpoint_offers",
    "capability_transparency_witness_attestations",
)


def upgrade():
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text("""
            CREATE FUNCTION icheck_guard_witness_proof_history()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'Witness proof history is immutable';
            END; $$
        """))
        for table in TABLES:
            op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{table} "
                f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
                "EXECUTE FUNCTION icheck_guard_witness_proof_history()"))
    elif dialect == "sqlite":
        for table in TABLES:
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{table}_{action.lower()} "
                    f"BEFORE {action} ON {table} BEGIN "
                    "SELECT RAISE(ABORT, 'Witness proof history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if any(bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar()
               for table in TABLES):
            raise RuntimeError("Witness proof downgrade requires visibility of all namespaces")
        bind.execute(sa.text("LOCK TABLE " + ", ".join(sorted(TABLES)) + " IN ACCESS EXCLUSIVE MODE"))
    if any(bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() for table in TABLES):
        raise RuntimeError("Cannot downgrade recorded witness proof history")
    if bind.dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f"DROP TRIGGER icheck_seal_{table} ON {table}"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_witness_proof_history()"))
    elif bind.dialect.name == "sqlite":
        for table in TABLES:
            for action in ("UPDATE", "DELETE"):
                op.execute(sa.text(f"DROP TRIGGER icheck_seal_{table}_{action.lower()}"))
