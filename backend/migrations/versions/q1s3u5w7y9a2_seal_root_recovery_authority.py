"""Seal recorded root-recovery authority and terminal transitions."""
from alembic import op
import sqlalchemy as sa

revision = "q1s3u5w7y9a2"
down_revision = "p8r0t2v4x6z9"
branch_labels = depends_on = None

POLICY = "organization_trust_recovery_policies"
CEREMONY = "organization_trust_root_reanchors"
POLICY_IMMUTABLE = (
    "id", "tenant_id", "region_id", "trust_domain_id", "version", "authority_trust_key_id",
    "authority_key_fingerprint_sha256", "trustee_key_ids", "trustee_key_fingerprints_sha256",
    "required_approvals", "delay_hours", "bundle_sequence", "bundle_digest_sha256",
    "statement_digest_sha256", "authority_signature_sha256", "signed_policy_snapshot",
    "transparency_sequence", "reason", "created_by", "created_at",
)
CEREMONY_IMMUTABLE = (
    "id", "tenant_id", "region_id", "trust_domain_id", "recovery_policy_id", "from_trust_key_id",
    "to_trust_key_id", "ceremony_id", "from_key_fingerprint_sha256", "to_key_fingerprint_sha256",
    "bundle_sequence", "bundle_digest_sha256", "witness_checkpoint_offer_id", "witness_log_id",
    "witness_epoch", "witness_sequence", "witness_head_digest_sha256", "statement_digest_sha256",
    "next_signature_sha256", "trustee_approval_count", "trustee_signature_evidence",
    "signed_reanchor_snapshot", "issued_at", "expires_at", "execute_after",
    "proposal_transparency_sequence", "reason", "proposed_by", "proposed_at",
)
JSON_FIELDS = {"trustee_key_ids", "trustee_key_fingerprints_sha256", "signed_policy_snapshot",
    "trustee_signature_evidence", "signed_reanchor_snapshot"}


def _postgres_changed(fields):
    return " OR ".join(
        (f"OLD.{name}::jsonb IS DISTINCT FROM NEW.{name}::jsonb" if name in JSON_FIELDS
         else f"OLD.{name} IS DISTINCT FROM NEW.{name}") for name in fields)


def _postgres_guard():
    policy_changed = _postgres_changed(POLICY_IMMUTABLE)
    ceremony_changed = _postgres_changed(CEREMONY_IMMUTABLE)
    return f"""
    CREATE FUNCTION icheck_guard_root_recovery_authority() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Root recovery history is immutable'; END IF;
      IF TG_TABLE_NAME = '{POLICY}' THEN
        IF ({policy_changed}) OR OLD.active IS NOT TRUE OR NEW.active IS NOT FALSE
          OR OLD.superseded_at IS NOT NULL OR NEW.superseded_at IS NULL THEN
          RAISE EXCEPTION 'Root recovery history is immutable';
        END IF;
      ELSIF TG_TABLE_NAME = '{CEREMONY}' THEN
        IF ({ceremony_changed}) OR OLD.status <> 'pending' OR NEW.status NOT IN ('executed', 'cancelled') THEN
          RAISE EXCEPTION 'Root recovery history is immutable';
        END IF;
        IF NEW.status = 'executed' AND
          (NEW.execution_checkpoint_offer_id IS NULL OR NEW.execution_transparency_sequence IS NULL
           OR NEW.execution_reason IS NULL OR NEW.executed_by IS NULL OR NEW.executed_at IS NULL
           OR NEW.cancelled_by IS NOT NULL OR NEW.cancelled_at IS NOT NULL) THEN
          RAISE EXCEPTION 'Root recovery terminal evidence is incomplete';
        END IF;
        IF NEW.status = 'cancelled' AND
          (NEW.cancelled_by IS NULL OR NEW.cancelled_at IS NULL OR
           NEW.execution_checkpoint_offer_id IS NOT NULL OR NEW.execution_transparency_sequence IS NOT NULL
           OR NEW.execution_reason IS NOT NULL OR NEW.executed_by IS NOT NULL OR NEW.executed_at IS NOT NULL) THEN
          RAISE EXCEPTION 'Root recovery terminal evidence is incomplete';
        END IF;
      END IF;
      RETURN NEW;
    END; $$
    """


def _sqlite_guard(table, immutable):
    changed = " OR ".join(f"OLD.{name} IS NOT NEW.{name}" for name in immutable)
    if table == POLICY:
        invalid = "OLD.active IS NOT 1 OR NEW.active IS NOT 0 OR OLD.superseded_at IS NOT NULL OR NEW.superseded_at IS NULL"
    else:
        invalid = ("OLD.status <> 'pending' OR NEW.status NOT IN ('executed','cancelled') OR "
            "(NEW.status = 'executed' AND (NEW.execution_checkpoint_offer_id IS NULL OR "
            "NEW.execution_transparency_sequence IS NULL OR NEW.execution_reason IS NULL OR "
            "NEW.executed_by IS NULL OR NEW.executed_at IS NULL OR NEW.cancelled_by IS NOT NULL OR "
            "NEW.cancelled_at IS NOT NULL)) OR "
            "(NEW.status = 'cancelled' AND (NEW.cancelled_by IS NULL OR NEW.cancelled_at IS NULL OR "
            "NEW.execution_checkpoint_offer_id IS NOT NULL OR NEW.execution_transparency_sequence IS NOT NULL OR "
            "NEW.execution_reason IS NOT NULL OR NEW.executed_by IS NOT NULL OR NEW.executed_at IS NOT NULL))")
    return (f"CREATE TRIGGER icheck_seal_{table}_update BEFORE UPDATE ON {table} "
        f"WHEN ({changed}) OR ({invalid}) BEGIN SELECT RAISE(ABORT, 'Root recovery history is immutable'); END")


def upgrade():
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(_postgres_guard()))
        for table in (POLICY, CEREMONY):
            op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{table} BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION icheck_guard_root_recovery_authority()"))
    elif dialect == "sqlite":
        for table, immutable in ((POLICY, POLICY_IMMUTABLE), (CEREMONY, CEREMONY_IMMUTABLE)):
            op.execute(sa.text(_sqlite_guard(table, immutable)))
            op.execute(sa.text(f"CREATE TRIGGER icheck_seal_{table}_delete BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'Root recovery history is immutable'); END"))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        if any(bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar()
               for table in (POLICY, CEREMONY)):
            raise RuntimeError("Root recovery authority downgrade requires visibility of all namespaces")
        bind.execute(sa.text("LOCK TABLE " + ", ".join(sorted((POLICY, CEREMONY))) + " IN ACCESS EXCLUSIVE MODE"))
    if any(bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() for table in (POLICY, CEREMONY)):
        raise RuntimeError("Cannot downgrade recorded root recovery authority")
    if bind.dialect.name == "postgresql":
        for table in (POLICY, CEREMONY):
            op.execute(sa.text(f"DROP TRIGGER icheck_seal_{table} ON {table}"))
        op.execute(sa.text("DROP FUNCTION icheck_guard_root_recovery_authority()"))
    elif bind.dialect.name == "sqlite":
        for table in (POLICY, CEREMONY):
            for operation in ("update", "delete"):
                op.execute(sa.text(f"DROP TRIGGER icheck_seal_{table}_{operation}"))
