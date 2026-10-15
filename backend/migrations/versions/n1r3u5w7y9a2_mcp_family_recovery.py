"""Retain exact consent-family recovery claims and bounded independent proof."""
from alembic import op
import sqlalchemy as sa

revision = "n1r3u5w7y9a2"
down_revision = "m0q2t4v6x8z1"
branch_labels = depends_on = None
TABLE = "mcp_oauth_family_recoveries"
CONSENT = "mcp_oauth_consent_attempts"
OBSERVATIONS = "mcp_write_independent_observations"


def _visible(*tables):
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in tables:
            if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar() is not False:
                raise RuntimeError("Family recovery migration requires actual all-namespace visibility")
    elif bind.dialect.name != "sqlite":
        raise RuntimeError("Family recovery requires PostgreSQL or SQLite")
    return bind


def _binding_limit(bind, old, new):
    if bind.dialect.name == "postgresql":
        definition = bind.scalar(sa.text("SELECT pg_get_functiondef('icheck_mcp_write_independent_guard()'::regprocedure)"))
        fragment = f"binding_count NOT BETWEEN 1 AND {old}"
        if definition.count(fragment) != 1:
            raise RuntimeError("Independent proof guard differs from the expected migration contract")
        # Extend only this existing bound, preserving every provenance/authority guard.
        bind.exec_driver_sql(definition.replace(fragment, f"binding_count NOT BETWEEN 1 AND {new}"))
    with op.batch_alter_table(OBSERVATIONS) as batch:
        batch.drop_constraint("ck_mcp_write_independent_bindings", type_="check")
        batch.create_check_constraint("ck_mcp_write_independent_bindings", f"bound_value_count BETWEEN 1 AND {new}")


def upgrade():
    bind = _visible(CONSENT, OBSERVATIONS)
    op.add_column(CONSENT, sa.Column("family_recovery_id", sa.String(32), nullable=True))
    op.create_table(TABLE,
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.Column("attempt_id", sa.String(36), sa.ForeignKey(CONSENT + ".id", ondelete="RESTRICT"), nullable=False),
        sa.Column("server_id", sa.String(36), nullable=False),
        sa.Column("generation", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("initiated_by", sa.String(36), nullable=False),
        sa.Column("initiated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by", sa.String(36), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("proposal_id", sa.String(36), nullable=True),
        sa.Column("verification_tool_call_id", sa.String(36), nullable=True),
        sa.Column("proof", sa.JSON(none_as_null=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "region_id", "attempt_id", name="uq_mcp_family_recovery_attempt"),
        sa.CheckConstraint("status IN ('awaiting_evidence','issuer_verified')", name="ck_mcp_family_recovery_status"),
        sa.CheckConstraint("(status='awaiting_evidence' AND proof IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL AND proposal_id IS NULL AND verification_tool_call_id IS NULL) OR (status='issuer_verified' AND proof IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND proposal_id IS NOT NULL AND verification_tool_call_id IS NOT NULL AND reviewed_by<>initiated_by AND reviewed_at>=initiated_at)", name="ck_mcp_family_recovery_review"),
    )
    op.create_index("ix_mcp_family_recovery_history", TABLE, ["tenant_id", "region_id", "server_id", "initiated_at", "id"])
    _binding_limit(bind, 8, 16)
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_family_recovery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Family recovery custody cannot be deleted'; END IF;
      IF TG_OP='INSERT' THEN
        IF NEW.status<>'awaiting_evidence' OR NOT EXISTS (
          SELECT 1 FROM {CONSENT} c WHERE c.id=NEW.attempt_id AND c.server_id=NEW.server_id
            AND c.generation=NEW.generation AND c.tenant_id=NEW.tenant_id AND c.region_id=NEW.region_id
            AND c.family_recovery_id IS NULL AND c.status<>'connected'
            AND ((NEW.snapshot::jsonb->'consent')-'authorization_locator')=(c.snapshot::jsonb-'authorization_locator')
            AND NEW.snapshot::jsonb->'target'=c.target::jsonb
            AND NEW.snapshot::jsonb->'locator'->>'transaction_id'=c.transaction_id
            AND (NEW.snapshot::jsonb->'locator'=c.snapshot::jsonb->'authorization_locator' OR (
              (c.snapshot::jsonb->'authorization_locator' IS NULL OR c.snapshot::jsonb->'authorization_locator'='null'::jsonb)
              AND EXISTS (SELECT 1 FROM mcp_oauth_transactions t WHERE t.id=c.transaction_id
                AND t.server_id=c.server_id AND t.tenant_id=c.tenant_id AND t.region_id=c.region_id
                AND t.consumed_at IS NOT NULL AND t.state_hash=NEW.snapshot::jsonb->'locator'->>'state_sha256'))))
        THEN RAISE EXCEPTION 'Family recovery requires the exact unclaimed consent attempt'; END IF;
      ELSE
        IF ROW(NEW.id,NEW.tenant_id,NEW.region_id,NEW.attempt_id,NEW.server_id,NEW.generation,
               NEW.snapshot::jsonb,NEW.initiated_by,NEW.initiated_at)
           IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.region_id,OLD.attempt_id,OLD.server_id,OLD.generation,
               OLD.snapshot::jsonb,OLD.initiated_by,OLD.initiated_at)
        THEN RAISE EXCEPTION 'Original family recovery custody is immutable'; END IF;
        IF OLD.status='issuer_verified' AND ROW(NEW.status,NEW.reviewed_by,NEW.reviewed_at,
             NEW.proposal_id,NEW.verification_tool_call_id,NEW.proof::jsonb)
           IS DISTINCT FROM ROW(OLD.status,OLD.reviewed_by,OLD.reviewed_at,
             OLD.proposal_id,OLD.verification_tool_call_id,OLD.proof::jsonb)
        THEN RAISE EXCEPTION 'Retained issuer containment proof is immutable'; END IF;
        IF NEW.status='issuer_verified' AND OLD.status<>'issuer_verified' AND NOT EXISTS (
          SELECT 1 FROM agent_action_proposals p
          JOIN investigation_tool_calls w ON w.id=p.tool_call_id
          JOIN investigation_tool_calls v ON v.id=NEW.verification_tool_call_id
          JOIN mcp_tool_activations wa ON wa.id=w.artifact_activation_id
          JOIN mcp_tool_activations va ON va.id=v.artifact_activation_id
          JOIN agent_tool_registrations wt ON wt.id=w.tool_id
          JOIN agent_tool_registrations vt ON vt.id=v.tool_id
          JOIN {CONSENT} c ON c.id=NEW.attempt_id
          WHERE p.id=NEW.proposal_id AND p.status IN ('succeeded','executing')
            AND p.approved_by_principal_id IS NOT NULL AND p.approved_by IS NOT NULL
            AND p.decided_at<=p.execution_started_at AND p.execution_started_at>=NEW.initiated_at
            AND w.started_at>=p.execution_started_at AND w.arguments::jsonb=p.arguments::jsonb
            AND w.investigation_id=p.investigation_id AND w.tool_id=p.tool_id
            AND v.investigation_id<>w.investigation_id AND v.status='succeeded'
            AND v.arguments::jsonb->>'source_tool_call_id'=w.id
            AND wt.transport='mcp' AND NOT wt.read_only AND vt.transport='mcp' AND vt.read_only
            AND wa.server_id<>va.server_id AND wa.tool_registration_id=w.tool_id AND va.tool_registration_id=v.tool_id
            AND wa.artifact_version_id=w.artifact_version_id AND va.artifact_version_id=v.artifact_version_id
            AND w.artifact_activation_id=NEW.snapshot::jsonb->'write_tool'->>'activation_id'
            AND v.artifact_activation_id=NEW.snapshot::jsonb->'verification_tool'->>'activation_id'
            AND w.artifact_version_id=NEW.snapshot::jsonb->'write_tool'->>'version_id'
            AND v.artifact_version_id=NEW.snapshot::jsonb->'verification_tool'->>'version_id'
            AND w.artifact_content_hash=NEW.snapshot::jsonb->'write_tool'->>'content_hash'
            AND v.artifact_content_hash=NEW.snapshot::jsonb->'verification_tool'->>'content_hash'
            AND w.artifact_activation_sha256=NEW.snapshot::jsonb->'write_tool'->>'contract_hash'
            AND v.artifact_activation_sha256=NEW.snapshot::jsonb->'verification_tool'->>'contract_hash'
            AND NEW.proof::jsonb->>'original_tool_call_id'=w.id
            AND NEW.proof::jsonb->>'original_plan_hash'=p.plan_hash
            AND NEW.proof::jsonb->>'verification_result_hash'=v.result_hash
            AND NEW.proof::jsonb->>'write_artifact_version_id'=w.artifact_version_id
            AND NEW.proof::jsonb->>'write_artifact_activation_id'=w.artifact_activation_id
            AND NEW.proof::jsonb->>'verification_artifact_version_id'=v.artifact_version_id
            AND NEW.proof::jsonb->>'verification_artifact_activation_id'=v.artifact_activation_id
            AND (NEW.proof::jsonb->>'observed_at')::timestamptz=(v.result::jsonb->>'observed_at')::timestamptz
            AND NEW.proof::jsonb->>'evidence_reference'=v.result::jsonb->>'evidence_reference'
            AND NEW.proof::jsonb->>'family_reference'=v.result::jsonb->'values'->>'family_reference'
            AND NEW.proof::jsonb->>'containment_reference'=v.result::jsonb->'values'->>'containment_reference'
            AND v.result::jsonb->>'source_tool_call_id'=w.id
            AND v.result::jsonb->>'verification_kind'='target_state'
            AND v.result::jsonb->>'observed_target_state'='absent'
            AND (v.result::jsonb->>'observed_at')::timestamptz>=NEW.initiated_at
            AND (w.finished_at IS NULL OR (v.result::jsonb->>'observed_at')::timestamptz>=w.finished_at)
            AND v.result::jsonb->'values' @> jsonb_build_object(
              'recovery_id',NEW.id,'server_id',NEW.server_id,'consent_attempt_id',NEW.attempt_id,
              'consent_generation',NEW.generation,'issuer',c.issuer,'client_id',c.client_id,'resource',c.resource,
              'vault_version',c.target_version,'transaction_id',c.transaction_id,
              'state_sha256',NEW.snapshot::jsonb->'locator'->>'state_sha256',
              'pkce_s256',NEW.snapshot::jsonb->'locator'->>'pkce_s256',
              'family_revoked',true,'issuance_blocked',true,'exclusive_transaction_family',true,
              'containment_scope','authorization_transaction')
            AND p.arguments::jsonb @> jsonb_build_object(
              'recovery_id',NEW.id,'server_id',NEW.server_id,'consent_attempt_id',NEW.attempt_id,
              'consent_generation',NEW.generation,'issuer',c.issuer,'client_id',c.client_id,'resource',c.resource,
              'vault_version',c.target_version,'transaction_id',c.transaction_id,
              'state_sha256',NEW.snapshot::jsonb->'locator'->>'state_sha256',
              'pkce_s256',NEW.snapshot::jsonb->'locator'->>'pkce_s256')
            AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id
            AND w.tenant_id=NEW.tenant_id AND w.region_id=NEW.region_id
            AND v.tenant_id=NEW.tenant_id AND v.region_id=NEW.region_id
            AND wa.tenant_id=NEW.tenant_id AND wa.region_id=NEW.region_id
            AND va.tenant_id=NEW.tenant_id AND va.region_id=NEW.region_id
            AND wt.tenant_id=NEW.tenant_id AND wt.region_id=NEW.region_id
            AND vt.tenant_id=NEW.tenant_id AND vt.region_id=NEW.region_id)
        THEN RAISE EXCEPTION 'Issuer containment proof lacks exact independent provenance'; END IF;
      END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_family_recovery_guard BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_family_recovery_guard()"))
    op.execute(sa.text(f"""CREATE FUNCTION icheck_consent_family_claim_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP='INSERT' AND NEW.family_recovery_id IS NOT NULL
      THEN RAISE EXCEPTION 'Family recovery must claim a retained consent attempt'; END IF;
      IF TG_OP='UPDATE' THEN
        IF OLD.family_recovery_id IS NOT NULL AND NEW.family_recovery_id IS DISTINCT FROM OLD.family_recovery_id
        THEN RAISE EXCEPTION 'Consent family recovery claim is immutable'; END IF;
        IF NEW.family_recovery_id IS NOT NULL THEN
          IF NEW.status IN ('storage_admitted','connected') AND NEW.status IS DISTINCT FROM OLD.status
          THEN RAISE EXCEPTION 'Claimed consent cannot publish new credentials'; END IF;
          IF NOT EXISTS (SELECT 1 FROM {TABLE} r WHERE r.id=NEW.family_recovery_id AND r.attempt_id=NEW.id
                AND r.server_id=NEW.server_id AND r.generation=NEW.generation
                AND r.tenant_id=NEW.tenant_id AND r.region_id=NEW.region_id)
          THEN RAISE EXCEPTION 'Family recovery claim must bind the exact original attempt'; END IF;
        END IF;
      END IF;
      RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_consent_family_claim_guard BEFORE INSERT OR UPDATE ON {CONSENT} FOR EACH ROW EXECUTE FUNCTION icheck_consent_family_claim_guard()"))


def downgrade():
    bind = _visible(CONSENT, TABLE, OBSERVATIONS)
    if (bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first()
            or bind.execute(sa.text(f"SELECT 1 FROM {CONSENT} WHERE family_recovery_id IS NOT NULL LIMIT 1")).first()
            or bind.execute(sa.text(f"SELECT 1 FROM {OBSERVATIONS} WHERE bound_value_count>8 LIMIT 1")).first()):
        raise RuntimeError("Retained family custody or extended independent proof prevents downgrade")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_consent_family_claim_guard ON {CONSENT}"))
        op.execute(sa.text("DROP FUNCTION icheck_consent_family_claim_guard()"))
    _binding_limit(bind, 16, 8)
    op.drop_table(TABLE)
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_family_recovery_guard()"))
    op.drop_column(CONSENT, "family_recovery_id")
