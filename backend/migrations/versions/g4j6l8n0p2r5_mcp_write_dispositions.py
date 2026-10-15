"""Append-only custody for an unresolved MCP write; no determinate outcome."""

from alembic import op
import sqlalchemy as sa


revision = "g4j6l8n0p2r5"
down_revision = "f3h5j7l9n1q4"
branch_labels = depends_on = None
TABLE = "mcp_write_dispositions"
TRIGGER = "icheck_mcp_write_disposition_guard"


def upgrade():
    bind = op.get_bind()
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("original_tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("reviewed_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("tenant_id", "region_id", "request_id", name="uq_mcp_write_disposition_request"),
        sa.CheckConstraint("decision = 'unresolved'", name="ck_mcp_write_disposition_unresolved"),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_disposition_reason"),
    )
    for column in (
        "proposal_id", "original_tool_call_id", "reviewed_by_principal_id",
        "tenant_id", "region_id",
    ):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index(
        "ix_mcp_write_disposition_proposal", TABLE,
        ["tenant_id", "region_id", "proposal_id", "recorded_at"],
    )
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text(f"""CREATE FUNCTION {TRIGGER}() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        provider_refs jsonb;
        independent_refs jsonb;
        expected_refs jsonb;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'MCP write dispositions are append-only';
        END IF;
        -- The parent lock serializes this custody snapshot with child inserts.
        PERFORM 1 FROM agent_action_proposals proposal
        WHERE proposal.id=NEW.proposal_id
          AND proposal.tenant_id=NEW.tenant_id AND proposal.region_id=NEW.region_id
        FOR UPDATE;
        IF NOT FOUND OR NOT EXISTS (
            SELECT 1 FROM agent_action_proposals proposal
            JOIN investigations investigation ON investigation.id=proposal.investigation_id
            JOIN investigation_tool_calls original ON original.id=proposal.tool_call_id
            JOIN agent_tool_registrations tool ON tool.id=proposal.tool_id
            JOIN control_plane_principals reviewer ON reviewer.id=NEW.reviewed_by_principal_id
            WHERE proposal.id=NEW.proposal_id
              AND proposal.tenant_id=NEW.tenant_id AND proposal.region_id=NEW.region_id
              AND investigation.tenant_id=NEW.tenant_id AND investigation.region_id=NEW.region_id
              AND original.tenant_id=NEW.tenant_id AND original.region_id=NEW.region_id
              AND tool.tenant_id=NEW.tenant_id AND tool.region_id=NEW.region_id
              AND reviewer.tenant_id=NEW.tenant_id AND reviewer.principal_type='user'
              AND reviewer.enabled AND reviewer.subject=NEW.reviewed_by
              AND proposal.tool_call_id=NEW.original_tool_call_id
              AND proposal.plan_hash=NEW.plan_hash
              AND proposal.status='executing' AND proposal.execution_started_at IS NOT NULL
              AND investigation.status IN ('escalated','failed','cancelled')
              AND original.investigation_id=investigation.id AND original.tool_id=tool.id
              AND original.status='running' AND original.started_at IS NOT NULL
              AND original.arguments::jsonb=proposal.arguments::jsonb
              AND tool.transport='mcp' AND NOT tool.read_only
              AND proposal.requested_by_principal_id IS DISTINCT FROM reviewer.id
              AND proposal.approved_by_principal_id IS DISTINCT FROM reviewer.id
              AND proposal.requested_by<>reviewer.subject
              AND proposal.approved_by IS DISTINCT FROM reviewer.subject
        ) THEN
            RAISE EXCEPTION 'MCP disposition lacks a separate authorized unknown write';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mcp_write_reconciliation_observations observation
            WHERE observation.proposal_id=NEW.proposal_id
              AND (observation.recorded_by_principal_id=NEW.reviewed_by_principal_id
                   OR observation.recorded_by=NEW.reviewed_by)
        ) OR EXISTS (
            SELECT 1 FROM mcp_write_reconciliation_reviews review
            WHERE review.proposal_id=NEW.proposal_id
              AND (review.reviewed_by_principal_id=NEW.reviewed_by_principal_id
                   OR review.reviewed_by=NEW.reviewed_by)
        ) OR EXISTS (
            SELECT 1 FROM mcp_write_independent_observations observation
            WHERE observation.proposal_id=NEW.proposal_id
              AND (observation.recorded_by_principal_id=NEW.reviewed_by_principal_id
                   OR observation.recorded_by=NEW.reviewed_by)
        ) OR EXISTS (
            SELECT 1 FROM mcp_write_independent_reviews review
            WHERE review.proposal_id=NEW.proposal_id
              AND (review.reviewed_by_principal_id=NEW.reviewed_by_principal_id
                   OR review.reviewed_by=NEW.reviewed_by)
        ) THEN
            RAISE EXCEPTION 'Disposition reviewer participated in the retained evidence';
        END IF;
        IF (SELECT count(*) FROM mcp_write_reconciliation_observations WHERE proposal_id=NEW.proposal_id)>1000
           OR (SELECT count(*) FROM mcp_write_reconciliation_reviews WHERE proposal_id=NEW.proposal_id)>1000
           OR (SELECT count(*) FROM mcp_write_independent_observations WHERE proposal_id=NEW.proposal_id)>1000
           OR (SELECT count(*) FROM mcp_write_independent_reviews WHERE proposal_id=NEW.proposal_id)>1000 THEN
            RAISE EXCEPTION 'MCP disposition evidence exceeds the complete review bound';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mcp_write_reconciliation_reviews review
            LEFT JOIN mcp_write_reconciliation_observations observation
              ON observation.id=review.observation_id AND observation.proposal_id=NEW.proposal_id
            WHERE review.proposal_id=NEW.proposal_id
              AND (observation.id IS NULL OR review.tenant_id<>observation.tenant_id
                   OR review.region_id<>observation.region_id)
        ) OR EXISTS (
            SELECT 1 FROM mcp_write_independent_reviews review
            LEFT JOIN mcp_write_independent_observations observation
              ON observation.id=review.observation_id AND observation.proposal_id=NEW.proposal_id
            WHERE review.proposal_id=NEW.proposal_id
              AND (observation.id IS NULL OR review.tenant_id<>observation.tenant_id
                   OR review.region_id<>observation.region_id)
        ) THEN
            RAISE EXCEPTION 'MCP disposition evidence contains an orphaned review';
        END IF;
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'observation_id', observation.id,
            'lookup_result_hash', observation.lookup_result_hash,
            'review_id', review.id,
            'review_decision', review.decision
        ) ORDER BY observation.id), '[]'::jsonb) INTO provider_refs
        FROM mcp_write_reconciliation_observations observation
        LEFT JOIN mcp_write_reconciliation_reviews review
          ON review.observation_id=observation.id AND review.proposal_id=NEW.proposal_id
        WHERE observation.proposal_id=NEW.proposal_id;
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'observation_id', observation.id,
            'verification_result_hash', observation.verification_result_hash,
            'review_id', review.id,
            'review_decision', review.decision
        ) ORDER BY observation.id), '[]'::jsonb) INTO independent_refs
        FROM mcp_write_independent_observations observation
        LEFT JOIN mcp_write_independent_reviews review
          ON review.observation_id=observation.id AND review.proposal_id=NEW.proposal_id
        WHERE observation.proposal_id=NEW.proposal_id;
        expected_refs := jsonb_build_object(
            'format_version', 'icheck.mcp-write-disposition-refs/v1',
            'provider', provider_refs, 'independent', independent_refs
        );
        IF NEW.evidence_refs::jsonb IS DISTINCT FROM expected_refs THEN
            RAISE EXCEPTION 'MCP disposition evidence references differ from the locked set';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mcp_write_dispositions prior
            WHERE prior.proposal_id=NEW.proposal_id
              AND prior.tenant_id=NEW.tenant_id AND prior.region_id=NEW.region_id
              AND prior.evidence_refs::jsonb=NEW.evidence_refs::jsonb
        ) THEN
            RAISE EXCEPTION 'This complete evidence set already has an unresolved disposition';
        END IF;
        NEW.recorded_at := clock_timestamp();
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(
        f"CREATE TRIGGER {TRIGGER} BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"
    ))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated MCP write dispositions")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION {TRIGGER}()"))
    op.drop_table(TABLE)
