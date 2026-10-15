"""Append-only independent review of MCP lookup evidence."""
from alembic import op
import sqlalchemy as sa

revision = "z8r6t4v2x0y9"
down_revision = "k4m6o8q0s2u5"
branch_labels = depends_on = None
TABLE = "mcp_write_reconciliation_reviews"


def upgrade():
    bind = op.get_bind()
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observation_id", sa.String(36), sa.ForeignKey("mcp_write_reconciliation_observations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reviewed_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("observation_id", name="uq_mcp_write_recon_review_observation"),
        sa.CheckConstraint("decision IN ('accept', 'reject', 'inconclusive')", name="ck_mcp_write_recon_review_decision"),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_recon_review_reason"),
    )
    for column in ("proposal_id", "observation_id", "reviewed_by_principal_id", "tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index("ix_mcp_write_recon_review_proposal", TABLE, ["tenant_id", "region_id", "proposal_id", "reviewed_at"])
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text("""CREATE FUNCTION icheck_mcp_write_recon_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'MCP write reconciliation reviews are immutable';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM mcp_write_reconciliation_observations observation
            JOIN agent_action_proposals proposal ON proposal.id=observation.proposal_id
            JOIN investigations investigation ON investigation.id=proposal.investigation_id
            JOIN investigation_tool_calls original_call ON original_call.id=observation.original_tool_call_id
            JOIN investigation_tool_calls lookup_call ON lookup_call.id=observation.lookup_tool_call_id
            LEFT JOIN mcp_tool_activations write_activation ON write_activation.id=original_call.artifact_activation_id
            LEFT JOIN artifact_versions write_version ON write_version.id=original_call.artifact_version_id
            LEFT JOIN mcp_tool_activations lookup_activation ON lookup_activation.id=lookup_call.artifact_activation_id
            LEFT JOIN artifact_versions lookup_version ON lookup_version.id=lookup_call.artifact_version_id
            WHERE observation.id=NEW.observation_id
              AND observation.proposal_id=NEW.proposal_id
              AND observation.tenant_id=NEW.tenant_id AND observation.region_id=NEW.region_id
              AND proposal.tenant_id=NEW.tenant_id AND proposal.region_id=NEW.region_id
              AND investigation.tenant_id=NEW.tenant_id AND investigation.region_id=NEW.region_id
              AND original_call.tenant_id=NEW.tenant_id AND original_call.region_id=NEW.region_id
              AND lookup_call.tenant_id=NEW.tenant_id AND lookup_call.region_id=NEW.region_id
              AND proposal.tool_call_id=original_call.id
              AND proposal.status='executing' AND original_call.status='running'
              AND investigation.status IN ('escalated','failed','cancelled')
              AND lookup_call.status='succeeded' AND lookup_call.result_hash=observation.lookup_result_hash
              AND observation.recorded_by_principal_id IS NOT NULL
              AND observation.recorded_by_principal_id<>NEW.reviewed_by_principal_id
              AND observation.recorded_by<>NEW.reviewed_by
              AND (
                NEW.decision<>'accept' OR (
                  write_activation.tenant_id=NEW.tenant_id AND write_activation.region_id=NEW.region_id
                  AND write_version.tenant_id=NEW.tenant_id AND write_version.region_id=NEW.region_id
                  AND lookup_activation.tenant_id=NEW.tenant_id AND lookup_activation.region_id=NEW.region_id
                  AND lookup_version.tenant_id=NEW.tenant_id AND lookup_version.region_id=NEW.region_id
                  AND write_activation.tool_registration_id=original_call.tool_id
                  AND write_activation.artifact_version_id=write_version.id
                  AND original_call.artifact_content_hash=write_version.content_hash
                  AND original_call.artifact_activation_sha256=write_activation.contract_sha256
                  AND lookup_activation.tool_registration_id=lookup_call.tool_id
                  AND lookup_activation.artifact_version_id=lookup_version.id
                  AND lookup_call.artifact_content_hash=lookup_version.content_hash
                  AND lookup_call.artifact_activation_sha256=lookup_activation.contract_sha256
                  AND (write_version.definition->'spec'->>'read_only')='false'
                  AND (lookup_version.definition->'spec'->>'read_only')='true'
                  AND (write_version.definition->'spec'->>'tool_name')=write_activation.tool_name
                  AND (lookup_version.definition->'spec'->>'tool_name')=lookup_activation.tool_name
                  AND (write_version.definition->'spec'->>'outcome_lookup_tool_name')=lookup_activation.tool_name
                )
              )
        ) THEN
            RAISE EXCEPTION 'MCP write reconciliation review lacks independent exact evidence';
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_mcp_write_recon_review_guard BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_mcp_write_recon_review_guard()"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated MCP write reconciliation reviews")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_mcp_write_recon_review_guard ON {TABLE}"))
        op.execute(sa.text("DROP FUNCTION icheck_mcp_write_recon_review_guard()"))
    op.drop_table(TABLE)
