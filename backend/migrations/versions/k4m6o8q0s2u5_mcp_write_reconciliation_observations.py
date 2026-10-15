"""Append-only evidence from a separate read-only MCP outcome lookup."""
from alembic import op
import sqlalchemy as sa

revision = "k4m6o8q0s2u5"
down_revision = "i3k5m7o9q1s4"
branch_labels = depends_on = None
TABLE = "mcp_write_reconciliation_observations"


def upgrade():
    bind = op.get_bind()
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("original_tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("lookup_tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider_outcome", sa.String(16), nullable=False),
        sa.Column("provider_reference", sa.String(255)),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lookup_result_hash", sa.String(64), nullable=False),
        sa.Column("recorded_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT")),
        sa.Column("recorded_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("lookup_tool_call_id", name="uq_mcp_write_recon_lookup_call"),
        sa.CheckConstraint("provider_outcome IN ('applied', 'not_applied', 'unknown')", name="ck_mcp_write_recon_outcome"),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_recon_reason"),
    )
    for column in ("proposal_id", "original_tool_call_id", "lookup_tool_call_id", "tenant_id", "region_id"):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index("ix_mcp_write_recon_recorded_by", TABLE, ["recorded_by_principal_id"])
    op.create_index("ix_mcp_write_recon_proposal", TABLE, ["tenant_id", "region_id", "proposal_id", "created_at"])
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text("""CREATE FUNCTION icheck_mcp_write_recon_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'MCP write reconciliation observations are immutable';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM agent_action_proposals p
            JOIN investigations i ON i.id=p.investigation_id
            JOIN investigation_tool_calls original_call ON original_call.id=NEW.original_tool_call_id
            JOIN agent_tool_registrations original_tool ON original_tool.id=p.tool_id
            JOIN investigation_tool_calls lookup_call ON lookup_call.id=NEW.lookup_tool_call_id
            JOIN investigations lookup_investigation ON lookup_investigation.id=lookup_call.investigation_id
            JOIN agent_tool_registrations lookup_tool ON lookup_tool.id=lookup_call.tool_id
            JOIN mcp_tool_activations lookup_activation ON lookup_activation.id=lookup_call.artifact_activation_id
            JOIN artifact_versions lookup_version ON lookup_version.id=lookup_call.artifact_version_id
            WHERE p.id=NEW.proposal_id AND p.tool_call_id=original_call.id
              AND p.tenant_id=NEW.tenant_id AND p.region_id=NEW.region_id
              AND i.tenant_id=NEW.tenant_id AND i.region_id=NEW.region_id
              AND original_call.tenant_id=NEW.tenant_id AND original_call.region_id=NEW.region_id
              AND original_tool.tenant_id=NEW.tenant_id AND original_tool.region_id=NEW.region_id
              AND lookup_call.tenant_id=NEW.tenant_id AND lookup_call.region_id=NEW.region_id
              AND lookup_investigation.tenant_id=NEW.tenant_id AND lookup_investigation.region_id=NEW.region_id
              AND lookup_tool.tenant_id=NEW.tenant_id AND lookup_tool.region_id=NEW.region_id
              AND lookup_activation.tenant_id=NEW.tenant_id AND lookup_activation.region_id=NEW.region_id
              AND lookup_version.tenant_id=NEW.tenant_id AND lookup_version.region_id=NEW.region_id
              AND i.status IN ('escalated','failed','cancelled')
              AND p.status='executing' AND original_call.status='running'
              AND original_call.investigation_id=i.id AND original_call.tool_id=p.tool_id
              AND p.arguments::jsonb=original_call.arguments::jsonb
              AND original_tool.transport='mcp' AND NOT original_tool.read_only
              AND lookup_tool.transport='mcp' AND lookup_tool.read_only
              AND lookup_call.investigation_id<>i.id
              AND lookup_call.status='succeeded' AND lookup_call.finished_at IS NOT NULL
              AND lookup_activation.tool_registration_id=lookup_tool.id
              AND lookup_activation.artifact_version_id=lookup_version.id
              AND lookup_call.artifact_content_hash=lookup_version.content_hash
              AND lookup_call.artifact_activation_sha256=lookup_activation.contract_sha256
              AND lookup_call.result_hash=NEW.lookup_result_hash
              AND lookup_call.arguments->>'source_tool_call_id'=original_call.id
              AND lookup_call.result->>'source_tool_call_id'=original_call.id
              AND lookup_call.result->>'provider_outcome'=NEW.provider_outcome
              AND lookup_call.result->>'provider_reference' IS NOT DISTINCT FROM NEW.provider_reference
              AND (lookup_call.result->>'observed_at')::timestamptz=NEW.observed_at
              AND (NEW.provider_outcome='unknown' OR NEW.provider_reference IS NOT NULL)
              AND NEW.observed_at>=original_call.started_at
              AND NEW.observed_at>=lookup_call.started_at-interval '5 minutes'
              AND NEW.observed_at<=lookup_call.finished_at+interval '5 minutes'
        ) THEN
            RAISE EXCEPTION 'MCP write reconciliation observation has no exact bound lookup evidence';
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER icheck_mcp_write_recon_guard BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION icheck_mcp_write_recon_guard()"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated MCP write reconciliation observations")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER icheck_mcp_write_recon_guard ON {TABLE}"))
        op.execute(sa.text("DROP FUNCTION icheck_mcp_write_recon_guard()"))
    op.drop_table(TABLE)
