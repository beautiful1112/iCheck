"""Keep an escalated unknown MCP write and its proposal unchanged."""

from alembic import op
import sqlalchemy as sa


revision = "f3h5j7l9n1q4"
down_revision = "e2g4i6k8m0p3"
branch_labels = depends_on = None


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(sa.text("""CREATE FUNCTION icheck_unknown_mcp_call_fence() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.status='running' AND EXISTS (
            SELECT 1 FROM agent_action_proposals proposal
            JOIN investigations investigation ON investigation.id=proposal.investigation_id
            JOIN agent_tool_registrations tool ON tool.id=proposal.tool_id
            WHERE proposal.tool_call_id=OLD.id AND proposal.status='executing'
              AND proposal.tenant_id=OLD.tenant_id AND proposal.region_id=OLD.region_id
              AND investigation.tenant_id=OLD.tenant_id AND investigation.region_id=OLD.region_id
              AND investigation.status IN ('escalated','failed','cancelled')
              AND tool.tenant_id=OLD.tenant_id AND tool.region_id=OLD.region_id
              AND tool.transport='mcp' AND NOT tool.read_only
        ) THEN
            RAISE EXCEPTION 'Unknown MCP write Tool calls are immutable';
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_unknown_mcp_call_fence
        BEFORE UPDATE OR DELETE ON investigation_tool_calls
        FOR EACH ROW EXECUTE FUNCTION icheck_unknown_mcp_call_fence()"""))
    op.execute(sa.text("""CREATE FUNCTION icheck_unknown_mcp_proposal_fence() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.status='executing' AND EXISTS (
            SELECT 1 FROM investigations investigation
            JOIN investigation_tool_calls original ON original.id=OLD.tool_call_id
            JOIN agent_tool_registrations tool ON tool.id=OLD.tool_id
            WHERE investigation.id=OLD.investigation_id
              AND investigation.tenant_id=OLD.tenant_id AND investigation.region_id=OLD.region_id
              AND investigation.status IN ('escalated','failed','cancelled')
              AND original.tenant_id=OLD.tenant_id AND original.region_id=OLD.region_id
              AND original.status='running'
              AND tool.tenant_id=OLD.tenant_id AND tool.region_id=OLD.region_id
              AND tool.transport='mcp' AND NOT tool.read_only
        ) THEN
            RAISE EXCEPTION 'Unknown MCP write proposals are immutable';
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text("""CREATE TRIGGER icheck_unknown_mcp_proposal_fence
        BEFORE UPDATE OR DELETE ON agent_action_proposals
        FOR EACH ROW EXECUTE FUNCTION icheck_unknown_mcp_proposal_fence()"""))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    if bind.execute(sa.text("""SELECT 1 FROM agent_action_proposals proposal
        JOIN investigations investigation ON investigation.id=proposal.investigation_id
        JOIN investigation_tool_calls original ON original.id=proposal.tool_call_id
        JOIN agent_tool_registrations tool ON tool.id=proposal.tool_id
        WHERE proposal.status='executing' AND original.status='running'
          AND investigation.status IN ('escalated','failed','cancelled')
          AND tool.transport='mcp' AND NOT tool.read_only LIMIT 1""")).first():
        raise RuntimeError("Cannot remove unknown MCP write fence while unresolved writes remain")
    op.execute(sa.text("DROP TRIGGER icheck_unknown_mcp_proposal_fence ON agent_action_proposals"))
    op.execute(sa.text("DROP FUNCTION icheck_unknown_mcp_proposal_fence()"))
    op.execute(sa.text("DROP TRIGGER icheck_unknown_mcp_call_fence ON investigation_tool_calls"))
    op.execute(sa.text("DROP FUNCTION icheck_unknown_mcp_call_fence()"))
