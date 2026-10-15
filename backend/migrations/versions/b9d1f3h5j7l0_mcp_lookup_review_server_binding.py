"""Require the frozen write and accepted lookup to share one MCP server."""

from alembic import op
import sqlalchemy as sa


revision = "b9d1f3h5j7l0"
down_revision = "z8r6t4v2x0y9"
branch_labels = depends_on = None
TABLE = "mcp_write_reconciliation_reviews"
TRIGGER = "icheck_mcp_write_recon_server_guard"


def _binding_query(review: str) -> str:
    """Use one exact predicate for retained-review upgrade and new inserts."""
    return f"""SELECT 1 FROM mcp_write_reconciliation_observations observation
            JOIN agent_action_proposals proposal ON proposal.id=observation.proposal_id
            JOIN investigation_tool_calls original_call ON original_call.id=observation.original_tool_call_id
            JOIN investigation_tool_calls lookup_call ON lookup_call.id=observation.lookup_tool_call_id
            JOIN mcp_tool_activations write_activation ON write_activation.id=original_call.artifact_activation_id
            JOIN mcp_tool_activations lookup_activation ON lookup_activation.id=lookup_call.artifact_activation_id
            JOIN artifact_versions write_version ON write_version.id=original_call.artifact_version_id
            JOIN artifact_versions lookup_version ON lookup_version.id=lookup_call.artifact_version_id
            JOIN mcp_servers write_server ON write_server.id=write_activation.server_id
            JOIN mcp_servers lookup_server ON lookup_server.id=lookup_activation.server_id
            WHERE observation.id={review}.observation_id
              AND observation.proposal_id={review}.proposal_id
              AND proposal.id={review}.proposal_id
              AND proposal.tool_call_id=original_call.id
              AND observation.tenant_id={review}.tenant_id AND observation.region_id={review}.region_id
              AND proposal.tenant_id={review}.tenant_id AND proposal.region_id={review}.region_id
              AND original_call.tenant_id={review}.tenant_id AND original_call.region_id={review}.region_id
              AND lookup_call.tenant_id={review}.tenant_id AND lookup_call.region_id={review}.region_id
              AND write_activation.tenant_id={review}.tenant_id AND write_activation.region_id={review}.region_id
              AND lookup_activation.tenant_id={review}.tenant_id AND lookup_activation.region_id={review}.region_id
              AND write_version.tenant_id={review}.tenant_id AND write_version.region_id={review}.region_id
              AND lookup_version.tenant_id={review}.tenant_id AND lookup_version.region_id={review}.region_id
              AND write_server.tenant_id={review}.tenant_id AND write_server.region_id={review}.region_id
              AND lookup_server.tenant_id={review}.tenant_id AND lookup_server.region_id={review}.region_id
              AND write_activation.server_id=lookup_activation.server_id
              AND write_activation.tool_registration_id=original_call.tool_id
              AND lookup_activation.tool_registration_id=lookup_call.tool_id
              AND write_activation.artifact_version_id=write_version.id
              AND lookup_activation.artifact_version_id=lookup_version.id
              AND original_call.artifact_content_hash=write_version.content_hash
              AND lookup_call.artifact_content_hash=lookup_version.content_hash
              AND original_call.artifact_activation_sha256=write_activation.contract_sha256
              AND lookup_call.artifact_activation_sha256=lookup_activation.contract_sha256
              AND (write_version.definition->'spec'->>'read_only')='false'
              AND (lookup_version.definition->'spec'->>'read_only')='true'
              AND write_version.definition->'spec'->>'tool_name'=write_activation.tool_name
              AND lookup_version.definition->'spec'->>'tool_name'=lookup_activation.tool_name
              AND write_version.definition->'spec'->>'mcp_tool_name'=write_activation.mcp_tool_name
              AND lookup_version.definition->'spec'->>'mcp_tool_name'=lookup_activation.mcp_tool_name
              AND write_version.definition->'spec'->>'mcp_server_name'=write_server.name
              AND lookup_version.definition->'spec'->>'mcp_server_name'=lookup_server.name
              AND write_version.definition->'spec'->>'outcome_lookup_tool_name'=lookup_activation.tool_name"""


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table in (
        TABLE, "mcp_write_reconciliation_observations", "agent_action_proposals",
        "investigation_tool_calls", "mcp_tool_activations", "artifact_versions", "mcp_servers",
    ):
        if bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": table}).scalar():
            raise RuntimeError("Same-server guard upgrade requires all-namespace visibility")
    if bind.execute(sa.text(
        f"SELECT 1 FROM {TABLE} review WHERE review.decision='accept' "
        f"AND NOT EXISTS ({_binding_query('review')}) LIMIT 1"
    )).first():
        raise RuntimeError("Retained accepted MCP lookup review lacks the frozen same-server binding")
    op.execute(sa.text(f"""CREATE FUNCTION {TRIGGER}()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.decision <> 'accept' THEN
            RETURN NEW;
        END IF;
        IF NOT EXISTS ({_binding_query('NEW')}) THEN
            RAISE EXCEPTION 'Accepted MCP lookup review lacks the frozen same-server binding';
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER {TRIGGER} BEFORE INSERT ON {TABLE} "
                       f"FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"))


def downgrade():
    bind = op.get_bind()
    if (bind.dialect.name == "postgresql"
            and bind.execute(sa.text("SELECT row_security_active(:table)"), {"table": TABLE}).scalar()):
        raise RuntimeError("Same-server guard downgrade requires all-namespace review visibility")
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot remove same-server guard with retained reconciliation reviews")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION {TRIGGER}()"))
