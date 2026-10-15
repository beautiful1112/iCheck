"""Retain read-only target evidence without resolving an uncertain MCP write."""

from alembic import op
import sqlalchemy as sa


revision = "c0e2g4i6k8m1"
down_revision = "b9d1f3h5j7l0"
branch_labels = depends_on = None
TABLE = "mcp_write_independent_observations"
TRIGGER = "icheck_mcp_write_independent_guard"


def upgrade():
    bind = op.get_bind()
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("original_tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("verification_tool_call_id", sa.String(36), sa.ForeignKey("investigation_tool_calls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("verification_kind", sa.String(32), nullable=False),
        sa.Column("observed_target_state", sa.String(16), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_reference", sa.String(255)),
        sa.Column("bound_value_count", sa.Integer(), nullable=False),
        sa.Column("verification_result_hash", sa.String(64), nullable=False),
        sa.Column("recorded_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("recorded_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("verification_tool_call_id", name="uq_mcp_write_independent_call"),
        sa.CheckConstraint("verification_kind IN ('target_state', 'recipient_receipt')", name="ck_mcp_write_independent_kind"),
        sa.CheckConstraint("observed_target_state IN ('present', 'absent', 'unknown')", name="ck_mcp_write_independent_state"),
        sa.CheckConstraint("bound_value_count BETWEEN 1 AND 8", name="ck_mcp_write_independent_bindings"),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_independent_reason"),
    )
    for column in (
        "proposal_id", "original_tool_call_id", "verification_tool_call_id",
        "recorded_by_principal_id", "tenant_id", "region_id",
    ):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index("ix_mcp_write_independent_proposal", TABLE, ["tenant_id", "region_id", "proposal_id", "created_at"])
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text(f"""CREATE FUNCTION {TRIGGER}() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
        approved_arguments jsonb;
        verifier_result jsonb;
        contract jsonb;
        binding jsonb;
        expected jsonb;
        observed jsonb;
        binding_path text;
        binding_key text;
        binding_type text;
        binding_count integer;
        max_age integer;
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'Independent MCP observations are immutable';
        END IF;
        NEW.created_at := clock_timestamp();
        SELECT proposal.arguments::jsonb, verifier.result::jsonb,
               write_version.definition::jsonb->'spec'->'independent_verification'
          INTO approved_arguments, verifier_result, contract
          FROM agent_action_proposals proposal
          JOIN investigations original_investigation ON original_investigation.id=proposal.investigation_id
          JOIN investigation_tool_calls original ON original.id=NEW.original_tool_call_id
          JOIN agent_tool_registrations write_tool ON write_tool.id=proposal.tool_id
          JOIN investigation_tool_calls verifier ON verifier.id=NEW.verification_tool_call_id
          JOIN investigations verifier_investigation ON verifier_investigation.id=verifier.investigation_id
          JOIN agent_tool_registrations verifier_tool ON verifier_tool.id=verifier.tool_id
          JOIN mcp_tool_activations write_activation ON write_activation.id=original.artifact_activation_id
          JOIN mcp_tool_activations verifier_activation ON verifier_activation.id=verifier.artifact_activation_id
          JOIN artifact_versions write_version ON write_version.id=original.artifact_version_id
          JOIN artifact_versions verifier_version ON verifier_version.id=verifier.artifact_version_id
          JOIN mcp_servers write_server ON write_server.id=write_activation.server_id
          JOIN mcp_servers verifier_server ON verifier_server.id=verifier_activation.server_id
          JOIN control_plane_principals recorder ON recorder.id=NEW.recorded_by_principal_id
         WHERE proposal.id=NEW.proposal_id AND proposal.tool_call_id=original.id
           AND proposal.tenant_id=NEW.tenant_id AND proposal.region_id=NEW.region_id
           AND original_investigation.tenant_id=NEW.tenant_id AND original_investigation.region_id=NEW.region_id
           AND original.tenant_id=NEW.tenant_id AND original.region_id=NEW.region_id
           AND write_tool.tenant_id=NEW.tenant_id AND write_tool.region_id=NEW.region_id
           AND verifier.tenant_id=NEW.tenant_id AND verifier.region_id=NEW.region_id
           AND verifier_investigation.tenant_id=NEW.tenant_id AND verifier_investigation.region_id=NEW.region_id
           AND verifier_tool.tenant_id=NEW.tenant_id AND verifier_tool.region_id=NEW.region_id
           AND write_activation.tenant_id=NEW.tenant_id AND write_activation.region_id=NEW.region_id
           AND verifier_activation.tenant_id=NEW.tenant_id AND verifier_activation.region_id=NEW.region_id
           AND write_version.tenant_id=NEW.tenant_id AND write_version.region_id=NEW.region_id
           AND verifier_version.tenant_id=NEW.tenant_id AND verifier_version.region_id=NEW.region_id
           AND write_server.tenant_id=NEW.tenant_id AND write_server.region_id=NEW.region_id
           AND verifier_server.tenant_id=NEW.tenant_id AND verifier_server.region_id=NEW.region_id
           AND recorder.tenant_id=NEW.tenant_id AND recorder.subject=NEW.recorded_by
           AND recorder.principal_type='user' AND recorder.enabled
           AND original_investigation.status IN ('escalated','failed','cancelled')
           AND proposal.status='executing' AND proposal.execution_started_at IS NOT NULL
           AND original.status='running' AND original.started_at IS NOT NULL
           AND original.investigation_id=original_investigation.id AND original.tool_id=write_tool.id
           AND proposal.arguments::jsonb=original.arguments::jsonb
           AND write_tool.transport='mcp' AND NOT write_tool.read_only
           AND verifier_tool.transport='mcp' AND verifier_tool.read_only
           AND verifier.investigation_id<>original.investigation_id
           AND verifier.status='succeeded' AND verifier.started_at IS NOT NULL
           AND verifier.finished_at IS NOT NULL AND verifier.result_hash=NEW.verification_result_hash
           AND verifier.finished_at>=verifier.started_at
           AND verifier.arguments->>'source_tool_call_id'=original.id
           AND verifier.result->>'source_tool_call_id'=original.id
           AND verifier.result->>'verification_kind'=NEW.verification_kind
           AND verifier.result->>'observed_target_state'=NEW.observed_target_state
           AND verifier.result->>'evidence_reference' IS NOT DISTINCT FROM NEW.evidence_reference
           AND (verifier.result->>'observed_at')::timestamptz=NEW.observed_at
           AND write_activation.server_id<>verifier_activation.server_id
           AND write_activation.tool_registration_id=write_tool.id
           AND verifier_activation.tool_registration_id=verifier_tool.id
           AND write_activation.artifact_version_id=write_version.id
           AND verifier_activation.artifact_version_id=verifier_version.id
           AND original.artifact_content_hash=write_version.content_hash
           AND verifier.artifact_content_hash=verifier_version.content_hash
           AND original.artifact_activation_sha256=write_activation.contract_sha256
           AND verifier.artifact_activation_sha256=verifier_activation.contract_sha256
           AND write_version.definition->'spec'->>'read_only'='false'
           AND verifier_version.definition->'spec'->>'read_only'='true'
           AND write_version.definition->'spec'->>'tool_name'=write_activation.tool_name
           AND verifier_version.definition->'spec'->>'tool_name'=verifier_activation.tool_name
           AND verifier_tool.name=verifier_activation.tool_name
           AND write_version.definition->'spec'->>'mcp_tool_name'=write_activation.mcp_tool_name
           AND verifier_version.definition->'spec'->>'mcp_tool_name'=verifier_activation.mcp_tool_name
           AND write_version.definition->'spec'->>'mcp_server_name'=write_server.name
           AND verifier_version.definition->'spec'->>'mcp_server_name'=verifier_server.name
           AND write_version.definition->'spec'->'independent_verification'->>'tool_name'=verifier_activation.tool_name;
        IF NOT FOUND OR contract IS NULL THEN
            RAISE EXCEPTION 'Independent MCP observation lacks exact frozen verifier evidence';
        END IF;
        IF contract->>'kind' IS DISTINCT FROM NEW.verification_kind
           OR jsonb_typeof(contract->'bindings') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'Independent MCP observation kind or bindings are invalid';
        END IF;
        binding_count := jsonb_array_length(contract->'bindings');
        IF binding_count NOT BETWEEN 1 AND 8 OR NEW.bound_value_count<>binding_count THEN
            RAISE EXCEPTION 'Independent MCP observation binding count differs';
        END IF;
        IF (SELECT count(DISTINCT value->>'original_argument_path')
            FROM jsonb_array_elements(contract->'bindings'))<>binding_count
           OR (SELECT count(DISTINCT value->>'observed_value_key')
               FROM jsonb_array_elements(contract->'bindings'))<>binding_count THEN
            RAISE EXCEPTION 'Independent MCP observation bindings are not unique';
        END IF;
        IF NEW.verification_kind='recipient_receipt' AND NOT (
            contract->'bindings' @> '[{{"observed_value_key":"recipient_id"}}]'::jsonb
            AND contract->'bindings' @> '[{{"observed_value_key":"document_digest"}}]'::jsonb
        ) THEN
            RAISE EXCEPTION 'Recipient verification needs recipient and document bindings';
        END IF;
        IF NEW.observed_target_state<>'unknown' AND NEW.evidence_reference IS NULL THEN
            RAISE EXCEPTION 'Determinate independent observation needs a reference';
        END IF;
        IF NEW.evidence_reference IS NOT NULL AND NEW.evidence_reference !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{{0,254}}$' THEN
            RAISE EXCEPTION 'Independent observation reference must be opaque';
        END IF;
        max_age := COALESCE((contract->>'max_age_seconds')::integer, 300);
        IF max_age NOT BETWEEN 60 AND 3600 OR NEW.observed_at<(
            SELECT started_at FROM investigation_tool_calls WHERE id=NEW.original_tool_call_id
        ) OR NEW.observed_at<(
            SELECT started_at FROM investigation_tool_calls WHERE id=NEW.verification_tool_call_id
        )-interval '5 minutes' OR NEW.observed_at>(
            SELECT finished_at FROM investigation_tool_calls WHERE id=NEW.verification_tool_call_id
        )+interval '5 minutes' OR NEW.observed_at>NEW.created_at+interval '5 minutes'
           OR NEW.created_at-NEW.observed_at>make_interval(secs => max_age) THEN
            RAISE EXCEPTION 'Independent MCP observation is not fresh';
        END IF;
        FOR binding IN SELECT value FROM jsonb_array_elements(contract->'bindings') LOOP
            binding_path := binding->>'original_argument_path';
            binding_key := binding->>'observed_value_key';
            binding_type := binding->>'value_type';
            IF binding_path IS NULL OR binding_path !~ '^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*$'
               OR binding_key IS NULL OR binding_key !~ '^[A-Za-z_][A-Za-z0-9_]*$' THEN
                RAISE EXCEPTION 'Independent MCP binding path is invalid';
            END IF;
            IF lower(binding_path) ~ '(auth|community|credential|key|passphrase|password|private|secret|token)'
               OR lower(binding_key) ~ '(auth|community|credential|key|passphrase|password|private|secret|token)' THEN
                RAISE EXCEPTION 'Independent MCP binding cannot expose credentials';
            END IF;
            expected := jsonb_extract_path(approved_arguments, VARIADIC string_to_array(binding_path, '.'));
            observed := verifier_result->'values'->binding_key;
            IF expected IS NULL OR observed IS NULL OR binding_type IS NULL
               OR expected<>observed OR (
                binding_type='string' AND jsonb_typeof(expected)<>'string'
            ) OR (
                binding_type='boolean' AND jsonb_typeof(expected)<>'boolean'
            ) OR (
                binding_type='integer' AND (jsonb_typeof(expected)<>'number' OR expected::text !~ '^-?[0-9]+$'
                    OR observed::text !~ '^-?[0-9]+$')
            ) OR (
                binding_type='number' AND jsonb_typeof(expected)<>'number'
            ) OR binding_type NOT IN ('string','boolean','integer','number') THEN
                RAISE EXCEPTION 'Independent MCP observed target differs from approved arguments';
            END IF;
        END LOOP;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER {TRIGGER} BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated independent MCP observations")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION {TRIGGER}()"))
    op.drop_table(TABLE)
