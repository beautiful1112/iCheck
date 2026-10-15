"""Independent review of retained MCP target evidence, without write disposition."""

from alembic import op
import sqlalchemy as sa


revision = "d1f3h5j7l9n2"
down_revision = "c0e2g4i6k8m1"
branch_labels = depends_on = None
TABLE = "mcp_write_independent_reviews"
TRIGGER = "icheck_mcp_write_independent_review_guard"


def upgrade():
    bind = op.get_bind()
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("proposal_id", sa.String(36), sa.ForeignKey("agent_action_proposals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observation_id", sa.String(36), sa.ForeignKey("mcp_write_independent_observations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reviewed_by_principal_id", sa.String(36), sa.ForeignKey("control_plane_principals.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
        sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002"),
        sa.UniqueConstraint("observation_id", name="uq_mcp_write_independent_review_observation"),
        sa.CheckConstraint("decision IN ('accept', 'reject', 'inconclusive')", name="ck_mcp_write_independent_review_decision"),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 1000", name="ck_mcp_write_independent_review_reason"),
    )
    for column in (
        "proposal_id", "observation_id", "reviewed_by_principal_id", "tenant_id", "region_id",
    ):
        op.create_index(f"ix_{TABLE}_{column}", TABLE, [column])
    op.create_index(
        "ix_mcp_write_independent_review_proposal", TABLE,
        ["tenant_id", "region_id", "proposal_id", "reviewed_at"],
    )
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY"))
    predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
    op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {TABLE} USING ({predicate}) WITH CHECK ({predicate})"))
    op.execute(sa.text(f"""CREATE FUNCTION {TRIGGER}() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'Independent MCP reviews are immutable';
        END IF;
        NEW.reviewed_at := clock_timestamp();
        IF NOT EXISTS (
            SELECT 1 FROM mcp_write_independent_observations observation
            JOIN agent_action_proposals proposal ON proposal.id=observation.proposal_id
            JOIN investigations original_investigation ON original_investigation.id=proposal.investigation_id
            JOIN investigation_tool_calls original ON original.id=observation.original_tool_call_id
            JOIN investigation_tool_calls verifier ON verifier.id=observation.verification_tool_call_id
            JOIN investigations verifier_investigation ON verifier_investigation.id=verifier.investigation_id
            JOIN control_plane_principals reviewer ON reviewer.id=NEW.reviewed_by_principal_id
            WHERE observation.id=NEW.observation_id AND observation.proposal_id=NEW.proposal_id
              AND observation.tenant_id=NEW.tenant_id AND observation.region_id=NEW.region_id
              AND proposal.tenant_id=NEW.tenant_id AND proposal.region_id=NEW.region_id
              AND original_investigation.tenant_id=NEW.tenant_id AND original_investigation.region_id=NEW.region_id
              AND original.tenant_id=NEW.tenant_id AND original.region_id=NEW.region_id
              AND verifier.tenant_id=NEW.tenant_id AND verifier.region_id=NEW.region_id
              AND verifier_investigation.tenant_id=NEW.tenant_id AND verifier_investigation.region_id=NEW.region_id
              AND reviewer.tenant_id=NEW.tenant_id
              AND reviewer.principal_type='user' AND reviewer.enabled
              AND reviewer.subject=NEW.reviewed_by
              AND observation.recorded_by_principal_id<>NEW.reviewed_by_principal_id
              AND observation.recorded_by<>NEW.reviewed_by
              AND proposal.tool_call_id=original.id AND proposal.status='executing'
              AND original_investigation.status IN ('escalated','failed','cancelled')
              AND original.status='running' AND original.investigation_id=original_investigation.id
              AND verifier.status='succeeded' AND verifier.investigation_id<>original.investigation_id
              AND verifier.result_hash=observation.verification_result_hash
              AND verifier.arguments->>'source_tool_call_id'=original.id
              AND verifier.result->>'source_tool_call_id'=original.id
              AND verifier.result->>'verification_kind'=observation.verification_kind
              AND verifier.result->>'observed_target_state'=observation.observed_target_state
              AND verifier.result->>'evidence_reference' IS NOT DISTINCT FROM observation.evidence_reference
              AND (verifier.result->>'observed_at')::timestamptz=observation.observed_at
              AND (
                NEW.decision<>'accept' OR EXISTS (
                    SELECT 1 FROM mcp_tool_activations write_activation
                    JOIN mcp_tool_activations verifier_activation
                      ON verifier_activation.id=verifier.artifact_activation_id
                    JOIN artifact_versions write_version ON write_version.id=original.artifact_version_id
                    JOIN artifact_versions verifier_version ON verifier_version.id=verifier.artifact_version_id
                    JOIN mcp_servers write_server ON write_server.id=write_activation.server_id
                    JOIN mcp_servers verifier_server ON verifier_server.id=verifier_activation.server_id
                    WHERE write_activation.id=original.artifact_activation_id
                      AND write_activation.tenant_id=NEW.tenant_id AND write_activation.region_id=NEW.region_id
                      AND verifier_activation.tenant_id=NEW.tenant_id AND verifier_activation.region_id=NEW.region_id
                      AND write_version.tenant_id=NEW.tenant_id AND write_version.region_id=NEW.region_id
                      AND verifier_version.tenant_id=NEW.tenant_id AND verifier_version.region_id=NEW.region_id
                      AND write_server.tenant_id=NEW.tenant_id AND write_server.region_id=NEW.region_id
                      AND verifier_server.tenant_id=NEW.tenant_id AND verifier_server.region_id=NEW.region_id
                      AND write_activation.server_id<>verifier_activation.server_id
                      AND write_activation.tool_registration_id=original.tool_id
                      AND verifier_activation.tool_registration_id=verifier.tool_id
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
                      AND write_version.definition->'spec'->>'mcp_tool_name'=write_activation.mcp_tool_name
                      AND verifier_version.definition->'spec'->>'mcp_tool_name'=verifier_activation.mcp_tool_name
                      AND write_version.definition->'spec'->>'mcp_server_name'=write_server.name
                      AND verifier_version.definition->'spec'->>'mcp_server_name'=verifier_server.name
                      AND write_version.definition->'spec'->'independent_verification'->>'tool_name'=verifier_activation.tool_name
                      AND write_version.definition->'spec'->'independent_verification'->>'kind'=observation.verification_kind
                      AND jsonb_typeof(write_version.definition::jsonb->'spec'->'independent_verification'->'bindings')='array'
                      AND jsonb_array_length(write_version.definition::jsonb->'spec'->'independent_verification'->'bindings')=observation.bound_value_count
                      AND COALESCE((write_version.definition->'spec'->'independent_verification'->>'max_age_seconds')::integer, 300) BETWEEN 60 AND 3600
                      AND observation.created_at-observation.observed_at<=make_interval(
                          secs => COALESCE((write_version.definition->'spec'->'independent_verification'->>'max_age_seconds')::integer, 300)
                      )
                      AND (observation.verification_kind<>'recipient_receipt' OR (
                          write_version.definition::jsonb->'spec'->'independent_verification'->'bindings' @> '[{{"observed_value_key":"recipient_id"}}]'::jsonb
                          AND write_version.definition::jsonb->'spec'->'independent_verification'->'bindings' @> '[{{"observed_value_key":"document_digest"}}]'::jsonb
                      ))
                      AND (
                          SELECT count(DISTINCT value->>'original_argument_path')
                          FROM jsonb_array_elements(write_version.definition::jsonb->'spec'->'independent_verification'->'bindings')
                      )=observation.bound_value_count
                      AND (
                          SELECT count(DISTINCT value->>'observed_value_key')
                          FROM jsonb_array_elements(write_version.definition::jsonb->'spec'->'independent_verification'->'bindings')
                      )=observation.bound_value_count
                      AND NOT EXISTS (
                          SELECT 1 FROM jsonb_array_elements(
                              write_version.definition::jsonb->'spec'->'independent_verification'->'bindings'
                          ) AS binding(value)
                          WHERE binding.value->>'original_argument_path' IS NULL
                             OR binding.value->>'observed_value_key' IS NULL
                             OR binding.value->>'value_type' IS NULL
                             OR binding.value->>'original_argument_path' !~ '^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*$'
                             OR binding.value->>'observed_value_key' !~ '^[A-Za-z_][A-Za-z0-9_]*$'
                             OR lower(binding.value->>'original_argument_path') ~ '(auth|community|credential|key|passphrase|password|private|secret|token)'
                             OR lower(binding.value->>'observed_value_key') ~ '(auth|community|credential|key|passphrase|password|private|secret|token)'
                             OR binding.value->>'value_type' NOT IN ('string','boolean','integer','number')
                             OR jsonb_extract_path(
                                 proposal.arguments::jsonb,
                                 VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                             ) IS NULL
                             OR verifier.result::jsonb->'values'->(binding.value->>'observed_value_key') IS NULL
                             OR jsonb_extract_path(
                              proposal.arguments::jsonb,
                              VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                             ) IS DISTINCT FROM verifier.result::jsonb->'values'->(binding.value->>'observed_value_key')
                             OR (
                                 binding.value->>'value_type'='string' AND jsonb_typeof(jsonb_extract_path(
                                     proposal.arguments::jsonb, VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                                 ))<>'string'
                             ) OR (
                                 binding.value->>'value_type'='boolean' AND jsonb_typeof(jsonb_extract_path(
                                     proposal.arguments::jsonb, VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                                 ))<>'boolean'
                             ) OR (
                                 binding.value->>'value_type' IN ('integer','number') AND jsonb_typeof(jsonb_extract_path(
                                     proposal.arguments::jsonb, VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                                 ))<>'number'
                             ) OR (
                                 binding.value->>'value_type'='integer' AND jsonb_extract_path(
                                     proposal.arguments::jsonb, VARIADIC string_to_array(binding.value->>'original_argument_path', '.')
                                 )::text !~ '^-?[0-9]+$'
                             ) OR (
                                 binding.value->>'value_type'='integer' AND (
                                     verifier.result::jsonb->'values'->(binding.value->>'observed_value_key')
                                 )::text !~ '^-?[0-9]+$'
                             )
                      )
                )
              )
        ) THEN
            RAISE EXCEPTION 'Independent MCP review lacks exact separate-person evidence';
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(f"CREATE TRIGGER {TRIGGER} BEFORE INSERT OR UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade populated independent MCP reviews")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION {TRIGGER}()"))
    op.drop_table(TABLE)
