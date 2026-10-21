import pytest

from icheck import database_release, worker_database_roles as grants
from icheck.models import Base


def test_lease_profile_is_explicit_and_does_not_reach_approval_or_secret_tables():
    profile = grants.PROFILES["collector-lease-reconciler"]
    assert len(profile) == 10
    assert profile["audit_events"] == ("INSERT",)
    assert profile["device_connections"] == ("SELECT",)
    assert profile["devices"] == ("SELECT",)
    assert grants.COLUMN_GRANTS["collector-lease-reconciler"]["devices"]["UPDATE"] == ("onboarding_status", "updated_at")
    assert not {"credential_profiles", "control_plane_access_tokens", "ai_settings", "change_proposals", "checkpoints"}.intersection(profile)
    assert not any(set(privileges) - {"SELECT", "INSERT", "UPDATE"} for privileges in profile.values())


def test_integration_worker_can_progress_but_cannot_authorize_or_rotate_credentials():
    profile = grants.PROFILES["integration-sync-worker"]
    assert set(profile) == {"alembic_version", "tenants", "regions", "monitoring_integration_connections",
        "monitoring_integration_schedules", "monitoring_integration_syncs", "monitoring_integration_resources", "audit_events"}
    columns = grants.COLUMN_GRANTS["integration-sync-worker"]
    assert columns["monitoring_integration_connections"]["UPDATE"] == ("updated_at",)
    assert not {"enabled", "revision", "connection_revision", "interval_seconds", "updated_by"}.intersection(
        columns["monitoring_integration_schedules"]["UPDATE"])
    assert not any("DELETE" in privileges for privileges in profile.values())


@pytest.mark.parametrize("profile", sorted(grants.PROFILES))
def test_all_profiles_name_real_columns_and_never_grant_blanket_update_or_destruction(profile):
    tables = grants.PROFILES[profile]
    assert not {"control_plane_access_tokens", "control_plane_browser_sessions", "control_plane_oidc_transactions",
                "control_plane_workload_exchanges", "change_proposals", "checkpoints"}.intersection(tables)
    if profile not in {"workflow-dispatch-worker", "scaling-worker"}:
        assert "ai_provider_configs" not in tables
    if profile != "workflow-dispatch-worker":
        assert not {"control_plane_principals", "control_plane_roles",
                    "control_plane_role_bindings"}.intersection(tables)
    for table, permissions in tables.items():
        assert table == "alembic_version" or table in Base.metadata.tables
        assert set(permissions) <= {"SELECT", "INSERT"}
    for table, privileges in grants.COLUMN_GRANTS.get(profile, {}).items():
        assert table in tables
        for privilege, columns in privileges.items():
            assert privilege == "UPDATE" and columns and len(columns) == len(set(columns))
            assert set(columns) <= set(Base.metadata.tables[table].columns.keys())
            assert not {"id", "tenant_id", "region_id"}.intersection(columns)


def test_projection_retains_all_contracts_but_cannot_edit_source_or_credential_identity():
    profile = grants.PROFILES["projection-worker"]
    assert {"wireless_client_sessions", "ip_address_observations", "knowledge_relationships",
            "collector_condition_receipts", "service_indicator_artifact_publications"} <= set(profile)
    columns = grants.COLUMN_GRANTS["projection-worker"]
    assert columns["devices"]["UPDATE"] == ("updated_at",)
    assert columns["collector_deployments"]["UPDATE"] == ("updated_at",)
    assert columns["credential_profiles"]["UPDATE"] == ("updated_at",)
    assert "mac_address" not in columns["endpoints"]["UPDATE"]
    assert "source_retirement_id" not in columns["alerts"]["UPDATE"]
    assert "enabled" not in columns["service_indicator_artifact_bindings"]["UPDATE"]


def test_indicator_role_keeps_query_threshold_and_backend_authority_read_only():
    profile = grants.PROFILES["indicator-worker"]
    assert len(profile) == 11
    columns = grants.COLUMN_GRANTS["indicator-worker"]
    assert columns["metric_backends"]["UPDATE"] == ("updated_at",)
    assert columns["service_indicator_definitions"]["UPDATE"] == ("updated_at",)
    assert "credential_profiles" not in columns
    assert not {"query", "revision", "enabled", "metric_backend_id", "definition_id"}.intersection(
        columns["service_indicator_prometheus_bindings"]["UPDATE"])
    assert "UPDATE" not in profile["service_indicator_observations"]


def test_rollout_role_cannot_replan_publish_approve_or_forge_collection_health():
    profile = grants.PROFILES["rollout-worker"]
    columns = grants.COLUMN_GRANTS["rollout-worker"]
    assert len(profile) == 18
    assert "INSERT" not in set().union(*map(set, (p for t, p in profile.items() if t != "audit_events")))
    assert profile["collector_runs"] == ("SELECT",) and "collector_runs" not in columns
    assert profile["artifact_versions"] == ("SELECT",) and "artifact_versions" not in columns
    assert profile["device_connection_activations"] == ("SELECT",)
    assert set(columns["collector_deployments"]["UPDATE"]) == {
        "artifact_version_id", "lease_worker_id", "lease_token_hash", "lease_expires_at", "next_run_at", "updated_at"}
    assert not {"plan_sha256", "to_version_id", "from_version_id", "scope_site", "batch_size",
                "ring_percentages", "observation_seconds", "created_by"}.intersection(columns["collector_fleet_rollouts"]["UPDATE"])
    assert not {"pre_change_sha256", "post_change_sha256", "ring_index", "deployment_id", "rolled_back_at"}.intersection(
        columns["collector_fleet_rollout_items"]["UPDATE"])
    assert "rollout-worker" not in grants.NAMESPACE_EXEMPT_METADATA


def test_scaling_role_can_only_recommend_not_configure_or_apply_capacity():
    profile = grants.PROFILES["scaling-worker"]
    assert len(profile) == 16
    assert {table for table, permissions in profile.items() if "INSERT" in permissions} == {
        "worker_scaling_decisions", "audit_events"}
    assert grants.COLUMN_GRANTS["scaling-worker"] == {
        "worker_scaling_policies": {"UPDATE": ("updated_at",)}}
    assert not {"worker_scaling_application_events", "credential_profiles", "control_plane_principals",
                "artifacts", "mcp_servers", "collector_runs", "agent_action_proposals"}.intersection(profile)
    assert "scaling-worker" not in grants.NAMESPACE_EXEMPT_METADATA


def test_capacity_role_can_report_and_drain_but_not_recommend_configure_or_claim():
    profile = grants.PROFILES["systemd-capacity-provider"]
    assert len(profile) == 12
    assert {table for table, permissions in profile.items() if "INSERT" in permissions} == {
        "worker_scaling_application_events", "audit_events"}
    assert grants.COLUMN_GRANTS["systemd-capacity-provider"] == {
        "worker_scaling_policies": {"UPDATE": ("updated_at",)},
        "collector_workers": {"UPDATE": ("state", "updated_at")},
        "agent_workers": {"UPDATE": ("state", "updated_at")},
    }
    assert not {"credential_profiles", "ai_provider_configs", "mcp_servers", "artifacts",
                "control_plane_principals", "agent_action_proposals"}.intersection(profile)
    assert "systemd-capacity-provider" not in grants.NAMESPACE_EXEMPT_METADATA


def test_transport_role_can_only_deliver_and_append_verified_public_witness_evidence():
    profile = grants.PROFILES["ecosystem-transport-worker"]
    columns = grants.COLUMN_GRANTS["ecosystem-transport-worker"]
    assert len(profile) == 14
    assert {t for t, p in profile.items() if "INSERT" in p} == {
        "ecosystem_transport_jobs", "ecosystem_transport_workers", "capability_transparency_witness_attestations", "audit_events"}
    for table in ("ecosystem_transport_endpoints", "credential_profiles", "capability_transparency_witnesses",
                  "capability_transparency_witness_policy", "organization_trust_domains"):
        assert columns[table] == {"UPDATE": ("updated_at",)}
    assert columns["artifact_trust_keys"] == {"UPDATE": ("created_at",)}
    assert not {"payload_snapshot", "endpoint_id", "dedupe_key", "max_attempts", "created_by"}.intersection(
        columns["ecosystem_transport_jobs"]["UPDATE"])
    assert not {"ai_provider_configs", "mcp_servers", "control_plane_principals", "artifacts", "artifact_versions",
                "capability_pack_installations", "capability_promotion_receipts", "collector_deployments"}.intersection(profile)
    assert "ecosystem-transport-worker" not in grants.NAMESPACE_EXEMPT_METADATA


def test_quality_role_cannot_edit_policy_evidence_approval_or_secrets():
    profile = grants.PROFILES["quality-worker"]
    columns = grants.COLUMN_GRANTS["quality-worker"]
    assert len(profile) == 35
    assert profile["capability_quality_assessments"] == ("SELECT", "INSERT")
    assert set(columns["capability_quality_policies"]["UPDATE"]) == {
        "last_assessment_id", "next_evaluation_at", "updated_at"}
    assert columns["governed_change_evidence"]["UPDATE"] == ("created_at",)
    assert columns["investigation_tool_calls"]["UPDATE"] == ("started_at",)
    for table in ("collector_runs", "investigations",
                  "agent_action_proposals", "governed_change_plans",
                  "change_preapproval_authorizations", "change_rollback_authorizations"):
        assert profile[table] == ("SELECT",) and table not in columns
    assert not {"credential_profiles", "ai_provider_configs", "mcp_servers", "control_plane_principals",
                "service_catalog_entries", "knowledge_relationships", "devices", "agent_executions"}.intersection(profile)
    assert "quality-worker" not in grants.NAMESPACE_EXEMPT_METADATA


def test_dispatch_role_can_enqueue_and_capture_but_cannot_approve_or_execute():
    profile = grants.PROFILES["workflow-dispatch-worker"]
    columns = grants.COLUMN_GRANTS["workflow-dispatch-worker"]
    assert profile["agent_executions"] == ("SELECT", "INSERT")
    assert "agent_executions" not in columns
    assert profile["agent_action_proposals"] == ("SELECT",)
    assert not {"credential_profiles", "mcp_servers", "report_delivery_receipts", "investigation_tool_calls"}.intersection(profile)
    for table in grants.NAMESPACE_EXEMPT_METADATA["workflow-dispatch-worker"]:
        assert profile[table] == ("SELECT",)
        assert columns[table]["UPDATE"] == ("updated_at",)
    assert set(grants.NAMESPACE_EXEMPT_METADATA) == {"workflow-dispatch-worker"}
    assert not {"cron_expression", "authorization_scope", "revision", "run_as_principal_id",
                "workflow_input", "report_artifact_version_id"}.intersection(columns["workflow_schedule_activations"]["UPDATE"])
    assert set(columns["report_storage_policies"]["UPDATE"]) == {
        "used_instances", "used_bytes", "used_attachment_bytes", "updated_at"}
    assert not {"authorization_scope", "permission_snapshot", "requested_by_principal_id",
                "conclusion", "finished_at"}.intersection(columns["investigations"]["UPDATE"])


@pytest.mark.parametrize("role", ["pg_monitor", "MixedCase", "role; DROP TABLE devices", "with space", "", "a" * 64, None])
def test_role_names_cannot_be_sql_or_reserved_role_fragments(role):
    with pytest.raises(ValueError):
        grants._target("collector-lease-reconciler", role)


def test_remote_agent_cannot_be_given_an_internal_database_profile():
    with pytest.raises(ValueError, match="Unknown"):
        grants._target("agent", "icheck_agent")


@pytest.mark.parametrize("acknowledgements", [[], ["--acknowledge-grants"], ["--acknowledge-drained"]])
def test_apply_requires_both_operator_acknowledgements(monkeypatch, acknowledgements):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://operator@localhost/icheck")
    with pytest.raises(SystemExit) as refused:
        database_release.main(["worker-grants", "--profile", "collector-lease-reconciler", "--role", "icheck_lease", "--apply", *acknowledgements])
    assert refused.value.code == 2


def test_cli_inspection_does_not_request_mutation(monkeypatch, capsys):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://operator@localhost/icheck")
    calls = []
    def inspect(url, **kwargs):
        calls.append(kwargs)
        return {"complete": False, "missing_table_grants": [{"table": "audit_events", "privilege": "INSERT"}]}
    monkeypatch.setattr(grants, "inspect_worker_grants", inspect)
    assert database_release.main(["worker-grants", "--profile", "collector-lease-reconciler", "--role", "icheck_lease"]) == 1
    assert calls == [{"profile": "collector-lease-reconciler", "role": "icheck_lease", "apply": False}]
    assert "audit_events" in capsys.readouterr().out


def test_cli_apply_is_explicit_and_redacts_driver_failure(monkeypatch, capsys):
    monkeypatch.setenv("ICHECK_DATABASE_URL", "postgresql://operator:private-grant-password@localhost/icheck")
    def fail(url, **kwargs):
        assert kwargs["apply"] is True
        raise RuntimeError(url + " private-provider-token")
    monkeypatch.setattr(grants, "inspect_worker_grants", fail)
    assert database_release.main(["worker-grants", "--profile", "collector-lease-reconciler", "--role", "icheck_lease", "--apply", "--acknowledge-grants", "--acknowledge-drained"]) == 1
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "private-grant-password" not in captured.out + captured.err
    assert "private-provider-token" not in captured.out + captured.err
