"""Reviewed PostgreSQL table grants for trusted internal controllers.

Remote Agents/Collectors/Attestors must not use these database roles. Profiles
are explicit source contracts, not grants inferred from observed queries or all
ORM tables. Existing excess authority is rejected, never silently revoked.
"""
from __future__ import annotations

import re
from typing import Any

import psycopg
from psycopg import sql

from .checkpoint_schema import postgres_dsn


ROLE_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
PROFILES = {
    "integration-sync-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        # Encrypted integration tokens only; other credential stores are excluded.
        "monitoring_integration_connections": ("SELECT",),
        "monitoring_integration_schedules": ("SELECT",),
        "monitoring_integration_syncs": ("SELECT", "INSERT"),
        "monitoring_integration_resources": ("SELECT", "INSERT"),
        "audit_events": ("INSERT",),
    },
    "ecosystem-transport-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "ecosystem_transport_endpoints": ("SELECT",),
        "ecosystem_transport_jobs": ("SELECT", "INSERT"),
        "ecosystem_transport_workers": ("SELECT", "INSERT"),
        "credential_profiles": ("SELECT",),
        "capability_transparency_checkpoint_offers": ("SELECT",),
        "capability_transparency_witnesses": ("SELECT",),
        "capability_transparency_witness_policy": ("SELECT",),
        "capability_transparency_witness_attestations": ("SELECT", "INSERT"),
        "artifact_trust_keys": ("SELECT",),
        "organization_trust_domains": ("SELECT",),
        "audit_events": ("INSERT",),
    },
    "systemd-capacity-provider": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "worker_scaling_policies": ("SELECT",),
        "worker_scaling_decisions": ("SELECT",),
        "worker_scaling_application_events": ("SELECT", "INSERT"),
        "collector_workers": ("SELECT",),
        "agent_workers": ("SELECT",),
        "collector_deployments": ("SELECT",),
        "device_connection_preflights": ("SELECT",),
        "agent_executions": ("SELECT",),
        "audit_events": ("INSERT",),
    },
    "quality-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "capability_quality_policies": ("SELECT",),
        "capability_quality_assessments": ("SELECT", "INSERT"),
        "artifacts": ("SELECT",),
        "artifact_versions": ("SELECT",),
        "collector_definitions": ("SELECT",),
        "agent_tool_registrations": ("SELECT",),
        # Existing runtime outcomes/status/content are evidence, not writable.
        # Two explicit timestamp-only receipt-lock grants are disclosed below.
        # Outcome verification reads bounded raw calls/plans and emits a
        # minimized manifest; it does not invoke Tools or resolve credentials.
        "collector_runs": ("SELECT",),
        "investigations": ("SELECT",),
        "investigation_tool_calls": ("SELECT",),
        "agent_action_proposals": ("SELECT",),
        "governed_change_plans": ("SELECT",),
        "governed_change_evidence": ("SELECT",),
        "change_preapproval_authorizations": ("SELECT",),
        "change_preapproval_execution_grants": ("SELECT",),
        "change_preapproval_budget_claims": ("SELECT",),
        "change_rollback_authorizations": ("SELECT",),
        "change_rollback_execution_grants": ("SELECT",),
        # Native Alert/condition retirement triggers check these even for a
        # non-Collector quality key. Historical reads confer no source writes.
        "collector_condition_sources": ("SELECT",),
        "collector_source_retirements": ("SELECT",),
        "capability_pack_installed_artifacts": ("SELECT",),
        "capability_pack_installations": ("SELECT",),
        "capability_pack_revocations": ("SELECT",),
        "alerts": ("SELECT", "INSERT"),
        "alert_condition_states": ("SELECT", "INSERT"),
        "situations": ("SELECT", "INSERT"),
        "situation_alerts": ("SELECT", "INSERT"),
        "situation_events": ("INSERT",),
        "workflow_trigger_activations": ("SELECT",),
        "workflow_trigger_events": ("INSERT",),
        "situation_integration_bindings": ("SELECT",),
        "situation_integration_events": ("INSERT",),
        "audit_events": ("INSERT",),
    },
    "scaling-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "worker_scaling_policies": ("SELECT",),
        "worker_scaling_decisions": ("SELECT", "INSERT"),
        "artifact_versions": ("SELECT",),
        "collector_definitions": ("SELECT",),
        "collector_deployments": ("SELECT",),
        "collector_canary_rollouts": ("SELECT",),
        "collector_workers": ("SELECT",),
        "agent_workers": ("SELECT",),
        "agent_executions": ("SELECT",),
        "investigations": ("SELECT",),
        "ai_model_configs": ("SELECT",),
        # Provider-type/config metadata and external references only; no I/O
        # or secret resolution. ORM worker reads include token hashes, not
        # usable registration/bearer credentials or session/access tokens.
        "ai_provider_configs": ("SELECT",),
        "audit_events": ("INSERT",),
    },
    "rollout-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "artifacts": ("SELECT",),
        "artifact_versions": ("SELECT",),
        "collector_definitions": ("SELECT",),
        "devices": ("SELECT",),
        # External reference/adapter/selector metadata only. Never resolved here.
        "credential_profiles": ("SELECT",),
        "collector_deployments": ("SELECT",),
        "collector_runs": ("SELECT",),
        "device_connection_activations": ("SELECT",),
        "collector_fleet_rollouts": ("SELECT",),
        "collector_fleet_rollout_items": ("SELECT",),
        "collector_fleet_rollout_rings": ("SELECT",),
        "capability_pack_installed_artifacts": ("SELECT",),
        "capability_pack_installations": ("SELECT",),
        "capability_pack_revocations": ("SELECT",),
        "audit_events": ("INSERT",),
    },
    "collector-lease-reconciler": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "devices": ("SELECT",),
        "device_connections": ("SELECT",),
        "device_connection_activations": ("SELECT",),
        "collector_deployments": ("SELECT",),
        "collector_runs": ("SELECT",),
        "collector_canary_rollouts": ("SELECT",),
        "audit_events": ("INSERT",),
    },
    "projection-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "artifacts": ("SELECT",),
        "artifact_versions": ("SELECT",),
        "collector_definitions": ("SELECT",),
        "collector_deployments": ("SELECT",),
        "collector_runs": ("SELECT",),
        "collector_workers": ("SELECT",),
        # References/selector metadata only: this table stores no secret values.
        # OS/Vault custody remains separate; projection never resolves secrets.
        "credential_profiles": ("SELECT",),
        "devices": ("SELECT",),
        "collection_envelopes": ("SELECT",),
        "knowledge_projection_workers": ("SELECT", "INSERT"),
        "knowledge_projections": ("SELECT",),
        "endpoints": ("SELECT", "INSERT"),
        "ip_address_observations": ("SELECT", "INSERT"),
        "endpoint_attachments": ("SELECT", "INSERT"),
        "network_observation_states": ("SELECT", "INSERT"),
        "wireless_client_sessions": ("SELECT", "INSERT"),
        "wireless_snapshot_states": ("SELECT", "INSERT"),
        "knowledge_entities": ("SELECT", "INSERT"),
        "knowledge_relationships": ("SELECT", "INSERT"),
        "alert_rules": ("SELECT",),
        "alerts": ("SELECT", "INSERT"),
        "alert_condition_states": ("SELECT", "INSERT"),
        "situations": ("SELECT", "INSERT"),
        "situation_alerts": ("SELECT", "INSERT"),
        "situation_events": ("INSERT",),
        "service_catalog_entries": ("SELECT",),
        "service_catalog_components": ("SELECT",),
        "workflow_trigger_activations": ("SELECT",),
        "workflow_trigger_events": ("INSERT",),
        "situation_integration_bindings": ("SELECT",),
        "situation_integration_events": ("INSERT",),
        "collector_condition_admissions": ("SELECT",),
        "collector_condition_sources": ("SELECT", "INSERT"),
        "collector_condition_receipts": ("SELECT", "INSERT"),
        "collector_source_retirements": ("SELECT",),
        "service_indicator_definitions": ("SELECT",),
        "service_indicator_artifact_bindings": ("SELECT",),
        "service_indicator_artifact_publications": ("SELECT", "INSERT"),
        "service_indicator_observations": ("SELECT", "INSERT"),
        "audit_events": ("SELECT", "INSERT"),
    },
    "indicator-worker": {
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        "credential_profiles": ("SELECT",),
        "metric_backends": ("SELECT",),
        "service_indicator_definitions": ("SELECT",),
        "service_indicator_prometheus_bindings": ("SELECT",),
        "service_indicator_workers": ("SELECT", "INSERT"),
        "service_indicator_poll_runs": ("SELECT", "INSERT"),
        "service_indicator_observations": ("SELECT", "INSERT"),
        "audit_events": ("INSERT",),
    },
    "workflow-dispatch-worker": {
        "alert_investigation_policies": ("SELECT",),
        "alert_investigation_events": ("SELECT", "INSERT"),
        "alembic_version": ("SELECT",),
        "tenants": ("SELECT",),
        "regions": ("SELECT",),
        # Central authorization metadata, not tokens, sessions or login secrets.
        # principal_context/domain readers independently bind tenant + region.
        "control_plane_principals": ("SELECT",),
        "control_plane_roles": ("SELECT",),
        "control_plane_role_bindings": ("SELECT",),
        "artifacts": ("SELECT",),
        "artifact_versions": ("SELECT",),
        "agent_tool_registrations": ("SELECT",),
        # Provider policy metadata contains external secret references only;
        # dispatch never resolves them or invokes models/remote Tools.
        "ai_provider_configs": ("SELECT",),
        "ai_model_configs": ("SELECT",),
        "ai_model_routes": ("SELECT",),
        "agent_profiles": ("SELECT",),
        "investigations": ("SELECT", "INSERT"),
        "investigation_checkpoints": ("SELECT", "INSERT"),
        "investigation_evidence": ("SELECT", "INSERT"),
        "agent_executions": ("SELECT", "INSERT"),
        "agent_execution_events": ("SELECT", "INSERT"),
        "workflow_schedule_activations": ("SELECT",),
        "workflow_schedule_events": ("SELECT", "INSERT"),
        "workflow_trigger_activations": ("SELECT",),
        "workflow_trigger_events": ("SELECT",),
        "situation_integration_bindings": ("SELECT",),
        "situation_integration_events": ("SELECT",),
        "alerts": ("SELECT",),
        "situations": ("SELECT",),
        "situation_alerts": ("SELECT",),
        "situation_events": ("SELECT",),
        # Entity/component ACL reads for scheduled reports and retained proofs.
        "devices": ("SELECT",),
        "endpoints": ("SELECT",),
        "ip_address_observations": ("SELECT",),
        "endpoint_attachments": ("SELECT",),
        "wireless_client_sessions": ("SELECT",),
        "knowledge_entities": ("SELECT",),
        "service_catalog_entries": ("SELECT",),
        "service_catalog_components": ("SELECT",),
        "service_indicator_definitions": ("SELECT",),
        "service_indicator_observations": ("SELECT",),
        "service_report_instances": ("SELECT", "INSERT"),
        "service_report_instance_services": ("SELECT", "INSERT"),
        "report_proof_admissions": ("SELECT", "INSERT"),
        "report_instance_proof_references": ("SELECT", "INSERT"),
        "report_attachments": ("SELECT", "INSERT"),
        "report_storage_policies": ("SELECT", "INSERT"),
        "report_purge_tombstones": ("SELECT",),
        "capability_pack_installed_artifacts": ("SELECT",),
        "capability_pack_installations": ("SELECT",),
        "capability_pack_revocations": ("SELECT",),
        # Historical material only: no peer approval, cutover or closure writes.
        "collector_condition_sources": ("SELECT",),
        "collector_condition_receipts": ("SELECT",),
        "collector_condition_admissions": ("SELECT",),
        "alert_condition_states": ("SELECT",),
        "collector_source_qualification_requests": ("SELECT",),
        "collector_source_qualification_reviews": ("SELECT",),
        "collector_source_replacement_requests": ("SELECT",),
        "collector_source_replacement_reviews": ("SELECT",),
        "collector_source_retirements": ("SELECT",),
        "situation_closure_requests": ("SELECT",),
        "situation_closure_grants": ("SELECT",),
        # Investigation binding's native closure fence reads ownership epochs.
        "situation_closure_ownerships": ("SELECT",),
        "situation_closure_receipts": ("SELECT",),
        "situation_recovery_policy_requests": ("SELECT",),
        "situation_recovery_policy_reviews": ("SELECT",),
        "action_target_admissions": ("SELECT",),
        "agent_action_proposals": ("SELECT",),
        "audit_events": ("INSERT",),
    },
}
COLUMN_GRANTS = {"collector-lease-reconciler": {
    "devices": {"UPDATE": ("onboarding_status", "updated_at")},
    "device_connection_activations": {"UPDATE": (
        "runtime_status", "health_reason", "last_evaluated_at", "updated_at",
        "last_run_id", "last_run_status", "last_run_finished_at", "last_success_at",
        "last_failure_at", "consecutive_failures",
    )},
    "collector_deployments": {"UPDATE": (
        "last_finished_at", "lease_worker_id", "lease_token_hash", "lease_expires_at",
        "next_run_at", "updated_at", "enabled",
    )},
    "collector_runs": {"UPDATE": ("status", "finished_at", "error", "stats")},
    "collector_canary_rollouts": {"UPDATE": (
        "status", "evaluated_at", "updated_at", "passed_at", "aborted_at", "abort_reason",
        "last_run_id", "records_received", "successful_runs", "qualifying_runs",
        "failed_runs", "last_gate_result",
    )},
}}
COLUMN_GRANTS["integration-sync-worker"] = {
    "monitoring_integration_connections": {"UPDATE": ("updated_at",)},  # Required for row locks only.
    "monitoring_integration_schedules": {"UPDATE": (
        "next_run_at", "active_run_id", "lease_token", "lease_expires_at", "failures",
        "last_attempt_at", "last_success_at", "last_error",
    )},
    "monitoring_integration_syncs": {"UPDATE": (
        "host_ids", "cursor", "observed", "status", "error_code", "updated_at", "finished_at",
    )},
    "monitoring_integration_resources": {"UPDATE": (
        "name", "monitoring_enabled", "observed_at", "last_run_id", "connection_revision",
    )},
}
COLUMN_GRANTS["rollout-worker"] = {
    # NOWAIT shared reference locks require one real writable timestamp.
    "devices": {"UPDATE": ("updated_at",)},
    "credential_profiles": {"UPDATE": ("updated_at",)},
    "collector_deployments": {"UPDATE": (
        "artifact_version_id", "lease_worker_id", "lease_token_hash", "lease_expires_at",
        "next_run_at", "updated_at",
    )},
    "collector_fleet_rollouts": {"UPDATE": (
        "status", "planned_count", "pending_count", "blocked_count", "deferred_count",
        "migrated_count", "failed_count", "rolled_back_count", "rollback_failed_count",
        "automation_state", "current_ring_index", "automation_updated_at", "started_at",
        "completed_at", "last_batch_result", "updated_at",
    )},
    "collector_fleet_rollout_items": {"UPDATE": (
        "status", "attempt_count", "last_error_code", "last_error_sha256", "migrated_at", "updated_at",
    )},
    "collector_fleet_rollout_rings": {"UPDATE": (
        "status", "healthy_deployments", "missing_evidence_deployments", "successful_runs", "failed_runs",
        "last_gate_result", "evidence_sha256", "started_at", "observation_started_at",
        "evaluated_at", "passed_at", "updated_at",
    )},
}
COLUMN_GRANTS["scaling-worker"] = {
    # FOR UPDATE needs a genuine writable column. This allows timestamp writes,
    # not edits to replica bounds, policy enablement, revision or ownership.
    "worker_scaling_policies": {"UPDATE": ("updated_at",)},
}
COLUMN_GRANTS["systemd-capacity-provider"] = {
    # Genuine timestamp privilege for the same policy mutex used by evaluators
    # and editors. Host authority is independently limited by protected mappings
    # and exact-instance Polkit rules, never a database or root capability.
    "worker_scaling_policies": {"UPDATE": ("updated_at",)},
    "collector_workers": {"UPDATE": ("state", "updated_at")},
    "agent_workers": {"UPDATE": ("state", "updated_at")},
}
COLUMN_GRANTS["ecosystem-transport-worker"] = {
    # Genuine timestamp authority supports shared endpoint/credential/policy/
    # witness/public-key/domain locks. No identity, material or settings writes.
    "ecosystem_transport_endpoints": {"UPDATE": ("updated_at",)},
    "credential_profiles": {"UPDATE": ("updated_at",)},
    "capability_transparency_witnesses": {"UPDATE": ("updated_at",)},
    "capability_transparency_witness_policy": {"UPDATE": ("updated_at",)},
    # Trust keys have no updated_at column. This genuine creation-timestamp
    # privilege is only for FOR SHARE, never key identity or revocation edits.
    "artifact_trust_keys": {"UPDATE": ("created_at",)},
    "organization_trust_domains": {"UPDATE": ("updated_at",)},
    "ecosystem_transport_workers": {"UPDATE": ("state", "last_heartbeat_at", "updated_at")},
    "ecosystem_transport_jobs": {"UPDATE": (
        "status", "attempt_count", "next_attempt_at", "lease_worker_id", "lease_token_hash",
        "lease_expires_at", "response_digest_sha256", "result_summary", "error_type",
        "error_sha256", "completed_at", "updated_at",
    )},
}
COLUMN_GRANTS["quality-worker"] = {
    # Sealed rollback receipt verification takes FOR SHARE on failure evidence.
    # These are genuine timestamp UPDATE privileges, not outcome/status writes.
    # Native terminal-call immutability still rejects changed call timestamps.
    "governed_change_evidence": {"UPDATE": ("created_at",)},
    "investigation_tool_calls": {"UPDATE": ("started_at",)},
    "capability_quality_policies": {"UPDATE": ("last_assessment_id", "next_evaluation_at", "updated_at")},
    "alerts": {"UPDATE": (
        "severity", "status", "title", "description", "occurrence_count", "details", "last_seen",
        "resolved_at", "resolved_by",
    )},
    "alert_condition_states": {"UPDATE": (
        "event_type", "entity_type", "entity_id", "source_rule_id", "state", "observed_at",
        "latest_alert_id", "revision", "updated_at",
    )},
    "situations": {"UPDATE": (
        "correlation_version", "status", "severity", "priority_score", "title", "summary",
        "alert_count", "active_alert_count", "occurrence_count", "correlation_confidence",
        "event_sequence", "first_seen", "last_seen", "resolved_at", "resolved_by", "updated_at",
        "acknowledged_at", "acknowledged_by",
    )},
    "situation_alerts": {"UPDATE": (
        "severity_snapshot", "status_snapshot", "occurrence_count_snapshot", "last_seen", "updated_at",
    )},
}
COLUMN_GRANTS["projection-worker"] = {
    # PostgreSQL row locks require UPDATE on at least one column. Only the
    # named timestamp is granted on reference rows; identity/config/content,
    # publication, credentials and authority fields cannot be updated.
    "artifact_versions": {"UPDATE": ("created_at",)},
    "collector_definitions": {"UPDATE": ("created_at",)},
    "collector_deployments": {"UPDATE": ("updated_at",)},
    "collector_runs": {"UPDATE": ("finished_at",)},
    "collector_workers": {"UPDATE": ("updated_at",)},
    "credential_profiles": {"UPDATE": ("updated_at",)},
    "devices": {"UPDATE": ("updated_at",)},
    "service_catalog_entries": {"UPDATE": ("updated_at",)},
    "service_catalog_components": {"UPDATE": ("updated_at",)},
    "service_indicator_definitions": {"UPDATE": ("updated_at",)},
    "service_indicator_artifact_bindings": {"UPDATE": ("updated_at",)},
    "collector_condition_sources": {"UPDATE": ("created_at",)},
    "knowledge_projection_workers": {"UPDATE": ("state", "last_heartbeat_at", "updated_at")},
    "knowledge_projections": {"UPDATE": (
        "status", "attempt_count", "next_attempt_at", "lease_worker_id", "lease_token_hash",
        "lease_expires_at", "result_summary", "error_type", "error_sha256", "completed_at", "updated_at",
    )},
    "endpoints": {"UPDATE": ("hostname", "username", "vendor", "first_seen", "last_seen", "updated_at")},
    "ip_address_observations": {"UPDATE": ("active", "last_seen", "observed_at")},
    "endpoint_attachments": {"UPDATE": ("active", "last_seen", "observed_at", "raw_data")},
    "network_observation_states": {"UPDATE": ("state", "observed_at", "payload", "revision", "updated_at")},
    "wireless_snapshot_states": {"UPDATE": ("state", "observed_at", "payload", "revision", "updated_at")},
    "wireless_client_sessions": {"UPDATE": (
        "ip_address", "access_point", "ssid", "bssid", "radio", "band", "channel", "vlan_id",
        "rssi", "snr", "active", "disconnected_at", "last_seen", "observed_at", "raw_data",
    )},
    "knowledge_entities": {"UPDATE": (
        "display_name", "status", "active", "attributes", "first_seen", "last_seen",
        "observed_at", "last_envelope_id", "updated_at",
    )},
    "knowledge_relationships": {"UPDATE": (
        "active", "attributes", "first_seen", "last_seen", "observed_at", "last_envelope_id", "updated_at",
    )},
    "alerts": {"UPDATE": (
        "severity", "status", "title", "description", "occurrence_count", "details", "last_seen",
        "resolved_at", "resolved_by",
    )},
    "alert_condition_states": {"UPDATE": (
        "event_type", "entity_type", "entity_id", "source_rule_id", "state", "observed_at",
        "latest_alert_id", "revision", "updated_at",
    )},
    "situations": {"UPDATE": (
        "correlation_version", "status", "severity", "priority_score", "title", "summary",
        "alert_count", "active_alert_count", "occurrence_count", "correlation_confidence",
        "event_sequence", "first_seen", "last_seen", "acknowledged_at", "acknowledged_by",
        "resolved_at", "resolved_by", "updated_at",
    )},
    "situation_alerts": {"UPDATE": (
        "severity_snapshot", "status_snapshot", "occurrence_count_snapshot", "last_seen", "updated_at",
    )},
}
COLUMN_GRANTS["indicator-worker"] = {
    # Reference-row locks fence configuration changes at observation commit;
    # only timestamps are writable, never credentials/queries/thresholds.
    "metric_backends": {"UPDATE": ("updated_at",)},
    "service_indicator_definitions": {"UPDATE": ("updated_at",)},
    "service_indicator_workers": {"UPDATE": ("state", "last_heartbeat_at", "updated_at")},
    "service_indicator_prometheus_bindings": {"UPDATE": (
        "next_run_at", "last_scheduled_at", "last_started_at", "last_succeeded_at", "last_failed_at",
        "consecutive_failures", "last_error_type", "last_error_sha256", "updated_at",
    )},
    "service_indicator_poll_runs": {"UPDATE": (
        "status", "attempt_count", "next_attempt_at", "lease_worker_id", "lease_token_hash",
        "lease_expires_at", "observation_id", "result_type", "series_count", "error_type",
        "error_sha256", "completed_at", "updated_at",
    )},
}
REGISTRY_TABLES = {"alembic_version", "tenants", "regions"}
# The official identity migration deliberately leaves these central metadata
# tables outside namespace RLS. This exception is profile-specific, disclosed
# in inspection output, and must never expand to credentials or other profiles.
NAMESPACE_EXEMPT_METADATA = {"workflow-dispatch-worker": frozenset({
    "control_plane_principals", "control_plane_roles", "control_plane_role_bindings",
})}
PROFILES["workflow-dispatch-worker"].update({table: ("SELECT",) for table in (
    "monitoring_integration_connections", "monitoring_integration_alert_feeds", "monitoring_integration_events",
    "monitoring_integration_resources", "monitoring_integration_bindings")})

# This reader can project source episodes and cancel their automatic runs, but
# cannot approve a mapping, enable a feed, enqueue AI, or change device credentials.
PROFILES["integration-alert-worker"] = {
    **{table: ("SELECT",) for table in ("alembic_version", "tenants", "regions", "devices",
        "monitoring_integration_connections", "monitoring_integration_alert_feeds",
        "monitoring_integration_resources", "monitoring_integration_bindings",
        "alert_investigation_events", "agent_executions", "investigations",
        # Existing alert trigger checks that this is not a retired Collector source.
        "collector_condition_sources")},
    "monitoring_integration_events": ("SELECT", "INSERT"),
    "alerts": ("SELECT", "INSERT"),
    "agent_execution_events": ("SELECT", "INSERT"),
    "audit_events": ("INSERT",),
}
COLUMN_GRANTS["integration-alert-worker"] = {
    "monitoring_integration_connections": {"UPDATE": ("updated_at",)},
    "monitoring_integration_alert_feeds": {"UPDATE": (
        "next_run_at", "cursor", "bootstrap_ids", "phase", "failures", "last_error", "last_attempt_at", "last_success_at")},
    "monitoring_integration_events": {"UPDATE": (
        "connection_revision", "observation", "available", "source_resolved", "checked_at", "alert_id",
        "resource_id", "binding_revision", "stopped_at", "stop_reason")},
    "alerts": {"UPDATE": ("last_seen", "title", "details", "severity", "status", "resolved_at", "resolved_by",
                          "acknowledged_at", "acknowledged_by")},
    "agent_executions": {"UPDATE": (
        "cancellation_requested_at", "cancellation_requested_by", "cancellation_reason", "status", "finished_at",
        "worker_id", "lease_token_hash", "lease_expires_at", "updated_at")},
    "investigations": {"UPDATE": ("status", "finished_at", "updated_at")},
}

COLUMN_GRANTS["workflow-dispatch-worker"] = {
    # Admission mutex/heartbeat only; cannot enable or widen standing policy.
    "alert_investigation_policies": {"UPDATE": ("dispatcher_seen_at", "dispatcher_status")},
    # Retained-proof readers take FOR SHARE locks to fence identity revocation.
    # PostgreSQL requires UPDATE on one column even for this read-only mutex.
    "control_plane_principals": {"UPDATE": ("updated_at",)},
    "control_plane_roles": {"UPDATE": ("updated_at",)},
    "control_plane_role_bindings": {"UPDATE": ("updated_at",)},
    "investigations": {"UPDATE": (
        "workflow_artifact_version_id", "workflow_input", "workflow_snapshot",
        "workflow_trigger_event_id", "workflow_schedule_event_id", "situation_integration_event_id",
        "situation_id", "max_iterations", "max_tool_calls", "timeout_seconds", "token_budget",
        "status", "started_at", "updated_at",
    )},
    "workflow_schedule_activations": {"UPDATE": (
        "enabled", "excluded_runs", "last_excluded_at", "next_fire_at", "last_fire_at",
        "last_misfire_at", "missed_runs", "updated_at",
    )},
    "workflow_schedule_events": {"UPDATE": (
        "status", "attempt_count", "error_type", "error_sha256", "updated_at",
    )},
    "workflow_trigger_events": {"UPDATE": (
        "status", "attempt_count", "error_type", "error_sha256", "updated_at",
    )},
    "situation_integration_events": {"UPDATE": (
        "status", "attempt_count", "error_type", "error_sha256", "updated_at",
    )},
    "report_storage_policies": {"UPDATE": (
        "used_instances", "used_bytes", "used_attachment_bytes", "updated_at",
    )},
}


def _target(profile: str, role: str) -> dict[str, tuple[str, ...]]:
    if profile not in PROFILES:
        raise ValueError("Unknown internal Worker database profile")
    if not isinstance(role, str) or not ROLE_PATTERN.fullmatch(role) or role.startswith("pg_"):
        raise ValueError("Worker database role must be a canonical existing login name")
    return PROFILES[profile]


def _preflight(cursor, role: str, tables: dict[str, tuple[str, ...]], column_grants,
               *, namespace_exempt_metadata: frozenset[str] = frozenset()) -> dict[str, Any]:
    cursor.execute("SELECT current_schema(), current_database(), current_user")
    schema, database, actor = cursor.fetchone()
    if schema != "public":
        raise RuntimeError("Internal Worker schema must resolve to public")
    cursor.execute("""SELECT r.oid,r.rolcanlogin,r.rolsuper,r.rolbypassrls,
      r.rolcreatedb,r.rolcreaterole,r.rolreplication,
      EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid),
      EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid),
      EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=r.oid),
      EXISTS(SELECT 1 FROM pg_class WHERE relowner=r.oid),
      EXISTS(SELECT 1 FROM pg_proc WHERE proowner=r.oid)
      FROM pg_roles r CROSS JOIN pg_database d
      WHERE r.rolname=%s AND d.datname=current_database()""", (role,))
    row = cursor.fetchone()
    if row is None or not row[1] or any(row[2:]):
        raise RuntimeError("Internal Worker requires an unprivileged non-owner login without role membership")
    role_oid = row[0]
    cursor.execute("""SELECT
      has_database_privilege(%s,current_database(),'CREATE'),
      has_database_privilege(%s,current_database(),'TEMP'),
      has_database_privilege(%s,current_database(),'CONNECT WITH GRANT OPTION'),
      EXISTS(SELECT 1 FROM pg_namespace n WHERE
        (has_schema_privilege(%s,n.oid,'CREATE') OR has_schema_privilege(%s,n.oid,'USAGE WITH GRANT OPTION')))
      """, (role, role, role, role, role))
    if any(cursor.fetchone()):
        raise RuntimeError("Internal Worker must not have DDL, TEMP or database/schema grant options")
    cursor.execute("SELECT version_num FROM public.alembic_version")
    revisions = cursor.fetchall()
    from alembic.script import ScriptDirectory
    from .database_release import migration_config
    heads = ScriptDirectory.from_config(migration_config()).get_heads()
    if len(heads) != 1 or revisions != [(heads[0],)]:
        raise RuntimeError("Internal Worker grants require the installed migration head")
    cursor.execute("""SELECT c.oid,n.nspname,c.relname,c.relkind,c.relrowsecurity
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
        AND c.relkind IN ('r','p','v','m','f') ORDER BY n.nspname,c.relname""")
    relations = cursor.fetchall()
    public = {name: (oid, kind, rls) for oid, namespace, name, kind, rls in relations if namespace == "public"}
    for name in tables:
        if name not in public or public[name][1] != "r":
            raise RuntimeError("Internal Worker profile relation is missing or unexpected")
        if name not in REGISTRY_TABLES | namespace_exempt_metadata and not public[name][2]:
            raise RuntimeError("Internal Worker profile relation must retain namespace RLS")
    missing = []
    missing_columns = []
    for oid, namespace, name, _, _ in relations:
        allowed = tables.get(name, ()) if namespace == "public" else ()
        columns = column_grants.get(name, {}) if namespace == "public" else {}
        for privilege in PRIVILEGES:
            cursor.execute("SELECT has_table_privilege(%s,%s,%s),has_table_privilege(%s,%s,%s)",
                (role, oid, privilege, role, oid, privilege + " WITH GRANT OPTION"))
            has_privilege, grantable = cursor.fetchone()
            # Column-only grants are hidden from has_table_privilege; inspect
            # them too, including grant options on only one protected column.
            if privilege in {"SELECT", "INSERT", "UPDATE", "REFERENCES"}:
                cursor.execute("SELECT has_any_column_privilege(%s,%s,%s),has_any_column_privilege(%s,%s,%s)",
                    (role, oid, privilege, role, oid, privilege + " WITH GRANT OPTION"))
                column_privilege, column_grantable = cursor.fetchone()
            else:
                column_privilege = column_grantable = False
            if (grantable or column_grantable or
                    ((has_privilege or column_privilege) and privilege not in allowed and privilege not in columns) or
                    (has_privilege and privilege in columns)):
                raise RuntimeError("Internal Worker has table or column authority outside its reviewed profile")
            if privilege in allowed and not has_privilege:
                missing.append({"table": name, "privilege": privilege})
            if privilege in columns:
                cursor.execute("SELECT attnum,attname FROM pg_attribute WHERE attrelid=%s AND attnum>0 AND NOT attisdropped", (oid,))
                attributes = cursor.fetchall()
                if set(columns[privilege]) - {attribute for _, attribute in attributes}:
                    raise RuntimeError("Internal Worker profile column is missing")
                for number, attribute in attributes:
                    cursor.execute("SELECT has_column_privilege(%s,%s,%s,%s)", (role, oid, number, privilege))
                    present = cursor.fetchone()[0]
                    if present and attribute not in columns[privilege]:
                        raise RuntimeError("Internal Worker has column authority outside its reviewed profile")
                    if not present and attribute in columns[privilege]:
                        missing_columns.append({"table": name, "column": attribute, "privilege": privilege})
    cursor.execute("""SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
      AND (has_sequence_privilege(%s,c.oid,'USAGE') OR has_sequence_privilege(%s,c.oid,'SELECT')
        OR has_sequence_privilege(%s,c.oid,'UPDATE')))""", (role, role, role))
    if cursor.fetchone()[0]:
        raise RuntimeError("Internal Worker profile does not authorize sequence access")
    cursor.execute("""SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND p.prosecdef
        AND p.prorettype NOT IN ('trigger'::regtype,'event_trigger'::regtype)
        AND has_function_privilege(%s,p.oid,'EXECUTE'))""", (role,))
    if cursor.fetchone()[0]:
        raise RuntimeError("Internal Worker must not execute unreviewed security-definer functions")
    cursor.execute("SELECT has_database_privilege(%s,current_database(),'CONNECT'),has_schema_privilege(%s,'public','USAGE')", (role, role))
    connect, usage = cursor.fetchone()
    return {"database": database, "role_oid": role_oid, "actor": actor,
            "migration_head": heads[0], "missing_table_grants": missing,
            "missing_column_grants": missing_columns,
            "database_connect": connect, "schema_usage": usage,
            "complete": not missing and not missing_columns and connect and usage}


def inspect_worker_grants(database_url: str, *, profile: str, role: str,
                          apply: bool = False) -> dict[str, Any]:
    tables = _target(profile, role)
    column_grants = COLUMN_GRANTS.get(profile, {})
    metadata = NAMESPACE_EXEMPT_METADATA.get(profile, frozenset())
    with psycopg.connect(postgres_dsn(database_url)) as connection:
        with connection.cursor() as cursor:
            # Inspect-only work cannot accidentally perform DDL through helpers.
            if not apply:
                cursor.execute("SET TRANSACTION READ ONLY")
            before = _preflight(cursor, role, tables, column_grants, namespace_exempt_metadata=metadata)
            if apply:
                if before["actor"] == role:
                    raise RuntimeError("Worker cannot provision its own grants")
                cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(before["database"]), sql.Identifier(role)))
                cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
                for table, privileges in tables.items():
                    cursor.execute(sql.SQL("GRANT {} ON TABLE public.{} TO {}").format(
                        sql.SQL(", ").join(sql.SQL(p) for p in privileges), sql.Identifier(table), sql.Identifier(role)))
                for table, privileges in column_grants.items():
                    for privilege, columns in privileges.items():
                        cursor.execute(sql.SQL("GRANT {} ({}) ON TABLE public.{} TO {}").format(
                            sql.SQL(privilege), sql.SQL(", ").join(sql.Identifier(column) for column in columns),
                            sql.Identifier(table), sql.Identifier(role)))
                after = _preflight(cursor, role, tables, column_grants, namespace_exempt_metadata=metadata)
                if after["role_oid"] != before["role_oid"] or not after["complete"]:
                    raise RuntimeError("Internal Worker grant state changed during provisioning")
            else:
                after = before
    return {"format_version": "icheck.worker-database-grants/v1", "profile": profile, "role": role,
            "database": after["database"], "migration_head": after["migration_head"],
            "applied": apply, "complete": after["complete"],
            "tables": {name: list(privileges) for name, privileges in tables.items()},
            "column_grants": column_grants,
            "namespace_exempt_authorization_metadata": sorted(metadata),
            "missing_table_grants": after["missing_table_grants"],
            "missing_column_grants": after["missing_column_grants"],
            "database_connect": after["database_connect"], "schema_usage": after["schema_usage"],
            "owner_or_privileged": False, "ddl_or_temp": False, "role_membership": False,
            "grant_options": False, "unrelated_table_or_column_access": False,
            "role_created": False, "database_migrated": False, "services_changed": False}
