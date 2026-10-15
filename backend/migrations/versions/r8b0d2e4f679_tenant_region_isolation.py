"""tenant and regional control-plane isolation

Revision ID: r8b0d2e4f679
Revises: q7a9c1d3f568
Create Date: 2026-10-01 12:00:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa


revision: str = "r8b0d2e4f679"
down_revision: str | None = "q7a9c1d3f568"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_REGION_ID = "00000000-0000-0000-0000-000000000002"


EXISTING_TABLES = (
    "agent_action_proposals",
    "agent_execution_events",
    "agent_executions",
    "agent_profiles",
    "agent_tool_registrations",
    "agent_workers",
    "ai_model_configs",
    "ai_model_routes",
    "ai_provider_configs",
    "alert_rules",
    "alerts",
    "artifact_replay_cases",
    "artifact_replay_runs",
    "artifact_signature_verifications",
    "artifact_trust_keys",
    "artifact_versions",
    "artifacts",
    "audit_events",
    "capability_pack_installations",
    "capability_pack_installed_artifacts",
    "capability_pack_revocation_feeds",
    "capability_pack_revocations",
    "capability_promotion_policy",
    "capability_promotion_receipts",
    "capability_promotion_sources",
    "capability_studio_messages",
    "capability_studio_sessions",
    "capability_transparency_checkpoint_offers",
    "capability_transparency_gossip_observations",
    "capability_transparency_records",
    "capability_transparency_state",
    "capability_transparency_witness_attestations",
    "capability_transparency_witness_policy",
    "capability_transparency_witnesses",
    "change_risk_policies",
    "collection_envelopes",
    "collector_canary_rollouts",
    "collector_definitions",
    "collector_deployments",
    "collector_fleet_rollout_items",
    "collector_fleet_rollouts",
    "collector_runs",
    "collector_workers",
    "control_plane_access_tokens",
    "control_plane_browser_sessions",
    "control_plane_principals",
    "control_plane_role_bindings",
    "control_plane_roles",
    "credential_profiles",
    "device_activation_policies",
    "device_connection_activations",
    "device_connection_preflights",
    "device_connections",
    "devices",
    "ecosystem_transport_endpoints",
    "ecosystem_transport_jobs",
    "ecosystem_transport_workers",
    "endpoint_attachments",
    "endpoints",
    "governed_change_evidence",
    "governed_change_plans",
    "investigation_checkpoints",
    "investigation_evidence",
    "investigation_tool_calls",
    "investigation_topology_proposal_evidence",
    "investigation_topology_proposals",
    "investigations",
    "ip_address_observations",
    "knowledge_entities",
    "knowledge_projection_workers",
    "knowledge_projections",
    "knowledge_relationships",
    "mcp_servers",
    "mcp_tool_activations",
    "metric_backends",
    "organization_trust_bundle_imports",
    "organization_trust_domains",
    "organization_trust_recovery_policies",
    "organization_trust_root_reanchors",
    "organization_trust_root_rotations",
    "remote_capability_catalog_entries",
    "remote_capability_catalog_key_rotations",
    "remote_capability_catalog_snapshots",
    "remote_capability_catalog_sources",
    "service_catalog_components",
    "service_catalog_dependencies",
    "service_catalog_entries",
    "service_indicator_artifact_bindings",
    "service_indicator_artifact_publications",
    "service_indicator_definitions",
    "service_indicator_observations",
    "service_indicator_poll_runs",
    "service_indicator_prometheus_bindings",
    "service_indicator_workers",
    "situation_alerts",
    "situation_events",
    "situation_hypotheses",
    "situation_hypothesis_evidence",
    "situation_hypothesis_revisions",
    "situation_impact_assessment_evidence",
    "situation_impact_assessments",
    "situation_integration_bindings",
    "situation_integration_events",
    "situation_integration_inbound_events",
    "situation_integration_remote_references",
    "situations",
    "wireless_client_sessions",
    "workflow_schedule_activations",
    "workflow_schedule_events",
    "workflow_trigger_activations",
    "workflow_trigger_events",
)

IDENTITY_TABLES = {
    "control_plane_access_tokens",
    "control_plane_browser_sessions",
    "control_plane_principals",
    "control_plane_role_bindings",
    "control_plane_roles",
}


def _add_namespace_columns(table_name: str) -> None:
    op.add_column(
        table_name,
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            server_default=DEFAULT_TENANT_ID,
            nullable=False,
        ),
    )
    op.add_column(
        table_name,
        sa.Column(
            "region_id",
            sa.String(length=36),
            server_default=DEFAULT_REGION_ID,
            nullable=False,
        ),
    )
    op.create_index(
        f"ix_{table_name}_tenant_id",
        table_name,
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        f"ix_{table_name}_region_id",
        table_name,
        ["region_id"],
        unique=False,
    )


def _legacy_unique_name(table_name: str, column_name: str) -> str:
    # The initial schema leaves these constraints unnamed. SQLite batch
    # reflection applies the convention below, but PostgreSQL supplies its
    # own name (or retains a name from an earlier downgrade). Reflect the
    # actual single-column constraint rather than guessing its spelling.
    if op.get_bind().dialect.name == "sqlite":
        return f"uq_{table_name}_{column_name}"
    names = [constraint["name"]
        for constraint in sa.inspect(op.get_bind()).get_unique_constraints(table_name)
        if constraint["column_names"] == [column_name]]
    if len(names) != 1 or not names[0]:
        raise RuntimeError(f"Expected one legacy unique constraint on {table_name}.{column_name}")
    return names[0]


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("default_region_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            server_default=DEFAULT_TENANT_ID,
            nullable=False,
        ),
        sa.Column(
            "region_id",
            sa.String(length=36),
            server_default=DEFAULT_REGION_ID,
            nullable=False,
        ),
        sa.CheckConstraint("slug <> ''", name="ck_tenant_slug_nonempty"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    for column in ("enabled", "default_region_id", "tenant_id", "region_id"):
        op.create_index(
            f"ix_tenants_{column}", "tenants", [column], unique=False
        )

    op.create_table(
        "regions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("code", sa.String(length=63), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("region_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("code <> ''", name="ck_region_code_nonempty"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "code", name="uq_region_tenant_code"
        ),
    )
    for column in ("code", "enabled", "tenant_id", "region_id"):
        op.create_index(
            f"ix_regions_{column}", "regions", [column], unique=False
        )

    now = datetime.now(UTC)
    op.bulk_insert(
        sa.table(
            "tenants",
            sa.column("id", sa.String),
            sa.column("slug", sa.String),
            sa.column("name", sa.String),
            sa.column("enabled", sa.Boolean),
            sa.column("default_region_id", sa.String),
            sa.column("created_by", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
            sa.column("tenant_id", sa.String),
            sa.column("region_id", sa.String),
        ),
        [
            {
                "id": DEFAULT_TENANT_ID,
                "slug": "local",
                "name": "Local tenant",
                "enabled": True,
                "default_region_id": DEFAULT_REGION_ID,
                "created_by": "system.migration",
                "created_at": now,
                "updated_at": now,
                "tenant_id": DEFAULT_TENANT_ID,
                "region_id": DEFAULT_REGION_ID,
            }
        ],
        multiinsert=False,
    )
    op.bulk_insert(
        sa.table(
            "regions",
            sa.column("id", sa.String),
            sa.column("code", sa.String),
            sa.column("name", sa.String),
            sa.column("enabled", sa.Boolean),
            sa.column("created_by", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
            sa.column("tenant_id", sa.String),
            sa.column("region_id", sa.String),
        ),
        [
            {
                "id": DEFAULT_REGION_ID,
                "code": "primary",
                "name": "Primary region",
                "enabled": True,
                "created_by": "system.migration",
                "created_at": now,
                "updated_at": now,
                "tenant_id": DEFAULT_TENANT_ID,
                "region_id": DEFAULT_REGION_ID,
            }
        ],
        multiinsert=False,
    )

    for table_name in EXISTING_TABLES:
        _add_namespace_columns(table_name)

    op.add_column(
        "control_plane_principals",
        sa.Column(
            "allowed_region_ids",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )
    op.add_column(
        "control_plane_principals",
        sa.Column(
            "platform_admin",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_control_plane_principals_platform_admin",
        "control_plane_principals",
        ["platform_admin"],
        unique=False,
    )

    op.drop_index(
        "ix_control_plane_principals_subject",
        table_name="control_plane_principals",
    )
    op.create_index(
        "ix_control_plane_principals_subject",
        "control_plane_principals",
        ["subject"],
        unique=False,
    )
    op.drop_index(
        "ix_control_plane_roles_name",
        table_name="control_plane_roles",
    )
    op.create_index(
        "ix_control_plane_roles_name",
        "control_plane_roles",
        ["name"],
        unique=False,
    )
    with op.batch_alter_table("control_plane_principals") as batch:
        batch.create_unique_constraint(
            "uq_control_plane_principal_tenant_subject",
            ["tenant_id", "subject"],
        )
    with op.batch_alter_table("control_plane_roles") as batch:
        batch.create_unique_constraint(
            "uq_control_plane_role_namespace_name",
            ["tenant_id", "region_id", "name"],
        )
    with op.batch_alter_table("control_plane_role_bindings") as batch:
        batch.drop_constraint(
            "uq_control_plane_role_binding", type_="unique"
        )
        batch.create_unique_constraint(
            "uq_control_plane_role_binding",
            ["principal_id", "role_id", "region_id"],
        )

    op.drop_index("ix_devices_name", table_name="devices")
    op.create_index("ix_devices_name", "devices", ["name"], unique=False)
    with op.batch_alter_table(
        "devices",
        naming_convention={
            "uq": "uq_%(table_name)s_%(column_0_name)s",
        },
    ) as batch:
        batch.drop_constraint(
            _legacy_unique_name("devices", "management_ip"), type_="unique"
        )
        batch.create_unique_constraint(
            "uq_device_namespace_name",
            ["tenant_id", "region_id", "name"],
        )
        batch.create_unique_constraint(
            "uq_device_namespace_management_ip",
            ["tenant_id", "region_id", "management_ip"],
        )
    op.drop_index("ix_endpoints_mac_address", table_name="endpoints")
    op.create_index(
        "ix_endpoints_mac_address",
        "endpoints",
        ["mac_address"],
        unique=False,
    )
    with op.batch_alter_table("endpoints") as batch:
        batch.create_unique_constraint(
            "uq_endpoint_namespace_mac",
            ["tenant_id", "region_id", "mac_address"],
        )
    with op.batch_alter_table(
        "alert_rules",
        naming_convention={
            "uq": "uq_%(table_name)s_%(column_0_name)s",
        },
    ) as batch:
        batch.drop_constraint(_legacy_unique_name("alert_rules", "name"), type_="unique")
        batch.create_unique_constraint(
            "uq_alert_rule_namespace_name",
            ["tenant_id", "region_id", "name"],
        )

    if op.get_bind().dialect.name == "postgresql":
        for table_name in EXISTING_TABLES:
            if table_name in IDENTITY_TABLES:
                continue
            op.execute(
                sa.text(f'ALTER TABLE "{table_name}" ENABLE ROW LEVEL SECURITY')
            )
            op.execute(
                sa.text(
                    f'CREATE POLICY icheck_namespace_isolation ON "{table_name}" '
                    "USING (tenant_id = current_setting('icheck.tenant_id', true) "
                    "AND region_id = current_setting('icheck.region_id', true)) "
                    "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
                    "AND region_id = current_setting('icheck.region_id', true))"
                )
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in reversed(EXISTING_TABLES):
            if table_name in IDENTITY_TABLES:
                continue
            op.execute(
                sa.text(
                    f'DROP POLICY IF EXISTS icheck_namespace_isolation '
                    f'ON "{table_name}"'
                )
            )
            op.execute(
                sa.text(f'ALTER TABLE "{table_name}" DISABLE ROW LEVEL SECURITY')
            )

    with op.batch_alter_table("alert_rules") as batch:
        batch.drop_constraint(
            "uq_alert_rule_namespace_name", type_="unique"
        )
        batch.create_unique_constraint("uq_alert_rules_name", ["name"])
    with op.batch_alter_table("endpoints") as batch:
        batch.drop_constraint("uq_endpoint_namespace_mac", type_="unique")
    op.drop_index("ix_endpoints_mac_address", table_name="endpoints")
    op.create_index(
        "ix_endpoints_mac_address",
        "endpoints",
        ["mac_address"],
        unique=True,
    )
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint(
            "uq_device_namespace_management_ip", type_="unique"
        )
        batch.drop_constraint("uq_device_namespace_name", type_="unique")
        batch.create_unique_constraint(
            "uq_devices_management_ip", ["management_ip"]
        )
    op.drop_index("ix_devices_name", table_name="devices")
    op.create_index("ix_devices_name", "devices", ["name"], unique=True)

    with op.batch_alter_table("control_plane_role_bindings") as batch:
        batch.drop_constraint(
            "uq_control_plane_role_binding", type_="unique"
        )
        batch.create_unique_constraint(
            "uq_control_plane_role_binding", ["principal_id", "role_id"]
        )
    with op.batch_alter_table("control_plane_roles") as batch:
        batch.drop_constraint(
            "uq_control_plane_role_namespace_name", type_="unique"
        )
    with op.batch_alter_table("control_plane_principals") as batch:
        batch.drop_constraint(
            "uq_control_plane_principal_tenant_subject", type_="unique"
        )
    op.drop_index(
        "ix_control_plane_roles_name", table_name="control_plane_roles"
    )
    op.create_index(
        "ix_control_plane_roles_name",
        "control_plane_roles",
        ["name"],
        unique=True,
    )
    op.drop_index(
        "ix_control_plane_principals_subject",
        table_name="control_plane_principals",
    )
    op.create_index(
        "ix_control_plane_principals_subject",
        "control_plane_principals",
        ["subject"],
        unique=True,
    )
    op.drop_index(
        "ix_control_plane_principals_platform_admin",
        table_name="control_plane_principals",
    )
    op.drop_column("control_plane_principals", "platform_admin")
    op.drop_column("control_plane_principals", "allowed_region_ids")

    for table_name in reversed(EXISTING_TABLES):
        op.drop_index(f"ix_{table_name}_region_id", table_name=table_name)
        op.drop_index(f"ix_{table_name}_tenant_id", table_name=table_name)
        op.drop_column(table_name, "region_id")
        op.drop_column(table_name, "tenant_id")

    for column in ("code", "enabled", "tenant_id", "region_id"):
        op.drop_index(f"ix_regions_{column}", table_name="regions")
    op.drop_table("regions")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    for column in ("enabled", "default_region_id", "tenant_id", "region_id"):
        op.drop_index(f"ix_tenants_{column}", table_name="tenants")
    op.drop_table("tenants")
