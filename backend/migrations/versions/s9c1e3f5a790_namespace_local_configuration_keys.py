"""make configuration and worker natural keys namespace-local

Revision ID: s9c1e3f5a790
Revises: r8b0d2e4f679
Create Date: 2026-10-02 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "s9c1e3f5a790"
down_revision: str | None = "r8b0d2e4f679"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


INDEX_KEYS = (
    (
        "service_indicator_workers",
        "name",
        "ix_service_indicator_workers_name",
        "uq_service_indicator_worker_namespace_name",
    ),
    (
        "credential_profiles",
        "name",
        "ix_credential_profiles_name",
        "uq_credential_profile_namespace_name",
    ),
    (
        "metric_backends",
        "name",
        "ix_metric_backends_name",
        "uq_metric_backend_namespace_name",
    ),
    (
        "ai_provider_configs",
        "name",
        "ix_ai_provider_configs_name",
        "uq_ai_provider_namespace_name",
    ),
    (
        "ai_model_configs",
        "display_name",
        "ix_ai_model_configs_display_name",
        "uq_ai_model_namespace_display_name",
    ),
    (
        "ai_model_routes",
        "purpose",
        "ix_ai_model_routes_purpose",
        "uq_ai_model_route_namespace_purpose",
    ),
    (
        "agent_profiles",
        "name",
        "ix_agent_profiles_name",
        "uq_agent_profile_namespace_name",
    ),
    (
        "agent_tool_registrations",
        "name",
        "ix_agent_tool_registrations_name",
        "uq_agent_tool_namespace_name",
    ),
    (
        "mcp_servers",
        "name",
        "ix_mcp_servers_name",
        "uq_mcp_server_namespace_name",
    ),
    (
        "change_risk_policies",
        "risk_class",
        "ix_change_risk_policies_risk_class",
        "uq_change_risk_policy_namespace_class",
    ),
    (
        "agent_workers",
        "name",
        "ix_agent_workers_name",
        "uq_agent_worker_namespace_name",
    ),
    (
        "collector_workers",
        "name",
        "ix_collector_workers_name",
        "uq_collector_worker_namespace_name",
    ),
    (
        "collector_deployments",
        "name",
        "ix_collector_deployments_name",
        "uq_collector_deployment_namespace_name",
    ),
)


CONSTRAINT_KEYS = (
    (
        "ecosystem_transport_endpoints",
        "uq_ecosystem_transport_endpoint_name",
        ("name",),
    ),
    (
        "ecosystem_transport_workers",
        "uq_ecosystem_transport_worker_name",
        ("name",),
    ),
    (
        "ecosystem_transport_jobs",
        "uq_ecosystem_transport_job_dedupe",
        ("dedupe_key",),
    ),
)


def upgrade() -> None:
    for table, column, index_name, constraint_name in INDEX_KEYS:
        op.drop_index(index_name, table_name=table)
        op.create_index(index_name, table, [column], unique=False)
        with op.batch_alter_table(table) as batch:
            batch.create_unique_constraint(
                constraint_name,
                ["tenant_id", "region_id", column],
            )

    # The original worker constraint was unnamed. PostgreSQL assigns a name;
    # SQLite batch reflection synthesizes one using the convention below.
    constraints = [item
        for item in sa.inspect(op.get_bind()).get_unique_constraints("knowledge_projection_workers")
        if item["column_names"] == ["name"]]
    if len(constraints) != 1:
        raise RuntimeError("Expected one legacy unique constraint on knowledge_projection_workers.name")
    legacy_name = constraints[0]["name"] or "uq_knowledge_projection_workers_name"
    with op.batch_alter_table(
        "knowledge_projection_workers",
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch:
        batch.drop_constraint(
            legacy_name,
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_knowledge_projection_worker_namespace_name",
            ["tenant_id", "region_id", "name"],
        )

    for table, constraint_name, columns in CONSTRAINT_KEYS:
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(constraint_name, type_="unique")
            batch.create_unique_constraint(
                constraint_name,
                ["tenant_id", "region_id", *columns],
            )

    op.drop_index("uq_mcp_tool_active_name", table_name="mcp_tool_activations")
    op.create_index(
        "uq_mcp_tool_active_name",
        "mcp_tool_activations",
        ["tenant_id", "region_id", "tool_name"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("uq_mcp_tool_active_name", table_name="mcp_tool_activations")
    op.create_index(
        "uq_mcp_tool_active_name",
        "mcp_tool_activations",
        ["tool_name"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )

    for table, constraint_name, columns in reversed(CONSTRAINT_KEYS):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(constraint_name, type_="unique")
            batch.create_unique_constraint(constraint_name, list(columns))

    with op.batch_alter_table("knowledge_projection_workers") as batch:
        batch.drop_constraint(
            "uq_knowledge_projection_worker_namespace_name",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_knowledge_projection_workers_name",
            ["name"],
        )

    for table, column, index_name, constraint_name in reversed(INDEX_KEYS):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(constraint_name, type_="unique")
        op.drop_index(index_name, table_name=table)
        op.create_index(index_name, table, [column], unique=True)
