"""Require reviewed target classification for Studio-generated Collectors.

Revision ID: l1n3p5r7t9v2
Revises: k0m2p4r6t8v1
"""

from datetime import UTC, datetime
import ipaddress
from urllib.parse import urlsplit

from alembic import op
import sqlalchemy as sa


revision = "l1n3p5r7t9v2"
down_revision = "k0m2p4r6t8v1"
branch_labels = depends_on = None


CONSTRAINT = "ck_collector_deployment_target_classification"
RULE = (
    "CASE "
    "WHEN target_classification IS NULL THEN external_source_reason IS NULL "
    "WHEN target_classification = 'registered_device' THEN "
    "scope_device_id IS NOT NULL AND external_source_reason IS NULL "
    "WHEN target_classification = 'external_source' THEN "
    "scope_device_id IS NULL AND external_source_reason IS NOT NULL "
    "AND length(trim(external_source_reason)) >= 10 "
    "WHEN target_classification = 'legacy_unreviewed' THEN "
    "external_source_reason IS NULL "
    "ELSE false END"
)


def _direct_device_target(target: object, management_ip: object, name: object) -> bool:
    """Frozen upgrade-time counterpart of the direct generated-target rule."""
    if not isinstance(target, dict):
        return False
    hosts: set[str] = set()
    url = target.get("url")
    if isinstance(url, str):
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"} or not hostname:
            return False
        hosts.add(hostname.lower())
    for key in ("host", "target"):
        value = target.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        host = value.strip()
        try:
            host = str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            if host.startswith("[") and "]:" in host:
                host = host[1:host.index("]")]
            elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
                host = host.rsplit(":", 1)[0]
        hosts.add(host.lower())
    return bool(hosts) and hosts.issubset({
        str(management_ip).lower(), str(name).lower(),
    })


def upgrade() -> None:
    connection = op.get_bind()
    metadata = sa.MetaData()
    deployments = sa.Table("collector_deployments", metadata, autoload_with=connection)
    versions = sa.Table("artifact_versions", metadata, autoload_with=connection)
    artifacts = sa.Table("artifacts", metadata, autoload_with=connection)
    devices = sa.Table("devices", metadata, autoload_with=connection)
    legacy_generated: list[str] = []
    legacy_scoped_generated: list[str] = []
    now = datetime.now(UTC)
    unscoped_query = (
        sa.select(
            deployments.c.id,
            deployments.c.lease_expires_at,
            artifacts.c.labels,
        )
        .join(versions, deployments.c.artifact_version_id == versions.c.id)
        .join(artifacts, versions.c.artifact_id == artifacts.c.id)
        .where(
            deployments.c.scope_device_id.is_(None),
            artifacts.c.labels["generated"].as_boolean().is_(True),
        )
        .order_by(deployments.c.id)
    )
    if connection.dialect.name == "postgresql":
        unscoped_query = unscoped_query.with_for_update(of=deployments)
    rows = connection.execute(unscoped_query)
    for row in rows:
        if not isinstance(row.labels, dict) or row.labels.get("generated") is not True:
            continue
        expires = row.lease_expires_at
        if expires is not None and (
            expires.replace(tzinfo=UTC) if expires.tzinfo is None
            else expires.astimezone(UTC)
        ) >= now:
            raise RuntimeError(
                "Drain active unscoped Studio Collector leases before target classification migration"
            )
        legacy_generated.append(row.id)

    scoped_query = (
        sa.select(
            deployments.c.id,
            deployments.c.target,
            deployments.c.lease_expires_at,
            artifacts.c.labels,
            devices.c.management_ip,
            devices.c.name,
        )
        .join(versions, deployments.c.artifact_version_id == versions.c.id)
        .join(artifacts, versions.c.artifact_id == artifacts.c.id)
        .outerjoin(devices, deployments.c.scope_device_id == devices.c.id)
        .where(
            deployments.c.scope_device_id.is_not(None),
            deployments.c.scope_device_identity_revision > 0,
            artifacts.c.labels["generated"].as_boolean().is_(True),
        )
        .order_by(deployments.c.id)
    )
    if connection.dialect.name == "postgresql":
        scoped_query = scoped_query.with_for_update(of=deployments)
    scoped_rows = connection.execute(scoped_query)
    for row in scoped_rows:
        if not isinstance(row.labels, dict) or row.labels.get("generated") is not True:
            continue
        if _direct_device_target(row.target, row.management_ip, row.name):
            continue
        expires = row.lease_expires_at
        if expires is not None and (
            expires.replace(tzinfo=UTC) if expires.tzinfo is None
            else expires.astimezone(UTC)
        ) >= now:
            raise RuntimeError(
                "Drain active scoped Studio Collector leases before endpoint-binding migration"
            )
        legacy_scoped_generated.append(row.id)

    op.add_column(
        "collector_deployments",
        sa.Column("target_classification", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "collector_deployments",
        sa.Column("external_source_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_collector_deployments_target_classification",
        "collector_deployments",
        ["target_classification"],
    )
    op.execute(sa.text(
        "UPDATE collector_deployments SET target_classification = 'registered_device' "
        "WHERE scope_device_id IS NOT NULL AND scope_device_identity_revision > 0"
    ))
    op.execute(sa.text(
        "UPDATE collector_deployments SET target_classification = 'legacy_unreviewed' "
        "WHERE scope_device_id IS NOT NULL AND scope_device_identity_revision = 0"
    ))
    needs_review = legacy_generated + legacy_scoped_generated
    for start in range(0, len(needs_review), 500):
        connection.execute(
            sa.text(
                "UPDATE collector_deployments SET "
                "target_classification = 'legacy_unreviewed', enabled = false, "
                "next_run_at = NULL, lease_worker_id = NULL, "
                "lease_token_hash = NULL, lease_expires_at = NULL "
                "WHERE id IN :ids"
            ).bindparams(sa.bindparam("ids", expanding=True)),
            {"ids": needs_review[start:start + 500]},
        )
    with op.batch_alter_table("collector_deployments") as batch:
        batch.create_check_constraint(CONSTRAINT, RULE)


def downgrade() -> None:
    connection = op.get_bind()
    classified = connection.execute(sa.text(
        "SELECT COUNT(*) FROM collector_deployments "
        "WHERE target_classification IS NOT NULL OR external_source_reason IS NOT NULL"
    )).scalar_one()
    if classified:
        raise RuntimeError("Cannot discard reviewed Collector target classifications")
    op.drop_index(
        "ix_collector_deployments_target_classification",
        table_name="collector_deployments",
    )
    with op.batch_alter_table("collector_deployments") as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.drop_column("external_source_reason")
        batch.drop_column("target_classification")
