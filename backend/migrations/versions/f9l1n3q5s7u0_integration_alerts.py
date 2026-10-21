"""Durable external alert feeds and event identities, disabled by default."""
from alembic import op
import sqlalchemy as sa

revision = "f9l1n3q5s7u0"
down_revision = "e8k0m2p4r6t9"
branch_labels = depends_on = None
FEEDS = "monitoring_integration_alert_feeds"
EVENTS = "monitoring_integration_events"


def namespace():
    return [sa.Column("tenant_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000001"),
            sa.Column("region_id", sa.String(36), nullable=False, server_default="00000000-0000-0000-0000-000000000002")]


def upgrade():
    op.create_table(FEEDS, *namespace(),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("cursor", sa.String(20), nullable=False),
        sa.Column("bootstrap_ids", sa.JSON()),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(64)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.CheckConstraint("revision > 0 AND connection_revision > 0", name="ck_integration_alert_feed_revision"),
        sa.CheckConstraint("interval_seconds >= 60 AND interval_seconds <= 3600", name="ck_integration_alert_feed_interval"),
        sa.CheckConstraint("phase IN ('bootstrap','new','reconcile')", name="ck_integration_alert_feed_phase"))
    op.create_table(EVENTS, *namespace(),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("monitoring_integration_connections.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connection_revision", sa.Integer(), nullable=False),
        sa.Column("remote_id", sa.String(20), nullable=False),
        sa.Column("observation", sa.JSON(), nullable=False),
        sa.Column("available", sa.Boolean(), nullable=False),
        sa.Column("source_resolved", sa.Boolean(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="RESTRICT")),
        sa.Column("resource_id", sa.String(36), sa.ForeignKey("monitoring_integration_resources.id", ondelete="RESTRICT")),
        sa.Column("binding_revision", sa.Integer()),
        sa.Column("stopped_at", sa.DateTime(timezone=True)),
        sa.Column("stop_reason", sa.String(128)),
        sa.UniqueConstraint("tenant_id", "region_id", "connection_id", "remote_id", name="uq_integration_event_identity"),
        sa.UniqueConstraint("alert_id", name="uq_integration_event_alert"))
    for table, fields in ((FEEDS, ("tenant_id", "region_id", "next_run_at")), (EVENTS, ("tenant_id", "region_id", "connection_id", "checked_at"))):
        for field in fields:
            op.create_index(f"ix_{table}_{field}", table, [field])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            predicate = "tenant_id=current_setting('icheck.tenant_id',true) AND region_id=current_setting('icheck.region_id',true)"
            op.execute(sa.text(f"CREATE POLICY icheck_namespace_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})"))


def downgrade():
    for table in (EVENTS, FEEDS):
        if op.get_bind().execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("Cannot discard external alert feeds or event history")
    op.drop_table(EVENTS)
    op.drop_table(FEEDS)
