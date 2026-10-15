"""Durable, namespaced AI activation policy proposal history.

Revision ID: w6y8a0c2e5g8
Revises: v5x7z9b1d3f6
"""

from alembic import op
import sqlalchemy as sa


revision = "w6y8a0c2e5g8"
down_revision = "v5x7z9b1d3f6"
branch_labels = depends_on = None

TABLE = "activation_policy_proposals"
FROZEN = (
    "id", "tenant_id", "region_id", "parent_id", "device_id",
    "artifact_version_id", "protocol", "actor", "request_key",
    "request_sha256", "brief", "created_at",
)


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(36), nullable=False,
            server_default="00000000-0000-0000-0000-000000000001",
        ),
        sa.Column(
            "region_id", sa.String(36), nullable=False,
            server_default="00000000-0000-0000-0000-000000000002",
        ),
        sa.Column(
            "parent_id", sa.String(36),
            sa.ForeignKey(f"{TABLE}.id", ondelete="RESTRICT"), nullable=True,
        ),
        sa.Column(
            "device_id", sa.String(36),
            sa.ForeignKey("devices.id", ondelete="RESTRICT"), nullable=True,
        ),
        sa.Column(
            "artifact_version_id", sa.String(36),
            sa.ForeignKey("artifact_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("request_key", sa.String(36), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("brief", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result_snapshot", sa.JSON(), nullable=False),
        sa.Column("result_sha256", sa.String(64), nullable=True),
        sa.Column("route_id", sa.String(36), nullable=True),
        sa.Column("model_id", sa.String(36), nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "region_id", "actor", "request_key",
            name="uq_activation_policy_proposal_request",
        ),
        sa.CheckConstraint(
            "status IN ('generating', 'succeeded', 'failed')",
            name="ck_activation_policy_proposal_status",
        ),
        sa.CheckConstraint(
            "tokens_used >= 0", name="ck_activation_policy_proposal_tokens",
        ),
    )
    for field in (
        "tenant_id", "region_id", "parent_id", "device_id",
        "artifact_version_id", "actor", "status", "created_at",
    ):
        op.create_index(f"ix_{TABLE}_{field}", TABLE, [field])
    op.create_index(
        "ix_activation_policy_proposal_device_created",
        TABLE, ["device_id", "created_at"],
    )
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            f"CREATE POLICY icheck_namespace_isolation ON {TABLE} "
            "USING (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true)) "
            "WITH CHECK (tenant_id = current_setting('icheck.tenant_id', true) "
            "AND region_id = current_setting('icheck.region_id', true))"
        ))
        changed = " OR ".join(
            f'OLD."{field}" IS DISTINCT FROM NEW."{field}"'
            for field in FROZEN
        )
        op.execute(sa.text(
            "CREATE FUNCTION icheck_guard_activation_policy_proposal() "
            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
            "IF TG_OP = 'DELETE' THEN "
            "RAISE EXCEPTION 'Activation proposal history cannot be deleted'; "
            "END IF; "
            "IF OLD.status != 'generating' OR "
            "NEW.status NOT IN ('succeeded', 'failed') OR "
            f"({changed}) THEN "
            "RAISE EXCEPTION 'Activation proposal history is sealed'; "
            "END IF; RETURN NEW; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_activation_policy_proposal "
            f"BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW "
            "EXECUTE FUNCTION icheck_guard_activation_policy_proposal()"
        ))
    elif dialect == "sqlite":
        changed = " OR ".join(
            f'OLD."{field}" IS NOT NEW."{field}"'
            for field in FROZEN
        )
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_activation_policy_proposal_update "
            f"BEFORE UPDATE ON {TABLE} WHEN OLD.status != 'generating' "
            f"OR NEW.status NOT IN ('succeeded', 'failed') OR ({changed}) "
            "BEGIN SELECT RAISE(ABORT, 'Activation proposal history is sealed'); END"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER icheck_sealed_activation_policy_proposal_delete "
            f"BEFORE DELETE ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT, 'Activation proposal history cannot be deleted'); END"
        ))


def downgrade() -> None:
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} LIMIT 1")).first():
        raise RuntimeError("Cannot downgrade recorded activation policy proposals")
    op.drop_table(TABLE)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION icheck_guard_activation_policy_proposal()"))
