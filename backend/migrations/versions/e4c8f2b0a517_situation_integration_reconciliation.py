"""situation integration remote references and signed reconciliation

Revision ID: e4c8f2b0a517
Revises: d3b7e1a9f406
Create Date: 2026-09-28 16:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e4c8f2b0a517"
down_revision: str | None = "d3b7e1a9f406"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("situation_integration_bindings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "provider_key",
                sa.String(length=64),
                nullable=False,
                server_default="generic",
            )
        )
        batch_op.add_column(
            sa.Column(
                "remote_reference_tool_name", sa.String(length=255), nullable=True
            )
        )
        batch_op.add_column(
            sa.Column(
                "remote_reference_mapping",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "inbound_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column("inbound_key_id", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(
            sa.Column("inbound_public_key_pem", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "inbound_public_key_sha256", sa.String(length=64), nullable=True
            )
        )
        batch_op.create_index(
            "ix_situation_integration_bindings_provider_key", ["provider_key"]
        )
        batch_op.create_index(
            "ix_situation_integration_bindings_inbound_enabled",
            ["inbound_enabled"],
        )

    op.create_table(
        "situation_integration_remote_references",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("integration_event_id", sa.String(length=36), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("situation_id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("provider_key", sa.String(length=64), nullable=False),
        sa.Column("remote_id", sa.String(length=255), nullable=False),
        sa.Column("remote_url", sa.String(length=2048), nullable=True),
        sa.Column("remote_status", sa.String(length=128), nullable=True),
        sa.Column("remote_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_tool_call_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["integration_event_id"],
            ["situation_integration_events.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"],
            ["situation_integration_bindings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["situation_id"], ["situations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["source_tool_call_id"],
            ["investigation_tool_calls.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "integration_event_id", name="uq_situation_remote_ref_event"
        ),
        sa.UniqueConstraint(
            "binding_id", "remote_id", name="uq_situation_remote_ref_binding_id"
        ),
    )
    for column, unique in (
        ("integration_event_id", False),
        ("binding_id", False),
        ("situation_id", False),
        ("investigation_id", False),
        ("provider_key", False),
        ("remote_id", False),
        ("remote_status", False),
        ("source_tool_call_id", False),
    ):
        op.create_index(
            f"ix_situation_integration_remote_references_{column}",
            "situation_integration_remote_references",
            [column],
            unique=unique,
        )

    op.create_table(
        "situation_integration_inbound_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("reference_id", sa.String(length=36), nullable=False),
        sa.Column("provider_event_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("remote_status", sa.String(length=128), nullable=False),
        sa.Column("remote_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_key_id", sa.String(length=128), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('accepted', 'ignored_stale')",
            name="ck_situation_inbound_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"],
            ["situation_integration_bindings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["reference_id"],
            ["situation_integration_remote_references.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binding_id",
            "provider_event_id",
            name="uq_situation_inbound_provider_event",
        ),
    )
    for column in (
        "binding_id",
        "reference_id",
        "provider_event_id",
        "event_type",
        "remote_status",
        "remote_updated_at",
        "outcome",
        "received_at",
    ):
        op.create_index(
            f"ix_situation_integration_inbound_events_{column}",
            "situation_integration_inbound_events",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "binding_id",
            "reference_id",
            "provider_event_id",
            "event_type",
            "remote_status",
            "remote_updated_at",
            "outcome",
            "received_at",
        )
    ):
        op.drop_index(
            f"ix_situation_integration_inbound_events_{column}",
            table_name="situation_integration_inbound_events",
        )
    op.drop_table("situation_integration_inbound_events")
    for column, _unique in reversed(
        (
            ("integration_event_id", False),
            ("binding_id", False),
            ("situation_id", False),
            ("investigation_id", False),
            ("provider_key", False),
            ("remote_id", False),
            ("remote_status", False),
            ("source_tool_call_id", False),
        )
    ):
        op.drop_index(
            f"ix_situation_integration_remote_references_{column}",
            table_name="situation_integration_remote_references",
        )
    op.drop_table("situation_integration_remote_references")
    with op.batch_alter_table("situation_integration_bindings") as batch_op:
        batch_op.drop_index(
            "ix_situation_integration_bindings_inbound_enabled"
        )
        batch_op.drop_index("ix_situation_integration_bindings_provider_key")
        batch_op.drop_column("inbound_public_key_sha256")
        batch_op.drop_column("inbound_public_key_pem")
        batch_op.drop_column("inbound_key_id")
        batch_op.drop_column("inbound_enabled")
        batch_op.drop_column("remote_reference_mapping")
        batch_op.drop_column("remote_reference_tool_name")
        batch_op.drop_column("provider_key")
