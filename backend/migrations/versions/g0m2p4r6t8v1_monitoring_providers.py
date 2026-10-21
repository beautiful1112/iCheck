"""Add native Orion and normalized connector bridge providers."""
from alembic import op
import sqlalchemy as sa

revision = "g0m2p4r6t8v1"
down_revision = "f9l1n3q5s7u0"
branch_labels = depends_on = None
TABLE = "monitoring_integration_connections"
CONSTRAINT = "ck_monitoring_integration_provider"


def change(expression):
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_constraint(CONSTRAINT, type_="check")
        batch.create_check_constraint(CONSTRAINT, expression)


def upgrade():
    change("provider IN ('zabbix','solarwinds_orion','rest_webhook')")


def downgrade():
    if op.get_bind().execute(sa.text(f"SELECT 1 FROM {TABLE} WHERE provider != 'zabbix' LIMIT 1")).first():
        raise RuntimeError("Cannot remove configured monitoring providers")
    change("provider = 'zabbix'")
