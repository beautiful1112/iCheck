"""Preserve terminal Tool-call evidence after its atomic completion."""

from alembic import op
import sqlalchemy as sa


revision = "e2g4i6k8m0p3"
down_revision = "d1f3h5j7l9n2"
branch_labels = depends_on = None
TABLE = "investigation_tool_calls"
TRIGGER = "icheck_terminal_tool_call_fence"


def upgrade():
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(sa.text(f"""CREATE FUNCTION {TRIGGER}() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.status IN ('succeeded', 'failed') THEN
            RAISE EXCEPTION 'Terminal Tool calls are immutable';
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END $$"""))
    op.execute(sa.text(
        f"CREATE TRIGGER {TRIGGER} BEFORE UPDATE OR DELETE ON {TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {TRIGGER}()"
    ))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    if bind.execute(sa.text(f"SELECT 1 FROM {TABLE} WHERE status IN ('succeeded','failed') LIMIT 1")).first():
        raise RuntimeError("Cannot remove terminal Tool-call fence with retained terminal results")
    op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
    op.execute(sa.text(f"DROP FUNCTION {TRIGGER}()"))
