"""Extend guided AI presets without changing existing key custody or approval."""
from alembic import op
import sqlalchemy as sa

revision = "a4g6i8k0m2p5"
down_revision = "z3f5h7j9l1n4"
branch_labels = depends_on = None


def _replace(expression):
    with op.batch_alter_table("ai_managed_connections") as batch:
        batch.drop_constraint("ck_ai_managed_preset", type_="check")
        batch.create_check_constraint("ck_ai_managed_preset", expression)


def upgrade():
    _replace("preset IN ('openrouter', 'openai', 'anthropic', 'gemini', 'deepseek', 'qwen_cn', 'qwen_sg')")


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM ai_managed_connections WHERE preset <> 'openrouter' LIMIT 1")).first():
        raise RuntimeError("Cannot remove provider presets while their credential custody exists")
    _replace("preset = 'openrouter'")
