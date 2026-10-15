"""Seal validated activation policy content and lifecycle at the database boundary.

Revision ID: h7k9m1p3r5t8
Revises: g6j8l0n2p4r7
"""

from alembic import op
import sqlalchemy as sa


revision = "h7k9m1p3r5t8"
down_revision = "g6j8l0n2p4r7"
branch_labels = depends_on = None

TABLE = "device_activation_policies"
FUNCTION = "icheck_guard_device_activation_policy"
TRIGGER = "icheck_device_activation_policy_lifecycle"
IDENTITY = (
    "id", "tenant_id", "region_id", "name", "version", "created_by", "created_at",
)
CONTENT = (
    "protocol", "adapter_type", "artifact_version_id", "target_template",
    "configuration_defaults", "worker_selector", "execution_mode", "schedule_seconds",
)
JSON_FIELDS = frozenset(("target_template", "configuration_defaults", "worker_selector"))
UPDATED = ("updated_by", "updated_at")
VALIDATION = ("content_hash", "validated_at", "validated_by")
PUBLICATION = ("published_at", "published_by")


def _changed(fields: tuple[str, ...], dialect: str) -> str:
    expressions = []
    for field in fields:
        before = f'OLD."{field}"'
        after = f'NEW."{field}"'
        if dialect == "postgresql" and field in JSON_FIELDS:
            before += "::text"
            after += "::text"
        comparison = "IS DISTINCT FROM" if dialect == "postgresql" else "IS NOT"
        expressions.append(f"{before} {comparison} {after}")
    return "(" + " OR ".join(expressions) + ")"


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect not in ("postgresql", "sqlite"):
        raise RuntimeError("Activation policy lifecycle guard requires PostgreSQL or SQLite")
    identity = _changed(IDENTITY, dialect)
    content = _changed(CONTENT, dialect)
    updated = _changed(UPDATED, dialect)
    validation = _changed(VALIDATION, dialect)
    publication = _changed(PUBLICATION, dialect)
    frozen = _changed(CONTENT + ("revision",) + UPDATED + VALIDATION, dialect)
    draft_edit_invalid = (
        f"({validation} OR {publication} OR "
        f"({content} AND (NEW.revision <> OLD.revision + 1 "
        "OR NEW.updated_by IS NULL OR NEW.updated_at IS NULL "
        + ("OR NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at" if dialect == "postgresql"
           else "OR NEW.updated_at IS OLD.updated_at")
        + f")) OR (NOT {content} AND (NEW.revision <> OLD.revision OR {updated})))"
    )
    validate_invalid = (
        f"({content} OR {updated} OR {publication} "
        "OR NEW.revision <> OLD.revision OR NEW.content_hash IS NULL "
        "OR NEW.validated_at IS NULL OR NEW.validated_by IS NULL)"
    )
    if dialect == "postgresql":
        op.execute(sa.text(
            f"CREATE FUNCTION {FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN "
            "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION "
            "'Activation policy history cannot be deleted'; END IF; "
            f"IF {identity} THEN RAISE EXCEPTION "
            "'Activation policy identity is sealed'; END IF; "
            "IF OLD.status = 'DRAFT' THEN "
            "IF NEW.status = 'DRAFT' THEN "
            f"IF {draft_edit_invalid} THEN RAISE EXCEPTION "
            "'Activation policy draft revision is invalid'; END IF; "
            "ELSIF NEW.status = 'VALIDATED' THEN "
            f"IF {validate_invalid} THEN RAISE EXCEPTION "
            "'Activation policy validation is invalid'; END IF; "
            "ELSE RAISE EXCEPTION 'Activation policy lifecycle is sealed'; END IF; "
            "ELSIF OLD.status = 'VALIDATED' THEN "
            f"IF NEW.status <> 'PUBLISHED' OR {frozen} "
            "OR NEW.published_at IS NULL OR NEW.published_by IS NULL "
            "THEN RAISE EXCEPTION 'Activation policy lifecycle is sealed'; END IF; "
            "ELSIF OLD.status = 'PUBLISHED' THEN "
            f"IF NEW.status <> 'DEPRECATED' OR {frozen} OR {publication} "
            "THEN RAISE EXCEPTION 'Activation policy lifecycle is sealed'; END IF; "
            "ELSE RAISE EXCEPTION 'Activation policy lifecycle is sealed'; END IF; "
            "RETURN NEW; END; $$"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER {TRIGGER} BEFORE UPDATE OR DELETE ON {TABLE} "
            f"FOR EACH ROW EXECUTE FUNCTION {FUNCTION}()"
        ))
    else:
        invalid = (
            f"{identity} OR "
            f"(OLD.status = 'DRAFT' AND ((NEW.status = 'DRAFT' AND {draft_edit_invalid}) "
            f"OR (NEW.status = 'VALIDATED' AND {validate_invalid}) "
            "OR NEW.status NOT IN ('DRAFT', 'VALIDATED'))) OR "
            f"(OLD.status = 'VALIDATED' AND (NEW.status != 'PUBLISHED' OR {frozen} "
            "OR NEW.published_at IS NULL OR NEW.published_by IS NULL)) OR "
            f"(OLD.status = 'PUBLISHED' AND (NEW.status != 'DEPRECATED' OR {frozen} "
            f"OR {publication})) OR OLD.status = 'DEPRECATED'"
        )
        op.execute(sa.text(
            f"CREATE TRIGGER {TRIGGER}_update BEFORE UPDATE ON {TABLE} "
            f"WHEN {invalid} BEGIN SELECT RAISE(ABORT, "
            "'Activation policy lifecycle is sealed'); END"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER {TRIGGER}_delete BEFORE DELETE ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT, 'Activation policy history cannot be deleted'); END"
        ))


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER} ON {TABLE}"))
        op.execute(sa.text(f"DROP FUNCTION {FUNCTION}()"))
    elif dialect == "sqlite":
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER}_update"))
        op.execute(sa.text(f"DROP TRIGGER {TRIGGER}_delete"))
