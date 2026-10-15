from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated, Any

from fastapi import Header
from sqlalchemy import String, and_, create_engine, false, text, true
from sqlalchemy import event
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
    with_loader_criteria,
)
from sqlalchemy.pool import StaticPool

from .config import get_settings


DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_REGION_ID = "00000000-0000-0000-0000-000000000002"


class NamespaceViolation(RuntimeError):
    """Raised when a write attempts to cross the active namespace."""


class Base(DeclarativeBase):
    # Every persisted row carries its security namespace. Identity and
    # namespace-registry tables opt out of automatic predicates, but retain
    # these columns so their service layer can bind them explicitly.
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        default=DEFAULT_TENANT_ID,
        server_default=DEFAULT_TENANT_ID,
        index=True,
        nullable=False,
    )
    region_id: Mapped[str] = mapped_column(
        String(36),
        default=DEFAULT_REGION_ID,
        server_default=DEFAULT_REGION_ID,
        index=True,
        nullable=False,
    )
    __namespace_exempt__ = False


settings = get_settings()
engine_options: dict[str, object] = {"pool_pre_ping": True}

if settings.database_url.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
    if ":memory:" in settings.database_url:
        engine_options["poolclass"] = StaticPool

engine = create_engine(settings.database_url, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def require_locking_transaction(db: Session, *, purpose: str) -> None:
    """Require atomic PostgreSQL row locks and fresh snapshots after a wait."""
    if db.get_bind().dialect.name != "postgresql":
        return
    connection = db.connection()
    # Isolation alone does not detect DBAPI autocommit, which releases row
    # locks after each statement. Unknown drivers must also fail closed.
    if (getattr(connection.connection.dbapi_connection, "autocommit", True)
        or connection.get_isolation_level() != "READ COMMITTED"):
        raise ValueError(
            f"{purpose} require PostgreSQL READ COMMITTED isolation with autocommit disabled"
        )


def set_session_namespace(
    db: Session,
    tenant_id: str,
    region_id: str,
    *,
    enforce: bool = True,
) -> None:
    """Bind all subsequent ORM work in this transaction to one namespace."""

    tenant_id = str(tenant_id).strip()
    region_id = str(region_id).strip()
    if not tenant_id or not region_id:
        raise NamespaceViolation("tenant_id and region_id are required")
    db.info["namespace_enforced"] = enforce
    db.info["tenant_id"] = tenant_id
    db.info["region_id"] = region_id
    if (
        db.in_transaction()
        and db.bind is not None
        and db.bind.dialect.name == "postgresql"
    ):
        _apply_database_namespace(db.connection(), tenant_id, region_id)


def session_namespace(db: Session) -> tuple[str, str] | None:
    tenant_id = db.info.get("tenant_id")
    region_id = db.info.get("region_id")
    if not tenant_id or not region_id:
        return None
    return str(tenant_id), str(region_id)


def validate_session_namespace(db: Session) -> tuple[str, str]:
    """Require an enabled tenant/region pair already bound to the session."""

    namespace = session_namespace(db)
    if namespace is None:
        raise NamespaceViolation(
            "X-Icheck-Tenant-ID and X-Icheck-Region-ID are required"
        )
    tenant_id, region_id = namespace
    # Imported lazily because the model module itself depends on Base.
    from .models import Region, Tenant

    tenant = db.get(Tenant, tenant_id)
    region = db.get(Region, region_id)
    if tenant is None or not tenant.enabled:
        raise NamespaceViolation("The selected tenant does not exist or is disabled")
    if (
        region is None
        or not region.enabled
        or region.tenant_id != tenant.id
        or region.region_id != region.id
    ):
        raise NamespaceViolation(
            "The selected region does not exist, is disabled, or belongs to another tenant"
        )
    return tenant.id, region.id


def _apply_database_namespace(
    connection: Any,
    tenant_id: str,
    region_id: str,
) -> None:
    connection.execute(
        text(
            "SELECT set_config('icheck.tenant_id', :tenant_id, true), "
            "set_config('icheck.region_id', :region_id, true)"
        ),
        {"tenant_id": tenant_id, "region_id": region_id},
    )


@event.listens_for(Session, "after_begin")
def _restore_database_namespace(
    db: Session,
    _transaction: Any,
    connection: Any,
) -> None:
    """Restore transaction-local PostgreSQL RLS selectors after every commit."""

    if connection.dialect.name != "postgresql":
        return
    namespace = session_namespace(db)
    if not db.info.get("namespace_enforced") or namespace is None:
        return
    _apply_database_namespace(connection, *namespace)


@contextmanager
def namespace_enforcement_suspended(db: Session):
    previous = db.info.get("namespace_enforced")
    db.info["namespace_enforced"] = False
    try:
        yield
    finally:
        db.info["namespace_enforced"] = previous


@event.listens_for(Session, "do_orm_execute")
def _enforce_namespace_on_orm(execute_state: Any) -> None:
    db = execute_state.session
    if not db.info.get("namespace_enforced"):
        return
    tenant_id = db.info.get("tenant_id")
    region_id = db.info.get("region_id")
    if tenant_id and region_id:
        predicate = with_loader_criteria(
            Base,
            lambda model: (
                true()
                if getattr(model, "__namespace_exempt__", False)
                else and_(
                    model.tenant_id == tenant_id,
                    model.region_id == region_id,
                )
            ),
            include_aliases=True,
        )
    else:
        predicate = with_loader_criteria(
            Base,
            lambda model: (
                true()
                if getattr(model, "__namespace_exempt__", False)
                else false()
            ),
            include_aliases=True,
        )
    execute_state.statement = execute_state.statement.options(predicate)


@event.listens_for(Session, "before_flush")
def _enforce_namespace_on_flush(
    db: Session,
    _flush_context: Any,
    _instances: Any,
) -> None:
    if not db.info.get("namespace_enforced"):
        return
    namespace = session_namespace(db)
    for instance in db.new:
        if not isinstance(instance, Base) or getattr(
            instance, "__namespace_exempt__", False
        ):
            continue
        if namespace is None:
            raise NamespaceViolation(
                "A tenant and region must be selected before writing data"
            )
        tenant_id, region_id = namespace
        existing_tenant = getattr(instance, "tenant_id", None)
        existing_region = getattr(instance, "region_id", None)
        if existing_tenant not in (None, tenant_id) or existing_region not in (
            None,
            region_id,
        ):
            raise NamespaceViolation(
                "The write namespace does not match the authenticated namespace"
            )
        instance.tenant_id = tenant_id
        instance.region_id = region_id


def get_db(
    x_icheck_tenant_id: Annotated[
        str | None,
        Header(alias="X-Icheck-Tenant-ID"),
    ] = None,
    x_icheck_region_id: Annotated[
        str | None,
        Header(alias="X-Icheck-Region-ID"),
    ] = None,
) -> Generator[Session, None, None]:
    db = SessionLocal()
    db.info["namespace_enforced"] = True
    if x_icheck_tenant_id and x_icheck_region_id:
        # Authentication will independently validate these selectors for user
        # requests. Worker bearer tokens are looked up inside this boundary.
        set_session_namespace(
            db, x_icheck_tenant_id, x_icheck_region_id
        )
    elif get_settings().control_plane_auth_mode == "disabled":
        set_session_namespace(db, DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
