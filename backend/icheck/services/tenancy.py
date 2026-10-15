from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import (
    DEFAULT_REGION_ID,
    DEFAULT_TENANT_ID,
    session_namespace,
    set_session_namespace,
)
from ..models import (
    ControlPlaneRole,
    ControlPlaneRoleBinding,
    Region,
    Tenant,
    new_id,
)
from ..tenancy_schemas import RegionCreate, TenantCreate
from .audit import record_audit_event


DEFAULT_TENANT_SLUG = "local"
DEFAULT_REGION_CODE = "primary"


def _stage_region_defaults(db: Session) -> None:
    # Imports remain local to keep tenancy registry bootstrap independent from
    # the feature services that persist region-bound configuration.
    from ..builtin_agent_tools import ensure_builtin_agent_tools
    from .agent_profiles import ensure_default_agent_profiles
    from .alerts import ensure_default_rules
    from .change_risk_policies import ensure_change_risk_policies

    ensure_default_rules(db, commit=False)
    ensure_change_risk_policies(db, commit=False)
    ensure_default_agent_profiles(db, commit=False)
    ensure_builtin_agent_tools(db, commit=False)


def _restore_namespace(
    db: Session,
    namespace: tuple[str, str] | None,
) -> None:
    if namespace is not None:
        set_session_namespace(db, *namespace)


def ensure_default_namespace(db: Session) -> tuple[Tenant, Region]:
    tenant = db.get(Tenant, DEFAULT_TENANT_ID)
    region = db.get(Region, DEFAULT_REGION_ID)
    changed = False
    if tenant is None:
        tenant = Tenant(
            id=DEFAULT_TENANT_ID,
            tenant_id=DEFAULT_TENANT_ID,
            region_id=DEFAULT_REGION_ID,
            slug=DEFAULT_TENANT_SLUG,
            name="Local tenant",
            enabled=True,
            default_region_id=DEFAULT_REGION_ID,
            created_by="system.bootstrap",
        )
        db.add(tenant)
        changed = True
    if region is None:
        region = Region(
            id=DEFAULT_REGION_ID,
            tenant_id=DEFAULT_TENANT_ID,
            region_id=DEFAULT_REGION_ID,
            code=DEFAULT_REGION_CODE,
            name="Primary region",
            enabled=True,
            created_by="system.bootstrap",
        )
        db.add(region)
        changed = True
    if changed:
        db.commit()
    return tenant, region


def resolve_tenant(db: Session, selector: str) -> Tenant | None:
    return db.scalar(
        select(Tenant).where(
            or_(Tenant.id == selector, Tenant.slug == selector)
        )
    )


def resolve_region(
    db: Session,
    tenant_id: str,
    selector: str,
) -> Region | None:
    return db.scalar(
        select(Region).where(
            Region.tenant_id == tenant_id,
            or_(Region.id == selector, Region.code == selector),
        )
    )


def create_tenant(
    db: Session,
    payload: TenantCreate,
    *,
    actor: str,
) -> tuple[Tenant, Region]:
    tenant_id = new_id()
    region_id = new_id()
    tenant = Tenant(
        id=tenant_id,
        tenant_id=tenant_id,
        region_id=region_id,
        slug=payload.slug,
        name=payload.name,
        enabled=True,
        default_region_id=region_id,
        created_by=actor,
    )
    region = Region(
        id=region_id,
        tenant_id=tenant_id,
        region_id=region_id,
        code=payload.default_region_code,
        name=payload.default_region_name,
        enabled=True,
        created_by=actor,
    )
    original_namespace = session_namespace(db)
    db.add_all((tenant, region))
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="tenancy.tenant.created",
            actor_type="user",
            actor_id=actor,
            entity_type="tenant",
            entity_id=tenant.id,
            details={
                "slug": tenant.slug,
                "default_region_id": region.id,
            },
        )
        db.flush()
        set_session_namespace(db, tenant.id, region.id)
        _stage_region_defaults(db)
        db.flush()
        _restore_namespace(db, original_namespace)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _restore_namespace(db, original_namespace)
        raise ValueError("Tenant slug already exists") from exc
    except Exception:
        db.rollback()
        _restore_namespace(db, original_namespace)
        raise
    db.refresh(tenant)
    db.refresh(region)
    return tenant, region


def create_region(
    db: Session,
    tenant: Tenant,
    payload: RegionCreate,
    *,
    actor: str,
    bootstrap_principal_id: str | None = None,
) -> Region:
    region_id = new_id()
    region = Region(
        id=region_id,
        tenant_id=tenant.id,
        region_id=region_id,
        code=payload.code,
        name=payload.name,
        enabled=payload.enabled,
        created_by=actor,
    )
    original_namespace = session_namespace(db)
    db.add(region)
    try:
        db.flush()
        if bootstrap_principal_id is not None:
            admin_role = db.scalar(
                select(ControlPlaneRole).where(
                    ControlPlaneRole.name == "admin",
                    ControlPlaneRole.system.is_(True),
                )
            )
            if admin_role is None:
                raise RuntimeError("Built-in admin role is unavailable")
            db.add(
                ControlPlaneRoleBinding(
                    principal_id=bootstrap_principal_id,
                    role_id=admin_role.id,
                    scope={"all": True},
                    tenant_id=tenant.id,
                    region_id=region.id,
                    created_by=actor,
                )
            )
        record_audit_event(
            db,
            event_type="tenancy.region.created",
            actor_type="user",
            actor_id=actor,
            entity_type="region",
            entity_id=region.id,
            details={"tenant_id": tenant.id, "code": region.code},
        )
        db.flush()
        set_session_namespace(db, tenant.id, region.id)
        _stage_region_defaults(db)
        db.flush()
        _restore_namespace(db, original_namespace)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _restore_namespace(db, original_namespace)
        raise ValueError("Region code already exists in this tenant") from exc
    except Exception:
        db.rollback()
        _restore_namespace(db, original_namespace)
        raise
    db.refresh(region)
    return region
