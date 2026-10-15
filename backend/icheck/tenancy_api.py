from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import (
    current_principal,
    require_global_permissions,
    require_platform_permissions,
)
from .config import get_settings
from .database import get_db
from .models import ControlPlanePrincipal, Region, Tenant
from .services.control_plane_auth import (
    PrincipalContext,
    provision_tenant_admin,
)
from .services.tenancy import create_region, create_tenant
from .tenancy_schemas import (
    NamespaceContextRead,
    RegionCreate,
    RegionRead,
    TenantAdminCreate,
    TenantAdminIssue,
    TenantCreate,
    TenantRead,
)


router = APIRouter(prefix="/api/v1/tenancy", tags=["tenancy"])


def _tenant(db: Session, tenant_id: str) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _region(db: Session, region_id: str, tenant_id: str) -> Region:
    region = db.scalar(
        select(Region).where(
            Region.id == region_id,
            Region.tenant_id == tenant_id,
        )
    )
    if region is None:
        raise HTTPException(status_code=404, detail="Region not found")
    return region


@router.get("/context", response_model=NamespaceContextRead)
def namespace_context(
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    tenant = _tenant(db, principal.tenant_id)
    region = _region(db, principal.region_id, principal.tenant_id)
    stored = (
        db.get(ControlPlanePrincipal, principal.principal_id)
        if principal.principal_id
        else None
    )
    return {
        "tenant": tenant,
        "region": region,
        "allowed_region_ids": (
            list(stored.allowed_region_ids) if stored is not None else []
        ),
        "platform_admin": principal.platform_admin,
    }


@router.get("/tenants", response_model=list[TenantRead])
def list_tenants(
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_platform_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[Tenant]:
    return list(
        db.scalars(select(Tenant).order_by(Tenant.slug).limit(limit)).all()
    )


@router.post(
    "/tenants",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant_route(
    payload: TenantCreate,
    actor: PrincipalContext = Depends(
        require_platform_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> Tenant:
    try:
        tenant, _ = create_tenant(db, payload, actor=actor.subject)
        return tenant
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/tenants/{tenant_id}/admins",
    response_model=TenantAdminIssue,
    status_code=status.HTTP_201_CREATED,
)
def provision_tenant_admin_route(
    tenant_id: str,
    payload: TenantAdminCreate,
    actor: PrincipalContext = Depends(
        require_platform_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    tenant = _tenant(db, tenant_id)
    region = _region(db, tenant.default_region_id, tenant.id)
    try:
        principal, token, raw_token = provision_tenant_admin(
            db,
            tenant,
            region,
            payload,
            actor=actor,
            default_token_ttl_hours=(
                get_settings().control_plane_default_token_ttl_hours
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "principal": principal,
        "token": {"token": token, "access_token": raw_token},
    }


@router.get("/regions", response_model=list[RegionRead])
def list_regions(
    include_disabled: bool = False,
    principal: PrincipalContext = Depends(current_principal),
    db: Session = Depends(get_db),
) -> list[Region]:
    query = select(Region).where(Region.tenant_id == principal.tenant_id)
    if not include_disabled:
        query = query.where(Region.enabled.is_(True))
    return list(db.scalars(query.order_by(Region.code)).all())


@router.post(
    "/regions",
    response_model=RegionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_region_route(
    payload: RegionCreate,
    actor: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
    db: Session = Depends(get_db),
) -> Region:
    try:
        return create_region(
            db,
            _tenant(db, actor.tenant_id),
            payload,
            actor=actor.subject,
            bootstrap_principal_id=actor.principal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
