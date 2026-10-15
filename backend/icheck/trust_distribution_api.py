from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .services.authorization_scope import request_actor
from .services.control_plane_auth import PrincipalContext
from .services.trust_distribution import (
    create_organization_trust_domain,
    export_organization_trust_bundle,
    import_organization_trust_bundle,
    list_organization_trust_bundle_imports,
    list_organization_trust_domains,
    list_organization_trust_root_rotations,
    preview_organization_trust_bundle,
    rotate_organization_trust_root,
    set_organization_trust_domain_state,
)
from .trust_distribution_schemas import (
    OrganizationTrustBundleImportCreate,
    OrganizationTrustBundleImportRead,
    OrganizationTrustBundlePreviewCreate,
    OrganizationTrustBundlePreviewRead,
    OrganizationTrustDomainCreate,
    OrganizationTrustDomainRead,
    OrganizationTrustDomainStateCreate,
    OrganizationTrustRootRotationCreate,
    OrganizationTrustRootRotationRead,
    SignedOrganizationTrustBundle,
)


router = APIRouter(
    prefix="/api/v1/organization-trust",
    tags=["organization-trust"],
)
DBSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/domains",
    response_model=OrganizationTrustDomainRead,
    status_code=status.HTTP_201_CREATED,
)
def create_organization_trust_domain_route(
    payload: OrganizationTrustDomainCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustDomainRead:
    try:
        return OrganizationTrustDomainRead.model_validate(
            create_organization_trust_domain(
                db,
                payload,
                actor=request_actor(principal, payload.created_by),
            )
        )
    except ValueError as exc:
        code = 409 if "already exists" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/domains",
    response_model=list[OrganizationTrustDomainRead],
)
def list_organization_trust_domains_route(
    db: DBSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[OrganizationTrustDomainRead]:
    return [
        OrganizationTrustDomainRead.model_validate(item)
        for item in list_organization_trust_domains(db, limit=limit)
    ]


@router.post(
    "/domains/{domain_id}/state",
    response_model=OrganizationTrustDomainRead,
)
def set_organization_trust_domain_state_route(
    domain_id: str,
    payload: OrganizationTrustDomainStateCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustDomainRead:
    try:
        return OrganizationTrustDomainRead.model_validate(
            set_organization_trust_domain_state(
                db,
                domain_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/bundles/preview",
    response_model=OrganizationTrustBundlePreviewRead,
)
def preview_organization_trust_bundle_route(
    domain_id: str,
    payload: OrganizationTrustBundlePreviewCreate,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustBundlePreviewRead:
    try:
        return preview_organization_trust_bundle(db, domain_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/domains/{domain_id}/bundles/import",
    response_model=OrganizationTrustBundleImportRead,
    status_code=status.HTTP_201_CREATED,
)
def import_organization_trust_bundle_route(
    domain_id: str,
    payload: OrganizationTrustBundleImportCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustBundleImportRead:
    try:
        return OrganizationTrustBundleImportRead.model_validate(
            import_organization_trust_bundle(
                db,
                domain_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        message = str(exc)
        code = 409 if (
            "sequence" in message
            or "not installable" in message
            or "already exists" in message
        ) else 422
        raise HTTPException(status_code=code, detail=message) from exc


@router.get(
    "/bundles",
    response_model=list[OrganizationTrustBundleImportRead],
)
def list_organization_trust_bundle_imports_route(
    db: DBSession,
    domain_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[OrganizationTrustBundleImportRead]:
    return [
        OrganizationTrustBundleImportRead.model_validate(item)
        for item in list_organization_trust_bundle_imports(
            db,
            domain_id=domain_id,
            limit=limit,
        )
    ]


@router.get(
    "/bundles/{import_id}/export",
    response_model=SignedOrganizationTrustBundle,
)
def export_organization_trust_bundle_route(
    import_id: str,
    db: DBSession,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> SignedOrganizationTrustBundle:
    try:
        return export_organization_trust_bundle(db, import_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/root-rotations",
    response_model=list[OrganizationTrustRootRotationRead],
)
def list_organization_trust_root_rotations_route(
    db: DBSession,
    domain_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    _: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> list[OrganizationTrustRootRotationRead]:
    return [
        OrganizationTrustRootRotationRead.model_validate(item)
        for item in list_organization_trust_root_rotations(
            db,
            domain_id=domain_id,
            limit=limit,
        )
    ]


@router.post(
    "/domains/{domain_id}/rotate-root",
    response_model=OrganizationTrustRootRotationRead,
)
def rotate_organization_trust_root_route(
    domain_id: str,
    payload: OrganizationTrustRootRotationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_global_permissions("auth.admin")
    ),
) -> OrganizationTrustRootRotationRead:
    try:
        return OrganizationTrustRootRotationRead.model_validate(
            rotate_organization_trust_root(
                db,
                domain_id,
                payload,
                actor=request_actor(principal, payload.actor),
            )
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
