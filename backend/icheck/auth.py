from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db, set_session_namespace
from .services.control_plane_auth import (
    ControlPlaneAuthenticationError,
    ControlPlaneAuthorizationError,
    PrincipalContext,
    authenticate_access_token,
    authenticate_browser_session,
    development_principal,
)
from .services.audit import record_audit_event


def current_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_icheck_csrf_token: Annotated[
        str | None,
        Header(alias="X-Icheck-CSRF-Token"),
    ] = None,
    x_icheck_tenant_id: Annotated[
        str | None,
        Header(alias="X-Icheck-Tenant-ID"),
    ] = None,
    x_icheck_region_id: Annotated[
        str | None,
        Header(alias="X-Icheck-Region-ID"),
    ] = None,
    icheck_tenant_id: Annotated[
        str | None,
        Query(alias="icheck_tenant_id"),
    ] = None,
    icheck_region_id: Annotated[
        str | None,
        Query(alias="icheck_region_id"),
    ] = None,
    browser_session: Annotated[
        str | None,
        Cookie(alias="icheck_session"),
    ] = None,
    db: Session = Depends(get_db),
) -> PrincipalContext:
    settings = get_settings()
    if settings.control_plane_auth_mode == "disabled":
        principal = development_principal()
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        return principal
    try:
        if authorization:
            principal = authenticate_access_token(
                db,
                authorization,
                tenant_selector=x_icheck_tenant_id or icheck_tenant_id,
                region_selector=x_icheck_region_id or icheck_region_id,
            )
        else:
            principal = authenticate_browser_session(
                db,
                browser_session,
                csrf_token=x_icheck_csrf_token,
                require_csrf=request.method.upper()
                in {"POST", "PUT", "PATCH", "DELETE"},
                tenant_selector=x_icheck_tenant_id or icheck_tenant_id,
                region_selector=x_icheck_region_id or icheck_region_id,
            )
        set_session_namespace(db, principal.tenant_id, principal.region_id)
        return principal
    except ControlPlaneAuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except ControlPlaneAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_permissions(*permissions: str) -> Callable[..., PrincipalContext]:
    def dependency(
        request: Request,
        principal: PrincipalContext = Depends(current_principal),
        db: Session = Depends(get_db),
    ) -> PrincipalContext:
        if not principal.permits(*permissions):
            record_audit_event(
                db,
                event_type="auth.permission.denied",
                actor_type=principal.principal_type,
                actor_id=principal.subject,
                entity_type="api_route",
                entity_id=request.url.path,
                outcome="denied",
                details={
                    "method": request.method,
                    "required_permissions": list(permissions),
                },
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required permission: {', '.join(permissions)}",
            )
        return principal

    return dependency


def require_global_permissions(
    *permissions: str,
) -> Callable[..., PrincipalContext]:
    def dependency(
        request: Request,
        principal: PrincipalContext = Depends(require_permissions(*permissions)),
        db: Session = Depends(get_db),
    ) -> PrincipalContext:
        if principal.authorization_scope.get("all") is not True:
            record_audit_event(
                db,
                event_type="auth.scope.denied",
                actor_type=principal.principal_type,
                actor_id=principal.subject,
                entity_type="api_route",
                entity_id=request.url.path,
                outcome="denied",
                details={"method": request.method, "required_scope": "all"},
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This operation requires global authorization scope",
            )
        return principal

    return dependency


def require_platform_permissions(
    *permissions: str,
) -> Callable[..., PrincipalContext]:
    def dependency(
        request: Request,
        principal: PrincipalContext = Depends(require_permissions(*permissions)),
        db: Session = Depends(get_db),
    ) -> PrincipalContext:
        if not principal.platform_admin:
            record_audit_event(
                db,
                event_type="auth.platform_scope.denied",
                actor_type=principal.principal_type,
                actor_id=principal.subject,
                entity_type="api_route",
                entity_id=request.url.path,
                outcome="denied",
                details={"method": request.method},
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This operation requires platform administration",
            )
        return principal

    return dependency
