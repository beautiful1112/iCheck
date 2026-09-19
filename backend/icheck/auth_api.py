from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import current_principal, require_permissions
from .auth_schemas import (
    AccessTokenCreate,
    AccessTokenIssue,
    AccessTokenRead,
    BootstrapRequest,
    BootstrapResult,
    PrincipalContextRead,
    PrincipalCreate,
    PrincipalRead,
    RoleBindingCreate,
    RoleBindingRead,
    RoleCreate,
    RoleRead,
    TokenRevoke,
)
from .config import get_settings
from .database import get_db
from .models import (
    ControlPlaneAccessToken,
    ControlPlanePrincipal,
    ControlPlaneRole,
    ControlPlaneRoleBinding,
)
from .services.control_plane_auth import (
    PrincipalContext,
    bootstrap_admin,
    create_principal,
    create_role,
    create_role_binding,
    issue_access_token,
    revoke_access_token,
)


router = APIRouter(prefix="/api/v1/auth", tags=["control-plane-auth"])


def _principal(db: Session, principal_id: str) -> ControlPlanePrincipal:
    principal = db.get(ControlPlanePrincipal, principal_id)
    if principal is None:
        raise HTTPException(status_code=404, detail="Principal not found")
    return principal


def _context_read(context: PrincipalContext) -> PrincipalContextRead:
    return PrincipalContextRead(
        principal_id=context.principal_id,
        subject=context.subject,
        principal_type=context.principal_type,
        permissions=sorted(context.permissions),
        role_names=list(context.role_names),
        authorization_scope=context.authorization_scope,
        auth_method=context.auth_method,
    )


@router.post(
    "/bootstrap",
    response_model=BootstrapResult,
    status_code=status.HTTP_201_CREATED,
)
def bootstrap_control_plane(
    payload: BootstrapRequest,
    bootstrap_token: str | None = Header(
        default=None, alias="X-Icheck-Bootstrap-Token"
    ),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    settings = get_settings()
    configured = settings.control_plane_bootstrap_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control-plane bootstrap is not configured",
        )
    if bootstrap_token is None or not secrets.compare_digest(
        configured, bootstrap_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid control-plane bootstrap token",
        )
    if not payload.enabled:
        raise HTTPException(
            status_code=422,
            detail="Bootstrap administrator must be enabled",
        )
    try:
        principal, token, raw_token = bootstrap_admin(
            db,
            payload,
            default_token_ttl_hours=settings.control_plane_default_token_ttl_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "principal": principal,
        "token": {"token": token, "access_token": raw_token},
    }


@router.get("/me", response_model=PrincipalContextRead)
def get_current_principal(
    principal: PrincipalContext = Depends(current_principal),
) -> PrincipalContextRead:
    return _context_read(principal)


@router.post(
    "/principals",
    response_model=PrincipalRead,
    status_code=status.HTTP_201_CREATED,
)
def create_principal_route(
    payload: PrincipalCreate,
    actor: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> ControlPlanePrincipal:
    try:
        return create_principal(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/principals", response_model=list[PrincipalRead])
def list_principals(
    enabled: bool | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlanePrincipal]:
    query = select(ControlPlanePrincipal)
    if enabled is not None:
        query = query.where(ControlPlanePrincipal.enabled == enabled)
    return list(
        db.scalars(query.order_by(ControlPlanePrincipal.subject).limit(limit)).all()
    )


@router.post(
    "/roles",
    response_model=RoleRead,
    status_code=status.HTTP_201_CREATED,
)
def create_role_route(
    payload: RoleCreate,
    actor: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> ControlPlaneRole:
    try:
        return create_role(db, payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/roles", response_model=list[RoleRead])
def list_roles(
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneRole]:
    return list(
        db.scalars(select(ControlPlaneRole).order_by(ControlPlaneRole.name).limit(limit)).all()
    )


@router.post(
    "/principals/{principal_id}/bindings",
    response_model=RoleBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_role_binding_route(
    principal_id: str,
    payload: RoleBindingCreate,
    actor: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> ControlPlaneRoleBinding:
    try:
        return create_role_binding(
            db,
            _principal(db, principal_id),
            payload,
            actor=actor,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        code = 409 if "already" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get(
    "/principals/{principal_id}/bindings",
    response_model=list[RoleBindingRead],
)
def list_role_bindings(
    principal_id: str,
    _: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneRoleBinding]:
    _principal(db, principal_id)
    return list(
        db.scalars(
            select(ControlPlaneRoleBinding)
            .where(ControlPlaneRoleBinding.principal_id == principal_id)
            .order_by(ControlPlaneRoleBinding.created_at)
        ).all()
    )


@router.post(
    "/principals/{principal_id}/tokens",
    response_model=AccessTokenIssue,
    status_code=status.HTTP_201_CREATED,
)
def issue_access_token_route(
    principal_id: str,
    payload: AccessTokenCreate,
    actor: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    settings = get_settings()
    token, raw_token = issue_access_token(
        db,
        _principal(db, principal_id),
        payload,
        actor=actor,
        default_token_ttl_hours=settings.control_plane_default_token_ttl_hours,
    )
    return {"token": token, "access_token": raw_token}


@router.get(
    "/principals/{principal_id}/tokens",
    response_model=list[AccessTokenRead],
)
def list_access_tokens(
    principal_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    _: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> list[ControlPlaneAccessToken]:
    _principal(db, principal_id)
    return list(
        db.scalars(
            select(ControlPlaneAccessToken)
            .where(ControlPlaneAccessToken.principal_id == principal_id)
            .order_by(ControlPlaneAccessToken.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.post("/tokens/{token_id}/revoke", response_model=AccessTokenRead)
def revoke_access_token_route(
    token_id: str,
    payload: TokenRevoke,
    actor: PrincipalContext = Depends(require_permissions("auth.admin")),
    db: Session = Depends(get_db),
) -> ControlPlaneAccessToken:
    token = db.get(ControlPlaneAccessToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Access token not found")
    try:
        return revoke_access_token(db, token, reason=payload.reason, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
