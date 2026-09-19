from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .services.control_plane_auth import (
    ControlPlaneAuthenticationError,
    PrincipalContext,
    authenticate_access_token,
    development_principal,
)


def current_principal(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> PrincipalContext:
    settings = get_settings()
    if settings.control_plane_auth_mode == "disabled":
        return development_principal()
    try:
        return authenticate_access_token(db, authorization)
    except ControlPlaneAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_permissions(*permissions: str) -> Callable[..., PrincipalContext]:
    def dependency(
        principal: PrincipalContext = Depends(current_principal),
    ) -> PrincipalContext:
        if not principal.permits(*permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required permission: {', '.join(permissions)}",
            )
        return principal

    return dependency
