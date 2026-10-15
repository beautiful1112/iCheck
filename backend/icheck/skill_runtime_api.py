from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .agent_schemas import InvestigationStartResult
from .auth import require_permissions
from .database import get_db
from .services.authorization_scope import (
    request_actor,
    require_requested_investigation_scope,
)
from .services.control_plane_auth import PrincipalContext
from .services.skill_runtime import (
    create_skill_investigation,
    list_published_skills,
    published_skill_read,
    skill_version,
)
from .skill_runtime_schemas import PublishedSkillRead, SkillInvestigationCreate


router = APIRouter(prefix="/api/v1/skill-runtime", tags=["skill-runtime"])
DBSession = Annotated[Session, Depends(get_db)]


@router.get("/skills", response_model=list[PublishedSkillRead])
def list_published_skills_route(
    db: DBSession,
    _: PrincipalContext = Depends(
        require_permissions("investigations.create")
    ),
) -> list[PublishedSkillRead]:
    return [published_skill_read(item) for item in list_published_skills(db)]


@router.post(
    "/skills/{version_id}/investigations",
    response_model=InvestigationStartResult,
)
def run_published_skill_route(
    version_id: str,
    payload: SkillInvestigationCreate,
    db: DBSession,
    principal: PrincipalContext = Depends(
        require_permissions("investigations.create")
    ),
) -> dict[str, object]:
    require_requested_investigation_scope(db, principal, payload.scope)
    try:
        investigation, checkpoint = create_skill_investigation(
            db,
            skill_version(db, version_id),
            payload,
            principal=principal,
            actor=request_actor(principal, payload.actor),
        )
        return {"investigation": investigation, "checkpoint": checkpoint}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
