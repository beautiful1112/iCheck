from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from .auth import require_permissions
from .database import get_db
from .public_research_http import ResearchUnavailable
from .research_schemas import ResearchRead, ResearchSearch, ResearchDocument, ResearchResult
from .services import research
from .services.control_plane_auth import PrincipalContext
from .openrouter_api import administrator, no_store
from .research_schemas import ResearchSettingsRead, ResearchSettingsUpdate, ResearchSettingsTest, ResearchSettingsTestRead
from .services import research_settings
from .services.openrouter_setup import ManagedAIUnavailable

router = APIRouter(prefix="/api/v1/research", tags=["public-research"])


@router.get("/status")
def status(principal: PrincipalContext = Depends(require_permissions("investigations.read")), db: Session = Depends(get_db)):
    return research.status(db)


@router.get("/settings", response_model=ResearchSettingsRead)
def settings(response: Response, _: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return research_settings.setup_status(db)


def settings_operation(operation, db, payload, principal):
    try:
        return operation(db, payload, actor=principal.subject)
    except research_settings.ResearchSettingsConflict as error:
        db.rollback()
        raise HTTPException(409, str(error), headers={"Cache-Control": "no-store"}) from None
    except ManagedAIUnavailable:
        db.rollback()
        raise HTTPException(503, "Encrypted search-key storage is unavailable; ask an administrator to check the existing AI key storage",
                            headers={"Cache-Control": "no-store"}) from None
    except ValueError as error:
        db.rollback()
        raise HTTPException(422, str(error), headers={"Cache-Control": "no-store"}) from None


@router.put("/settings", response_model=ResearchSettingsRead)
def save_settings(payload: ResearchSettingsUpdate, response: Response,
                  principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return settings_operation(research_settings.save, db, payload, principal)


@router.post("/settings/test", response_model=ResearchSettingsTestRead)
def test_settings(payload: ResearchSettingsTest, response: Response,
                  principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    no_store(response)
    return settings_operation(research_settings.test_connection, db, payload, principal)


def invoke(name, payload, db, principal):
    try:
        return research.tools_for_ai(name, db, payload.model_dump(), principal)[0]
    except ResearchUnavailable as error:
        raise HTTPException(422, str(error)) from None


@router.post("/search", response_model=ResearchResult)
def search(payload: ResearchSearch, db: Session = Depends(get_db),
           principal: PrincipalContext = Depends(require_permissions("investigations.read"))):
    return invoke("research.search", payload, db, principal)


@router.post("/read", response_model=ResearchDocument)
def read(payload: ResearchRead, db: Session = Depends(get_db),
         principal: PrincipalContext = Depends(require_permissions("investigations.read"))):
    return invoke("research.read", payload, db, principal)
