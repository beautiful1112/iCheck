from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .agent_schemas import InvestigationRead
from .auth import require_global_permissions, require_permissions
from .autonomy_schemas import AlertInvestigationPolicyUpdate, CapabilityNeedRead, CapabilityNeed, InvestigationFollowup, CapabilityStudioLink
from .config import get_settings
from .database import get_db, require_locking_transaction
from .models import AlertInvestigationEvent, InvestigationCapabilityRequest, InvestigationCheckpoint, CapabilityStudioSession
from .services import alert_investigation, investigation_assistance
from .services.control_plane_auth import PrincipalContext


router = APIRouter(prefix="/api/v1/autonomy", tags=["investigation-assistance"])


def administrator(principal: PrincipalContext = Depends(require_global_permissions("ai.manage", "alerts.manage"))):
    if get_settings().control_plane_auth_mode != "disabled" and principal.principal_type != "user":
        raise HTTPException(403, "A human administrator must authorize automatic investigation")
    return principal


@router.get("/alert-policy")
def read_policy(response: Response, _: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return alert_investigation.policy_status(db)


@router.put("/alert-policy")
def save_policy(payload: AlertInvestigationPolicyUpdate, response: Response,
                principal: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    try:
        return alert_investigation.save_policy(db, payload, principal)
    except (ValueError, PermissionError, IntegrityError) as error:
        db.rollback()
        if isinstance(error, IntegrityError):
            raise HTTPException(409, "Policy changed; reload before saving") from None
        raise HTTPException(403 if isinstance(error, PermissionError) else 409, str(error)) from None


@router.get("/alert-events")
def events(limit: int = Query(default=50, ge=1, le=100),
           _: PrincipalContext = Depends(administrator), db: Session = Depends(get_db)):
    rows = db.scalars(select(AlertInvestigationEvent).order_by(AlertInvestigationEvent.created_at.desc()).limit(limit))
    return [dict(id=row.id, alert_id=row.alert_id, investigation_id=row.investigation_id,
                 status=row.status, reason=row.reason, created_at=row.created_at) for row in rows]


@router.get("/investigations/{investigation_id}/requests", response_model=list[CapabilityNeedRead])
def requests(investigation_id: str, principal: PrincipalContext = Depends(require_permissions("investigations.read")),
             db: Session = Depends(get_db)):
    investigation_assistance.visible_investigation(db, investigation_id, principal)
    return [investigation_assistance.request_document(row) for row in db.scalars(
        select(InvestigationCapabilityRequest).where(InvestigationCapabilityRequest.investigation_id == investigation_id)
        .order_by(InvestigationCapabilityRequest.created_at))]


@router.get("/requests/{request_id}", response_model=CapabilityNeedRead)
def request_details(request_id: str, principal: PrincipalContext = Depends(require_permissions("investigations.read")),
                    db: Session = Depends(get_db)):
    row = db.get(InvestigationCapabilityRequest, request_id)
    if row is None:
        raise HTTPException(404, "Capability request not found")
    investigation_assistance.visible_investigation(db, row.investigation_id, principal)
    return investigation_assistance.request_document(row)


@router.post("/investigations/{investigation_id}/save-skill", response_model=CapabilityNeedRead)
def save_skill(investigation_id: str, principal: PrincipalContext = Depends(require_permissions("investigations.read", "investigations.create")),
               db: Session = Depends(get_db)):
    investigation = investigation_assistance.visible_investigation(db, investigation_id, principal)
    if investigation.status != "completed":
        raise HTTPException(409, "Complete the investigation before saving its approach")
    checkpoint = db.scalar(select(InvestigationCheckpoint).where(
        InvestigationCheckpoint.investigation_id == investigation.id).order_by(InvestigationCheckpoint.sequence.desc()).limit(1))
    plan = ((checkpoint.state or {}).get("plan") or [])[:12] if checkpoint else []
    return investigation_assistance.save_request(db, investigation, CapabilityNeed(kind="skill",
        description=("Create a reusable read-only diagnostic Skill for this objective. Generalize device-specific inputs, "
            "require fresh evidence and escalation when evidence is insufficient. Do not embed credentials.\n" + investigation.objective[:1800]
            + "\nRecorded approach (historical guidance, not proof):\n" + "\n".join(str(step)[:140] for step in plan))[:4000],
        reason="Operator requested a reusable Skill from this completed investigation"))


@router.put("/requests/{request_id}/studio-session", response_model=CapabilityNeedRead)
def link_studio(request_id: str, payload: CapabilityStudioLink,
                principal: PrincipalContext = Depends(require_global_permissions("capabilities.manage", "investigations.read")),
                db: Session = Depends(get_db)):
    require_locking_transaction(db, purpose="Capability authoring handoff")
    row = db.scalar(select(InvestigationCapabilityRequest).where(InvestigationCapabilityRequest.id == request_id).with_for_update())
    if row is None:
        raise HTTPException(404, "Capability request not found")
    investigation_assistance.visible_investigation(db, row.investigation_id, principal)
    session = db.get(CapabilityStudioSession, payload.session_id)
    expected_kind = "tool" if row.kind == "mcp" else row.kind
    if (session is None or session.artifact_kind != expected_kind
            or row.kind == "mcp" and not (session.sample_document or {}).get("executable_extension")):
        raise HTTPException(409, "Studio session is unavailable or has a different capability kind")
    if row.studio_session_id is not None and row.studio_session_id != session.id:
        raise HTTPException(409, "This request already has an authoring session; reopen its saved link")
    if row.studio_session_id is None:
        from .services.audit import record_audit_event
        record_audit_event(db, event_type="investigation.capability_authoring_linked", actor_type="user",
            actor_id=principal.subject, entity_type="investigation", entity_id=row.investigation_id,
            details={"request_id": row.id, "studio_session_id": session.id})
    row.studio_session_id = session.id
    db.commit()
    return investigation_assistance.request_document(row)


@router.post("/investigations/{investigation_id}/continue", response_model=InvestigationRead, status_code=201)
def continue_investigation(investigation_id: str, payload: InvestigationFollowup,
                          principal: PrincipalContext = Depends(require_permissions("investigations.read", "investigations.create")),
                          db: Session = Depends(get_db)):
    investigation = investigation_assistance.visible_investigation(db, investigation_id, principal, lock=True)
    try:
        return investigation_assistance.followup(db, investigation, payload, principal)
    except (ValueError, LookupError) as error:
        db.rollback()
        raise HTTPException(409, str(error)) from None
