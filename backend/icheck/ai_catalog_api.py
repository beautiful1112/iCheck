"""Human-approved AI catalog retirement/restoration; retain all referenced history."""
import hashlib
import json
import secrets
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from .ai_schemas import AIStrictModel
from .auth import require_global_permissions
from .config import get_settings
from .database import get_db, session_namespace
from .models import AIManagedConnection, AIModelConfig, AIModelRoute, AIProviderConfig, CredentialProfile, Investigation
from .services.control_plane_auth import PrincipalContext
from .services.audit import record_audit_event
from .ai_failure_diagnostics import batch_model
from .services.ai_catalog_mutex import catalog_lock

router = APIRouter(prefix="/api/v1/ai/catalog", tags=["ai-settings"])
Kind = Literal["credentials", "providers", "models", "routes"]
MODELS = {"credentials": CredentialProfile, "providers": AIProviderConfig, "models": AIModelConfig, "routes": AIModelRoute}


class LifecyclePreview(AIStrictModel):
    enabled: bool


class LifecycleApply(LifecyclePreview):
    preview_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=1, max_length=1000)


def admin(principal: PrincipalContext = Depends(require_global_permissions("ai.manage"))):
    if get_settings().control_plane_auth_mode != "disabled" and principal.principal_type != "user":
        raise HTTPException(status_code=403, detail="A human AI administrator is required")
    return principal


def plan(db, kind, item_id, enabled):
    row = db.scalar(select(MODELS[kind]).where(MODELS[kind].id == item_id)
        .execution_options(populate_existing=True).with_for_update())
    if row is None: raise HTTPException(status_code=404, detail="AI configuration item not found")
    if kind == "credentials" and "ai_provider" not in row.allowed_adapters:
        raise HTTPException(status_code=404, detail="AI credential reference not found")
    routes = db.scalars(select(AIModelRoute).where(AIModelRoute.enabled.is_(True)).with_for_update()).all()
    models = db.scalars(select(AIModelConfig).where(AIModelConfig.enabled.is_(True)).with_for_update()).all()
    providers = db.scalars(select(AIProviderConfig).where(AIProviderConfig.enabled.is_(True)).with_for_update()).all()
    active = db.scalars(select(Investigation).where(Investigation.status.in_(["pending", "running", "waiting_approval"]))).all()
    blockers, dependencies = [], []
    if not enabled:
        if kind == "models":
            dependencies = [{"kind": "route", "id": r.id, "name": r.purpose} for r in routes
                if row.id == r.primary_model_id or row.id in (r.fallback_model_ids or [])]
            if any(row.id == i.model_id or row.id in (i.fallback_model_ids or []) for i in active):
                blockers.append("An active investigation pins this model; wait for it to finish or cancel it first.")
        elif kind == "providers":
            dependencies = [{"kind": "model", "id": m.id, "name": m.display_name} for m in models if m.provider_id == row.id]
        elif kind == "credentials":
            if set(row.allowed_adapters) != {"ai_provider"}:
                blockers.append("This reference is shared with non-AI adapters. AI-only retirement is not permitted; use a separate AI credential reference so device/collector consumers remain protected.")
            dependencies = [{"kind": "provider", "id": p.id, "name": p.name} for p in providers
                if p.credential_profile_ref in {row.id, row.name}]
        elif kind == "routes" and any(i.route_id == row.id for i in active):
            blockers.append("An active investigation uses this route; finish or cancel it before removing the route.")
        if dependencies:
            blockers.append("Enabled dependencies still use this item. Replace or remove them first; nothing will be cascaded or deleted.")
    else:
        if kind == "models":
            parent = db.get(AIProviderConfig, row.provider_id)
            if not parent or not parent.enabled: blockers.append("Enable the provider before restoring this model.")
            if parent and parent.base_url.rstrip("/") == "https://openrouter.ai/api/v1" and batch_model(row.model_name):
                blockers.append("Batch-only models cannot be restored to interactive use; choose a synchronous model instead.")
        elif kind == "providers" and row.auth_type != "none":
            credential = db.scalar(select(CredentialProfile).where(
                (CredentialProfile.id == row.credential_profile_ref) | (CredentialProfile.name == row.credential_profile_ref)))
            if not credential or not credential.enabled: blockers.append("Restore an eligible credential reference before enabling this provider.")
        elif kind == "routes":
            for mid in [row.primary_model_id, *(row.fallback_model_ids or [])]:
                model = db.get(AIModelConfig, mid)
                parent = db.get(AIProviderConfig, model.provider_id) if model else None
                if not model or not model.enabled or not parent or not parent.enabled or batch_model(model.model_name):
                    blockers.append("Every route model and provider must be enabled and synchronous before restoring this route."); break
    label = getattr(row, "display_name", None) or getattr(row, "name", None) or getattr(row, "purpose", item_id)
    state = {"namespace": session_namespace(db), "kind": kind, "id": item_id, "enabled": row.enabled,
        "revision": getattr(row, "revision", None), "name": label, "dependencies": dependencies,
        "blockers": blockers, "requested_enabled": enabled,
        "active_investigations": sorted(i.id for i in active),
        "configuration": {column.name: getattr(row, column.name) for column in row.__table__.columns
            if column.name not in {"secret_ref", "created_at", "updated_at", "last_checked_at"}}}
    # Hash non-secret metadata, not encrypted custody or secret-reference locations.
    state["configuration"] = {k: (v.isoformat() if hasattr(v, "isoformat") else v)
        for k, v in state["configuration"].items()}
    digest = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return row, {"contract": "icheck.ai-catalog-lifecycle-preview/v1", "kind": kind, "id": item_id,
        "name": label, "enabled": enabled, "preview_hash": digest, "blockers": blockers,
        "dependencies": dependencies, "history_retained": True,
        "warning": "Remove disables this item in the active catalog. Historical runs, model identities and encrypted custody are retained. Restore does not grant outbound approval."}


@router.post("/{kind}/{item_id}/lifecycle/preview")
def preview(kind: Kind, item_id: str, payload: LifecyclePreview, response: Response,
        principal: PrincipalContext = Depends(admin), db: Session = Depends(get_db)):
    if kind == "credentials" and not principal.permits("credentials.manage"):
        raise HTTPException(status_code=403, detail="Credential management permission is required")
    response.headers["Cache-Control"] = "no-store"
    catalog_lock(db)
    _, result = plan(db, kind, item_id, payload.enabled)
    db.commit()
    return result


@router.post("/{kind}/{item_id}/lifecycle")
def apply(kind: Kind, item_id: str, payload: LifecycleApply, response: Response,
        principal: PrincipalContext = Depends(admin), db: Session = Depends(get_db)):
    if kind == "credentials" and not principal.permits("credentials.manage"):
        raise HTTPException(status_code=403, detail="Credential management permission is required")
    if not payload.reason.strip(): raise HTTPException(status_code=422, detail="An approval reason is required")
    response.headers["Cache-Control"] = "no-store"
    catalog_lock(db)
    row, reviewed = plan(db, kind, item_id, payload.enabled)
    if not secrets.compare_digest(reviewed["preview_hash"], payload.preview_hash):
        raise HTTPException(status_code=409, detail="Dependencies or configuration changed; request a fresh lifecycle preview")
    if reviewed["blockers"]: raise HTTPException(status_code=409, detail=" ".join(reviewed["blockers"]))
    if row.enabled != payload.enabled:
        row.enabled = payload.enabled
        if hasattr(row, "revision"): row.revision += 1
        if kind == "providers" and not payload.enabled:
            custody = db.scalar(select(AIManagedConnection).where(AIManagedConnection.provider_id == row.id).with_for_update())
            if custody:
                custody.outbound_enabled = False; custody.revision += 1; custody.updated_by = principal.subject
        record_audit_event(db, event_type="ai.catalog.lifecycle_changed", actor_type="user", actor_id=principal.subject,
            entity_type="ai_" + kind, entity_id=row.id,
            details={"enabled": payload.enabled, "preview_hash": payload.preview_hash, "reason": payload.reason,
                "history_retained": True})
        db.commit()
    return {"kind": kind, "id": item_id, "enabled": payload.enabled, "history_retained": True}
