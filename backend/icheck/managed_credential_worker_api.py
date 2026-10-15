"""No-store managed secret leases; never available to browser or Agent principals."""
import secrets
from datetime import UTC
from fastapi import APIRouter, Header, HTTPException, Response
from sqlalchemy import select
from .collector_api import DBSession, WorkerPeer, _authorize_run
from .collector_schemas import CredentialGrantRequest
from .device_api import _authorize_worker, _worker
from .models import DeviceConnectionPreflight, utcnow
from .services.collectors import issue_credential_grant
from .services.devices import _as_utc, _token_hash
from .services.device_credentials import profile, resolve, DeviceCredentialUnavailable
from .services.audit import record_audit_event

router = APIRouter(prefix="/api/v1", tags=["worker-device-credentials"])


def secret_reply(db, p, expiry, adapter, worker, entity):
    if p is None or not p.enabled or p.provider != "managed_device" or adapter not in p.allowed_adapters:
        raise ValueError("Managed credential is unavailable for this assignment")
    labels = {**worker.labels, "site": worker.site}
    if any(labels.get(k) != v for k, v in p.worker_selector.items()):
        raise ValueError("Worker does not match credential scope")
    if _as_utc(expiry) <= utcnow():
        raise ValueError("Credential lease has expired")
    values = resolve(db, p)
    record_audit_event(db, event_type="credential.device.lease_issued", actor_type="worker", actor_id=worker.id,
        entity_type="credential_profile", entity_id=p.id,
        details={"assignment_id": entity, "revision": p.revision, "adapter": adapter})
    db.commit()
    return {"values": values, "expires_at": _as_utc(expiry), "profile_revision": p.revision}


@router.post("/collector-runs/{run_id}/managed-credential")
def run_secret(run_id: str, payload: CredentialGrantRequest, response: Response, db: DBSession,
               peer_identity: WorkerPeer, authorization: str | None = Header(default=None)):
    response.headers["Cache-Control"] = "no-store"
    _authorize_run(db, run_id, authorization, peer_identity)
    try:
        grant = issue_credential_grant(db, run_id, payload.lease_token)
        from .models import CollectorRun
        run = db.get(CollectorRun, run_id)
        p = profile(db, grant.profile_id, lock=True)
        if p is None or p.revision != grant.profile_revision:
            raise ValueError("Credential changed during lease issuance")
        return secret_reply(db, p, grant.expires_at, grant.adapter_type, run.worker, run_id)
    except (LookupError, ValueError, DeviceCredentialUnavailable):
        raise HTTPException(409, "Managed credential lease denied", headers={"Cache-Control": "no-store"}) from None


@router.post("/collector-workers/{worker_id}/device-preflights/{preflight_id}/managed-credential")
def preflight_secret(worker_id: str, preflight_id: str, payload: CredentialGrantRequest, response: Response,
                     db: DBSession, peer_identity: WorkerPeer, authorization: str | None = Header(default=None)):
    response.headers["Cache-Control"] = "no-store"
    worker = _worker(db, worker_id)
    _authorize_worker(worker, authorization)
    from .services.worker_mtls import verify_worker_peer
    try:
        from .config import get_settings
        verify_worker_peer(db, worker, peer_identity, kind="collector", mode=get_settings().worker_mtls_mode)
        preflight = db.scalar(select(DeviceConnectionPreflight).where(DeviceConnectionPreflight.id == preflight_id))
        if (preflight is None or preflight.worker_id != worker.id or preflight.status != "running"
                or not secrets.compare_digest(preflight.lease_token_hash, _token_hash(payload.lease_token))):
            raise ValueError("Invalid preflight ownership")
        c = preflight.connection
        if (not c.enabled or not c.device.enabled or c.verification_status != "running"
                or c.verification_worker_id != worker.id or c.verification_lease_expires_at is None
                or _as_utc(c.verification_lease_expires_at) <= utcnow()
                or not secrets.compare_digest(c.verification_lease_token_hash or "", _token_hash(payload.lease_token))
                or preflight.target_host != c.device.management_ip or preflight.site_snapshot != c.device.site):
            raise ValueError("Preflight target changed")
        p = profile(db, c.credential_profile_ref or "", lock=True)
        return secret_reply(db, p, preflight.lease_expires_at, c.adapter_type, worker, preflight.id)
    except Exception:
        raise HTTPException(409, "Managed preflight credential lease denied", headers={"Cache-Control": "no-store"}) from None
