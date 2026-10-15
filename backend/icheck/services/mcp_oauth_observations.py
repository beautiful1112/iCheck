"""Accept non-secret observations only inside a current, authenticated assignment."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import ValidationError

from ..models import AgentWorker, AgentWorkerState, CredentialProfile, MCPServer
from ..database import require_locking_transaction
from ..oauth_observation import OAuthCredentialObservation, OAuthCredentialReceipt


def locked_oauth_server(db: Session, server_id: str) -> MCPServer | None:
    require_locking_transaction(db, purpose="OAuth credential custody")
    return db.scalar(select(MCPServer).where(MCPServer.id == server_id)
        .with_for_update().execution_options(populate_existing=True))


def accept_oauth_observation(
    db: Session, server: MCPServer, observation: OAuthCredentialObservation, *,
    source: str, assignment_id: str, expected_generation: str | None,
    profile_id: str, profile_revision: int, worker: AgentWorker | None = None,
) -> bool:
    # The caller first authenticates/fences its lease and persisted assignment.
    # Lock and refresh the server so concurrent reconnect/revoke cannot be lost.
    current = locked_oauth_server(db, server.id)
    if current is None or not current.enabled or current.auth_mode != "oauth_authorization_code":
        return False
    if (current.oauth_status != "connected" or not expected_generation
        or current.oauth_generation != expected_generation
        or observation.generation != expected_generation):
        return False
    profile = db.scalar(select(CredentialProfile).where(CredentialProfile.id == profile_id)
        .with_for_update(read=True).execution_options(populate_existing=True))
    if (profile is None or not profile.enabled or profile.provider != "mcp_oauth_vault"
        or profile.revision != profile_revision
        or current.credential_profile_ref not in {profile.id, profile.name}
        or (profile.tenant_id, profile.region_id) != (current.tenant_id, current.region_id)):
        return False
    if worker is not None:
        # The server/profile lock wait may outlive a label/state containment.
        # Refresh the actual row; the caller's cached identity is not current
        # selector evidence. This only rejects metadata, never an owned result.
        worker = db.get(AgentWorker, worker.id, populate_existing=True)
        if worker is None or worker.state != AgentWorkerState.ONLINE or (
            (worker.tenant_id, worker.region_id) != (current.tenant_id, current.region_id)
            or any((worker.labels or {}).get(k) != v for k, v in (profile.worker_selector or {}).items())
        ):
            return False
    now = datetime.now(UTC)
    # A delayed credential receipt is not fresh evidence. Future-skew allowance
    # is small and independent of the access token's reported lifetime.
    if not now - timedelta(minutes=5) <= observation.observed_at <= now + timedelta(seconds=30):
        return False
    if observation.token_expires_at > observation.observed_at + timedelta(seconds=86_430):
        return False
    if observation.vault_version < (current.oauth_bundle_version or 0):
        return False
    if current.oauth_credential_observation:
        try:
            previous = OAuthCredentialReceipt.model_validate(current.oauth_credential_observation)
        except ValidationError:
            return False  # Informational metadata cannot block write-result custody.
        if (observation.vault_version < previous.vault_version
            or (observation.vault_version == previous.vault_version
                and observation.observed_at <= previous.observed_at)):
            return False
    receipt = OAuthCredentialReceipt(
        **observation.model_dump(), source=source,
        worker_id=worker.id if worker else None, assignment_id=assignment_id, received_at=now,
    )
    current.oauth_credential_observation = receipt.model_dump(mode="json")
    # Never connect, activate, grant scopes, or overwrite consent expiry here.
    return True
