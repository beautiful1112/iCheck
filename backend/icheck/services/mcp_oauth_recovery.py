"""Approved issuer containment plus independently verified, exact Vault cleanup.

No token replay, pasted provider acknowledgement, guessed legacy target, or
receipt can authorize recovery. The frozen containment Tool and verifier are
ordinary in-product capabilities, not a privileged special MCP transport.
"""
import secrets
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..credentials import CredentialUnavailable, MCPOAuthVaultCredentialProvider, validate_secret_reference
from ..mcp_oauth_recovery_schemas import MCPOAuthRecoveryConfirm, MCPOAuthRecoveryRead, MCPOAuthRecoveryStart
from ..models import AgentActionProposal, ArtifactVersion, AuditEvent, CredentialProfile, InvestigationToolCall, MCPServer, utcnow
from ..oauth_observation import OAuthRevocationIntent
from ..oauth_recovery import OAuthContainmentProof, OAuthRecoveryCustody
from ..studio_schemas import GeneratedToolSpec
from .action_reconciliation import qualify_completed_mcp_verification, qualify_independent_mcp_verification
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext
from .current_authority import current_human_authority
from .mcp_consent_custody import assert_no_open_consent
from .change_governance import _hash_document
from .mcp_oauth import MCPOAuthError, _sha256, _token_profile, _token_store
from .mcp_oauth_observations import locked_oauth_server


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _human(actor: PrincipalContext, server: MCPServer, *, review: bool = False):
    permissions = ("tools.admin", "changes.approve") if review else ("tools.admin",)
    if (actor.principal_type != "user" or actor.principal_id is None
            or actor.authorization_scope.get("all") is not True
            or not actor.permits(*permissions)
            or (actor.tenant_id, actor.region_id) != (server.tenant_id, server.region_id)):
        raise PermissionError("OAuth recovery requires a scoped authenticated human administrator")


def _custody(server: MCPServer) -> OAuthRecoveryCustody:
    try:
        return OAuthRecoveryCustody.model_validate(server.oauth_recovery_custody)
    except ValidationError as exc:
        raise ValueError("OAuth recovery custody is unavailable or invalid; execution remains fenced") from exc


class MissingOriginalIntent(ValueError):
    pass


def _recovery_store(settings: Settings, intent: OAuthRevocationIntent,
                    store: MCPOAuthVaultCredentialProvider | None):
    store = store or _token_store(settings)
    if (getattr(store, "address", None) != (intent.vault_address or "").rstrip("/")
            or getattr(store, "namespace", None) != intent.vault_namespace):
        raise ValueError("Recovery provider differs from the original Vault identity")
    return store


def containment_arguments(server: MCPServer, custody: OAuthRecoveryCustody) -> dict[str, str | int]:
    target = custody.target
    return {
        "recovery_id": custody.recovery_id, "server_id": server.id,
        "consent_generation": target.generation or "legacy",
        "issuer": target.issuer, "client_id": target.client_id, "resource": target.resource,
        "vault_version": target.vault_version,
    }


def read_oauth_recovery(server: MCPServer) -> MCPOAuthRecoveryRead:
    custody = _custody(server)
    return MCPOAuthRecoveryRead(
        server_id=server.id, recovery_id=custody.recovery_id, status=custody.status,
        required_containment_arguments=containment_arguments(server, custody),
        initiated_by=custody.initiated_by, initiated_at=custody.initiated_at,
        reviewed_by=custody.reviewed_by, reviewed_at=custody.reviewed_at,
        proposal_id=custody.proposal_id, verification_tool_call_id=custody.verification_tool_call_id,
        fence_verified=custody.fence_verified, completed_at=custody.completed_at,
        reconnect_allowed=(custody.status == "complete" and server.oauth_status == "revoked"
                           and custody.target.generation == server.oauth_generation),
    )


def _matching_intent(server: MCPServer) -> OAuthRevocationIntent:
    try:
        intent = OAuthRevocationIntent.model_validate(server.oauth_revocation_intent)
    except ValidationError as exc:
        if server.oauth_revocation_intent is not None:
            raise ValueError("Original cleanup intent is corrupt; preserve its custody for explicit recovery review") from exc
        raise MissingOriginalIntent("The original cleanup target requires consent-audit reconstruction") from exc
    if (intent.server_id != server.id
            or (intent.tenant_id, intent.region_id) != (server.tenant_id, server.region_id)
            or intent.generation != server.oauth_generation):
        raise ValueError("The original cleanup target does not match this server")
    return intent


def _legacy_intent(db: Session, server: MCPServer, payload: MCPOAuthRecoveryStart, settings: Settings):
    """Recover ONLY from a persisted consent snapshot, never today's mutable profile.

    Older consent audits without this snapshot cannot prove the original Vault
    identity/reference. Keep them pending and explain the evidence gap.
    """
    if payload.connected_audit_id is None or payload.original_secret_ref is None:
        raise ValueError("Original cleanup intent is missing; exact consent-audit evidence is required")
    event = db.get(AuditEvent, payload.connected_audit_id)
    latest = db.scalar(select(AuditEvent).where(
        AuditEvent.entity_type == "mcp_server", AuditEvent.entity_id == server.id,
        AuditEvent.event_type == "mcp.oauth.connected", AuditEvent.outcome == "success",
    ).order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(1))
    if (event is None or latest is None or event.id != latest.id
            or event.event_type != "mcp.oauth.connected" or event.outcome != "success"
            or event.entity_type != "mcp_server" or event.entity_id != server.id
            or (event.tenant_id, event.region_id) != (server.tenant_id, server.region_id)
            or server.oauth_connected_at is None):
        raise ValueError("Legacy recovery must use this generation's latest successful consent audit")
    details = event.details
    required = {"vault_profile_id", "vault_profile_revision", "vault_ref_sha256", "vault_address",
                "vault_namespace", "generation", "client_id", "issuer", "resource", "connected_at"}
    if not isinstance(details, dict) or not required.issubset(details):
        raise ValueError("Legacy consent lacks original-target evidence; no target can safely be inferred")
    if (type(details["vault_profile_id"]) is not str or not 1 <= len(details["vault_profile_id"]) <= 36
            or type(details["vault_profile_revision"]) is not int or details["vault_profile_revision"] < 0):
        raise ValueError("Legacy consent profile evidence is invalid")
    reference = validate_secret_reference("mcp_oauth_vault", payload.original_secret_ref)
    if (details["connected_at"] != _utc(server.oauth_connected_at).isoformat()
            or details["vault_ref_sha256"] != _sha256(reference)
            or details["generation"] != server.oauth_generation
            or details["client_id"] != server.oauth_client_id
            or details["issuer"] != server.oauth_issuer or details["resource"] != server.oauth_resource
            or details["vault_address"] != settings.server_secret_vault_address
            or details["vault_namespace"] != settings.server_secret_vault_namespace):
        raise ValueError("Legacy consent evidence differs from the original target or Vault identity")
    profile = db.scalar(select(CredentialProfile).where(CredentialProfile.id == details["vault_profile_id"])
                        .with_for_update(read=True).execution_options(populate_existing=True))
    if (profile is None or (profile.tenant_id, profile.region_id) != (server.tenant_id, server.region_id)):
        raise ValueError("Original credential profile is unavailable in this namespace")
    return OAuthRevocationIntent(
        intent_id=secrets.token_hex(16), server_id=server.id,
        tenant_id=server.tenant_id, region_id=server.region_id, generation=server.oauth_generation,
        profile_id=profile.id, profile_revision=details["vault_profile_revision"], secret_ref=reference,
        vault_address=details["vault_address"], vault_namespace=details["vault_namespace"],
    )


def start_oauth_recovery(
    db: Session, server: MCPServer, payload: MCPOAuthRecoveryStart, *, actor: PrincipalContext,
    settings: Settings | None = None, token_store: MCPOAuthVaultCredentialProvider | None = None,
) -> MCPOAuthRecoveryRead:
    _human(actor, server)
    settings = settings or get_settings()
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise LookupError("MCP server not found")
    authority = current_human_authority(db, actor, permissions=("tools.admin",),
        tenant_id=server.tenant_id, region_id=server.region_id)
    actor = authority.actor
    assert_no_open_consent(db, server)
    if (server.auth_mode != "oauth_authorization_code"
            or server.oauth_status not in {"connected", "expired", "revocation_pending"}):
        raise ValueError("Only an existing OAuth consent or pending cleanup can enter recovery")
    if server.oauth_recovery_custody is not None:
        old = _custody(server)
        if old.status == "cleanup_pending":
            raise ValueError("Reviewed cleanup must be resumed, not replaced")
        if old.status == "awaiting_evidence" and payload.expected_recovery_id != old.recovery_id:
            raise ValueError("Replacing unreviewed recovery requires its exact recovery ID")
        if old.status == "complete" and old.target.generation == server.oauth_generation:
            raise ValueError("This generation already completed recovery")
    elif payload.expected_recovery_id is not None:
        raise ValueError("OAuth recovery was superseded")
    if server.oauth_status == "revocation_pending":
        try:
            intent = _matching_intent(server)
        except MissingOriginalIntent:
            intent = _legacy_intent(db, server, payload, settings)
        else:
            if payload.original_secret_ref is not None:
                raise ValueError("A retained original cleanup target cannot be replaced by a submitted reference")
    else:
        if payload.original_secret_ref is not None or server.oauth_revocation_intent is not None:
            raise ValueError("Existing consent recovery cannot substitute a cleanup target")
        profile = _token_profile(db, server)
        intent = OAuthRevocationIntent(
            intent_id=secrets.token_hex(16), server_id=server.id,
            tenant_id=server.tenant_id, region_id=server.region_id, generation=server.oauth_generation,
            profile_id=profile.id, profile_revision=profile.revision, secret_ref=profile.secret_ref,
            vault_address=settings.server_secret_vault_address, vault_namespace=settings.server_secret_vault_namespace,
        )
    if (intent.vault_address != settings.server_secret_vault_address
            or intent.vault_namespace != settings.server_secret_vault_namespace):
        raise ValueError("Original Vault identity changed; recovery remains fenced")
    token_store = _recovery_store(settings, intent, token_store)
    target = token_store.inspect_recovery_target(intent.secret_ref, expected_generation=intent.generation)
    if (target.issuer != server.oauth_issuer or target.resource != server.oauth_resource
            or target.client_id != server.oauth_client_id):
        raise ValueError("Vault recovery target differs from the original issuer, client, or resource")
    authority.assert_live(db)
    now = utcnow()
    custody = OAuthRecoveryCustody(
        recovery_id=secrets.token_hex(16), intent_id=intent.intent_id, target=target,
        status="awaiting_evidence", initiated_by_principal_id=actor.principal_id,
        initiated_by=actor.subject, initiated_at=now, connected_audit_id=payload.connected_audit_id,
    )
    previous = server.oauth_recovery_custody
    server.oauth_revocation_intent = intent.model_dump(mode="json")
    server.oauth_recovery_custody = custody.model_dump(mode="json")
    server.oauth_status = "revocation_pending"
    server.updated_at = now
    record_audit_event(db, event_type="mcp.oauth.recovery.started", actor_type="user", actor_id=actor.subject,
        entity_type="mcp_server", entity_id=server.id,
        details={"recovery_id": custody.recovery_id, "intent_id": intent.intent_id,
                 "reason_sha256": _sha256(payload.reason), "previous_custody": previous,
                 "target": target.model_dump(mode="json"), "connected_audit_id": payload.connected_audit_id})
    authority.assert_live(db)
    db.commit()
    return read_oauth_recovery(server)


def _qualify_containment(db: Session, server: MCPServer, custody: OAuthRecoveryCustody,
                        payload: MCPOAuthRecoveryConfirm):
    proposal = db.scalar(select(AgentActionProposal).where(AgentActionProposal.id == payload.proposal_id)
                         .with_for_update(read=True).execution_options(populate_existing=True))
    verification = db.scalar(select(InvestigationToolCall).where(InvestigationToolCall.id == payload.verification_tool_call_id)
                             .with_for_update(read=True).execution_options(populate_existing=True))
    if (proposal is None or verification is None
            or any((row.tenant_id, row.region_id) != (server.tenant_id, server.region_id)
                   for row in (proposal, verification))
            or not proposal.approved_by_principal_id or not proposal.approved_by
            or proposal.decided_at is None or proposal.execution_started_at is None
            or _utc(proposal.execution_started_at) < custody.initiated_at
            or _utc(proposal.decided_at) > _utc(proposal.execution_started_at)):
        raise ValueError("Containment requires a separately approved write executed after the recovery fence")
    try:
        if proposal.status == "succeeded":
            qualified = qualify_completed_mcp_verification(db, proposal, verification.id)
        else:
            qualified = qualify_independent_mcp_verification(db, proposal, verification.id)
    except ValueError as exc:
        # Schema diagnostics can quote an upstream value. Expose only a fixed
        # administrative message, not provider/Tool response text.
        raise ValueError("Containment evidence is not qualified by its frozen contracts") from exc
    original = db.get(InvestigationToolCall, qualified.original_tool_call_id)
    if original is None or _utc(original.started_at) < custody.initiated_at:
        raise ValueError("Containment Tool call predates this recovery")
    if original.finished_at is not None and qualified.observed_at < _utc(original.finished_at):
        raise ValueError("Containment verification predates the completed action")
    version = db.get(ArtifactVersion, original.artifact_version_id)
    try:
        spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Frozen containment evidence contract is invalid") from exc
    bindings = spec.independent_verification.bindings
    arguments = containment_arguments(server, custody)
    declared = {(binding.original_argument_path, binding.observed_value_key, binding.value_type)
                for binding in bindings}
    required = {(key, key, "integer" if key == "vault_version" else "string") for key in arguments}
    values = verification.result.get("values", {})
    if (not required.issubset(declared)
            or qualified.verification_kind != "target_state" or qualified.observed_target_state != "absent"
            or qualified.observed_at < custody.initiated_at
            or any(type(proposal.arguments.get(key)) is not type(value)
                   or proposal.arguments.get(key) != value or values.get(key) != value
                   for key, value in arguments.items())
            or values.get("family_revoked") is not True or values.get("issuance_blocked") is not True
            or not all(isinstance(values.get(key), str) and 1 <= len(values[key]) <= 255
                       for key in ("family_reference", "containment_reference"))):
        raise ValueError("Independent evidence must prove exact-target family revocation and blocked future issuance")
    assert_no_inline_secrets(verification.result, "OAuth containment evidence")
    try:
        return OAuthContainmentProof(
            original_tool_call_id=original.id, original_plan_hash=proposal.plan_hash,
            verification_result_hash=verification.result_hash,
            write_artifact_version_id=original.artifact_version_id,
            write_artifact_activation_id=original.artifact_activation_id,
            verification_artifact_version_id=verification.artifact_version_id,
            verification_artifact_activation_id=verification.artifact_activation_id,
            observed_at=qualified.observed_at, evidence_reference=qualified.evidence_reference,
            family_reference=values["family_reference"], containment_reference=values["containment_reference"],
        )
    except ValueError as exc:
        raise ValueError("Containment proof must retain valid opaque references and exact provenance") from exc


def _retained_proof(db: Session, server: MCPServer, custody: OAuthRecoveryCustody):
    """Retained review survives process loss, not substitution of its evidence."""
    proof = custody.proof
    proposal = db.get(AgentActionProposal, custody.proposal_id, populate_existing=True)
    original = db.get(InvestigationToolCall, proof.original_tool_call_id, populate_existing=True)
    verification = db.get(InvestigationToolCall, custody.verification_tool_call_id, populate_existing=True)
    if (any(row is None or (row.tenant_id, row.region_id) != (server.tenant_id, server.region_id)
            for row in (proposal, original, verification))
            or proposal.tool_call_id != proof.original_tool_call_id or proposal.plan_hash != proof.original_plan_hash
            or verification.result_hash != proof.verification_result_hash
            or _hash_document(verification.result) != proof.verification_result_hash
            or original.artifact_version_id != proof.write_artifact_version_id
            or original.artifact_activation_id != proof.write_artifact_activation_id
            or verification.artifact_version_id != proof.verification_artifact_version_id
            or verification.artifact_activation_id != proof.verification_artifact_activation_id
            or any(type(proposal.arguments.get(key)) is not type(value) or proposal.arguments.get(key) != value
                   for key, value in containment_arguments(server, custody).items())):
        raise ValueError("Reviewed containment evidence was substituted; cleanup remains fenced")


def confirm_oauth_recovery(
    db: Session, server: MCPServer, payload: MCPOAuthRecoveryConfirm, *, actor: PrincipalContext,
    settings: Settings | None = None, token_store: MCPOAuthVaultCredentialProvider | None = None,
) -> MCPOAuthRecoveryRead:
    _human(actor, server, review=True)
    settings = settings or get_settings()
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise LookupError("MCP server not found")
    authority = current_human_authority(db, actor, permissions=("tools.admin", "changes.approve"),
        tenant_id=server.tenant_id, region_id=server.region_id)
    actor = authority.actor
    assert_no_open_consent(db, server)
    custody = _custody(server)
    if custody.recovery_id != payload.expected_recovery_id:
        raise ValueError("OAuth recovery was superseded")
    if actor.principal_id == custody.initiated_by_principal_id:
        raise PermissionError("The recovery initiator cannot independently confirm cleanup")
    if custody.status == "complete":
        if (custody.proposal_id != payload.proposal_id
                or custody.verification_tool_call_id != payload.verification_tool_call_id):
            raise ValueError("Completed recovery cannot substitute its evidence")
        return read_oauth_recovery(server)
    intent = _matching_intent(server)
    if (server.oauth_status != "revocation_pending" or intent.intent_id != custody.intent_id
            or intent.generation != custody.target.generation
            or intent.vault_address != settings.server_secret_vault_address
            or intent.vault_namespace != settings.server_secret_vault_namespace):
        raise ValueError("OAuth recovery target was superseded or the original Vault identity changed")
    if custody.status == "awaiting_evidence":
        proof = _qualify_containment(db, server, custody, payload)
        authority.assert_live(db)
        custody = OAuthRecoveryCustody.model_validate({
            **custody.model_dump(), "status": "cleanup_pending", "proposal_id": payload.proposal_id,
            "verification_tool_call_id": payload.verification_tool_call_id,
            "reviewed_by_principal_id": actor.principal_id, "reviewed_by": actor.subject,
            "reviewed_at": utcnow(), "cleanup_version": custody.target.vault_version + 1, "proof": proof,
        })
        server.oauth_recovery_custody = custody.model_dump(mode="json")
        record_audit_event(db, event_type="mcp.oauth.recovery.reviewed", actor_type="user", actor_id=actor.subject,
            entity_type="mcp_server", entity_id=server.id,
            details={"recovery_id": custody.recovery_id, "proposal_id": payload.proposal_id,
                     "verification_tool_call_id": payload.verification_tool_call_id, "proof": proof.model_dump(mode="json"),
                     "reason_sha256": _sha256(payload.reason)})
        authority.assert_live(db)
        db.commit()  # Durable review BEFORE any cleanup I/O; retries never replay containment.
    elif (custody.proposal_id != payload.proposal_id
            or custody.verification_tool_call_id != payload.verification_tool_call_id):
        raise ValueError("Pending recovery cannot substitute reviewed evidence")
    _retained_proof(db, server, custody)

    def current():
        row = locked_oauth_server(db, server.id)
        if (row is None or row.oauth_status != "revocation_pending"
                or row.oauth_generation != intent.generation
                or row.oauth_revocation_intent != intent.model_dump(mode="json")
                or row.oauth_recovery_custody != custody.model_dump(mode="json")):
            raise ValueError("OAuth recovery custody changed; execution remains fenced")
        return row

    def retain_fence(version: int):
        nonlocal custody
        row = current()
        if version != custody.cleanup_version:
            raise ValueError("OAuth recovery fence version differs from reviewed custody")
        custody = OAuthRecoveryCustody.model_validate({**custody.model_dump(), "fence_verified": True})
        row.oauth_recovery_custody = custody.model_dump(mode="json")
        record_audit_event(db, event_type="mcp.oauth.recovery.fenced", actor_type="user", actor_id=actor.subject,
            entity_type="mcp_server", entity_id=row.id,
            details={"recovery_id": custody.recovery_id, "cleanup_version": version})
        db.commit()

    def authorize_mutation(phase: str):
        nonlocal actor
        if phase not in {"fence", "delete"}:
            raise ValueError("OAuth recovery mutation phase is invalid")
        row = current()
        live = current_human_authority(db, actor, permissions=("tools.admin", "changes.approve"),
            tenant_id=row.tenant_id, region_id=row.region_id)
        actor = live.actor
        live.assert_live(db)
        record_audit_event(db, event_type="mcp.oauth.recovery.mutation_admitted", actor_type="user", actor_id=actor.subject,
            entity_type="mcp_server", entity_id=row.id,
            details={"recovery_id": custody.recovery_id, "phase": phase,
                     "principal_id": actor.principal_id, "auth_method": actor.auth_method,
                     "credential_id": actor.access_token_id if actor.auth_method == "bearer" else actor.session_id,
                     "cleanup_version": custody.cleanup_version})
        # Release authorization locks BEFORE external I/O. Later withdrawal
        # stops the next admission, but cannot erase this operation's receipt.
        live.assert_live(db)
        db.commit()

    try:
        token_store = _recovery_store(settings, intent, token_store)
        cleaned = token_store.cleanup_contained_recovery(intent.secret_ref, custody.target,
            recovery_id=custody.recovery_id, fence_verified=custody.fence_verified,
            retain_fence=retain_fence, authorize_mutation=authorize_mutation)
        if type(cleaned) is not int or cleaned != custody.cleanup_version:
            raise CredentialUnavailable("OAuth recovery cleanup version differs from reviewed custody")
    except CredentialUnavailable as exc:
        db.rollback()
        record_audit_event(db, event_type="mcp.oauth.recovery.cleanup_failed", actor_type="user", actor_id=actor.subject,
            entity_type="mcp_server", entity_id=server.id, outcome="failure",
            details={"recovery_id": custody.recovery_id, "error_type": type(exc).__name__})
        db.commit()
        raise MCPOAuthError("Recovery remains fenced; exact Vault cleanup must be retried", code="revocation_pending") from exc
    server = current()
    now = utcnow()
    custody = OAuthRecoveryCustody.model_validate({**custody.model_dump(), "status": "complete", "completed_at": now})
    server.oauth_recovery_custody = custody.model_dump(mode="json")
    server.oauth_status = "revoked"
    server.oauth_access_token_sha256 = None
    server.oauth_refresh_token_present = False
    server.oauth_token_expires_at = None
    server.oauth_credential_observation = None
    server.oauth_revocation_intent = None
    server.oauth_revoked_by = actor.subject
    server.oauth_revoked_at = server.updated_at = now
    record_audit_event(db, event_type="mcp.oauth.recovery.completed", actor_type="user", actor_id=actor.subject,
        entity_type="mcp_server", entity_id=server.id,
        details={"recovery_id": custody.recovery_id, "proposal_id": custody.proposal_id,
                 "verification_tool_call_id": custody.verification_tool_call_id, "cleanup_version": custody.cleanup_version})
    db.commit()
    return read_oauth_recovery(server)
