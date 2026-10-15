"""Governed exact-transaction issuer containment, separate from Vault cleanup.

Neither admission nor confirmation executes a Tool. The selected published
capabilities use the normal approval/runtime path, with a separate verifier.
Ambiguous shared families, old-target-only evidence and pasted claims cannot
release an unresolved consent. Local cleanup is a subsequent protocol.
"""
import base64
import hashlib
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..models import (AgentActionProposal, AgentToolRegistration, ArtifactVersion, ArtifactVersionStatus,
    InvestigationToolCall, MCPOAuthConsentAttempt, MCPOAuthFamilyRecovery, MCPOAuthTransaction,
    MCPServer, MCPToolActivation, utcnow)
from ..oauth_consent import OPEN_CONSENT_STATUSES, OAuthAuthorizationLocator, OAuthConsentSnapshot, OAuthConsentTarget
from ..oauth_family_recovery import (MCPOAuthFamilyRecoveryConfirm, MCPOAuthFamilyRecoveryRead,
    MCPOAuthFamilyRecoveryStart, OAuthFamilyRecoverySnapshot, OAuthRecoveryToolPin)
from ..oauth_recovery import OAuthContainmentProof
from ..studio_schemas import GeneratedToolSpec
from ..schema_validation import validate_instance
from .action_reconciliation import qualify_completed_mcp_verification, qualify_independent_mcp_verification
from .audit import record_audit_event
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext
from .current_authority import current_human_authority
from .mcp_oauth import _fernet, _sha256
from .mcp_oauth_observations import locked_oauth_server


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _attempt(db: Session, server: MCPServer, attempt_id: str, *, lock: bool = False):
    query = select(MCPOAuthConsentAttempt).where(MCPOAuthConsentAttempt.id == attempt_id,
        MCPOAuthConsentAttempt.server_id == server.id, MCPOAuthConsentAttempt.tenant_id == server.tenant_id,
        MCPOAuthConsentAttempt.region_id == server.region_id).execution_options(populate_existing=True)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise LookupError("Consent attempt not found")
    return row


def _snapshot(attempt: MCPOAuthConsentAttempt, server: MCPServer):
    try:
        snapshot = OAuthConsentSnapshot.model_validate(attempt.snapshot)
        target = OAuthConsentTarget.model_validate(attempt.target)
    except ValueError as exc:
        raise ValueError("Original consent custody is invalid; no target can be inferred") from exc
    if (snapshot.server_id != server.id or (snapshot.tenant_id, snapshot.region_id) != (server.tenant_id, server.region_id)
            or snapshot.client_id != attempt.client_id or snapshot.generation != attempt.previous_generation
            or target.vault_version != attempt.target_version or target.generation != attempt.previous_generation):
        raise ValueError("Original consent custody does not match this attempt")
    return snapshot, target


def _locator(db: Session, attempt: MCPOAuthConsentAttempt, snapshot: OAuthConsentSnapshot, settings: Settings):
    if snapshot.authorization_locator is not None:
        if snapshot.authorization_locator.transaction_id != attempt.transaction_id:
            raise ValueError("Consent locator belongs to another transaction")
        return snapshot.authorization_locator
    # Legacy reconstruction needs the actual authenticated PKCE ciphertext and
    # original transaction, not a time window, mutable profile or operator guess.
    transaction = db.get(MCPOAuthTransaction, attempt.transaction_id)
    if (transaction is None or transaction.server_id != attempt.server_id
            or (transaction.tenant_id, transaction.region_id) != (attempt.tenant_id, attempt.region_id)
            or transaction.consumed_at is None or transaction.oauth_generation != attempt.previous_generation
            or transaction.issuer != attempt.issuer or transaction.resource != attempt.resource
            or transaction.actor_id != attempt.actor_id or transaction.consent_snapshot != attempt.snapshot):
        raise ValueError("Original authorization locator is unavailable; recovery remains fenced")
    try:
        # Read-only recovery may happen after callback expiry; Fernet still
        # authenticates the original ciphertext. This never redeems a code.
        verifier = _fernet(settings).decrypt(transaction.code_verifier_ciphertext.encode("ascii")).decode("ascii")
        return OAuthAuthorizationLocator(transaction_id=transaction.id, state_sha256=transaction.state_hash,
            pkce_s256=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii"))
    except Exception as exc:
        raise ValueError("Original authorization locator cannot be authenticated") from exc


def _arguments(db: Session, row: MCPOAuthFamilyRecovery, snapshot: OAuthFamilyRecoverySnapshot):
    attempt = db.get(MCPOAuthConsentAttempt, row.attempt_id)
    if (attempt is None or attempt.family_recovery_id != row.id or attempt.server_id != row.server_id
            or attempt.generation != row.generation
            or (attempt.tenant_id, attempt.region_id) != (row.tenant_id, row.region_id)):
        raise ValueError("Recovery claim differs from its original consent attempt")
    try:
        original = OAuthConsentSnapshot.model_validate(attempt.snapshot)
        target = OAuthConsentTarget.model_validate(attempt.target)
        if (snapshot.consent != original or snapshot.target != target
                or snapshot.locator.transaction_id != attempt.transaction_id
                or (original.authorization_locator is not None and snapshot.locator != original.authorization_locator)):
            raise ValueError("Mismatch")
    except ValueError as exc:
        raise ValueError("Recovery snapshot differs from the original consent custody") from exc
    # Issuer/resource are the discovered identities, not today's server settings.
    return dict(recovery_id=row.id, server_id=row.server_id, consent_attempt_id=row.attempt_id,
        consent_generation=row.generation, issuer=attempt.issuer, client_id=attempt.client_id,
        resource=attempt.resource, vault_version=snapshot.target.vault_version,
        transaction_id=snapshot.locator.transaction_id, state_sha256=snapshot.locator.state_sha256,
        pkce_s256=snapshot.locator.pkce_s256)


def _pin(db: Session, activation_id: str, server: MCPServer, *, read_only: bool):
    activation = db.scalar(select(MCPToolActivation).where(MCPToolActivation.id == activation_id)
        .with_for_update(read=True).execution_options(populate_existing=True))
    def shared(model, identity):
        return db.scalar(select(model).where(model.id == identity).with_for_update(read=True)
            .execution_options(populate_existing=True))
    version = shared(ArtifactVersion, activation.artifact_version_id) if activation else None
    tool = shared(AgentToolRegistration, activation.tool_registration_id) if activation else None
    peer = shared(MCPServer, activation.server_id) if activation else None
    if (any(row is None for row in (activation, version, tool, peer))
            or any((row.tenant_id, row.region_id) != (server.tenant_id, server.region_id)
                   for row in (activation, version, tool, peer))
            or activation.status != "active" or activation.rollout_state != "full" or activation.circuit_state != "closed"
            or version.status != ArtifactVersionStatus.PUBLISHED or not tool.enabled or not peer.enabled
            or peer.id == server.id or tool.transport != "mcp" or tool.read_only is not read_only):
        raise ValueError("Select available published containment and verifier capabilities in this namespace")
    try:
        spec = GeneratedToolSpec.model_validate(version.definition["spec"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Selected frozen Tool contract is invalid") from exc
    if (spec.read_only is not read_only or spec.tool_name != activation.tool_name or tool.name != spec.tool_name
            or spec.mcp_server_name != peer.name or spec.mcp_tool_name != activation.mcp_tool_name
            or (not read_only and (spec.risk_level != "change" or not spec.requires_approval))):
        raise ValueError("Selected Tool does not satisfy its frozen containment role")
    return OAuthRecoveryToolPin(activation_id=activation.id, version_id=version.id, server_id=peer.id,
        tool_id=tool.id, tool_name=tool.name, content_hash=version.content_hash, contract_hash=activation.contract_sha256), spec


def read_family_recovery(db: Session, server: MCPServer, attempt_id: str) -> MCPOAuthFamilyRecoveryRead:
    attempt = _attempt(db, server, attempt_id)
    row = db.get(MCPOAuthFamilyRecovery, attempt.family_recovery_id) if attempt.family_recovery_id else None
    if row is None or (row.tenant_id, row.region_id) != (server.tenant_id, server.region_id):
        raise LookupError("Consent family recovery has not been started")
    try:
        snapshot = OAuthFamilyRecoverySnapshot.model_validate(row.snapshot)
        proof = OAuthContainmentProof.model_validate(row.proof) if row.proof is not None else None
    except ValueError as exc:
        raise ValueError("Retained family recovery custody is invalid") from exc
    local_verified = False
    if attempt.family_contained_at is not None:
        from .mcp_family_local import read_family_local
        local_verified = read_family_local(db, server, attempt_id).local_cleanup_verified
    return MCPOAuthFamilyRecoveryRead(server_id=server.id, attempt_id=attempt.id, recovery_id=row.id, status=row.status,
        required_containment_arguments=_arguments(db, row, snapshot), write_tool=snapshot.write_tool,
        verification_tool=snapshot.verification_tool, initiated_by=row.initiated_by, initiated_at=row.initiated_at,
        reviewed_by=row.reviewed_by, reviewed_at=row.reviewed_at, proposal_id=row.proposal_id,
        verification_tool_call_id=row.verification_tool_call_id, evidence_reference=proof.evidence_reference if proof else None,
        local_cleanup_verified=local_verified)


def start_family_recovery(db: Session, server: MCPServer, attempt_id: str, payload: MCPOAuthFamilyRecoveryStart,
                          *, actor: PrincipalContext, settings: Settings | None = None):
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise LookupError("MCP server not found")
    authority = current_human_authority(db, actor, permissions=("tools.admin",),
        tenant_id=server.tenant_id, region_id=server.region_id)
    attempt = _attempt(db, server, attempt_id, lock=True)
    if attempt.family_recovery_id is not None:
        raise ValueError("This attempt already has retained family recovery custody")
    if attempt.status not in {*OPEN_CONSENT_STATUSES, "superseded", "revoked"}:
        raise ValueError("Current connected consent must use the ordinary revocation path")
    snapshot, target = _snapshot(attempt, server)
    locator = _locator(db, attempt, snapshot, settings or get_settings())
    write_pin, write_spec = _pin(db, payload.write_activation_id, server, read_only=False)
    verification_pin, _ = _pin(db, payload.verification_activation_id, server, read_only=True)
    if (write_pin.server_id == verification_pin.server_id or write_spec.independent_verification is None
            or write_spec.independent_verification.kind != "target_state"
            or write_spec.independent_verification.tool_name != verification_pin.tool_name):
        raise ValueError("Containment must designate a separately pinned read-only verifier")
    frozen = OAuthFamilyRecoverySnapshot(consent=snapshot, target=target, locator=locator,
        write_tool=write_pin, verification_tool=verification_pin)
    row = MCPOAuthFamilyRecovery(id=secrets.token_hex(16), attempt_id=attempt.id, server_id=server.id,
        tenant_id=server.tenant_id, region_id=server.region_id, generation=attempt.generation,
        status="awaiting_evidence", snapshot=frozen.model_dump(mode="json"), initiated_by=authority.actor.principal_id)
    db.add(row); db.flush()
    attempt.family_recovery_id = row.id
    arguments = _arguments(db, row, frozen)
    required = {(key, key, "integer" if key == "vault_version" else "string") for key in arguments}
    declared = {(binding.original_argument_path, binding.observed_value_key, binding.value_type)
                for binding in write_spec.independent_verification.bindings}
    if not required.issubset(declared):
        raise ValueError("Containment contract must bind the exact transaction and consent generation")
    try:
        validate_instance(arguments, write_spec.input_schema, "containment arguments")
    except ValueError as exc:
        raise ValueError("Containment Tool does not accept the exact recovery context") from exc
    attempt.updated_at = utcnow()
    record_audit_event(db, event_type="mcp.oauth.family_recovery.started", actor_type="user",
        actor_id=authority.actor.subject, entity_type="mcp_server", entity_id=server.id,
        details={"recovery_id": row.id, "attempt_id": attempt.id, "generation": attempt.generation,
                 "reason_sha256": _sha256(payload.reason), "write_activation_id": write_pin.activation_id,
                 "verification_activation_id": verification_pin.activation_id})
    authority.assert_live(db); db.commit()
    return read_family_recovery(db, server, attempt.id)


def _qualify(db: Session, row: MCPOAuthFamilyRecovery, frozen: OAuthFamilyRecoverySnapshot,
             payload: MCPOAuthFamilyRecoveryConfirm):
    proposal = db.scalar(select(AgentActionProposal).where(AgentActionProposal.id == payload.proposal_id)
        .with_for_update(read=True).execution_options(populate_existing=True))
    verification = db.scalar(select(InvestigationToolCall).where(InvestigationToolCall.id == payload.verification_tool_call_id)
        .with_for_update(read=True).execution_options(populate_existing=True))
    if (proposal is None or verification is None
            or any((item.tenant_id, item.region_id) != (row.tenant_id, row.region_id) for item in (proposal, verification))
            or proposal.decided_at is None or proposal.execution_started_at is None
            or _utc(proposal.execution_started_at) < _utc(row.initiated_at)):
        raise ValueError("Containment requires an approved write executed after the recovery claim")
    try:
        qualified = (qualify_completed_mcp_verification if proposal.status == "succeeded"
                     else qualify_independent_mcp_verification)(db, proposal, verification.id)
    except ValueError as exc:
        raise ValueError("Containment evidence does not satisfy the frozen independent contracts") from exc
    original = db.get(InvestigationToolCall, qualified.original_tool_call_id)
    for call, pin in ((original, frozen.write_tool), (verification, frozen.verification_tool)):
        if (call is None or call.tool_id != pin.tool_id or call.artifact_version_id != pin.version_id
                or call.artifact_activation_id != pin.activation_id or call.artifact_content_hash != pin.content_hash
                or call.artifact_activation_sha256 != pin.contract_hash):
            raise ValueError("Containment evidence must use the capabilities pinned at recovery admission")
    values = verification.result.get("values", {})
    arguments = _arguments(db, row, frozen)
    if (not proposal.approved_by_principal_id or not proposal.approved_by
            or _utc(proposal.decided_at) > _utc(proposal.execution_started_at)
            or _utc(original.started_at) < _utc(row.initiated_at)
            or (original.finished_at is not None and qualified.observed_at < _utc(original.finished_at))
            or qualified.verification_kind != "target_state" or qualified.observed_target_state != "absent"
            or qualified.observed_at < _utc(row.initiated_at)
            or any(type(proposal.arguments.get(key)) is not type(value) or proposal.arguments.get(key) != value
                   or type(values.get(key)) is not type(value) or values.get(key) != value for key, value in arguments.items())
            or values.get("family_revoked") is not True or values.get("issuance_blocked") is not True
            or values.get("exclusive_transaction_family") is not True
            or values.get("containment_scope") != "authorization_transaction"):
        raise ValueError("Evidence must prove exclusive exact-transaction containment without collateral revocation")
    assert_no_inline_secrets(verification.result, "OAuth family containment evidence")
    try:
        return OAuthContainmentProof(original_tool_call_id=original.id, original_plan_hash=proposal.plan_hash,
            verification_result_hash=verification.result_hash, write_artifact_version_id=original.artifact_version_id,
            write_artifact_activation_id=original.artifact_activation_id,
            verification_artifact_version_id=verification.artifact_version_id,
            verification_artifact_activation_id=verification.artifact_activation_id,
            observed_at=qualified.observed_at, evidence_reference=qualified.evidence_reference,
            family_reference=values.get("family_reference"), containment_reference=values.get("containment_reference"))
    except ValueError as exc:
        raise ValueError("Containment evidence must retain opaque references and exact provenance") from exc


def confirm_family_recovery(db: Session, server: MCPServer, attempt_id: str, payload: MCPOAuthFamilyRecoveryConfirm,
                            *, actor: PrincipalContext):
    server = locked_oauth_server(db, server.id)
    if server is None:
        raise LookupError("MCP server not found")
    authority = current_human_authority(db, actor, permissions=("tools.admin", "changes.approve"),
        tenant_id=server.tenant_id, region_id=server.region_id)
    attempt = _attempt(db, server, attempt_id, lock=True)
    row = db.scalar(select(MCPOAuthFamilyRecovery).where(MCPOAuthFamilyRecovery.id == attempt.family_recovery_id)
        .with_for_update().execution_options(populate_existing=True)) if attempt.family_recovery_id else None
    if row is None or row.id != payload.expected_recovery_id:
        raise ValueError("Recovery claim is unavailable or superseded")
    if authority.actor.principal_id == row.initiated_by:
        raise PermissionError("Recovery requires a different human reviewer from its initiator")
    if row.status == "issuer_verified":
        if (row.proposal_id, row.verification_tool_call_id) != (payload.proposal_id, payload.verification_tool_call_id):
            raise ValueError("Retained containment proof cannot be replaced")
        authority.assert_live(db)
        return read_family_recovery(db, server, attempt.id)
    try:
        frozen = OAuthFamilyRecoverySnapshot.model_validate(row.snapshot)
    except ValueError as exc:
        raise ValueError("Retained family recovery custody is invalid") from exc
    proof = _qualify(db, row, frozen, payload)
    row.proof = proof.model_dump(mode="json")
    row.status = "issuer_verified"; row.reviewed_by = authority.actor.principal_id; row.reviewed_at = utcnow()
    row.proposal_id = payload.proposal_id; row.verification_tool_call_id = payload.verification_tool_call_id
    record_audit_event(db, event_type="mcp.oauth.family_recovery.issuer_verified", actor_type="user",
        actor_id=authority.actor.subject, entity_type="mcp_server", entity_id=server.id,
        details={"recovery_id": row.id, "attempt_id": attempt.id, "proposal_id": row.proposal_id,
                 "verification_tool_call_id": row.verification_tool_call_id, "reason_sha256": _sha256(payload.reason),
                 "reconnect_allowed": False, "local_cleanup_verified": False})
    authority.assert_live(db); db.commit()
    return read_family_recovery(db, server, attempt.id)
