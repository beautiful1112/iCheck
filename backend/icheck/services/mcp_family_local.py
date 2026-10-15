"""Durable local execution; issuer proof and reconnect remain separate decisions."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..credentials import MCPOAuthVaultCredentialProvider
from ..models import MCPOAuthFamilyLocalExecution, MCPOAuthFamilyLocalMutation, MCPOAuthFamilyRecovery, utcnow
from ..oauth_family_local import (FamilyLocalCompletion, FamilyLocalPlan, FamilyLocalReceipt, FamilyLocalScope,
    MCPOAuthFamilyLocalExecute, MCPOAuthFamilyLocalRead, MCPOAuthFamilyLocalStart)
from ..oauth_family_recovery import MCPOAuthFamilyRecoveryConfirm, OAuthFamilyRecoverySnapshot
from ..oauth_recovery import OAuthContainmentProof
from .audit import record_audit_event
from .control_plane_auth import PrincipalContext
from .current_authority import current_human_authority
from .mcp_family_recovery import _arguments, _attempt, _qualify, _utc
from .mcp_family_local_vault import execute_family_local_cleanup, plan_family_local_cleanup, _receipt_matches
from .mcp_oauth import _sha256, _token_store
from .mcp_oauth_observations import locked_oauth_server


def _context(db, server_id, attempt_id, *, lock=False):
    server = locked_oauth_server(db, server_id)
    if server is None:
        raise LookupError("MCP server not found")
    attempt = _attempt(db, server, attempt_id, lock=lock)
    query = select(MCPOAuthFamilyRecovery).where(MCPOAuthFamilyRecovery.id == attempt.family_recovery_id,
        MCPOAuthFamilyRecovery.tenant_id == server.tenant_id, MCPOAuthFamilyRecovery.region_id == server.region_id)
    family = db.scalar((query.with_for_update() if lock else query).execution_options(populate_existing=True))
    if family is None or family.status != "issuer_verified":
        raise ValueError("Independently reviewed exact-family issuer proof is required before local cleanup")
    try:
        frozen = OAuthFamilyRecoverySnapshot.model_validate(family.snapshot)
        proof = OAuthContainmentProof.model_validate(family.proof)
    except ValueError as exc:
        raise ValueError("Retained family proof or original custody is invalid") from exc
    _arguments(db, family, frozen)
    return server, attempt, family, frozen, proof


def _authority(db, actor, server, family):
    current = current_human_authority(db, actor, permissions=("tools.admin", "changes.approve"),
        tenant_id=server.tenant_id, region_id=server.region_id)
    if current.actor.principal_id == family.initiated_by:
        raise PermissionError("Local cleanup requires a different current human from the recovery initiator")
    return current


def _credential(actor):
    return actor.access_token_id if actor.auth_method == "bearer" else actor.session_id


def _proof(db, family, frozen, retained):
    payload = MCPOAuthFamilyRecoveryConfirm(expected_recovery_id=family.id, proposal_id=family.proposal_id,
        verification_tool_call_id=family.verification_tool_call_id, reason="Revalidate retained exact-family containment proof")
    if _qualify(db, family, frozen, payload) != retained:
        raise ValueError("Retained issuer proof no longer matches its exact independent provenance")


def _execution(db, family, *, lock=False):
    query = select(MCPOAuthFamilyLocalExecution).where(MCPOAuthFamilyLocalExecution.recovery_id == family.id,
        MCPOAuthFamilyLocalExecution.tenant_id == family.tenant_id, MCPOAuthFamilyLocalExecution.region_id == family.region_id)
    row = db.scalar((query.with_for_update() if lock else query).execution_options(populate_existing=True))
    if row is None:
        raise LookupError("Local family cleanup has not been admitted")
    return row


def _retained(row, attempt, family, frozen, proof):
    try:
        plan = FamilyLocalPlan.model_validate(row.plan)
        receipt = FamilyLocalReceipt.model_validate(row.receipt) if row.receipt is not None else None
        completion = FamilyLocalCompletion.model_validate(row.completion) if row.completion is not None else None
        scope = FamilyLocalScope(recovery_id=family.id, attempt_id=attempt.id, generation=attempt.generation,
            locator=frozen.locator, issuer=attempt.issuer, client_id=attempt.client_id, resource=attempt.resource,
            target=frozen.target, historical=plan.scope.historical, vault_address=frozen.consent.vault_address,
            vault_namespace=frozen.consent.vault_namespace, secret_ref=frozen.consent.token_profile.secret_ref)
        if (plan.plan_id != row.id or plan.scope != scope or row.proof != proof.model_dump(mode="json")
                or row.recovery_id != family.id or row.admitted_by == family.initiated_by
                or (plan.scope.historical and attempt.status not in {"superseded", "revoked"})
                or type(row.deleted_versions) is not list
                or any(type(v) is not int for v in row.deleted_versions)
                or row.deleted_versions != sorted(set(row.deleted_versions))):
            raise ValueError("Invalid plan custody")
        if receipt is not None:
            _receipt_matches(plan, receipt)
        allowed = set(receipt.owned_versions) if receipt else set()
        if receipt and plan.mode in {"reserve_empty", "retire_head"}:
            allowed.add(receipt.reservation_version)
        if not set(row.deleted_versions).issubset(allowed):
            raise ValueError("Deletion custody exceeds the original family")
        if completion is not None and (receipt is None or completion.plan_id != row.id
                or completion.recovery_id != family.id or completion.fence_version != receipt.fence_version
                or set(completion.deleted_versions) != allowed or set(row.deleted_versions) != allowed
                or completion.restored_previous != (plan.mode == "preserve_previous")
                or (plan.mode == "preserve_previous" and completion.head_version != receipt.reservation_version + 1)):
            raise ValueError("Incomplete local receipt")
        expected_status = "complete" if completion else "fenced" if receipt else "admitted"
        if row.status != expected_status or (completion is not None) != (row.completed_at is not None):
            raise ValueError("Local phase differs from its receipts")
    except ValueError as exc:
        raise ValueError("Retained local execution custody is invalid; preserve the fence") from exc
    return plan, receipt, completion


def read_family_local(db: Session, server, attempt_id: str) -> MCPOAuthFamilyLocalRead:
    server, attempt, family, frozen, proof = _context(db, server.id, attempt_id)
    row = _execution(db, family)
    plan, receipt, completion = _retained(row, attempt, family, frozen, proof)
    verified = (completion is not None and attempt.family_contained_at is not None
        and _utc(attempt.family_contained_at) == _utc(row.completed_at))
    return MCPOAuthFamilyLocalRead(server_id=server.id, attempt_id=attempt.id, recovery_id=family.id,
        plan_id=row.id, status=row.status, mode=plan.mode, planned_head_version=plan.head_version,
        affected_versions=plan.owned_versions, admitted_by=row.admitted_by, admitted_at=row.admitted_at,
        receipt=receipt, deleted_versions=tuple(row.deleted_versions), completion=completion,
        completed_at=row.completed_at, local_cleanup_verified=verified)


def start_family_local(db: Session, server, attempt_id: str, payload: MCPOAuthFamilyLocalStart, *,
                       actor: PrincipalContext, settings: Settings | None = None,
                       token_store: MCPOAuthVaultCredentialProvider | None = None):
    server, attempt, family, frozen, proof = _context(db, server.id, attempt_id, lock=True)
    authority = _authority(db, actor, server, family)
    if family.id != payload.expected_recovery_id:
        raise ValueError("Recovery claim was replaced")
    existing = db.scalar(select(MCPOAuthFamilyLocalExecution.id).where(MCPOAuthFamilyLocalExecution.recovery_id == family.id))
    if existing is not None:
        raise ValueError("An immutable local plan already exists; resume its owned custody instead")
    _proof(db, family, frozen, proof)
    scope = FamilyLocalScope(recovery_id=family.id, attempt_id=attempt.id, generation=attempt.generation,
        locator=frozen.locator, issuer=attempt.issuer, client_id=attempt.client_id, resource=attempt.resource,
        target=frozen.target, historical=attempt.status in {"superseded", "revoked"},
        vault_address=frozen.consent.vault_address, vault_namespace=frozen.consent.vault_namespace,
        secret_ref=frozen.consent.token_profile.secret_ref)
    plan = plan_family_local_cleanup(token_store or _token_store(settings or get_settings()), scope)
    row = MCPOAuthFamilyLocalExecution(id=plan.plan_id, recovery_id=family.id,
        tenant_id=server.tenant_id, region_id=server.region_id, plan=plan.model_dump(mode="json"),
        proof=proof.model_dump(mode="json"), status="admitted", admitted_by=authority.actor.principal_id,
        auth_method=authority.actor.auth_method, credential_id=_credential(authority.actor), deleted_versions=[])
    db.add(row)
    record_audit_event(db, event_type="mcp.oauth.family_local.admitted", actor_type="user",
        actor_id=authority.actor.subject, entity_type="mcp_server", entity_id=server.id,
        details={"recovery_id": family.id, "attempt_id": attempt.id, "plan_id": row.id,
                 "mode": plan.mode, "reason_sha256": _sha256(payload.reason), "reconnect_allowed": False})
    db.flush(); authority.assert_live(db); db.commit()
    return read_family_local(db, server, attempt.id)


def execute_family_local(db: Session, server, attempt_id: str, payload: MCPOAuthFamilyLocalExecute, *,
                         actor: PrincipalContext, settings: Settings | None = None,
                         token_store: MCPOAuthVaultCredentialProvider | None = None):
    server_id = server.id
    def locked():
        context = _context(db, server_id, attempt_id, lock=True)
        current_server, attempt, family, frozen, proof = context
        row = _execution(db, family, lock=True)
        if (family.id, row.id) != (payload.expected_recovery_id, payload.expected_plan_id):
            raise ValueError("Original local plan is unavailable or superseded")
        _retained(row, attempt, family, frozen, proof)
        return (*context, row)

    server, attempt, family, frozen, proof, row = locked()
    authority = _authority(db, actor, server, family)
    _proof(db, family, frozen, proof)
    plan, receipt, completion = _retained(row, attempt, family, frozen, proof)
    deleted_versions = tuple(row.deleted_versions)
    authority.assert_live(db); db.commit()  # Release every lock BEFORE mutation I/O.
    if completion is not None:
        return read_family_local(db, server, attempt_id)
    provider = token_store or _token_store(settings or get_settings())

    def authorize(phase, version):
        server, _, family, frozen, proof, row = locked()
        current = _authority(db, actor, server, family)
        _proof(db, family, frozen, proof)
        if row.status == "complete":
            raise ValueError("Local execution is already complete; no new mutation is authorized")
        db.add(MCPOAuthFamilyLocalMutation(execution_id=row.id, tenant_id=row.tenant_id, region_id=row.region_id,
            phase=phase, version=version, authorized_by=current.actor.principal_id,
            auth_method=current.actor.auth_method, credential_id=_credential(current.actor)))
        db.flush(); current.assert_live(db); db.commit()

    # Owned receipts are evidence of already-admitted I/O. Do not discard them
    # merely because credentials expired or grants were withdrawn afterwards.
    def fence(value):
        *_, row = locked()
        if row.receipt is not None and FamilyLocalReceipt.model_validate(row.receipt) != value:
            raise ValueError("Retained fence receipt cannot be replaced")
        if row.receipt is None:
            row.receipt = value.model_dump(mode="json"); row.status = "fenced"
        db.flush(); db.commit()

    def deleted(version):
        *_, row = locked()
        row.deleted_versions = sorted(set(row.deleted_versions) | {version})
        db.flush(); db.commit()

    def complete(value):
        _, attempt, _, _, _, row = locked()
        if row.completion is not None:
            if FamilyLocalCompletion.model_validate(row.completion) != value:
                raise ValueError("Retained completion receipt cannot be replaced")
        else:
            row.completion = value.model_dump(mode="json"); row.status = "complete"; row.completed_at = utcnow()
            db.flush()
            attempt.family_contained_at = row.completed_at; attempt.updated_at = row.completed_at
            record_audit_event(db, event_type="mcp.oauth.family_local.completed", actor_type="system",
                actor_id="owned-local-receipt", entity_type="mcp_server", entity_id=server_id,
                details={"recovery_id": row.recovery_id, "attempt_id": attempt.id, "plan_id": row.id,
                         "reconnect_allowed": False, "original_status": attempt.status})
        db.flush(); db.commit()

    try:
        execute_family_local_cleanup(provider, plan, receipt=receipt, deleted_versions=deleted_versions,
            authorize_mutation=authorize, retain_fence=fence, retain_deleted=deleted, retain_completion=complete)
    except BaseException:
        db.rollback()  # Never roll back any earlier committed admission/receipt.
        raise
    return read_family_local(db, server, attempt_id)
