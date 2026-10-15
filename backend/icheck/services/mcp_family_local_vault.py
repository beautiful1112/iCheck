"""Exact-family Vault finalization primitives, with durable admission/receipt hooks.

This module never redeems/revokes a token, destroys metadata, infers an owner
from a deadline, or chooses a new profile. The control plane must retain the
plan and verified issuer proof before invoking execution. Every new mutation
requires current authority; receipts survive subsequent authority withdrawal.
"""
import secrets
from datetime import UTC, datetime
from typing import Callable

from ..credentials import CredentialUnavailable, MCP_OAUTH_VAULT_SECRET_REF, MCPOAuthVaultCredentialProvider, VaultRequestError
from ..oauth_consent import OAuthAuthorizationLocator
from ..oauth_family_local import (FamilyLocalCompletion, FamilyLocalPlan, FamilyLocalReceipt,
    FamilyLocalScope, FamilyRestoreWitness)

RESERVATION = "icheck_oauth_family_reservation"
RESTORATION = "icheck_oauth_family_restoration"


def _provider(provider, scope):
    if provider.address != scope.vault_address.rstrip("/") or provider.namespace != scope.vault_namespace:
        raise CredentialUnavailable("Family cleanup provider differs from the original Vault identity")
    provider._kv2_location(scope.secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)


def _metadata(provider, scope):
    mount, path, _ = provider._kv2_location(scope.secret_ref, pattern=MCP_OAUTH_VAULT_SECRET_REF)
    try:
        document = provider._request_json("GET", f"{mount}/metadata/{path}")
    except VaultRequestError as exc:
        if exc.status_code == 404 and scope.target.vault_version == 0:
            return 0, 0, {}
        raise CredentialUnavailable("Original Vault metadata is unavailable; no absence may be inferred") from exc
    try:
        data = document["data"]
        current, oldest, versions = data["current_version"], data["oldest_version"], data["versions"]
        if (type(current) is not int or not 0 <= current <= 2_147_483_647 or type(oldest) is not int
                or not 0 <= oldest <= current or type(versions) is not dict or len(versions) > 512):
            raise ValueError("Invalid range")
        if current == 0:
            if oldest != 0 or versions:
                raise ValueError("Version zero cannot contain history")
            return 0, 0, {}
        start = max(1, oldest)
        if current - start + 1 > 512 or set(versions) != {str(v) for v in range(start, current + 1)}:
            raise ValueError("Incomplete version metadata")
        inactive = {}
        now = datetime.now(UTC)
        for key, item in versions.items():
            destroyed, deleted = item["destroyed"], item["deletion_time"]
            if type(destroyed) is not bool or type(deleted) is not str or len(deleted) > 128:
                raise ValueError("Invalid version state")
            when = None if not deleted else datetime.fromisoformat(deleted.replace("Z", "+00:00"))
            if when is not None and when.tzinfo is None:
                raise ValueError("Deletion time requires a timezone")
            inactive[int(key)] = destroyed or (when is not None and when <= now)
        return current, start, inactive
    except (KeyError, TypeError, ValueError) as exc:
        raise CredentialUnavailable("Vault family version metadata is invalid or incomplete") from exc


def _version(provider, scope, version):
    document, observed = provider.read_kv2_document(scope.secret_ref, version=version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
    if type(observed) is not int or observed != version:
        raise CredentialUnavailable("Vault returned a different archived version")
    return document


def _head(provider, scope):
    current, oldest, inactive = _metadata(provider, scope)
    document = None if current == 0 or inactive[current] else _version(provider, scope, current)
    return document, current, oldest, inactive


def _owned(provider, scope, document):
    if document.get(provider.GENERATION_KEY) != scope.generation:
        return False
    bundle = provider._validate_bundle(document)
    try:
        locator = OAuthAuthorizationLocator.model_validate(bundle.get("icheck_oauth_authorization_locator"))
    except ValueError as exc:
        raise CredentialUnavailable("Affected family has no valid original authorization locator") from exc
    if (locator != scope.locator or bundle["issuer"] != scope.issuer
            or bundle["client_id"] != scope.client_id or bundle["resource"] != scope.resource):
        raise CredentialUnavailable("Vault generation does not belong to the reviewed transaction family")
    return True


def _previous(provider, scope):
    target = scope.target
    if not target.present:
        raise CredentialUnavailable("There is no previous bundle to restore")
    document = provider._validate_bundle(_version(provider, scope, target.vault_version))
    state = provider._coordination(document, target.vault_version)
    if (document.get(provider.GENERATION_KEY) != target.generation or document["issuer"] != target.issuer
            or document["client_id"] != target.client_id or document["resource"] != target.resource
            or (state is not None and (state["status"] != "ready" or state["owner"] != target.coordination_owner))
            or (state is None and target.coordination_owner is not None)):
        raise CredentialUnavailable("Previous bundle differs from the exact original target")
    # A ready coordination receipt belongs to its old version, not the restore.
    document.pop(provider.COORDINATION_KEY, None)
    return document


def plan_family_local_cleanup(provider: MCPOAuthVaultCredentialProvider, scope: FamilyLocalScope) -> FamilyLocalPlan:
    """Read-only bounded inventory; the caller must durably admit this exact plan."""
    _provider(provider, scope)
    head, current, oldest, inactive = _head(provider, scope)
    if current < scope.target.vault_version:
        raise CredentialUnavailable("Vault version history regressed behind consent admission")
    if head is not None and RESERVATION in head:
        raise CredentialUnavailable("Another local recovery owns the Vault head")
    owned = []
    for version in range(max(oldest, scope.target.vault_version + 1), current + 1):
        if not inactive[version] and _owned(provider, scope, _version(provider, scope, version)):
            owned.append(version)
    head_owned = head is not None and _owned(provider, scope, head)
    generation = head.get(provider.GENERATION_KEY) if head is not None else None
    if current == scope.target.vault_version:
        if scope.historical:
            raise CredentialUnavailable("Historical family cannot be inferred from the original pre-consent head")
        if scope.target.present:
            _previous(provider, scope)
            if head is None:
                raise CredentialUnavailable("Previous live bundle is missing")
            mode = "preserve_previous"
        else:
            if head is not None:
                raise CredentialUnavailable("Originally absent credentials were replaced without a version advance")
            mode = "reserve_empty"
    elif head_owned:
        if scope.historical:
            mode = "retire_head"
        elif scope.target.present:
            _previous(provider, scope)  # Never guess/restore an unavailable original family.
            mode = "preserve_previous"
        else:
            mode = "reserve_empty"
    else:
        mode = "retired_elsewhere"  # Never CAS/delete another current family's head.
    if _metadata(provider, scope)[0] != current:
        raise CredentialUnavailable("Vault inventory changed during local preflight; admit no mutation")
    try:
        return FamilyLocalPlan(plan_id=secrets.token_hex(16), scope=scope, mode=mode,
            head_version=current, head_generation=generation, owned_versions=tuple(owned),
            allow_late_publish=current == scope.target.vault_version and mode in {"preserve_previous", "reserve_empty"})
    except ValueError as exc:
        raise CredentialUnavailable("Vault family plan exceeds its bounded contract") from exc


def _receipt_matches(plan, receipt):
    if receipt.plan_id != plan.plan_id or receipt.recovery_id != plan.scope.recovery_id or receipt.mode != plan.mode:
        raise CredentialUnavailable("Local receipt belongs to a different admitted plan")
    late = plan.allow_late_publish and receipt.source_version == plan.head_version + 1
    expected = tuple(sorted((*plan.owned_versions, receipt.source_version))) if late else plan.owned_versions
    if receipt.source_version != plan.head_version and not late:
        raise CredentialUnavailable("Local reservation silently rebased its target")
    if receipt.owned_versions != expected or receipt.fence_version <= plan.scope.target.vault_version:
        raise CredentialUnavailable("Local fence does not cover the exact affected versions")


def _marker(plan, receipt):
    return {"plan": plan.model_dump(mode="json"), "receipt": receipt.model_dump(mode="json")}


def _owned_marker(provider, plan, document, version):
    try:
        marker = document[RESERVATION]
        if set(marker) != {"plan", "receipt"} or FamilyLocalPlan.model_validate(marker["plan"]) != plan:
            raise ValueError("Wrong plan")
        receipt = FamilyLocalReceipt.model_validate(marker["receipt"])
        _receipt_matches(plan, receipt)
        if receipt.reservation_version != version:
            raise ValueError("Wrong reservation version")
        clean = {key: value for key, value in document.items() if key != RESERVATION}
        if plan.mode == "preserve_previous":
            bundle = provider._validate_bundle(clean)
            target = plan.scope.target
            if (bundle.get(provider.GENERATION_KEY) != target.generation or bundle["issuer"] != target.issuer
                    or bundle["client_id"] != target.client_id or bundle["resource"] != target.resource
                    or provider.COORDINATION_KEY in bundle):
                raise ValueError("Wrong previous family")
        elif clean:
            raise ValueError("Tokenless reservation contains unexpected data")
        return receipt, clean
    except (KeyError, TypeError, ValueError) as exc:
        raise CredentialUnavailable("Local recovery reservation differs from durable custody") from exc


def _inactive(provider, scope, version, *, fence):
    current, oldest, flags = _metadata(provider, scope)
    if current < fence:
        raise CredentialUnavailable("Vault fence/version history regressed during cleanup")
    return version < oldest or flags.get(version) is True


def _foreign_head(provider, plan, *, fence):
    document, current, _, _ = _head(provider, plan.scope)
    if current < fence or (document is not None and document.get(provider.GENERATION_KEY) == plan.scope.generation):
        raise CredentialUnavailable("Affected family is still the current Vault head")
    return current


def execute_family_local_cleanup(
    provider: MCPOAuthVaultCredentialProvider, plan: FamilyLocalPlan, *,
    receipt: FamilyLocalReceipt | None = None, deleted_versions: tuple[int, ...] = (),
    authorize_mutation: Callable[[str, int], None], retain_fence: Callable[[FamilyLocalReceipt], None],
    retain_deleted: Callable[[int], None], retain_completion: Callable[[FamilyLocalCompletion], None],
) -> FamilyLocalCompletion:
    """Execute/resume an admitted exact plan, never an issuer grant or new target.

    Hooks must durably commit admission before I/O and an owned receipt after it.
    Every new delete/restore needs fresh authority, including retries with a
    retained fence. Callback/DB failure stops before the next mutation.
    """
    if not all(callable(hook) for hook in (authorize_mutation, retain_fence, retain_deleted, retain_completion)):
        raise ValueError("Local cleanup requires all current-authority and durable-receipt hooks")
    _provider(provider, plan.scope)
    if receipt is not None:
        _receipt_matches(plan, receipt)
    if (any(type(v) is not int for v in deleted_versions) or tuple(sorted(set(deleted_versions))) != deleted_versions
            or (deleted_versions and receipt is None)):
        raise CredentialUnavailable("Local deletion receipts are invalid or lack a retained fence")
    head, current, _, _ = _head(provider, plan.scope)
    previous = None
    if receipt is None:
        if head is not None and RESERVATION in head:
            receipt, previous = _owned_marker(provider, plan, head, current)
        elif plan.mode == "retired_elsewhere":
            _foreign_head(provider, plan, fence=plan.head_version)
            receipt = FamilyLocalReceipt(plan_id=plan.plan_id, recovery_id=plan.scope.recovery_id,
                mode=plan.mode, source_version=plan.head_version, fence_version=plan.head_version,
                owned_versions=plan.owned_versions)
        else:
            late = (plan.allow_late_publish and current == plan.head_version + 1
                    and head is not None and _owned(provider, plan.scope, head))
            if current != plan.head_version and not late:
                raise CredentialUnavailable("Vault target changed; the local plan cannot be rebased")
            if not late and head is not None:
                if current == plan.scope.target.vault_version and plan.mode == "preserve_previous":
                    _previous(provider, plan.scope)
                elif not _owned(provider, plan.scope, head):
                    raise CredentialUnavailable("Local plan cannot reserve an unrelated live bundle")
            if head is None and plan.mode not in {"reserve_empty"}:
                raise CredentialUnavailable("Admitted live Vault head became absent")
            owned = tuple(sorted((*plan.owned_versions, current))) if late else plan.owned_versions
            receipt = FamilyLocalReceipt(plan_id=plan.plan_id, recovery_id=plan.scope.recovery_id,
                mode=plan.mode, source_version=current, fence_version=current + 1,
                reservation_version=current + 1, owned_versions=owned)
            previous = _previous(provider, plan.scope) if plan.mode == "preserve_previous" else {}
            values = {**previous, RESERVATION: _marker(plan, receipt)}
            authorize_mutation("reserve", current)
            try:
                written = provider.write_kv2_document(plan.scope.secret_ref, values, cas=current, pattern=MCP_OAUTH_VAULT_SECRET_REF)
                if type(written) is not int or written != receipt.reservation_version:
                    raise CredentialUnavailable("Local reservation returned an invalid version")
            except CredentialUnavailable:
                try:
                    observed = _version(provider, plan.scope, receipt.reservation_version)
                    if observed != values:
                        raise CredentialUnavailable("Reservation ownership cannot be established")
                except CredentialUnavailable:
                    raise CredentialUnavailable("Local reservation outcome is unknown; retain its admitted plan") from None
        _receipt_matches(plan, receipt)
        retain_fence(receipt)  # MUST be durable before any deletion/restore.
    allowed_deleted = set(receipt.owned_versions)
    if plan.mode in {"reserve_empty", "retire_head"}:
        allowed_deleted.add(receipt.reservation_version)
    if not set(deleted_versions).issubset(allowed_deleted):
        raise CredentialUnavailable("Deletion receipt exceeds the reviewed family")
    deleted = set(deleted_versions)
    for version in receipt.owned_versions:
        if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
            if not _owned(provider, plan.scope, _version(provider, plan.scope, version)):
                raise CredentialUnavailable("Archived version belongs to another family; it cannot be deleted")
            authorize_mutation("delete_version", version)
            try:
                provider.delete_kv2_version(plan.scope.secret_ref, version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
            except CredentialUnavailable:
                if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
                    raise CredentialUnavailable("Archived deletion outcome is unknown") from None
            if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
                raise CredentialUnavailable("Archived family version remains readable")
        if version not in deleted:
            retain_deleted(version); deleted.add(version)
    expiry = None
    if plan.mode == "preserve_previous":
        head, current, _, _ = _head(provider, plan.scope)
        witness = FamilyRestoreWitness(plan_id=plan.plan_id, recovery_id=plan.scope.recovery_id,
            reservation_version=receipt.reservation_version)
        if current == receipt.reservation_version + 1 and head is not None and head.get(RESTORATION) == witness.model_dump(mode="json"):
            restored = provider._validate_bundle(head)
            target = plan.scope.target
            if (restored.get(provider.GENERATION_KEY) != target.generation or restored["issuer"] != target.issuer
                    or restored["client_id"] != target.client_id or restored["resource"] != target.resource):
                raise CredentialUnavailable("Restored credentials differ from the original family")
        else:
            if head is None:
                raise CredentialUnavailable("Owned reservation is unavailable before restore")
            owned_receipt, previous = _owned_marker(provider, plan, head, current)
            if owned_receipt != receipt:
                raise CredentialUnavailable("Restore cannot replace a different local fence")
            restored = {**previous, RESTORATION: witness.model_dump(mode="json")}
            authorize_mutation("restore", current)
            try:
                written = provider.write_kv2_document(plan.scope.secret_ref, restored, cas=current, pattern=MCP_OAUTH_VAULT_SECRET_REF)
                if type(written) is not int or written != current + 1:
                    raise CredentialUnavailable("Restore returned an invalid version")
            except CredentialUnavailable:
                try:
                    if _version(provider, plan.scope, current + 1) != restored:
                        raise CredentialUnavailable("Restore ownership is unknown")
                except CredentialUnavailable:
                    raise CredentialUnavailable("Original-family restoration outcome is unknown") from None
            current += 1
        expiry = provider._timestamp(restored["expires_at"])
        if _metadata(provider, plan.scope)[0] != current:
            raise CredentialUnavailable("Restoration was superseded before completion")
    elif plan.mode in {"reserve_empty", "retire_head"}:
        version = receipt.reservation_version
        if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
            owned_receipt, _ = _owned_marker(provider, plan, _version(provider, plan.scope, version), version)
            if owned_receipt != receipt:
                raise CredentialUnavailable("Cannot delete a different reservation")
            authorize_mutation("delete_reservation", version)
            try:
                provider.delete_kv2_version(plan.scope.secret_ref, version, pattern=MCP_OAUTH_VAULT_SECRET_REF)
            except CredentialUnavailable:
                if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
                    raise CredentialUnavailable("Reservation deletion outcome is unknown") from None
            if not _inactive(provider, plan.scope, version, fence=receipt.fence_version):
                raise CredentialUnavailable("Local reservation remains readable")
        if version not in deleted:
            retain_deleted(version); deleted.add(version)
        current = _foreign_head(provider, plan, fence=receipt.fence_version)
    else:
        current = _foreign_head(provider, plan, fence=receipt.fence_version)
    completion = FamilyLocalCompletion(plan_id=plan.plan_id, recovery_id=plan.scope.recovery_id,
        fence_version=receipt.fence_version, head_version=current, restored_previous=plan.mode == "preserve_previous",
        previous_expires_at=expiry, deleted_versions=tuple(sorted(deleted)))
    retain_completion(completion)
    return completion
