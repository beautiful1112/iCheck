"""Immutable indexed action routing; unknown history is never inferred from args."""
from __future__ import annotations

from sqlalchemy import and_, exists, select, text, union

from ..database import session_namespace
from ..models import (ActionTargetAdmission, ActionTargetKey, AgentActionProposal,
    GovernedChangePlan, Investigation)
from .collector_conditions import canonical

MAX_TARGET_PATHS = 16


def routing_keys(contract, targets):
    bindings = contract.get("authorization_target_paths", {}) if isinstance(contract, dict) else {}
    if not isinstance(bindings, dict) or not 0 < len(bindings) <= MAX_TARGET_PATHS:
        return [], True
    keys = set(); unknown = False
    for path, kind in bindings.items():
        value = targets.get(path) if isinstance(targets, dict) else None
        if (not isinstance(kind, str) or kind not in {"device_id", "site"} or not isinstance(value, str)
            or not value.strip(" \t\n\r\f\v") or len(value) > (36 if kind == "device_id" else 255)):
            unknown = True
        else:
            keys.add((kind, value))
    return [{"kind": kind, "value": value} for kind, value in sorted(keys)], unknown


def _pins(db, proposal, investigation, plan):
    routing_plan = plan or (db.get(GovernedChangePlan, proposal.rollback_of_change_plan_id)
        if proposal.rollback_of_change_plan_id else None)
    contract = routing_plan.tool_contract_snapshot if routing_plan else {}
    targets = routing_plan.target_snapshot if routing_plan else {}
    keys, unknown = routing_keys(contract, targets)
    return dict(proposal_id=proposal.id, investigation_id=investigation.id,
        situation_id=investigation.situation_id, tool_id=proposal.tool_id,
        change_plan_id=plan.id if plan else None,
        routing_plan_id=routing_plan.id if routing_plan else None,
        rollback_of_change_plan_id=proposal.rollback_of_change_plan_id,
        origin="frozen_plan" if plan else "frozen_rollback_plan" if routing_plan else "legacy_unknown", unknown_targets=unknown,
        contract_snapshot=contract, target_snapshot=targets, target_keys=keys)


def seal_action_targets(db, proposal, investigation, plan):
    """Seal after plan creation, in the same admission transaction; no new digest."""
    expected = _pins(db, proposal, investigation, plan)
    row = db.get(ActionTargetAdmission, proposal.id)
    if row is None:
        row = ActionTargetAdmission(id=proposal.id, **expected)
        db.add(row); db.flush()
    if any(canonical(getattr(row, key)) != canonical(value) for key, value in expected.items()):
        raise ValueError("Action target admission differs from immutable routing provenance")
    # Native migrations derive every key on INSERT. Metadata-only SQLite tests
    # use the identical explicit derivation, not a weaker target interpretation.
    present = {(item.target_kind, item.target_id) for item in db.scalars(
        select(ActionTargetKey).where(ActionTargetKey.admission_id == row.id)).all()}
    for key in row.target_keys:
        if (key["kind"], key["value"]) not in present:
            db.add(ActionTargetKey(admission_id=row.id, target_kind=key["kind"], target_id=key["value"]))
    db.flush()
    return row


def assert_action_target_pins(db, proposal, investigation, plan):
    row = db.get(ActionTargetAdmission, proposal.id, populate_existing=True)
    if row is None:
        # Metadata-only/legacy test stores have no native admission trigger.
        # They remain conservatively related, never silently trusted routing.
        return None
    expected = _pins(db, proposal, investigation, plan)
    if any(canonical(getattr(row, key)) != canonical(value) for key, value in expected.items()):
        raise ValueError("Related action routing changed after immutable target admission")
    keys = list(db.scalars(select(ActionTargetKey).where(ActionTargetKey.admission_id == row.id).limit(17)).all())
    if sorted((key.target_kind, key.target_id) for key in keys) != sorted(
        (key["kind"], key["value"]) for key in row.target_keys):
        raise ValueError("Related action target index is incomplete or differs from retained admission")
    return row


def related_action_ids(db, situation_id, devices, sites, *, limit):
    """Union indexed branches; unrelated known namespace history never clips proof."""
    namespace = session_namespace(db)
    if namespace is None:
        raise ValueError("Action target lookup requires a selected namespace")
    tenant, region = namespace
    if db.get_bind().dialect.name == "postgresql":
        # Seal even this transaction's flushed-but-uncommitted raw proposals
        # before proof. A deferred fallback cannot hide a same-transaction write.
        db.execute(text("SET CONSTRAINTS icheck_action_target_deferred IMMEDIATE"))
    admission_scope = and_(ActionTargetAdmission.tenant_id == tenant, ActionTargetAdmission.region_id == region)
    key_scope = and_(ActionTargetKey.tenant_id == tenant, ActionTargetKey.region_id == region)
    branches = [select(ActionTargetAdmission.proposal_id.label("proposal_id")).where(admission_scope,
        ActionTargetAdmission.situation_id == situation_id),
        select(ActionTargetAdmission.proposal_id.label("proposal_id")).where(admission_scope,
            ActionTargetAdmission.unknown_targets.is_(True))]
    for kind, values in (("device_id", devices), ("site", sites)):
        if values:
            branches.append(select(ActionTargetKey.admission_id.label("proposal_id")).where(
                key_scope, ActionTargetKey.target_kind == kind, ActionTargetKey.target_id.in_(sorted(values))))
    # PostgreSQL's deferred native admission guarantees there are no committed
    # missing rows. SQLite has no deferred constraint triggers; its fallback is
    # deliberately exhaustive, and not a production fleet performance claim.
    if db.get_bind().dialect.name != "postgresql":
        branches.append(select(AgentActionProposal.id.label("proposal_id")).where(
            AgentActionProposal.tenant_id == tenant, AgentActionProposal.region_id == region,
            ~exists(select(ActionTargetAdmission.id).where(ActionTargetAdmission.proposal_id == AgentActionProposal.id))))
    candidates = union(*branches).subquery()
    return list(db.scalars(select(candidates.c.proposal_id).order_by(candidates.c.proposal_id).limit(limit)).all())
