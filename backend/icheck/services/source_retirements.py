"""Atomic permanent source cutover. No physical operation or closure authority."""
from datetime import datetime, timedelta

from sqlalchemy import select

from ..config import get_settings
from ..database import session_namespace
from ..models import (Alert, AlertConditionState, AlertStatus, CollectorConditionAdmission, CollectorConditionReceipt, CollectorConditionSource,
    CollectorSourceReplacementRequest, CollectorSourceReplacementReview, CollectorSourceReplacementRevocation,
    CollectorSourceRetirement, Situation, SituationAlert, SituationClosureOwnership, new_id, utcnow)
from ..source_replacement_schemas import SourceRetirementRead
from .alert_conditions import as_utc
from .audit import record_audit_event
from .authorization_scope import require_alert_access, require_situation_access
from .collector_conditions import canonical
from .collectors import assert_no_inline_secrets
from .control_plane_auth import PrincipalContext
from .source_qualifications import _row, _start, _origin, _human
from .source_replacements import (MANAGE, REVIEW, _authority, _material, _namespace_query, _pair, _scope)
from .situations import _recompute_situation, append_situation_event

EXECUTE = "alerts.sources.replace"
PROTOCOL = "icheck.collector.source-retirement/v1"
MAX_MEMBERS = 512


def retirement_for_source(db, source_id, *, namespace=None):
    namespace = namespace or session_namespace(db)
    if namespace is None:
        raise PermissionError("Source retirement requires a selected namespace")
    return db.scalar(select(CollectorSourceRetirement).where(CollectorSourceRetirement.tenant_id == namespace[0],
        CollectorSourceRetirement.region_id == namespace[1],
        CollectorSourceRetirement.old_source_id == source_id).execution_options(populate_existing=True))


def _state(db, source):
    state = db.scalar(_namespace_query(db, AlertConditionState).where(AlertConditionState.dedup_key == source.dedup_key)
        .with_for_update(nowait=True).execution_options(populate_existing=True))
    expected = source.context["definition"]["event_type"], source.entity_type, source.entity_id, None
    if state is None or state.observed_at is None or (state.event_type, state.entity_type, state.entity_id, state.source_rule_id) != expected:
        raise ValueError("Source cutover requires a sealed condition watermark with exact identity")
    return state


def _state_pin(state):
    return {"id": state.id, "revision": state.revision, "state": state.state,
        "observed_at": as_utc(state.observed_at).isoformat(), "latest_alert_id": state.latest_alert_id,
        "event_type": state.event_type, "entity_type": state.entity_type, "entity_id": state.entity_id,
        "source_rule_id": state.source_rule_id}


def admitted_source_clock(db, source):
    """Include already sealed, not-yet-projected observations in the cutoff."""
    pins = CollectorConditionAdmission.context["pins"]
    query = _namespace_query(db, CollectorConditionAdmission).where(
        CollectorConditionAdmission.deployment_id == source.deployment_id,
        CollectorConditionAdmission.artifact_version_id == source.artifact_version_id,
        pins["assignment_sha256"].as_string() == source.assignment_sha256,
        pins["definition"]["key"].as_string() == source.condition_key,
        pins["entity"]["id"].as_string() == source.entity_id,
        pins["entity"]["type"].as_string() == source.entity_type)
    credential = source.context["credential_profile"]
    if credential is None:
        query = query.where(CollectorConditionAdmission.credential_grant_audit_id.is_(None))
    else:
        query = query.where(pins["credential_profile"]["profile_id"].as_string() == credential["profile_id"],
            pins["credential_profile"]["profile_revision"].as_integer() == credential["profile_revision"])
    value = db.scalar(query.with_only_columns(CollectorConditionAdmission.observed_at)
        .order_by(CollectorConditionAdmission.observed_at.desc()).limit(1))
    if value is None:
        raise ValueError("Source cutover has no exact sealed observation clock")
    return as_utc(value)


def read_source_retirement(db, retirement_id, actor):
    row = _row(db, CollectorSourceRetirement, retirement_id)
    sources = [_row(db, CollectorConditionSource, row.old_source_id), _row(db, CollectorConditionSource, row.new_source_id)]
    current = _authority(db, sources, actor, "alerts.read")
    return retirement_reference_scope(db, row, actor, current)


def retirement_reference_scope(db, row, *actors):
    """Validate retained references under actual read authority, not live origin.

    Non-material recovery checks use this internally without granting material
    permissions or embedding executor snapshots in their public proof.
    """
    sources = [_row(db, CollectorConditionSource, row.old_source_id), _row(db, CollectorConditionSource, row.new_source_id)]
    for actor in actors:
        if not actor.permits("alerts.read"):
            raise PermissionError("Retained retirement references require alerts.read")
        _scope(db, sources, actor)
    request = _row(db, CollectorSourceReplacementRequest, row.request_id)
    review = _row(db, CollectorSourceReplacementReview, row.review_id)
    if (request.old_source_id != row.old_source_id or request.new_source_id != row.new_source_id
        or review.request_id != request.id or request.prior_retirement_id is not None):
        raise ValueError("Retained source retirement lineage is invalid")
    for receipt_id, source, state_pin in ((row.old_watermark_receipt_id, sources[0], row.old_state_snapshot),
        (row.new_receipt_id, sources[1], row.new_state_snapshot)):
        receipt = _row(db, CollectorConditionReceipt, receipt_id)
        if (receipt.source_id != source.id or receipt.condition_state_id != state_pin.get("id")
            or receipt.alert_id != state_pin.get("latest_alert_id")
            or as_utc(receipt.observed_at) != as_utc(datetime.fromisoformat(state_pin["observed_at"]))):
            raise ValueError("Retained source retirement receipt crosses its source")
        if receipt.alert_id is not None:
            for principal in actors:
                require_alert_access(db, principal, receipt.alert_id)
            if _row(db, Alert, receipt.alert_id).dedup_key != source.dedup_key:
                raise ValueError("Retained source retirement Alert crosses its source")
    if row.superseded_alert_id:
        for principal in actors:
            require_alert_access(db, principal, row.superseded_alert_id)
        alert = _row(db, Alert, row.superseded_alert_id)
        if alert.source_retirement_id != row.id or alert.dedup_key != sources[0].dedup_key:
            raise ValueError("Retained source supersession is invalid")
    result = SourceRetirementRead.model_validate(row.result)
    if any(canonical(getattr(row, key)) != canonical(getattr(result, key)) for key in (
        "id", "request_id", "review_id", "old_source_id", "new_source_id", "old_watermark_receipt_id", "new_receipt_id",
        "superseded_alert_id", "executor_principal_id", "executor_subject", "execution_key", "reason",
        "executor_snapshot", "old_state_snapshot", "new_state_snapshot")) or as_utc(row.created_at) != as_utc(result.created_at):
        raise ValueError("Retained source retirement result does not match immutable material")
    return result


def apply_source_replacement(db, request_id, payload, actor):
    _start(db)
    # The namespace fence must precede the complete deployment prefix. Native
    # writers also take it. A closure transaction never waits behind our lower
    # source/state locks; neither transaction retains it during human review.
    from .situation_closure import closure_action_barrier
    closure_action_barrier(db, writer=True)
    previous = db.scalar(_namespace_query(db, CollectorSourceRetirement).where(
        CollectorSourceRetirement.execution_key == payload.execution_key))
    if previous is not None:
        if (previous.request_id != request_id or previous.reason != payload.reason
            or previous.executor_principal_id != actor.principal_id or previous.executor_subject != actor.subject):
            raise ValueError("Source retirement execution key was reused with different intent or executor")
        # Exact committed retries are historical reads, not fresh execution.
        return read_source_retirement(db, previous.id, actor)
    request = _row(db, CollectorSourceReplacementRequest, request_id)
    sources = _pair(db, request)
    current = _authority(db, sources, actor, EXECUTE, nowait=True)
    if not actor.permits("alerts.read") or not current.permits("alerts.read"):
        raise PermissionError("Source retirement requires initiating and current alerts.read")
    if not get_settings().enable_reviewed_source_replacement:
        raise PermissionError("Reviewed source replacement is disabled on this host")
    if request.prior_retirement_id is not None:
        raise ValueError("Historical source revalidation cannot replace its permanent retirement")
    material = _material(db, request, sources, nonblocking_authority=True)
    old, new = sources
    if retirement_for_source(db, old.id) or retirement_for_source(db, new.id):
        raise ValueError("Retired source cannot be retired twice or used as a current target")
    review = db.scalar(_namespace_query(db, CollectorSourceReplacementReview).where(
        CollectorSourceReplacementReview.request_id == request.id))
    if review is None or db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
        CollectorSourceReplacementRevocation.review_id == review.id)):
        raise ValueError("Source replacement requires an unrevoked independent acceptance")
    namespace = session_namespace(db)
    frozen = request.snapshot["initiating_authority"]
    author = PrincipalContext(principal_id=request.author_principal_id, subject=request.author_subject,
        principal_type="user", permissions=frozenset(frozen["permissions"]), role_names=(), authorization_scope=frozen["scope"],
        auth_method="source_replacement_request", tenant_id=namespace[0], region_id=namespace[1])
    author = _authority(db, sources, author, MANAGE, nowait=True)
    peer = _human(db, review.reviewer_principal_id, review.reviewer_subject, REVIEW, material_access_required=True, nowait=True)
    _scope(db, sources, peer)
    if (current.principal_id == peer.principal_id or current.subject == peer.subject
        or author.principal_id == peer.principal_id or author.subject == peer.subject):
        raise PermissionError("Source retirement executor must be independent of the human reviewer")
    if as_utc(request.expires_at) <= utcnow() or canonical(material) != canonical(request.snapshot["material"]):
        raise ValueError("Source replacement intent expired or exact material changed")
    states = {source.id: _state(db, source) for source in sorted(sources, key=lambda row: row.id)}
    old_state, new_state = states[old.id], states[new.id]
    if new_state.state not in {"active", "quiet"}:
        raise ValueError("Source retirement target must have a known active or quiet state")
    at = as_utc(new_state.observed_at)
    old_admitted_at = admitted_source_clock(db, old)
    definition = new.context["definition"]
    if at > utcnow() or utcnow()-at > timedelta(seconds=definition["max_age_seconds"]) or at < max(as_utc(old_state.observed_at), old_admitted_at):
        raise ValueError("Source retirement target is future, stale or older than the old watermark")
    def receipt(source, state, *, known):
        query = _namespace_query(db, CollectorConditionReceipt).where(CollectorConditionReceipt.source_id == source.id,
            CollectorConditionReceipt.condition_state_id == state.id, CollectorConditionReceipt.observed_at == state.observed_at)
        if known:
            query = query.where(CollectorConditionReceipt.disposition == "accepted", CollectorConditionReceipt.verdict == state.state,
                CollectorConditionReceipt.alert_id == state.latest_alert_id if state.latest_alert_id else CollectorConditionReceipt.alert_id.is_(None))
        else:
            query = query.where(CollectorConditionReceipt.disposition.in_(["accepted", "conflict"]))
        row = db.scalar(query.order_by(CollectorConditionReceipt.created_at.desc(), CollectorConditionReceipt.id).limit(1))
        if row is None:
            raise ValueError("Source retirement watermark has no exact sealed receipt")
        return row
    old_receipt, new_receipt = receipt(old, old_state, known=False), receipt(new, new_state, known=True)
    new_snapshot, _ = _origin(db, new, new_receipt, nowait=True)
    if canonical(new_snapshot) != canonical(material["new"]["qualification_snapshot"]):
        raise ValueError("Source retirement target receipt is not currently qualified")
    alerts = {}
    for source in sources:
        state = states[source.id]
        if state.latest_alert_id:
            row = _row(db, Alert, state.latest_alert_id, lock=True, nowait=True)
            if row.dedup_key != source.dedup_key or row.source_retirement_id:
                raise ValueError("Source cutover Alert identity is invalid or already superseded")
            for principal in (actor, current): require_alert_access(db, principal, row.id)
            alerts[source.id] = row
    target = alerts.get(new.id)
    if (new_state.state == "active" and (target is None or target.status not in {AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED})) or (
        new_state.state == "quiet" and target is not None and target.status != AlertStatus.RESOLVED):
        raise ValueError("Target Alert does not agree with its current sealed condition state")
    old_alert = alerts.get(old.id)
    superseded = old_alert if old_alert and old_alert.status in {AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED} else None
    parents = list(db.scalars(_namespace_query(db, Situation).join(SituationAlert, SituationAlert.situation_id == Situation.id)
        .where(SituationAlert.alert_id == superseded.id if superseded else False).order_by(Situation.id)
        .with_for_update(of=Situation, nowait=True).execution_options(populate_existing=True)).all())
    if len(parents) > MAX_MEMBERS:
        raise ValueError("Source retirement Situation membership exceeds its bound")
    for parent in parents:
        for principal in (actor, current): require_situation_access(db, principal, parent.id)
        members = list(db.scalars(_namespace_query(db, SituationAlert).where(SituationAlert.situation_id == parent.id).limit(MAX_MEMBERS+1)))
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError("Source retirement requires bounded complete Situation membership")
        if db.scalar(_namespace_query(db, SituationClosureOwnership).where(SituationClosureOwnership.situation_id == parent.id,
            SituationClosureOwnership.state == "claimed", SituationClosureOwnership.lease_expires_at > utcnow())):
            raise ValueError("Situation has an active reviewed closure lease")
    assert_no_inline_secrets(payload.model_dump())
    retirement_id = new_id()
    result = SourceRetirementRead(protocol=PROTOCOL, id=retirement_id, request_id=request.id, review_id=review.id,
        old_source_id=old.id, new_source_id=new.id, old_watermark_receipt_id=old_receipt.id, new_receipt_id=new_receipt.id,
        superseded_alert_id=superseded.id if superseded else None, executor_principal_id=current.principal_id,
        executor_subject=current.subject, executor_snapshot={"permissions": sorted(actor.permissions), "scope": actor.authorization_scope},
        execution_key=payload.execution_key, reason=payload.reason,
        old_state_snapshot={**_state_pin(old_state), "admitted_through_at": old_admitted_at.isoformat()},
        new_state_snapshot=_state_pin(new_state), created_at=utcnow())
    row = CollectorSourceRetirement(**result.model_dump(exclude={"protocol", "verification_basis", "physical_truth_automatically_verified", "authorizes_incident_closure"}),
        result=result.model_dump(mode="json"))
    db.add(row); db.flush()
    if superseded:
        superseded.source_retirement_id = row.id; db.flush()
    for parent in parents:
        _recompute_situation(db, parent, actor=current.subject)
        append_situation_event(db, parent, event_type="collector.source.retired", actor=current.subject,
            details={"retirement_id": row.id, "superseded_alert_id": superseded.id,
                "authorizes_incident_closure": False, "measured_resolution": False})
    record_audit_event(db, event_type="collector.source.retired", actor_type=current.principal_type, actor_id=current.subject,
        entity_type="collector_source_retirement", entity_id=row.id,
        details={"old_source_id": old.id, "new_source_id": new.id, "superseded_alert_id": row.superseded_alert_id,
            "authorizes_incident_closure": False, "physical_truth_automatically_verified": False})
    db.flush()
    return read_source_retirement(db, row.id, actor)
