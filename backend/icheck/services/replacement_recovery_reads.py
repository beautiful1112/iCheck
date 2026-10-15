"""Retained v2 provenance and scope; never refresh retired origin or authority."""
from datetime import datetime

from sqlalchemy import select

from ..models import (AlertConditionState, CollectorConditionReceipt, CollectorConditionSource,
    CollectorSourceQualificationRequest, CollectorSourceQualificationReview)
from ..replacement_recovery_proof_schemas import ReplacementRecoveryProof
from .alert_conditions import as_utc
from .authorization_scope import require_alert_access
from .collector_conditions import canonical
from .replacement_recovery import replacement_references
from .source_qualifications import _row, require_source_access
from .source_replacements import historical_source_receipt


def historical_replacement_recovery_scope(db, report, policy, review_id, identity, *actors):
    from .situation_recovery import _bindings, policy_reference_scope
    proof = ReplacementRecoveryProof.model_validate(report)
    if (policy.proof_version != 2 or proof.situation_id != identity["situation_id"]
        or proof.policy_review_id != review_id or proof.evidence_environment != policy.evidence_environment):
        raise ValueError("Retained replacement recovery policy lineage is invalid")
    expected = identity["members"]
    # Preserve the original timestamp spelling shared by the immutable intent
    # and report; typed validation must not rewrite +00:00 into Z for comparison.
    values = report["membership"]
    if not expected or canonical([{key: item.get(key) for key in expected[0]} for item in values]) != canonical(expected):
        raise ValueError("Retained replacement membership differs from the closure request")
    policy_reference_scope(db, policy, *actors)
    bindings = {item.source_id: item.qualification_review_id for item in _bindings(policy)}
    replacements = {item.old.id: item for item in replacement_references(db, policy)}
    members = {item.alert_id: item for item in proof.membership}
    covered = set()
    for item in proof.source_evidence:
        source = _row(db, CollectorConditionSource, item.source_id)
        accepted = _row(db, CollectorSourceQualificationReview, item.qualification_review_id)
        request = _row(db, CollectorSourceQualificationRequest, accepted.request_id)
        if (bindings.get(source.id) != accepted.id or request.source_id != source.id
            or request.id != item.qualification_request_id):
            raise ValueError("Retained current source qualification is outside the exact policy")
        for actor in actors: require_source_access(db, source, actor)
        samples = list(db.scalars(select(CollectorConditionReceipt).where(
            CollectorConditionReceipt.id.in_(item.quiet_sample_receipt_ids))))
        if len(samples) != len(item.quiet_sample_receipt_ids):
            raise ValueError("Retained replacement quiet samples are unavailable")
        by_id = {row.id: row for row in samples}
        ordered = [by_id[value] for value in item.quiet_sample_receipt_ids]
        times = [as_utc(row.observed_at) for row in ordered]
        if (times[0] != item.quiet_observed_at or times[-1] != item.quiet_window_start
            or ordered[0].admission_id != item.quiet_admission_id
            or len(ordered) < policy.min_quiet_samples
            or (times[0]-times[-1]).total_seconds() < policy.min_quiet_seconds
            or any(not 0 < (left-right).total_seconds() <= policy.max_sample_gap_seconds
                for left, right in zip(times, times[1:]))):
            raise ValueError("Retained replacement quiet window differs from its immutable samples")
        state = _row(db, AlertConditionState, ordered[0].condition_state_id)
        if state.dedup_key != source.dedup_key:
            raise ValueError("Retained replacement state is outside its source")
        interval = list(db.scalars(select(CollectorConditionReceipt).where(
            CollectorConditionReceipt.source_id == source.id,
            CollectorConditionReceipt.observed_at >= item.quiet_window_start,
            CollectorConditionReceipt.observed_at <= item.quiet_observed_at,
            CollectorConditionReceipt.disposition.in_(["accepted", "conflict"]))
            .order_by(CollectorConditionReceipt.observed_at.desc(), CollectorConditionReceipt.id).limit(257)))
        if [row.id for row in interval] != item.quiet_sample_receipt_ids:
            raise ValueError("Retained replacement window omits or bridges accepted or conflicting evidence")
        for row in ordered:
            if (row.source_id != source.id or row.condition_state_id != state.id or row.verdict != "quiet"
                or row.disposition != "accepted" or as_utc(row.observed_at) <= item.quiet_after):
                raise ValueError("Retained replacement quiet receipt lineage is invalid")
            historical_source_receipt(db, source, request, row)
        if ordered[0].alert_id != item.current_alert_id:
            raise ValueError("Retained replacement current Alert pointer differs from its quiet receipt")
        if item.current_alert_id:
            for actor in actors: require_alert_access(db, actor, item.current_alert_id)
        for member in item.members:
            pin = members.get(member.alert_id)
            if pin is None or member.alert_id in covered:
                raise ValueError("Retained replacement member is unavailable or repeated")
            covered.add(member.alert_id)
            active_source = _row(db, CollectorConditionSource, member.active_source_id)
            active_review = _row(db, CollectorSourceQualificationReview, member.qualification_review_id)
            active_request = _row(db, CollectorSourceQualificationRequest, active_review.request_id)
            active = _row(db, CollectorConditionReceipt, member.active_receipt_id)
            if (active_request.source_id != active_source.id or active_request.id != member.qualification_request_id
                or active.source_id != active_source.id or active.alert_id != member.alert_id
                or active.verdict != "active" or active.disposition != "accepted"
                or active_source.dedup_key != pin.dedup_key
                or (active_source.context["definition"]["event_type"], active_source.entity_type, active_source.entity_id)
                    != (pin.event_type, pin.entity_type, pin.entity_id)):
                raise ValueError("Retained historical active receipt provenance is invalid")
            historical_source_receipt(db, active_source, active_request, active)
            floor = max(as_utc(active.observed_at), pin.last_seen)
            if member.retirement_id is None:
                if (active_source.id != source.id or member.qualification_review_id != accepted.id
                    or pin.status != "resolved" or pin.source_retirement_id is not None):
                    raise ValueError("Retained direct recovery cannot manufacture replacement provenance")
            else:
                mapping = replacements.get(active_source.id)
                if (mapping is None or mapping.retirement.id != member.retirement_id
                    or mapping.request.id != member.replacement_request_id or mapping.review.id != member.replacement_review_id
                    or mapping.target.id != source.id
                    or mapping.request.old_qualification_review_id != active_review.id):
                    raise ValueError("Retained recovery replacement is outside its exact policy binding")
                cutoff = as_utc(datetime.fromisoformat(mapping.retirement.old_state_snapshot["admitted_through_at"]))
                if floor > cutoff:
                    raise ValueError("Retained active member exceeds its permanent retirement watermark")
                floor = max(floor, cutoff)
                if pin.status == "resolved":
                    if pin.source_retirement_id is not None:
                        raise ValueError("Retained measured resolution cannot fake supersession")
                elif (pin.source_retirement_id != mapping.retirement.id
                    or member.alert_id != mapping.retirement.superseded_alert_id):
                    raise ValueError("Retained active member lacks exact permanent supersession")
            if item.quiet_after < floor:
                raise ValueError("Retained quiet window borrows evidence before an old member clock")
            for actor in actors:
                require_source_access(db, active_source, actor)
                require_alert_access(db, actor, member.alert_id)
    if covered != set(members):
        raise ValueError("Retained replacement recovery does not cover complete frozen membership")
