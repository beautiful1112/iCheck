"""Explicit current mappings for retired sources; no implicit generation alias."""
from dataclasses import dataclass

from sqlalchemy import select

from ..models import (CollectorConditionSource, CollectorSourceReplacementRequest,
    CollectorSourceReplacementReview, CollectorSourceReplacementRevocation, CollectorSourceRetirement, utcnow)
from ..situation_recovery_schemas import RecoveryReplacementBinding, RecoverySourceBinding
from .alert_conditions import as_utc
from .collector_conditions import canonical
from .control_plane_auth import PrincipalContext
from .source_qualifications import _row, _human
from .source_replacements import MANAGE, REVIEW, _authority, _material, _namespace_query, _scope


@dataclass(frozen=True)
class ReplacementReference:
    binding: RecoveryReplacementBinding
    retirement: CollectorSourceRetirement
    request: CollectorSourceReplacementRequest
    review: CollectorSourceReplacementReview
    old: CollectorConditionSource
    target: CollectorConditionSource
    cutover_target: CollectorConditionSource


def replacement_bindings(policy):
    values = [RecoveryReplacementBinding.model_validate(value) for value in policy.replacement_bindings]
    if (policy.proof_version == 2) != bool(values) or len(values) > 64:
        raise ValueError("Recovery replacement proof version or binding bound is invalid")
    if len({item.old_source_id for item in values}) != len(values) or len({item.retirement_id for item in values}) != len(values):
        raise ValueError("Recovery replacement bindings repeat historical authority")
    return sorted(values, key=lambda item: item.old_source_id)


def replacement_references(db, policy):
    bindings = [RecoverySourceBinding.model_validate(value) for value in policy.source_bindings]
    current = {item.source_id: item.qualification_review_id for item in bindings}
    references = []
    for binding in replacement_bindings(policy):
        retirement = _row(db, CollectorSourceRetirement, binding.retirement_id)
        review = _row(db, CollectorSourceReplacementReview, binding.replacement_review_id)
        request = _row(db, CollectorSourceReplacementRequest, review.request_id)
        if (retirement.old_source_id != binding.old_source_id or request.old_source_id != binding.old_source_id
            or binding.old_source_id in current or current.get(request.new_source_id) != request.new_qualification_review_id):
            raise ValueError("Recovery mapping does not bind its retired source and exact current qualification")
        applied = (request.id == retirement.request_id and review.id == retirement.review_id
            and request.prior_retirement_id is None and request.new_source_id == retirement.new_source_id)
        revalidated = request.prior_retirement_id == retirement.id
        if not (applied or revalidated):
            raise ValueError("Recovery mapping requires completed original retirement or explicit historical revalidation")
        references.append(ReplacementReference(binding, retirement, request, review,
            _row(db, CollectorConditionSource, request.old_source_id),
            _row(db, CollectorConditionSource, request.new_source_id),
            _row(db, CollectorConditionSource, retirement.new_source_id)))
    return references


def reference_sources(sources, references):
    result = {source.id: source for source in sources}
    for item in references:
        for source in (item.old, item.target, item.cutover_target):
            result[source.id] = source
    return [result[key] for key in sorted(result)]


def require_replacement_scope(db, references, *actors):
    from .source_retirements import retirement_reference_scope
    for item in references:
        for actor in actors:
            _scope(db, [item.old, item.target, item.cutover_target], actor)
        retirement_reference_scope(db, item.retirement, *actors)


def current_replacement(db, item, policy):
    """Validate every mapping even when current membership does not use it."""
    request, review = item.request, item.review
    if (as_utc(request.expires_at) <= utcnow() or as_utc(policy.expires_at) > as_utc(request.expires_at)
        or request.evidence_environment != policy.evidence_environment
        or db.scalar(_namespace_query(db, CollectorSourceReplacementRevocation).where(
            CollectorSourceReplacementRevocation.review_id == review.id))):
        raise ValueError("Recovery mapping expired, was revoked or is outlived by its policy")
    material = _material(db, request, (item.old, item.target), applied_retirement=item.retirement, nonblocking_authority=True)
    if canonical(material) != canonical(request.snapshot["material"]):
        raise ValueError("Recovery mapping exact accepted material changed")
    frozen = request.snapshot["initiating_authority"]
    author = PrincipalContext(principal_id=request.author_principal_id, subject=request.author_subject,
        principal_type="user", permissions=frozenset(frozen["permissions"]), role_names=(), authorization_scope=frozen["scope"],
        auth_method="retained_mapping_author", tenant_id=request.tenant_id, region_id=request.region_id)
    _authority(db, [item.old, item.target], author, MANAGE, nowait=True)
    peer = _human(db, review.reviewer_principal_id, review.reviewer_subject, REVIEW, material_access_required=True, nowait=True)
    _scope(db, [item.old, item.target], peer)
    if peer.principal_id == request.author_principal_id or peer.subject == request.author_subject:
        raise ValueError("Recovery mapping reviewer is not independent")
    return as_utc(request.expires_at)
