from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..ai_schemas import AgentProfileCreate, AgentProfileUpdate
from ..models import (
    AIModelConfig,
    AIModelRoute,
    AIProviderConfig,
    AgentProfile,
    utcnow,
)
from .audit import record_audit_event


AGENT_PROFILE_CONTRACT = "icheck.agent-profile/v1"
DEFAULT_AGENT_PROFILE_NAME = "l1-operator"
PRIVACY_RANK = {"external": 0, "private": 1, "local": 2}
DEFAULT_AGENT_PROFILE: dict[str, Any] = {
    "name": DEFAULT_AGENT_PROFILE_NAME,
    "description": "Default bounded AI L1 infrastructure operator.",
    "role_instructions": (
        "Act as the L1 infrastructure operator. Diagnose from persisted evidence, "
        "prefer the least invasive eligible Tool, distinguish fact from hypothesis, "
        "and never claim success without verification."
    ),
    "escalation_instructions": (
        "Escalate when evidence is insufficient, scope or permissions are missing, "
        "the budget is exhausted, or a safe next diagnostic step is unavailable."
    ),
    "route_purpose": "investigation",
    "tool_policy": "permission_scoped",
    "allowed_tool_names": [],
    "minimum_provider_privacy": "external",
    "allowed_data_residencies": [],
    "allowed_model_cost_classes": ["low", "standard", "premium"],
    "max_iterations": 100,
    "max_tool_calls": 500,
    "timeout_seconds": 3600,
    "token_budget": 10_000_000,
    "enabled": True,
}


def ensure_default_agent_profiles(db: Session, *, commit: bool = True) -> None:
    existing = db.scalar(
        select(AgentProfile).where(AgentProfile.name == DEFAULT_AGENT_PROFILE_NAME)
    )
    if existing is not None:
        return
    db.add(
        AgentProfile(
            **DEFAULT_AGENT_PROFILE,
            revision=1,
            created_by="system.bootstrap",
            updated_by="system.bootstrap",
            update_reason="Built-in bounded L1 AgentProfile.",
        )
    )
    if commit:
        db.commit()


def list_agent_profiles(db: Session) -> list[AgentProfile]:
    return list(db.scalars(select(AgentProfile).order_by(AgentProfile.name)).all())


def get_agent_profile(
    db: Session,
    reference: str,
    *,
    lock: bool = False,
) -> AgentProfile:
    query = select(AgentProfile).where(
        or_(AgentProfile.id == reference, AgentProfile.name == reference)
    )
    if lock:
        query = query.with_for_update()
    profile = db.scalar(query)
    if profile is None:
        raise LookupError("AgentProfile not found")
    return profile


def agent_profile_snapshot(profile: AgentProfile) -> dict[str, Any]:
    return {
        "contract": AGENT_PROFILE_CONTRACT,
        "profile_id": profile.id,
        "revision": profile.revision,
        "name": profile.name,
        "description": profile.description,
        "role_instructions": profile.role_instructions,
        "escalation_instructions": profile.escalation_instructions,
        "route_purpose": profile.route_purpose,
        "tool_policy": profile.tool_policy,
        "allowed_tool_names": list(profile.allowed_tool_names or []),
        "minimum_provider_privacy": profile.minimum_provider_privacy,
        "allowed_data_residencies": list(
            profile.allowed_data_residencies or []
        ),
        "allowed_model_cost_classes": list(
            profile.allowed_model_cost_classes or []
        ),
        "max_iterations": profile.max_iterations,
        "max_tool_calls": profile.max_tool_calls,
        "timeout_seconds": profile.timeout_seconds,
        "token_budget": profile.token_budget,
        "enabled": profile.enabled,
    }


def _route_models(
    db: Session,
    route: AIModelRoute,
    *,
    candidate_model_ids: list[str] | None = None,
    require_enabled: bool = True,
) -> list[tuple[AIModelConfig, AIProviderConfig]]:
    pairs: list[tuple[AIModelConfig, AIProviderConfig]] = []
    model_ids = candidate_model_ids or [
        route.primary_model_id,
        *(route.fallback_model_ids or []),
    ]
    for model_id in model_ids:
        model = db.get(AIModelConfig, model_id)
        if model is None or (require_enabled and not model.enabled):
            raise ValueError(f"AgentProfile model {model_id!r} is unavailable")
        provider = db.get(AIProviderConfig, model.provider_id)
        if provider is None or (require_enabled and not provider.enabled):
            raise ValueError(
                f"AgentProfile model {model_id!r} has no enabled provider"
            )
        pairs.append((model, provider))
    return pairs


def assert_agent_profile_model_policy(
    db: Session,
    profile: AgentProfile,
    route: AIModelRoute,
    *,
    candidate_model_ids: list[str] | None = None,
    require_enabled: bool = True,
) -> None:
    required_privacy = PRIVACY_RANK.get(profile.minimum_provider_privacy)
    if required_privacy is None:
        raise ValueError("AgentProfile provider privacy policy is invalid")
    allowed_residencies = set(profile.allowed_data_residencies or [])
    allowed_costs = set(profile.allowed_model_cost_classes or [])
    if not allowed_costs:
        raise ValueError("AgentProfile must allow at least one model cost class")
    for model, provider in _route_models(
        db,
        route,
        candidate_model_ids=candidate_model_ids,
        require_enabled=require_enabled,
    ):
        actual_privacy = PRIVACY_RANK.get(provider.privacy_tier)
        if actual_privacy is None or actual_privacy < required_privacy:
            raise ValueError(
                f"AI provider {provider.name!r} does not meet AgentProfile "
                f"privacy tier {profile.minimum_provider_privacy!r}"
            )
        if (
            allowed_residencies
            and provider.data_residency not in allowed_residencies
        ):
            raise ValueError(
                f"AI provider {provider.name!r} data residency "
                f"{provider.data_residency!r} is not allowed by AgentProfile"
            )
        if model.cost_class not in allowed_costs:
            raise ValueError(
                f"AI model {model.display_name!r} cost class "
                f"{model.cost_class!r} is not allowed by AgentProfile"
            )


def resolve_investigation_agent_profile(
    db: Session,
    *,
    reference: str | None,
    route: AIModelRoute,
) -> AgentProfile | None:
    if reference:
        profile = get_agent_profile(db, reference)
    elif route.purpose == "investigation":
        profile = db.scalar(
            select(AgentProfile).where(
                AgentProfile.name == DEFAULT_AGENT_PROFILE_NAME
            )
        )
    else:
        profile = None
    if profile is None:
        return None
    if not profile.enabled:
        raise ValueError("AgentProfile is disabled")
    if profile.route_purpose != route.purpose:
        raise ValueError("AgentProfile does not match the requested AI route")
    assert_agent_profile_model_policy(db, profile, route)
    return profile


def assert_agent_profile_runtime_current(
    db: Session,
    snapshot: dict[str, Any],
    route: AIModelRoute,
    *,
    candidate_model_ids: list[str],
) -> AgentProfile | None:
    if not snapshot:
        return None
    profile_id = snapshot.get("profile_id")
    profile = db.get(AgentProfile, profile_id) if profile_id else None
    if profile is None or agent_profile_snapshot(profile) != snapshot:
        raise ValueError("Investigation AgentProfile has drifted")
    if not profile.enabled:
        raise ValueError("Investigation AgentProfile is disabled")
    assert_agent_profile_model_policy(
        db,
        profile,
        route,
        candidate_model_ids=candidate_model_ids,
        require_enabled=False,
    )
    return profile


def _validate_profile_route(db: Session, route_purpose: str) -> AIModelRoute:
    route = db.scalar(
        select(AIModelRoute).where(AIModelRoute.purpose == route_purpose)
    )
    if route is None or not route.enabled:
        raise ValueError("AgentProfile requires an enabled AI model route")
    return route


def create_agent_profile(
    db: Session,
    payload: AgentProfileCreate,
    *,
    actor: str,
) -> AgentProfile:
    route = _validate_profile_route(db, payload.route_purpose)
    profile = AgentProfile(
        **payload.model_dump(exclude={"created_by"}),
        revision=1,
        created_by=actor,
        updated_by=actor,
        update_reason="AgentProfile created.",
    )
    assert_agent_profile_model_policy(db, profile, route)
    db.add(profile)
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ai.agent_profile.created",
            actor_type="user",
            actor_id=actor,
            entity_type="agent_profile",
            entity_id=profile.id,
            details={"profile": agent_profile_snapshot(profile)},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AgentProfile name already exists") from exc
    db.refresh(profile)
    return profile


def update_agent_profile(
    db: Session,
    profile: AgentProfile,
    payload: AgentProfileUpdate,
    *,
    actor: str,
) -> AgentProfile:
    if profile.revision != payload.expected_revision:
        raise ValueError("AgentProfile revision is stale")
    previous = agent_profile_snapshot(profile)
    route = _validate_profile_route(db, payload.route_purpose)
    values = payload.model_dump(
        exclude={"expected_revision", "reason", "actor"}
    )
    for field, value in values.items():
        setattr(profile, field, value)
    assert_agent_profile_model_policy(db, profile, route)
    profile.revision += 1
    profile.updated_by = actor
    profile.update_reason = payload.reason
    profile.updated_at = utcnow()
    try:
        db.flush()
        record_audit_event(
            db,
            event_type="ai.agent_profile.updated",
            actor_type="user",
            actor_id=actor,
            entity_type="agent_profile",
            entity_id=profile.id,
            details={
                "previous": previous,
                "current": agent_profile_snapshot(profile),
                "reason": payload.reason,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("AgentProfile name already exists") from exc
    db.refresh(profile)
    return profile
