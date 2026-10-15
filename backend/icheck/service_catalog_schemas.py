from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from .schemas import APIModel


ServiceCriticality = Literal["tier_0", "tier_1", "tier_2", "tier_3"]
BusinessImpact = Literal["critical", "high", "moderate", "low"]
ServiceStatus = Literal["active", "retired"]
ServiceNodeType = Literal["device", "endpoint", "knowledge_entity"]
ServiceComponentRole = Literal[
    "entrypoint", "dependency", "compute", "data", "network", "other"
]
ServiceDependencyType = Literal[
    "synchronous", "asynchronous", "data", "shared_infrastructure"
]


class ServiceCatalogAPIModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ServiceComponentCreate(ServiceCatalogAPIModel):
    node_type: ServiceNodeType
    entity_id: str = Field(min_length=1, max_length=36)
    role: ServiceComponentRole = "dependency"
    required: bool = True
    evidence_note: str = Field(default="", max_length=4000)


class ServiceCreate(ServiceCatalogAPIModel):
    service_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10_000)
    owner_team: str = Field(min_length=1, max_length=255)
    owner_contact: str | None = Field(default=None, max_length=512)
    criticality: ServiceCriticality
    business_impact: BusinessImpact
    business_impact_summary: str = Field(default="", max_length=10_000)
    slo_target_percent: float | None = Field(default=None, ge=0, le=100)
    recovery_time_objective_minutes: int | None = Field(
        default=None, ge=0, le=5_256_000
    )
    recovery_point_objective_minutes: int | None = Field(
        default=None, ge=0, le=5_256_000
    )
    tags: dict[str, str] = Field(default_factory=dict)
    components: list[ServiceComponentCreate] = Field(min_length=1, max_length=200)
    created_by: str = Field(min_length=1, max_length=255)

    @field_validator("tags")
    @classmethod
    def bounded_tags(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 100:
            raise ValueError("tags cannot contain more than 100 entries")
        if any(len(key) > 128 or len(item) > 512 for key, item in value.items()):
            raise ValueError("tag key or value is too long")
        return value

    @field_validator("components")
    @classmethod
    def unique_components(
        cls, value: list[ServiceComponentCreate]
    ) -> list[ServiceComponentCreate]:
        identities = {(item.node_type, item.entity_id) for item in value}
        if len(identities) != len(value):
            raise ValueError("service components must be unique")
        return value


class ServiceUpdate(ServiceCatalogAPIModel):
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    owner_team: str | None = Field(default=None, min_length=1, max_length=255)
    owner_contact: str | None = Field(default=None, max_length=512)
    criticality: ServiceCriticality | None = None
    business_impact: BusinessImpact | None = None
    business_impact_summary: str | None = Field(default=None, max_length=10_000)
    slo_target_percent: float | None = Field(default=None, ge=0, le=100)
    recovery_time_objective_minutes: int | None = Field(
        default=None, ge=0, le=5_256_000
    )
    recovery_point_objective_minutes: int | None = Field(
        default=None, ge=0, le=5_256_000
    )
    status: ServiceStatus | None = None
    tags: dict[str, str] | None = None
    actor: str = Field(min_length=1, max_length=255)

    @field_validator("tags")
    @classmethod
    def bounded_tags(
        cls, value: dict[str, str] | None
    ) -> dict[str, str] | None:
        if value is None:
            return value
        if len(value) > 100:
            raise ValueError("tags cannot contain more than 100 entries")
        if any(len(key) > 128 or len(item) > 512 for key, item in value.items()):
            raise ValueError("tag key or value is too long")
        return value


class ServiceComponentRead(ServiceCatalogAPIModel):
    id: str
    node_id: str
    node_type: ServiceNodeType
    entity_id: str
    display_name: str
    site: str | None
    available: bool
    role: ServiceComponentRole
    required: bool
    evidence_note: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class ServiceRead(ServiceCatalogAPIModel):
    id: str
    service_key: str
    name: str
    description: str
    owner_team: str
    owner_contact: str | None
    criticality: ServiceCriticality
    business_impact: BusinessImpact
    business_impact_summary: str
    slo_target_percent: float | None
    recovery_time_objective_minutes: int | None
    recovery_point_objective_minutes: int | None
    status: ServiceStatus
    tags: dict[str, str]
    revision: int
    components: list[ServiceComponentRead]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ServiceComponentAction(ServiceCatalogAPIModel):
    actor: str = Field(min_length=1, max_length=255)


class ServiceDependencyCreate(ServiceCatalogAPIModel):
    expected_revision: int = Field(ge=1)
    target_service_id: str = Field(min_length=1, max_length=36)
    dependency_type: ServiceDependencyType
    critical: bool = True
    evidence_note: str = Field(min_length=3, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


class ServiceDependencyAction(ServiceCatalogAPIModel):
    expected_revision: int = Field(ge=1)
    actor: str = Field(min_length=1, max_length=255)


class ServiceDependencyRead(ServiceCatalogAPIModel):
    id: str
    source_service_id: str
    source_service_key: str
    source_service_name: str
    target_service_id: str
    target_service_key: str
    target_service_name: str
    dependency_type: ServiceDependencyType
    critical: bool
    evidence_note: str
    created_by: str
    created_at: datetime
    updated_at: datetime
