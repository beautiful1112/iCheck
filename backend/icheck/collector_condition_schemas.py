"""Protocol-neutral condition definitions and strictly typed measurements."""
from __future__ import annotations

import math
from typing import Any, Literal

from pydantic import ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator, model_validator

from .models import AlertSeverity
from .schemas import APIModel

COLLECTOR_CONDITION_V1 = "icheck.collector.condition/v1"
Scalar = StrictBool | StrictInt | StrictFloat | StrictStr


class ConditionModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


def bounded_scalar(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Condition measurements must be finite")
    if isinstance(value, str) and len(value) > 255:
        raise ValueError("Condition strings cannot exceed 255 characters")
    if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 256:
        raise ValueError("Condition integers cannot exceed 256 bits")
    return value


class CollectorConditionDefinition(ConditionModel):
    key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    event_type: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    entity_type: Literal["device", "endpoint", "knowledge_entity", "external"]
    title: str = Field(min_length=1, max_length=255)
    severity: AlertSeverity = AlertSeverity.WARNING
    operator: Literal["lt", "lte", "gt", "gte", "eq", "ne"]
    expected: Scalar
    unit: str | None = Field(default=None, max_length=64)
    max_age_seconds: int = Field(default=300, ge=1, le=86400, strict=True)

    @field_validator("expected")
    @classmethod
    def valid_expected(cls, value: Scalar) -> Scalar:
        return bounded_scalar(value)

    @model_validator(mode="after")
    def ordered_numbers(self) -> "CollectorConditionDefinition":
        if self.operator in {"lt", "lte", "gt", "gte"} and (
            isinstance(self.expected, bool) or not isinstance(self.expected, (int, float))
        ):
            raise ValueError("Ordered condition predicates require a numeric expected value")
        return self


class CollectorConditionObservation(ConditionModel):
    condition_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    entity_id: str | None = Field(default=None, min_length=1, max_length=255)
    value: Scalar | None = None
    quality: Literal["valid", "unknown"] = "valid"

    @field_validator("value")
    @classmethod
    def valid_value(cls, value: Scalar | None) -> Scalar | None:
        return bounded_scalar(value)


def condition_definitions(definition: dict[str, Any]) -> list[CollectorConditionDefinition]:
    items = definition.get("condition_contracts", [])
    if not isinstance(items, list) or len(items) > 64:
        raise ValueError("Collector condition_contracts must be a list of at most 64 definitions")
    result = [CollectorConditionDefinition.model_validate(item) for item in items]
    if len({item.key for item in result}) != len(result):
        raise ValueError("Collector condition keys must be unique within an immutable version")
    return result


def evaluate_condition(definition: CollectorConditionDefinition, observation: CollectorConditionObservation) -> bool | None:
    if observation.quality != "valid" or observation.value is None:
        return None
    value, expected = observation.value, definition.expected
    if isinstance(expected, bool):
        compatible = isinstance(value, bool)
    elif isinstance(expected, (int, float)):
        compatible = isinstance(value, (int, float)) and not isinstance(value, bool)
    else:
        compatible = isinstance(value, str)
    if not compatible:
        return None
    if definition.operator == "lt":
        return value < expected
    if definition.operator == "lte":
        return value <= expected
    if definition.operator == "gt":
        return value > expected
    if definition.operator == "gte":
        return value >= expected
    if definition.operator == "eq":
        return value == expected
    return value != expected
