from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Literal, Union
from uuid import UUID

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator, model_serializer

from .agent_schemas import AgentChangeContract
from .schemas import APIModel
from .collector_condition_schemas import CollectorConditionDefinition, COLLECTOR_CONDITION_V1, Scalar, bounded_scalar
from .projection_schemas import PROJECTION_CONTRACT_MODELS
from .http_metrics import HTTPMetric


COLLECTOR_SOURCE_PATH = r"^[A-Za-z][A-Za-z0-9_-]*(?:\.(?:[A-Za-z][A-Za-z0-9_-]*|[0-9]+))*$"
COLLECTOR_DESTINATION_PATH = r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)*$"
MAX_COLLECTOR_MAPPING_NODES = 128
MAX_COLLECTOR_ARRAY_DEPTH = 8
MAX_COLLECTOR_ARRAY_ITEMS = 10000


class StudioStrictModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class CollectorFieldMapping(StudioStrictModel):
    source_field: str = Field(
        min_length=1,
        max_length=128,
        pattern=COLLECTOR_SOURCE_PATH,
    )
    destination_field: str = Field(
        min_length=1,
        max_length=128,
        pattern=COLLECTOR_DESTINATION_PATH,
    )


class CollectorConstantMapping(StudioStrictModel):
    """A bounded literal is compiled as data, never as executable source."""
    constant: Scalar | None
    destination_field: str = Field(min_length=1, max_length=128, pattern=COLLECTOR_DESTINATION_PATH)

    @field_validator("constant")
    @classmethod
    def bounded_constant(cls, value):
        return bounded_scalar(value)


def _unique_mapping_destinations(value: list[Any]) -> list[Any]:
    destinations = [item.destination_field for item in value]
    if len(destinations) != len(set(destinations)):
        raise ValueError("field mapping destinations must be unique")
    for index, destination in enumerate(destinations):
        if len(destination.split(".")) > 8:
            raise ValueError("field mapping destinations cannot exceed eight levels")
        for other in destinations[index + 1:]:
            if destination.startswith(other + ".") or other.startswith(destination + "."):
                raise ValueError("field mapping destinations cannot overlap parent and child paths")
    return value


class CollectorArrayMapping(StudioStrictModel):
    """Cardinality-preserving data mapping, never a filter or executable loop."""

    source_field: str = Field(min_length=1, max_length=128, pattern=COLLECTOR_SOURCE_PATH)
    destination_field: str = Field(min_length=1, max_length=128, pattern=COLLECTOR_DESTINATION_PATH)
    item_field: str | None = Field(default=None, min_length=1, max_length=128, pattern=COLLECTOR_SOURCE_PATH)
    item_mappings: list[Union[CollectorFieldMapping, CollectorConstantMapping, "CollectorArrayMapping"]] | None = Field(
        default=None, min_length=1, max_length=64
    )
    max_items: int = Field(default=2000, ge=1, le=MAX_COLLECTOR_ARRAY_ITEMS, strict=True)
    accept_single_object: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def exactly_one_item_shape(self) -> "CollectorArrayMapping":
        if (self.item_field is None) == (self.item_mappings is None):
            raise ValueError("Array mappings require exactly one of item_field or item_mappings")
        if self.item_mappings is not None:
            _unique_mapping_destinations(self.item_mappings)
        return self


CollectorArrayMapping.model_rebuild()
CollectorMapping = CollectorFieldMapping | CollectorConstantMapping | CollectorArrayMapping


class GeneratedCollectorSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    records_path: str | None = Field(
        default=None,
        max_length=512,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    record_type: str = Field(
        min_length=1,
        max_length=128,
    )
    source: str = Field(min_length=1, max_length=255)
    subject_field: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    idempotency_field: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    observed_at_field: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=COLLECTOR_SOURCE_PATH
    )
    preserve_unmapped_fields: bool = True
    field_mappings: list[CollectorMapping] = Field(
        min_length=1,
        max_length=64,
    )
    condition_contracts: list[CollectorConditionDefinition] = Field(default_factory=list, max_length=64)

    @model_serializer(mode="wrap")
    def serialize_optional_conditions(self, handler):
        result = handler(self)
        if not self.condition_contracts:
            result.pop("condition_contracts", None)
        if self.observed_at_field is None:
            result.pop("observed_at_field", None)
        return result

    @field_validator("record_type")
    @classmethod
    def registered_or_custom_record_type(cls, value: str) -> str:
        if value in PROJECTION_CONTRACT_MODELS or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value):
            return value
        raise ValueError("Versioned record_type must be a registered projection contract; custom dotted names are raw-only")

    @model_validator(mode="after")
    def condition_record_contract(self) -> "GeneratedCollectorSpec":
        if self.condition_contracts:
            if self.record_type != COLLECTOR_CONDITION_V1:
                raise ValueError("Condition definitions require the collector condition record_type")
            if len({item.key for item in self.condition_contracts}) != len(self.condition_contracts):
                raise ValueError("Generated collector condition keys must be unique")
        elif self.record_type == COLLECTOR_CONDITION_V1:
            raise ValueError("Condition record_type requires declared condition_contracts")
        return self

    @field_validator("field_mappings")
    @classmethod
    def unique_destination_fields(
        cls, value: list[CollectorMapping]
    ) -> list[CollectorMapping]:
        _unique_mapping_destinations(value)
        pending = [(mapping, 0) for mapping in value]
        nodes = 0
        while pending:
            mapping, depth = pending.pop()
            nodes += 1
            if nodes > MAX_COLLECTOR_MAPPING_NODES:
                raise ValueError("Collector mappings cannot exceed 128 total operations")
            if isinstance(mapping, CollectorArrayMapping):
                if depth >= MAX_COLLECTOR_ARRAY_DEPTH:
                    raise ValueError("Collector array mappings cannot exceed eight nested levels")
                pending.extend((child, depth + 1) for child in mapping.item_mappings or [])
        return value


class WorkflowTrigger(StudioStrictModel):
    trigger_type: Literal["manual", "alert", "schedule", "situation"] = "manual"
    event_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )

    @model_validator(mode="after")
    def validate_trigger(self) -> "WorkflowTrigger":
        if self.trigger_type in {"alert", "situation"} and not self.event_type:
            raise ValueError(f"{self.trigger_type} triggers require event_type")
        if self.trigger_type in {"manual", "schedule"} and self.event_type:
            raise ValueError(
                f"{self.trigger_type} triggers cannot declare event_type"
            )
        return self


class WorkflowInputBinding(StudioStrictModel):
    argument: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z][A-Za-z0-9_-]*$",
    )
    input_path: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )


def _workflow_node_json_schema(schema: dict[str, Any]) -> None:
    """Expose local node-shape rules to structured-output providers.

    Keep the stored/runtime model unchanged. Complete anyOf object variants use
    the same field definitions, including their length/pattern bounds and refs.
    Cross-node reachability and tool authorization still require local checks.
    """
    base = deepcopy(schema)
    variants = []
    for node_types in (
        ["tool", "post_check", "rollback"], ["agent_loop"], ["approval"], ["end"],
    ):
        variant = deepcopy(base)
        properties = variant["properties"]
        properties["node_type"] = {"type": "string", "enum": node_types}
        required = list(variant.get("required", []))

        def require_non_null(name: str) -> None:
            field = properties[name]
            choices = field.pop("anyOf")
            field.update(next(choice for choice in choices if choice.get("type") != "null"))
            field.pop("default", None)
            required.append(name)

        def null_only(name: str) -> None:
            properties[name] = {"type": "null", "default": None}

        if node_types[0] in {"tool", "post_check", "rollback"}:
            require_non_null("tool_name")
        else:
            null_only("tool_name")
        if node_types == ["agent_loop"]:
            require_non_null("objective")
            require_non_null("max_iterations")
            properties["allowed_tools"]["minItems"] = 1
            required.append("allowed_tools")
        else:
            null_only("max_iterations")
            properties["allowed_tools"]["maxItems"] = 0
        if node_types == ["end"]:
            for name in ("objective", "on_success", "on_failure", "rollback_node_id"):
                null_only(name)
            properties["input_bindings"]["maxItems"] = 0
            properties["requires_approval"] = {"type": "boolean", "enum": [False], "default": False}
        else:
            require_non_null("on_success")
        variant["required"] = required
        variants.append(variant)
    schema.clear()
    schema.update({"title": base.get("title", "WorkflowNode"), "anyOf": variants})


class WorkflowNode(StudioStrictModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid", json_schema_extra=_workflow_node_json_schema)

    node_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    title: str = Field(min_length=1, max_length=255)
    node_type: Literal[
        "tool",
        "agent_loop",
        "approval",
        "post_check",
        "rollback",
        "end",
    ]
    tool_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    objective: str | None = Field(default=None, min_length=1, max_length=4000)
    input_bindings: list[WorkflowInputBinding] = Field(
        default_factory=list,
        max_length=64,
    )
    allowed_tools: list[str] = Field(default_factory=list, max_length=32)
    on_success: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    on_failure: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    requires_approval: bool = False
    rollback_node_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    max_iterations: int | None = Field(default=None, ge=1, le=25)

    @field_validator("input_bindings")
    @classmethod
    def unique_workflow_arguments(
        cls,
        value: list[WorkflowInputBinding],
    ) -> list[WorkflowInputBinding]:
        arguments = [item.argument for item in value]
        if len(arguments) != len(set(arguments)):
            raise ValueError("workflow input binding arguments must be unique")
        return value

    @field_validator("allowed_tools")
    @classmethod
    def unique_allowed_tools(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 255 for item in normalized):
            raise ValueError("allowed tool names must not exceed 255 characters")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_node_shape(self) -> "WorkflowNode":
        direct_tool_types = {"tool", "post_check", "rollback"}
        if self.node_type in direct_tool_types and not self.tool_name:
            raise ValueError(f"{self.node_type} nodes require tool_name")
        if self.node_type not in direct_tool_types and self.tool_name:
            raise ValueError(f"{self.node_type} nodes cannot declare tool_name")
        if self.node_type == "agent_loop":
            if not self.objective or not self.max_iterations:
                raise ValueError(
                    "agent_loop nodes require objective and max_iterations"
                )
            if not self.allowed_tools:
                raise ValueError("agent_loop nodes require allowed_tools")
        elif self.allowed_tools or self.max_iterations:
            raise ValueError(
                "allowed_tools and max_iterations are only valid for agent_loop"
            )
        if self.node_type == "end" and any(
            [
                self.on_success,
                self.on_failure,
                self.rollback_node_id,
                self.input_bindings,
                self.objective,
                self.requires_approval,
            ]
        ):
            raise ValueError("end nodes cannot declare execution or transition fields")
        if self.node_type != "end" and not self.on_success:
            raise ValueError("non-end workflow nodes require on_success")
        return self


class GeneratedWorkflowSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    trigger: WorkflowTrigger = Field(default_factory=WorkflowTrigger)
    input_schema: dict[str, Any]
    start_node: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    nodes: list[WorkflowNode] = Field(min_length=2, max_length=64)
    max_runtime_seconds: int = Field(default=300, ge=1, le=3600)
    max_total_tool_calls: int = Field(default=20, ge=1, le=500)
    max_total_tokens: int = Field(default=50_000, ge=1, le=10_000_000)

    @field_validator("nodes")
    @classmethod
    def unique_node_ids(cls, value: list[WorkflowNode]) -> list[WorkflowNode]:
        node_ids = [item.node_id for item in value]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("workflow node IDs must be unique")
        return value


class GeneratedTopologySpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    node_types: list[Literal["device", "endpoint", "knowledge_entity"]] = Field(
        min_length=1,
        max_length=3,
    )
    edge_types: list[
        Literal[
            "wired_attachment",
            "wireless_association",
            "ip_observation",
            "knowledge_relationship",
        ]
    ] = Field(default_factory=list, max_length=4)
    device_kinds: list[str] = Field(default_factory=list, max_length=32)
    knowledge_entity_types: list[str] = Field(default_factory=list, max_length=64)
    knowledge_relationship_types: list[str] = Field(
        default_factory=list,
        max_length=64,
    )
    sites: list[str] = Field(default_factory=list, max_length=64)
    enabled_devices_only: bool = True
    active_entities_only: bool = True
    active_edges_only: bool = True
    layout: Literal["force", "hierarchical", "radial"] = "force"
    group_by: Literal["none", "site", "kind"] = "none"
    max_nodes: int = Field(default=100, ge=10, le=500)
    max_edges: int = Field(default=250, ge=10, le=1000)

    @field_validator(
        "node_types",
        "edge_types",
        "device_kinds",
        "knowledge_entity_types",
        "knowledge_relationship_types",
        "sites",
    )
    @classmethod
    def unique_topology_values(cls, value: list[Any]) -> list[Any]:
        normalized = [
            item.strip() if isinstance(item, str) else item
            for item in value
            if not isinstance(item, str) or item.strip()
        ]
        if any(isinstance(item, str) and len(item) > 128 for item in normalized):
            raise ValueError("topology selector values must not exceed 128 characters")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_topology_shape(self) -> "GeneratedTopologySpec":
        endpoint_edges = {
            "wired_attachment",
            "wireless_association",
            "ip_observation",
        }
        if endpoint_edges.intersection(self.edge_types) and not {
            "device",
            "endpoint",
        }.issubset(self.node_types):
            raise ValueError(
                "endpoint relationship edges require device and endpoint nodes"
            )
        if (
            "knowledge_relationship" in self.edge_types
            and "knowledge_entity" not in self.node_types
        ):
            raise ValueError(
                "knowledge relationship edges require knowledge entity nodes"
            )
        if self.device_kinds and "device" not in self.node_types:
            raise ValueError("device filters require device nodes")
        if (
            self.knowledge_entity_types
            or self.knowledge_relationship_types
        ) and "knowledge_entity" not in self.node_types:
            raise ValueError(
                "knowledge type filters require knowledge entity nodes"
            )
        if self.knowledge_relationship_types and (
            "knowledge_relationship" not in self.edge_types
        ):
            raise ValueError(
                "knowledge relationship type filters require knowledge edges"
            )
        if self.sites and not {"device", "knowledge_entity"}.intersection(
            self.node_types
        ):
            raise ValueError("site filters require device or knowledge nodes")
        return self


class VisualizationPanel(StudioStrictModel):
    panel_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    title: str = Field(min_length=1, max_length=255)
    chart_type: Literal["line", "stat", "status"] = "line"
    service_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    indicator_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    show_thresholds: bool = True
    max_points: int = Field(default=120, ge=1, le=500)


class GeneratedVisualizationSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    layout_columns: int = Field(default=2, ge=1, le=4)
    refresh_seconds: int = Field(default=60, ge=15, le=3600)
    lookback_minutes: int = Field(default=360, ge=5, le=10_080)
    panels: list[VisualizationPanel] = Field(min_length=1, max_length=12)

    @field_validator("panels")
    @classmethod
    def unique_visualization_panels(
        cls,
        value: list[VisualizationPanel],
    ) -> list[VisualizationPanel]:
        panel_keys = [item.panel_key for item in value]
        if len(panel_keys) != len(set(panel_keys)):
            raise ValueError("visualization panel keys must be unique")
        selectors = [
            (item.service_key, item.indicator_key)
            for item in value
        ]
        if len(selectors) != len(set(selectors)):
            raise ValueError(
                "a visualization can select each service indicator only once"
            )
        return value


class ReportIndicator(StudioStrictModel):
    section_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    title: str = Field(min_length=1, max_length=255)
    service_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    indicator_key: str = Field(
        min_length=2,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )


class GeneratedServiceReportSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    report_title: str = Field(min_length=1, max_length=255)
    lookback_minutes: int = Field(default=1440, ge=5, le=10_080)
    max_samples_per_indicator: int = Field(default=500, ge=1, le=500)
    include_thresholds: bool = True
    indicators: list[ReportIndicator] = Field(min_length=1, max_length=20)

    @field_validator("indicators")
    @classmethod
    def unique_report_indicators(
        cls,
        value: list[ReportIndicator],
    ) -> list[ReportIndicator]:
        section_keys = [item.section_key for item in value]
        if len(section_keys) != len(set(section_keys)):
            raise ValueError("report section keys must be unique")
        selectors = [
            (item.service_key, item.indicator_key) for item in value
        ]
        if len(selectors) != len(set(selectors)):
            raise ValueError(
                "a report can select each service indicator only once"
            )
        return value


class ReportRetainedProofReference(StudioStrictModel):
    reference_kind: Literal["source_replacement_request", "source_retirement", "situation_closure_receipt"]
    reference_id: UUID


class ReportRetainedProofSelector(ReportRetainedProofReference):
    section_key: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_-]*$")
    title: str = Field(min_length=1, max_length=255)


class GeneratedRetainedProofReportSpec(GeneratedServiceReportSpec):
    proof_contract_version: Literal[2] = 2
    # v2 uses the existing governed visualization engine's 12-panel budget.
    # Proof-only reports may use all 20 section slots; v1 is not reinterpreted.
    indicators: list[ReportIndicator] = Field(default_factory=list, max_length=12)
    retained_proofs: list[ReportRetainedProofSelector] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def unique_proof_sections(self):
        keys = [item.section_key for item in self.indicators] + [item.section_key for item in self.retained_proofs]
        refs = [(item.reference_kind, item.reference_id) for item in self.retained_proofs]
        if len(keys) > 20 or len(keys) != len(set(keys)) or len(refs) != len(set(refs)):
            raise ValueError("Report sections and retained references must be unique, with at most 20 sections")
        return self


class ToolFixture(StudioStrictModel):
    name: str = Field(min_length=1, max_length=255)
    arguments: dict[str, Any]
    expected_output: dict[str, Any]


class IndependentVerificationBinding(StudioStrictModel):
    original_argument_path: str = Field(
        min_length=1, max_length=255,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$",
    )
    observed_value_key: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    value_type: Literal["string", "boolean", "integer", "number"]

    @model_validator(mode="after")
    def forbid_secret_bindings(self) -> "IndependentVerificationBinding":
        sensitive = ("auth", "community", "credential", "key", "passphrase",
                     "password", "private", "secret", "token")
        if any(term in part.lower() for part in self.original_argument_path.split(".") for term in sensitive):
            raise ValueError("Independent verification cannot expose a credential argument")
        if any(term in self.observed_value_key.lower() for term in sensitive):
            raise ValueError("Independent verification cannot expose a credential value")
        return self


class IndependentVerificationContract(StudioStrictModel):
    tool_name: str = Field(
        min_length=1, max_length=255, pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    kind: Literal["target_state", "recipient_receipt"]
    max_age_seconds: int = Field(default=300, ge=60, le=3600, strict=True)
    bindings: list[IndependentVerificationBinding] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def require_unique_target_identity(self) -> "IndependentVerificationContract":
        paths = [item.original_argument_path for item in self.bindings]
        keys = [item.observed_value_key for item in self.bindings]
        if len(paths) != len(set(paths)) or len(keys) != len(set(keys)):
            raise ValueError("Independent verification bindings must be one-to-one")
        if self.kind == "recipient_receipt" and not {"recipient_id", "document_digest"}.issubset(keys):
            raise ValueError("Recipient receipt verification requires recipient and document bindings")
        return self


class OutcomeLookupCorrelationContract(StudioStrictModel):
    """Frozen provider correlation expectation, never live conformance proof."""

    tool_name: str = Field(
        min_length=1, max_length=255, pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    operation_key_transport: Literal["mcp_tools_call_meta"] = "mcp_tools_call_meta"
    operation_key_name: Literal["icheck/toolCallId"] = "icheck/toolCallId"
    lookup_argument_name: Literal["source_tool_call_id"] = "source_tool_call_id"
    lookup_result_name: Literal["source_tool_call_id"] = "source_tool_call_id"
    consistency_window_seconds: int = Field(ge=60, le=86400, strict=True)
    max_observation_age_seconds: int = Field(ge=60, le=3600, strict=True)


class GeneratedToolSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    tool_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    transport: Literal["mcp"] = "mcp"
    mcp_server_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    mcp_tool_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: Literal["observe", "diagnose", "change"] = "observe"
    read_only: bool = True
    requires_approval: bool = False
    change_contract: AgentChangeContract | None = None
    outcome_lookup_tool_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    outcome_lookup_correlation: OutcomeLookupCorrelationContract | None = None
    independent_verification: IndependentVerificationContract | None = None
    required_permissions: list[str] = Field(default_factory=list, max_length=32)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_result_bytes: int = Field(default=1_000_000, ge=1024, le=10_000_000)
    fixtures: list[ToolFixture] = Field(min_length=1, max_length=10)

    @field_validator("required_permissions")
    @classmethod
    def normalize_tool_permissions(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 128 for item in normalized):
            raise ValueError("tool permissions must not exceed 128 characters")
        return list(dict.fromkeys(normalized))

    @field_validator("fixtures")
    @classmethod
    def unique_fixture_names(cls, value: list[ToolFixture]) -> list[ToolFixture]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("tool fixture names must be unique")
        return value

    @model_validator(mode="after")
    def validate_tool_risk(self) -> "GeneratedToolSpec":
        if self.read_only:
            if (
                self.risk_level == "change"
                or self.requires_approval
                or self.change_contract is not None
                or self.outcome_lookup_tool_name is not None
                or self.outcome_lookup_correlation is not None
                or self.independent_verification is not None
            ):
                raise ValueError(
                    "read-only tools cannot declare change risk, approval, a change contract, "
                    "an outcome lookup, or independent verification"
                )
        elif self.risk_level != "change" or not self.requires_approval:
            raise ValueError(
                "state-changing tools require change risk and human approval"
            )
        if self.outcome_lookup_tool_name == self.tool_name:
            raise ValueError("A write Tool cannot be its own read-only outcome lookup")
        if (self.outcome_lookup_correlation is not None
            and self.outcome_lookup_correlation.tool_name != self.outcome_lookup_tool_name):
            raise ValueError("Frozen lookup correlation must name the designated outcome lookup")
        if self.independent_verification is not None and self.independent_verification.tool_name in {
            self.tool_name, self.outcome_lookup_tool_name,
        }:
            raise ValueError("Independent verification must use a distinct read-only Tool")
        return self


class GeneratedSkillSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    skill_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    instructions: str = Field(min_length=20, max_length=12_000)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    allowed_tools: list[str] = Field(min_length=1, max_length=32)
    success_criteria: list[str] = Field(min_length=1, max_length=20)
    escalation_conditions: list[str] = Field(min_length=1, max_length=20)
    evidence_required: Literal[True] = True
    read_only: Literal[True] = True
    max_iterations: int = Field(default=6, ge=1, le=20)
    max_tool_calls: int = Field(default=12, ge=1, le=100)
    max_total_tokens: int = Field(default=20_000, ge=1, le=250_000)

    @field_validator(
        "allowed_tools", "success_criteria", "escalation_conditions"
    )
    @classmethod
    def normalize_skill_lists(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if not normalized:
            raise ValueError("skill lists require at least one non-empty entry")
        if any(len(item) > 1000 for item in normalized):
            raise ValueError("skill list entries must not exceed 1000 characters")
        return list(dict.fromkeys(normalized))


class CommandOutputInput(StudioStrictModel):
    command_profile: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    target_host: str = Field(min_length=1, max_length=255)
    target_port: int = Field(default=22, ge=1, le=65535)
    sample_output: str = Field(min_length=1, max_length=500_000)


class MIBInput(StudioStrictModel):
    mib_document_text: str = Field(
        min_length=1,
        max_length=1_000_000,
    )


class GeneratedSNMPExporterProposalSpec(StudioStrictModel):
    artifact_name: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9-]*$",
    )
    description: str = Field(min_length=1, max_length=4000)
    exporter_module_name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    walk_symbols: list[str] = Field(min_length=1, max_length=64)
    max_repetitions: int = Field(default=25, ge=1, le=50)
    retries: int = Field(default=2, ge=0, le=5)
    timeout_seconds: int = Field(default=10, ge=1, le=60)

    @field_validator("walk_symbols")
    @classmethod
    def normalize_walk_symbols(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if len(normalized) != len(value):
            raise ValueError("walk_symbols cannot contain blank values")
        if any(
            len(item) > 128
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", item) is None
            for item in normalized
        ):
            raise ValueError("walk_symbols contains an invalid MIB symbol")
        if len(normalized) != len(set(normalized)):
            raise ValueError("walk_symbols must be unique")
        return normalized


class HTTPMonitoringInput(StudioStrictModel):
    mode: Literal["api", "probe"] = "api"
    auth_mode: Literal["none", "bearer", "basic", "api_key"] = "none"
    credential_header: str = Field(default="X-API-Key", max_length=64)
    schedule_seconds: int = Field(default=60, ge=15, le=3600)
    credential_profile_ref: str | None = Field(default=None, max_length=128)


class GeneratedHTTPMonitoringSpec(StudioStrictModel):
    contract: Literal["icheck.http-monitoring-authoring/v1"] = "icheck.http-monitoring-authoring/v1"
    artifact_name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
    description: str = Field(min_length=1, max_length=4000)
    metrics: list[HTTPMetric] = Field(default_factory=list, max_length=32)
    unsupported_metrics: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("unsupported_metrics")
    @classmethod
    def bounded_unsupported(cls, value):
        if any(not item.strip() or len(item) > 255 for item in value):
            raise ValueError("Unsupported metric descriptions must be bounded nonempty text")
        return value


class SNMPMonitoringInput(StudioStrictModel):
    profile: Literal["standard-network", "cisco-cpu", "network-tables", "custom"] = "standard-network"
    mib_documents: list[str] = Field(default_factory=list, max_length=16)
    mib_modules: list[str] = Field(default_factory=list, max_length=16)
    schedule_seconds: int = Field(default=30, ge=15, le=3600)
    credential_profile_ref: str | None = Field(default=None, max_length=128)

    @field_validator("mib_documents")
    @classmethod
    def bounded_mibs(cls, value):
        try: sizes = [len(text.encode("utf-8")) for text in value]
        except UnicodeError: raise ValueError("MIB sources must be valid UTF-8") from None
        if any(not 1 <= size <= 1_000_000 for size in sizes) or sum(sizes) > 2_000_000:
            raise ValueError("Uploaded MIBs exceed the bounded source bundle limit")
        return value


from .snmp_generator import SNMPLookup


class GeneratedSNMPMonitoringSpec(StudioStrictModel):
    contract: Literal["icheck.snmp-monitoring-authoring/v1"] = "icheck.snmp-monitoring-authoring/v1"
    artifact_name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
    description: str = Field(min_length=1, max_length=4000)
    symbols: list[str] = Field(min_length=1, max_length=32)
    # Parsed again by the native compiler; generated definitions cannot include
    # arbitrary YAML, paths, credentials or commands.
    lookups: list[SNMPLookup] = Field(default_factory=list, max_length=8)
    unsupported_metrics: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("symbols")
    @classmethod
    def symbolic(cls, value):
        from .snmp_generator import SNMPGeneratorRequest
        return SNMPGeneratorRequest(symbols=value).symbols

    @field_validator("unsupported_metrics")
    @classmethod
    def bounded_unsupported(cls, value):
        return GeneratedHTTPMonitoringSpec.bounded_unsupported(value)


class ExporterMonitoringInput(StudioStrictModel):
    plugin:Literal["linux","windows","containers","vmware"]
    scheme:Literal["https","http"]="https"
    port:int|None=Field(default=None,ge=1,le=65535)
    server_name:str|None=None
    auth_mode:Literal["none","basic","bearer"]="none"
    credential_profile_ref:str|None=Field(default=None,max_length=128)
    schedule_seconds:int=Field(default=30,ge=15,le=3600)
    container_id:str|None=Field(default=None,min_length=1,max_length=512)
    container_name:str|None=Field(default=None,min_length=1,max_length=255)
    vmware_scope:Literal["hosts","vms","datastores"]|None=None
    vmware_name:str|None=Field(default=None,min_length=1,max_length=255)
    vmware_datacenter:str|None=Field(default=None,min_length=1,max_length=255)


class GeneratedExporterMonitoringSpec(StudioStrictModel):
    contract:Literal["icheck.exporter-monitoring-authoring/v1"]="icheck.exporter-monitoring-authoring/v1"
    artifact_name:str=Field(min_length=1,max_length=128,pattern=r"^[a-z][a-z0-9-]*$")
    description:str=Field(min_length=1,max_length=4000)
    groups:list[Literal["cpu","memory","disk","network","uptime"]]=Field(min_length=1,max_length=5)
    unsupported_metrics:list[str]=Field(default_factory=list,max_length=32)

    @field_validator("unsupported_metrics")
    @classmethod
    def bounded_unsupported(cls,value): return GeneratedHTTPMonitoringSpec.bounded_unsupported(value)


class CapabilityStudioSessionCreate(StudioStrictModel):
    title: str = Field(min_length=1, max_length=255)
    brief: str = Field(min_length=10, max_length=20_000)
    target_url: str | None = Field(default=None, min_length=1, max_length=2048)
    sample_document: dict[str, Any] | list[Any] | None = None
    openapi_document: dict[str, Any] | None = None
    openapi_document_text: str | None = Field(
        default=None,
        min_length=1,
        max_length=1_000_000,
    )
    operation_id: str | None = Field(default=None, min_length=1, max_length=255)
    command_input: CommandOutputInput | None = None
    mib_input: MIBInput | None = None
    http_monitoring: HTTPMonitoringInput | None = None
    snmp_monitoring: SNMPMonitoringInput | None = None
    exporter_monitoring: ExporterMonitoringInput | None = None
    source_document_text: str | None = Field(
        default=None,
        min_length=1,
        max_length=65_536,
    )
    source_document_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$",
    )
    source_document_media_type: Literal[
        "text/plain",
        "text/markdown",
        "text/x-rst",
    ] | None = None
    route_purpose: str = Field(
        default="capability.authoring",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    created_by: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_collector_input(self) -> "CapabilityStudioSessionCreate":
        if self.exporter_monitoring is not None:
            if any(x is not None for x in (self.target_url,self.sample_document,self.openapi_document,self.openapi_document_text,
                    self.operation_id,self.command_input,self.mib_input,self.http_monitoring,self.snmp_monitoring)):
                raise ValueError("Native exporter monitoring uses one platform profile without another source mode")
            return self
        if self.snmp_monitoring is not None:
            if any(value is not None for value in (self.target_url, self.sample_document, self.openapi_document,
                    self.openapi_document_text, self.operation_id, self.command_input, self.mib_input, self.http_monitoring)):
                raise ValueError("SNMP monitoring uses its profile/MIB source without another collector source mode")
            return self
        if self.http_monitoring is not None:
            if not self.target_url or any(value is not None for value in (self.openapi_document, self.openapi_document_text,
                    self.operation_id, self.command_input, self.mib_input)):
                raise ValueError("HTTP monitoring needs one target URL and optional sanitized JSON sample, without other source modes")
            return self
        document_fields = (
            self.source_document_text,
            self.source_document_name,
            self.source_document_media_type,
        )
        if any(value is not None for value in document_fields) and not all(
            value is not None for value in document_fields
        ):
            raise ValueError(
                "source document text, name, and media type must be provided together"
            )
        if self.mib_input is not None:
            if self.source_document_text is not None:
                raise ValueError(
                    "MIB input cannot be combined with a source document"
                )
            if any(
                value is not None
                for value in (
                    self.target_url,
                    self.sample_document,
                    self.openapi_document,
                    self.openapi_document_text,
                    self.operation_id,
                    self.command_input,
                )
            ):
                raise ValueError(
                    "MIB input cannot be combined with REST, OpenAPI, or "
                    "command output input"
                )
            return self
        if self.command_input is not None:
            if any(
                value is not None
                for value in (
                    self.target_url,
                    self.sample_document,
                    self.openapi_document,
                    self.openapi_document_text,
                    self.operation_id,
                )
            ):
                raise ValueError(
                    "Command output input cannot be combined with REST or "
                    "OpenAPI input"
                )
            return self
        if (
            self.openapi_document is not None
            and self.openapi_document_text is not None
        ):
            raise ValueError(
                "Provide openapi_document or openapi_document_text, not both"
            )
        if (
            self.openapi_document is not None
            or self.openapi_document_text is not None
        ):
            if not self.operation_id:
                raise ValueError("OpenAPI input requires operation_id")
            if self.sample_document is not None:
                raise ValueError(
                    "OpenAPI input cannot also provide sample_document"
                )
            return self
        if self.operation_id is not None:
            raise ValueError(
                "operation_id requires openapi_document or openapi_document_text"
            )
        if self.target_url is None or self.sample_document is None:
            raise ValueError(
                "Direct collector input requires target_url and sample_document"
            )
        return self


class CapabilityStudioWorkflowCreate(StudioStrictModel):
    title: str = Field(min_length=1, max_length=255)
    brief: str = Field(min_length=10, max_length=20_000)
    route_purpose: str = Field(
        default="capability.authoring",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    created_by: str = Field(min_length=1, max_length=255)


class CapabilityStudioTopologyCreate(CapabilityStudioWorkflowCreate):
    pass


class CapabilityStudioVisualizationCreate(CapabilityStudioWorkflowCreate):
    pass


class CapabilityStudioReportCreate(CapabilityStudioWorkflowCreate):
    report_contract_version: StrictInt = Field(default=1, ge=1, le=2)
    retained_proof_references: list[ReportRetainedProofReference] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def explicit_proof_report(self):
        refs = [(item.reference_kind, item.reference_id) for item in self.retained_proof_references]
        if ((self.report_contract_version == 2) != bool(refs) or len(refs) != len(set(refs))):
            raise ValueError("Version 2 requires unique explicit retained proof references; version 1 accepts none")
        return self


class CapabilityStudioToolCreate(CapabilityStudioWorkflowCreate):
    pass


class CapabilityStudioSkillCreate(CapabilityStudioWorkflowCreate):
    pass


class CapabilityStudioMessageCreate(StudioStrictModel):
    content: str = Field(min_length=1, max_length=20_000)
    actor: str = Field(min_length=1, max_length=255)
    request_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class CapabilityStudioGenerate(StudioStrictModel):
    actor: str = Field(min_length=1, max_length=255)
    request_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class CapabilityStudioRevisionCreate(StudioStrictModel):
    source_type: Literal[
        "collector_run",
        "artifact_replay_run",
        "agent_execution",
    ]
    source_id: str = Field(min_length=36, max_length=36)
    revision_goal: str = Field(min_length=10, max_length=4000)
    route_purpose: str = Field(
        default="capability.authoring",
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    actor: str = Field(min_length=1, max_length=255)


class CapabilityStudioMessageRead(StudioStrictModel):
    id: str
    session_id: str
    role: Literal["user", "assistant", "system"]
    content: str
    content_hash: str
    structured_content: dict[str, Any]
    @field_validator("structured_content", mode="before")
    @classmethod
    def private_compiler_sources(cls, value):
        if isinstance(value, dict) and isinstance(value.get("snmp_monitoring_input"), dict):
            return {**value, "snmp_monitoring_input": {key: item for key, item in value["snmp_monitoring_input"].items()
                if key != "mib_documents"}}
        return value
    created_at: datetime


class CapabilityStudioSessionRead(StudioStrictModel):
    id: str
    title: str
    artifact_kind: Literal[
        "collector",
        "workflow",
        "topology",
        "visualization",
        "report",
        "tool",
        "skill",
    ]
    status: Literal[
        "draft",
        "generating",
        "validated",
        "published",
        "failed",
    ]
    route_purpose: str
    route_id: str | None
    model_id: str | None
    brief: str
    target_url: str
    sample_document: dict[str, Any] | list[Any]
    source_document_name: str | None
    source_document_media_type: str | None
    source_document_sha256: str | None
    source_document_bytes: int | None
    source_context_bytes: int | None
    source_document_redaction_count: int | None
    current_spec: dict[str, Any]
    generation_attempt_id: str | None
    artifact_id: str | None
    artifact_version_id: str | None
    revision_source_type: Literal[
        "collector_run",
        "artifact_replay_run",
        "agent_execution",
    ] | None
    revision_source_id: str | None
    revision_source_artifact_version_id: str | None
    revision_evidence_sha256: str | None
    tokens_used: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    messages: list[CapabilityStudioMessageRead] = Field(default_factory=list)


class CapabilityStudioPublish(StudioStrictModel):
    actor: str = Field(min_length=1, max_length=255)
    expected_artifact_version_id: str = Field(min_length=36, max_length=36)


class CapabilityStudioRestore(CapabilityStudioPublish):
    source_version: int = Field(ge=1, strict=True)
    reason: str = Field(min_length=3, max_length=4000)


class CapabilityStudioGenerationRead(StudioStrictModel):
    id: str
    session_id: str
    request_key: str
    actor: str
    status: Literal["generating", "generated", "draft", "validated", "failed", "interrupted"]
    lease_expires_at: datetime
    model_schema: str | None
    prompt_sha256: str | None
    model_document_sha256: str | None
    usage_recorded: bool
    route_id: str | None
    model_id: str | None
    tokens_used: int
    artifact_id: str | None
    artifact_version_id: str | None
    candidate_sha256: str | None
    result_sha256: str | None
    failure_code: str | None
    created_at: datetime
    updated_at: datetime
