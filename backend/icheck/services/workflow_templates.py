from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AgentToolRegistration
from ..schema_validation import validate_schema
from ..studio_schemas import GeneratedWorkflowSpec, WorkflowNode


WORKFLOW_FORMAT_VERSION = "icheck.workflow/v1"
WORKFLOW_RUNTIME = "icheck_workflow_v1"


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def workflow_tool_catalog(db: Session) -> list[dict[str, Any]]:
    tools = db.scalars(
        select(AgentToolRegistration)
        .where(AgentToolRegistration.enabled.is_(True))
        .order_by(AgentToolRegistration.name)
    ).all()
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "risk_level": tool.risk_level,
            "read_only": tool.read_only,
            "required_permissions": tool.required_permissions,
            "input_schema": tool.input_schema,
        }
        for tool in tools
    ]


def _transitions(node: WorkflowNode) -> list[str]:
    return list(
        dict.fromkeys(
            value
            for value in [
                node.on_success,
                node.on_failure,
                node.rollback_node_id,
            ]
            if value
        )
    )


def _schema_path(schema: dict[str, Any], dotted: str) -> dict[str, Any]:
    current: Any = schema
    for part in dotted.split("."):
        properties = current.get("properties") if isinstance(current, dict) else None
        if not isinstance(properties, dict) or part not in properties:
            raise ValueError(f"Workflow input path {dotted!r} is not in input_schema")
        current = properties[part]
    if not isinstance(current, dict):
        raise ValueError(f"Workflow input path {dotted!r} has an invalid schema")
    return current


def _json_types(schema: dict[str, Any]) -> set[str]:
    value = schema.get("type")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _dependency(tool: AgentToolRegistration) -> dict[str, Any]:
    return {
        "id": tool.id,
        "name": tool.name,
        "transport": tool.transport,
        "handler": tool.handler,
        "risk_level": tool.risk_level,
        "read_only": tool.read_only,
        "required_permissions": sorted(tool.required_permissions),
        "input_schema_sha256": _hash(tool.input_schema),
        "output_schema_sha256": _hash(tool.output_schema),
        "timeout_seconds": tool.timeout_seconds,
        "max_result_bytes": tool.max_result_bytes,
    }


def _cycles(
    nodes: dict[str, WorkflowNode],
    edges: dict[str, list[str]],
) -> list[list[str]]:
    state = {node_id: 0 for node_id in nodes}
    stack: list[str] = []
    discovered: dict[tuple[str, ...], list[str]] = {}

    def visit(node_id: str) -> None:
        state[node_id] = 1
        stack.append(node_id)
        for target in edges[node_id]:
            if state[target] == 0:
                visit(target)
            elif state[target] == 1:
                start = stack.index(target)
                cycle = stack[start:].copy()
                discovered.setdefault(tuple(sorted(cycle)), cycle)
        stack.pop()
        state[node_id] = 2

    for node_id in nodes:
        if state[node_id] == 0:
            visit(node_id)
    return list(discovered.values())


def validate_workflow_spec(
    db: Session,
    spec: GeneratedWorkflowSpec,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validate_schema(spec.input_schema, "workflow.input_schema")
    if spec.input_schema.get("type") != "object":
        raise ValueError("workflow.input_schema must declare type object")
    if not isinstance(spec.input_schema.get("properties"), dict):
        raise ValueError("workflow.input_schema must declare properties")
    if spec.input_schema.get("additionalProperties") is not False:
        raise ValueError("workflow.input_schema must set additionalProperties false")

    nodes = {node.node_id: node for node in spec.nodes}
    if spec.start_node not in nodes:
        raise ValueError("workflow start_node does not exist")
    end_nodes = sorted(
        node.node_id for node in spec.nodes if node.node_type == "end"
    )
    if not end_nodes:
        raise ValueError("workflow requires at least one end node")

    edges = {node.node_id: _transitions(node) for node in spec.nodes}
    for source, targets in edges.items():
        missing = sorted(set(targets) - set(nodes))
        if missing:
            raise ValueError(
                f"workflow node {source!r} references missing nodes {missing}"
            )

    reachable: set[str] = set()
    queue = deque([spec.start_node])
    while queue:
        node_id = queue.popleft()
        if node_id in reachable:
            continue
        reachable.add(node_id)
        queue.extend(edges[node_id])
    unreachable = sorted(set(nodes) - reachable)
    if unreachable:
        raise ValueError(f"workflow contains unreachable nodes {unreachable}")

    reverse_edges: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for source, targets in edges.items():
        for target in targets:
            reverse_edges[target].append(source)
    can_finish: set[str] = set()
    queue = deque(end_nodes)
    while queue:
        node_id = queue.popleft()
        if node_id in can_finish:
            continue
        can_finish.add(node_id)
        queue.extend(reverse_edges[node_id])
    no_end_path = sorted(set(nodes) - can_finish)
    if no_end_path:
        raise ValueError(f"workflow nodes cannot reach an end node: {no_end_path}")

    cycles = _cycles(nodes, edges)
    for cycle in cycles:
        if not any(nodes[node_id].node_type == "agent_loop" for node_id in cycle):
            raise ValueError(
                "workflow cycles require a bounded agent_loop node: "
                f"{sorted(cycle)}"
            )

    referenced_names = {
        name
        for node in spec.nodes
        for name in [node.tool_name, *node.allowed_tools]
        if name
    }
    tools = {
        tool.name: tool
        for tool in db.scalars(
            select(AgentToolRegistration).where(
                AgentToolRegistration.name.in_(referenced_names),
                AgentToolRegistration.enabled.is_(True),
            )
        ).all()
    }
    missing_tools = sorted(referenced_names - set(tools))
    if missing_tools:
        raise ValueError(
            f"workflow references unavailable tools {missing_tools}"
        )

    permissions: set[str] = set()
    state_change_nodes: list[str] = []
    approval_nodes: list[str] = []
    referenced_rollbacks: set[str] = set()
    for node in spec.nodes:
        if node.node_type == "approval":
            approval_nodes.append(node.node_id)
        if node.node_type not in {"tool", "post_check", "rollback"}:
            if node.input_bindings:
                raise ValueError(
                    f"workflow node {node.node_id!r} cannot declare input bindings"
                )
        if node.tool_name:
            tool = tools[node.tool_name]
            permissions.update(tool.required_permissions)
            tool_properties = tool.input_schema.get("properties", {})
            if not isinstance(tool_properties, dict):
                raise ValueError(
                    f"tool {tool.name!r} has an invalid input schema"
                )
            bound_arguments = {item.argument for item in node.input_bindings}
            unknown_arguments = sorted(bound_arguments - set(tool_properties))
            if unknown_arguments:
                raise ValueError(
                    f"workflow node {node.node_id!r} binds unknown tool arguments "
                    f"{unknown_arguments}"
                )
            required_arguments = set(tool.input_schema.get("required", []))
            missing_arguments = sorted(required_arguments - bound_arguments)
            if missing_arguments:
                raise ValueError(
                    f"workflow node {node.node_id!r} is missing required tool "
                    f"arguments {missing_arguments}"
                )
            for binding in node.input_bindings:
                source_schema = _schema_path(
                    spec.input_schema,
                    binding.input_path,
                )
                source_types = _json_types(source_schema)
                target_types = _json_types(tool_properties[binding.argument])
                if source_types and target_types and not source_types <= target_types:
                    raise ValueError(
                        f"workflow binding {binding.input_path!r} for "
                        f"{node.node_id!r}.{binding.argument} has incompatible types"
                    )
            if node.node_type == "post_check" and not tool.read_only:
                raise ValueError("post_check nodes must use a read-only tool")
            if node.node_type == "rollback" and tool.read_only:
                raise ValueError("rollback nodes must use a state-changing tool")
            if not tool.read_only:
                state_change_nodes.append(node.node_id)
                if not node.requires_approval:
                    raise ValueError(
                        f"state-changing node {node.node_id!r} requires approval"
                    )
                if node.node_type != "rollback":
                    if not node.rollback_node_id:
                        raise ValueError(
                            f"state-changing node {node.node_id!r} requires rollback"
                        )
                    rollback_node = nodes[node.rollback_node_id]
                    if rollback_node.node_type != "rollback":
                        raise ValueError(
                            f"rollback target for {node.node_id!r} must be a rollback node"
                        )
                    referenced_rollbacks.add(node.rollback_node_id)
                    post_check = nodes[node.on_success]
                    if post_check.node_type != "post_check":
                        raise ValueError(
                            f"state-changing node {node.node_id!r} must transition "
                            "to a post_check on success"
                        )
                    if post_check.on_failure != node.rollback_node_id:
                        raise ValueError(
                            f"post_check for {node.node_id!r} must transition to "
                            "its rollback node on failure"
                        )
        if node.node_type == "agent_loop":
            for tool_name in node.allowed_tools:
                tool = tools[tool_name]
                if not tool.read_only or tool.risk_level == "change":
                    raise ValueError(
                        "agent_loop allowed_tools must be read-only; "
                        f"{tool_name!r} is state-changing"
                    )
                permissions.update(tool.required_permissions)

    rollback_nodes = {
        node.node_id for node in spec.nodes if node.node_type == "rollback"
    }
    unused_rollbacks = sorted(rollback_nodes - referenced_rollbacks)
    if unused_rollbacks:
        raise ValueError(
            f"workflow contains rollback nodes not attached to a change: {unused_rollbacks}"
        )

    # Compute graph dominators so `requires_approval=true` cannot merely label a
    # change node while a path actually bypasses the approval interrupt.
    dominators: dict[str, set[str]] = {
        node_id: ({node_id} if node_id == spec.start_node else set(nodes))
        for node_id in nodes
    }
    changed = True
    while changed:
        changed = False
        for node_id in nodes:
            if node_id == spec.start_node:
                continue
            predecessors = reverse_edges[node_id]
            shared = set(nodes)
            for predecessor in predecessors:
                shared &= dominators[predecessor]
            updated = {node_id, *shared}
            if updated != dominators[node_id]:
                dominators[node_id] = updated
                changed = True
    approval_set = set(approval_nodes)
    for node_id in state_change_nodes:
        if not dominators[node_id] & approval_set:
            raise ValueError(
                f"state-changing node {node_id!r} can bypass an approval node"
            )

    dependencies = sorted(
        (_dependency(tool) for tool in tools.values()),
        key=lambda item: item["name"],
    )
    ordered_nodes = []
    seen: set[str] = set()
    queue = deque([spec.start_node])
    while queue:
        node_id = queue.popleft()
        if node_id in seen:
            continue
        seen.add(node_id)
        ordered_nodes.append(node_id)
        queue.extend(edges[node_id])
    graph_document = {
        "start_node": spec.start_node,
        "nodes": [node.model_dump(mode="json") for node in spec.nodes],
    }
    report = {
        "runtime": WORKFLOW_RUNTIME,
        "isolation": "declarative_graph",
        "graph_sha256": _hash(graph_document),
        "node_count": len(nodes),
        "edge_count": sum(len(targets) for targets in edges.values()),
        "ordered_nodes": ordered_nodes,
        "end_nodes": end_nodes,
        "cycles": cycles,
        "tool_dependencies": [item["name"] for item in dependencies],
        "required_permissions": sorted(permissions),
        "approval_nodes": sorted(approval_nodes),
        "state_change_nodes": sorted(state_change_nodes),
        "budgets": {
            "max_runtime_seconds": spec.max_runtime_seconds,
            "max_total_tool_calls": spec.max_total_tool_calls,
            "max_total_tokens": spec.max_total_tokens,
        },
    }
    return report, dependencies


def workflow_artifact_documents(
    db: Session,
    spec: GeneratedWorkflowSpec,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    report, dependencies = validate_workflow_spec(db, spec)
    definition = {
        "format_version": WORKFLOW_FORMAT_VERSION,
        "spec": spec.model_dump(mode="json"),
        "tool_dependencies": dependencies,
    }
    implementation = {
        "runtime": WORKFLOW_RUNTIME,
        "entrypoint": spec.start_node,
    }
    tests = [
        {
            "name": "Deterministic workflow graph validation",
            "expected_graph_sha256": report["graph_sha256"],
            "expected_node_count": report["node_count"],
            "expected_required_permissions": report["required_permissions"],
        }
    ]
    return definition, implementation, tests


def validate_workflow_artifact_contract(
    db: Session,
    definition: dict[str, Any],
    implementation: dict[str, Any],
    tests: list[dict[str, Any]],
) -> dict[str, Any]:
    if set(definition) != {"format_version", "spec", "tool_dependencies"}:
        raise ValueError("workflow definition has unsupported fields")
    if definition.get("format_version") != WORKFLOW_FORMAT_VERSION:
        raise ValueError("workflow format_version is unsupported")
    spec = GeneratedWorkflowSpec.model_validate(definition.get("spec"))
    report, dependencies = validate_workflow_spec(db, spec)
    if definition.get("tool_dependencies") != dependencies:
        raise ValueError("workflow Tool Registry dependencies changed")
    if implementation != {
        "runtime": WORKFLOW_RUNTIME,
        "entrypoint": spec.start_node,
    }:
        raise ValueError("workflow implementation contract is invalid")
    expected_tests = [
        {
            "name": "Deterministic workflow graph validation",
            "expected_graph_sha256": report["graph_sha256"],
            "expected_node_count": report["node_count"],
            "expected_required_permissions": report["required_permissions"],
        }
    ]
    if tests != expected_tests:
        raise ValueError("workflow validation preview does not match its graph")
    return report
