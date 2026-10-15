from __future__ import annotations

from typing import Any

from ..sandbox import SandboxUnavailable
from .http_json import collect_http_json


def collect_http_json_sandbox(
    assignment: dict[str, Any],
) -> list[dict[str, Any]]:
    """Fetch through trusted HTTP controls, then transform in OS isolation."""

    executor = assignment.get("_runtime", {}).get("sandbox_executor")
    if executor is None or not hasattr(executor, "transform"):
        raise SandboxUnavailable("Generated-code sandbox is unavailable on Worker")
    implementation = assignment.get("implementation")
    if not isinstance(implementation, dict):
        raise ValueError("Sandbox collector implementation is missing")
    trusted_envelopes = collect_http_json(assignment)
    configuration = {
        **(assignment.get("defaults") or {}),
        **(assignment.get("configuration") or {}),
    }
    return executor.transform(
        implementation,
        trusted_envelopes,
        configuration,
        list(assignment.get("output_kinds") or []),
    )
