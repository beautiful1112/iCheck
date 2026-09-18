from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, SchemaError, validators


MAX_SCHEMA_BYTES = 100_000
MAX_SCHEMA_DEPTH = 30
MAX_SCHEMA_NODES = 5_000


def _inspect_schema(value: Any, *, path: str = "$", depth: int = 0) -> int:
    if depth > MAX_SCHEMA_DEPTH:
        raise ValueError(f"{path}: schema nesting exceeds {MAX_SCHEMA_DEPTH}")
    nodes = 1
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in {"$ref", "$dynamicRef"} and isinstance(child, str):
                parsed = urlparse(child)
                if parsed.scheme or parsed.netloc or (
                    child and not child.startswith("#")
                ):
                    raise ValueError(
                        f"{child_path}: only local JSON Schema references are allowed"
                    )
            nodes += _inspect_schema(child, path=child_path, depth=depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            nodes += _inspect_schema(
                child,
                path=f"{path}[{index}]",
                depth=depth + 1,
            )
    if nodes > MAX_SCHEMA_NODES:
        raise ValueError(f"{path}: schema exceeds {MAX_SCHEMA_NODES} nodes")
    return nodes


def validate_schema(schema: dict[str, Any], name: str) -> None:
    encoded = json.dumps(schema, separators=(",", ":"), ensure_ascii=True).encode()
    if len(encoded) > MAX_SCHEMA_BYTES:
        raise ValueError(f"{name} exceeds {MAX_SCHEMA_BYTES} bytes")
    _inspect_schema(schema, path=name)
    validator_class = validators.validator_for(
        schema,
        default=Draft202012Validator,
    )
    try:
        validator_class.check_schema(schema)
    except SchemaError as exc:
        location = ".".join(str(item) for item in exc.absolute_path)
        suffix = f" at {location}" if location else ""
        raise ValueError(f"{name} is not a valid JSON Schema{suffix}: {exc.message}") from exc


def validate_instance(
    instance: Any,
    schema: dict[str, Any],
    name: str,
) -> None:
    validate_schema(schema, f"{name} schema")
    validator_class = validators.validator_for(
        schema,
        default=Draft202012Validator,
    )
    errors = sorted(
        validator_class(schema).iter_errors(instance),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(item) for item in error.absolute_path)
    suffix = f" at {location}" if location else ""
    raise ValueError(f"{name} is invalid{suffix}: {error.message}")
