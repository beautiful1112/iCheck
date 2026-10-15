from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from yaml.events import AliasEvent, MappingEndEvent, MappingStartEvent
from yaml.events import SequenceEndEvent, SequenceStartEvent
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver


MAX_OPENAPI_BYTES = 1_000_000
MAX_OPENAPI_PATHS = 250
MAX_SCHEMA_DEPTH = 12
MAX_SCHEMA_NODES = 1_000
MAX_YAML_EVENTS = 100_000
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


@dataclass(frozen=True)
class OpenAPICollectorInput:
    target_url: str
    sample_document: dict[str, Any] | list[Any]
    operation_summary: dict[str, Any]


class _StrictOpenAPILoader(yaml.SafeLoader):
    pass


def _strict_mapping(
    loader: _StrictOpenAPILoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    if not isinstance(node, MappingNode):
        raise ValueError("OpenAPI YAML mapping is invalid")
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if isinstance(key, int) and not isinstance(key, bool):
            key = str(key)
        if not isinstance(key, str):
            raise ValueError("OpenAPI YAML object keys must be strings")
        if key in mapping:
            raise ValueError(f"OpenAPI YAML contains duplicate key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictOpenAPILoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _strict_mapping,
)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"OpenAPI JSON contains duplicate key: {key}")
        result[key] = value
    return result


def parse_openapi_document_text(text: str) -> tuple[dict[str, Any], str]:
    if len(text.encode("utf-8")) > MAX_OPENAPI_BYTES:
        raise ValueError(f"openapi_document exceeds {MAX_OPENAPI_BYTES} bytes")
    try:
        document = json.loads(text, object_pairs_hook=_json_pairs)
        encoding = "openapi_json"
    except json.JSONDecodeError:
        depth = 0
        event_count = 0
        try:
            for event in yaml.parse(text, Loader=yaml.SafeLoader):
                event_count += 1
                if event_count > MAX_YAML_EVENTS:
                    raise ValueError("OpenAPI YAML is too complex")
                if isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                    raise ValueError("OpenAPI YAML aliases and anchors are not allowed")
                if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                    depth += 1
                    if depth > 40:
                        raise ValueError("OpenAPI YAML nesting exceeds the limit")
                elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                    depth -= 1
            document = yaml.load(text, Loader=_StrictOpenAPILoader)
        except (yaml.YAMLError, TypeError) as exc:
            raise ValueError("openapi_document_text must be safe YAML or JSON") from exc
        encoding = "openapi_yaml"
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be an object")
    _encoded(document)
    return document, encoding


def _encoded(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("openapi_document must be finite JSON") from exc


def _document_hash(document: dict[str, Any]) -> str:
    return hashlib.sha256(_encoded(document)).hexdigest()


def _pointer(root: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ValueError("OpenAPI references must be local JSON pointers")
    current: Any = root
    for raw_segment in reference[2:].split("/"):
        segment = unquote(raw_segment).replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
            continue
        if isinstance(current, list) and segment.isdigit():
            index = int(segment)
            if index < len(current):
                current = current[index]
                continue
        raise ValueError(f"OpenAPI local reference does not exist: {reference}")
    return current


def _resolve(
    value: Any,
    root: dict[str, Any],
    *,
    references: tuple[str, ...] = (),
) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    if set(value) != {"$ref"}:
        raise ValueError("OpenAPI $ref objects cannot contain sibling fields")
    reference = value["$ref"]
    if not isinstance(reference, str):
        raise ValueError("OpenAPI $ref must be a string")
    if reference in references:
        raise ValueError("OpenAPI contains a cyclic local reference")
    if len(references) >= MAX_SCHEMA_DEPTH:
        raise ValueError("OpenAPI reference depth exceeds the limit")
    return _resolve(
        _pointer(root, reference),
        root,
        references=(*references, reference),
    )


def _validate_references(value: Any, *, depth: int = 0) -> int:
    if depth > 40:
        raise ValueError("OpenAPI document nesting exceeds the limit")
    nodes = 1
    if isinstance(value, dict):
        reference = value.get("$ref")
        if reference is not None and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            raise ValueError("OpenAPI references must be local JSON pointers")
        for item in value.values():
            nodes += _validate_references(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            nodes += _validate_references(item, depth=depth + 1)
    if nodes > 100_000:
        raise ValueError("OpenAPI document is too complex")
    return nodes


def _server_url(document: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]) -> str:
    raw_servers = operation.get("servers") or path_item.get("servers") or document.get("servers")
    if not isinstance(raw_servers, list) or not raw_servers:
        raise ValueError("OpenAPI operation requires an HTTP(S) server or target override")
    server = raw_servers[0]
    if not isinstance(server, dict) or not isinstance(server.get("url"), str):
        raise ValueError("OpenAPI server URL is invalid")
    url = server["url"]
    variables = server.get("variables", {})
    if not isinstance(variables, dict):
        raise ValueError("OpenAPI server variables are invalid")
    for name, definition in variables.items():
        if not isinstance(definition, dict) or "default" not in definition:
            raise ValueError(f"OpenAPI server variable {name!r} requires a default")
        url = url.replace("{" + str(name) + "}", str(definition["default"]))
    if "{" in url or "}" in url:
        raise ValueError("OpenAPI server URL has unresolved variables")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("OpenAPI server must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("OpenAPI server must not contain credentials, query, or fragment")
    return url.rstrip("/")


def _json_media(content: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(content, dict):
        raise ValueError("OpenAPI response must define JSON content")
    for media_type, media in content.items():
        normalized = str(media_type).lower().split(";", 1)[0].strip()
        if normalized == "application/json" or normalized.endswith("+json"):
            if not isinstance(media, dict):
                raise ValueError("OpenAPI JSON media definition is invalid")
            return str(media_type), media
    raise ValueError("OpenAPI operation requires a JSON response")


def _response(operation: dict[str, Any], root: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    responses = operation.get("responses")
    if not isinstance(responses, dict) or not responses:
        raise ValueError("OpenAPI operation requires responses")
    def is_success(item: Any) -> bool:
        value = str(item)
        return (
            len(value) == 3
            and value.isdigit()
            and value.startswith("2")
        ) or value.upper() == "2XX"

    statuses = sorted(
        responses,
        key=lambda item: (
            0 if is_success(item) else 1,
            str(item),
        ),
    )
    for status in statuses:
        if not is_success(status):
            continue
        response = _resolve(responses[status], root)
        if not isinstance(response, dict):
            continue
        try:
            media_type, media = _json_media(response.get("content"))
        except ValueError:
            continue
        return str(status), media_type, media
    raise ValueError("OpenAPI operation requires a successful JSON response")


def _example(media: dict[str, Any], schema: dict[str, Any], root: dict[str, Any]) -> Any | None:
    if "example" in media:
        return media["example"]
    examples = media.get("examples")
    if isinstance(examples, dict) and examples:
        candidate = _resolve(examples[sorted(examples)[0]], root)
        if isinstance(candidate, dict) and "value" in candidate:
            return candidate["value"]
    resolved_schema = _resolve(schema, root)
    if isinstance(resolved_schema, dict) and "example" in resolved_schema:
        return resolved_schema["example"]
    return None


def _schema_sample(
    schema: Any,
    root: dict[str, Any],
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    if depth > MAX_SCHEMA_DEPTH:
        raise ValueError("OpenAPI response schema depth exceeds the limit")
    budget = budget or [MAX_SCHEMA_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("OpenAPI response schema is too complex")
    schema = _resolve(schema, root)
    if not isinstance(schema, dict):
        raise ValueError("OpenAPI response schema must be an object")
    for key in ("example", "default", "const"):
        if key in schema:
            return schema[key]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    for composite in ("oneOf", "anyOf"):
        variants = schema.get(composite)
        if isinstance(variants, list) and variants:
            return _schema_sample(variants[0], root, depth=depth + 1, budget=budget)
    all_of = schema.get("allOf")
    if isinstance(all_of, list) and all_of:
        combined: dict[str, Any] = {}
        for item in all_of:
            value = _schema_sample(item, root, depth=depth + 1, budget=budget)
            if not isinstance(value, dict):
                raise ValueError("OpenAPI allOf samples must resolve to objects")
            combined.update(value)
        return combined
    schema_type = schema.get("type")
    properties = schema.get("properties")
    if schema_type == "object" or isinstance(properties, dict):
        if not isinstance(properties, dict) or not properties:
            raise ValueError("OpenAPI response objects require properties or an example")
        if len(properties) > 128:
            raise ValueError("OpenAPI response object has too many properties")
        return {
            str(name): _schema_sample(
                child,
                root,
                depth=depth + 1,
                budget=budget,
            )
            for name, child in properties.items()
        }
    if schema_type == "array":
        if "items" not in schema:
            raise ValueError("OpenAPI response arrays require items")
        return [
            _schema_sample(
                schema["items"],
                root,
                depth=depth + 1,
                budget=budget,
            )
        ]
    if schema_type == "boolean":
        return False
    if schema_type == "integer":
        return 0
    if schema_type == "number":
        return 0.0
    if schema_type == "null":
        return None
    if schema_type == "string" or schema_type is None:
        formats = {
            "date": "2026-01-01",
            "date-time": "2026-01-01T00:00:00Z",
            "email": "user@example.invalid",
            "hostname": "host.example.invalid",
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "uri": "https://example.invalid/resource",
            "uuid": "00000000-0000-4000-8000-000000000000",
        }
        return formats.get(str(schema.get("format")), "example")
    raise ValueError(f"Unsupported OpenAPI response schema type: {schema_type!r}")


def _parameter_summary(
    document: dict[str, Any],
    path_item: dict[str, Any],
    operation: dict[str, Any],
) -> list[dict[str, Any]]:
    combined = [
        *(path_item.get("parameters") or []),
        *(operation.get("parameters") or []),
    ]
    if not isinstance(combined, list) or len(combined) > 128:
        raise ValueError("OpenAPI operation parameters exceed the limit")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in combined:
        parameter = _resolve(raw, document)
        if not isinstance(parameter, dict):
            raise ValueError("OpenAPI parameter definition is invalid")
        name = parameter.get("name")
        location = parameter.get("in")
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 128
            or location not in {"path", "query", "header", "cookie"}
        ):
            raise ValueError("OpenAPI parameter name or location is invalid")
        schema = _resolve(parameter.get("schema", {}), document)
        schema_type = schema.get("type") if isinstance(schema, dict) else None
        schema_format = schema.get("format") if isinstance(schema, dict) else None
        if schema_type is not None and not isinstance(schema_type, str):
            raise ValueError("OpenAPI parameter schema type is invalid")
        if schema_format is not None and not isinstance(schema_format, str):
            raise ValueError("OpenAPI parameter schema format is invalid")
        result[(name, location)] = {
            "name": name,
            "in": location,
            "required": bool(parameter.get("required")),
            "type": schema_type,
            "format": schema_format,
        }
    return list(result.values())


def extract_openapi_collector_input(
    document: dict[str, Any],
    *,
    operation_id: str,
    target_url_override: str | None = None,
) -> OpenAPICollectorInput:
    encoded = _encoded(document)
    if len(encoded) > MAX_OPENAPI_BYTES:
        raise ValueError(f"openapi_document exceeds {MAX_OPENAPI_BYTES} bytes")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith(("3.0.", "3.1.")):
        raise ValueError("Only OpenAPI 3.0 and 3.1 documents are supported")
    _validate_references(document)
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("OpenAPI document requires paths")
    if len(paths) > MAX_OPENAPI_PATHS:
        raise ValueError(f"OpenAPI document exceeds {MAX_OPENAPI_PATHS} paths")

    matches: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    for path, raw_path_item in paths.items():
        path_item = _resolve(raw_path_item, document)
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > 512
            or not isinstance(path_item, dict)
        ):
            raise ValueError("OpenAPI path definition is invalid")
        for method, raw_operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            operation = _resolve(raw_operation, document)
            if isinstance(operation, dict) and operation.get("operationId") == operation_id:
                matches.append((path, method.lower(), path_item, operation))
    if not matches:
        raise ValueError(f"OpenAPI operationId not found: {operation_id}")
    if len(matches) != 1:
        raise ValueError(f"OpenAPI operationId is ambiguous: {operation_id}")
    path, method, path_item, operation = matches[0]
    if method != "get":
        raise ValueError("Collector Studio supports only read-only OpenAPI GET operations")

    status, media_type, media = _response(operation, document)
    schema = media.get("schema")
    if not isinstance(schema, dict):
        raise ValueError("OpenAPI JSON response requires a schema")
    sample = _example(media, schema, document)
    sample_source = "openapi_example"
    if sample is None:
        sample = _schema_sample(schema, document)
        sample_source = "schema_synthesized"
    if not isinstance(sample, (dict, list)):
        raise ValueError("OpenAPI response sample must be an object or array")

    if target_url_override:
        target_url = target_url_override
    else:
        target_url = _server_url(document, path_item, operation) + path
    if len(target_url) > 2048:
        raise ValueError("OpenAPI target URL exceeds 2048 characters")
    tags = operation.get("tags") or []
    if not isinstance(tags, list) or any(
        not isinstance(item, str) for item in tags
    ):
        raise ValueError("OpenAPI operation tags must be an array of strings")
    operation_description = operation.get("summary") or ""
    if not isinstance(operation_description, str):
        raise ValueError("OpenAPI operation summary must be a string")
    if len(media_type) > 128:
        raise ValueError("OpenAPI response media type exceeds 128 characters")
    summary = {
        "source_format": "openapi",
        "document_sha256": _document_hash(document),
        "openapi_version": version,
        "operation_id": operation_id,
        "method": method.upper(),
        "path": path,
        "summary": operation_description[:500],
        "tags": [item[:128] for item in tags[:32]],
        "parameters": _parameter_summary(document, path_item, operation),
        "response_status": status,
        "response_media_type": media_type,
        "sample_source": sample_source,
        "sample_sha256": hashlib.sha256(_encoded(sample)).hexdigest(),
    }
    return OpenAPICollectorInput(
        target_url=target_url,
        sample_document=sample,
        operation_summary=summary,
    )
