"""400 validation details are specific but never arbitrary upstream prose."""
import json
import pytest
import gzip
from icheck.ai_failure_diagnostics import provider_diagnostic
from icheck.ai_wire_format import graph_response_format
from icheck.langgraph_runtime import GraphDecision

SECRET = "sk-or-v1-do-not-export-synthetic-private-key"
PRIVATE = "private-device-198.18.0.123-prompt-data"


def envelope(message, **extra):
    return json.dumps({"error": {"message": "Provider returned error", "metadata": {
        "provider_name": "Alibaba", "error_type": "invalid_request", "provider_code": "InvalidParameter",
        "raw": json.dumps({"code": "InvalidParameter", "message": message + " " + SECRET + " " + PRIVATE,
            "request_id": SECRET, "prompt": PRIVATE, **extra}),
    }}}).encode()


@pytest.mark.parametrize("message,code,parameter,constraint", [
    ("Reasoning is mandatory for this model and cannot be disabled", "provider_reasoning_required", "reasoning.enabled", "cannot_disable_reasoning"),
    ("response_format.json_schema.strict must be true", "provider_schema_strict_required", "response_format.json_schema.strict", "must_be_true"),
    ("The value of the enable_thinking parameter is restricted to True", "provider_thinking_required", "enable_thinking", "must_be_true"),
    ("Json mode response is not supported when enable_thinking is true", "provider_json_thinking_conflict", "enable_thinking", "json_mode_requires_false"),
    ("messages must contain the word json to use response_format json_object", "provider_json_prompt_required", "messages", "must_contain_json_keyword"),
    ("response_format json_schema is not supported", "provider_schema_mode_unsupported", "response_format.type", "json_schema_not_supported"),
    ("Invalid schema: additionalProperties is not allowed here", "provider_json_schema_invalid", "response_format.json_schema.schema", "invalid_schema"),
])
def test_nested_provider_validation_has_exact_safe_constraint(message, code, parameter, constraint):
    value = provider_diagnostic(400, envelope(message))
    assert value["code"] == code and value["root_cause_known"]
    assert value["provider_error"]["parameter"] == parameter
    assert value["provider_error"]["constraint"] == constraint
    assert value["provider_error"]["provider_code"] == "InvalidParameter"
    assert value["provider_error"]["error_type"] == "invalid_request"
    assert SECRET not in json.dumps(value) and PRIVATE not in json.dumps(value)
    assert "raw" not in value["provider_error"] and "message" not in value["provider_error"]


def test_safe_parameter_is_retained_but_unknown_value_constraint_is_not_invented():
    value = provider_diagnostic(400, envelope("Invalid value", param="temperature"))
    assert value["provider_error"]["parameter"] == "temperature"
    assert value["code"] == "provider_parameter_invalid" and value["root_cause_known"] is False
    assert SECRET not in json.dumps(value)


@pytest.mark.parametrize("body", [b"not JSON", b"[]", b"{}", b"{" + b"x" * 20000,
    (b'{"error":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"),
    json.dumps({"error": {"message": SECRET, "param": SECRET, "metadata": {
        "error_type": SECRET, "provider_code": SECRET, "provider_name": SECRET, "raw": [PRIVATE]}}}).encode(),
])
def test_unknown_oversized_malformed_or_untrusted_detail_is_explicitly_unknown(body):
    value = provider_diagnostic(400, body)
    assert value["code"] == "provider_bad_request" and value["root_cause_known"] is False
    assert value["provider_error"] == {} and value["evidence_source"] == "http_status_only"
    assert SECRET not in json.dumps(value) and PRIVATE not in json.dumps(value)


def test_qwen_probe_and_agent_share_full_schema_with_required_strict_mode():
    qwen = graph_response_format("https://openrouter.ai/api/v1", "qwen/qwen3.8-max-0902")
    assert qwen["json_schema"]["strict"] is True
    assert qwen["json_schema"]["schema"] == GraphDecision.model_json_schema()
    for base, model in [("https://openrouter.ai/api/v1", "openai/gpt-4o"), ("https://other.example/v1", "qwen/qwen3.8-max-0902")]:
        assert graph_response_format(base, model)["json_schema"]["strict"] is False


def test_bad_request_and_credit_failure_are_not_conflated():
    assert provider_diagnostic(400)["code"] == "provider_bad_request"
    assert provider_diagnostic(402)["code"] == "provider_credit_required"


def test_openrouter_mandatory_reasoning_top_level_message_is_not_lost():
    body = json.dumps({"error": {"message": "Reasoning cannot be disabled for model qwen/qwen3.8-max-0902", "code": 400}}).encode()
    value = provider_diagnostic(400, body)
    assert value["root_cause_known"] and value["code"] == "provider_reasoning_required"
    assert value["provider_error"] == {"parameter": "reasoning.enabled", "constraint": "cannot_disable_reasoning"}


@pytest.mark.parametrize("body,format", [
    (json.dumps({"code": "InvalidParameter", "message": "json_schema strict must be true " + SECRET}).encode(), "json"),
    (b"response_format json_schema strict must be true", "non_json"),
    (json.dumps({"detail": "json_schema strict must be true " + SECRET}).encode(), "json"),
    (gzip.compress(envelope("json_schema strict must be true")), "gzip_json"),
])
def test_native_plain_wrapped_and_compressed_validation_remain_safe(body, format):
    value = provider_diagnostic(400, body)
    assert value["code"] == "provider_schema_strict_required"
    assert value["diagnostic_context"]["body_format"] == format
    assert SECRET not in json.dumps(value)


def test_gzip_bomb_and_empty_response_are_bounded_and_explicit():
    value = provider_diagnostic(400, gzip.compress(b"x" * 1000000))
    assert not value["root_cause_known"]
    assert value["diagnostic_context"]["body_format"] == "compressed_invalid_or_oversized"
    assert provider_diagnostic(400)["diagnostic_context"]["body_format"] == "empty"


def test_wrapped_validation_loc_is_allowlisted_and_input_is_never_exported():
    body = json.dumps({"detail": [{"type": "value_error", "loc": ["body", "temperature"], "msg": "Invalid value", "input": SECRET}]}).encode()
    value = provider_diagnostic(400, body)
    assert value["provider_error"]["parameter"] == "temperature"
    assert SECRET not in json.dumps(value)
