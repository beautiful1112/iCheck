"""Fixed, actionable AI diagnostics. Never return upstream prose or request bodies."""
import json
import re
import zlib
from pydantic import ValidationError


DECISION_FIELDS = frozenset({"action", "plan", "hypotheses", "tool_requests", "confidence", "conclusion",
    "uncertainty", "escalation_reason", "structured_output", "token_usage", "tool_name", "arguments", "purpose",
    "statement", "supporting_evidence_ids", "contradicting_evidence_ids"})
DECISION_RULES = {
    "continue decisions require at least one tool request": "continue_requires_tools",
    "complete decisions require a conclusion": "complete_requires_conclusion",
    "escalate decisions require a reason": "escalate_requires_reason",
    "terminal decisions cannot request tools": "terminal_cannot_request_tools",
    "structured_output is valid only for complete decisions": "structured_output_requires_complete",
    "Graph decision must be a JSON object": "decision_requires_object",
    "Graph decision content must be text": "decision_content_requires_text",
    "Graph decision content is missing": "decision_content_missing",
    "Situation completion requires impact assessment structured_output": "situation_output_required",
    "Topology proposal completion requires structured_output": "topology_output_required",
    "Visualization proposal completion requires structured_output": "visualization_output_required",
    "Skill completion requires structured_output": "skill_output_required",
    "Skill completion requires persisted evidence": "skill_evidence_required",
    "Skill output references evidence outside the investigation": "skill_evidence_outside_scope",
    "agent_loop nodes cannot declare tool_name": "workflow_agent_loop_cannot_declare_tool",
    "end nodes cannot declare tool_name": "workflow_end_cannot_declare_tool",
    "agent_loop nodes require objective and max_iterations": "workflow_agent_loop_requires_objective_and_budget",
    "agent_loop nodes require allowed_tools": "workflow_agent_loop_requires_tools",
    "allowed_tools and max_iterations are only valid for agent_loop": "workflow_agent_fields_require_agent_loop",
    "end nodes cannot declare execution or transition fields": "workflow_end_must_be_terminal",
    "non-end workflow nodes require on_success": "workflow_nonterminal_requires_success_transition",
}
VALIDATION_TYPES = frozenset({"missing", "extra_forbidden", "literal_error", "string_type", "string_too_long",
    "string_too_short", "list_type", "dict_type", "model_type", "float_type", "float_parsing", "int_type",
    "int_parsing", "int_from_float", "greater_than_equal", "less_than_equal", "too_long", "too_short", "value_error", "json_invalid"})


def model_validation_diagnostic(error, *, finish_reason=None, stage="graph_decision", known_fields=DECISION_FIELDS):
    """Exact fixed rule / safe schema path; never Pydantic input, ctx or raw msg."""
    issues = []
    if isinstance(error, ValidationError):
        # Only the fixed local validator messages are classified from context.
        for item in error.errors(include_input=False, include_url=False)[:10]:
            path = ".".join(str(part) if type(part) is int else part if part in known_fields else "<unknown-field>"
                for part in item.get("loc", ()))[:256] or "$"
            kind = item.get("type")
            rule = kind if kind in VALIDATION_TYPES else "schema_validation"
            context_error = (item.get("ctx") or {}).get("error")
            rule = DECISION_RULES.get(str(context_error), rule)
            issues.append({"path": path, "rule": rule})
    elif isinstance(error, json.JSONDecodeError):
        issues.append({"path": "$", "rule": "invalid_json", "line": error.lineno, "column": error.colno})
    else:
        issues.append({"path": "$", "rule": DECISION_RULES.get(str(error), "output_contract_invalid")})
    if finish_reason == "length":
        issues.insert(0, {"path": "$", "rule": "output_token_limit_reached"})
    known = all(issue["rule"] not in {"output_contract_invalid", "schema_validation"} for issue in issues)
    detail = "; ".join(issue["path"] + ": " + issue["rule"] for issue in issues)
    result = diagnostic("model_schema_invalid", "Model response failed local Capability Studio validation." if stage == "capability_authoring" else "Model response failed local Agent validation.",
        ("Rejected output: " if stage == "capability_authoring" else "Rejected decision: ") + detail + ".",
        "Review the reported rule and runtime model settings. No tools ran for this rejected decision; do not bypass validation.")
    result.update(root_cause_known=known, evidence_source="local_validation", validation_errors=issues,
        validation_stage=stage)
    if finish_reason in {"stop", "length", "tool_calls", "content_filter", "error"}:
        result["finish_reason"] = finish_reason
    return result


def schema_field_names(schema):
    """Whitelist field names from a local response-model schema, never a model output."""
    fields, pending = set(), [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            fields.update(name for name in node.get("properties", {})
                          if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name))
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return frozenset(fields)


def timeout_diagnostic(*, worker=False, timeout_seconds=None):
    value = diagnostic("worker_reasoning_timeout" if worker else "provider_timeout",
        "Worker timed out waiting for AI reasoning." if worker else "AI provider response exceeded its time limit.",
        "The worker's bounded control-plane wait expired; this does not prove a device connectivity problem." if worker
        else "The model call did not complete within the provider/remaining-investigation elapsed-time limit, including response-body reads.",
        "Review runtime timing and model settings. Provider charges may be unresolved; do not automatically repeat the call.")
    value.update(stage="worker_control_plane" if worker else "provider_http", root_cause_known=True,
        evidence_source="local_timeout")
    if isinstance(timeout_seconds, (int, float)):
        value["timeout_seconds"] = round(timeout_seconds, 3)
    return value


ERROR_TYPES = frozenset({"invalid_request", "invalid_prompt", "unprocessable", "context_length_exceeded",
    "max_tokens_exceeded", "token_limit_exceeded", "string_too_long", "authentication", "permission_denied",
    "payment_required", "rate_limit_exceeded", "provider_overloaded", "provider_unavailable", "not_found",
    "precondition_failed", "payload_too_large", "content_policy_violation", "refusal", "server", "timeout", "unmapped"})
PROVIDER_CODES = frozenset({"InvalidParameter", "InvalidParameterValue", "InvalidRequest", "BadRequest",
    "invalid_request_error", "invalid_request", "invalid_parameter", "invalid_value", "invalid_json_schema",
    "invalid_schema", "unsupported_parameter", "unsupported_value", "invalid_response_format"})
PROVIDERS = frozenset({"Alibaba", "Alibaba Cloud", "Alibaba Cloud Int.", "OpenAI", "Anthropic", "Google",
    "DeepSeek", "Qwen", "Fireworks", "Together", "Groq", "OpenRouter"})
PARAMETERS = frozenset({"response_format", "response_format.type", "response_format.json_schema",
    "response_format.json_schema.strict", "response_format.json_schema.schema", "json_schema", "strict",
    "enable_thinking", "reasoning", "reasoning.enabled", "reasoning.effort", "max_tokens", "max_completion_tokens",
    "messages", "tools", "tool_choice", "temperature", "top_p"})


def _error_evidence(body):
    """Read bounded known envelopes, never return messages/raw/prompt or arbitrary tokens."""
    safe, messages = {}, []
    context = {"body_format": "unavailable", "body_bytes": min(len(body), 16385) if isinstance(body, bytes) else 0}
    try:
        if not isinstance(body, bytes) or len(body) > 16384:
            context["body_format"] = "oversized" if isinstance(body, bytes) else "unavailable"
            return safe, messages, context
        if not body:
            context["body_format"] = "empty"
            return safe, messages, context
        compressed = body.startswith(b"\x1f\x8b")
        if compressed:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            body = decoder.decompress(body, 16385)
            if len(body) > 16384 or not decoder.eof or decoder.unused_data:
                context["body_format"] = "compressed_invalid_or_oversized"
                return safe, messages, context
        try:
            document = json.loads(body)
        except (ValueError, UnicodeError):
            context["body_format"] = "non_json"
            # Some gateways return plain validation text. Only fixed classifiers
            # see it; it is never exposed or retained as a message.
            if not body.lstrip().startswith((b"{", b"[")):
                messages.append(body.decode("utf-8", errors="replace")[:4096].lower())
            return safe, messages, context
        context["body_format"] = "gzip_json" if compressed else "json"
        if not isinstance(document, dict):
            context["body_format"] = "unsupported_json_envelope"
            return safe, messages, context
        error = document.get("error")
        if isinstance(error, str):
            messages.append(error[:4096].lower())
        # OpenRouter, native Alibaba, and wrapped validation gateways.
        error = error if isinstance(error, dict) else document
        envelopes = [error]
        detail = document.get("detail")
        if isinstance(detail, str): messages.append(detail[:4096].lower())
        elif isinstance(detail, dict): envelopes.append(detail)
        elif isinstance(detail, list): envelopes.extend(item for item in detail[:8] if isinstance(item, dict))
        metadata = error.get("metadata")
        if isinstance(metadata, dict):
            for field, allowed in (("error_type", ERROR_TYPES), ("provider_code", PROVIDER_CODES), ("provider_name", PROVIDERS)):
                value = metadata.get(field)
                if isinstance(value, str) and value in allowed:
                    safe[field] = value
            raw = metadata.get("raw")
            if isinstance(raw, str) and len(raw) <= 16384:
                try: raw = json.loads(raw)
                except (ValueError, RecursionError): raw = None
            if isinstance(raw, dict):
                nested = raw.get("error")
                envelopes.append(nested if isinstance(nested, dict) else raw)
        for envelope in envelopes:
            code = envelope.get("code")
            if isinstance(code, str) and code in PROVIDER_CODES:
                safe.setdefault("provider_code", code)
            kind = envelope.get("type")
            if isinstance(kind, str) and kind in ERROR_TYPES:
                safe.setdefault("error_type", kind)
            param = envelope.get("param") or envelope.get("parameter")
            location = envelope.get("loc")
            if not param and isinstance(location, list) and all(isinstance(item, str) for item in location):
                param = ".".join(location[1:] if location[:1] == ["body"] else location)
            if isinstance(param, str) and param in PARAMETERS:
                safe["parameter"] = param
            message = envelope.get("message") or envelope.get("msg")
            if isinstance(message, str):
                messages.append(message[:4096].lower())
    except (ValueError, UnicodeError, RecursionError, zlib.error):
        context["body_format"] = "malformed"
        pass
    return safe, messages, context


def _validation_diagnostic(safe, messages, status):
    # Emit fixed constraints, never quotations of attacker-controlled provider prose.
    for message in reversed(messages):
        if "reasoning" in message and any(phrase in message for phrase in (
                "cannot be disabled", "cannot disable", "mandatory", "must be enabled", "does not support disabling")):
            safe.update(parameter="reasoning.enabled", constraint="cannot_disable_reasoning")
            return diagnostic("provider_reasoning_required", "Selected model requires reasoning to stay enabled.",
                "OpenRouter rejected disabling reasoning for this model. The model requires reasoning.enabled=true; reasoning support does not imply it can be disabled.",
                "Use the corrected low-effort readiness test without enabled=false. Adding credits will not fix this validation error.", status=status)
        if "strict" in message and re.search(r"(?:must|only|requires?|required|supports?).{0,45}\btrue\b", message):
            safe.update(parameter="response_format.json_schema.strict", constraint="must_be_true")
            return diagnostic("provider_schema_strict_required", "Provider requires strict JSON-schema mode.",
                "The provider rejected response_format.json_schema.strict because it requires true, not false.",
                "Use the corrected Qwen schema request and test once; adding credits will not fix this HTTP 400.", status=status)
        if "enable_thinking" in message and ("restricted to true" in message or "must be true" in message):
            safe.update(parameter="enable_thinking", constraint="must_be_true")
            return diagnostic("provider_thinking_required", "Selected endpoint requires thinking mode.",
                "The provider rejected enable_thinking=false; this endpoint requires enable_thinking=true.",
                "Use compatible reasoning and output settings; do not automatically increase the approved budget.", status=status)
        if ("enable_thinking" in message or "thinking mode" in message) and (
                "not supported" in message or "must be false" in message) and ("json" in message or "response_format" in message):
            safe.update(parameter="enable_thinking", constraint="json_mode_requires_false")
            return diagnostic("provider_json_thinking_conflict", "Endpoint rejects JSON mode with thinking enabled.",
                "The provider requires thinking disabled for this JSON output mode.",
                "Use compatible reasoning settings while retaining local schema validation and approved budgets.", status=status)
        if "messages" in message and "json" in message and "must contain" in message:
            safe.update(parameter="messages", constraint="must_contain_json_keyword")
            return diagnostic("provider_json_prompt_required", "JSON output mode requires a JSON instruction.",
                "The provider requires the word JSON in the messages for response_format=json_object.",
                "Include the fixed JSON output instruction; no account credit change is needed.", status=status)
        if "json_schema" in message and ("not supported" in message or "unsupported" in message):
            safe.update(parameter="response_format.type", constraint="json_schema_not_supported")
            return diagnostic("provider_schema_mode_unsupported", "Endpoint does not accept JSON-schema output.",
                "The selected endpoint rejected response_format.type=json_schema.",
                "Select an endpoint with JSON-schema support; iCheck will not silently downgrade validation.", status=status)
        if "schema" in message and ("invalid" in message or "not permitted" in message or "not allowed" in message):
            safe.update(parameter="response_format.json_schema.schema", constraint="invalid_schema")
            for keyword in ("additionalproperties", "required", "anyof", "oneof", "$ref", "$defs", "patternproperties", "propertynames"):
                if keyword in message:
                    safe["schema_keyword"] = {"additionalproperties": "additionalProperties", "anyof": "anyOf", "oneof": "oneOf", "patternproperties": "patternProperties", "propertynames": "propertyNames"}.get(keyword, keyword)
                    break
            suffix = " Rejected schema keyword: " + safe["schema_keyword"] + "." if "schema_keyword" in safe else ""
            return diagnostic("provider_json_schema_invalid", "Provider rejected the JSON schema.",
                "The provider reported an invalid response_format JSON schema." + suffix,
                "Correct the reported schema constraint; keep local validation and do not retry the same invalid payload.", status=status)
    if safe.get("parameter"):
        return diagnostic("provider_parameter_invalid", "Provider rejected a request parameter.",
            "The provider reported invalid parameter: " + safe["parameter"] + ". Its value and raw message were withheld.",
            "Correct this parameter before retrying; HTTP 400 is not a credit-shortage response.", status=status)
    return None


def batch_model(model_name: str) -> bool:
    return model_name.lower().endswith(":batch")


def diagnostic(code, summary, cause, recommendation, *, status=None):
    return {"contract": "icheck.ai-runtime-diagnostic/v1", "code": code,
            "summary": summary, "cause": cause, "recommendation": recommendation,
            "upstream_status": status, "stage": "ai_inference"}


def batch_diagnostic():
    return diagnostic("batch_model_not_interactive", "Batch-only model cannot run an interactive Agent.",
        "The selected :batch variant requires an asynchronous Batch API; iCheck's Agent uses synchronous chat completions.",
        "Choose the non-batch model, test inference, then approve replacement of the affected routes.")


def provider_diagnostic(status: int, body: bytes = b"", *, model_name=""):
    # Classify a bounded response using known phrases; no provider message ever escapes.
    safe, messages, context = _error_evidence(body)
    message = " ".join(messages)
    if batch_model(model_name):
        result = batch_diagnostic(); result["upstream_status"] = status; return result
    if status == 400:
        result = _validation_diagnostic(safe, messages, status)
        known = result is not None and "constraint" in safe
        if result is None:
            result = diagnostic("provider_bad_request", "Provider rejected the inference request (HTTP 400).",
                "The provider rejected request validation. No specific safe validation constraint was returned or recognized; the exact rejected field is unknown.",
                "Inspect the safe provider error code and correct request compatibility. Do not add credits or repeatedly retry this unchanged payload.", status=status)
        result.update(provider_error=safe, root_cause_known=known,
            evidence_source="provider_validation" if known else "provider_error_metadata" if safe else "http_status_only",
            diagnostic_context=context)
        return result
    mappings = {
        401: ("provider_key_rejected", "AI provider rejected authentication.", "The inference API key is invalid, expired or revoked.", "Replace the saved inference key and verify it in AI settings."),
        402: ("provider_credit_required", "AI provider requires credit.", "The provider rejected the request because its billing or key spending limit was reached.", "Review provider credit and key limits; do not change device credentials."),
        403: ("provider_access_denied", "AI provider denied this request.", "Provider account, policy or model access restrictions blocked inference.", "Review the provider's access policy and selected model."),
        404: ("provider_endpoint_unavailable", "AI provider found no eligible inference endpoint.", "The model, provider routing, account policy or required request parameters have no eligible endpoint.", "Choose a synchronous model and run Test model inference; review provider routing and data policy if it still fails."),
        429: ("provider_rate_limited", "AI provider rate limit reached.", "The provider rejected inference due to a rate or capacity limit.", "Wait before retrying, or configure an explicitly approved fallback model."),
    }
    if status == 404 and ("data policy" in message or "privacy" in message):
        return diagnostic("provider_policy_no_endpoint", "Provider policy excludes all eligible endpoints.",
            "OpenRouter reports that the account's data/privacy policy leaves no eligible provider.",
            "Review OpenRouter data policy or choose an eligible model; iCheck will not weaken your policy.", status=status)
    if status == 404 and ("support" in message and ("parameter" in message or "tool" in message)):
        return diagnostic("provider_parameters_no_endpoint", "No endpoint supports the required model parameters.",
            "The provider could not route this structured-output request to a compatible endpoint.",
            "Choose a model with synchronous JSON-schema support and test inference.", status=status)
    values = mappings.get(status, ("provider_request_rejected", "AI provider rejected inference.",
        f"The provider returned HTTP {status}; no successful model response was received.",
        "Test the model in AI settings and review provider availability; retry only within approved budgets."))
    return diagnostic(*values, status=status)


def diagnostic_text(value):
    return f"{value['summary']} {value['cause']} Next: {value['recommendation']}"
