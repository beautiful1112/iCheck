"""Wire adapters only. Authorization, quotas and tool execution stay in iCheck.

Claude's result tool is a JSON envelope, never an executable IT/MCP tool.
Every caller still validates the complete local result schema before using it.
"""
from copy import deepcopy
import json

from .ai_provider_presets import preset_for_url

RESULT_TOOL = "icheck_structured_result"


def prepare_completion(provider_type, base_url, payload):
    body = deepcopy(payload)
    preset = preset_for_url(base_url)
    if provider_type == "anthropic":
        if set(body) - {"model", "max_tokens", "max_completion_tokens", "stream", "messages", "response_format",
                        "temperature", "top_p", "top_k"}:
            raise ValueError("Native Anthropic custom parameters support only temperature, top_p and top_k; unsupported parameters were not sent")
        schema = body["response_format"]["json_schema"]["schema"]
        systems = [m["content"] for m in body["messages"] if m["role"] == "system"]
        systems.append("Return your complete structured result through icheck_structured_result exactly once. "
                       "This is an output envelope, not an operational tool call. Do not return prose instead.")
        native = {"model": body["model"], "max_tokens": body.get("max_completion_tokens", body.get("max_tokens", 4096)),
                  "stream": False, "system": "\n\n".join(systems),
                  "messages": [m for m in body["messages"] if m["role"] != "system"],
                  "tools": [{"name": RESULT_TOOL, "description": "Return the final structured response; no action is executed.",
                             "input_schema": schema}],
                  "tool_choice": {"type": "auto", "disable_parallel_tool_use": True}}
        for key in ("temperature", "top_p", "top_k"):
            if key in body:
                native[key] = body[key]
        return base_url + "/messages", native
    if preset and preset.id in {"deepseek", "qwen_cn", "qwen_sg"}:
        schema = body["response_format"]["json_schema"]["schema"]
        body["response_format"] = {"type": "json_object"}
        body["messages"].append({"role": "user", "content": "Return only a JSON object satisfying this JSON Schema: "
                                 + json.dumps(schema, separators=(",", ":"))})
        # Direct Qwen JSON mode requires non-thinking mode. OpenRouter is untouched.
        if preset.id.startswith("qwen_"):
            body["enable_thinking"] = False
    if preset and preset.id in {"openai", "gemini"}:
        # iCheck schemas include open dictionaries; do not claim strict-subset
        # compatibility. The full Pydantic schema remains enforced on receipt.
        body["response_format"]["json_schema"]["strict"] = False
    if preset and preset.id == "openai" and "max_tokens" in body:
        body["max_completion_tokens"] = body.pop("max_tokens")
    return base_url + "/chat/completions", body


def normalize_completion(provider_type, document):
    if provider_type != "anthropic" or not isinstance(document, dict):
        return document
    usage = document.get("usage")
    total = None
    if isinstance(usage, dict):
        counts = [usage.get("input_tokens"), usage.get("output_tokens"),
                  usage.get("cache_creation_input_tokens", 0), usage.get("cache_read_input_tokens", 0)]
        if all(type(n) is int and 0 <= n <= 1_000_000_000 for n in counts):
            total = sum(counts) if sum(counts) <= 1_000_000_000 else None
    content = document.get("content")
    calls = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"] if isinstance(content, list) else []
    result = None
    if (document.get("stop_reason") == "tool_use" and len(calls) == 1
            and calls[0].get("name") == RESULT_TOOL and isinstance(calls[0].get("input"), dict)):
        result = json.dumps(calls[0]["input"])
    # Invalid/truncated results retain reported usage so failed calls are charged
    # against local budgets; they never become successful decisions.
    return {"usage": {"total_tokens": total},
            "choices": [{"message": {"content": result}, "finish_reason": document.get("stop_reason")}],
            **({"error": document["error"]} if "error" in document else {})}
