"""Conservative interactive Qwen defaults, independent of advertised capacity."""
QWEN_OUTPUT_LIMIT = 4096


def qwen_runtime_parameters(base_url: str, model_name: str, parameters: dict, remaining_tokens: int) -> dict:
    result = dict(parameters)
    if base_url.rstrip("/") != "https://openrouter.ai/api/v1" or not model_name.lower().startswith("qwen/"):
        return result
    output = result.get("max_completion_tokens", result.get("max_tokens", QWEN_OUTPUT_LIMIT))
    result.pop("max_completion_tokens", None)
    result["max_tokens"] = min(output, QWEN_OUTPUT_LIMIT, remaining_tokens)
    # The affected model advertises mandatory reasoning and minimal effort.
    # Do not infer effort support from the qwen vendor prefix for other models.
    if model_name.lower() == "qwen/qwen3.8-max-0902":
        result.pop("reasoning_effort", None)
        result["reasoning"] = {"enabled": True, "effort": "minimal"}
    return result
