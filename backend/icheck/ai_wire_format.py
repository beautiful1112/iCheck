"""Keep the readiness probe and interactive Agent on the same output contract."""
from .langgraph_runtime import GraphDecision


def graph_response_format(base_url: str, model_name: str) -> dict:
    # Alibaba's Qwen JSON-schema mode uses strict=true, including optional fields
    # and local references. Other providers retain their existing flexible mode.
    qwen = base_url.rstrip("/") == "https://openrouter.ai/api/v1" and model_name.lower().startswith("qwen/")
    return {"type": "json_schema", "json_schema": {"name": "icheck_graph_decision",
        "strict": qwen, "schema": GraphDecision.model_json_schema()}}
