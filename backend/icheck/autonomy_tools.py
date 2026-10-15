from .autonomy_schemas import CapabilityDiscovery, CapabilityDiscoveryRead, CapabilityNeed, CapabilityNeedRead


def _tool(name, description, input_model, output_model):
    return dict(name=name, handler=name, transport="internal", description=description,
        input_schema=input_model.model_json_schema(), output_schema=output_model.model_json_schema(),
        risk_level="observe", read_only=True, required_permissions=["investigations.read"],
        timeout_seconds=15, max_result_bytes=150000, enabled=True, created_by="system.bootstrap")


AUTONOMY_TOOLS = (
    _tool("investigation.discover_capabilities", "Discover authorized installed tools and published reusable Skills/Workflows. "
          "Checks catalog availability and public research configuration without device contact or model calls.",
          CapabilityDiscovery, CapabilityDiscoveryRead),
    _tool("investigation.request_capability", "Save a missing-capability brief for human review in Studio, linked to this investigation. "
          "Does not generate, install, execute or grant permission. Use when existing tools cannot perform a needed operation.",
          CapabilityNeed, CapabilityNeedRead),
)
