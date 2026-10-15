"""Protocol dispatch for the small shared declarative monitoring contract."""
from .http_monitoring_templates import HTTPTemplateDefinition, SCHEMA
from .snmp_monitoring_templates import SNMPTemplateDefinition
from .exporter_monitoring_templates import ExporterTemplateDefinition


def parse(definition):
    if definition.get("plugin") == "http": return HTTPTemplateDefinition.model_validate(definition)
    if definition.get("plugin") == "snmp": return SNMPTemplateDefinition.model_validate(definition)
    if definition.get("plugin") in {"linux","windows","containers","vmware"}: return ExporterTemplateDefinition.model_validate(definition)
    raise ValueError("Unsupported monitoring template plugin")


def validate_contract(definition, implementation, tests, collector):
    plugin = parse(definition).plugin
    if plugin == "http":
        from .http_monitoring_templates import validate_contract as validate
    elif plugin=="snmp":
        from .snmp_monitoring_templates import validate_contract as validate
    else:
        from .exporter_monitoring_templates import validate_contract as validate
    return validate(definition, implementation, tests, collector)
