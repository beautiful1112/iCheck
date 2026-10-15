"""Studio generation and immutable executable package validation."""
import json
from uuid import UUID

from ..collector_schemas import ArtifactCreate
from ..extension_schemas import (EXTENSION_FORMAT, EXTENSION_RUNTIME, BACKUP_OUTPUT, DEVICE_INPUT,
    GeneratedExtensionSpec)
from ..models import Artifact, CapabilityStudioSession, utcnow
from ..sandbox import execute_extension_tool, POTENTIAL_SECRET_LITERAL
from ..schema_validation import validate_instance
from .audit import record_audit_event
from .tool_skills import _strict_object_schema


EXTENSION_PROMPT = """Create an executable iCheck MCP extension for the engineer's task.
Return the required JSON model, including actual Python implementation source for each tool,
the pinned netmiko==4.8.0 dependency, typed output schemas and synthetic executable fixtures.
The supported native runtime is Netmiko read-only acquisition followed by isolated generated Python.
Choose the requested supported SSH device_type, never invent a different vendor or use telnet.
Each tool has fixed reviewed show/display commands. Do not use shell operators, interactive
configuration, arbitrary command parameters, credentials, file paths or network code.
Full read commands are show interface(s) optionally followed by status/brief/description/descriptions/terse,
show ip interface brief, show version, display interface optionally followed by brief,
display ip interface brief, display version. No abbreviations. Other command families are unsupported.
Every callable tool accepts only device_id; the platform resolves current scope and protected SSH credentials.
Generate one reusable server package containing all requested tools, not one server per tool or device.
Installation is a package-level human approval after automated fixtures and runtime discovery.
Do not ask users to configure internal dependencies or select/test devices as an installation prerequisite.
Device access is shared inventory configuration; optional live tests are separate from installation.
source defines transform(records, configuration): records is a list of command output strings;
configuration contains device_id. Return one JSON object matching output_schema. You may define
helper functions; no imports/classes/while/try/raise/decorators, dunder/private attributes,
file/network/process calls or credential handling. Supported builtins: abs all any bool dict
enumerate float int isinstance len list max min range round set sorted str sum tuple zip.
Supported methods: append copy count endswith extend get index items join keys lower replace
split startswith strip upper values. Use bounded for-loops and explicit parsing.
Include a get_interface_status tool if requested. Configuration backups use operation backup,
one of show running-config, show configuration, display current-configuration; never a read tool.
Backup source receives only [protected_backup_receipt], NOT raw configuration. Return records[0]
unchanged. Use exactly the supplied backup_output_schema. Read fixtures use command-output strings
in readings. Backup fixtures use exactly one synthetic receipt JSON OBJECT in readings and that same
object as expected_output, never JSON-encoded strings, configuration text or credentials.
Explain unsupported writes in description, never claim to implement them.
Refinement revises the existing package in the same conversation. Generation/fixture validation
does not imply installation, registration, live-target verification or permission to configure devices.
"""


def extension_documents(spec):
    spec = GeneratedExtensionSpec.model_validate(spec)
    document = spec.model_dump(mode="json")
    serialized = json.dumps(document, sort_keys=True, ensure_ascii=True, indent=2) + "\n"
    if len(serialized.encode()) > 262_144 or POTENTIAL_SECRET_LITERAL.search(serialized):
        raise ValueError("Extension package is oversized or contains potential credential literals")
    files = {"server.py": "from icheck.extension_runtime import package_main\n\nif __name__ == '__main__':\n    package_main(__file__)\n",
        "extension.json": serialized, "requirements.txt": "netmiko==4.8.0\n"}
    files.update({f"tools/{tool.name}.py": tool.source for tool in spec.tools})
    return ({"format_version": EXTENSION_FORMAT, "spec": document},
        {"runtime": EXTENSION_RUNTIME, "entrypoint": "server.py", "files": files},
        [{"tool": tool.name, **fixture.model_dump(mode="json")} for tool in spec.tools for fixture in tool.fixtures])


def validate_extension_contract(definition, implementation, tests, *, sandbox_executor=None):
    if set(definition) != {"format_version", "spec"} or definition["format_version"] != EXTENSION_FORMAT:
        raise ValueError("Executable extension definition is invalid")
    spec = GeneratedExtensionSpec.model_validate(definition["spec"])
    expected = extension_documents(spec)
    if (definition, implementation, tests) != expected:
        raise ValueError("Executable package differs from its reviewed source and tool contract")
    from .collectors import assert_no_inline_secrets
    assert_no_inline_secrets(spec.model_dump(mode="json"), "extension specification")
    reports = []
    for tool in spec.tools:
        _strict_object_schema(tool.output_schema, "extension output schema")
        for fixture in tool.fixtures:
            if len(fixture.readings) != len(tool.commands):
                raise ValueError("Fixture must represent every declared command")
            if tool.operation == "backup":
                validate_instance(fixture.readings[0], BACKUP_OUTPUT, "synthetic protected backup receipt")
                UUID(fixture.readings[0]["backup_id"])
            elif any(not isinstance(item, str) for item in fixture.readings):
                raise ValueError("Read fixtures require command output strings")
            result = execute_extension_tool(tool.source, fixture.readings,
                {"device_id": "00000000-0000-4000-8000-000000000001"}, executor=sandbox_executor)
            validate_instance(result, tool.output_schema, "generated fixture output")
            assert_no_inline_secrets(result, "generated fixture output")
            if result != fixture.expected_output:
                raise ValueError("Generated implementation did not match its fixture")
            if tool.operation == "backup" and result != fixture.readings[0]:
                raise ValueError("Generated implementation changed the backup receipt")
            reports.append({"tool": tool.name, "fixture": fixture.name, "passed": True})
    return {"runtime": EXTENSION_RUNTIME, "isolation": "native_kernel_sandbox", "fixture_results": reports,
        "fixture_count": len(reports), "tool_names": [item.name for item in spec.tools],
        "dependencies": spec.dependencies, "input_schema": DEVICE_INPUT, "device_type": spec.device_type,
        "required_permissions": ["assets.read", "investigations.create"], "package_generated": True,
        "installed": False, "registered": False, "target_tested": False,
        "activation": "reviewed_native_install_required"}


def generate_extension(db, session, *, actor, generation, generator=None):
    from .capability_studio import _message
    generated = (generator or generation).generate(route_purpose=session.route_purpose,
        response_model=GeneratedExtensionSpec, schema_name="icheck_generated_mcp_extension",
        system_prompt=EXTENSION_PROMPT,
        prompt_document={"brief": session.brief, "current_spec": session.current_spec or None,
            "backup_output_schema": BACKUP_OUTPUT,
            "conversation": [{"role": row.role, "content": row.content} for row in session.messages[-20:]]},
        entity_type="capability_studio_session", entity_id=session.id, actor_id=actor)
    spec = GeneratedExtensionSpec.model_validate(generated.document.model_dump())
    if session.artifact_id:
        artifact = db.get(Artifact, session.artifact_id)
        if artifact is None:
            raise ValueError("Studio artifact no longer exists")
        spec = spec.model_copy(update={"artifact_name": artifact.name})
    session = generation.save_spec(spec)
    definition, implementation, tests = extension_documents(spec)
    artifact, version = generation.candidate(ArtifactCreate.model_validate({
        "name": spec.artifact_name, "kind": "tool", "description": spec.description, "owner": actor,
        "labels": {"generated": True, "studio_session_id": session.id, "format": EXTENSION_FORMAT},
        "initial_version": {"definition": definition, "implementation": implementation,
            "tests": tests, "created_by": actor}}))
    version = generation.validate(version, actor)
    session = db.get(CapabilityStudioSession, session.id)
    session.status, session.updated_at = "validated", utcnow()
    db.add(_message(session, role="assistant", content=(
        f"Generated executable MCP package {artifact.name}, version {version.version}, with "
        f"{len(spec.tools)} tools. Generated Python passed {version.validation_report['fixture_count']} "
        "isolated fixture checks. Review code, dependencies and commands under Advanced. "
        "This package is not installed, registered or tested against a real target."),
        structured_content={"spec": session.current_spec, "artifact_id": artifact.id,
            "artifact_version_id": version.id, "validation_report": version.validation_report}))
    record_audit_event(db, event_type="capability.extension.generated", actor_type="user", actor_id=actor,
        entity_type="capability_studio_session", entity_id=session.id,
        details={"artifact_id": artifact.id, "artifact_version_id": version.id,
            "tool_count": len(spec.tools), "fixture_count": version.validation_report["fixture_count"]})
    return generation.finish()
