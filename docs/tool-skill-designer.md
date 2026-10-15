# Tool and Skill Designers

## Product boundary

### Executable extension requirement

The deployed r19.8 authoring path generates executable Netmiko extension packages in the same Studio
conversation. Managed test/install/register, disablement and rollback now have
implementations in Studio and the existing agent runtime. Rendered fixture
checks passed creation, revision, target tests, installation, backup download,
restore and disablement. Native deployment and installed stdio/sandbox checks
passed; real-target qualification remains. It is not an external-IDE task for the user.

Choose **Create with AI → Create a plugin or MCP server** from the Studio library.
The first package implements `get_interface_status` and `backup_configuration`
over Netmiko using an inventory target and protected SSH credential reference.
Backups are device reads with protected platform storage writes: configuration
contents can contain secrets and must not be returned verbatim to chat or logs.
Return a protected backup reference, timestamp and result summary.

The generated version contains implementation source, bounded dependency
declarations, typed tool schemas and checks. Build and execute it in a dedicated
unprivileged native process with bounded resources and target access. Generated
code never runs in the control plane or receives credentials. Trusted platform
services authorize targets and hold encrypted secrets and backups. Reuse
the existing artifact history, credential grants and Tool Registry; tool calls
participate in the existing LangGraph runtime.

After AI preview and automatic fixture checks, **Approve and install** orchestrates
packaging, isolated startup, live tool discovery/schema validation and registry
binding behind one reviewed action. Report partial failures with a repair action;
do not label generated code as an installed or callable server. Keep technical
details under Advanced. The library exposes installation state and active/latest
versions. **Manage server** opens package approval and lifecycle controls.
Optional device tests and backup history have a separate page; shared access
settings belong to Assets. Installation does not require a test or target list.
**Conversations** retains authoring sessions independently of installation.
No core source edit or product release is needed per plugin.

Configuration changes/restores are separate change tools with explicit target
approval and verification. Installing a plugin grants no blanket device-write
permission. Acceptance requires creating, using and revising a working extension
entirely in the product, including a real interface result and retrievable backup
on a target chosen by the engineer. This real-target acceptance is still pending.

### Register native SSH targets

Add device supports SSH with `configuration.verification_mode = "studio"`.
For existing inventory without SSH, `POST /api/v1/assets/devices/{id}/native-ssh`
adds a register-only connection with a current device revision, port and managed
SSH-password reference for the same site. Device settings exposes this action.
Neither action contacts the target or queues a Collector preflight. Registration
is not successful verification: the connection remains `not_requested`, with no
next-verification time, until selected native tools are tested separately.
Connection re-enablement and identity correction preserve this boundary. Legacy
Collector SSH retry is rejected for these bindings. Monitoring labels them
On-demand tools rather than pending or successfully scraped.

### Conversational package generation

`POST /api/v1/capability-studio/sessions/extensions` starts the new **Create a
plugin or MCP server** task. Shared generate/refine endpoints retain ownership,
usage accounting, immutable versions and retry semantics. Its Artifact kind is
`tool`, with format `icheck.mcp-extension/v1`; existing `icheck.tool/v1` contracts
remain unchanged. No new authoring database schema or second agent loop is needed.

Each package includes an MCP `server.py`, canonical `extension.json`, generated
Python functions under `tools/`, the pinned `netmiko==4.8.0` dependency declaration,
closed output schemas and executable fixtures. Generated functions run under the
existing Landlock/seccomp or Bubblewrap sandbox with no filesystem, network or
process access. They parse trusted acquisition results; they never receive an SSH
connection object or a credential. Fixture validation executes the code rather
than only checking its schema. A separate stdio process implements initialization,
tool discovery and typed calls; fixture results carry an explicit fixture label.

The first Netmiko adapter policy permits full interface/version commands and
three protected configuration-backup reads. It rejects aliases, arbitrary command
parameters, shell operators, configuration changes and unreviewed command families.
New tools can change parsing and schemas inside this policy without core edits;
other acquisition adapters and command families need their own reviewed policies.
This is not general unrestricted Python or arbitrary dependency installation.

Trusted acquisition requires a per-call target/command/driver binding with a
current-authority callback. It uses strict SSH host keys, finite read timeouts,
no SSH agent and no session log. These options follow the
[Netmiko connection API](https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html).
Backup contents go to the protected-storage callback before generated code sees
only the receipt. Generated code cannot change that receipt. Generic template
publication is not presented as installation in Studio.

### Native execution and backup custody source

The native host now installs canonical files atomically into a private,
version-addressed directory and checks the installed catalog through an actual
[MCP stdio subprocess](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio).
Each invocation starts a fresh trusted host with a minimal environment, CPU/memory
limits and a wall-clock deadline. Timeout or authorization failure kills the
process group, including generated-code children. A separate anonymous socket
carries credential resolution, current-authority checks and backup custody;
generated code cannot access it. Credentials are absent from argv, inherited
environment, MCP messages and driver logs. Strict host-key verification rejects
unknown or changed keys; trusted key files cannot be group/world writable.

Raw configurations cross only that private custody channel. The platform stores
them with AES-GCM in `extension_configuration_backups`, using the protected
managed-device key and authenticated namespace, target and version metadata.
Migration `v9b1d3f5h7j0` retains history, enforces PostgreSQL namespace isolation
and blocks a destructive downgrade when backups exist. Receipts contain an ID,
timestamp, checksum and byte count, never the configuration. The download route
`/api/v1/capability-studio/configuration-backups/{id}/download` requires a current
human identity with capability-management and device-read access, returns a
non-cacheable attachment, and records an audit event without the body. It is not
an Agent Tool. Database backups must retain the managed-device key separately.

AI Operator presents a backup card only for a successful `extensions.*` call
with a valid four-field receipt and matching `native_mcp_result` evidence in the
same investigation. The card and Studio tests share a human-triggered download
control using the selected namespace and authenticated browser session. It never
accepts a tool-provided URL or renders configuration contents. Session/workspace
changes discard in-flight results; the endpoint remains authoritative for current
human/device access. Downloading a snapshot does not restore the device.

These paths are deployed in r19.8. The Studio controls connect
selected-target tests to reviewed installation and the Tool Registry. No
autonomous configuration writes or restores are implemented by this adapter.

### Reviewed installation and agent integration

Studio installs a reusable package before any target is needed. At invocation,
the platform resolves an enabled SSH connection and managed credential from
inventory, subject to package policy and the caller's current authority. Saved
host identity and compatibility come from Assets. Local/special addresses and connections pinned to a
remote worker are rejected by this first native adapter. SSH keys and external
secret providers are not yet supported by this credential resolver.

Each tool test retains its exact package hash, target/credential binding, result
and request key. A replay of the same request does not repeat acquisition.
Tests are optional diagnostics, not reusable-package installation authority.
The compatibility API still accepts recent tests for explicitly target-bound
legacy installations; it never silently expands their scope. Backup tests save an encrypted
configuration; raw contents are only available through the protected download.

**Approve and install** reruns isolated fixtures and verifies real stdio discovery,
then atomically binds the
reviewed package to existing `AgentToolRegistration` rows using `managed_mcp`.
Names are `extensions.<artifact-name>.<tool-name>`. The existing model catalog,
Tool executor, Skills and bounded LangGraph loop use this transport; no second
registry or agent loop is introduced. Both initiating and current device scope
and permissions are checked before and during calls. The first tools do not
change monitored infrastructure, although backup tools write protected platform
storage. Failed calls discard uncommitted backup bodies and record failed health.

Installation requires capability-management, tool-administration, device-read
and activation permissions. An installed version remains active while its draft
is edited. Disable removes its tools from model discovery and blocks further
calls, even if its source version has been deprecated. Restore swaps back to the
previous installed version and access policy together; the GUI previews both.
It never restores device configuration. Reusable installations store one policy
instead of enumerating devices, so a thousand-device inventory needs no thousand
installation bindings. Calls still obey existing agent/workflow budgets and access
checks; this is not an unlimited fleet-concurrency claim.

Migration `x1d3f5h7j9l2` adds current and previous policy fields. Null policy retains
old target-bound behavior. A human must explicitly approve inventory access to
upgrade that behavior. Policy approvals are retained and block destructive downgrade.
The initial generated runtime remains Netmiko interface/version reads and protected
backups. Future HTTP/firewall runtime adapters must reuse this package lifecycle.
Arbitrary HTTP/firewall executable generation and autonomous configuration writes
are not claimed by this release.

The library distinguishes installed/disabled MCP tools from published templates.
Health labels describe last startup discovery or last tool outcome, not continuous
availability. Native provisioning must install the pinned extension dependencies
and set `ICHECK_EXTENSION_PACKAGES_ROOT` to an absolute, service-owned mode-0700
directory. SQL migration `w0c2e4g6i8k1` retains installation/test records with
namespace isolation and terminal test-history guards. Both extension migrations,
runtime provisioning and the paired GUI are installed on the preview server.

Native packages select the reviewed `extensions,windows` extras and include the
complete offline wheelhouse. The extension selection adds 13 pinned dependencies
without changing the existing 73 pins. During a backed-up paired upgrade,
`upgrade_engineering_preview.py --enable-native-extensions` provisions
`/var/lib/icheck/extensions` as `icheck:icheck` mode 0700 and adds a fixed
control-plane systemd override for that path. Only the existing API database role
receives access to extension tables; backup bodies are insert/read-only.
The agent worker continues to delegate tool execution through the authenticated
control plane and does not receive storage access or custody keys. Provisioning
does not generate, install, enable or call any device-specific tool.

To try the workflow, add an enabled SSH connection and managed SSH password
credential in Assets, then open Studio and request a Netmiko extension for your
device type. Review the generated tools, select that connection, and supply its
verified public host key. Approve and run each tool's target test; backup tests
save a protected configuration. Review the successful results and choose
**Install and register reviewed version**. Use **Tell AI what to change** for a
new draft; test and install that version separately. **Disable tools** stops
further use, and **Restore previous installed version** restores the reviewed
package and target bindings, not device configuration.

Source verification covers a two-version Studio conversation, real kernel-sandbox
execution, a real stdio child and schema/result matching, command and source
rejection, backup receipt integrity and compatibility with existing tool contracts.
The MCP result shape follows the [structured tool-result contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content).
The host additionally passed real Netmiko/SSH transport checks against a loopback
device simulator, including generated parsing, backup storage and download,
invalid host keys, revocation and deadlines. A disposable PostgreSQL migration
check passed namespace, immutable-history and downgrade guards. The model and
device responses remain simulated; no live AI or lab qualification is claimed.

### Current contract authoring

Capability Studio now authors two additional immutable contract types:

- `icheck.tool/v1` describes an external MCP tool, its schemas, risk,
  permissions, limits, and exact fixtures.
- `icheck.skill/v1` describes a bounded reusable read-only diagnostic agent
  instruction set over existing Tool Registry entries.

Both use the configured `capability.authoring` model route, structured JSON
schema output, prompt-hash audit, immutable Artifact versions, conversational
refinement, and explicit human publication.

This design deliberately does not require every iCheck tool to be MCP. Trusted
platform-native operations remain internal handlers. MCP is the boundary for a
user-authored external tool because it separates the immutable contract from
the external implementation and credential domain.

## Tool contract

The model may define:

- a stable Tool and MCP server/tool name;
- strict object input and output JSON Schemas with
  `additionalProperties: false`;
- observe, diagnose, or change risk plus read-only state;
- for an evidence-gated change Tool, an optional `icheck.change-tool/v1`
  contract naming scalar target/idempotency paths, pre-check, dry-run,
  post-check, rollback Tools and their boolean success paths, plus maintenance-
  window policy;
- required permissions, timeout, and result-size limits; and
- one to ten exact input/output fixtures.

The platform validates every schema, checks every fixture against both schemas,
rejects inline-secret shapes, and enforces that a state-changing contract has
change risk and requires human approval. Generated contracts cannot claim an
internal handler or contain executable code.

Publishing a Tool Artifact does **not** create an `AgentToolRegistration`, make
it model-visible, connect an MCP server, or permit execution. The implemented
MCP Gateway separately registers a server, calls live `tools/list`, proves the
advertised input/output schemas exactly match the published contract, and then
records a reasoned canary activation. Runtime evidence gates human promotion,
and a circuit breach requires fresh attestation before canary recovery. Agent
Workers attach lease-bounded credentials
outside model context and validate structured results before persistence. See
`docs/mcp-gateway.md`.

MCP activation preserves the optional change contract on the Tool Registry
entry. When that Tool is proposed, iCheck resolves and freezes the declared
dependencies and applies the dual-hash, evidence-gated lifecycle described in
`docs/governed-change-plans.md`. A state-changing Tool without this additive
contract remains on the compatibility approval kernel and is not a production-
ready change adapter.

## Diagnostic skill contract

A Skill contains strict input/output schemas, bounded instructions, an allowed
tool list, success criteria, escalation conditions, evidence requirements, and
iteration/tool-call/token budgets. During validation, iCheck resolves each tool
from the live enabled Tool Registry and stores a dependency snapshot containing
its durable ID, transport, risk/read-only state, permissions, schema hashes,
timeout, and result-size limit.

The first Skill contract is diagnostic and read-only. Any missing, disabled, or
state-changing dependency fails validation. Platform policy is explicitly
higher precedence than Skill instructions. A published Skill is selectable on
the AI L1 home and creates an ordinary durable LangGraph investigation with an
immutable Skill snapshot. Input and final structured output are schema-checked;
the model catalog and execution gate both enforce the Skill allowlist; route and
Skill budgets are intersected; and completion requires persisted evidence.

Compatibility is rechecked when the run is created, when the reasoner is built,
and before a tool call. Disabled tools, schema/handler/permission/limit drift,
an unpublished Skill, or a changed dependency snapshot fail closed. Skill input
is represented in the investigation but only its SHA-256 digest is written to
the binding audit event. Published versions created before executable-handler
pinning must be revalidated into a new version before they can run.

## API

```text
POST /api/v1/capability-studio/sessions/tools
POST /api/v1/capability-studio/sessions/skills
GET  /api/v1/skill-runtime/skills
POST /api/v1/skill-runtime/skills/{version_id}/investigations
```

The shared generate, message/refinement, inspect, and publish endpoints handle
the remainder of the lifecycle. Global `capabilities.manage` authorization is
required for mutation; user-supplied actor fields are ignored in required-auth
mode.

## Remaining runtime work

- state-changing skills represented as governed workflows with approval,
  post-check, and rollback rather than free-form skill instructions;
- scheduled or event-triggered Skill runs and runtime-quality analytics;
- broader Skill runtime-quality analytics and direct failure-cohort comparison.
