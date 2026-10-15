# Capability Studio

## Engineering preview as of 14 October 2026

### Library and authoring navigation

The deployed r19.23 release separates reusable MCP installation from device access and
makes Monitoring resource-centric. Its SQL migration is `x1d3f5h7j9l2`. Capability
Studio opens at `/studio` with a categorized library: Data collectors,
MCP servers, Function tools, Workflows & skills, and Other capabilities. It combines
versioned artifacts, registered agent tools and external MCP connections. Search
and category filters operate on the loaded registries. The overview shows up to
six entries per category; opening a category reveals more in bounded batches.
Registry limits and unavailable sources are reported instead of implying a
complete or empty inventory.

Generated MCP cards distinguish **Not installed**, **Installed · Enabled**,
**Installed · Disabled**, and **Installation status unavailable**. The active
version is separate from the latest draft and last recorded runtime check.
Published collector templates do not imply enabled monitoring, and an enabled
external MCP connection does not prove that its server is healthy.

The deployed package hierarchy update shows **one server with its contained tools** on
the library card and setup page. Installation is package-wide, not per tool.
Never-validated MCP drafts are collapsed separately, with their conversation and
version history preserved; they do not increase the main server-package count.
An installed, deprecated, or previously validated package remains manageable.
The two historical Cisco entries are separate authoring attempts, each already
containing both interface-status and configuration-backup tools. The first failed
draft is retained; the successful `example-interface-backup` package has
two validated versions and is not installed. No artifact merge or deletion is
needed to represent a single two-tool server.

**Create with AI** opens `/studio/builder`. **Conversations** opens the saved
session list at `/studio/conversations`; each session has its own builder URL.
The conversation page contains one session, its preview and revision controls,
without a capability sidebar or an inline MCP installation form. Grafana agent
sessions remain available in AI Operator history. Existing `/studio?session=…`,
investigation and pinned-template links redirect to the corresponding builder.

**Manage server** opens `/studio/mcp?artifact=…` independently of a conversation.
It displays the tools, version and installation state. **Approve and install**
performs isolated fixture validation, packages the server, checks actual MCP startup
and discovery, and registers all tools together. No target selection, SSH setup or
live device test is required. The summary discloses inventory access, read-only
commands and protected backup storage. Managed processes start on demand; ready
does not mean a continuously running daemon or proven device reachability.

The installation stores an approved inventory policy, not a list of tested devices.
At each invocation, the executor intersects that policy with the initiating and
current caller's permissions, then resolves the device's saved connection,
credential, fingerprint and compatibility profile. The binding is frozen and
rechecked during that call. Adding devices or rotating credentials does not require
reinstalling the package. Missing device access produces a setup error pointing to
Assets. Existing target-bound installations retain their authority until explicitly
reapproved; rollback restores the previous version and its policy together.

**Advanced** contains version/disable/restore controls and a link to the separate
optional test and backup-history page. These tests contact a selected device, but
are never an installation gate. Browsing or installing never calls a paid model
or a device. Installation creates no schedules and grants no device-write authority.

The deployed SSH identity update replaces manual key entry with **Read device fingerprint**
and **Confirm and save fingerprint**. Reading performs one bounded key exchange
with the selected inventory IP/port, without resolving credentials, authenticating
or executing a command. A first-use fingerprint is an observation, not independent
proof of ownership. The human explicitly confirms trust; only then is the public
identity saved on that connection. Reopening the page reuses it without another
network request. Every Netmiko connection still verifies the exact saved key.
Changed keys or target identities need replacement review; stale confirmation
cannot overwrite newer device, credential or identity state. No SQL migration is
needed. Existing API clients may still supply an independently verified key when
no identity has been saved; they cannot override a saved or stale identity.

The selected saved SSH credential is reused without asking for it again. A device
with no inventory site inherits its credential's exact connection scope, without
being assigned a physical site or changing SNMP. Explicit site conflicts and
extra remote-worker selectors still fail. The target picker searches names/IPs
and shows the saved credential name. Source, local SSH-simulator and rendered
fixture checks cover this behavior. The release contains no registered SSH
target or saved SSH credential. Verify your own device's supported algorithms
and approved connection profile before testing it.

### Device specific legacy SSH

The r19.22 release added **Connection profile**. In r19.23 it lives under
**Assets → device settings → Device access**, shared by every MCP package.
Keep **Modern SSH** for normal targets. For an older switch, select
**Legacy Cisco — group14 / SHA-1**, accept the device-specific risk and click
**Save SSH profile**. Read and confirm its fingerprint before first device use.
Selecting or saving a profile does not connect to the device, trust a key or run
a tool. Switch back to Modern SSH with the same control when compatibility is no
longer needed. Profile changes invalidate frozen calls and legacy target-bound
installations. Reusable installations resolve the current profile on their next
call; the package itself needs no reinstallation.

`legacy_cisco_v1` adds DH group14/SHA-1, RSA/SHA-1 host signatures, AES-CBC and
HMAC-SHA1 while preferring modern algorithms. It does not support group1-only,
DSA-only, 3DES-only or MD5-only devices, SSHv1, or unrestricted algorithm strings.
Legacy CBC is never paired with ETM MACs. Modern mode uses SHA2 MACs and AES CTR/GCM.
Both modes retain strict host-key checking, credential custody, fixed commands,
timeouts, sandboxing and current authorization. There is no automatic downgrade.

This human-only, audited exception is stored on the selected SSH connection and
bound to its device ID, connection ID, address, port and identity revision. If the
target changes, it must be reviewed again. It is not a credential-wide, site-wide,
system SSH or fleet setting. It covers native Studio MCP discovery and Netmiko
tools; existing AsyncSSH collectors keep their separate deployment policy.

The adapter retains Paramiko 5.0.0 and Netmiko 4.8.0. Small connection-local
subclasses select the legacy hash algorithms using the library's existing DH and
RSA implementations; they do not patch global maps or downgrade dependencies.
Paramiko 5 removed the legacy defaults ([upstream changelog](https://www.paramiko.org/changelog.html));
the explicit adapter and wire tests must be reviewed when updating that dependency.
Real-device qualification is installation-specific. Test interface retrieval
and protected backup behavior only on an authorized target. Both tools belong
to one package; a historical test is not permission for a future device action.

This library-first layout supersedes the earlier conversation-first landing page.
It retains the existing authoring, runtime, permissions and database contracts.

**Deployed in r19.8:** **Create a plugin or MCP server** provides
executable code, dependencies, typed tools, isolated fixture execution and conversational
revision in the existing versioned Artifact system. The native runtime includes private package installation,
a bounded native MCP process, encrypted backup storage and human-only downloads.
The original r19.8 controls required selected-target tests before installation;
r19.23 replaces that workflow with package approval and dynamic device resolution.
The existing executor continues enforcing target and credential custody. The
r19.22 Cisco qualification above covers real reads and backup acquisition,
not a full live-agent fleet workflow.
The first extension uses Netmiko for interface checks and protected configuration backups;
see [Tool and Skill Designers](tool-skill-designer.md#executable-extension-requirement).
It reuses this builder and library rather than requiring an external IDE. Code and
dependency details stay under Advanced; draft validation is shown separately from
installation and registration status. Generating or publishing
a draft alone does not make its tools available to the AI Operator.

The separate builder offers Monitor a device or API,
Build a dashboard and Automate a check, with workflow/Skill/tool inference from
the request. Definitions, source formats, permission/runtime details and version
history are under Advanced. Real model/target acceptance is
separate from deployment. The
[development goal](codex-goal.md) and [Grafana design](grafana-monitoring-design.md)
supersede the old visualization and Service Intelligence direction below.

Monitoring target selection supports case-insensitive name/address search across
all six native monitoring plugins. Results stay bounded to 100 enabled, authorized
connections of the selected protocol. A new search clears the previous selection,
evidence and approval; late responses cannot restore older choices. Searching is
read-only and does not test or enable a target.

API response, OpenAPI GET, fixed SSH-output and MIB-proposal inputs reuse existing
authoring APIs and immutable generation/publication guards. No sample is
prefilled as collected data. The preview shows requested target, interval,
credential reference, outputs/steps, validation result and next action. Saving
requires review of the exact validated version; publication does not enable a
target or prove fresh samples. MIB proposals remain blocked from publication.

Dashboard tasks use the existing LangGraph worker inside Studio, with a
`grafana-dashboard` task scope restricting execution to native read/propose and
bounded metric-query tools. They cannot enroll devices, run probes, change
infrastructure or apply Grafana edits. Proposal cards open the single-confirmation
review page; conversational revisions refer to the retained change ID. Uncertain
writes require inspection before another revision. No separate agent loop was
added to the browser.

The library searches bounded registries, shows published versions separately
from installation state, and links authored capabilities to their conversations
and version history. Workflow/Skill links pin a published version and
prefill the Operator without starting a run. Older report/visualization sessions
remain readable, without new authoring or chart rendering. Template disablement
and live target health remain on the corresponding device/runtime pages rather
than being inferred from publication status.

Reusable workflow and Skill inputs now use ordinary fields on the Operator.
Device references have an authorized inventory selector, enums have choices and
numeric/boolean values retain their types. Only declared defaults are populated;
no device or false/zero value is invented to make a run look ready. Nested or
mixed-type input remains editable under Advanced JSON and schema. The server
still validates the complete contract, current dependencies, permissions and
budgets before queueing a run. Opening a saved capability does not execute it.

Studio now offers **Prior versions and restore preview** for workflows and Skills.
An earlier definition becomes a new revalidated draft in the same conversation,
with its current preview and publication action updated together. A stale draft
is rejected and a failed validation rolls back the candidate without replacing
the current conversation. Existing published versions, triggers and in-flight
runs remain untouched by the preview. Restoring does not call a model or a tool;
the operator must review and save the exact candidate before using it.
Source tests cover conversation creation, revision, restoration, publication and
a fixed-step/bounded-agent-loop run through the existing graph. The model wire
and device inventory are fixtures, not real-device or model-quality acceptance.
See [workflow templates](workflow-templates.md) for the engineer journey.

Focused API/permission tests and native build checks pass; fixture browser checks
cover the new interface. Actual model-backed creation/revision and the complete
exporter installation → selected-target test → continuous Prometheus samples →
Grafana lifecycle are still release gates, not consequences of this UI refactor.
The [HTTP monitoring slice](http-monitoring.md) now uses the same versioned
declarative contract from Studio conversation through a selected-target test,
one reviewed publish/enroll action, fresh-sample verification and native Grafana
proposal. Schema-only drafts need no synthetic sample. Conversational revisions
retain prior immutable versions; the existing history restores a reviewed prior
definition as a new version. Its source/private-fixture checks passed, including
real local HTTP requests and temporary native Prometheus. Live model/device and
fresh Grafana target-dashboard acceptance remain release gates.
SNMP now uses that same Studio journey: select a profile or upload vendor MIBs,
review the native compiled measurements, explicitly install the versioned module,
test every requested metric on a chosen target and review publish/enrollment.
Identity-only verification and exporter `up` are not sufficient. The source/private
SNMP/gateway/Prometheus path is tested; native generator/broker provisioning is
deployed, while model and device acceptance remain pending. The old MIB proposal publication gate is unchanged;
compiled or installed status alone never means enabled monitoring. See
[SNMP module generation](snmp-exporter-attestation.md).

Linux and Windows now use this same source workflow. Studio infers their
monitoring technology, exposes protected authentication/transport settings and
tests the expected measurements and selected collectors before activation.
Actual Linux host metrics passed a private native Prometheus check; Windows
remains fixture-qualified. Both workflows are deployed in the current preview. See
[system exporter monitoring](system-exporter-monitoring.md) for prerequisites,
supported groups and the remaining live acceptance boundaries.

Containers also use the shared source builder and target workflow. The cAdvisor
option exposes exact name/ID selection and an honest source-preview label.
Source timestamps and per-container metric completeness gate collection proof;
native Grafana proposals do not claim workload readiness. See
[container monitoring](container-monitoring.md). Paired deployment is complete;
real runtime qualification remains separate from the private fixture checks.

VMware follows this same builder. Select the exact host, VM or datastore name
and optional datacenter, then test a registered exporter endpoint. The source
preview label distinguishes fixture checks from real-vSphere qualification.
Fresh scrape receipt and object health remain separate; the selected exporter
does not expose original performance timestamps. See
[VMware monitoring](vmware-monitoring.md) for the catalog and prerequisites.

### Engineer journey

The landing page has search, existing capability cards and a **Create** action.
Offer three starting intents: **Monitor a device or API**, **Build a dashboard**,
and **Automate a check**. A user can instead type a request. Do not require
selection among seven implementation-specific designers.

1. **Describe.** Ask only for missing operational facts. Reuse selected devices
   and credential references. Accept vendor documents, MIBs, sanitized samples
   or supported curl syntax. Infer the plugin/template kind. Allow device
   enrollment here or selection from Assets; location remains optional.
2. **Preview.** Show the target, expected measurements/outcome, interval,
   credential reference, permissions and Grafana dashboard. Mark unsupported
   data and missing prerequisites. Show a readable difference for a revision.
3. **Test.** Validate locally, then offer one explicitly selected bounded target
   test. Show the result and correction action. Paid model calls and network
   tests must be visible, not implicit in opening the page.
4. **Enable.** One confirmation covers the displayed collection/dashboard plan.
   Record installation, Prometheus target activation, fresh samples and Grafana
   readiness separately. Partial failure offers a scoped retry or rollback
   without repeating successful steps or duplicating resources.

Keep the conversation and a short result/next-action panel visible; stack them
in task order on narrow screens. Put generated JSON/code, detailed validation,
permissions, dependencies, provenance and version history under **Advanced
details**. A library card shows name, purpose, supported target type, version
and actual enabled/error state, with Use, Edit with AI, Disable and History.

### Reuse the capability lifecycle

Reuse the existing artifact registry and backend validation. A monitoring
template joins versioned exporter/adapter configuration, metric schema,
target/secret references, collection settings, optional rules and a Grafana
dashboard definition. Tools, Skills and workflows reuse the same lifecycle.
Publishing is distinct from enabling, but one reviewed UI action can compose
those backend steps. A tested draft is not evidence of installed monitoring.

AI repair starts from a failed run or missing metric, proposes a revision,
tests it and asks to replace the current assignment. It cannot broaden network
permissions, edit privileged core code or approve its own deployment.

Dashboard authoring produces Grafana definitions and uses Grafana for the real
visual preview. Retire service-indicator visualization/report creation from the
default builder. Keep legacy artifacts readable until a migration is available;
do not create another iCheck chart editor.

### Acceptance

An engineer creates and revises an SNMP or HTTP template, tests it, enables it
and opens fresh Grafana metrics without reading code or editing files. A reusable
workflow is created in conversation and found in the library. Invalid credentials,
unsupported metrics, missing exporters and partial activation each show a clear
next action. Check desktop/narrow-screen flow, keyboard access and progress.
Reuse a focused workflow check instead of a new script for every revision.

## Existing implementation to reuse or retire

The following records the retained backend and historical UI before the redesign.
Legacy route/rendering descriptions below are historical, not supported new
product journeys. They do not require retaining the seven-designer layout or
custom visualization runtime.

The implemented Capability Studio vertical slices are governed conversational
JSON Collector, Workflow Template, Topology View, Service-indicator
Visualization, Service-health Report, MCP Tool Contract, and Diagnostic Skill
Designers. An authorized user can
stay inside iCheck to:

1. describe the collection purpose and provide a representative JSON response,
   or select an exact read-only GET operation from local OpenAPI 3.0/3.1 JSON
   or YAML, or select a platform-owned fixed read-only SSH command profile and
   provide sanitized representative JSON output, or upload one bounded SMI MIB
   to create a non-publishable SNMP Exporter proposal. REST, OpenAPI, and
   fixed-command sessions may also include one bounded plain-text, Markdown,
   or reStructuredText API/vendor document as untrusted design context;
2. ask the configured `capability.authoring` model route for a typed collector
   specification;
3. inspect the proposed contract beside the conversation;
4. compile the contract into an immutable `python_sandbox_v1` draft;
5. execute an exact-output fixture under the real generated-code sandbox;
6. publish the validated version explicitly; and
7. request a conversational refinement, producing another immutable version.

For workflows, the model selects only registered tools and proposes a typed
graph. The platform proves reachability, termination, bounded cycles, input
bindings, permissions, and approval/post-check/rollback dominance before the
same immutable publication lifecycle. Published versions can be launched
manually from the AI L1 home or activated for idempotent Alert-triggered
execution. The durable Workflow reasoner reuses the Agent Worker, evidence,
authorization, budget, checkpoint, and exact-plan approval kernel; see
`docs/workflow-templates.md`.

Completed Investigations can also emit strict evidence-bound Topology or
Service-indicator Visualization proposals. They remain separate from the
authoring session and immutable Artifact lifecycle until a global reviewer
supplies a reason and publishes them from `/studio/proposals` or
`/studio/visualization-proposals`. Preview validation uses the Investigation's
frozen authorization scope; publication revalidates current dependencies and
is atomic. See `docs/investigation-topology-proposals.md` and
`docs/investigation-visualization-proposals.md`.

For topology views, the model receives only aggregate inventory dimensions and
proposes a typed declarative selector/layout contract. The platform resolves
current device and endpoint identities itself, builds a bounded preview from
wired attachment, wireless association, and IP-observation history, and omits
usernames and raw vendor payloads. See `docs/topology-views.md`.

For service-indicator visualizations, the model receives only a bounded safe
catalog of enabled service/indicator keys, display names, kinds, units,
thresholds, and data-presence flags. It proposes line, stat, or status panels;
the platform validates exact selectors, queries normalized observations under
hard time/point budgets, and omits source queries, dimensions, evidence
references, actors, contacts, components, and raw telemetry. Published views
run on the dedicated, scope-filtered `/visualizations` surface. See
`docs/service-indicator-visualizations.md`.

For tools, the model can define only a typed MCP-bound contract with strict
input/output schemas and exact fixtures. Publication does not activate the tool
or insert it into the executable Tool Registry. For skills, the model may
compose only existing enabled read-only tools, whose IDs, schema hashes,
permissions, timeouts, and result limits are pinned into the Artifact. Skills
also require bounded agent budgets, evidence, success criteria, and escalation
conditions. See `docs/tool-skill-designer.md`.

The browser workspace is `/studio`. It is intentionally separate from the AI
L1 home and uses three product surfaces: authoring sessions, conversation, and
the proposed contract/governance gate. Raw device, terminal, and telemetry data
remain on their dedicated evidence pages.

## Authoring ownership and recovery

All seven designers use a durable, namespace-local generation record. A UUID
`request_key` binds one authenticated author, Artifact kind and refinement
intent. Supply the same key when retrying that intent; a new key means an
explicitly new model-backed iteration. Omitting the optional key retains the
legacy new-iteration behaviour and is not an idempotent retry contract.

The platform claims the session before calling the model, but releases database
locks during transport. A 30-minute lease and an unguessable owner fence survive
the model gateway's audit commit. PostgreSQL uses database time for expiry,
`READ COMMITTED` with autocommit disabled, and an enforced namespace for the
whole mutation path. Another live request receives `409` before any model call.
Late responses can account usage but cannot replace a newer request's spec,
candidate, status or messages.

Completed model bytes, schema identity, hashes and known usage are saved before
deterministic compilation. Artifact creation/version allocation and the exact
Studio candidate reference commit together while the Artifact identity lock is
held. The draft remains inspectable if validation fails. Validation, its report,
the assistant message, completion audit and immutable response snapshot commit
together. Request identity, recorded model usage/results, candidate references
and completed snapshots have database write-once guards; generation history
cannot be deleted through the runtime role.

An expired request with saved model bytes can resume under the same key without
another model call. If its draft was already recorded, recovery validates that
exact version and rejects changed compiled content. Without saved bytes, the
external outcome remains uncertain and the old key cannot replay the provider
request. An exact completed-call audit can reconcile known token usage, but
does not reconstruct the missing proposal. Unknown usage is shown as unreconciled,
not zero cost. An operator can deliberately start a new request after reviewing
that uncertainty. Deterministic rejection likewise requires a new key for a new
iteration; it does not overwrite the failed record or its draft.

Retrying a completed request returns its original validated snapshot, even if
the session subsequently advanced or published. This is historical evidence,
not the current head or new publication authority. The UI reloads the current
session after recovery. Publication requires `expected_artifact_version_id`
matching the version the reviewer saw. The Studio owner lock precedes the
Artifact boundary, and publication, session status and its message commit
together. An exact still-current publication retry retains one decision; a
changed or retired candidate fails closed. Publishing still does not activate
tools or collectors or satisfy external SNMP attestation gates.

`GET /api/v1/capability-studio/sessions/{id}/generations` returns bounded
generation metadata, not owner secrets, model documents, prompts or snapshots.
`POST /api/v1/capability-studio/sessions/{id}/generations/{request_key}/retry`
reuses the recorded intent for its authenticated original author. Generate and
refine endpoints also accept the optional key. `/studio` exposes the current
request phase, exact candidate, known usage, retry and deliberate new-iteration
controls. Existing unowned `generating` sessions become `failed` during the
migration with a namespace-local audit; their spec, draft, conversation and
usage are retained. Downgrading recorded generation history is refused.

## Trust boundary

```text
operator intent + sanitized JSON sample
  + HTTP URL OR OpenAPI GET operation OR fixed SSH command-profile identity
  + OR minimized, locally resolved MIB symbol catalog
  + optional sanitized, untrusted source-document context (except MIB)
                    |
                    v
 governed structured-model route (strict JSON schema, budgets, fallback)
                    |
                    v
        GeneratedCollectorSpec, never executable model output
                    |
                    v
 deterministic platform compiler + sample-path/schema/secret validation
                    |
                    v
 immutable ArtifactVersion + exact expected-output fixture
                    |
                    v
 Landlock/seccomp/rlimit process sandbox (no network or credentials)
                    |
                    v
         validated draft --human publish--> published version
```

The model does not generate arbitrary Python. It can propose only the strict
`GeneratedCollectorSpec` fields: artifact metadata, record path and type,
stable identity fields, and bounded source-to-destination mappings. The
platform owns the compiler and runtime template. Every proposed mapping must be
present in the supplied sample; subject and idempotency paths must resolve to a
scalar in every fixture record.

The target URL cannot contain user information, query parameters, or fragments.
Samples and authoring text are rejected for recognized inline-secret shapes.
An optional source document is accepted only for non-MIB Collector sessions as
a complete name/media-type/text tuple. The UTF-8 input is limited to 64 KiB,
2,000 lines, and 4,096 characters per line; supported media types are plain
text, Markdown, and reStructuredText. Private-key material, unsupported control
or Unicode format characters, and invalid filenames fail closed. Recognized
credential literals and password/token/key/authorization assignments are
redacted before persistence or model use. The raw document is not retained.
The API returns only filename, media type, raw-input SHA-256/byte count,
sanitized-context byte count, and redaction count; Artifacts and audit records
contain provenance, never the text. The sanitized text is explicitly marked as
untrusted data in the system prompt: it may clarify field semantics but cannot
add a field absent from the deterministic sample, change policy, authorize a
network action, supply credentials/code, or bypass validation/publication.
For OpenAPI input, the platform accepts at most 1 MB and 250 paths, supports
only 3.0/3.1 documents and GET operations, resolves only bounded local
JSON-pointer `$ref` values, and never performs a specification fetch. Text
input is decoded as strict JSON or safe YAML. YAML anchors, aliases, duplicate
keys, unsafe tags, multiple documents, excessive event count, and excessive
nesting fail closed; common numeric response keys are normalized to strings.
It selects a
successful JSON response, uses its explicit example or deterministically
synthesizes one from the bounded schema, applies the same secret checks, and
stores only a minimized operation summary, source hash, and sample. The full
document and unrelated operations are neither retained nor sent to the model.

Command-output input is deliberately narrower than arbitrary CLI authoring.
The author selects one registered `command_profile`, a hostname/IP and port,
and sanitized JSON output. The profile maps inside trusted platform code to one
exact read-only command; neither the request, model, Artifact, nor deployment
can supply command text. The sample parser rejects non-JSON scalars,
non-finite values, duplicate keys, inline secrets, and input over 500 KB. Only
the parsed sample plus profile/platform/port and sample hash enter the session,
Artifact, and model context; the raw text and command are not retained.

MIB input is a proposal compiler, not an executable configuration path. The
platform accepts one UTF-8 SMI module up to 1 MB, strips comments, bounds symbol
and OID complexity, and resolves only numeric roots and local assignments. It
keeps a source hash plus a minimized catalog containing symbol name, kind,
numeric OID, syntax, access, and index names. Descriptions, notifications,
unresolved symbols, and the raw MIB never enter the model context or persistent
session. The model may select only names from that catalog. Trusted platform
code maps those names back to numeric OIDs and deterministically produces an
`icheck.snmp-exporter-proposal/v1` generator module using the built-in
`snmp_exporter` adapter. Invented names, duplicate OIDs, changed numeric OIDs,
or an unpinned module fail validation.

Every initial MIB-derived version carries an unsatisfied
`external_snmp_exporter_generator_v1` publication gate. Contract validation is
hash-only and deliberately reports `publication_blocked=true`; neither the UI
nor the Artifact API can publish it. An external SNMP Exporter generator must
compile the module, the generated module must be installed, and a live-device
walk/cardinality check must submit a signed attestation. The implemented control
plane verifies the dedicated attestor key, all exact hashes, freshness, bounded
live-scrape counts, and replay nonce before it creates a new immutable
`icheck.snmp-exporter-attested/v1` version. That version still cannot publish
directly: it must pass the ordinary platform Collector canary and human canary
promotion. No model response can satisfy or remove either gate. See
`docs/snmp-exporter-attestation.md`.

The response sample, target URL shape, and minimized operation summary are sent
to the configured model, so
operators must still provide sanitized representative data rather than a raw
production response containing business-sensitive values. Provider and
infrastructure credentials are never included. Provider authentication is
resolved server-side from a credential reference.

The trusted HTTP or SSH adapter owns the future network request or fixed
command and credential injection. The SSH path additionally requires a
deployment credential reference, a Worker target allowlist, and an absolute
existing OpenSSH `known_hosts` file; agent/default-key fallback and keyboard-
interactive authentication are disabled. Generated code receives only normalized JSON envelopes and
non-secret configuration. Publishing does not deploy or activate the collector;
deployment remains a separate scoped, reviewed operation.

## Model and authorization prerequisites

- Configure an allowlisted OpenAI-compatible provider under `/settings/ai`.
- Register a model with both `chat` and `json_schema` capabilities.
- Create an enabled route whose purpose is `capability.authoring`.
- Enable the same supported sandbox contract on the API validator and runtime
  Workers (`ICHECK_SANDBOX_ENABLED=true`).
- Use an administrator or bind the built-in `capability_author` role with
  global scope. Studio content is global platform intellectual property and is
  not exposed through a site-scoped binding.

The browser never accepts a provider token. It uses the existing HttpOnly
browser session and rotating CSRF boundary in required-auth mode.

## API

```text
POST /api/v1/capability-studio/sessions
POST /api/v1/capability-studio/sessions/workflows
POST /api/v1/capability-studio/sessions/topologies
POST /api/v1/capability-studio/sessions/tools
POST /api/v1/capability-studio/sessions/skills
GET  /api/v1/capability-studio/sessions
GET  /api/v1/capability-studio/sessions/{session_id}
POST /api/v1/capability-studio/sessions/{session_id}/generate
POST /api/v1/capability-studio/sessions/{session_id}/messages
POST /api/v1/capability-studio/sessions/{session_id}/publish
```

Collector session creation accepts exactly one of four base input shapes.
Existing sample mode sends `target_url` plus `sample_document`. OpenAPI mode
sends a JSON object in `openapi_document` or local JSON/YAML text in
`openapi_document_text`, plus the selected operation; `target_url` is an optional environment
override when the document has no usable absolute server:

```json
{
  "title": "Inventory API collector",
  "brief": "Collect the current device inventory.",
  "openapi_document_text": "openapi: 3.1.0\npaths: {}\n",
  "operation_id": "listDevices",
  "target_url": "https://inventory.example/api/devices",
  "created_by": "capability.author"
}
```

The abbreviated `paths` value above illustrates the request fields only; a real
document must contain the selected GET operation and a successful JSON response
schema.

Direct REST, OpenAPI, and fixed-command modes may add this optional tuple. The
browser can read a local `.txt`, `.md`, `.markdown`, or `.rst` file, but sends
only its bounded text in the session-creation request:

```json
{
  "source_document_text": "# Field semantics\\n`serial` is the stable chassis ID.",
  "source_document_name": "vendor-api-notes.md",
  "source_document_media_type": "text/markdown"
}
```

All three fields are required together. This tuple is rejected for MIB input,
whose separately minimized symbol catalog remains the sole model context.

Fixed-command mode sends no command string:

```json
{
  "title": "Linux interface collector",
  "brief": "Collect Linux interface, MAC, and IP inventory over SSH.",
  "command_input": {
    "command_profile": "linux.ip_address_json",
    "target_host": "linux-01.example.internal",
    "target_port": 22,
    "sample_output": "[{\"ifname\":\"eth0\",\"address\":\"52:54:00:12:34:56\"}]"
  },
  "created_by": "capability.author"
}
```

MIB mode sends the document only inside the creation request; it is minimized
before the session is committed:

```json
{
  "title": "ACME sensor MIB",
  "brief": "Propose a bounded SNMP Exporter module for temperature sensors.",
  "mib_input": {
    "mib_document_text": "ACME-SENSORS-MIB DEFINITIONS ::= BEGIN\n...\nEND"
  },
  "created_by": "capability.author"
}
```

Sessions persist the conversation, prompt-independent typed specification,
selected route/model IDs, token usage, and exact Artifact/version references.
For an uploaded source document, the session also retains only the sanitized
untrusted context plus bounded provenance. The public session projection never
returns that context. Audit records contain prompt/document hashes and
structural metadata, not the prompt, sample body, or source-document text.

States are `draft`, `generating`, `validated`, `published`, and `failed`.
Model, deterministic-validation, and sandbox failures fail closed. If Artifact
creation already completed when a fixture fails, the rejected draft remains
traceable. A new request key creates a new iteration; a recorded-request retry
follows the recovery contract above. Only the session's current validated,
explicitly reviewed version can pass the publish gate.

## Verified acceptance

The final full native PostgreSQL suite passed 357 tests on 16.15 on 2026-10-03,
including 156 Studio transaction and populated-migration cases. The final full
backend suite passed 549 tests; frontend type-check/build also passed. These
are controlled code/database fixtures, not browser/device-lab acceptance, live
model semantic accuracy or whole-server failover. See
PostgreSQL acceptance (private development evidence; not distributed).

Automated acceptance covers:

- strict OpenAI-compatible JSON-schema requests and governed route/model IDs;
- OpenAPI local-reference resolution, explicit examples and deterministic
  schema synthesis, full-document/model-context minimization, and immutable
  hash/operation provenance;
- rejection of external references, non-GET operations, ambiguous/missing
  operation IDs, unsupported response media, and secret-bearing examples;
- source-document byte/line/line-length and media-type bounds, secret
  redaction, private-key/control-character rejection, prompt-injection
  classification as untrusted data, response/audit/Artifact text omission, and
  immutable hash/size/redaction provenance;
- fixed-command profile pinning, strict JSON/duplicate-key rejection, bounded
  provenance, target allowlisting, required deployment credentials, and
  mandatory SSH host-key verification without implicit credentials;
- bounded MIB parsing and minimization, deterministic symbol-to-numeric-OID
  compilation, invented-symbol rejection, immutable hash provenance, and
  publication denial until external generator/live-device attestation;
- model token accounting and prompt-hash-only audit;
- deterministic rejection of mappings absent from the supplied sample;
- real Landlock/seccomp fixture execution with network denial;
- validated-only human publication;
- conversation-driven creation of a second immutable version;
- deprecation of the previously published version only when the new one is
  published;
- inline credential rejection; and
- inspection and safe retry after a sandbox-rejected draft.

Workflow acceptance additionally covers real Tool Registry projection,
dependency snapshots, permission derivation, bounded graph preview, missing-tool
and unbounded-cycle rejection, and static approval/post-check/rollback proof for
state-changing paths.

Topology acceptance covers aggregate-only model context, current inventory
selector validation, bounded device/endpoint preview, wired/Wi-Fi/IP edge
projection, immutable publication, and omission of usernames and raw vendor
payloads from model context and preview output.

Tool/Skill acceptance covers strict schema and fixture validation, MCP-only
generated tool transport, separate activation, non-registration after
publication, immutable conversational refinement, Tool Registry dependency
hashes and permission union, fixed agent budgets, and rejection of
state-changing tool dependencies from diagnostic skills.

The separately governed MCP Gateway now registers allowlisted servers, attests
live schemas against published Tool versions, activates/deactivates Registry
entries, and lets the existing bounded Agent Loop execute schema-validated
structured results. Publication itself remains non-activating. See
`docs/mcp-gateway.md`.

The shared Artifact lifecycle also provides bounded semantic version diff,
5 MB `icheck.artifact.bundle/v1` export/import with digest and content-hash
verification, deterministic revalidation in the target environment, and
immutable restore candidates that require a separate publish action. See
`docs/artifact-lifecycle.md`.

The dedicated `/studio/artifacts` subpage exposes version hashes, bounded diff,
browser export/import, restore candidates, and explicit publication without
placing lifecycle administration on the AI L1 home.

The dedicated `/studio/replay` subpage stores sanitized Collector golden cases
and reruns eligible immutable versions under `python_sandbox_v1`. Comparison
evidence is bounded to counts and hashes, and replay never deploys or promotes
the tested version. See `docs/artifact-lifecycle.md`.

The dedicated `/studio/rollouts` subpage starts one scoped shadow deployment
for a validated polling Collector. Production evidence ingestion is suppressed;
health uses run status, minimum records, bounded hashes, failure limits, and a
deadline. Passed candidates require human promotion, and a candidate that has
entered canary cannot bypass that promotion path. This is Artifact publication
promotion and remains separate from deployment replacement. Before starting,
the canary form requires explicit target ownership review: select a current
registered Device (with its identity revision and site), or classify an API as
an external source and record why it is outside Device inventory. The control
plane repeats that check, and a Worker disables stale or conflicting targets
before assignment. Generated registered-device targets with an unrelated URL
or unrecognized host are rejected; an unrelated API host can instead be
reviewed as an external source. A Device-name match remains an inventory
assertion, not DNS/TLS proof, and custom aliases need a separate attestation.
Each new canary retains that ownership decision on its own record, plus a digest
of the candidate, target, configuration, Worker selector, credential reference,
schedule and creator. The rollout detail shows the original review even if the
deployment changes or disappears. Promotion fails if the review fields or
deployment drift, or if the current Device binding no longer matches. Older
canaries lack verifiable start-time ownership and require a fresh
canary; their missing snapshot is displayed explicitly. Promotion locks the
reviewed Device and deployment rows until its publication transaction commits.
For an external API target, recognized hosts are also fenced against concurrent
Device registration or identity correction throughout the creation, Worker
claim, and publication checks. The database enforces the matching host keys for
all Device insert/delete/name-or-IP changes. An opaque custom endpoint field
is not a reviewed Device binding; DNS and TLS peer identity remain separate.
After promotion,
the same page can create a scoped immutable fleet plan, inspect blocked or
eligible deployments, and apply or roll back bounded batches using the exact
plan hash. Plans can instead opt into deterministic percentage rings driven by
an independently deployed controller. Each ring requires fresh post-migration
healthy Collector runs before the next ring; failures pause closed and the UI
provides audited pause, fresh-window resume, and abort controls. Active leases
defer, deployment drift stops, and records owned by the device-activation
approval flow cannot be rewritten through this path.

Published Workflows now have a governed execution and scheduling path.
`/api/v1/workflow-runtime/workflows` lists immutable runnable contracts;
manual launch validates typed input, caller permissions, current Tool Registry
compatibility, and route/workflow budget intersection before atomically binding
and queuing an Investigation. Fixed nodes execute deterministically, while an
`agent_loop` receives only its declared read-only tools. State-changing nodes
reuse the common exact-plan LangGraph interrupt and four-eyes approval path.
Alert-trigger activation is separate from publication and stores an explicit
run-as principal, object scope, and bounded input mapping. New Alerts enter a
deduplicated durable outbox, and `/studio/workflows` exposes activation and
dispatch health.

Schedule-triggered Workflow Artifacts are activated with a separate exact-
version runtime policy containing a bounded five-field cron expression, IANA
timezone, typed static input, run-as identity, authorization scope, and misfire
grace. A revisioned calendar adds up to 100 timezone-aware, non-overlapping
absolute exclusion windows. The Agent Worker creates one durable occurrence per
activation and scheduled UTC instant, skips stale misfires rather than
producing an unbounded catch-up burst, and persists calendar matches as
non-dispatched skipped occurrences. It rechecks publication, identity, scope,
input, and dependency compatibility before dispatch. `/studio/workflows`
exposes calendar editing, next/last fire, missed/excluded-run health,
occurrence attempts, and disable state.

Published diagnostic Skills now have a governed execution path on the AI L1
home. `/api/v1/skill-runtime/skills` exposes published contracts and
`POST /api/v1/skill-runtime/skills/{version_id}/investigations` validates typed
input, caller permissions, current read-only tool dependencies, and the exact
published dependency snapshot before it creates and starts a normal durable
investigation. The investigation stores the immutable Skill content hash,
instructions, schemas, allowed tools, criteria, and dependency metadata.
LangGraph projects only those tools, rechecks the allowlist immediately before
each call, applies the smaller of route and Skill budgets, and accepts completion
only after evidence exists and the structured result passes the published
output schema. This runtime does not weaken platform policy or make a Skill a
state-changing workflow.

Portable Artifacts can also be imported in an externally signed
`icheck.artifact.signed-bundle/v1` envelope. The control plane verifies
Ed25519 signatures with locally registered public trust keys and stores
fingerprint/digest/verifier provenance, but never stores private keys and never
lets a signature bypass target validation or human publication.

Frontend lint and the Node 22 production build include `/studio`. The automated
gateway is controlled; live model-provider compatibility remains a lab gate.

After a Collector version is published, Studio links that exact version to the
Activation Policies editor. The editor can ask the configured structured
`capability.authoring` model for a site-scoped policy suggestion and refine it
in-page, with optional authorized device/protocol context from the Devices
page. This is not an Artifact publication or a Collector deployment: the
model suggestion is not saved as a policy until an operator explicitly creates
a draft, and validation, publication, device preflight, and exact-plan approval
remain separate. See `docs/device-activation.md` for the model-data minimization
and validation boundary. The current refinement chain is not durable across
browser restarts; a recoverable, idempotent conversation remains planned.

## Runtime evidence revision

`POST /api/v1/capability-studio/sessions/from-runtime` opens a conversational
revision from one failed `collector_run`, `artifact_replay_run`, or
`agent_execution`. The operation is idempotent per tenant, region, source type,
and source ID. It requires `capabilities.manage`, a failed source, an exact
Artifact-version binding, and a prior Studio specification for that exact
version. Legacy Collector runs without exact-version provenance fail closed.

The platform constructs the revision context rather than trusting runtime
payloads. Collector failures contribute status and an error digest; replay
failures contribute bounded mismatch types, indices, expected/actual hashes,
and error digests; agent failures contribute bounded attempt/budget facts and
error or escalation digests. Raw targets, deployment configuration, Collector
errors, replay output, agent input, scope snapshots, credentials, and arbitrary
labels are never copied into the Studio conversation or audit event. The
resulting evidence has a canonical SHA-256 and is labelled as untrusted data in
the model context.

Creation does not call a model and never repairs or republishes automatically.
The operator reviews the source/version banner and explicitly requests a
refinement. That refinement creates a new immutable version on the same
Artifact and retains source provenance. All ordinary schema, dependency,
sandbox, human-publication, activation, canary, and rollout controls still
apply.

## Remaining M3 work

The supporting `/studio/catalog` runtime view now projects each current
published capability through its live contract, dependency, activation,
permission, and signed-provenance checks. It exposes stable blocker codes and
bounded summaries rather than raw Artifact definitions, deployment inputs,
schemas, credentials, or exception text. See `docs/capability-catalog.md`.

This slice does not yet claim the full Capability Studio milestone. Governed
MIB ingestion, signed external-attestation acceptance, immutable deployable-
version creation, and canary-only publication are implemented. Remaining work
includes deploying the hardened generator/installation/live-device attestor,
performing real-lab acceptance, and adding vendor-specific exporter packs,
live vendor recovery-gateway/drill and CI identity-provider acceptance,
and multi-tenant scheduler scale acceptance. The first visualization type is
implemented for governed service indicators. The first Report type is a
deterministic service-health snapshot over those indicators. It runs on demand
and can also be injected fresh into an exact-version schedule Workflow whose
delivery node is a governed state-changing MCP Tool with approval, post-check,
and rollback. Exact output-schema mapping commits one immutable delivery
receipt only with the completed Workflow terminal checkpoint. Arbitrary query
authoring, broader visualization/report types,
built-in PDF/email delivery, retained report instances, and live vendor
adapters remain future governed slices.
Durable witness and promotion transport, including endpoint mTLS rotation, and
manual atomic promotion publication are implemented on their dedicated
surfaces.

## Registered normalized Collector outputs — 5 October 2026

Studio and runtime projection now share one catalog of nine registered
versioned contracts. `GET /api/v1/capability-studio/collector-contracts` requires
authenticated global `capabilities.manage`, like Collector authoring, and returns
the required envelope kind and bounded payload schema. The designer receives
the same catalog, and the Studio subpage exposes it in a collapsed reference.
The platform infers entity/relationship/observation/event kind; the model does
not invent it. Unknown versioned names are refused. Existing custom dotted
names remain compatible, explicitly raw-only, and do not populate normalized
inventory/topology. Review output support separately from sandbox status.

`field_mappings` can copy whole arrays/objects, read bounded numeric list
indices in source paths and build nested objects with dotted destination paths.
Destinations are unique, at most eight levels and cannot overlap a parent/child.
Nested writes copy existing parent objects rather than mutating source fixtures;
a scalar destination parent fails the whole transform. Literal mappings remain
bounded scalar data. The existing no-import/no-network/AST/secret/rlimit policy
is unchanged. This first registered-output slice did not add arbitrary code,
expressions, type conversion or per-array-item remapping. The bounded array
follow-up below implements the latter without widening sandbox permissions.

Registered fixtures are checked against their actual projection DTO before a
candidate can be sandbox-validated or published. Network domain checks include
normalized MAC/IP validity, alias uniqueness, family ambiguity, strict VLAN/
detach and no Wi-Fi bypass. Wireless fixtures retain completeness/RSSI/normalized
MAC/clock coherence checks. Graph and event shapes use their own contract and
kind, not an observation-only wrapper. A rejected fixture remains a terminal,
accounted generation with retained specification but no publishable candidate.
Actual generation, reviewed publication, Device-owned target classification,
admission, hardened transform and scoped projection are tested with controlled
HTTP/model transport and real PostgreSQL RLS; this is not a live browser/lab run.

Optional `observed_at_field` selects an actual collection timestamp present in
every fixture/collected record. It normalizes identically to the trusted HTTP/
SSH adapter. A missing/null/non-string/invalid configured clock fails rather
than receiving a fresh timestamp. Without a mapping, Worker collection time is
used; this is not vendor freshness proof. Legacy specification serialization
does not add a null clock field. Immutable version defaults pin record type,
kind, descriptive source, record/identity paths and the selected clock; deployment
tuning cannot rewrite these or disable the clock. Correcting them requires a
new reviewed version. Existing published versions are not retroactively changed:
drain/revalidate/review them before coordinated rollout.

Every catalog/Artifact support description is structural only and explicitly
denies independent verification and incident-closure authority. Current source
and target authorization is still enforced at collection/projection; candidate
fixtures are not admission or semantic proof. Representative vendor GUI authoring,
physical/transport/clock qualification, production rollout/load and six-class
lab acceptance remain open. Current bounded list support is described below.

The ninth contract is `icheck.inventory.network-observation/v2`, for explicit
address/VLAN and interface/VLAN object sets. Select it when a MAC has parallel
ports or the same address on different VLANs. Map vendor arrays with
`item_mappings`; declare `ip_family_scope` whenever supplying IP bindings.
Omitted/null sets preserve prior observations; explicit empty sets clear only
the declared source-owned dimension. This is not physical completeness or
incident-closure proof. V1 and wireless snapshot semantics remain unchanged;
see the [binding-set contract](./collector-contracts.md#explicit-ipvlan-and-portvlan-binding-sets-v2).
Controlled publication/admission/sandbox/projection passes on PostgreSQL RLS.
The Studio preview now separates parallel paths, reports visible counts and
discloses its 16-node/32-edge rendering cap. The
verification record (private development evidence; not distributed) keeps
those code/browser checks separate from live vendor and production acceptance.
The complete ordinary regression at this v2 boundary passes 1,287 with 24 skips;
the full product and integrated demo are not accepted by that result.

## Bounded vendor-array mappings — 5 October 2026

Users can now ask the in-product designer to normalize fields inside each vendor
array item, including nested arrays. These are declarative mapping data, not
model-written expressions or a larger Python permission set. Exactly one mode
is required on each array mapping: `item_field` extracts a relative source path;
`item_mappings` constructs a fresh object using field, scalar-constant or nested
array mappings. Source paths inside an item are relative to that item. Existing
field/constant mappings and legacy serialization remain compatible.

For a Linux-style interface record, this mapping retains every reported address:

```json
{
  "source_field": "addr_info",
  "destination_field": "ip_addresses",
  "item_field": "local",
  "max_items": 256
}
```

For controller client objects with vendor-specific nested identity fields:

```json
{
  "source_field": "associated",
  "destination_field": "clients",
  "item_mappings": [
    { "source_field": "identity.mac", "destination_field": "mac_address" },
    { "source_field": "address", "destination_field": "ip_address" },
    { "source_field": "wireless.network", "destination_field": "ssid" }
  ],
  "max_items": 2000
}
```

Order, duplicates, explicit null values and observed empty lists are preserved;
the registered payload DTO may still reject inappropriate values or duplicates.
There is no filtering, deduplication, dropped row, expression or type coercion.
An absent/null/non-list array, missing extraction path, over-limit array or
nested mapping failure refuses the entire transform, not a partial result or
an invented empty snapshot. An actual empty list is distinct from missing input.
Representative fixtures must demonstrate every sourced item path; an all-empty
fixture cannot prove a path that never appears. Literal-only item plans do not
invent sourced fields. `accept_single_object: true` explicitly wraps a vendor
singleton object; it is strict boolean and defaults to false.

Non-object root records and array items use the trusted adapter's `value` wrapper.
For example, `item_field: "value"` preserves a primitive array, including real
nulls. Objects are not wrapped. Subject/idempotency/source-clock selectors use
the same normalized payload in fixture creation and trusted HTTP/SSH collection.
No inferred timestamp or other conversion is added.

Schema bounds are 64 mappings per object, 128 operations across the full plan,
eight nested array levels and a strict `max_items` of 1–10,000 per array
(default 2,000). Every transformed response shares fixed budgets of 100,000
array-item visits and 1,000,000 mapping/extraction steps. Nested visits count at
each level. Immutable Artifact mapping policy records these limits; deployment
configuration cannot enlarge them. Existing input/output/source/AST/record/
execution-time sandbox caps still apply and can reject a plan below these
numeric maxima. These are safety ceilings, not capacity guarantees.

The Studio reference includes a collapsed array guide. A real-browser check
found and corrected the old fixed-column mobile clipping: panels now stack on
narrow screens and secondary workspace navigation is a keyboard-operable compact
menu. Controlled catalog refusal clears stale rows and displays the error.
Retained conflict/logical/legacy endpoint labels survive mobile rendering and
reload on the separate Endpoints subpage. These fixture checks are not live GUI
authoring, production authentication or a complete accessibility assessment.

The Studio quota badge displays the smaller actor/namespace headroom, including
zero. Missing or invalid quota data displays `unavailable`, never `unbounded`;
only two explicit null ceilings are unlimited. Retained uncertain charges remain
visible. This is a budget display, not authorization. Fifteen dependency-free
frontend unit cases and controlled browser error/zero/unlimited/tighter-namespace
checks pass; backend model admission remains authoritative.

Final targeted acceptance passes 263 ordinary cases (39 array cases) and 185
non-owner PostgreSQL cases, including two additional vendor-shaped publication-
to-inventory flows. Model/HTTP transport is controlled; sandbox execution,
publication, Device classification/admission and scoped projection are real
code paths. Frontend typing/full strict lint/production build pass. Existing
published definitions are not rewritten; drain, regenerate/review and roll out
matching code. No production migration, live device/model or integrated demo
was run. See the bounded record (private development evidence; not distributed).
