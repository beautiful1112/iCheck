# iCheck agent runtime contract

## Alert ownership and conversational troubleshooting — 14 October source update

Alerts and conversations use the same bounded investigation runtime. Operators
describe an objective; they do not need a predefined workflow or to select an
MCP server. The model chooses relevant authorized tools, adapts to observations,
researches missing public references, and reports uncertainty rather than
unsupported recovery. Existing Workflows/Skills remain reusable options.

Ordinary web investigations, automatic alert investigations and follow-ups now
use `execution_mode=diagnose`. Advertisement and execution reject tools with
`read_only=false`, change risk, or a change contract. This is a database-backed
runtime boundary, not a prompt convention. Legacy API investigations default to
`standard`; their existing approval checks remain unchanged.

### Standing alert policy

AI Settings → Automatic investigation (`/settings/ai/autonomy`) manages one
policy per tenant/region, **off by default**. A human administrator authorizes
future selected-severity alerts across the workspace or selected sites,
including future resources at those sites. There is no per-device tool binding.
Saving an enabled policy authorizes model charges and relevant read-only checks,
not installation, infrastructure changes or automatic alert closure.

The existing Workflow Dispatch Worker admits alerts without model/network I/O.
It rechecks the policy author's current permissions and saved scope, locks the
policy row, then atomically commits an Alert receipt, Investigation, checkpoint
and Agent queue item. Namespace/Alert uniqueness prevents repeat dispatch.
Existing fully visible Situations provide a grouping key; otherwise the affected
entity is used. Related alerts link to an active/recent run instead of spawning
another session. Grouping does not prove each later alert was separately checked.

Daily starts (UTC), concurrency, cooldown, maximum admission age, severity and
an explicit maintenance pause bound admission. Resolved/stale/paused alerts are
recorded as skipped. Capacity-limited alerts remain eligible only until their
admission age expires. Enabling/widening a policy does not backfill old alerts.
Disable stops new admission, not already queued/running work; existing runs keep
their cancellation controls. The GUI exposes dispatcher heartbeat and decisions.
A saved policy is not proof the dispatcher is running. The worker's PostgreSQL
profile can update policy heartbeat/status, not enable or widen policy.

**User decision, 14 October:** silencing or closing the triggering alert stops
its automatic investigation, not only notifications. Acknowledgement alone does
not stop it. A grouped receipt is a reference to the originating alert's run,
not a new independent investigation; the originating alert controls that run.
Manual conversations and explicitly requested follow-ups remain separate user
requests. Stopping does not close an alert, claim recovery or erase evidence.

The control plane gates worker claims, lease renewals and each model/tool
operation. Resolved alerts and disabled/superseded metric rules stop automatic
work. For native Prometheus alerts it reads the provisioned Alertmanager's
`/api/v2/alerts` and matches the retained applied rule's full labels and namespace.
`status.silencedBy` covers silences created both here and directly in that native
Alertmanager, including broader/regex silences. No duplicate matcher engine is
introduced; inhibition alone is not treated as an explicit user silence.
See the [native API contract](https://github.com/prometheus/alertmanager/blob/main/api/v2/openapi.yaml).

Confirmed in-product silences and local user closure cancel queued/waiting work
in the same transaction, or request cancellation of a running execution. Native
external changes and source clearance are observed at the next execution
boundary. A DB dispatch receipt may exist before the claim gate stops a run;
that receipt is not evidence of a model/device call. The DB-only dispatcher
still makes no network calls and needs no wider grants.

Unavailable, malformed, missing or unprocessed native status stops automatic
metric investigation with an explicit reason; it is not inferred to mean fault
recovery. Already dispatched calls may finish, and previously committed evidence
is retained. Cancellation prevents subsequent work once observed. Silence expiry
does not restart that episode's stopped run; an operator may explicitly start
a new investigation. No remote/unprovisioned Alertmanager federation is implied.

### Direct AI dashboard authoring

`/dashboards` now offers a plain-language **Create with AI** form and **Edit with
AI** beside each installed dashboard. It reuses the existing bounded native
Grafana investigation and Studio conversation component, not a browser-owned
agent loop. Revisions include the selected connection and resource UID, ask AI
to read the current definition/version and preserve unrelated panels/settings.
Further conversation reads the previous saved proposal. The UI requests
`execution_mode=diagnose` and the existing `grafana-dashboard` tool boundary.

Model calls require explicit submission; browsing, choosing a dashboard or
opening history does not start generation. Saved runs have a paginated
connection/task-filtered history and reloadable URL. Successful proposal receipts
load the review area automatically. Applying still requires the existing exact
plan confirmation and current resource-version checks. Manual JSON editing is
optional and collapsed under Advanced. The former **Prepare revision** button
only loaded a definition for manual editing; it was not AI authoring.

### Capability gaps and continuation

`investigation.discover_capabilities` uses the reasoner's current permission,
profile, diagnostic and MCP-availability filters. It also returns published
Skill/Workflow metadata and research readiness. It performs no device connection
test; inventory/connection tools still supply target-specific readiness.

`investigation.request_capability` saves a bounded, deduplicated brief owned by
the executor's investigation. It cannot choose another investigation, generate
or install code, or expand permissions. The operator opens the prefilled Studio
brief, asks AI to preview, reviews/installs through the existing lifecycle, and
returns to continue the investigation. Page navigation makes no model/device
calls. Existing generated-MCP adapter limitations still apply: a brief is not
proof that an arbitrary requested protocol or operation is implemented.
The first authoring session is durably linked before generation, so reopening
the request resumes that Studio conversation rather than creating another one.

Continue creates a **new bounded read-only run** linked by
`parent_investigation_id`. It does not reopen a terminal checkpoint, reset its
counters or reuse approvals. Active-child retry protection avoids duplicate
submissions. At most three prior runs and six small successful results per run
are considered within a 24 KB historical-context budget. Current authorization
and tool availability apply; history is never labeled fresh evidence. Completed
investigations can save their objective/recorded approach as a Skill brief for
Studio review, not automatic publication or activation.

Migration `z3f5h7j9l1n4`, paired GUI/backend and restricted dispatch worker
grants/service were deployed in r19.25 on 14 October. The default policy remains
disabled with a healthy dispatcher heartbeat; no paid/provider/device journey
was run. See the deployment record (private development evidence; not distributed).
Unattended remediation, automatic
installation, automatic Skill publication and unapproved nested workflow
execution are not introduced.

## Retained observations between reasoning steps

The reasoner receives the latest tool batch plus a bounded view of earlier
terminal calls from the same investigation and namespace. This prevents a later
discovery step from discarding an earlier connection ID or observed result.
The view reads existing call records referenced by the graph checkpoint; it is
not a second history store or agent loop. Current tool allowlists apply, disabled
tools are excluded, and another investigation's call cannot be borrowed.

At most 16 prior calls and 64,000 encoded bytes enter this context. Large results
or arguments carry explicit omission flags, not fabricated empty data. Observed
timestamps remain historical. Tool content remains untrusted evidence and cannot
authorize actions. Latest-batch semantics for deterministic workflow nodes,
durable checkpoints, cancellation, budgets and duplicate-call blocking are unchanged.

A simulated-model three-step Grafana journey verifies connection discovery,
metric discovery and a local proposal without repeated calls or a Grafana write.
This verifies the runtime path, not provider quality or real-device monitoring.

## Native dashboard preview completion

A `grafana-dashboard` task finishes when its admitted tool batch succeeds and
the native executor supplies a validated dashboard-proposal receipt. This avoids
another model iteration after the requested preview already exists. The receipt
is generated only for the internal dashboard preview/restore handlers, outside
bound workflow and Skill runs; a remote tool's result body cannot assert it.

Normal budget checks, checkpoint persistence, finalization and duplicate-call
protection still apply. The conclusion links to the proposal and explicitly says
it is unapplied. This does not approve a Grafana write or establish device health.
Ordinary investigations continue their reason/tool/evidence loop. The r19.7
source checks include remote-worker checkpoints and failed/budget-exhausted
batches; historical failed demo executions are not rewritten.

## v0.1 r13: deadline coordination and safe decision rejection

Bootstrap includes an absolute `reasoning_deadline` derived from the persisted
investigation start and timeout. The Worker renews ownership/checks cancellation
before each reason RPC; that RPC's wait is remaining investigation time plus a
bounded five-second return margin, not the unrelated default 30-second HTTP wait.
Provider attempts and configured fallback chains remain inside the investigation
deadline and lease (ten-second settlement/finalization margin). Response-body
keep-alives cannot extend a model's total HTTP attempt timeout. Missing deadlines
on legacy fixtures retain the ordinary timeout; deployment drains/restarts API
and Workers together because bootstrap is a strict protocol contract.

Qwen runtime output is bounded to 4,096 tokens per call or less; the affected
mandatory-reasoning model uses minimal enabled reasoning. Rejected decisions
retain only safe field paths, fixed validation rules, safe finish reason and JSON
position. The server audits the failure and settles known/unknown usage before
returning an escalation decision. A rejected turn executes no Tools. Transport
loss is not automatically replayed and does not imply a network-device fault.
Diagnosis reads late quota receipts rather than claiming zero model usage from
the graph counter. Historical counters/audits are not repaired by invention.
See [AI runtime settings](ai-provider-configuration.md) for limits and disclosure.

### v0.1 r10: provider failure is a typed Agent outcome

The remote reasoning endpoint converts known model/provider unavailability into
an `escalate` GraphDecision with a safe, actionable reason and accounted token
usage, rather than an opaque HTTP 500/ControlPlaneHTTPError. Per-candidate failure
audits retain fixed diagnostic codes and upstream statuses, never upstream prose
or request secrets. Existing fallback candidates remain bounded and audited.
OpenRouter batch variants fail before inference I/O. Structured Studio generation
uses the same safe HTTP classification. Model-independent diagnosis reads those
audits through authorized investigation access; `platform.diagnose_ai_runtime`
exposes a read-only repair proposal without new inference or state changes.
Explicit repair retry creates a new task from the original objective/scope with
current authorization and model route; old runs are not rebound or rewritten.

## Purpose

The M2 kernel is the first executable AI-operator path. It is deliberately
separate from the dashboard and from collector scheduling: the model reasons
over typed, persisted evidence and cannot read credentials or directly mutate
infrastructure.

```text
Investigation + route snapshot
            ↓
OpenAI-compatible structured reasoner
            ↓
LangGraph bounded decision node
       ├── complete / escalate
       └── typed tool requests
                    ↓
             policy and schema gate
                    ↓
              internal tool handler
                    ↓
       persisted call + evidence reference
                    ↓
              reason with evidence
```

## Durable state ownership

iCheck and LangGraph persist different contracts:

- LangGraph checkpoint storage owns executable thread state and restart
  continuity. The control plane accepts PostgreSQL only in production, enables
  strict MessagePack mode, verifies owner-provisioned saver tables without DDL
  at startup, and uses the
  investigation ID as the thread ID. Remote Agent Workers read and write this
  state only through the lease-bound `icheck.agent-runtime/v1` HTTPS API.
- iCheck product tables own the stable API and audit contract: investigations,
  immutable sequential checkpoints with SHA-256 state hashes, evidence
  references, and tool calls with argument/result hashes.

The separation keeps the user-visible investigation trace independent of a
specific orchestration library. SQLite plus the in-memory LangGraph saver is
used only for automated development tests. A dedicated PostgreSQL process-loss
probe verifies LangGraph checkpoint continuity. A second private PostgreSQL
probe now verifies two real database-free Agent Worker processes exchanging a
lease through the loopback control-plane API. Production HTTPS/mTLS and load
acceptance remain open.

## Execution workers and events

Starting an investigation atomically creates a queued execution and its first
ordered event. Agent workers enroll with a dedicated bootstrap token, receive a
rotating bearer token, advertise provider capabilities, and atomically claim a
bounded number of compatible executions. Only lease-token hashes are stored.

Each graph node verifies ownership, checks cancellation, renews the lease,
persists the product checkpoint, and emits a bounded progress event. An expired
lease can be claimed by another worker; the assignment explicitly states whether
the same LangGraph thread must resume. If the graph committed a terminal
investigation but the worker crashed before acknowledging completion, the next
scheduler pass reconciles the execution without replaying the graph. An expired
cancelled run is similarly closed instead of remaining stuck.

Completion also has a durable acknowledgement receipt bound to the authenticated
Worker, its one-time lease token hash, and the exact requested status and error.
If the control plane commits completion but the HTTP response is lost, the
Worker retries the same request at most twice on transport failure or an
upstream 5xx response. A matching replay returns the
committed execution without another event or audit record; a changed request,
token, or Worker is rejected. The receipt is cleared when an approved
`waiting_approval` execution is queued for a new attempt. Only hashes, not
lease tokens, are stored in the receipt.

Clients can read ordered events after a sequence or connect to the SSE endpoint.
SSE accepts `Last-Event-ID`, emits persisted event names and IDs, sends
keepalives, terminates on a terminal/waiting state, and returns a reconnectable
cursor on timeout.

The AI L1 home consumes this contract directly. It creates and starts durable
investigations, reads checkpoints/evidence/tool calls, follows execution events,
and exposes cancellation. It does not infer progress from chat text and does not
show fabricated activity when the API is unavailable. Its information
architecture and current limits are documented in `operator-workspace.md`.

The standalone `icheck-agent-worker` command is database-free. Worker
registration, heartbeat/drain, claim, renewal/cancellation observation,
checkpoint reads/writes, reason and Tool operations, graph-progress
publication, and completion all use the hardened control-plane HTTPS client
with a rotating bearer token and optional/required Worker mTLS. Progress accepts
only the fixed graph-node vocabulary and must exactly match the persisted
Investigation counters; lease tokens never enter event payloads. Tool and
reason operations carry deterministic IDs and run in their own durable
control-plane LangGraph threads, making exact retries idempotent. MCP credentials
remain Worker-local: the control plane delegates a bounded credential reference,
the Worker resolves it for one invocation, and only a schema-validated redacted
result returns. Workflow schedule/Alert/Situation outbox dispatch runs in the
separate PostgreSQL-only `icheck-workflow-dispatch-worker`. Systemd references
and environment templates are under `deploy/systemd/`; the full boundary is in
`agent-runtime-protocol.md`.

## Investigation state and bounds

The persisted state includes objective and immutable scope, status, iteration,
plan, typed hypotheses, evidence and tool-call IDs, confidence, conclusion,
uncertainty, and escalation reason. The selected route is snapshotted into each
investigation as maximum iterations, tool calls, wall-clock seconds, and tokens.

The runtime enforces:

- monotonic iteration and token counters;
- a request timeout capped by the investigation's remaining wall-clock budget;
- tool-call and token budgets;
- duplicate tool-and-argument call hashes;
- tool input and output JSON Schemas;
- response byte limits and secret-shape rejection;
- immutable objective/scope and terminal state;
- controlled escalation for model, tool, schema, and budget failures.

### Published diagnostic Skills

A Skill run uses the same durable investigation, worker lease, checkpoint,
evidence, audit, and LangGraph machinery as an autonomous investigation. At
creation, iCheck validates the caller's permissions and typed input, verifies
that the published Skill's read-only tool dependencies still exactly match the
live Registry, and binds an immutable runtime snapshot to the investigation.
The effective iteration, tool-call, and token budgets are the minimum of the
selected model route and Skill contract.

The model prompt treats Skill instructions as subordinate to platform policy
and receives only the Skill's allowed tools. The execution path independently
checks that allowlist and the dependency snapshot before every call. A Skill
cannot complete without persisted evidence; its `structured_output` must match
the published output schema, and any evidence IDs it reports must refer to the
investigation's actual evidence ledger. The validated output is stored on the
investigation and rendered separately from the prose conclusion on the AI L1
home.

### Published Workflows

A Workflow run is also an ordinary leased Investigation, but replaces free-form
planning with an immutable typed graph. Creation validates the published
version, workflow input, caller or trigger run-as permissions, authorization
scope, route, and exact dependency snapshot in one transaction. Fixed nodes are
advanced deterministically by `WorkflowReasoner`; direct tool, post-check, and
rollback nodes still use the common tool/evidence path. A bounded
`agent_loop` delegates to the model reasoner with only its node-local
read-only allowlist.

State-changing Workflow tools reuse the exact-plan LangGraph interrupt. The
handler cannot run until a different authorized principal approves the stored
plan hash; resume continues the same thread. Workflow budgets cannot enlarge
route budgets. New launches require a published Artifact, while an already
bound run may finish after deprecation if its Tool Registry dependencies remain
compatible.

An Alert-triggered Workflow is scheduled through a separate activation and a
durable outbox keyed by activation plus Alert ID. The outbox stores the exact
version, input mapping, run-as principal, and object scope, and creates at most
one Investigation per event. Trigger dispatch is performed by the regional
`icheck-workflow-dispatch-worker`, with bounded retries and hash-only failure
metadata.

Only gateway-reported `usage.total_tokens` is charged. A model cannot choose its
own usage value. Prompts and raw model responses are not written to audit events.

## Model adapter

The first adapter calls an allowlisted OpenAI-compatible
`/chat/completions` endpoint. It uses the model name and default parameters from
the selected model profile and resolves bearer or X-API-key credentials on the
server through the existing credential reference. Requests and responses are
bounded to 1 MB.

The model returns a JSON-schema-guided decision. Provider-side strict mode is
disabled because tool argument objects differ per registered tool; iCheck then
performs fail-closed Pydantic validation of the decision and JSON Schema
validation of each selected tool's arguments. Malformed responses are audited
without response content and durably escalate the investigation.

The selected primary and ordered fallback model IDs are snapshotted when the
investigation is created; later route edits cannot alter an in-flight execution.
The worker can claim the route even if its primary is later disabled. For each
reasoning iteration, the adapter attempts the snapshot in order and continues
only after a retryable configuration, provider, transport, response-envelope,
or graph-decision failure. Local request-size and investigation-deadline
failures are non-retryable.

Every candidate attempt records model, provider, candidate position, fallback
state, outcome, and bounded error metadata. Provider-reported token usage from
an invalid primary response is added to the successful fallback usage; if all
candidates fail, metered failed usage is still applied to the graph and can
exhaust its token budget. Raw model content and credentials are never audited.

Each model reasoning iteration also enters the shared UTC-day AI model-call
quota before contacting any candidate. It durably reserves the investigation's
remaining token budget for its originating actor and tenant/region, then
releases unused capacity only when all external charges in the fallback chain
are known. An uncertain provider charge retains the full reservation even if a
later candidate succeeds. A graph iteration has one deterministic quota intent:
replaying it after a process loss refuses another provider request rather than
double-charging an unknown attempt. This is not a provider billing guarantee;
orphaned reservations require operator reconciliation.

## Tool policy

The registry supports `internal` and `mcp` transports and observe, diagnose, and
change risk. Every investigation snapshots the authenticated principal,
permissions, and authorization scope. The reasoner projects only enabled
internal handlers permitted by that snapshot; persistence and execution enforce
the same permissions again. Device, endpoint-history, Alert, and generic-graph
handlers also apply the immutable device/site scope at their SQL boundary and
filter child records. Controller-centric Wi-Fi queries revalidate the exact
authorized controller and namespace before reading sessions. Raw PromQL now
uses the [parsed series-scope boundary](metric-query-authorization.md) for
namespace and current device/site scope before evaluation. Device-specific
queries construct and verify stable namespace/device-ID labels, not IP/name
aliases. Scoped raw LogQL remains rejected. This is packaged in the r34
candidate, not installed r30 acceptance.

Implemented tools:

| Tool | Purpose | Evidence |
|---|---|---|
| `inventory.get_device` | Bounded device identity, onboarding, connection verification, activation, and runtime health | Device reference |
| `inventory.get_endpoint_history` | Bounded, active-first IP, wired attachment, and Wi-Fi controller history selected by endpoint ID, MAC, or unambiguous IP | Endpoint reference |
| `wireless.list_controller_clients` | Bounded current/recent clients for one authorized wireless controller, optionally filtered by exact AP/SSID or weak RSSI/SNR thresholds | Controller plus complete request-hash reference |
| `alerts.list_open` | Bounded open/acknowledged alerts with optional severity filter | Alert references |
| `knowledge.query_graph` | Bounded one-hop generic graph selected by durable ID or an unambiguous type/external-key pair, with optional direction and relationship-type filters | Root knowledge-entity reference |
| `knowledge.find_paths` | Bounded shortest paths between two durable scoped entities, with optional direction and relationship-type filters | Endpoint pair plus complete request-hash reference |
| `metrics.query_instant` | Bounded instant PromQL against an allowlisted registered metric backend | Backend plus query-hash reference |
| `metrics.query_range` | Bounded recent PromQL range query against an allowlisted registered metric backend | Backend plus complete request-hash reference |
| `metrics.get_device_range` | Bounded Windows/Linux/SNMP exporter series for one authorized device, with platform-built and response-verified stable namespace/device-ID selectors | Device plus complete request-hash reference |
| `logs.query_range` | Bounded 24-hour LogQL query for globally scoped investigations, with label filtering and common-credential redaction | Backend plus complete request-hash reference |
| `logs.get_device_range` | Bounded Loki entries for one authorized Device, using a platform-built and response-verified backend-specific device label | Device plus complete request-hash reference |
| `situations.get_impact` | Bounded scoped Situation impact graph and deterministic dependency paths | Situation reference |
| `capacity.get_worker_scaling` | Latest regional Collector/Agent capacity recommendations and provider state | Scaling decision references |
| `reports.list_saved` | Discover at most ten retained service-health snapshots under current service scope, across Report Artifacts and exact historical versions | One durable snapshot reference per result |
| `reports.get_saved` | Read one exact retained report as bounded numeric sections, status and provenance; use historical values as historical evidence | Durable snapshot ID and SHA-256 reference |
| `windows.request_diagnostics` | Human-approved request for one exact preconfigured, device-bound PSRP/CIM operation set; no model-supplied script, target, credential, or configuration | Diagnostic request reference |
| `windows.get_latest_diagnostics` | Fresh successful PSRP/CIM records for one authorized Device, projected through fixed operation-specific field allowlists | Collector run reference |

`inventory.get_device` excludes connection configuration and credential profile
references. Endpoint history and controller client diagnostics exclude usernames
and raw vendor payloads. The controller Tool returns only bounded normalized
MAC/IP, endpoint, AP/SSID, radio, VLAN, RSSI/SNR, and timestamp fields; filters
and evidence use the complete request hash. The
generic graph tool returns at most 50 relationships and their distinct
neighbors, rechecks scope before tool-call persistence and execution, rejects
ambiguous natural keys, and omits arbitrary Entity/Relationship attributes.
The path tool permits at most four hops and 20 shortest paths, caps each
frontier query and traversal state, rejects cross-scope endpoints, prevents
cycles, and returns only minimized node and relationship fields. Its evidence
explicitly records topology reachability, not a causal or root-cause claim.
The PromQL tools cap the expression at 2,048 characters, timeout at 15 seconds,
and result limit at 100. Range queries additionally cap history at seven days
and 2,000 evaluation steps. Metric audit and evidence store SHA-256 hashes
rather than the raw expression. All successful tool results are validated,
hashed, and persisted; audit records contain hashes and status, not the result
body. The device-scoped gateway further limits results to 20 series, accepts
only exporter metric namespaces, verifies every returned `instance` and metric
name, and removes labels outside a fixed diagnostic allowlist.
Log tools cap Agent history at 24 hours, entries at 1,000 globally or 500 per
Device, timeouts at 15 seconds, response bytes at 5 MB, and each line at 4,096
characters. The log plane removes labels outside the backend allowlist and
forbids common identity/secret labels, redacts common bearer/basic and key-value
credential forms, and audits only a request hash. Raw LogQL fails closed for a
scoped Investigation; the Device gateway constructs and verifies the exact
configured device-label matcher.
`windows.request_diagnostics` is deliberately non-read-only and therefore uses
the ordinary exact-argument action proposal, independent approval, checkpoint,
and resume path. It can only select an enabled published on-demand deployment
whose device and exact operation set match; repeated requests observe the
existing queued/running work instead of adding another trigger. The follow-up
read Tool consumes only a completed successful run whose observations are fresh
and still match the current device and assignment. Pass the request's
`deployment_id` and `requested_at` as `not_before` to distinguish it from a prior
check. Explicit operation sets require coverage for every requested operation,
even when extra records are truncated. Nonfinite fields and old/future timestamps
are rejected. Evidence uses actual observation time, not completion time as a
freshness substitute; historical rows are retained after a binding changes.

Saved report Tools require the Investigation's `services.read` permission
snapshot. Discovery uses current tenant/region and complete service membership
before keyset pagination. Exact reads recheck the stored snapshot digest,
published or deprecated Report version, canonical source hash, selectors and
current service ownership before returning data. Both Tools emit only fixed
status codes, selector keys, bounded aggregates and provenance IDs/hashes;
author prose, display labels, source queries, observation dimensions, rendered
documents and credential details are absent. The evidence reference names the
durable saved instance and states that its values are historical. On LangGraph
resumption, an already completed Tool call is rechecked against current
ownership and snapshot content before its persisted result can be returned.
Use live metrics to support claims about the present; a saved report alone
does not establish current service health. These local read Tools do not
introduce an MCP server or a delivery side effect.

The Windows diagnostic Tool never executes PowerShell. It reads only a recent
successful on-demand run from the published `psrp_cim` adapter, verifies the
Device scope, selects the four fixed operations, and projects only their
documented CIM fields. Deployment targets, credential references, arbitrary
payload keys, run errors, and Worker details remain outside model context.

Core tools are not separate MCP servers. MCP is reserved for external or
user-installed capabilities. A published Tool Artifact becomes executable only
after live schema attestation and separate activation; the leased Worker then
validates arguments/results and stores hash-addressed evidence. An executable
state-changing internal tool creates a durable proposal containing the exact
tool, arguments, purpose, requester, and plan hash. LangGraph interrupts before
the handler runs. A different principal with `changes.approve` must decide the
exact plan; approval or rejection requeues the existing execution and resumes
the same LangGraph thread. An action already marked `executing` after worker
loss is treated as outcome-unknown and is not replayed automatically.

The resume path distinguishes a durable terminal Tool call from an uncertain
external outcome. If the exact approved action call is already persisted as
`succeeded` or `failed`, the runtime repairs the proposal transition, reuses
that result, and continues post-check/rollback orchestration without invoking
the Tool again. If no exact terminal call exists, it raises outcome-unknown and
blocks replay.

An optional `icheck.change-tool/v1` Tool contract activates the first M5
evidence gate. Proposal creation freezes action/dependency Tool and schema
versions, target arguments, authorization scope, risk, rollback, and only the
hash of the idempotency key. Pre-check and dry-run calls must be successful,
schema-validated, read-only calls from the same Investigation and target. A
frozen argument mapping lets a stage Tool use different input field names while
reading only frozen target values. Optional summary paths preserve only
schema-proven booleans, numbers, or SHA-256 strings for peer review; raw result
payloads remain outside the plan. The runtime automatically executes and binds
pre-check then dry-run before interrupting; LangGraph resume reuses those calls
instead of replaying them. A valid maintenance window plus both evidence stages
makes the plan eligible for dual-hash peer approval. Execution rechecks
Tool/scope/target/idempotency drift and automatically executes the frozen
post-check after action success. Failure or failed verification requires a
separately approved rollback request. Its proposal records the parent plan;
after exact execution the runtime automatically binds the schema-checked
boolean result to that plan. A contract with `rollback_check` then executes a
separate read-only, phase-bound restoration check against original pre-change
observations. The rollback proposal's iteration owns this new call; the original
action iteration does not. The parent stays `awaiting_rollback_check` until it
passes; mismatched, false or stale restoration is not successful rollback.
Recorded rollback results/evidence are reused and revalidated without another
write. The original approval is never reused. See
[governed-change-plans.md](./governed-change-plans.md).

The published low-risk primary-action path can now use a separately qualified
reviewed-policy grant after precheck/dry-run, without a new human interrupt.
Its host gate is off by default and requires mandatory governed Tool contracts.
An immutable per-action receipt, exact plan decision and Alert debit commit
together; execution-start repeats current reviewer, scope, quality, source and
budget admission checks. Missing eligibility follows the normal human path.
Rollback and uncontracted internal diagnostic Tools do not inherit this
authority. A reviewed action with an uncertain running call cannot be replayed,
including through delegated-call recovery. See
[reviewed-change-preapprovals.md](./reviewed-change-preapprovals.md).

The same LangGraph action path now tries a distinct recovery grant for an exact
rollback proposal. This uses `ICHECK_ENABLE_REVIEWED_ROLLBACK_EXECUTION=false`
by default and requires primary execution to be enabled too. Only a succeeded
primary action with a causal failed post-check can qualify automatically;
failed or uncertain primary Tool calls remain on the human/reconciliation path.
Independent human restoration samples qualify the grant; automatic recovery
cannot bootstrap its own positive qualification. Current authority, frozen
Tool implementations, target/template, failure deadline, causal Alert identity
and recovery evidence are rechecked before execution-start. One parent lock
serializes human and automatic rollback ownership, while an immutable receipt
owns the automatic slot. Exact retries return that receipt without requeueing
or writing again. Revocation is append-only and preserves historical results.
The approvals page shows this ownership separately from a human decision.
Restoration still leaves the original purpose failed and grants no incident
closure. Controlled Worker/MCP interruption is covered by the subsequent
result-ownership slice below; production adapter interruption and live vendor
truth remain open.

### Delegated write result ownership

An MCP write interruption now carries its execution ID, Worker ID, attempt
generation, exact running Tool-call ID and read-only classification. The durable
operation checkpoint owns those fields; the Worker cannot write the internal
operation thread through its checkpoint API. Returning that interruption is a
single dispatch opportunity, not permission to resend it. A second request
without a result fails closed even from the original owner. A replacement
Worker, or the same Worker under a new attempt, cannot obtain the unresolved
write or submit the previous attempt's result. Legacy unbound interruptions
require independent reconciliation.

Only the original active attempt may submit the matching MCP result. This is
result acceptance, not a new execution start: the proposal stays `executing`
until the result is validated and committed. Revocation/host disable does not
erase already-issued I/O or invalidate honest historical result recording.
After a committed terminal result, a replacement may recover it without a new
adapter call; an unknown running result cannot be converted into success.
Human and reviewed-policy actions use the same no-replay boundary.

MCP phases preserve their LangGraph interrupt positions while reusing committed
results. Replayed positions use endpoint-free `recorded_mcp_result`
acknowledgments, never another adapter dispatch. Explicit pending-interrupt
binding and inspection of pending task interrupts handle repeated resumes even
when a checkpoint's `next` list is empty. Existing activation/result-bound MCP
citations are restored into the returned graph state so the Worker progress
counts remain consistent; no citations are fabricated from the current registry.

Before rollout, drain active Agent executions and resolve old/unbound MCP writes,
then deploy both the API and the Worker protocol implementation. Older Workers
do not understand the new acknowledgment kind. Neither draining nor upgrading
cancels already-started adapter I/O. Both reviewed-execution gates remain off.
The controlled result/recovery acceptance (private development evidence; not distributed)
uses a private non-owner PostgreSQL role, real database-free Worker processes,
natural lease expiry and a loopback MCP/model gateway, not live devices or a
production CA/IdP. The following slice implements exact generic citation
recovery and sequential human-interrupt batching; incident closure is still
unfinished.

### Sequential request checkpoints and exact generic citations

Every requested Tool runs in its own `icheck-tool-request` LangGraph Task,
with primitive inputs/results and no Task retry policy. Requests remain
sequential, including when a model plans several Tools in one iteration. A
completed earlier Task returns its checkpointed result on resume rather than
shifting its old human interrupt onto a later request. Fresh API/Worker graph
bindings can resume the exact pending Task; approval does not apply to a whole
batch. Node failure preserves earlier completed results, call accounting and
citations, without inventing a result for the failing request.

New successful internal/MCP results have a separate immutable citation binding
in `investigation_tool_evidence_bindings`. Completion, binding and completion
audit commit in one transaction. The receipt pins the Tool/call, arguments,
result and finish time plus each reference's identity/times and a summary hash;
it does not duplicate raw summary content. At most 100 unique references may
belong to that exact Investigation and tenant/region. Database triggers enforce
namespace/result/reference identity and reject UPDATE/DELETE; receipt JSON is
bounded. Recovery checks the current result and minimized source pins before
returning only those existing references. Drift or missing references cannot
be replaced with investigation-wide guesses.

An absent receipt remains unbound, not an explicitly empty result. Migration
`v0x2z4b6d8f1` does not infer old internal associations. Proven old MCP
activation/result references retain their limited compatibility path. Manual
completion without an explicit service-level citation association remains
unbound. Populated history cannot be downgraded, nor can an RLS-limited role
decide that other namespaces are empty.

A rejected governed request may already have completed real read-only
pre-check/dry-run calls. The control plane returns bounded typed refusal
accounting, not a fabricated action-call ID or result. The Worker escalates
while retaining those prerequisite calls/references and earlier completed
actions. Two-action controlled HTTP-only flows preserve nine calls/references
on approval and seven on second-action rejection; all exact decisions and
semantic checks remain independent. Broader transport/authorization failures
remain failures, not successful or inferred action outcomes.

An unfinished operation checkpoint without a dynamic interrupt can also mean
the API died after Tool result commit and before node output persistence. It
resumes through the existing ledger rather than restarting the operation. A
control-plane-only recovery flag may consume that exact proposal's recorded
decision when no pending interrupt exists; normal nested interrupt positions
remain unchanged. The usual executor checks still deny every unbound running
write and revalidate approved starts and terminal history. Controlled seeded
checkpoint-gap tests cover committed reads/writes and rejection of a running
write; this is not an actual API/whole-server crash test.

Apply the owner migration after draining active investigations, then update
both API and Worker before admitting new executions. The Task checkpoint
layout and typed refusal response are not a hot-upgrade protocol for old
Workers/checkpoints. Already-started I/O is not cancelled by this rollout.
The batch/citation verification (private development evidence; not distributed)
records isolated non-owner PostgreSQL, controlled HTTP-only assignments,
Task resumption and repeat Worker SIGKILL checks. It is not production
identity/TLS, live-device truth, incident closure or fleet-capacity acceptance.

The risk class resolves to a revisioned `icheck.change-risk-policy/v1` record
during proposal creation. Its execution gate, maintenance requirement and
maximum duration, preview requirement, and authorization-binding requirement
are frozen into the plan. Approval and execution compare the frozen snapshot
with the current record, so a policy revision or disable operation fails closed
and requires a newly generated plan.

For a scoped Investigation, `authorization_target_paths` must bind at least one
frozen action field to an iCheck `device_id` or `site`. The runtime resolves it
against the immutable principal scope at plan creation and before
approval/execution. External MCP Tools therefore cannot use a valid permission
against an arbitrary target string.

## AgentProfiles

An Investigation may bind a revisioned `icheck.agent-profile/v1` policy. The
built-in `l1-operator` is selected by default for the `investigation` route.
Profiles provide role/escalation instructions, permission-scoped Registry or an
exact Tool allowlist, minimum provider privacy tier, permitted data residencies
and model cost classes, and iteration/Tool/time/token ceilings. Route and
profile budgets intersect by taking the lower value.

The complete profile is frozen into the Investigation and shown through the
API. Before model invocation the runtime compares it with the current enabled
revision and validates the Investigation's frozen primary/fallback candidates
against current provider/model placement metadata. Drift fails closed. Profile
instructions are a subordinate prompt section; they cannot override the system
policy, permissions, authorization scope, Skill/Workflow constraints, or
governed action approval.

## Verified behavior

Automated tests cover:

- typed registry, checkpoint, evidence, and tool-call API lifecycles;
- secret-shaped schemas, state-changing calls, duplicates, and exhausted
  budgets;
- LangGraph planning, tool use, evidence return, reevaluation, completion,
  checkpoint lookup, and deterministic failure escalation;
- a two-iteration database-backed run through a controlled
  OpenAI-compatible gateway, the real `inventory.get_device` handler, product
  checkpoints, LangGraph checkpoints, model/tool audits, confidence, and
  uncertainty;
- malformed model output escalation without persisting the private response;
- PostgreSQL DSN normalization and rejection of SQLite as a production graph
  checkpoint store;
- authenticated worker claims, token redaction, lease renewal/takeover,
  cooperative and immediate cancellation, capability filtering, ordered events,
  cursor reads, and resumable SSE;
- standalone worker completion, per-node progress, graph interrupt/rebuild/resume
  without tool replay, terminal graph-commit crash reconciliation, and a full
  HTTP-only reason → Tool → evidence → checkpoint → reason loop with no Worker
  database access;
- immutable permission snapshots, forged-actor rejection, catalog filtering,
  execution-time permission enforcement, exact-hash four-eyes approval,
  same-thread change resume, and ambiguous-action replay prevention.
- evidence-gated change-plan creation, hash-only idempotency provenance, exact-
  target evidence, maintenance-window and dual-hash approval, Tool drift
  rejection, terminal-call crash recovery without replay, post-check
  verification state, boolean rollback evidence, and separately observed typed
  original-state restoration that alone grants no authority. Separate default-off
  rollback qualification, immutable parent ownership and execution-time
  revalidation are now implemented; incident closure remains separate.
- site/device route filtering, endpoint child-record minimization, Agent tool
  object-scope denial, HttpOnly browser sessions, CSRF rotation, and revocation.
- bounded generic graph selection, direction/type filtering, strict result
  schema, minimized evidence, cross-site denial, and bounded deterministic
  multi-hop shortest-path traversal.
- governed MCP server health, exact published-schema attestation, raw Registry
  bypass rejection, lease-bound credential use, secret redaction, structured
  result evidence, deactivation, approval-before-remote-change execution, and
  delegated MCP interruption/resume across the HTTPS runtime boundary;
- published Skill typed input/output, dependency and allowlist enforcement, plus
  deterministic Workflow nodes, bounded agent loops, and idempotent Alert
  trigger dispatch by the separate regional dispatch worker.

## PostgreSQL checkpoint process-loss probe

The `icheck-checkpoint-recovery-test` command (or
`python -m icheck.checkpoint_recovery_test` from the checkout) requires
`ICHECK_RECOVERY_DATABASE_URL`, an explicit dedicated-database acknowledgement,
and a fresh, empty PostgreSQL database named `icheck_recovery_*`. It never falls
back to the application database. It writes only LangGraph PostgresSaver tables;
the disposable database must be removed by the operator after the run.

The first child process executes one synthetic read Tool, durably checkpoints
its evidence and tool-call ID, then is killed with `SIGKILL`. A new process
reopens the PostgreSQL saver, resumes the same investigation thread, reaches a
terminal checkpoint, and fails the probe if it replays the completed Tool. The
3 October 2026 private PostgreSQL report (private development evidence; not distributed)
passes all five gates. Reusing a non-empty database was also refused; all
temporary probe databases were removed and the private server stopped.

This proves graph-level persistence across a real process loss on the
development host. The Tool and reasoner are synthetic, and the probe does not
exercise Agent Worker leases, the `icheck.agent-runtime/v1` HTTPS boundary,
product audit checkpoints, cancellation, a live model, or a real device. Those
remain separate acceptance work.

## Agent Worker process takeover probe

The `icheck-agent-worker-recovery-test` command (or
`python -m icheck.agent_worker_recovery_test`) requires an explicit
acknowledgement and `ICHECK_AGENT_RECOVERY_DATABASE_URL` pointing to a newly
migrated `icheck_agent_recovery_*` database. It checks the checkout's sole
Alembic head, refuses existing application data, and requires a non-owner,
non-`BYPASSRLS` runtime role. The operator provisions and removes this
disposable database; the command never selects the normal application database
implicitly.

On 3 October 2026 the first real `icheck.agent_worker` process claimed an
investigation over loopback HTTP, called a controlled local model, and persisted
one `inventory.get_device` Tool result and product checkpoint. It was killed
with `SIGKILL` while its next model request was in flight. After the 15-second
lease expired naturally, a second Worker with no database or cloud credentials
claimed the same execution and completed it. The
saved private PostgreSQL report (private development evidence; not distributed)
passes all nine gates: two distinct claims, recorded reassignment, completed
investigation, one Tool call and one evidence record, and a continuous product
checkpoint sequence. The controlled model gateway received two requests. A
second run against the non-empty database was refused; all generated databases
and runtime roles were removed and the private server stopped.

The first trial exposed a startup self-deadlock: LangGraph's initial PostgreSQL
`CREATE INDEX CONCURRENTLY` waited on the bootstrap request's own open business
transaction. The control plane now initializes the saver before opening any
business transaction. Recovery also re-emitted an identical `tools` progress
state; the product checkpoint is now deduplicated by exact node and state, while
the ordered event marks `checkpoint_replayed` for the operator trace.

This is functional failover evidence on the development host, with a
development-auth control plane and controlled model over loopback HTTP. It does
not prove production Worker CA/mTLS, a live model or device, or representative
multi-worker concurrency and latency. The
disposable runtime role had schema `CREATE` permission to initialize the
LangGraph saver. The later owner-managed check below removes that grant; this
earlier takeover report alone does not establish least-privilege startup.

A separate in-flight cancellation report (private development evidence; not distributed)
passes twelve gates on a fresh non-owner PostgreSQL database. A real Worker
retained its first read-only Tool evidence, received an operator cancellation
while its next model request was in flight, and acknowledged a cancelled
execution and investigation without another product checkpoint. A subsequent
Worker did not reclaim the terminal run. Four native PostgreSQL transaction
tests cover real row-lock waits: an accepted cancellation blocks stale progress
and wins over a stale success acknowledgement; a committed terminal product
result rejects a late cancellation; and autocommit is refused before these
mutations. They also verify simultaneous replacement pollers skip a locked
cancelled execution and produce just one later reconciliation event. A fifth
native PostgreSQL case submits the same completion concurrently and checks
that one committed completion event survives both acknowledgements.

The separate cancel-then-SIGKILL report (private development evidence; not distributed)
passes fifteen gates. After cancellation was accepted during the second model
request, the Worker was killed before it could acknowledge the terminal state.
Its lease expired naturally, and a replacement Worker reconciled the execution
and investigation to `cancelled` without replaying the prior Tool or accepting
a new claim. A third Worker observed the same terminal state. These remain
controlled loopback and development-auth checks, not live-model or mTLS drills.

A separate completion response-loss report (private development evidence; not distributed)
passes thirteen gates with a real database-free Worker process. The guarded
`icheck-agent-worker-completion-loss-test` command requires explicit
acknowledgement and `ICHECK_AGENT_COMPLETION_LOSS_DATABASE_URL` pointing to a
fresh migrated `icheck_agent_recovery_*` database. A loopback TCP
proxy forwarded the first completion request to the control plane, read its
committed 200 response, and closed the Worker connection without returning it.
The Worker retried the identical request and received the committed result.
One Tool call, evidence record, execution attempt, completion event, and audit
record remained. The migrated database used a non-owner, non-`BYPASSRLS` role;
the disposable database and role were removed. This is local HTTP fault
acceptance, not production TLS, Worker CA, or proxy acceptance.

The same guarded command with `--local-mtls` issued a short-lived local CA and
ran the Worker over HTTPS with a required client certificate. Its
eighteen-gate report (private development evidence; not distributed)
records TLS 1.3, rejection without a client certificate, a Worker bound to the
verified certificate fingerprint, private key permissions, and the same
single-result response-loss recovery. The proxy strips client-supplied
certificate and forwarded-address headers before adding identity from the TLS
handshake. The temporary certificates, database, and role were removed. This
proves the local mTLS code path; it does not validate the production CA or
deployed reverse proxy.

## Owner managed PostgreSQL checkpoints

Production startup now requires `ICHECK_AUTO_CREATE_SCHEMA=false` and uses
`ICHECK_CHECKPOINT_SETUP_MODE=verify`. The separate
`icheck-checkpoint-schema-prepare` command requires
`ICHECK_CHECKPOINT_SCHEMA_OWNER_URL`, `--runtime-role`, and
`--acknowledge-database-ddl`; it never falls back to the application URL. Run
it as a database/schema owner after the application Alembic migration and
before starting the control plane. It executes the installed PostgresSaver
migrations, including concurrent indexes, then grants the runtime role only
schema `USAGE`, read-only migration history, and the DML required on the three
checkpoint data tables. A separate non-superuser checkpoint owner needs
`USAGE, CREATE` on `public`, database `TEMP` for the temporary namespace/thread
mapping tables, and `SELECT` on `regions`, `investigations`, and
`agent_executions`; it does not need `BYPASSRLS` or ownership of the application
tables. After revoking database privileges from `PUBLIC`, grant `TEMP` explicitly
to this owner, not to the runtime role. Missing `CREATE`, `TEMP` or source-table `SELECT` fails before the saver runs
any DDL. On an existing database, drain Agent traffic and take
a verified backup first: the command backfills direct Investigation threads
and reason/tool operation threads through their AgentExecution ownership. It
enumerates every registered region, reads the two source tables under that
region's RLS context, and builds a temporary thread-to-namespace map. An
orphaned or misattributed checkpoint stops the migration for review; it is not
assigned to a default tenant. A historical thread whose region is absent from
the registry also fails this audit. The command then sets tenant/region defaults,
non-null constraints and forced row-level security on all three data tables.

Both owner commands default to a 5,000 ms wait per database lock; use
`--lock-timeout-ms` to select 100–300,000 ms for a scheduled maintenance
window. This bounds each lock wait, not total migration time. The saver setup
uses its own autocommit connection because installed migrations include
`CREATE INDEX CONCURRENTLY`; the later namespace backfill, RLS installation,
grants and verification use a separate transaction. A timeout in the latter
phase rolls back its partial namespace changes, while earlier successful saver
migrations may already be committed. Before retrying, inspect blockers,
migration history, and `pg_index.indisvalid` for the required indexes:
an interrupted `CREATE INDEX CONCURRENTLY` can leave an invalid index that
`IF NOT EXISTS` will not repair. Resolve blockers and any invalid index under
the reviewed DBA procedure, drain traffic, then rerun the owner command; do
not bypass the timeout by disabling RLS. A native PostgreSQL contention test
holds locks on the saver migration-history and data tables, checks bounded
failure and unchanged legacy rows, then verifies a successful retry.

Owner preflight now rejects a same-name invalid index, an index on the wrong
table or column, or a non-index relation occupying a required index name before
the saver can run DDL. The runtime verifier checks that each required index is
valid and ready, is a plain single-column btree on `thread_id`, and belongs to
its expected table. Preflight tolerates a missing index so a first-time saver
install can create it; runtime verification always requires it. If migration
history is already complete but an index is missing, owner setup fails its
post-install verification and the operator must review the store. The product
does not automatically drop or rebuild an operator's index. A disposable native
PostgreSQL case reproduces invalid and wrong-name states, confirms preflight
rejection, then applies an explicit test-only repair and retries successfully.

Do not grant schema `CREATE` or blanket write access
to `checkpoint_migrations` afterward. The command fails if the installed
PostgresSaver migration contract differs from the reviewed version; update the
grant contract and tests before re-running owner setup for a saver upgrade.
The runtime role must not receive `TRUNCATE`, `REFERENCES` or `TRIGGER` on any
checkpoint table. In particular, PostgreSQL RLS cannot protect a table from
`TRUNCATE`.
The installed saver migration count and SQL digest are checked before the
owner opens a DDL-capable connection. Even a same-count SQL rewrite must be
reviewed before owner setup or runtime verification can proceed.

The verifier checks the migration version, required columns and valid indexes,
forced RLS, the exact reviewed namespace policy expression, namespace defaults,
table ownership and privileges, and refuses a
runtime role that owns the
database, bypasses RLS, has administrative role flags or privileged role
membership, inherits checkpoint table or schema ownership, or can create in
`public`. It does not issue DDL.
It also refuses database-level `CREATE`, which would let the role create a new
schema even without `CREATE` on `public`.
The scoped owner provisioning report (private development evidence; not distributed)
and twenty-one-gate Worker report (private development evidence; not distributed)
cover a fresh migrated non-owner PostgreSQL database: a database-free Worker
used local mTLS, persisted graph checkpoints and one Tool result, recovered a
dropped completion response, and left one completion event and audit record
without runtime schema `CREATE`. Native PostgreSQL tests prove the non-owner
role cannot read checkpoint rows without a namespace, across regions, or
across tenants; a cross-scope delete affects no row. They also confirm that
orphaned legacy threads stop the owner migration without committing partial
namespace columns. Missing table permissions, unexpected `CREATE` or
`CREATEDB`, and a stale saver version fail verification. Temporary databases,
roles and test certificates were removed.
Disabling RLS, adding a permissive policy, or widening the single policy with
`OR true` also fails the production verifier. A half-populated historical
namespace is refused rather than overwritten during backfill.

A separate non-superuser owner pre-traffic report (private development evidence; not distributed),
local-mTLS Worker report (private development evidence; not distributed),
and post-traffic owner rerun report (private development evidence; not distributed)
show the narrower owner role creating tables, a real Worker writing checkpoint
data, and the same owner successfully auditing the populated forced-RLS tables
again. Eight native PostgreSQL checkpoint tests now include this owner-role
path, the orphan inventory path, concurrent cross-scope graphs and lock
contention and index recovery. These are disposable local databases, not a deployed production
grant audit.

### Checkpoint orphan inventory

Before a populated-store upgrade, the checkpoint table owner can inventory
threads whose Investigation or AgentExecution ownership cannot be resolved:

```bash
ICHECK_CHECKPOINT_SCHEMA_OWNER_URL='<protected owner DSN>' \
  icheck-checkpoint-orphan-audit --acknowledge-schema-lock \
  --output /protected/path/checkpoint-orphan-inventory.json
```

The command requires the exact owner of all three checkpoint data tables,
schema `CREATE`, and source-table `SELECT`; it never falls back to the runtime
database URL. It temporarily disables checkpoint RLS inside a transaction to
scan all rows under one repeatable-read snapshot, takes table schema locks
with a 5,000 ms default timeout per lock, and rolls the
transaction back on success
or failure. Drain Agent traffic and use a
maintenance window. The JSON reports counts by table, missing or conflicting
thread ownership, rows with absent or unmatched namespaces, and at most twenty
SHA-256 hashes of orphan thread IDs. It does not expose raw thread IDs, delete
or quarantine rows, or approve cleanup. An unmatched namespace may indicate
either an orphan or an attribution error and needs investigation. The native
PostgreSQL tests confirm the scan leaves legacy tables without namespace
columns, and repeated scans of provisioned tables leave checkpoint rows and
forced RLS unchanged. There is no Investigation deletion API or accepted checkpoint
retention policy yet; governed quarantine/purge and a production-scale scan
remain open.

Each runtime checkpoint request binds the authenticated Investigation's
tenant and region to a dedicated PostgresSaver connection. The policy uses the
same session-namespace trust boundary as the rest of iCheck's PostgreSQL RLS:
the shared runtime database role can set its own session namespace, so this is
not isolation against arbitrary SQL executed with stolen runtime credentials.
A native test starts eight LangGraph reason nodes together on separate
checkpoint connections across four tenant/region scopes. It confirms each
runtime scope can read only its two threads in all three saver data tables and
that a connection without a scope reads none. This is a controlled functional
interleaving, not representative load or evidence about production connection
pooling. An opt-in synthetic populated-store rehearsal (private development evidence; not distributed)
also passed with 1,000 and 10,000 Investigations across ten regions, covering
direct and operation threads in all three saver data tables. It used a private
local PostgreSQL 16.15 server with JIT disabled because that extracted test
package lacked its LLVM dependency; these timings do not establish a
production upgrade window. A deployed role/grant audit, a production-equivalent
populated-store backfill rehearsal, governed cleanup of orphaned checkpoint threads, and
representative concurrency remain open before claiming production
multi-tenant readiness.

## Reviewed Situation control-plane Tools

The reviewed closure backend adds two owned Situation Tools. Recovery checks
are read-only, revalidate replay and accept a new `check_key` for another
observation. Closure is an exact Situation-bound control-plane mutation with
independent authority, current snapshot/role/scope checks, a runtime-owned
lease and atomic historical receipt. It never uses a physical action proposal
or exposes a lease token to the model. Committed closure can be recovered before
completing a lost Tool journal. Both proof versions now have actual API/Worker
process-loss and surviving-Worker truncated-response acceptance in isolated
loopback fixtures. Production HTTPS/mTLS, proxy and load acceptance remain
required. See
[reviewed-situation-closure.md](reviewed-situation-closure.md).

An unexpired owned claim returns the strict `icheck.owned-closure-wait/v1`
interruption. The nested Task and existing journal remain nonterminal. The
Worker renews its execution lease without publishing stale root counters, checks
cancellation and polls the same operation with no resume value or closure token.
The Worker checks a 35-second wait deadline between requests and shares the
32-request interruption budget. Each HTTP call still has its configured timeout;
35 seconds is not an end-to-end latency guarantee. Request/call identity cannot
change; epoch changes require a new attempt.
A wait cannot switch to an adapter invocation or fresh approval. Takeover still
requires natural closure-lease expiry and fresh domain authorization.

Only the durably keyed Tool RPC has the new transport retry policy: at most two
retries for truncated replies, connection loss/timeouts or HTTP 502/503/504,
with lease/cancellation checks and 0.2/0.4-second backoff. Each retry preserves
the exact request and any recorded MCP resume; it never invokes an adapter again.
Permission/conflict/application errors and malformed JSON are not retried.
This does not qualify every checkpoint/reason/provider transport.

Drain Agent ownership and upgrade the API and Worker together before enabling
closure. Old Workers do not understand the new wait interruption; mixed-version
rollout is not qualified. Installed gates and services are unchanged. Exact
acceptance boundaries are in the
closure runtime recovery record (private development evidence; not distributed).

Closure journal completion belongs to its owned runtime, identified by the
immutable request key rather than today's handler. Generic completion is denied
even after registry edits; the HTTP schema cannot supply the trusted runtime
flag. Completion requires the exact durable receipt and one reference to that
receipt. Cached Tasks must match the retained call, arguments, body and citation
binding. Original Agent history applies the same terminal-body/citation fence;
running commit-gap journals remain recoverable. Missing or failed terminal
bindings fail closed, without inventing citations or new authority.

Root invocation and resume use synchronous checkpoint durability whenever a
checkpointer exists. The next-step checkpoint must be acknowledged before Tool
dispatch; asynchronous persistence can otherwise lag a domain commit on shared
HTTP transport. Nondurable fixtures retain their prior behavior, not a production
fallback. Exact native, controlled-ordering and compatibility boundaries are in
the journal guard record (private development evidence; not distributed).

Closure selects governed action evidence through the
[immutable target catalog](action-target-admissions.md), including the original
frozen targets for rollback without a separate Plan. Index records never grant
execution permission or substitute for fresh structured outcome proof.

The focused `/situations/{id}/closure` page exposes separately governed manual
controls and read-only owned-request recovery. Its scoped discovery and receipt
metadata do not grant new Agent authority; a GUI GET never resumes the Agent
loop, finalizes closure or regenerates a runtime token. Full receipts remain
historical. See the closure contract for transient-secret and context fencing.

Full closure responses and original Agent history use the retained proof's read
scope, not today's correlation view or mutable action arguments. Current and
initiating `alerts.read` must cover all historical members, policy sources and
frozen typed action targets. A successful journal replay still rechecks this
read boundary. Generic Investigation readers cannot bypass it through saved
Tool calls, checkpoints, details or paged history; unrelated Investigation
permissions stay unchanged. Historical recovery needs no fresh grant, peer or
execution gate, and never replays a write. See
[historical proof access](reviewed-situation-closure.md#historical-proof-access).

## Remaining M2 work

- Repeat Agent Worker process-kill/restart and lease-race acceptance through
  production HTTPS/mTLS with a Worker CA, then repeat the passing loopback
  TCP response-loss drill through the production proxy and measure concurrency
  and latency under representative load;
- live enterprise IdP and ingress-policy acceptance for the implemented
  OIDC/trusted-proxy browser federation boundary;
- live-provider compatibility and fallback behavior outside the controlled test
  gateways;
- broader vendor/controller-specific investigation tools beyond the normalized
  Wi-Fi client session Tool;
- live deployment/acceptance of the implemented database-free MCP attestor,
  OAuth Authorization Code/PKCE flow, and external MCP servers;
- live production action-pack and rollback acceptance.
