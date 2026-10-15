# Governed workflow templates

## Implemented boundary

Capability Studio can author, preview, validate, publish, and conversationally
revise `icheck.workflow/v1` Artifact versions. A workflow may combine fixed
tool steps with a bounded read-only `agent_loop`, approval interrupts,
post-checks, rollback branches, and terminal nodes.

Published workflows now execute through the same leased Investigation,
LangGraph checkpoint, evidence, Tool Registry, and four-eyes approval boundary
as autonomous investigations. Manual workflows are launched from the AI L1
home. Alert, schedule, and Situation integration workflows are activated
separately from publication and enter durable, idempotent outboxes. Publication
remains capability registration, not permission to run automation or proof of
a successful production run.

## Workflow authoring validation

Generated workflow nodes have type-specific rules. Agent loops need a bounded
objective, allowed tools and iteration limit; terminal nodes cannot declare
execution or transitions. The authoring prompt now explains these conditions
explicitly, including null/empty defaults for strict provider output formats.
Validation remains mandatory. Fixed local diagnostic codes identify common
node-shape failures without exposing rejected model output or credentials.
Failed generation is retained and is not a published or executable template.

The r19.11 live rerun still failed on a missing success transition, so prompt
guidance alone did not qualify authoring. Deployed r19.12 also represents
node shapes as provider-facing JSON Schema `anyOf` variants. Non-terminal nodes
require a non-null success transition; direct tools require their tool name;
agent loops require their objective, allowed tools and iteration bound. End nodes
allow no execution or transition values. Sparse and existing null/default-filled
definitions retain their representation. Local graph, registry and approval
validation remain mandatory. Thirty focused checks pass, and the installed schema
rejects the observed missing/null transition shapes.

The separately approved r19.12 live rerun on 13 October created and revised
`preview-inventory-evidence-review` in the same Studio conversation. Both
model-generated versions validated and were reviewed and published. Version 2
is current; version 1 remains in deprecated history. The revision produces
Stored facts, Evidence gaps and Suggested read-only next checks, cites available
observation timestamps and labels unknown source age. It keeps a manual trigger,
only `inventory.get_device` and `inventory.get_endpoint_history`, three agent
iterations, six total tool calls, 300 seconds and 50,000 tokens. Authoring used
23,091 reported tokens across two requests. No workflow was executed or scheduled:
this qualifies that bounded authoring/publication journey, not a diagnostic run.
See the live receipt (private development evidence; not distributed).

## Engineer workflow

The simplified Studio, input forms and same-conversation restore flow are deployed
in the current paired preview. The two-version live authoring/publication check
above passed; execution and real diagnostic outcome acceptance remain required.
Source tests exercise the existing
graph and actual tool/evidence persistence with a mocked model transport.

The source qualification record (private development evidence; not distributed)
records the focused API and browser checks separately from live acceptance.

1. Open Capability Studio and select **Automate a check**. Describe the target,
   evidence to read and desired result. The builder chooses a fixed workflow or
   diagnostic Skill; schemas and implementation details stay under Advanced.
2. Review the proposed steps or allowed read-only tools, validation and limits.
   Draft validation proves a contract, not a completed diagnostic run. Ask AI
   to revise the check within the same conversation.
3. Save the exact reviewed version, then select **Use saved capability**. Choose
   an authorized device and ordinary input fields on the Operator. Advanced JSON
   supports complex schemas or a reference outside the first 100 device choices.
   Do not enter raw credentials. No run starts merely by following the link.
4. Explicitly start the check. This queues the exact saved version and may use
   approved tools or the configured AI budget. Review the persisted evidence,
   uncertainties and conclusion. A saved template is not an active schedule.
5. To restore, return to its Studio conversation, open **Prior versions and restore
   preview**, choose a retained definition and explain the reason. Review and save
   the new revalidated draft. Earlier history and in-flight snapshots remain
   intact; recurring triggers are not silently moved to the restored version.

Workflow and Skill publication, one manual run and recurring trigger activation
are separate actions. Infrastructure writes continue to require the existing
explicit approval and verification path. Read-only engineering checks do not
need remediation authority, a new MCP server or another agent implementation.

## Typed contract

Each generated specification declares:

- a manual, alert, schedule, or Situation lifecycle trigger;
- a strict object input schema with no unspecified fields;
- a start node and two to 64 uniquely named nodes;
- explicit success, failure, and rollback transitions;
- input-to-tool argument bindings, never expressions or inline scripts;
- direct tool, post-check, rollback, approval, bounded agent-loop, and end node
  types; and
- wall-clock, total tool-call, total token, and per-agent-loop iteration limits.

The authoring model receives only enabled Tool Registry metadata: name,
description, risk, read-only flag, required permissions, and input schema. It
cannot invent an executable handler or embed tool code in the workflow.

## Deterministic validation

Before an Artifact draft becomes `validated`, iCheck proves that:

- every transition references an existing node;
- every node is reachable from the start and can reach an end;
- a cycle contains a bounded `agent_loop`; deterministic unbounded cycles fail;
- every named tool exists and is enabled;
- every required tool argument has one input binding and binding JSON types are
  compatible;
- all agent-loop tools are read-only;
- post-check tools are read-only and rollback tools are state-changing;
- a state-changing tool requires approval, success flows to a post-check, and
  failure plus failed post-check flow to an attached rollback node;
- static graph dominators prove every path to each change and rollback passes
  an approval node; a boolean label alone cannot satisfy the gate;
- no rollback node is unattached; and
- the permission union and Tool Registry schema hashes are stored as immutable
  dependency evidence.

The validation report includes the graph hash, traversal preview, node/edge
counts, cycles, terminal nodes, tool dependencies, required permissions,
approval/change nodes, and all budgets. `/studio` renders the proposed nodes and
transitions beside the conversation before the human publish action.

## Portability and compatibility boundary

The Artifact definition stores the full generated spec and an explicit Tool
Registry dependency snapshot. The snapshot contains IDs, names, transport,
risk, read-only state, permissions, schema hashes, timeout, and result-size
limits. Validation fails if the current registry no longer matches that
snapshot. No hidden chat history is needed to understand the published graph.

Portable export/import is implemented, but registry dependency IDs remain
target-local and every import is revalidated against the destination Tool
Registry before publication. Signed envelopes can prove that a bundle digest
was signed by a locally trusted Ed25519 public key; signature verification does
not bypass dependency, schema, secret, or publication checks.

## Execution contract

```text
GET  /api/v1/workflow-runtime/workflows
POST /api/v1/workflow-runtime/workflows/{version_id}/investigations
```

A manual launch validates the strict workflow input schema, current caller
permissions, publication state, and exact immutable Tool Registry dependency
snapshot before it atomically creates, binds, and queues an Investigation. The
Investigation stores the Artifact version, content hash, input, graph, budgets,
and dependency handlers/schemas so a later Artifact revision cannot change
in-flight semantics.

The Workflow reasoner walks fixed nodes deterministically. Direct tool,
post-check, and rollback nodes use the common schema validation, authorization,
audit, tool-call, and evidence path. An `agent_loop` delegates to the normal
model reasoner with only that node's read-only allowlist and iteration budget.
State-changing calls cannot execute inline: the common LangGraph interrupt
persists an exact-plan proposal and resumes only after a different authorized
principal approves it. Route limits and workflow limits are intersected; a
workflow cannot enlarge the configured model or platform budget.

Before every tool call, execution rechecks that the version remains compatible
with the current Registry. An already-bound run may finish if its Artifact is
later deprecated, but dependency drift still fails closed. New runs require a
currently published version.

## Alert-trigger activation

```text
POST /api/v1/workflow-runtime/workflows/{version_id}/trigger-activation
GET  /api/v1/workflow-runtime/trigger-activations
POST /api/v1/workflow-runtime/trigger-activations/{activation_id}/disable
GET  /api/v1/workflow-runtime/trigger-events
```

Trigger activation is an explicit administrative action on an exact published
version. It stores a bounded alert-to-input mapping, route purpose, run-as
principal, and authorization scope. Required-auth deployments demand an
enabled service principal whose current roles and object scope authorize the
workflow and every dependency; an actor string supplied by the browser cannot
become the runtime identity.

When a new Alert is persisted, iCheck writes at most one trigger event per
activation and Alert ID. The dedicated Workflow Dispatch Worker claims those outbox rows with a lock,
creates at most one Investigation for each event, retries bounded failures, and
stores only error type and message hash. Alert deduplication therefore cannot
multiply workflow runs, and a process crash after Investigation creation cannot
create a second run. `/studio/workflows` exposes activation state and bounded
outbox health while keeping scheduling controls off the AI L1 home.

Dispatch persists its claim, then reacquires the event mutex and checks the
monotonically increasing attempt number, `processing` state and five-minute
expiry. Investigation bindings, the initial application checkpoint, Agent
execution queue/event, audit and terminal outbox state commit in one transaction.
Scheduled saved reports, proof admissions/references, attachment bytes and quota
charges join that same transaction. An expired claim rolls back staging; neither
success nor failure may overwrite a newer attempt. Legacy committed results are
still reconciled without a fourth creation attempt after a lost third claim.
PostgreSQL must use READ COMMITTED with DBAPI autocommit disabled.

Every creation requires current `investigations.create` permission. Alert
dispatch separately requires `alerts.read` and current access to the exact source
Alert before embedding mapped fields; Situation dispatch checks its full current
object scope. Dispatch never calls a model or external Tool. The Agent Worker
later executes the queued investigation through its independent authorization,
approval and bounded-loop gates.

The reviewed `workflow-dispatch-worker` database profile grants explicit reads,
queue/report INSERTs and named runtime UPDATE columns, not broad application DML.
It cannot change run-as identities, scopes, schedules, provider policy, existing
quota limits, approvals, action execution or conclusions, delete history, create
objects or read login tokens/credential profiles. A default accounting row may
be inserted only when the namespace has none. Provider policy records contain
external secret references only; this controller does not resolve them. Three
central principal/role/binding metadata tables intentionally lack namespace RLS
in the identity schema; this profile alone discloses read access plus
`updated_at` UPDATE for retained-proof FOR SHARE locks. Those grants really
permit timestamp writes, not pure SELECT. Domain authorization still filters
the selected tenant and region; all other business relations must retain RLS.
This trusted internal role must never be issued to tenant users, generated
capabilities or remote Workers. Its fixed selected namespace is a service
configuration boundary, not a per-login PostgreSQL tenant restriction.

## Cron schedule activation

```text
POST /api/v1/workflow-runtime/workflows/{version_id}/schedule-activation
GET  /api/v1/workflow-runtime/schedule-activations
POST /api/v1/workflow-runtime/schedule-activations/{activation_id}/exclusions
POST /api/v1/workflow-runtime/schedule-activations/{activation_id}/disable
GET  /api/v1/workflow-runtime/schedule-events
```

A Workflow Artifact declares `trigger_type: schedule`, but does not embed a
runtime calendar. After publication, an administrator activates its exact
version with a strict five-field cron expression, IANA timezone, typed static
Workflow input, route purpose, run-as principal, authorization scope, and
misfire grace. Cron lists, ranges, and steps are bounded; schedules that can
fire less than five minutes apart are rejected. Timezone conversion is based on
real local calendar time and rejects nonexistent local instants during DST.

An activation may carry up to 100 named absolute exclusion windows. Every
window has a stable non-secret ID, timezone-aware start/end, and a maximum span
of 366 days. Windows are normalized to UTC, sorted, and rejected if their IDs
repeat or their half-open intervals `[starts_at, ends_at)` overlap. The
calendar is editable only through a row-locked optimistic update with
`expected_revision` and an audit reason; stale writers receive a conflict.
Audit records retain calendar hashes, counts, IDs, and revisions rather than
window names.

The Agent Worker first locks due activations. An occurrence within its misfire
grace becomes one event uniquely keyed by activation and scheduled UTC time,
then the next occurrence is advanced in the same transaction. An older
occurrence is skipped, increments persistent misfire health, records a bounded
audit event, and advances from the current time instead of creating an
unbounded catch-up storm.

Calendar matching happens against the exact scheduled UTC instant before the
misfire decision. A match creates the same uniquely keyed durable occurrence
with `status=skipped`, `skip_reason=calendar_exclusion`, and the stable
window ID, increments exclusion health, and advances atomically. Skipped rows
are never claimed for dispatch and never create an Investigation. Malformed
persisted calendar state disables the activation and records hash-only failure
evidence rather than running through an ambiguous exclusion.

Schedule events use the same three-attempt, stale-processing recovery and
unique event-to-Investigation binding as Alert events. Dispatch rechecks that
the exact Workflow version is still published, the run-as identity and scope
remain authorized, the static input still matches the immutable schema, and
all Tool Registry dependencies remain compatible. Raw errors never enter event
state; only error type and SHA-256 are retained. `/studio/workflows` provides
cron activation, next/last fire, missed-run health, static input, disable, and
occurrence-outbox views away from the AI L1 home. It also provides the
calendar editor, revision state, excluded-run health, and distinct
non-dispatched skip evidence.

### Exact service-health Report input

A schedule activation may optionally pin one exact published
`icheck.service-health-report/v1` version and one Workflow input key. The static
input may not provide that key. Activation and every occurrence revalidate the
Report's publication/provenance/canonical contract, the run-as principal's
`services.read` permission and complete service scope, the combined input
schema, and the Workflow's current dependency snapshot.

The report key must bind directly to exactly one primary pinned state-changing
MCP Tool node.
Because it is a normal change node, the existing graph proof requires a
dominating approval, read-only post-check, and attached state-changing rollback.
Each occurrence generates fresh deterministic minimized values; audit and error
records retain hashes rather than report contents. Report or Tool drift fails
before Investigation creation. See
[governed scheduled report delivery](./report-delivery-schedules.md).

Activation also validates a bounded mapping from that Tool's immutable output
schema to required `delivery_id` and optional `delivery_url`/`delivery_status`.
When the Investigation reaches a completed terminal checkpoint, the same
transaction requires exactly one successful producer-node checkpoint followed
by its successful declared post-check checkpoint, verifies approved execution,
result hashes, chronology, report argument and exact Artifact provenance,
and creates one immutable receipt with both ToolCall references and times.
Failed delivery/checks or a rollback produce no receipt, even if their end node
completes the Workflow. A dispatched occurrence is labeled separately from
verified delivery. Versioned namespace-bound JSON export includes a deterministic
digest and explicitly retains legacy unverified labels. There is no automatic
receipt pruning.
Missing, duplicate, unsafe, or conflicting results roll back terminal
completion. `/studio/workflows` renders the receipt on its occurrence; audit
retains only the delivery-ID hash.

## Situation ticket and collaboration integration

```text
POST /api/v1/workflow-runtime/workflows/{version_id}/situation-integration
GET  /api/v1/workflow-runtime/situation-integrations
POST /api/v1/workflow-runtime/situation-integrations/{binding_id}/disable
GET  /api/v1/workflow-runtime/situation-integration-events
GET  /api/v1/workflow-runtime/situation-integration-references
GET  /api/v1/workflow-runtime/situation-integration-inbound-events
POST /api/v1/workflow-runtime/situation-integrations/{binding_id}/webhook
```

An external ticket or collaboration adapter is a normal published
`situation`-triggered Workflow with at least one governed MCP Tool dependency;
ServiceNow, Jira, Slack, Teams, and private systems are not hard-coded into the
Situation service. The trigger declares exactly one supported lifecycle event:
`situation.created`, `situation.acknowledged`,
`situation.attention_reopened`, `situation.resolved`, or
`situation.severity_changed`.

Binding is a separate administrative action on the exact published version. It
pins ticket versus collaboration intent, route, service run-as principal,
authorization scope, and a bounded mapping from minimized Situation and
timeline-event fields into the Workflow's typed input. Only whitelisted paths
are accepted; raw Alerts and arbitrary graph evidence are not copied into the
integration payload.

The transaction that appends a matching Situation timeline event also creates
at most one outbox delivery for each binding and event ID. The Workflow Dispatch Worker
claims deliveries with row locks, bounded retry, and stale-processing recovery,
then creates at most one Situation-linked Investigation. Dispatch rechecks the
current run-as permissions and Situation scope, exact publication state, typed
input, and immutable Tool Registry dependency snapshot. Remote change calls
continue through the normal MCP schema/result checks and, when state-changing,
the exact-plan four-eyes approval, post-check, and rollback path. Failure rows
retain only an error type and SHA-256 digest.

An optional binding contract names one pinned MCP Tool as the remote-reference
producer and maps its registered output-schema paths to `remote_id`, optional
`remote_url`, and optional `remote_status`. Terminal commit fails closed unless
exactly one successful producer call satisfies that contract. The resulting
reference is first-class Situation evidence and appears on `/situations` and in
the Workflow operations view; it is not inferred from model prose.

Optional inbound status reconciliation uses an Ed25519 public key configured at
binding activation. The public key is stored, but API responses expose only its
SHA-256 fingerprint. The sender posts the strict JSON contract with these
headers:

```text
X-Icheck-Timestamp: Unix seconds
X-Icheck-Event-Id: provider event ID
X-Icheck-Key-Id: configured key ID
X-Icheck-Signature: v1=<base64 Ed25519 signature>
```

The signed bytes are
`timestamp + "\\n" + provider_event_id + "\\n" + sha256(raw_body)`. Payloads
are limited to 64 KiB, timestamps to a five-minute window, and the header event
ID must equal the body. `(binding_id, provider_event_id)` is the replay key: an
identical replay returns the prior acknowledgement, while changed content
returns a conflict. Older or equal `remote_updated_at` values are durably marked
`ignored_stale`; a newer value updates only the external reference and appends
`situation.external_status_observed`. Raw webhook bodies are never stored, and
remote status never changes local acknowledgement or resolution.

Bindings affect future lifecycle events only; they do not replay historical
timeline entries. Vendor-specific webhook shapes must be converted to this
strict contract by a governed edge adapter.

## Verified acceptance

Automated coverage proves successful model generation, Tool Registry catalog
projection, immutable draft validation, publish and refinement, missing-tool
failure with model accounting, deterministic-cycle rejection, static
approval/post-check/rollback governance, fixed-node and bounded agent-loop
execution, node-level allowlists, typed input, dependency-drift failure,
alert-trigger activation, cron/timezone validation, scheduled-occurrence
idempotency, misfire skip/health, timezone-aware non-overlapping calendar
validation, optimistic calendar revisions, durable non-dispatched exclusion
events, corrupt-calendar fail-closed behavior, exact Report binding, minimized
fresh report generation, static overwrite rejection, Report drift failure,
direct state-changing MCP enforcement, Situation lifecycle mapping, MCP-only adapter
enforcement, unique Situation-event dispatch, publication-drift failure, and
disable behavior. Reconciliation coverage additionally proves output-schema
path validation, automatic remote-reference capture, Ed25519 verification,
idempotent exact replay, changed-body conflict, stale update suppression,
hash-only callback records, and local-lifecycle isolation.
Frontend lint and the Node 22 production build cover authoring, manual launch,
and `/studio/workflows` operations.

Live PostgreSQL process-kill/resume, production ServiceNow/Jira/Slack/Teams MCP
and webhook adapters, and multi-tenant scheduler scale remain acceptance or
later-phase work.

