# Governed scheduled report delivery

## Implemented boundary

A schedule-triggered `icheck.workflow/v1` Artifact may bind one exact published
`icheck.service-health-report/v1` or v2 version to one declared Workflow input key.
It composes existing Report,
Workflow, run-as authorization, durable outbox, approval, and MCP contracts; it
does not add a privileged email or webhook subsystem.

Activation remains separate from Artifact publication:

```text
POST /api/v1/workflow-runtime/workflows/{workflow_version_id}/schedule-activation
```

The activation request supplies `report_artifact_version_id` and
`report_input_key` together, plus a provider key and a bounded mapping from the
delivery Tool's declared output schema to required `delivery_id` and optional
`delivery_url`/`delivery_status`. The static Workflow input must not contain
the generated key. `/studio/workflows` lists only reports visible to the
current operator and stores the exact selected version, never “latest.”

It may also select `report_attachment_format` for a saved PDF/HTML/CSV/JSON
document. That mode stores exact bytes, injects only an authenticated retrieval
manifest, and requires a `document_sha256` output mapping supported by both
the send and read-only post-check Tools. Both outputs must match the approved
document digest; mismatch routes rollback without a delivery receipt. Pending
Investigations and verified receipts pin the saved instance. See
[saved report attachment delivery](./report-attachment-delivery.md).

## Activation and occurrence checks

At activation and again for every durable schedule occurrence, trusted runtime
code requires all of the following:

- the Workflow and Report are exact, currently published, canonical versions;
- Report content hash and publication time are present;
- the run-as principal still has `services.read`, `investigations.create`, all
  Workflow Tool permissions, and access to the complete report service set;
- the requested Investigation scope is still allowed;
- current Tool Registry entries still match the Workflow dependency snapshot;
- the Workflow has exactly one primary direct input binding from the generated-
  report key to a pinned MCP Tool dependency whose registered contract is
  state-changing;
- the receipt mapping resolves only string fields declared by that Tool's
  immutable output schema; and
- the combined static plus generated input passes the immutable Workflow JSON
  Schema.

The normal Workflow graph validator therefore also proves that the delivery
change is dominated by an approval node, succeeds through a read-only
post-check, and fails through an attached state-changing rollback. Report data
cannot be routed directly around these controls.

Each metric-only inline occurrence generates current values under the run-as
principal's current scope. Its injected object contains report/version provenance plus
the deterministic minimized snapshot: current values, aggregates, trends,
threshold states, and bounded counts. It excludes raw time series, source
queries/references, dimensions, evidence URLs, contacts, credentials, and model
prose. Static input and audit records contain only configured values and hashes;
the generated metric body is persisted only as the exact Investigation input.

An inline v2 occurrence instead captures a durable proof snapshot and injects
`icheck.workflow-retained-report/v1`, containing `instance_id`, exact Artifact
version provenance and the stored JSON `snapshot`. The Workflow and each bound
Tool must declare this strict schema; v1 numeric Tool contracts are not silently
reused. JSON Schema definitions belong at the outer input-schema root when
embedding the model schema under the configured key.

Capture, accounting, initiating-reader admission, proof references and
Investigation evidence commit together. Failed Investigation creation leaves
none of them retained. Preview validates a transient snapshot without retaining
rows. Recovery of a dispatched occurrence preserves its original saved identity.
Every direct report consumer, including verification and rollback, rechecks
the saved input and current persisted run-as roles before I/O. A cached ORM role
graph cannot preserve withdrawn read access. Historical capture scope remains
a bound even if current authority expands.

Workflow Agent loops receive `icheck.workflow-retained-report-context/v1`, a
references-only projection with the saved instance/version, proof kinds/IDs and
explicit historical, non-authorizing flags. Private recorded material and
initiating-reader admission never enter that context. Runtime rechecks exact
saved evidence and current authority before each model turn. A read-only proof
Tool can supply bounded facts under its own authorization. The original
approved delivery object remains unchanged. Consumers bound to a nested report
field cannot bypass the full report read check by passing only an instance ID.

## Immutable delivery receipt

Receipt creation is part of the same transaction that commits a completed
Investigation checkpoint. An end node alone is not proof: a failure/rollback
path can also end. Local and database-free Agent runtimes now persist minimized
`workflow_tool_outcomes` (call ID and runtime status only) on tools checkpoints.
Trusted code validates Investigation ownership, iteration, exact node/input
binding, persisted call status, approved action, and governed post-check where
a change contract is present. Legacy checkpoints remain readable but do not
retroactively supply this proof.

At completion, the runtime revalidates the immutable bound Workflow, requires
one successful producer-node execution and its subsequent successful declared
read-only post-check execution, verifies their result hashes and chronological
order, and requires both calls in the terminal evidence trail. An executed
rollback or failed producer/post-check produces no receipt even when the
Workflow legitimately completes. Missing or forged execution proof fails
closed. The producer argument must equal the generated report object; exact
Workflow and Report version/content hashes are rechecked before extracting
only the configured receipt fields. Workflow post-check success uses the
existing runtime outcome contract; production deployments require the governed
change contract's declared business-success predicate. Neither result is a
provider-signed acknowledgement.

```text
GET /api/v1/workflow-runtime/report-delivery-receipts
```

The immutable ledger binds schedule occurrence, activation, Investigation,
Workflow and Report versions/hashes, provider, Tool, ToolCall, delivery ID,
optional safe HTTP(S) URL/status, delivery time, verification ToolCall, and
verification time. Delivery URLs with
credentials, queries, or fragments are rejected. The same occurrence, external
provider ID, or ToolCall cannot create a second receipt. Replay is idempotent
only when every stored field is identical. Audit contains the delivery-ID hash,
not the raw ID, URL, generated report, or Tool result. `/studio/workflows`
shows the receipt beside its exact schedule occurrence.

The occurrence's `succeeded` status means the Investigation was dispatched,
not that delivery completed. The UI now labels it accordingly and only shows
“Delivery verified” when explicit verification evidence exists. Migrated older
receipts retain null verification fields and an explicit unverified label.
The schedule-event API also projects Investigation ID/status and bounded
delivery state (`not_dispatched`, `pending`, `reconciliation_required`,
`verified`, `unverified`, or `legacy_unverified`) through one
namespace-filtered query. The reconciliation state applies when the exact
bound delivery Tool has a persisted execution start but no verified receipt,
even if the Investigation later fails or escalates. A started write may have
reached the recipient; the UI directs the operator to check the provider or
recipient and Investigation history before any resend. Other terminal runs
without a started delivery remain `unverified`. Neither state proves provider
acceptance or non-delivery.

## Portable export and retention boundary

```text
GET /api/v1/workflow-runtime/report-delivery-receipts/{receipt_id}/export
```

The Web UI downloads versioned `icheck.report-delivery-receipt/v1` JSON for
numeric/legacy receipts, v2 for saved metric documents and v3 for inline or
document-based retained-proof reports. V3 always pins the saved instance;
document fields remain null for inline proof delivery. All use
the normal authenticated, namespace-selected API. Export
requires global-in-namespace `capabilities.read`; unknown or cross-namespace
IDs do not reveal a receipt. Saved-report receipts also require full current
and frozen snapshot visibility; receipt metadata cannot bypass revoked proof
read access. Lists inspect at most the requested candidate limit and omit
unreadable receipts, so a filtered list may contain fewer entries. Responses
use `no-store`. Export includes tenant/region, minimized receipt,
`workflow_postcheck` or `legacy_unverified` verification level, a deterministic
`content_sha256`, and explicit non-pruning retention metadata. Timestamps are
normalized to UTC. Hash the compact, key-sorted, ASCII-escaped JSON containing
all fields except `content_sha256` and `retention` to reproduce the digest.
This hash detects changed export contents; it is not a digital signature or
independent proof of provider authenticity. Raw reports, Tool results, and
credentials are excluded.

The current policy retains receipts without automatic expiry or pruning. No
cleanup worker, delete API, or expiry setting is introduced by this slice.
Disabling an activation is not deletion. Operators must include this ledger
and its referenced execution evidence in database backups. Saved snapshots have
separate legal-hold, complete archive verification and independently reviewed
purge controls. Those controls cannot delete an instance pinned by delivery or
Investigation evidence. Receipts themselves still have no purge API; a portable
export never authorizes deletion.

## Failure and lifecycle behavior

The schedule outbox retains its existing unique occurrence key, stale-worker
recovery, and maximum three attempts. Publication, provenance, canonical
contract, current scope, input-schema, or Tool dependency drift fails closed
before an Investigation is created. Event rows retain only error type and
SHA-256. Capability-pack revocation or uninstall disables schedules when either
their Workflow version or bound Report version belongs to the affected pack,
and terminally fails pending events.

At terminal commit, a missing/duplicate successful producer call, mismatched
report argument, changed provenance, absent mapped path, non-string receipt
value, or unsafe URL rolls back both the completed status and receipt. A
successful Tool call alone is therefore never presented as completed delivery.

Report generation is not a delivery side effect. SMTP, ticketing, messaging,
storage, and vendor credentials belong behind separately activated MCP servers
and credential references. The platform records the immutable Tool contract;
the adapter owns vendor protocol details.

If a state-changing MCP request enters transport but returns no usable reply,
the runtime cannot classify the provider outcome as a normal failed send. It
retains the exact Tool call as `running` and its approval as `executing`,
counts that attempted call, and escalates the Investigation without taking
the Workflow's ordinary failure or rollback edge. Automatic resume refuses
the same write. The schedule remains `reconciliation_required`; no verified
receipt is created. Pre-transport validation errors remain ordinary failures.
This is a safety stop, not proof that the provider accepted or rejected the
delivery.

## Verified and remaining gates

Automated coverage proves exact-version binding, generated-input overwrite
rejection, deterministic minimized output, immutable provenance, direct
state-changing MCP enforcement, one Investigation per occurrence, hash-only
audit/error state, fail-closed Report deprecation, canonical receipt capture,
unsafe URL rejection, duplicate producer rejection, and terminal transaction
rollback. Coverage additionally runs the real approval/interrupt/resume graph
with a transport fixture, proves successful rollback after failed verification
does not claim delivery, rejects completion without execution checkpoints,
checks replay and stable export digests, and denies cross-namespace export.
Strict-contract acceptance additionally proves that a successful send with a
false governed business-success predicate rolls back without a receipt. A
legacy-data migration test proves parent namespace backfill, preserves null
verification fields, and compares the entire migrated schema with ORM columns.
Frontend lint/build cover selector, contract, active binding, per-occurrence
receipt views, legacy labels, and authenticated JSON download compilation.
The MCP write-loss safety record (private development evidence; not distributed)
adds 55 affected ordinary passes, 22 adjacent passes, 15 Agent execution
checkpoint passes and one migrated non-owner forced-RLS PostgreSQL case. Its
provider-accepted/lost-reply condition is controlled; it verifies safe
escalation and no replay, not live recipient state or a complete current-code
regression.

For a delivery Tool delegated to a remote Agent Worker, the current source
also sends the persisted Tool-call ID in MCP request metadata and preserves a
post-dispatch lost reply as an unknown outcome. This ID helps a provider
adapter locate the attempt; it does not prove that a recipient received the
document or permit an automatic resend. These remote-path changes are newer
than the r17 bundle and still require provider-specific reconciliation. The
delegated response-loss record (private development evidence; not distributed)
tracks their code-level evidence.

The delivery action binds its persisted Tool-call ID before dispatch. A
`reconciliation_required` schedule occurrence includes that ID in the API
and Workflow page only when one started delivery attempt matches; ambiguous
or unbound attempts retain the warning without a lookup ID. The ID is
selectable for an operator's provider-side search, but neither the API nor
the page changes delivery state or authorizes another send. The
operator lookup record (private development evidence; not distributed)
covers the current-source regression checks.

For an escalated, still-running MCP delivery action, an approver can fetch a
read-only reconciliation packet from the action proposal. It gives the exact
provider lookup key and any frozen Artifact/activation IDs without exposing
the report arguments or claiming delivery. The Approvals page links this
context to the Investigation; no packet action invokes the delivery adapter,
resends the report or creates a receipt. Provider-side confirmation and
governed disposition remain open.

Live SMTP/ServiceNow/Jira/Slack/Teams/storage adapters, provider-signed inbound
acknowledgement updates, provider-specific lookup and recipient confirmation
after a lost response, production network/proxy response-loss acceptance,
live saved-document
adapters, recipient policy, receipt archive/hold/purge retention, and multi-
tenant scheduler scale remain lab or later product gates.
