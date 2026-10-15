# Capability execution quality

iCheck continuously evaluates persisted execution evidence for exact published
Collector, Tool, Skill and Workflow versions. Operators configure thresholds
in `/studio/quality`; the Agent reads minimized assessments through
`quality.get_execution_health`. This is the execution-health foundation for
earned autonomy, not permission to execute a change. Execution-health responses
label `authorizes_automation: false` and `execution_health_not_correctness`;
the separate outcome basis retains its own explicit evidence scope.

## Version identity and evidence

A policy binds one namespace-local Artifact version and its canonical content
hash. Creation checks published state, current material and the applicable
Collector or Tool/Skill/Workflow contract. Version upgrades require their own
policy and evidence; they do not inherit an older version's healthy history.
Policy settings use optimistic revisions. Assessment history is append-only
through the application API and is never overwritten by reevaluation.

Collector evidence uses `CollectorRun.artifact_version_id`, not the current
Deployment version. Skill and Workflow evidence uses the bound Investigation
version and snapshot content hash. New governed MCP Tool calls pin the active
Artifact version, content hash, activation ID and activation contract hash
before execution. Both local and delegated MCP paths compare these pins before
invoking the handler. An upgrade between call creation and execution fails
closed. Legacy calls without pins remain unattributed; migrations do not
reconstruct them from today's registry.

Assessment manifests retain only runtime IDs, safe status codes, pass/fail,
timestamps, durations, record counts and content hashes. They contain no Tool
arguments/results, target configuration, worker leases, raw errors, objectives,
model conclusions or authored names. Canonical policy, evidence and complete
assessment hashes bind each immutable observation. These are integrity hashes,
not provider signatures or protection against a privileged database attacker.

## Quality policy and assessment states

Policies configure a 5-minute to 7-day window, 1–2,000 minimum samples,
failure-rate ceiling in parts per million, nearest-rank p95 duration, terminal
sample freshness, evaluation interval and an optional Collector record floor.
For example, 100,000 failures per million means a 10% failure ceiling.
Failure comparison uses the exact integer ratio; it does not depend on rounded
display percentages. Latency includes failed terminal executions.

Waiting for dispatch or human approval is excluded. An overdue running
execution remains visible even when its start is older than the window and
fails the duration gate. Invalid/missing/future timestamps, missing runtime
pins, content/dependency drift and evidence-scan saturation cannot claim
health. Legacy unbound Collector/Tool rows are not inferred from mutable
Deployment/Registry links. More than 2,000 candidate rows fails closed as a
truncated assessment, rather than scoring a favorable sample.

An assessment is `healthy`, `degraded`, `insufficient_data` or `disabled`.
Insufficient or stale terminal evidence is not healthy. Read APIs additionally
expose `needs_evaluation` after policy/integrity/contract drift and `expired`
when the observation's validity has elapsed. Validity is twice the configured
evaluation interval, capped for healthy assessments by terminal-sample
freshness; a stopped controller cannot leave current health forever.
No state grants publication, activation, approval or remediation authority.
The Web UI also expires cached current-health labels without another request,
using server-relative monotonic deadlines rather than the browser wall clock.
Deadlines start conservatively at request initiation; slow API or Catalog
responses cannot extend a label's validity after receipt.

The measurement is execution health only. A completed Investigation does not
prove its conclusion, a successful MCP call does not prove a business outcome,
and sufficient Collector records do not prove correct normalization. Functional
accuracy, remediation post-check/rollback success, security, topology/data
correctness and representative lab acceptance remain separate quality gates.
Parsers, topology views, visualizations and Reports are not scored as executions
until they have their own reliable, version-pinned runtime evidence contract.

Published governed change Tools can now use the separate `remediation_outcome`
policy basis. Its causal post-check evidence, optionally with a typed state
transition, is not silently mixed with execution-health assessments. See
[remediation outcome quality](remediation-outcome-quality.md)
for phase identity, verification, replay-resistant samples and authority limits.

## Alerts and continuous controller

The regional control-plane `icheck-quality-worker` evaluates due policies in a
single transaction. PostgreSQL advisory leader election prevents two controller
replicas from owning the same namespace cycle; policy row locks serialize manual
evaluation and revisions. Assessment, next-due state, audit and Alert/Situation
changes commit together. Failure before commit leaves no partial observation or
Alert. This Worker receives no model or vendor credential and invokes no Tool.
Creation, edits, evaluation and leader cycles require PostgreSQL READ COMMITTED
with DBAPI autocommit disabled. A transaction-held shared Artifact identity
fence precedes the policy mutex. Both identity and immutable version binding
are rechecked after waits; retained signed pack revocation independently denies
health even if an owner restores the published flag.

Optional `capability.quality.degraded` Alerts are deduplicated by policy.
Fresh healthy evidence resolves them. Insufficient/stale evidence does not
clear an existing degradation. Explicit evaluation disable or alert opt-out
resolves the corresponding policy Alert on the next evaluation. A disabled
policy records its disabled assessment and then has no next due time until
revised; it does not generate an endless disabled ledger.

Policy creation is capped at 1,000 per namespace, with PostgreSQL serialization
of admission. API listings are paginated, assessment history is summary-only,
and one detail endpoint returns the bounded evidence manifest. Immutable
assessment retention currently has no automatic pruning; production needs
capacity/backup planning rather than silent history deletion.

## API and authorization

```text
GET  /api/v1/capability-quality/policies?offset=0&limit=50
POST /api/v1/capability-quality/policies
PUT  /api/v1/capability-quality/policies/{id}
POST /api/v1/capability-quality/policies/{id}/evaluate
GET  /api/v1/capability-quality/policies/{id}/assessments?limit=20
GET  /api/v1/capability-quality/assessments/{id}
```

Reads require namespace-wide `capabilities.read`; writes and manual evaluation
require namespace-wide `capabilities.manage`. Reasons are 10–512 characters and
enter audit only as hashes. Outcomes, scores and automation flags are not
caller-supplied fields. Namespace predicates are explicit even for service
sessions that start without automatic ORM filtering; production unbound
evaluation fails closed. Responses use `Cache-Control: no-store`.

The read-only Agent Tool returns at most 20 policy states and only current,
integrity-checked assessment summaries with evidence references. It enforces the
same global namespace scope, exposes no manifests or authored prose, and never
evaluates policies or creates an assessment. Expired/drifted observations do
not produce a current-health citation.

## Deployment and acceptance

`deploy/systemd/icheck-quality-worker.service` and `quality-worker.env.example`
support a protected, namespace-bound VM/bare-metal control-plane controller.
They are templates, not an installed or activated service. Distributed Agent
Workers still receive no database URL. Do not use a quality controller as an
unattended remediation actuator. The reviewed `quality-worker` database profile
uses 35 relations and 46 named UPDATE columns across seven relations. Only
policy current-assessment/due/updated state is writable, not thresholds,
enablement or revision. Existing status/result/phase/plan/scope/approval fields
and credential/provider/MCP-server/token/principal tables are inaccessible for
writes (the secret/identity tables are also unreadable). Two genuine timestamp
UPDATE grants, evidence `created_at` and call `started_at`, permit sealed
rollback receipt FOR SHARE locks. Native terminal-call immutability still
rejects changed call timestamps. Do not characterize the whole profile as
read-only; outcomes require bounded raw evidence reads and these lock grants.
It is a trusted fixed-namespace core role, not tenant/remote-Worker credentials
or a per-login namespace restriction.

The post-r31 source record (private development evidence; not distributed)
has 126 distinct ordinary and 44 exact-role native passes across corrected
segments, including edit/publication waits, signed revocation, sealed primary/
rollback history, and real subprocess SIGKILL before/after commit. Native
terminal/target guards are tested as stronger constraints than the SQLite
tampering fixtures, not disabled. This source is unbundled; no Quality host
login/grant/unit has been installed. Native deployment still requires approval.

Migration `g9h1j3l5n7q0` adds policy/assessment tables with PostgreSQL namespace
RLS and nullable historical Tool-call pins. Downgrade is permitted only before
quality configuration, assessment or pinned Tool-call history exists; its
PostgreSQL role must be able to inspect every namespace.

Local API, execution-provenance and real SQLite Alembic tests cover exact
version attribution, legacy exclusion, degraded/stale/expired/drifted evidence,
alert deduplication/recovery, transaction rollback, two tenants/three regions,
and guarded downgrade. Browser validation uses synthetic API responses,
including policy creation/revision/history, disabled evaluation, cached expiry
and a delayed response that arrives already expired without a transient healthy
label. These earlier checks are not live-controller, PostgreSQL or device-lab
acceptance. The later disposable native source checks above cover exact-role
RLS/contention/process loss, not installed-service production identity,
long-duration ledger capacity or live evidence. Separate independently qualified
low-risk primary-action admission is implemented with its host gate off by
default; execution-health assessments alone cannot qualify it. Separately
reviewed one-shot rollback authority and controlled Worker-loss recovery are
also implemented with their own default-off host gate; production adapter and
live semantic acceptance remain open. Independent incident-closure authority
and its proof UI exist separately, with their production/live acceptance still
open; Quality health does not grant them. See
[reviewed change preapprovals](./reviewed-change-preapprovals.md).

The subsequent Alert-ordering slice (private development evidence; not distributed)
records insufficient/stale evaluation as a newer unknown condition, so a late
older health assessment cannot resolve an existing degradation Alert. Historical
assessments and audits remain retained, but older evaluations cannot replace
the policy's current assessment/schedule. Equal-time verdicts retain the more
conservative assessment and record source conflict; a newer observation is
needed for recovery. A future-dated assessment is not current health. Disabled
configuration is still an administrative state, not independent quiet proof.
This is ordering of controlled evidence, not vendor truth or closure authority.
