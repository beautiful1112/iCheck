# Remediation outcome quality

iCheck distinguishes execution health from evidence that a remediation met its
declared post-condition. `/studio/quality` configures the evidence basis for an
exact published version. The read-only `quality.get_remediation_outcomes` Agent
Tool exposes minimized, current outcome assessments. A healthy outcome score
never grants execution, approval, rollback or incident-closure authority.

## Evidence basis

`execution_health` remains the default for Collector, Tool, Skill and Workflow
policies. `remediation_outcome` is available only for a published state-changing
Tool with `icheck.change-tool/v1`. One namespace-local, revisioned policy binds
each Artifact version and content hash. Changing its basis requires the expected
policy revision, invalidates current observations and leaves history's original
scope intact. A new version does not inherit another version's history.

Outcome assessments carry `remediation_outcome_not_authority` and
`authorizes_automation: false`. Legacy Tools measure declared boolean
post-checks. A Tool that declares structured state expectations can additionally
show a bounded before-and-after value transition. Neither basis proves vendor
signatures, the truth of an AI conclusion or permission for unattended repair.

## Causal verification

New governed plans freeze the exact dependency input/output schemas and their
hashes. Pre-check, dry-run and post-check calls have immutable plan-and-phase
identity; each phase admits at most one call. Its call hash includes that
identity. This permits a fresh post-change read by the same read-only Tool and
arguments used before a change, without permitting a second execution of an
already started phase. Recovery reuses only that exact phase's persisted call;
an absent, running or failed stage is not turned into successful evidence.

Binding a result verifies namespace, Investigation, Tool, exact mapped targets,
argument/result hashes, frozen schemas, boolean outcome and causal timestamps.
An unbound generic read cannot be laundered into phase evidence, even with a
valid recomputed hash. Database constraints reject one-sided/null or unknown
phase identities; service checks bind each verification call to its exact plan.
Pre-checks cannot predate the frozen plan. Dry-run follows a passed pre-check.
Post-check follows the actual succeeded action call, not merely proposal creation
or an asserted plan status. Approval/execution revalidate prerequisite evidence.
Rollback follows the actual failure or failed post-check and requires its own
exact, separately approved action proposal. Raw Tool results remain in their
original runtime ledger; they are not copied to assessment manifests.

Contracts with a read-only `rollback_check` also freeze typed
`rollback_expectations`. Original pre-check values must be restored by a fresh
plan-and-phase-bound read after the exact separately approved rollback. A true
rollback action flag cannot substitute for this read. The minimized
`rollback_verification` contains only comparison/freshness/timing booleans and
the check's reported-success flag, not original or restored values. Its basis
is `structured_state_restoration`; older recorded rollback flags remain
`declared_boolean_rollback`. Pending checks are not restored-state proof.
Both a verified restoration and a failed restoration remain failed original
purpose samples. The quality scan includes `awaiting_rollback_check` plans
even if the original action has aged out of its normal observation window.

The immutable authorization receipt binds the approval-time plan hash, not the
later evidence revision hash. Outcome verification reconstructs that approved
revision and verifies the current evidence hash separately. Post-check and
rollback evidence must not invalidate a genuine historical authorization;
later policy revocation denies new admission but does not erase valid history.

Old governed plans without frozen schemas require a fresh plan before approval
or execution. Migration does not reconstruct phase identities, Artifact pins or
verification claims from today's mutable registry.

## Outcome assessment

The evaluator revalidates the actual persisted action and evidence, rather than
trusting `verified`, `succeeded`, a model conclusion or an operator score. Proof
includes the canonical action-plan hash, separate-peer decision, execution
sequence, governed approval hash, exact target/scope and maintenance-window
binding, prerequisites, post-check and any separately approved rollback.

Only a succeeded action with its causal, passed post-check is a successful
purpose sample. A failed action or false post-check fails the purpose. A passed
rollback records `rolled_back` but still fails the original purpose; a false
rollback records `rollback_failed`. Unfinished verification has the configured
duration budget to finish; overdue verification fails closed. Invalid, missing,
cross-namespace or hash-drifted source evidence cannot claim healthy quality.

Known failed purposes contribute to the configured failure-rate ceiling; they
never count as successful samples. p95 measures action-to-verification/restoration
duration, including failed outcomes. Assessment health is an aggregate against
the configured thresholds, not a claim that every individual action succeeded.
Freshness is based on terminal verification/restoration evidence. Old unfinished
verification remains eligible even after the action has left the time window.

Repeated calls with the same idempotency-key hash and target hash count as one
logical purpose, using the latest attempt. Conflicting arguments for that same
identity fail closed. A replay cannot earn independent success samples.

## Structured state transitions

An optional `semantic_expectations` list on the published change Tool contract
names up to eight desired-state action arguments and matching pre-check and
post-check observation paths. Identity, idempotency and credential paths cannot
be used as the desired state. The three JSON Schema paths must have the same
non-null scalar type; a stage success flag cannot stand in for an observation.
The read-only stage Tools receive frozen target fields, not the action's desired
value. The plan freezes these requirements and the evaluator checks them against
the exact published Tool version again.

For each expectation, the pre-check value must differ from the desired value
and the post-check value must equal it. The pre-check must finish no more than
`max_precheck_age_seconds` before action start, and the post-check must finish
no more than `max_postcheck_delay_seconds` after action completion. Both bounds
default to 300 seconds and can be set from 60 to 3,600 seconds. A true boolean
post-check with the wrong, already-satisfied or stale state becomes
`semantic_mismatch`, not a successful quality sample. A legacy Tool without
expectations remains labelled `declared_boolean_postcheck`; it is not silently
promoted to semantic evidence. Such a Tool can still use the human-governed
change path, but cannot back a new reviewed low-risk preapproval policy.

The governed plan now uses that same bounded transition check while binding
post-check evidence. If the boolean success flag is true but the observed
transition is wrong or outside its time bounds, the evidence is recorded as
failed and the plan enters `rollback_required` instead of `verified`. Outcome
quality independently revalidates the effective verdict and reports the
semantic mismatch. Existing stored evidence with a conflicting older boolean
verdict fails closed on revalidation; it is not silently promoted to verified.
Rollback still requires its separate peer-approved action.

The assessment manifest retains only the requirements hash and per-check
booleans for state difference, desired-state match and time bounds. Original
action arguments and observed values stay in their governed Tool-call records.
This checks the consistency of a reviewed Tool contract and its observations;
it does not independently establish that a vendor/device reported truthful
state. Representative live-device and independent-source accuracy testing is
still required before any autonomous authority can be considered.

Outcome scans are bounded to 200 candidate actions and a 16 MiB canonical source
evidence budget per assessment/read revalidation. Large result fields are deferred
and released between samples rather than loaded as one fleet-sized result batch.
Exceeding either bound records its respective limit reason and degradation,
rather than choosing a favorable subset. Policy
minimum samples cannot exceed 200 in outcome mode. Live database/capacity
acceptance must establish suitable policy windows and fleet limits.

## Integrity and presentation

Immutable assessment manifests retain only runtime/plan/evidence IDs, safe
outcome codes, timestamps, pass/fail and integrity hashes. They contain no raw
targets, action arguments, results, objectives, model prose or credentials.
Canonical assessment hashes include the evidence scope. Current healthy outcome
reads also revalidate their persisted sources; a later source mutation or missing
record invalidates current health and removes its Agent citation.

The dedicated Studio page labels evidence basis and each historical observation's
scope. Execution-health and outcome Agent Tools filter their respective policy
modes; neither silently relabels the other kind of evidence. Both require
namespace-wide `capabilities.read` and reject site/device-scoped callers. Policy
edits/evaluations retain namespace-wide `capabilities.manage`, revision checks,
audit reasons and no-store responses. The existing regional quality controller
evaluates both modes transactionally and executes no Tool or model call.

## Migration and acceptance

Migration `h0j2k4m6p8r1` adds explicit policy/assessment modes and nullable
plan-phase Tool-call identity. Old policy settings default to execution health;
old assessment bodies/hashes and unattributed calls are preserved, not rewritten.
Old current observations require reevaluation under the new mode-bound contract.
Downgrade refuses to lose outcome policies, mode-bound assessment history or
phase-bound calls, and PostgreSQL downgrade requires visibility of all namespaces.

Local tests cover real canonical Tool publication, the graph's approval/resume
loop with a synthetic MCP adapter, separate rollback approval, shared Tool
freshness, source/hash/approval/target/scope/phase tampering, replay/saturation, API
binding rejection, structured state transitions and mismatch/time-bound cases,
two tenants/three regions and real SQLite Alembic round trips.
Synthetic activation/adapter/browser fixtures are not live vendor/device or
PostgreSQL acceptance. Representative vendor/device observation accuracy, production
RLS/concurrency/process-loss recovery and long-duration capacity remain open.
An independently qualified exact-policy execution bridge now uses this evidence
in atomic primary-action authorization and rechecks it before execution-start.
The host gate remains off by default. Native PostgreSQL tests cover the bridge's
RLS, debit contention/retries and pre-commit backend loss, not live semantic truth.
Separately reviewed one-shot rollback authority and controlled Worker-loss
recovery are now implemented with their own default-off host gate; live adapter,
identity/transport and semantic acceptance remain open. Independent incident
closure authority and focused proof UI are separately implemented but not
production/live accepted; M7 and the
full-product objective remain open. See `docs/reviewed-change-preapprovals.md`
for the separate qualification/authority boundary. An assessment by itself
still grants no execution authority.

The Alert-ordering follow-up (private development evidence; not distributed)
also retains newer uncertainty and conservative same-time quality verdicts.
An older evaluation stays historical rather than replacing current assessment
or clearing degradation. Future-dated assessments are not current health; none
of these cursors substitute for independent causal quiet-state verification.

The Quality source checkpoint (private development evidence; not distributed)
now verifies declared/structured outcomes, typed restoration, raw evidence
bounds and sealed primary/rollback authorization history under its exact
restricted PostgreSQL role. Later revocation preserves historical bindings,
but does not permit new actions. Two disclosed timestamp-only grants support
failure-evidence shared locks; native terminal and target guards remain intact.
Simulated action/rollback fixtures, acceptance references and source subprocess
recovery are not vendor semantics, installed systemd or physical repair proof.
