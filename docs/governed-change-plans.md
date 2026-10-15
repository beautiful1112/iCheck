# Governed change plans

## Boundary

The first M5 slices add an evidence-gated contract above the existing exact-
plan LangGraph interrupt and a separately deployable Ansible execution
adapter. They do not install a live write pack or authorize unattended
remediation. A state-changing Tool opts in by publishing
`icheck.change-tool/v1`; that contract survives Capability Studio publication
and MCP activation. Legacy change Tools still use the earlier four-eyes kernel
for compatibility and are not considered production-ready change adapters.
Development can retain that compatibility with
`ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS=false`. Production configuration is
invalid unless this setting is `true`, and proposal creation then rejects every
state-changing Tool that lacks `icheck.change-tool/v1`, except an exact
rollback already frozen by a governed parent plan.

The contract declares:

- risk class: `low`, `medium`, `high`, or `critical`;
- one or more scalar target paths in the action arguments;
- optional target-to-object-scope bindings (`device_id` or `site`), mandatory
  whenever the Investigation is not globally scoped;
- the action idempotency-key path;
- exact pre-check, dry-run, post-check, and rollback Tool names;
- a destination-to-frozen-target argument mapping for each stage;
- a schema-validated boolean success path for every evidence stage;
- up to eight optional bounded evidence-summary paths per stage; and
- up to eight optional typed desired-state transitions from an action argument
  to pre-check and post-check observation paths, each with bounded timing; and
- an optional read-only `rollback_check` and up to eight typed restoration
  expectations covering every declared pre-change observation; and
- whether a maintenance window is mandatory.

Pre-check, dry-run, and post-check Tools must be enabled and read-only. The
rollback Tool must be state-changing. Every dependency input schema must be
fully satisfied by its mapping; mappings may read only the frozen target paths
but may rename or nest them for a dependency Tool. Success paths must resolve
directly to boolean output schema fields; composed or invented model output is
not accepted. Summary paths may resolve only to booleans, integers/numbers, or
strings whose schema requires a 64-character lowercase hexadecimal SHA-256.
Secret-like paths and arbitrary strings such as raw configuration diffs are
rejected.

State-transition expectations use a non-identity, non-secret action argument
as the desired value. Both read-only observation paths must have the same
non-null scalar schema type as that argument and cannot reuse a stage success
flag. The dependency Tools receive only frozen target fields, not the desired
value. Requirements are frozen in the plan and rechecked against the published
action Tool during outcome-quality evaluation. They do not turn a plan's
boolean `verified` status into autonomous authority; see
`docs/remediation-outcome-quality.md`. The expectations are optional for
human-governed changes but required for new reviewed low-risk preapproval
policies.

Restoration expectations compare the original pre-check values with a separate
read-only call after the separately approved rollback finishes. They cannot use
success flags, secrets, mismatched scalar types or an unbound generic read. The
check receives frozen target fields, not the original values it must observe.
`max_check_delay_seconds` defaults to 300 and is bounded to 60–3,600 seconds.
Original pre-state freshness uses the strictest applicable semantic bound.
A successful rollback action enters `awaiting_rollback_check`; only a passing
restoration check enters `rolled_back`. A false flag, mismatched state or stale
observation enters `rollback_failed`. A missing/failed call remains unverified
and must escalate. This adds verification, not unattended rollback permission.
Legacy contracts retain their declared-boolean semantics and are explicitly
labelled as having no independent original-state check.

Migration `t8v0x2z4b6d9` adds the phase/status constraints without rewriting old
contracts or observations. Downgrade refuses configured restoration contracts,
phase calls and evidence, and refuses an RLS-limited migration connection.

## Durable plan

When LangGraph proposes an opted-in action, iCheck creates one
`icheck.change-plan/v1` record in the same transaction. It freezes:

- the original action-plan hash;
- action and dependency Tool IDs, transports, risk/read-only flags,
  permissions, schema hashes, and update timestamps;
- target values and the Investigation authorization scope;
- a SHA-256 hash of the idempotency key, never its raw value;
- risk and maintenance-window policy; and
- hash-addressed evidence attached to the plan.

The governed plan has its own revision and hash. Approval therefore binds two
hashes: the original Tool/arguments/purpose hash and the governed plan hash.
Optimistic revision and hash checks reject stale evidence or window edits.
For scoped Investigations, every declared authorization target is resolved
against current Device/site visibility at plan creation and again during
approval/execution. Missing bindings, cross-site Devices, deleted Devices, and
Devices moved outside the frozen scope fail closed.

## Risk policy

Risk labels are executable policy, not display metadata. iCheck stores exactly
one revisioned `icheck.change-risk-policy/v1` record for each of `low`,
`medium`, `high`, and `critical`. The policy controls whether execution is
enabled, whether a maintenance window is mandatory, the maximum window length,
and whether the Tool contract must declare a bounded dry-run summary and an
authorization target binding. Built-in defaults progressively tighten those
limits; critical changes require all gates and a maximum 60-minute window.

Plan creation freezes the policy ID, revision, and complete effective values.
Approval and execution compare that snapshot with the current database record.
Disabling or editing the policy therefore invalidates every older pending or
approved plan rather than silently changing its meaning. A new plan and peer
decision are required. Updates use optimistic revisions, require an audit
reason, and persist both previous and current snapshots in the audit trail.

```text
awaiting_evidence
  ├─ pre-check passed
  ├─ dry-run passed
  └─ valid maintenance window, when required
        ↓
ready_for_approval → approved → executing
                                  ├─ success → awaiting_postcheck → verified
                                  └─ failure / failed post-check
                                             ↓
                                      rollback_required
                                        ├─ rolled_back
                                        └─ rollback_failed
```

Rejecting a plan is allowed before it becomes ready. Approving is not. Approval
and execution both recheck that the active maintenance window contains the
current time. Immediately before a handler runs, iCheck also compares every
current Tool against its frozen snapshot and rechecks the authorization scope,
targets, idempotency hash, and both approval hashes. Drift fails closed.

## Evidence

Evidence binding accepts only a successful, persisted Tool call from the same
Investigation, produced by the exact frozen Tool and against the exact target.
The Tool result has already passed its registered output schema. iCheck then
reads the contract's boolean success path and stores only minimized provenance:
Tool/call IDs, argument hash, result hash, pass/fail, stage, actor, and time.
Raw credentials and result payloads do not enter the change plan.
When declared by the frozen contract, only the permitted scalar summary values
enter `evidence_snapshot.summary`; the full schema-validated Tool result remains
bound by its result hash. This gives the peer approver a useful dry-run preview
without persisting or showing raw device configuration.

The LangGraph Tool executor runs pre-check and then dry-run immediately after
the plan is frozen. A false/failed pre-check stops the sequence, so dry-run and
the action cannot run. The durable interrupt payload carries the change-plan
identity, hash, status, and any orchestration error. On approved resume, the
executor reads the existing stage evidence and call IDs rather than replaying
them. After a successful action it runs and binds the frozen post-check. All
four calls count against the same Investigation Tool budget and are reflected
in the resumed graph state.

The same no-replay rule covers a worker crash after action execution. An exact
Tool call already persisted as terminal is reused and its proposal transition
is repaired before post-check continues. A missing or still-running action call
is treated as outcome-unknown; it is not executed again.

Failed pre-check or dry-run evidence cannot make a plan ready. A failed
post-check requires rollback. A successful rollback call is not sufficient by
itself: its declared boolean result must also be true. Evidence attempts remain
append-only, and current policy uses the latest record for each stage.

For a plan with frozen desired-state observations, a true post-check success
flag alone no longer marks the plan verified. Evidence binding rechecks the
plan's material hash and the bound pre-check, then compares the observed state
before and after the action with the fixed desired value within the contract's
time bounds. A mismatch records a failed effective post-check and moves the
plan to `rollback_required`. The graph exposes the exact frozen rollback
request, but distinct peer or independently qualified recovery authority is
still mandatory before it can run.

When the post-check fails, the graph result gives the reasoner the exact frozen
rollback Tool name and mapped arguments with `requires_new_approval: true`. If
the reasoner requests it, iCheck matches exactly one rollback-required parent
plan and creates a normal state-changing proposal with a durable
`rollback_of_change_plan_id`. That proposal needs its own peer decision or a
separately qualified recovery grant; the original approval never supplies it. After
execution, the runtime validates the declared boolean rollback outcome and
binds it back to the parent plan as `rolled_back` or `rollback_failed`.
Production strict admission does not require that rollback Tool to declare a
recursive change contract. It permits the contract-less Tool only after the
runtime proves the exact Tool and arguments match one rollback-required parent;
the separate proposal and its distinct authority remain mandatory. Automatic
recovery is independently default-off and only admits a succeeded primary
action with a verified causal failed post-check. Failed/uncertain action calls
remain on the human/reconciliation path. Manual execution-start and automatic
admission serialize one-shot ownership on the same parent; another purpose
does not gain another write slot. See the
[recovery contract](./reviewed-change-preapprovals.md#independent-rollback-qualification-and-one-shot-recovery).

Verification now additionally freezes complete dependency schemas and validates
persisted argument/result hashes, exact mapped targets and causal timestamps.
Post-checks must begin after the actual action finished. Plan-and-phase call
identity permits a fresh read when pre-check and post-check use the same Tool
and arguments; recovery does not reuse a call from another phase or plan.
Rollback requires the actual failure/failed post-check and its separate exact
authorized proposal. Legacy plans without the frozen schemas require a fresh
plan, not inferred evidence. See `docs/remediation-outcome-quality.md` for the
separate, non-authorizing quality assessment of these declared outcomes.

## API and UI

| Purpose | Endpoint |
|---|---|
| Read scoped plan | `GET /api/v1/agent/action-proposals/{id}/change-plan` |
| Read scoped parent plan | `GET /api/v1/agent/change-plans/{id}` |
| Configure window | `PATCH .../{id}/change-plan/window` |
| Bind evidence | `POST .../{id}/change-plan/evidence` |
| Decide exact proposal and plan | `POST .../{id}/decision` |
| List risk policies | `GET /api/v1/agent/change-risk-policies` |
| Revise one risk policy | `PATCH /api/v1/agent/change-risk-policies/{risk_class}` |

`/approvals` displays the frozen targets, risk, status, idempotency hash,
evidence gates, maintenance window, and both approval hashes. It can bind the
latest eligible Investigation Tool call and configure the window. The requester
or operator uses `changes.plan`; the peer approver uses `changes.approve` and
still cannot approve their own action. Operators and approvers receive
`changes.policy.read`; only administrators (or a custom role with
`changes.policy.manage`) can revise policy. `/settings/change-policy` is the
separate administrative surface and is linked from `/approvals`, not placed on
the AI L1 home.

The separate `/settings/change-policy/preapprovals` page records reviewed
exact Tool/device/Alert envelopes and previews plan eligibility. These records
alone do not change the four-eyes action decision or its runtime boundary. A
separate independently qualified execution grant can authorize an exact primary
low-risk action when the host gate is enabled. Its immutable receipt and Alert
debit commit with the plan decision, and the runtime repeats current authority
checks before execution-start. The host gate is off by default. See
`docs/reviewed-change-preapprovals.md`.

The same subpage now exposes separate independent restoration qualification,
bounded recovery settings, expiry and append-only revocation for one primary
grant. It executes nothing by itself. The independent rollback host switch is
also off by default; historical rollback receipts on `/approvals` identify the
one failed-parent slot and original primary authorization without claiming
current permission, successful primary remediation or incident closure.

New plans hash a bounded snapshot of their originating Situation and then-open
Alert identities. Preapproval requires that frozen origin; adding a Situation or
Alert later cannot qualify an old plan. Changing the Investigation's Situation
invalidates the plan even for human approval and requires a new plan. A plan
without a usable Alert snapshot can still use the human path when its frozen
Situation and other governed evidence remain valid.

Reviewed preapproval also gives passed precheck and dry-run calls their own
completion-age limit, separate from Alert age. Preview alone does not authorize
execution; these freshness checks also apply to reviewed-policy admission.

## Current limitations

- The bounded Ansible Runner adapter and systemd templates are implemented, but
  Ansible Runner, a reviewed live pack, MCP activation, and device acceptance
  are not installed or claimed by this slice.
- `/approvals` retains manual evidence binding as an audited recovery path, but
  the normal runtime now schedules pre-check, dry-run, and post-check itself.
- The reasoner may request the frozen rollback, but its linked proposal always
  needs distinct authority. Human approval remains the default; independently
  qualified one-shot recovery is optional behind its separate disabled host
  switch. Primary permission never supplies rollback permission.
- A failed automatic stage is not replayed inside the same Investigation;
  operators must reject/escalate and create a fresh plan after fixing the cause.
- A delegated MCP write has one dispatch opportunity bound to an exact Worker
  attempt and running Tool call. Only that attempt may return its matching
  result. Neither an exact retry without a result nor a replacement Worker may
  redispatch it. A committed terminal result can be recovered without I/O;
  unknown running results require independent reconciliation even under human
  approval. Recorded MCP phase positions/citations survive repeated resumes.
  See [the result-ownership boundary](./agent-runtime.md#delegated-write-result-ownership).
- Sequential requests in one reasoning iteration now own distinct checkpointed
  Tasks and human decisions. Exact generic citation receipts preserve internal
  and MCP phase references across waits; source/result drift denies recovery.
  A refused second action retains its real pre-check/dry-run and prior completed
  action trace without inventing a primary call/result. A plain operation
  checkpoint/result commit gap recovers recorded results, not uncertain writes.
  See [the request/citation contract](./agent-runtime.md#sequential-request-checkpoints-and-exact-generic-citations).
  Drained, coordinated API/Worker migration is required; the controlled tests
  are not mixed-version or live production acceptance.
- Existing Tools without `icheck.change-tool/v1` remain compatible with the
  earlier exact-plan approval path only when the development compatibility gate
  is disabled. Production requires the new contract.
- Live device execution, kill testing against a production adapter, and
  production-scale concurrency acceptance wait for the lab. Native PostgreSQL
  tests cover atomic reviewed-policy admission/debit contention and backend
  termination before commit. The database-level terminal-result recovery and
  uncertain-action no-replay paths are covered. Separately qualified automatic
  rollback admission is implemented. Real Worker SIGKILL and a controlled
  loopback MCP adapter now cover in-flight unknown and committed-result recovery,
  including a six-phase all-MCP flow. Production adapter/Worker recovery,
  independent live semantic truth and incident closure remain open.
