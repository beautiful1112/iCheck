# Reviewed change preapprovals

iCheck now records a reviewed policy for one low-risk remediation Tool version,
one active device, one Alert event type and one exact action argument template.
Operators can author it in `/settings/change-policy/preapprovals` and preview a
concrete governed change plan. A reviewed record and a matching preview do not
approve a proposal or run a Tool. A separate independent execution grant can
qualify this exact reviewed revision. The Agent can use it only when the host's
reviewed-execution gate is explicitly enabled and all current admission checks
pass. The default remains human approval. The policy list is paged in batches
of 100 for larger fleets.

The Web Tool picker searches and pages the namespace-local Capability Catalog
in batches of 100. It offers only published, currently ready Tool versions
whose low-risk change contract identifies a device and declares desired-state
observations. The catalog's bounded scan is reported explicitly; a name search
can narrow a large fleet before that bound. The picker is a convenience, not
an authorization decision: creation, review and preview validate the exact
version and hash independently. A Tool selected before its MCP server becomes
unhealthy, disabled or disallowed cannot produce a matching preview. The same
applies to a missing, disabled or out-of-scope credential profile. A Tool
selection remains visible when the operator changes pages or search terms;
the stored content hash still comes from the originally selected version.

## Policy scope and review

The author selects a published Tool version and its canonical content hash, an
active device with a site, an Alert type, fixed action arguments, a maximum
Alert age, a separate maximum precheck/dry-run age and an expiry no more than
30 days away. Both age limits range from 60 to 3600 seconds and default to 300.
Only the idempotency-key value can vary: the template uses
`__ICHECK_IDEMPOTENCY_KEY__` at the Tool contract's declared path. Every other
action argument is fixed. The Tool must
declare `icheck.change-tool/v1`, low risk and an explicit device authorization
target. New policies also require a published desired-state observation
contract: a non-identity action argument with typed read-only precheck and
postcheck observation paths. Its current input schema must accept the template.
Templates are limited to 4096 canonical bytes and checked for inline secrets.

Policy names are unique per tenant and region. Creation starts in `draft`.
Review requires `changes.policy.manage` and `changes.approve`, a persistent,
enabled Principal that can access this region and is distinct from the author.
The service checks the reviewer's current persisted role bindings both at
review and preview time; removing either permission invalidates the preview.
Review binds the exact revision and fields with a SHA-256 hash. An edit
clears review and creates a new draft revision; revocation is final. Each action
requires a reason and writes a hash-only policy audit reference. The policy
stores a one-to-three-action limit per Alert. It is not an execution permission.

## Eligibility preview

The preview reads a specific, scoped governed plan. It checks a current review
and reviewer identity, expiry, low-risk ready state, complete frozen plan and
prerequisite evidence, an active required maintenance window, current published
Tool material and active MCP activation, exact device/site and action arguments,
current MCP endpoint policy, server health and credential readiness,
and an open Situation with a fresh open Alert for that same device and event
type. A future-dated Alert does not count. The latest passed precheck and
dry-run calls must each have completed within the separate evidence-age limit;
reattaching an old result cannot refresh its completion time. A fresh Alert
alone does not make stale prerequisite evidence eligible.

The preview compares each published desired-state argument with the exact
precheck Tool result. The observed pre-state must differ from the desired value
and match its frozen scalar schema type. It must also be no older than the
Tool contract's own `max_precheck_age_seconds` bound at preview time, in
addition to the policy's precheck/dry-run age bound. A true boolean precheck
cannot conceal an already-satisfied or stale observed state. The contract,
time bounds and observation paths must match the frozen governed plan. These
checks run again when the internal budget claim is attempted, but still grant
no approval or execution authority. Post-action state validation belongs to
the governed post-check verdict and an independent remediation outcome quality
assessment. Neither a preview nor a quality assessment grants authority: the
separate execution-grant and admission path below is required.

At plan creation, iCheck freezes the Investigation's Situation and up to 256
then-open Alert identities into the plan hash. Each identity includes the Alert
ID, event type, entity, deduplication key and first-seen time. Preapproval only
accepts a current Alert from that frozen set whose stable identity still
matches. A Situation attached afterward, a newly added Alert, a repurposed
Alert row, an origin set above the bound, or a legacy plan without this snapshot
cannot qualify. An Investigation whose Situation changes after plan creation
also invalidates that plan for human approval and requires replanning. A plan
that simply lacks a usable Alert snapshot can still follow the human path when
its other governed evidence remains valid. The source snapshot proves causal
association, not that a vendor or device reading is semantically correct.

The preview also reads the durable budget claim count for that Alert and its
effective ceiling. A prior claim under a stricter policy limits
later policies too, so creating a higher-limit policy cannot reset the budget.
The preview returns `candidate_matches`, the matched Alert and budget state,
and reason codes, while `authorizes_execution` remains false. It never changes
proposal, plan, Investigation or Worker state.

Policies tied to older published Tool versions without state observations
cannot be newly created or re-reviewed. An existing reviewed record remains
stored for audit but its preview cannot match; it must be replaced with a new
policy for a newly published Tool version. No policy or review is silently
upgraded to a different Tool contract.

An internal claim primitive takes a shared read lock on the scoped policy and
exclusive locks on the plan and matched Alert, then rechecks the entire
eligibility preview before writing one immutable claim. Different Alerts can
be claimed under one policy without an exclusive policy-row bottleneck; claims
against one Alert serialize on that Alert row in PostgreSQL. An exact retry
returns the already-written claim before a fresh eligibility preview, even if
the Alert has since become stale. A different policy, changed reviewed policy
material or changed plan material cannot reuse it. Returning that historical
debit never refreshes eligibility or authorizes execution. Each claim permanently
uses a slot, even if no device action follows; this is a deliberate fail-closed
rule until a separately proved no-side-effect release protocol exists. The
claim table is unique by governed plan and scoped by tenant and region; database
triggers reject update or deletion. No public claim endpoint exists. The
reviewed authorization path now calls the same primitive inside its own
transaction; debit, exact plan approval, authorization receipt, audit and queue
transition either commit together or all roll back. A standalone historical
claim can be reused only for its exact plan and reviewed policy; the admission
checks are still performed again. The ledger alone is not authority.

PostgreSQL claims require `READ COMMITTED` isolation: the ledger recount after
waiting for the Alert lock must use a new snapshot. Other isolation levels
fail closed before writing a claim. Actual DBAPI autocommit must also be
disabled so row locks, the debit and its audit share one transaction. Callers
must not reuse a long-lived `REPEATABLE READ` transaction for this primitive.

## Independent execution qualification

The separate qualification panel on `/settings/change-policy/preapprovals`
reads minimized exact-device/template evidence and recorded grant history. A
version-wide healthy score is insufficient. Qualification requires a current
`remediation_outcome` quality policy for the exact published version and content,
a zero-failure threshold, no failed or truncated evidence, and at least that
policy's minimum sample count of verified structured state transitions matching
the fixed device and argument template. Declared-boolean-only evidence cannot
qualify. Device, site, Tool and credential readiness are revalidated too.

An enabled persisted Principal with current `changes.policy.manage` and
`changes.approve`, region access and device scope records the grant. The
reviewer cannot be the policy author, quality-policy author or qualification
assessment evaluator. The payload binds the exact current policy-review and
assessment IDs, a future expiry within the policy expiry, an audit reason,
an acceptance reference and an explicit independent-validation confirmation.
The confirmation/reference are the reviewer's assertion of validation, not an
automatic check of external report contents or proof of live vendor accuracy.
Representative independent device observations still need lab acceptance.

The grant is immutable and unique for the reviewed policy revision. It records
the reviewer's persisted identity and pins the quality configuration and
qualification assessment. Creating it neither approves an action nor consumes
an Alert budget slot. An exact current retry returns the same grant; changing
or renewing it requires a revised, independently reviewed policy. Revoking the
policy stops new admission without deleting history. The UI calls history
"recorded", not a blanket assertion of current execution readiness, and shows
the host switch separately. Cached evidence expires in the form too.

## Exact authorization and execution admission

`ICHECK_ENABLE_REVIEWED_CHANGE_EXECUTION=false` is the default and remains
unchanged on this host. Enabling it also requires
`ICHECK_REQUIRE_GOVERNED_CHANGE_CONTRACTS=true`; it does not bypass per-policy
qualification, independent review, risk, scope or evidence gates. With the
host gate enabled, the Agent's existing LangGraph action path tries a bounded
namespace-local grant scan after successful precheck/dry-run. Ineligible or
saturated scans follow the existing human interrupt. High/critical-risk,
unmatched and rollback proposals do not inherit this primary-action authority.
Required maintenance windows still apply; qualification does not waive them.

Authorization rechecks both persisted policy and execution reviewers, their
current permissions/device scope, grant expiry, reviewed revision, Tool and
quality pins. It evaluates fresh outcome evidence again, requires an independent
execution reviewer distinct from the action requester, and binds exactly one
pending primary proposal. It then rechecks the frozen Alert origin, current
Alert identity/freshness, target, arguments, desired pre-state, prerequisites
and durable per-Alert ceiling. The immutable authorization receipt links the
grant, debit, exact action/plan hashes and current quality assessment. An exact
retry returns that receipt without another debit when current authority remains
valid. Historical receipt reads do not renew eligibility.

The runtime repeats current grant, reviewer, quality, source and budget checks
under database locks immediately before recording execution-start. Turning off
the host gate, reviewer revocation, target/source drift or degraded evidence
denies a not-yet-started action. This transaction boundary does not promise to
cancel network I/O already admitted and sent. Existing exact Tool/activation
and requester-scope checks remain in force. A terminal persisted action result
can be recovered without repeating it. A missing or still-running result is
outcome-unknown and requires independent reconciliation; reviewed authority
never permits replay of an ambiguous action.

Outcome verification validates the sealed historical authorization bindings,
not today's grant availability: later revocation cannot erase a completed
action's history or turn it into a human approval. A failed semantic post-check
still makes the parent plan rollback-required. This primary bridge never
authorizes rollback or incident closure. The separate recovery path below can
authorize an exact rollback proposal; closure remains unimplemented.

| Purpose | Endpoint (under `/api/v1/agent`) |
|---|---|
| Read scoped minimized qualification evidence | `GET /change-preapprovals/{policy}/execution-qualification` |
| Read recorded grants and host gate state | `GET /change-preapprovals/{policy}/execution-grants` |
| Independently qualify an exact policy revision | `POST /change-preapprovals/{policy}/execution-grants` |
| Authorize an already waiting exact plan | `POST /change-preapprovals/{policy}/execution-grants/{grant}/change-plans/{plan}/authorize` |
| Read the scoped historical action receipt | `GET /action-proposals/{proposal}/reviewed-authorization` |

The explicit authorization endpoint requires scoped plan/investigation access,
`changes.plan`, policy-read permission and both expected hashes. It queues the
already waiting execution, not a new Investigation or arbitrary Tool call.
Qualification/history reads hide policies outside the caller's device scope.

The ledger and authority transactions have passed native PostgreSQL contention,
non-owner RLS and pre-commit backend-termination checks. These are controlled
database tests, not live action/rollback, whole-server failover, production
upgrade, sustained capacity or semantic-accuracy acceptance. Keep unattended
execution disabled until the remaining release gates are accepted.

## Independent rollback qualification and one-shot recovery

The primary grant's qualification panel exposes a separate recovery section.
It configures the minimum independent restoration samples (default 5, range
1–200), evidence window (default/max 1440 minutes), maximum sample age
(default/max 86400 seconds, minimum 60), and failure-to-start deadline
(default 300 seconds, range 60–3600). The effective evidence horizon is the
smaller of window and age. Reads are bounded to 200 matching attempted recovery
plans and the existing 16 MiB outcome-proof budget; overflow or invalid/failed
history makes the recovery circuit ineligible. No raw configuration values are
added to the minimized evidence manifest.

Qualification requires a current exact primary grant, active target/site,
published low-risk version, structured `rollback_check` and complete typed
original-state observations. Only verified independent human recoveries for
the exact device/template and identical frozen Tool/risk dependencies count as
positive samples; repeated purposes are deduplicated. Automated recovery
failures invalidate the circuit, but automated successes cannot bootstrap its
own independent qualification. Failed remediation remains failed primary
quality; recovery readiness does not require falsely making it healthy again.

An enabled persisted reviewer with current policy-management and approval
permissions, namespace/device scope and no role in the source actions records
the grant. The policy author cannot qualify it. The request includes the exact
current evidence digest, independently validated reference, confirmation,
reason and a future expiry no later than the primary grant expiry. As with
primary qualification, a reference/confirmation is a reviewer assertion, not
automatic validation of external report contents or live vendor truth. Grant
creation executes nothing and consumes no Alert slot. The immutable record
pins settings, minimized proof and dependency snapshots, and is unique to one
primary grant. Changed/expired/revoked qualification requires a newly reviewed
primary policy revision, not renewal by editing its history.

`ICHECK_ENABLE_REVIEWED_ROLLBACK_EXECUTION=false` is independent and default off.
Enabling it requires primary execution to be enabled, which in turn requires
mandatory governed change contracts. An eligible rollback must bind the exact
succeeded primary action and its immutable primary authorization/debit, verified
causal failed post-check, original target/template/Tool implementations and
one low-risk `rollback_required` parent. Failed/uncertain primary Tool calls
do not qualify. Current reviewer roles, grants, policy, device/site, Tool/risk
pins, required maintenance window, failure deadline and stable causal Alert
identity are checked again. Current independent recovery proof must remain
healthy. Expired/revoked authority or drift falls back to the human interrupt;
it does not create a new unattended attempt.

The parent row serializes ownership for both human execution-start and automatic
admission. One immutable automatic receipt owns exactly one failed-parent
recovery slot, linking the separate grant, original primary receipt, exact
rollback action hash, failed post-check witness and recovery proof. Approval,
receipt, audit and queue transition commit together. There is no new Alert
debit, refund, reset or extra primary budget. Another rollback purpose or
proposal cannot obtain a second write after either ownership path starts.
Any unresolved write needs independent reconciliation and, where appropriate,
a newly planned/reviewed change; changing its wording is not another budget.

Execution-start repeats current admission under the grant and parent locks.
Revocation is a separate immutable record and blocks new starts without
erasing earlier receipt/proof. An exact authorized/completed retry returns its
historical receipt, never queues or executes again. Terminal recorded rollback
results are reused; missing/running results stay outcome-unknown even when a
delegated recovery caller permits ordinary running calls. This boundary does
not cancel I/O already admitted and sent, prove an adapter's idempotency, or
replace real Worker/process-loss and live semantic acceptance.

The GUI separates host-switch state, current independent proof, recorded grant,
expiry and revocation. A 403/409 qualification rejection clears proof and
confirmation while preserving the operator's reference/reason; refresh and
independent review are required before retry. History reload uses the recorded
sample settings rather than defaults. Approval history displays one-slot
ownership and its primary/failure references, with explicit historical-only
labels. Neither a receipt nor matching restoration means successful primary
remediation or incident closure.

| Purpose | Endpoint (under `/api/v1/agent`) |
|---|---|
| Read minimized recovery readiness | `GET /change-preapprovals/{policy}/execution-grants/{primary}/rollback-qualification` |
| Read recorded grant, revocation and host switch | `GET /change-preapprovals/{policy}/execution-grants/{primary}/rollback-grants` |
| Independently qualify recovery | `POST /change-preapprovals/{policy}/execution-grants/{primary}/rollback-grants` |
| Append independent grant revocation | `POST /change-preapprovals/{policy}/execution-grants/{primary}/rollback-grants/{grant}/revoke` |
| Authorize an exact waiting rollback | `POST /action-proposals/{proposal}/rollback-authorizations` |
| Read historical one-slot ownership | `GET /action-proposals/{proposal}/rollback-authorization` |

Migration `u9w1y3a5c7e0`, after `t8v0x2z4b6d9`, creates the three namespace-local
grant/revocation/receipt tables with restrictive foreign keys, uniqueness, RLS
and database-level update/delete rejection. Downgrade refuses any such history
or an RLS-limited migration role before dropping anything. These changes have
been exercised only in isolated acceptance databases; no production migration
or automatic host enablement was performed. See the
verification record (private development evidence; not distributed).

## Storage and acceptance

Migration `i1k3m5p7r9t2` creates the namespace-local policy table;
`j2l4n6p8r0t3` adds the budget claim table and its immutable-row guard; and
`k3m5p7r9t1v4` adds the independent evidence-age limit. The table remains
under PostgreSQL row-level isolation. The last migration gives existing
policies a 300-second default. Because that new field was not covered by
earlier peer-review hashes, it returns previously reviewed policies to draft,
increments their revision and writes a namespace-local, hash-only audit event.
An independent reviewer must review them again before they can match. Existing
budget claims remain immutable. Downgrade refuses to discard configured
policy or claim history and requires visibility across namespaces. Local tests
cover review-role revocation, stale prerequisite rejection, claim idempotency,
budget exhaustion across policies, frozen-origin membership and identity drift,
semantic-contract admission, already-satisfied and stale pre-state rejection,
target/Alert drift, tenant and region isolation, and SQLite Alembic round trips.
Migration `s7u9w1y3a5c8` adds namespace-local immutable execution-grant and
authorization-receipt tables, indexes and PostgreSQL RLS. Downgrade refuses any
populated authority history and any migration role with RLS-limited visibility;
it never silently discards grants or decisions.

On 2026-10-03, the opt-in PostgreSQL suite (private development evidence; not distributed)
passed 11 tests on PostgreSQL 16.15, including the full empty-schema migration
roundtrip, cross-policy contention, simultaneous exact retries, independent
Alerts under one policy, tenant/region raw-SQL isolation and immutable-row
guards. Actual backend termination before commit left no claim or budget audit;
simulated response loss after commit preserved both and allowed an exact retry.
The focused SQLite regression passed 17 tests. Neither fixture data nor these
bounded failures establish live-device, production upgrade, HA, backup/restore
or capacity acceptance. The integrated demo remains deferred.

On 2026-10-05, the authority bridge passed 13 focused unit cases and the complete
ordinary backend regression. The complete native suite passed 687 tests with
one opt-in skip. Four new authority cases cover non-owner sealed-history/RLS,
populated downgrade refusal, concurrent distinct admissions/exact retries and
actual backend termination before the authorization transaction commits. The
full empty-schema PostgreSQL migration roundtrip also passes. Frontend checks
and conditional browser rejection/expiry/retry, recorded-history, reload and
390px layout checks pass. All temporary services and generated database objects
were cleaned up. The effective host gate remains off, and Prometheus/SNMP
Exporter stayed active. See the
verification record (private development evidence; not distributed).
None of these fixtures completes M7 or accepts a live unattended action.

Subsequent restoration work adds a typed read-only original-state check after
a separately approved rollback. It does not broaden a primary execution grant.
The receipt verifier now reconstructs the immutable approved revision after
post-check/rollback evidence is attached, while also validating the current
revision. Exact historical completion and later policy revocation remain
auditable; new admission still requires current policy and quality gates.
See rollback restoration verification (private development evidence; not distributed).
Restoration verification alone grants no automatic permission. The distinct
qualification/admission path above now supplies bounded recovery authority;
incident closure and live recovery/semantic acceptance remain required.
