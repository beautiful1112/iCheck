# Reviewed Situation closure

Reviewed closure is a separate control-plane operation with independently
accepted authority, one current lease owner and an atomic historical receipt.
Automatic Alert recovery and a generic Situation `resolved` status still grant
no closure authority. Backend APIs, Agent Tools and a focused governance and
receipt page are implemented and verified in isolation. Sustained fleet/history
load and production/lab acceptance remain release gates. Immutable indexed
action routing is implemented separately. The host switch defaults to off.

The receipt/runtime path supports separate v1 and explicit v2 contracts.
[Replacement recovery v2](reviewed-source-generation-replacement.md) remains
read-only evidence; closing from that evidence additionally requires an explicitly
reviewed v2 grant and compatible claim/Tool intent. It cannot be wrapped in a v1
receipt or inherit v1 consent. The replacement closure host gate defaults to off.

## Replacement closure version 2

V2 policies retain exact old source, permanent retirement and accepted mapping
references while qualifying the current target. Grants persist `proof_version`,
with existing records defaulting to 1. New v2 grants, claims and AI calls must
select version 2 explicitly. Receipts retain
`icheck.reviewed-situation-closure/v2`; stable membership identity is unchanged
so switching policy or proof version cannot close the same members twice.

Current-target samples must follow each covered member's active/last-seen clock,
the permanent retirement's admitted watermark and every related action's
terminal verification. The checker collects actual action evidence before
sampling. Earlier quiet observations cannot block a genuinely later qualifying
window or be borrowed to satisfy its duration. A target that has never created
an Alert is valid; no placeholder Alert or old measurement rewrite is needed.

Typed historical readers validate current qualification and ordered quiet
receipts, old active qualification/receipt, retirement and mapping lineage,
complete frozen membership and both current/initiating scope. They reject
omitted observations within the claimed window, extra material, coerced flags
and inconsistent references. Historical retries never refresh an old producer,
peer or expiry, and do not acquire new execution authority.

`situations.close_reviewed_v2` is a separate builtin using the same runtime-owned
closure handler. Its input requires integer `proof_version=2`; installing it
does not rewrite an existing v1 Tool registration. The existing closure page
discovers retired-member policies, displays their version and the v2 gate, and
pins version in review and claim requests. Read-only recovery remains available
when that gate is off.

Migration `h2j4l6n8p0r3` preserves existing immutable guards and v1 history. It
adds native version compatibility, current mapping/source/policy/grant authority,
strict receipt references/clocks/coverage and an unchanged-member action fence
that recognizes permanent retirement. Its deployment prefix precedes fail-fast
lower locks, and database deadlines use the wall clock after waits. Migration
requires all-namespace visibility and drained API/Collector/Projection/Agent
ownership; downgrade refuses retained v2 grants before removing their schema.
Full origin and Worker attestation remain application checks, not claims made
by the native binding guard.

`ICHECK_ENABLE_REPLACEMENT_RECOVERY` and
`ICHECK_ENABLE_REPLACEMENT_SITUATION_CLOSURE` must both be enabled for new v2
closure, in addition to the reviewed-closure host gate. All deployment examples
default to false. The product host schema and gates are unchanged. Replacement
cutover API/GUI, actual Worker-loss/transport, deep-history, live-device and
production acceptance remain release gates.

Affected verification covers 455 distinct ordinary and 520 distinct migrated
non-owner PostgreSQL cases across resumed runs, including 40 ordinary/58 native
v2 closure cases. Frontend 39 unit cases, typing, targeted lint and production
build pass. The private server/database/role fixture was removed after `0|0`
counts. Exact coverage and corrected fixture assumptions are retained in the
v2 closure record (private development evidence; not distributed).
These results do not establish full-product, browser, live or production acceptance.

## Authority and proof bases

A persisted human with `situations.closure.qualify`, `alerts.read` and
`capabilities.read` explicitly accepts closure authority for a reviewed
[recovery policy](situation-recovery-policies.md). The reviewer must be
independent of the policy author, retain current source scope and permissions,
and provide an acceptance reference. The same independent policy reviewer may
also qualify closure; an unnecessary third review is not required. Grants are
immutable, cannot outlive the recovery policy, and have a 5–120 second maximum
requested lease. Revocation is append-only and remains possible after original
peer loss, origin drift or withdrawal of implementation-read permission.

The executor needs both current persisted `situations.close`/`alerts.read` and
the initiating caller's permissions and scope. Agent execution additionally
retains its Investigation snapshot and exact Situation binding. Role expansion
cannot broaden that snapshot. The executor cannot be the grant reviewer.
Source, policy and closure peers must retain their required authority. Fixture
or lab acceptance cannot authorize a host running in production mode.

Two proof bases remain distinct:

- `source_recovery` requires complete current source recovery without claiming
  that a repair caused it. It can represent automatic/external recovery or
  observed recovery after a structured, verified rollback restoration.
- `verified_remediation` also binds the full material of an exact published
  change Tool with structured state expectations and explicit targets. At
  least one exact Situation-bound action must have independently approved,
  identity-pinned execution and a passing typed pre/action/post transition.
  A boolean success label or an unlinked action cannot substitute for this.

Every related action must be safely terminal. Pending, executing, ambiguous,
unverified, failed-restoration and legacy identity-free results block closure.
The checker revalidates frozen targets, scopes, stages, approvals, activation
pins, structured transitions and restoration. Related actions include
Situation-bound actions and unlinked same-device/site actions; unknown targets
are conservatively related. Current approval/requester identities and target
scope are required. The closer must also be able to read every retained action
target under both its current role and initiating scope; admission cannot create
an unreadable complete receipt. The reviewed quiet window must begin strictly after the
terminal verification of every related action.

These observations are not scientific attribution of recovery to a repair.
Receipts always retain `remediation_causality_proven: false` and
`physical_truth_automatically_verified: false`. Human validation references do
not automatically prove vendor or physical semantics.

## Claim finalization and recovery

1. Claim with a stable request key, exact grant, reason, requested lease and
   expected ownership epoch. The intent pins the complete membership identity,
   not a mutable quiet timestamp. Different intent cannot reuse the key.
2. Admission checks fresh complete recovery and related actions. A lease is
   bounded by grant, source/policy/certificate and measurement deadlines.
   Only the newly admitted caller receives the token; only its hash persists.
3. Finalization repeats authority, source, membership and action checks inside
   the closure transaction. The owner, attempt, token, epoch and lease must
   still match after all waits. An old or released lease cannot finalize.
4. Situation state, a distinct `situation.closure.reviewed` event, audit,
   durable receipt and committed ownership complete in one transaction.
   No Alert episode or source clock is rewritten and no external I/O runs.
5. A lost response recovers the exact committed receipt before reconsidering
   expired/revoked execution authority or a disabled host gate. It still needs
   current scoped read authority and exact ownership. It never closes again.

An exact retry of a live claim returns metadata but never its token or a second
attempt. A lost claim response therefore waits for expiry or an explicit owner
release before a fresh epoch can take over. Release requires the exact owner
and token, but does not require a still-enabled execution gate or grant. New
claims/takeovers require explicit current-epoch comparison and fresh proof.
History is bounded and discloses truncation; historical receipts grant no
future authority. An unchanged membership cannot be closed again with a new
key or a manual status edit. New actual memberships require a new request and
fresh proof; the earlier receipt stays historical.

## Historical proof access

Every full receipt response uses the same historical read boundary, including
history, exact owned-request GET, committed claim/finalization retries and a
cached successful Agent Tool replay. Both current persisted `alerts.read` and
initiating read scope must cover the frozen primary entity, every retained Alert
member, all reviewed policy sources and every immutable action target. Today's
membership, mutable action arguments and current Tool registrations cannot
replace those retained scopes. A different caller may read scoped history but
cannot use the original owner's exact request or lease.

Generic Agent detail, journal and checkpoint reads also check the exact receipts
bound to that Investigation's original runtime-owned closure requests. A caller
with only `investigations.read` cannot recover the proof through those DTOs.
Investigation list/page results filter inaccessible contexts, and an inaccessible
context cannot be used as a page cursor. The binding comes from the retained
request key and Tool-call identity, not a mutable handler or history scope.
Unrelated Investigations keep their existing permissions. This bounded check
reads at most 1000 receipts individually; sustained history-load acceptance
remains separate.

The reader checks exact source qualification and quiet/active receipt lineage,
bounded nonduplicated samples and complete frozen member coverage. Unknown or
missing historical action routing requires global read scope; mutable arguments
never turn unknown history into known scope. A denied full proof fails closed,
without partial evidence or silent omission. The workspace's bounded metadata
list remains separate and grants no proof or execution authority.

Historical reads do not repeat fresh recovery, source attestation, approval,
expiry or host-gate qualification. Authorized readers can therefore recover an
unchanged committed proof after execution withdrawal, peer loss or expiry.
Reads never create a lease, retry a physical action, mint a token or create a
new digest. Later membership generations do not make old protected entities
readable, and role expansion cannot broaden the initiating snapshot.

## Transaction and native database contract

PostgreSQL requires READ COMMITTED with DBAPI autocommit off and an explicitly
selected namespace. Pending caller edits are rejected. Closure uses an
exclusive namespace advisory transaction fence; normal proposal/Investigation
writers use a shared fence and can proceed concurrently with each other. Both
use fail-fast acquisition, not reverse-order waiting. The fence is held only
for the proof transaction, never for the lease lifetime.

All selected deployment mutexes precede source origin locks. Related action,
Plan, stage-call, version and evidence locks use `NOWAIT` before the Situation
parent. The parent is last in the proof chain, ownership follows it, and fresh
membership/scope and deadlines are checked after waits. Contention rolls back
the whole transaction and returns a retryable conflict, not partial proof.

Native proposal guards prevent a new action in a currently claimed Situation
or its unchanged independently closed membership. An Investigation cannot
discard/reassociate its reviewed closure binding. Existing in-flight unlinked
same-target actions block finalization, and the namespace fence prevents a
new writer from slipping between the scan and commit. Later unrelated changes
can occur after that point-in-time receipt; it is never perpetual proof of a
device's state.

Migration `c7e9g1i3k5m8` adds six namespace-scoped tables for grants, revocations,
requests, ownership, attempts and receipts. PostgreSQL forces RLS, guards exact
references/proof shape, ownership transitions and append-only history, checks
receipt lease/grant expiry against its own clock, and installs native writer
fences. Downgrade checks all-namespace visibility and refuses populated history
before any DDL. SQLite remains a development fixture, not concurrent production
acceptance. No production migration or host-gate enablement accompanies the
code change.

## APIs and Agent runtime

| API | Purpose |
| --- | --- |
| `POST /api/v1/situation-closure-grants` | Independent authority qualification |
| `POST /api/v1/situation-closure-grants/{id}/revoke` | Retained emergency withdrawal |
| `POST /api/v1/situations/{id}/closure-claims` | Exact admission or historical committed retry |
| `POST /api/v1/situation-closure-requests/{id}/finalize` | Fresh fenced atomic closure or receipt recovery |
| `POST /api/v1/situation-closure-requests/{id}/release` | Exact owner release |
| `GET /api/v1/situations/{id}/closure-history?limit=50` | Scoped historical receipts and ownership epoch |
| `GET /api/v1/situations/{id}/closure-workspace?limit=50` | Scoped candidate records, metadata-only receipts and current ownership |
| `GET /api/v1/situation-closure-requests/{id}` | Exact owner read recovery without finalization or token regeneration |

`situations.get_recovery_evidence` is a read-only Tool. Replay rechecks current
authority and proof; a changed/expired report cannot be reused as fresh proof.
A new `check_key` permits another bounded observation in the Agent loop.
`situations.close_reviewed` is a control-plane Tool, not a generic physical
action proposal. Its request identity comes from the durable Tool-call ID and
its lease token stays inside the runtime. Completion loss recovers the closure
receipt before completing the Tool journal. A lost claim remains resumable
after expiry; the runtime never mints a second concurrent owner. While its claim
is still live, the API returns a typed `icheck.owned-closure-wait/v1` interruption
instead of failing the investigation. The existing nested Task/journal remains
nonterminal. Its HTTP-only Worker renews the execution lease, checks cancellation
and polls the same operation without a resume value or closure token. Waiting is
limited by a 35-second deadline checked between requests and the shared
32-request interruption budget; each HTTP call retains its configured timeout.
Identity
substitution, epoch regression and switching to an adapter or fresh approval are
rejected. A takeover still rechecks fresh authority after natural lease expiry.

The Tool RPC retries a lost/truncated response at most twice, with the exact
operation and any already-recorded MCP resume. It does not re-invoke an adapter.
HTTP 502/503/504 can retry; permission/conflict/application errors and malformed
JSON cannot. Both versions have real API/Worker SIGKILL coverage at six commit
boundaries and surviving-Worker coverage for a truncated committed response.
Committed receipt recovery remains available after execution/peer/gate
withdrawal without acquiring fresh authority. These are isolated non-owner
PostgreSQL and loopback-model checks, not production identity/vendor acceptance.
See the
runtime recovery record (private development evidence; not distributed).

The API and Worker must be upgraded together with Agent ownership drained.
Older Workers do not recognize the new wait interruption. No product service,
schema or closure gate is changed by this implementation.

Reserved names/handlers enforce their own risk, transport and snapshot
permissions even through aliases with an empty permission list. Unbound or
development-only Investigations cannot close a Situation. Unavailable owned
contexts are omitted from the model's advertised Tool list; historical runtime
recovery remains distinct from new execution. Generic physical action APIs and
direct internal-handler dispatch cannot substitute for this closure path.

`ICHECK_ENABLE_REVIEWED_SITUATION_CLOSURE=false` is the default. This switch is
separate from reviewed primary/rollback physical execution and is not a web
setting or model-supplied parameter.

## Focused operator page

`/situations/{id}/closure` separates closure governance from the AI-first home
and the recovery-evidence page. Manual admission/recovery and independent
qualification/revocation are collapsed sections. Fresh displayed recovery has
an expiring deadline; it never substitutes for backend revalidation of source,
peer, semantic and related-action authority at admission/finalization.

Discovery considers at most 200 recent policies and checks every binding against
both current persisted and initiating caller scopes, even when a source is not
a current Situation member. Grant and receipt lists default to 50 and allow
1–100; truncation is explicit. Optional exact `grant_id` or
`policy_request_id` lookup retrieves an older scoped candidate without scanning
the whole catalog. Mismatched IDs conflict; inaccessible or irrelevant policies
remain unavailable. An accepted record is not a currently qualified authority.

Receipt lists project only metadata and source/action counts in SQL, avoiding
bulk loading full proofs. The latest retained membership identity is compared
with the current identity, explicitly without claiming fresh recovery. Exact
owned-request GET can read one complete retained proof; the UI replaces its
metadata summary and discloses clipping beyond 24 source/action entries.
Deeper history and retention remain separate work.

The page owns stable qualification/admission retry identities and pins their
submitted material until success or an explicit new intent. Lease tokens stay
only in a ref in transient page memory, never React state, rendered markup,
local/session storage or application logging. Reload/navigation discards them;
an exact live-claim retry returns metadata without a replacement token. Each
asynchronous operation is fenced by its namespace generation and operation ID.
Namespace/identity changes and scope denials clear old context and secrets;
delayed old responses cannot attach authority to the new context.

Read recovery needs current `alerts.read`, exact original ownership and current
plus initiating scope for both the current Situation and the complete retained
proof, not a still-valid grant, gate or execution role. GET
never creates an attempt, finalizes a request or replays closure. Exact release
still requires the current attempt's token but survives execution withdrawal.
Independent revocation survives material-read withdrawal; a new qualification
does not. No page control enables the host gate.

The workspace verification record (private development evidence; not distributed)
retains ordinary, migrated non-owner PostgreSQL, frontend and controlled browser
boundaries. Intercepted synthetic browser transport verifies UI behavior; it is
not real browser authentication, vendor semantics or an integrated demo.

The historical scope verification record (private development evidence; not distributed)
retains the later receipt and original Agent-history privacy regressions,
legitimate read-only recovery, native RLS/bearer checks and their distinct
component boundaries. Whole-product and live acceptance remain separate.

## Remaining release gates

The [immutable action-target catalog](action-target-admissions.md) replaces the
namespace-history scan with indexed Situation/device/site/unknown lookup.
Known unrelated history does not consume the 256 related-or-unknown-proposal
proof budget. At most five governed evidence stages per Plan and a 2 MiB durable
proof remain. Exceeding a relevant bound fails closed; unresolved unknown history
is not discarded to qualify closure. Sustained fleet/history load is still open.
Historical receipts per Situation are bounded to 256; deeper governed history
and retention require their own acceptance.

Source-generation replacement and explicit v2 closure are implemented separately.
Owned completion and exact cached journal/receipt/citation guards are now
implemented. Generic completion cannot replace a live claim or committed receipt
after a handler edit. A trusted completion requires the durable receipt and its
single exact citation; terminal Agent history rejects unbound or substituted
material. Running commit gaps stay recoverable. Root invoke/resume persists
the next step synchronously before Tool dispatch. See the
journal guard record (private development evidence; not distributed).

Next are deeper governed history/reconciliation and representative load. Historical proof
scope is enforced separately from current correlation and fresh execution
authority. Broader authoring/accessibility and production Tool transport,
identity/mTLS/secrets/coordinated rollout/load/restart, live models/vendors and
the six-class GUI lab remain open. The integrated demo remains deferred.

Affected tests and their exact boundaries are retained in the
closure verification record (private development evidence; not distributed).
