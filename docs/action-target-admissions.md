# Immutable action target admission and closure lookup

Reviewed Situation closure uses indexed, immutable action-routing records rather
than scanning every proposal in a namespace. The records identify which actions
must be examined; they confer no execution permission, semantic verification,
repair-causality attribution or physical-truth claim.

## Retained routing provenance

`ActionTargetAdmission` retains the exact proposal, Investigation and Situation
binding, Tool, own change Plan, routing Plan, rollback context and complete frozen
contract/target snapshots. `ActionTargetKey` contains the distinct device/site
keys derived from that material. Both ledgers are append-only, namespace scoped
and protected by forced PostgreSQL RLS. Each proposal has one admission whose
identity equals the proposal ID; repeated target paths cannot count twice.

There are three routing origins. `frozen_plan` uses the proposal's own Plan.
`frozen_rollback_plan` uses the original frozen Plan when a rollback has no
separate Plan. `legacy_unknown` retains missing Plan material without deriving
targets from mutable arguments or the current Tool registration. Unsupported,
missing, blank, oversized or malformed target bindings remain explicitly unknown.
At most 16 authorization paths are interpreted, matching the governed contract.

An unknown routing record is conservatively related to every Situation in its
namespace. It cannot be silently relabelled known, assigned a later Plan or
discarded to unblock closure. A rejected proposal without any execution can
still be recorded as harmless by the existing closure proof; its retained
routing record itself proves no remediation. Governed reconciliation and deeper
history/retention acceptance remain separate work.

## Admission and native enforcement

The supported proposal path seals routing after Plan creation and before the
admission transaction commits. PostgreSQL also seals after a native Plan insert
and has a deferred constraint trigger that retains every raw/legacy proposal
without a Plan as unknown at commit. Closure makes that constraint immediate
before lookup, so a flushed but uncommitted proposal in the same transaction
cannot escape proof while its fallback is deferred.

Native insertion guards compare all routing material against exact scoped
parents, derive the complete key set and refuse forged indexes. Updates to
proposal/Investigation bindings or frozen Plan routing are refused once retained.
Proposal arguments may change, but cannot redirect the retained lookup. Their
execution/proof consistency remains subject to governed action validation.
Foreign keys and append-only guards retain the routing history during deletion.

Detailed historical closure reads use these same frozen typed keys for current
and initiating read authorization, including every target in a multi-device
action. Current proposal arguments and today's Situation membership cannot
replace them. Unknown routing requires global read scope even for a rejected
proposal without execution. Historical reads do not requalify current peers or
create new action authority. See [historical proof access](reviewed-situation-closure.md#historical-proof-access).

Normal writers keep the shared short transaction fence. Closure keeps the
exclusive short transaction fence and revalidates selected action proof with
fail-fast row locks before locking the Situation parent. No namespace fence is
held for the lease lifetime.

## Indexed lookup and exhaustive bounds

Lookup unions exact Situation binding, device keys, site keys and explicit
unknown records, then deduplicates proposal identities. Composite indexes begin
with tenant/region and include their routing selector. Known unrelated history
does not consume the closure proof budget. Every selected action still requires
the existing current peer, structured outcome, restoration, freshness and
quiet-window checks; the catalog never substitutes for those checks.

The limit remains 256 related or unknown proposals, with five evidence stages
per governed Plan and a 2 MiB durable proof. Exceeding the relevant bound fails
closed. A large unresolved or unknown history is not dropped, sampled or
presented as complete. Representative sustained fleet/history load and sparse
authorization-scope latency are still release gates.

SQLite keeps exhaustive missing-admission fallback because it has no deferred
constraint triggers. Its migrated insertion/reference and append-only guards
and explicit service derivation do not establish native concurrency or fleet
performance. PostgreSQL is the production acceptance target.

## Migration and release boundary

Migration `d8f0h2j4l6n9` follows `c7e9g1i3k5m8`. It requires visibility of every
namespace, locks the affected native tables and refuses undrained Agent
executions/leases or retained claimed closure ownership before DDL. Backfill
copies only frozen own/rollback Plan material, retaining absent or unsupported
routing as unknown. It does not backfill execution authority or independent
semantic qualification. Populated routing history or namespace-limited visibility
refuses downgrade before DDL.

Stop ingress and old processes, drain Agent work, release retained closure claims
and deploy matching API/Worker code in a maintenance window. The component's
isolated migration checks are not acceptance of a live mixed-version cutover.
All reviewed-execution host gates remain off; the integrated demo is deferred.

The verification record (private development evidence; not distributed)
distinguishes component regressions, symbolic 1,000-record routing checks and
actual native query plans from unaccepted production load, live action semantics
and remaining product/UI/lab gates.
