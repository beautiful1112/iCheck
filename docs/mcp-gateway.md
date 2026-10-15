# Governed MCP Gateway

## Product boundary

iCheck uses MCP at the external and user-extension boundary. Trusted core tools
remain typed in-process handlers; high-frequency collection remains a worker or
exporter protocol. An MCP server may group a focused operational domain and
does not need to be created per tool.

The first repository-owned production adapter is the separately deployed,
loopback-only Ansible Runner MCP service. Its reviewed catalog exposes five
stage Tools per operation and adds project/inventory/runner attestation,
explicit host allowlists, process isolation, and apply idempotency below this
gateway. See [Governed Ansible action adapter](./ansible-action-adapter.md).

The implemented gateway uses the stateless MCP `2026-07-28` HTTP transport. A
dedicated, database-free attestor Worker performs bounded `tools/list` contract
attestation; leased Agent Workers perform synchronous `tools/call`.
JSON responses and a single JSON-RPC response carried as an SSE event are
accepted. Session initialization, server-side tasks, MRTR, elicitation,
sampling, resources, and prompts are not enabled; unexpected task responses
fail closed. HTTP authorization supports static credential references or the
MCP `2026-07-28` OAuth Authorization Code flow described below.

## Publication is not activation

The executable path is deliberately split:

```text
Capability Studio generates Tool Artifact
  → deterministic schema + fixture validation
  → human publishes immutable version
  → administrator registers MCP server
  → OAuth connection, when selected
  → administrator queues an attestation
  → authenticated attestor Worker claims a bounded lease
  → Worker resolves its credential grant and runs live tools/list
  → exact input/output schema match
  → fresh hash-only attestation result
  → reasoned activation consumes that result exactly once
  → deterministic canary cohort + executable Tool Registry entry
  → runtime evidence gate + reasoned human promotion to 100%
```

Publishing `icheck.tool/v1` still has no runtime side effect. Direct creation of
an MCP Tool Registry entry through `/agent/tools` is rejected. Activation
requires the Artifact to be a published Tool version and its declared server
name to match. It also requires an unexpired, unconsumed Worker attestation for
the exact server configuration, credential-profile revision, Artifact content,
contract, and schema hashes. The result is valid for 15 minutes. Activation
does no outbound network or secret resolution; it atomically consumes the
attestation and creates the Registry entry in canary state. The activation
ledger pins the Artifact version, registry ID, server ID, tool names, schema hashes, contract
hash, actor, reason, attestor Worker, attestation time, rollout thresholds,
runtime counters, circuit state, revision, and promotion evidence.

Canary membership is a stable SHA-256 bucket over the activation and
investigation IDs. The model catalog and both local and delegated execution
paths independently enforce that cohort. Successful and failed calls update
the activation under a row lock. Promotion to full traffic requires the
configured successful-call floor, the failed-call budget, a closed circuit, an
expected revision, and a reasoned human action. Consecutive failures, or a
canary failure budget breach, open the circuit and disable the Registry entry.
Recovery requires a new exact-contract Worker attestation; consuming it resets
the counters and returns the same activation to a bounded canary rather than
silently restoring full traffic.

An active tool name must be deactivated before another version can own it. A
deactivated immutable version cannot be reactivated; a new version must be
published and attested. Deactivation disables the Registry entry immediately.

## Runtime execution

The existing LangGraph reason → tools → evidence loop can select an activated
MCP tool like an internal tool. The database executor rechecks, at call time:

- the Tool Registry entry is enabled;
- one governed activation is active;
- the activation circuit is closed and this investigation belongs to the
  deterministic canary cohort, unless it has already been promoted to full;
- the MCP server is enabled and its URL is still policy-valid;
- an OAuth server is connected rather than disconnected, revoked, or pending
  Vault cleanup;
- the pinned Artifact version remains published;
- the investigation permission snapshot permits the tool;
- the worker advertises the `mcp` capability; and
- any credential profile matches the worker and its active execution lease.

Arguments are validated before network access. The server must return an object
in `structuredContent`; that object is size-bounded, secret-redacted, and
validated against the published output schema before it enters the model
context or database. Successful calls create normal tool-call records plus a
hash-addressed `mcp_tool_result` evidence reference. Remote content is evidence,
not trusted instruction.

Read-only tools may participate in the bounded multi-step agent loop. A
state-changing MCP tool uses the same exact-plan, four-eyes LangGraph interrupt
as an internal tool, so `tools/call` does not occur before approval. The
approval, duplicate-call, iteration, tool-call, token, and wall-clock budgets
remain transport-independent.

Published `situation`-triggered Workflows are the outbound incident and
collaboration adapter boundary. A separately activated binding converts one
allowed Situation lifecycle event into a typed, scoped Investigation input;
the Workflow may then invoke an attested ServiceNow, Jira, Slack, Teams, or
private-system MCP Tool. Product-specific APIs and credentials therefore stay
outside the Situation core. The outbox does not bypass MCP activation,
call-time compatibility, approval, or evidence checks.
When a binding declares a remote-reference contract, activation also verifies
that the named producer is a pinned MCP dependency and that every configured
path resolves to a string in its registered output schema. Terminal Workflow
commit requires exactly one successful call to that producer. Its bounded
result becomes the durable remote reference; arbitrary model text cannot create
or change that identity.

## Network and credential controls

`ICHECK_MCP_ALLOWED_HOSTS` is an exact/wildcard outbound host allowlist.
Non-loopback endpoints require HTTPS. Embedded credentials, query strings,
fragments, and HTTP redirects are rejected. Requests include
`MCP-Protocol-Version`, `Mcp-Method`, and, for calls, `Mcp-Name`; response bytes,
pagination, timeout, schema depth, schema size, and result bytes are bounded.

Database rows contain only a credential profile reference. Both the attestor
Worker and the leased Agent Worker resolve the referenced environment or Vault
KV v2 secret locally through `WorkerCredentialBroker`. An attestation grant is
scoped to its job and lease; an execution grant is scoped to the activation and
Agent execution lease. Bearer, Basic, API-key, and explicitly named safe header
shapes are supported. Resolved values are zeroed after the request and scrubbed
from returned values and errors.

The attestor uses a dedicated bootstrap token, receives the reserved
`mcp_attestation` capability and `mcp_attestor` role only from its registration
endpoint, then authenticates claims and completion with its Worker Bearer token
and the configured Worker mTLS policy. Ordinary Agent registration and
heartbeat cannot acquire that capability. Jobs use hashed, Worker-bound lease
tokens, bounded retries with backoff, dead-letter state, tenant/region RLS, and
hash-only failure evidence. Claim payloads contain credential references, never
resolved secrets.

`POST /servers/{id}/check` remains an optional synchronous administrator
diagnostic. It may use the control plane's own unscoped environment/Vault
identity, but it is not an activation gate and cannot substitute for a Worker
attestation. `/settings/mcp` creates credential references without accepting a
secret value.

## OAuth authorization and token boundary

OAuth-enabled servers implement the MCP `2026-07-28` HTTP authorization flow:

1. iCheck probes `tools/list` and parses a Bearer `WWW-Authenticate` challenge.
2. It uses the advertised `resource_metadata` URL or the path-specific then
   root RFC 9728 well-known locations.
3. Protected-resource metadata must identify the exact canonical MCP endpoint.
   When it advertises multiple authorization servers, an administrator must
   select one explicitly.
4. The client tries RFC 8414 and OpenID Connect discovery locations in the MCP
   mandated order and requires an exact issuer match, allowlisted HTTPS
   endpoints, Authorization Code support, and PKCE `S256`.
5. A one-time, ten-minute transaction stores only hashed state/browser tokens,
   an encrypted PKCE verifier, issuer/resource binding, scope list, and metadata
   hash. The authorization request includes PKCE and the RFC 8707 `resource`.
6. The callback validates RFC 9207 `iss` before sending the code to any token
   endpoint, rediscovers and compares metadata, consumes the transaction once,
   and includes the same `resource` in the token request.

The initial 401 scope challenge is authoritative. A configured scope list acts as an
upper bound; a challenge outside it fails. Without a challenge, iCheck requests
the configured scopes or the protected resource's advertised minimum. A
configured `offline_access` is added only when advertised. Pre-registered
client IDs and HTTPS Client ID Metadata Document URLs are supported. iCheck can
publish its own public-client metadata at
`/api/v1/mcp/oauth/client-metadata`. Deprecated Dynamic Client Registration is
not implemented.

Access and refresh tokens never enter the iCheck database, an audit document,
an API response, or LangGraph state. The callback writes a bundle directly to
the credential profile's `mcp-oauth-vault://` KV v2 path with check-and-set.
On a data 404, iCheck reads only that key's metadata: soft deletion preserves
the latest version, so reconnect must use that version for CAS. Only metadata
404 permits create-only CAS=0. Denied or malformed metadata and a competing
write fail closed; there is no blind retry or unconditional overwrite. The
control-plane Vault identity needs `read` on the exact
`<mount>/metadata/<configured-bundle-path>` in addition to its existing data
permissions. No metadata listing, destroy permission or extra Worker grant is
required by this repair. These semantics follow [Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2).
Database rows retain the issuer, resource, scopes, expiry, token hash, refresh
presence, actor, and lifecycle timestamps. A confidential client secret remains
an ordinary control-plane secret reference; if used, its value is copied only
inside the Vault token bundle so a Worker can refresh without a database call.

Before each execution, the leased Agent Worker resolves the same Vault
reference locally. If the access token is near expiry, the
`mcp_oauth_vault` provider sends a refresh request with the bound resource,
supports refresh-token rotation, and CAS-writes the new bundle. A concurrent
winner is reread instead of overwritten. That describes the historical r48
implementation; its redemption-before-CAS race is repaired in source below.
Revocation blocks new grants first,
uses RFC 7009 for refresh/access tokens when the authorization server advertises
a revocation endpoint, then deletes the Vault bundle. If upstream revocation or
Vault cleanup fails, status remains
`revocation_pending`, execution stays blocked, and an administrator can retry.

The r48 OAuth GUI record (private development evidence; not distributed) verifies
consent, upstream revocation, provider denial without a token and reconnect at
the retained version through the packaged API and private PostgreSQL. Its
default-off `--oauth-fixture` requires only the separate authoring/execution
fixtures and rejects fault/rich/collector/condition mixtures before provisioning.
The loopback issuer verifies [PKCE S256](https://www.rfc-editor.org/rfc/rfc7636),
resource/client/callback binding and one-use consent/codes. A bounded Vault
fixture accepts only the exact token path and CAS; request budgets are checked
before mutation and public ledgers contain only event/status pairs. Focused
helper HTTPS cases include authenticated MCP reads and revoked-token rejection.
That initial GUI run dispatches no Worker or Agent and creates no activation. Packaged
OAuth handoff, refresh/rotation, scope-step-up, in-flight/recovery and live
issuer/Vault compatibility remain separate gates. Browser self-signed trust is
relaxed only in the disposable fixture; production TLS/mTLS/custody is not
accepted. All private secrets, processes and generated database/roles are removed.

The subsequent r48 OAuth Worker record (private development evidence; not distributed)
qualifies actual packaged Attestor/Agent Vault handoff on the unchanged candidate.
Normal GUI publication creates no authority; separate fresh Worker attestation
is consumed by reasoned activation. An exact-tool/local-only bounded Agent makes
one authenticated synthetic MCP call and retains a version/activation-pinned
result with one evidence/binding. GUI OAuth revocation returns HTTP 200, revokes
both upstream tokens and deletes the bundle. It does not erase the activation
or disable the registry: a fresh executor instead checks current OAuth state
before Vault/MCP I/O. Its failed attempt produces no evidence and the fixture's
next reason request fails; this is a denied execution, not a successful diagnosis
or catalog-removal acceptance. Separate reasoned deactivation removes authority.

Three one-shots exit zero; the terminal ledgers contain two accepted MCP methods,
19 of 48 issuer/Vault events and no active token/bundle. Private runtime/key/
database cleanup passes. No full suite, build or extra hash verification is
repeated. Completed/denied contrast incompletes remain, as do packaged refresh/
rotation, scope-step-up, in-flight/failure recovery, live issuer/Vault, broader
execution/GUI/accessibility and production/native/lab gates. The
handoff addendum (private development evidence; not distributed)
keeps full-product readiness false.

Latest refresh record (private development evidence; not distributed) and
readiness addendum (private development evidence; not distributed)
use a separate default-off `--oauth-refresh-fixture`: 30-second real-clock tokens,
strict selected bindings, pre-mutation budgets and rotating-token replay family
invalidation. Normal fixture lifetime remains 3,600 seconds. Twenty-five new and
three affected cases pass. Packaged Attestor and Agent independently rotate
expired bundles to Vault versions 2 and 3 before authenticated tools/list and
tools/call; latest normal upstream revoke/delete and separate deactivation pass.

One additional concurrent regression fails: both provider instances read the
same old refresh token and redeem it before Vault CAS. The second redemption
invalidates the active issuer family; neither subsequent resolution is usable.
The synthetic KV additionally validates issued tokens, so its retained version 1
is not a claim about real Vault write behavior. Real Vault may store an already
invalidated token. The underlying issuer replay failure follows
[RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2).
The product repair must coordinate across processes before redemption, bound
contender wait, fence generation/reconnect/revocation and fail closed on lost
responses or crashed ownership without blind refresh replay. Worker-local
expiry also needs non-secret, authenticated assignment-bound reporting: the
fresh GUI/database retain the consent-time expiry after both rotations. Neither
repair exists in r48. Shared refresh, step-up/in-flight/recovery/live issuer/
Vault, full GUI/accessibility and production/native/lab gates remain open.

The current source repair (private development evidence; not distributed)
reserves the exact bundle key by CAS **before** token redemption. Strict
generation/owner/base-version/deadline metadata distinguishes refreshing,
ready and revoking states. Contenders wait within elapsed/request limits and
reuse only the same generation/identity/scope and exact committed refresh.
Expired or lost/crashed ownership never allows automatic takeover or replay.
Fresh consent cannot replace an active or expired refresh reservation, or any
revoking state. Expired uncertainty needs verified recovery before consent can
replace the old bundle. A legacy bundle acquires its generation under the reservation;
legacy executors that ignore the metadata must be drained before rollout.

One exact readback can confirm a lost commit response. An unknown commit cannot
blindly revoke a published or newer token family. Compensation first uses CAS
to fence the exact still-pending owner and retain known tokens under revoking
state; cleanup failure needs an explicit retry. Ordinary revoke also advances
the version fence, uses upstream revocation and deletes only its reserved KV
version, then verifies data absence and the exact head. This follows the
[Vault version-delete API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#delete-secret-versions)
and [RFC 7009 response semantics](https://www.rfc-editor.org/rfc/rfc7009#section-2.2).
The control-plane needs reviewed update permission on only
`<mount>/delete/<configured-bundle-path>`; no listing/destroy/wildcard grant or
remote refresh-only Worker version-delete grant is required. No policy is applied.

Eighty distinct source cases pass: 57 new and 23 affected existing cases, with
eight changed guards verified again rather than counted twice. Real TLS cases
include two separate processes sharing one rotation, actual post-response
process death without grant replay and a delayed old-version delete preserving
new consent. An unknown issuer token after the crash remains live and fenced,
not proved revoked. Memory guards are not real Vault/provider-policy acceptance.
R48/installed r30 are unchanged. The source observation record (private development evidence; not distributed)
now qualifies strict non-secret generation/version/expiry/state receipts and
generation-aware grants for Attestor, HTTP-only and direct Agent paths. Current
namespace/assignment/profile/consent and monotonic freshness/lifetime fences
reject stale metadata. Locked callbacks compare transaction generation before
token exchange; revoke finalizes only its expected pending generation. Receipts
never alter consent expiry/scopes/activation or an already-issued unknown-write
result. The GUI labels control-plane expiry separately from timed, sourced
observations. Eighty-five distinct focused checks pass, including an authenticated
API/lease/checkpoint handoff and selected real TLS/process guards. Source migration
`i6l8n0q2s4u7` leaves legacy consent unbound until explicit reconnect.

The PostgreSQL custody record (private development evidence; not distributed)
qualifies 58 distinct checks: 40 actual migrated non-owner database cases, 12 new
guards and six affected contracts. OAuth begin/callback/receipt/revoke reject
autocommit and isolation modes other than READ COMMITTED before external I/O.
Callbacks hold refreshed shared profile custody before token exchange. Actual
server/profile lock waits recheck current generation/status, profile enabled/
revision and the actual worker ONLINE/namespace/selector row, not a cached identity.

Revoke commits a strict internal cleanup intent with pending status before I/O.
It pins original reference, generation, server/namespace, profile identity/revision
and Vault address/namespace. Retry never retargets a repointed or disabled profile,
including after actual process exit at the pending commit. This is cleanup-only
custody, not disabled-profile execution. Finalization matches the exact pending
intent and generation. Missing/corrupt/mismatched intents or changed Vault identity
require administrative recovery before cleanup; the new nullable migration head
`j7m9p1r3t5v8` invents no legacy intent. Populated migration/RLS and retained/hidden-
history downgrade guards pass. OAuth without a configured token profile cannot
take anonymous early-return credential paths.

At that source-only boundary r48/r30 and native policies were unchanged.
The r50 packaged GUI (private development evidence; not distributed)
now verifies naturally expired-token rotations to versions 3 and 5, sourced
Attestor/Agent receipts separate from consent version 1, receipt aging without
reload, one separately authorized pinned read and exact-version revoke.
Two upstream tokens are revoked and the bundle is absent at head 6. Public
metadata clears, but SQL stores JSON literal `null` for both nullable fields;
the actual cleanup downgrade guard rejects the cleared intent. R50 is blocked.
Repair ORM null semantics plus a new guarded all-namespace migration that
normalizes only JSON-null rows, then qualify actual populated PostgreSQL and a
new backend candidate. No real history is removed or legacy custody invented.
The active-only summary needs a clearer label; retained call history is intact.
Private operational fixtures are stopped and removed. Installed r30 and native
policies remain unchanged. Synthetic adapters do not prove unknown issuer-family cleanup,
cross-store atomicity, a legacy-intent administrative recovery workflow or live
Vault policy. Those gates, exact policy denial/legacy drain, scope-step-up/in-flight,
live compatibility and all broader production/native/accessibility/load/lab gates
remain. The earlier post-issuer crash token remains fenced, not proved revoked.

The subsequent source repair (private development evidence; not distributed)
at head `k8n0q2s4u6w9` uses `JSON(none_as_null=True)` for both fields. A new
visibility-guarded migration normalizes only JSON literal null; it preserves
real/invalid non-null custody, scalars, nested nulls and unrelated server history.
Seventeen distinct focused checks pass, including actual mixed-field PostgreSQL
and cleared-versus-retained downgrade guards. Normalization downgrade has no
inverse and cannot recreate false custody. The active-only label is clarified.
R50/installed r30 remain unchanged, so new packaging and selected normal GUI
clearance still precede the remaining lifecycle/production/native/lab gates.

The r51 packaged clearance (private development evidence; not distributed)
now freezes that k8 repair and explicit active-call UI label. Normal GUI consent
creates version 1; reasoned revoke reserves/deletes version 2; separately approved
reconnect creates a fresh generation at retained CAS version 3; final revoke
clears version 4. Both nullable fields are actual SQL NULL after registration,
callbacks and revoke. The packaged direct j7 guard permits cleared intent inside
an unconditional rollback, leaving head/generation history intact. No Worker or
Tool/Agent admission occurs in this selected replay; source populated receipt
cases and the earlier complete Worker journey remain evidence at their own scope.
All private operational fixtures and synthetic tokens/bundle are removed.
Installed r30 is unchanged. Unknown-family/legacy-intent recovery, quarantined/
mixed-version Worker reconnect, step-up/in-flight, exact policy/legacy drain and
all original production/native/accessibility/load/physical-lab gates remain.

A runtime HTTP 403 is a separate, governed step-up path. It is recognized only
when a Bearer challenge contains `error="insufficient_scope"` plus 1–100 valid,
bounded scope tokens. Ordinary 403 responses remain execution failures. iCheck
persists one namespace-isolated pending challenge per server/Tool, removes that
Tool from the model-visible and executable catalog, and does not retry, refresh,
or alter the circuit-failure budget. The Worker returns only the normalized
scope list and optional protected-resource metadata URL; raw headers, tokens,
and provider text do not cross the Worker boundary.

An administrator must first approve the exact challenge with an optimistic
revision and reason. Any scope outside the server's configured allowlist needs
a second explicit `allow_scope_expansion` decision, which durably expands that
policy. Authorization is then a new one-time PKCE browser transaction requesting
the union of the current grant and challenged scopes. A challenge-supplied
metadata URL must pass the same HTTPS/host allowlist and exact-resource binding
checks as ordinary discovery. Provider denial or callback failure returns the
ledger entry to `pending`; only a newly Vault-stored token containing every
challenged scope marks it `resolved`. No token or raw challenge is persisted.

## API and UI

Global `tools.admin` authorization protects the administrative routes below.
The callback is instead bound to a one-time browser transaction, and the CIMD
metadata document is intentionally public so an authorization server can fetch
it.

```text
POST /api/v1/mcp/servers
GET  /api/v1/mcp/servers
GET  /api/v1/mcp/fleet/telemetry
GET  /api/v1/mcp/servers/{server_id}
POST /api/v1/mcp/servers/{server_id}/check
POST /api/v1/mcp/servers/{server_id}/attestations
GET  /api/v1/mcp/attestations
POST /api/v1/mcp/attestors/register
POST /api/v1/mcp/attestors/{worker_id}/attestations/claim
POST /api/v1/mcp/attestors/{worker_id}/attestations/{attestation_id}/complete
GET  /api/v1/mcp/servers/{server_id}/oauth/start
GET  /api/v1/mcp/oauth/scope-challenges
POST /api/v1/mcp/oauth/scope-challenges/{challenge_id}/approve
GET  /api/v1/mcp/oauth/callback
GET  /api/v1/mcp/oauth/client-metadata
POST /api/v1/mcp/servers/{server_id}/oauth/revoke
GET  /api/v1/mcp/servers/{server_id}/oauth/recovery
POST /api/v1/mcp/servers/{server_id}/oauth/recovery
POST /api/v1/mcp/servers/{server_id}/oauth/recovery/confirm
POST /api/v1/mcp/servers/{server_id}/activations
GET  /api/v1/mcp/activations
POST /api/v1/mcp/activations/{activation_id}/promote
POST /api/v1/mcp/activations/{activation_id}/recover
POST /api/v1/mcp/activations/{activation_id}/deactivate
```

`/settings/mcp` provides the separate administration surface for secret/Vault
references, authentication mode, client ID/CIMD URL, issuer selection, scope
allowlist, OAuth connect/reauthorize/revoke, health, published-contract
selection, asynchronous attestation queue/ledger, selection of a fresh passed
result, canary policy, runtime health/circuit state, reasoned promotion,
re-attested recovery, deactivation, and a separate runtime scope-step-up queue
with explicit allowlist expansion followed by fresh consent. Its operations
column starts with namespace-scoped fleet posture and exception-only detail;
configuration and authoring controls remain in the separate left column.
It is linked from Capability Studio and AI settings rather than added to the L1
operator home.

`GET /api/v1/mcp/fleet/telemetry` requires global `tools.admin`. Complete
server, health/freshness, OAuth-attention, activation, circuit, call-result,
scope-review, and attestation counts are computed in the database for the
active tenant/region. `server_limit` bounds only the per-server detail list, not
the totals. The response carries no raw MCP error, provider response, header,
token, or credential value.

MCP guardrails also enter the normal Alert/Situation path. Opening a Tool
circuit upserts one deduplicated critical Alert per activation and recovery or
deactivation resolves it. A typed OAuth scope challenge upserts one
deduplicated warning Alert per server/tool and successful token-scope
verification resolves it. Alert evidence contains IDs, hashes, scopes, and
bounded counters rather than provider text or secrets.

## Verified behavior and remaining work

### Durable local family cleanup

The durable local qualification (private development evidence; not distributed)
adds source head `o2s4u6w8y0b3`. Beneath the exact attempt's family-recovery URL,
`GET /local` reads retained local history, `POST /local` admits a private original
plan and `POST /local/execute` resumes that plan. Mutation endpoints require a
current authenticated global human with `tools.admin` and `changes.approve`,
different from the recovery initiator. Payloads contain expected recovery/plan
IDs and a reason, never actor IDs, Vault paths or pasted operation receipts.

Admission retains the independently reviewed issuer proof and exact private plan.
Each new provider mutation requalifies original provenance and current human
authority, commits a phase/version admission and releases all locks before I/O.
Owned fence, deletion and completion receipts commit independently. Withdrawal
after admitted I/O cannot erase its receipt or authorize the next mutation.
Failed fence retention can resume its exact owned marker without another CAS.

Native guards enforce namespace isolation, original custody, append-only mutation
decisions, strict owned receipts, monotonic progress and exact completion.
Completion marks `family_contained_at` without changing the original consent
outcome. That exact family no longer blocks older-family recovery; existing
server uncertainty and revocation state remain. Public history may report local
cleanup verified while reconnect remains false. Historical cleanup never changes
another live generation. Conditional server adoption and plan replacement remain.

Fifteen new source/schema checks, 81 affected regressions and 13 actual non-owner
PostgreSQL cases pass. All four provider modes, withdrawal during I/O, a rolled-back
fence commit, typed receipt rejection, native custody/downgrade guards, RLS and
required-auth API are covered. All three private clusters are stopped. Upstreams
and retained Tool proof remain synthetic; actual governed execution, owned-process
loss, live cross-store truth, recovery UI and full-product gates remain open.

### Exact version local Vault recovery

The local provider qualification (private development evidence; not distributed)
adds bounded private plans for the original Vault address, namespace, key,
generation and authorization locator. Pending consent with an original bundle
reserves the exact head, deletes verified affected archives and restores only
that original family. An originally absent key receives a tokenless reservation.
Historical recovery retires affected archives without restoring an older family;
a different live head is neither replaced nor deleted.

Vault's [KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
supports explicit archived-version reads and version-specific deletion. Soft
deletion retains the current version, so it cannot justify CAS zero or deletion
of all metadata. Preconfigured metadata can legitimately precede version one,
as shown by the [Vault metadata implementation](https://github.com/hashicorp/vault-plugin-secrets-kv/blob/main/path_metadata.go).
That case requires exact integer zero current/oldest versions and empty history.
Scheduled future deletion is not treated as already inactive.

Plans contain at most 256 affected versions and inspect at most 512 retained
metadata entries. The only permitted publication race is the already-admitted
exact original nonce winning its original-head CAS. Arbitrary head changes
require a new governed plan decision, not a silent rebase. Ordinary bundle
validation rejects the local reservation marker.

Every execution requires authority, fence-receipt, deletion-receipt and
completion-receipt callbacks. A fence receipt must be retained before deletion
or restoration. Lost mutation responses permit one exact owned readback, not
issuer replay or blind mutation retry. Failed receipt retention stops before
the next mutation; owned restoration can resume without another CAS.

That provider phase qualified hooks with synthetic memory adapters, not durable database
authority. The module performs no issuer RPC and does not itself qualify issuer
proof, clear a consent claim, change server status or authorize reconnect.
Native persistence/guards, current-human decisions, API adoption and actual
cross-store process-loss acceptance remained next. The durable integration above
now exposes verified local cleanup; reconnect still requires a separate decision.

### Exact authorization transaction family recovery

The current source qualification (private development evidence; not distributed)
adds per-attempt recovery at `n1r3u5w7y9a2`. Authorization retains the original
transaction ID, existing state digest and public PKCE S256 challenge, never the
code, raw state or verifier. Callback checks the locator before redemption and
preserves it as validated Vault metadata. Pre-locator history requires its actual
matching transaction and authenticated ciphertext; missing evidence stays fenced.

Under `/api/v1/mcp/servers/{server_id}/oauth/consents/{attempt_id}/family-recovery`,
`POST` claims an unresolved or historical attempt, `GET` reads its public custody,
and `POST /confirm` retains independently qualified issuer evidence. Start needs
current global human `tools.admin`; confirm also needs `changes.approve` and a
different human from the initiator. The API accepts selected existing activation
IDs and retained proposal/verifier IDs, not credentials or pasted provider claims.
Neither admission nor confirmation activates or executes a Tool.

Start pins a published available approval-required write and its designated
read-only verifier on a separate MCP server. Its frozen contract must bind
`recovery_id`, `server_id`, `consent_attempt_id`, `consent_generation`, `issuer`,
`client_id`, `resource`, `vault_version`, `transaction_id`, `state_sha256` and
`pkce_s256`. The standard bounded contract now permits at most 16 bindings and
24 scalar result values. Other existing provenance, causal freshness, schema,
approval and namespace guards remain in force.

Qualified evidence comes from a separate successful verifier Investigation after
an approved completed or still-unknown containment write. It must bind all eleven
values and prove `family_revoked`, `issuance_blocked` and
`exclusive_transaction_family` are true, with `containment_scope` equal to
`authorization_transaction` and opaque family/containment/evidence references.
Shared-family or client-wide containment cannot be substituted for this scope.
The write's unknown outcome is not resolved or authorized for automatic replay.

A durable `issuer_verified` receipt does not verify local Vault cleanup or permit
reconnect. Open new-consent attempts stay fenced. A recovery claim prevents late
callback publication while retaining known-unstored compensation or an owned
`stored_unpublished` version. Historical proof leaves another current generation
and its Vault slot untouched. Native guards preserve exact original custody,
one-way claims and immutable proof; RLS and retained-data/visibility downgrade
guards prevent bypass through another namespace or schema rollback.

Twenty-five new source/schema checks, 57 existing regressions and ten actual
PostgreSQL cases pass. All seven disposable clusters stop without generated
database/role/session residue. Issuer/Vault data and retained Tool calls are
synthetic. Exact local finalization, operational workflow launch/pin replacement,
actual governed Tool execution, recovery UI, corrupt/shared-family review, live
provider/cross-store truth and a coherent package remain before all full-product
gates. Frozen r51 and installed r30 are unchanged; no integrated demo runs.

### Consent admission and generation history

The preceding consent custody contract (private development evidence; not distributed)
pins the original server/client/namespace, profile identities/revisions/references,
Vault identity, callback and authenticated human credential provenance when
authorization starts. Callback verifies that snapshot and current authority
before redemption. Vault preflight validates the exact generation/identity/version;
an uncertain refresh/revocation reservation, even expired, cannot admit a code.

Before token RPC, a durable generation attempt fences the server. Admission
commits and releases database locks before mutation I/O. A separate current
storage admission follows a valid response. Publication uses the original
pre-redemption version, not a reread/rebase. Only exact owned readback establishes
an ambiguous commit. Token lifetime starts before redemption, not response
receipt. A known stored version survives later containment as retained history;
configuration drift cannot silently publish it to a changed server.

Only newly received, provably unstored tokens receive compensation requests.
Those requests never delete the active Vault key, and acknowledgement is not
family-containment proof. Unknown, compensated and stored-but-unpublished
attempts stay fenced. Fresh consent, normal revoke and the older single-generation
recovery cannot clear them. Independent recovery for these new and historical
families, including issuer/collateral scope and actual Tool truth, remains open.

`GET /api/v1/mcp/servers/{server_id}/oauth/consents` returns bounded history
using `limit` (1–100) and `offset` (0–100000). Public records omit credentials,
Vault paths and private snapshots. Original custody/owned versions survive
transaction expiry. Superseded/local-revoked phases are not independent proof
that every remote family is contained. PostgreSQL RLS, immutable original
custody, version/transition guards and populated downgrade refusal preserve
that distinction. Legacy transactions receive no invented snapshot or history.

Selected source/API/RLS/concurrency/actual-child-loss checks pass with synthetic
upstreams. Normal administration UI/proof/history, real governed Tools and live
issuer/Vault loss/recovery precede coherent packaging and all broader release
gates. No installed pointer, policy, grant, service or migration is changed.

### OAuth administrative recovery source

The current authority contract (private development evidence; not distributed)
reloads the authenticated human's credential, enabled principal/namespace and
selected-region role grants after lock waits. It checks expiry after later
target/evidence waits and before admission commit. Initiation, review, fencing
and deletion require current global authority; a retained fence does not skip
the next delete check. Real browser sessions also recheck their enabled
federated identity where applicable. Credential provenance is internal, not
a recovery form input or public account field.

Each Vault mutation gets a durable admission and releases authorization locks
before I/O. If permissions are withdrawn during an admitted operation, retain
its verified fence/deletion receipt but refuse the next admission. This avoids
both stale authority and loss of known owned results. Sixty-five focused source
checks and 12 distinct actual PostgreSQL cases pass; upstream evidence remains
synthetic and the full GUI/provider/release gates below remain open.

The source qualification (private development evidence; not distributed)
adds explicit uncertain-family recovery. Start requires a real, globally scoped
human with `tools.admin` in the active namespace. It pins the original cleanup
intent and observed Vault version, sets `revocation_pending`, and returns
non-secret `required_containment_arguments`. Replacing an unreviewed observation
requires its exact recovery ID; reviewed cleanup cannot be replaced.

Use an ordinary governed containment MCP Tool with a frozen independent
verification contract. Its designated read-only verifier must run in a separate
Investigation on a separately pinned server. Bind these exact argument/value
pairs: `recovery_id`, `server_id`, `consent_generation`, `issuer`, `client_id`,
`resource`, and integer `vault_version`. The result uses `target_state`/`absent`
and must retain `family_revoked: true`, `issuance_blocked: true`, and opaque
`family_reference` and `containment_reference`. A successful write response,
ordinary token revocation acknowledgement, expiry or pasted claim is not proof.

Confirm requires a different real human with global `tools.admin` and
`changes.approve`, the recovery ID, approved proposal ID, verifier call ID and
reason. It durably retains qualified evidence before I/O, verifies deterministic
recovery ownership at the exact CAS version, commits that receipt, then deletes
only that version. A lost response is accepted only from exact owned readback.
Unproven absence or a newer Vault head remains fenced. Retained cleanup can be
retried without re-running containment, redeeming a grant or changing the
original Tool outcome. Recovery never activates a Tool or grants execution;
reconnection still requires separate fresh consent.

Fresh consent cannot overwrite a refresh reservation even after its deadline.
This preserves the original uncertain family and cleanup target. Pre-redemption
consent eligibility, claim-race compensation, generation history and the
operational exact-target bridge to containment/verifier Tools remain open.

For a missing legacy intent, start may accept `connected_audit_id` and
`original_secret_ref` together. They must match the latest successful consent's
original reference fingerprint, profile revision, Vault identity and exact
generation. Later profile edits/disablement cannot redirect cleanup. Older
consent history lacking that snapshot and corrupt nonempty intent remain
pending; no target is inferred and corrupt custody is preserved for review.
The public recovery response omits original Vault references and credentials.

Seventy-five distinct source checks and seven real PostgreSQL cases pass,
including actual two-user required-auth API requests under non-owner RLS.
The containment evidence and Vault are synthetic. Normal recovery GUI,
preserved corrupt/legacy target review, real governed Tool/provider truth,
cross-store process loss and new packaged acceptance remain open. Frozen r51,
installed r30 and the original full release/demo gates are unchanged.

Automated acceptance covers OAuth discovery order and binding, PKCE and
resource parameters, response-issuer rejection before code redemption,
one-time transaction replay rejection, Vault-only token handoff, Worker refresh
and rotation with CAS, revocation, protocol headers, authenticated database-free
attestor registration/claim/completion, reserved-capability denial, Worker-bound
lease replay rejection, exact schema attestation, configuration-drift rejection,
one-time activation consumption, raw Registry bypass rejection, authenticated
lease-bound execution, output validation, secret redaction, evidence persistence,
deterministic cohort stability, model/executor cohort enforcement, local and
delegated runtime accounting, revision-safe health-gated promotion, automatic
circuit opening and Registry disablement, fresh-attestation canary recovery,
immediate deactivation, typed runtime 403 parsing, bounded Worker propagation,
local and delegated challenge persistence without circuit penalties, explicit
allowlist expansion, failed-consent reset, fresh PKCE consent, token-scope
resolution, database-side bounded fleet aggregation, namespace and RBAC
isolation, exception-first UI rendering, guardrail Alert creation/resolution,
and a state-changing call interrupting before remote execution.

Remaining work includes live external signed-pack publisher compatibility,
live external OAuth/server compatibility, live Ansible/device acceptance, and
live PostgreSQL crash/resume acceptance.

Control-plane configuration requires the MCP/resource and authorization-server
host allowlists, callback/success URLs, a mode-0600 Fernet transaction key, and
the dedicated attestor bootstrap token. The diagnostic `/check` route may also
use a server-side Vault identity. Attestor and Agent Workers require their own
mTLS identity plus a Worker-local Vault token whose policy is restricted to
assigned credential/OAuth bundle paths. Use
`deploy/systemd/icheck-mcp-attestor.service` with
`deploy/systemd/mcp-attestor.env.example`; it intentionally has no database URL.
Generate the transaction key once, distribute it only to control-plane
instances, and rotate it only after pending transactions expire:

```bash
.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```
