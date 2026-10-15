# AI provider and model configuration

## Multi-provider guided setup — deployed r19.26, 15 October 2026

**Deployed with database/configuration backups and migration.** The primary card at
`/settings/ai` is now **Guided AI provider setup**, supporting OpenAI, Anthropic
Claude, Google Gemini, DeepSeek, Qwen (Beijing/Singapore) and OpenRouter.
See the [multi-provider guide](ai-multi-provider-setup.md) for exact endpoints,
the four Advanced sections, protocol differences and deployment requirements.
Earlier references to Guided OpenRouter setup below describe the previous UI.
Existing OpenRouter keys, models and routes were preserved; Agent Worker now
includes native Anthropic capability. No paid provider calls were made.

## Internet research: configuration GUI deployed in r19.24

Open **AI Settings → Internet search** (`/settings/ai/research`). This is a
separate configuration page, linked prominently from the AI settings workspace.
It is available on the running server at
`https://YOUR_SERVER:8443/settings/ai/research`. The paired r19.24 update and
additive migration were deployed on 14 October 2026 after database/configuration
backup. Authenticated GUI/API checks passed. No provider was configured or
activated, and no paid search or model call was made during deployment.

1. Select **Brave Search** or **SearXNG**. For Brave, enter a separate search API
   key in the password field. For SearXNG, enter an existing public HTTPS search
   endpoint with JSON output enabled.
2. Choose whether AI may search and set the daily request limit (default 100).
   Select **Save settings**. Saving does not make a provider, model or device call.
3. Optionally select **Test search · 1 request**. The button explicitly authorizes
   one fixed public-documentation search, which may consume provider credit.
   It does not contact a model or lab device. Save edits before testing them.

Keys are encrypted with AES-256-GCM using the existing managed-AI encryption
key. Ciphertext is bound to the workspace, connection and provider. APIs never
return the key, and the browser clears the input after a save attempt. Leave it
blank to retain a saved Brave key; changing to SearXNG removes that key from the
connection. Disabling searches retains it for later use. Direct public-document
reads are separate and remain permitted by the server's research switch.

Settings require a human with globally scoped `ai.manage` and
`credentials.manage` within the selected workspace. Browser writes use CSRF;
stale revisions are rejected. Tests of an old revision cannot mark a newer
configuration healthy. Managed settings override environment search configuration
for that workspace, including an explicit disabled setting. The server-wide
`ICHECK_RESEARCH_ENABLED=false` switch still blocks all research.

The daily limit is shared by AI Operator, Studio and connection tests. Admission
is committed atomically before a provider call; failed/admitted attempts count,
and settings edits do not reset usage. It resets at midnight UTC. This is a
request limit, not exact monetary billing or model-token accounting. Changing a
key, provider or setting clears the previous connection-test status.

Internet search is a separate platform capability, not an assumption that the
configured language model can browse. AI Operator has `research.search` and
`research.read` tools in the existing bounded tool loop. Studio can obtain public
references before authoring when no source document was supplied. The source
implementation retains source URLs, retrieval times and fetched-document hashes;
these are evidence of a read, not proof that a device supports the feature.

**Recommended provider: Brave Search API.** It is a managed HTTP search service,
so iCheck does not need to host another search engine. The provider remains
replaceable behind the same internal tool contract. SearXNG is an alternative
for an operator-managed search endpoint with JSON responses enabled. Tavily is
a reasonable managed alternative, but no Tavily adapter is implemented yet.
Provider accounts and billing must be established by the operator; a model
provider's token is not a search-provider key. Do not put either in chat.

Administrator provisioning and legacy fallback use these environment settings:

- `ICHECK_RESEARCH_ENABLED=true` permits public reference reads.
- `ICHECK_RESEARCH_PROVIDER=unconfigured` is the default: direct public
  documentation/MIB reads work, but general search explicitly reports missing
  setup until a connection is saved through the GUI. Existing deployments can
  still select `brave` with a protected key file or `searxng` with an endpoint.
- `ICHECK_RESEARCH_API_KEY_FILE` is an absolute protected file path for Brave.
  The file must be service-owned or root-owned, readable by the service, with no
  group/other permissions. It must contain only the key. Do not place the key in
  a URL or the environment example.
- `ICHECK_RESEARCH_SEARXNG_URL` is a public HTTPS search endpoint, without a
  query string, that allows `format=json`. Private/self-hosted network addresses
  are not accepted by the current public-only transport; do not disable its
  network checks to reach a private instance.
- `ICHECK_RESEARCH_TIMEOUT_SECONDS=12` bounds each transport request.

The experimental `bing_rss` adapter is not recommended or enabled by default:
live checks returned unrelated results. It is not a GUI provider choice. General
search has not been qualified against a configured paid provider. Exact monetary
spend accounting and the complete combined monitoring-extension approval flow
remain separate work. Migration `y2e4g6i8k0m3` adds the namespace-local encrypted
settings table without modifying existing devices, credentials or monitoring.

Research uses public HTTPS, validates every redirect/DNS result and connects to
the validated address with TLS verification. It carries no device credentials
or ambient cookies. Studio builds queries from public technical vocabulary, not
the full private prompt. Agent search rejects recognizable IP/MAC addresses,
email addresses, private URLs and secret assignments; this is not a guarantee
that arbitrary sensitive prose can be identified. Pages are untrusted reference
data, never execution instructions. Failed research must not become invented
OIDs, fabricated citations or automatic permission to contact a device.

Official setup documentation: [Brave API quickstart](https://api-dashboard.search.brave.com/documentation/quickstart)
and [SearXNG Search API](https://docs.searxng.org/dev/search_api.html).

## v0.1 r14: self-service model-call timeout

In **Guided OpenRouter setup**, edit **Model-call timeout (seconds)** and select
**Save model-call timeout**. This is a timeout-only operation: it neither asks for
the key nor rotates it, changes the approved endpoint, selects a model/route, or
calls OpenRouter. Changes require a human with `ai.manage`, browser CSRF, the
currently displayed timeout and, for managed connections, the current revision.
Stale edits fail with a refresh instruction. The connection revision advances
only on an actual change; previous probe/configuration approvals become stale.
Retired providers must be restored first. The provider catalog links managed
connections to this control; external providers have their own timeout control.
Advanced provider creation also exposes the timeout rather than hard-coding 20s.

The supported range is **1–120 seconds per model attempt**. New guided OpenRouter
connections default to **120s** for external reasoning; existing settings are not
silently migrated. For this requested server repair, the existing OpenRouter
provider is changed from 20s to 120s after deployment, preserving the user's 800s
task budgets, model profiles, key and outbound approval. Each actual call remains
bounded by the smaller task/lease remainder and retains the 4,096-token Qwen cap.
The 512-token readiness probe keeps its independent 30s-or-smaller transport cap.
A longer allowance is not a promise of model/provider availability or quality.
Previously failed runs remain sealed; only an explicit new-task retry uses new
settings. No paid call is needed merely to save a timeout.

Endpoint: `PUT /api/v1/ai/providers/{provider_id}/runtime-settings`, with
`expected_request_timeout_seconds`, `request_timeout_seconds`, and, for a managed
connection, `expected_connection_revision`. An audit retains the old/new limit,
revision and `inference_performed=false`, never secret values.

## v0.1 r13: bounded runtime and exact safe local validation

Investigation budgets and HTTP waits are separate. The control plane now supplies
the investigation's absolute deadline at Worker bootstrap. Before reasoning the
Worker renews its lease and checks cancellation; only the reasoning RPC may
extend its ordinary 30-second wait to the remaining investigation budget plus
five seconds for returning the outcome. Other Worker requests retain their limits.
Each model attempt uses the smallest of the provider timeout (20 seconds at r13
deployment), remaining investigation time, and remaining lease time minus a
ten-second finalization margin. Elapsed response-body time is bounded even when
OpenRouter sends periodic keep-alive bytes. No automatic replay follows a lost
reasoning response; unknown provider charges remain unresolved in the quota ledger.

Interactive OpenRouter Qwen requests are capped at 4,096 output tokens per call,
or a smaller configured/remaining limit. `qwen/qwen3.8-max-0902` explicitly keeps
mandatory reasoning enabled at `minimal` effort. Existing profiles receive this
wire policy without altering saved identities, credentials or route budgets;
new guided profiles also persist the bounded defaults. Studio uses the same
policy. Effort support is not guessed for other Qwen models. Provider-advertised
maximum capacity is not the default interactive allocation. The 512-output-token
readiness probe remains separate; it is not full workflow acceptance.
[OpenRouter reasoning documentation](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens)
describes mandatory reasoning, per-model effort discovery and output budgeting.

Local decision rejection retains safe schema paths and rule codes, for example
`tool_requests.0.tool_name: missing`, `$: continue_requires_tools`, or
`confidence: less_than_equal`. Malformed JSON retains line/column; truncation
retains the safe `length` finish reason. Unknown field names are masked, and
Pydantic input values/context, raw messages, prompts and model reasoning are not
stored. Provider timeouts retain a typed cause and elapsed limit. Model failure
audits retain attempt duration and reported tokens before returning escalation.
The root-cause panel also compares quota receipts with investigation progress:
late usage and unresolved charges are visible without rewriting sealed history.

The earlier 2026-10-12 failure retains only the generic invalid-decision message.
It now displays that proven validation failure and its late token receipt, but
cannot recover the discarded field/rule. Nothing in this update retries a paid
call, enrolls a device, changes allowlists or bypasses approval.

## v0.1 r12.1: safe provider validation causes and Qwen readiness

HTTP 400 is request validation, not an instruction to add credits. Guided model
tests and investigation root-cause panels show recognized provider error types,
native error codes, rejected parameter names, and validation constraints. The
server reads bounded top-level and nested OpenRouter provider errors, including
`metadata.raw` JSON, but never returns or audits that raw payload, free-form
messages, prompts, credentials, request IDs or arbitrary field values. Names
and codes are allowlisted; recognized constraints become fixed explanatory text.
If a constraint is absent or unrecognized, the UI explicitly says **Exact
validation constraint unavailable**. It does not invent a specific root cause.
Pre-r12 generic receipts cannot recover discarded details and are not rewritten.

OpenRouter Qwen probes use `response_format.json_schema.strict=true`, the full
GraphDecision schema and the same response format as Qwen Agent investigations.
Other providers retain their existing flexible Agent mode. Local GraphDecision,
selected Tool, authorization and output-contract validation remain enforced.
The probe keeps its 512-output-token cap, fixed no-inventory/no-Tool input,
charge approval, timeout and durable quota accounting. No automatic mode downgrade,
budget increase, provider switch or extra paid retry is introduced. Studio already
uses strict output mode; its HTTP validation failures retain the same safe
diagnostic in failure audits. Probe errors embedded in HTTP 200 responses are
classified as provider failures, not false schema successes.

The Qwen failure was traced to disabling mandatory reasoning: advertising `reasoning`
does not mean a model permits `enabled=false`. Readiness no longer disables
reasoning. If both `reasoning` and `reasoning_effort` are advertised, it chooses
the lowest non-disabled effort explicitly allowed by the model's `reasoning`
metadata (or by an explicit unrestricted effort declaration). Missing effort
metadata leaves settings alone. Qwen's catalog declares `mandatory=true` and
permits `minimal`; its test uses enabled reasoning at minimal effort instead
of its default xhigh effort. No token-cap increase is made.
Mandatory-reasoning HTTP 400 errors identify `reasoning.enabled` and the
`cannot_disable_reasoning` constraint directly. Native, wrapped, plain-text and
gzip validation envelopes are bounded; empty/malformed/oversized responses retain
only safe response-format/size context, not raw text. Gzip inflation is capped.

The deployed correction passed one live fixed-input Qwen call on 2026-10-12:
mandatory reasoning enabled at minimal effort, full Agent decision validation,
139 reported total tokens and known quota settlement. Two preceding agent-run
tests failed; the user approved the additional diagnostic/verification allowance.
All three requests retained the 512-output-token cap. No model or route was saved,
and old generic failure records were not rewritten. Successful test text appears
before the catalog reload finishes; Save becomes enabled after that reload.

See [OpenRouter error types](https://openrouter.ai/docs/api_reference/errors-and-debugging)
and [Alibaba Qwen JSON-schema mode](https://www.alibabacloud.com/help/en/model-studio/qwen-structured-output).

## v0.1 r11: retired-provider recovery in guided setup

Guided OpenRouter setup labels retired providers in its selector and displays
**Provider retired** with a direct **Restore** action. Review the existing
lifecycle preview, provide an approval reason and confirm; provider state reloads
without a page refresh. This preserves the saved key and does not restore models
or routes, approve outbound access, or make an AI request. If outbound access is
disabled, approve the endpoint separately before verifying the key. Discovery,
key replacement, inference tests and route saves remain blocked while retired.
The backend reports retirement explicitly, ahead of outbound/endpoint checks,
and rejects attempts to re-approve outbound access on a retired provider without
changing its key or revision. Actual endpoint-binding drift still fails closed.

## v0.1 r10: self-service configuration and governed repair

Multiple enabled models are available choices, not simultaneous calls. Each
purpose route selects one primary model and optional ordered fallbacks. Studio
and investigations can use different models; retries stay within their budgets.

Guided OpenRouter discovery now excludes `:batch` variants. They use the
asynchronous Batch API, whereas interactive Agents and Studio use synchronous
chat completions. A successful key/catalog check is not a generation test.
After selecting a model, explicitly approve **Test model inference** (may incur
charges). This fixed-input GraphDecision JSON-schema test uses no inventory or
Tools, has a 30-second transport timeout and at most 512 output tokens. A passed
test enables **Save model and routes** in the GUI. Saves bind the receipt to the
actor, model and connection revision, and reject stale configuration hashes.
Legacy API configuration without a test remains supported but is not an
inference-verified claim. Tests use durable quota admission/settlement; an unknown
external outcome conservatively retains admission capacity, which is not a bill.

Approved switching may reuse the current display name: the new model receives
that label; the old model keeps its ID, slug and configuration with a
previous-version label. Only selected routes move. Unselected routes and pinned
historical investigations remain intact. Replacement still clears the selected
routes' fallback lists and requires explicit approval.

Every AI credential reference, provider, model and route has **Remove from active
catalog**. It first previews dependencies; enter a reason and confirm the exact
preview. Enabled primary/fallback routes block model removal, and active
investigations block removal of pinned models/routes. Replace or remove dependent
routes first, then models, providers and finally token references. No cascading
delete occurs. Removing a managed provider revokes its outbound approval.
References shared with non-AI adapters cannot be retired from this AI-only page;
use a separate AI reference so device and Collector consumers remain protected.
**Retired AI configuration** offers Restore after parent checks; it does not
re-approve outbound access. Removal is retirement, not SQL deletion: model IDs,
runs, audit history and encrypted custody are retained. Names stay reserved;
restore existing items instead of creating duplicates. Secret destruction and
backup expiration are separate administrative retention operations.

The optional advanced modules mean **token reference → provider → model →
purpose route**. A token reference points to an administrator-provisioned server
environment variable, Vault KV field or dynamic-lease role; the form does not
configure environment variables or Vault. A provider identifies an approved
OpenAI-compatible URL and authentication. A model supplies its exact model ID
and capabilities, not proof of inference. A route chooses models and budgets for
`investigation`, `capability.authoring` or another purpose. Guided OpenRouter
users do not need to recreate these manually. Other hosts still require the
server administrator's allowlist; this page grants no unrestricted egress.

Failed investigations show **Root cause and proposed repair** directly. Diagnosis
uses retained model-attempt evidence, safe HTTP classifications and known batch
mismatches. Raw upstream bodies, keys and prompts are never exposed. Older
status-only audits can be diagnosed without rewriting history; the exact upstream
cause is not claimed if its response was not retained. **Review proposed
configuration repair** opens the affected provider and proposed synchronous model
where applicable. Choose any eligible model, test, and explicitly approve the
affected routes. **Retry original task after repair** creates a new investigation
with the original objective/scope, current permissions and current route. It may
incur charges. Original failure history remains intact, and enrollment/activation
still requires separate approval. `platform.diagnose_ai_runtime` is the reserved
read-only scoped Agent Tool for the same evidence-backed proposal. Diagnosis
works without another model call. This is configuration self-repair, not
unrestricted autonomous code patching or self-deployment.

Lifecycle actions require human global `ai.manage`; token references also require
`credentials.manage`. Browser mutations require CSRF. PostgreSQL namespace-local
transaction locks serialize catalog mutation and new investigation admission.
Probe/revocation checks do not retract already dispatched external requests.

```text
POST /api/v1/ai/openrouter/{provider_id}/probe
POST /api/v1/ai/catalog/{credentials|providers|models|routes}/{id}/lifecycle/preview
POST /api/v1/ai/catalog/{credentials|providers|models|routes}/{id}/lifecycle
GET  /api/v1/agent/investigations/{id}/diagnosis
POST /api/v1/agent/investigations/{id}/repair-retry
```

See OpenRouter's [Batch API](https://openrouter.ai/docs/batch-quickstart) and
[structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs).

## Milestone boundary

This is the governed configuration boundary for the M2 runtime while production
identity federation and live acceptance gates remain open. It configures provider
endpoints, credential references, model identities, ordered fallback, and
bounded purpose routes consumed by the LangGraph investigation worker and the
Capability Studio structured-authoring gateway. Revisioned AgentProfiles add
the operator role, Tool policy, model-placement policy, and stricter budget
ceiling without putting those controls into a prompt-only convention.

The administration UI is available at `/settings/ai`. The API surface is:

```text
POST /api/v1/credential-profiles
POST /api/v1/ai/providers
GET  /api/v1/ai/providers
PUT  /api/v1/ai/providers/{provider_id}
POST /api/v1/ai/providers/{provider_id}/health
POST /api/v1/ai/models
GET  /api/v1/ai/models
POST /api/v1/ai/routes
GET  /api/v1/ai/routes
POST /api/v1/ai/agent-profiles
GET  /api/v1/ai/agent-profiles
PUT  /api/v1/ai/agent-profiles/{profile_id}
GET  /api/v1/ai/authoring-quota
PUT  /api/v1/ai/authoring-quota
GET  /api/v1/ai/authoring-quota/reservations
GET  /api/v1/ai/authoring-quota/settlement-conflicts
GET  /api/v1/ai/authoring-quota/orphan-candidates
POST /api/v1/ai/authoring-quota/orphan-cases
GET  /api/v1/ai/authoring-quota/orphan-cases
POST /api/v1/ai/authoring-quota/orphan-cases/{case_id}/review
GET  /api/v1/ai/authoring-quota/supplement-candidates
POST /api/v1/ai/authoring-quota/supplements
GET  /api/v1/ai/authoring-quota/supplements
POST /api/v1/ai/authoring-quota/supplements/{case_id}/review
POST /api/v1/ai/authoring-quota/reconciliations
GET  /api/v1/ai/authoring-quota/reconciliations
POST /api/v1/ai/authoring-quota/reconciliations/{case_id}/review
```

## Guided OpenRouter setup

Use **Guided OpenRouter setup** at `/settings/ai` while signed in as a human
administrator with global `ai.manage` and `credentials.manage` in the selected
tenant/region. The other provider forms remain under **Advanced providers and
external secret references**.

1. Enter a connection name and an OpenRouter inference API key over HTTPS.
   Approve the displayed `https://openrouter.ai/api/v1` endpoint and select
   **Save key and approve OpenRouter**. This atomically creates the provider,
   its bound credential metadata and a namespace-local outbound approval.
2. Select **Verify key and discover models**. The server verifies the key using
   authenticated `GET /key`, then fetches `/models`. Only models advertising
   both `response_format` and `structured_outputs` appear in the selector.
3. Select a model, display name, cost class and one or both purpose routes:
   `investigation` and `capability.authoring`. Review execution budgets and
   run the explicitly charge-approved **Test model inference**, then select
   **Save model and routes**. The server rechecks the catalog and saves
   model/routes together. Existing routes remain unchanged unless you explicitly
   approve replacing them; replacement also clears their fallback lists.

No environment edits, token-reference setup, provider URL entry or service
restart is needed for these GUI steps once native encrypted storage is provisioned.
The guided provider is always classified as external. Models use
`provider.require_parameters=true` to request compatible upstream endpoints.
Credential/catalog health is not a billable generation test or proof of model
quality; subsequent investigations and Studio requests may incur provider charges.
See the official [OpenRouter key endpoint](https://openrouter.ai/docs/api/api-reference/api-keys/get-current-key)
and [structured-output contract](https://openrouter.ai/docs/guides/features/structured-outputs).

Managed keys are write-only: the password input clears on submission and workspace
changes; no key is returned by an API, retained in browser storage, or put into
audit/error metadata. `ai_managed_connections` stores AES-256-GCM ciphertext,
a random nonce and binding metadata. Authenticated associated data binds each
secret to its connection, provider, credential profile, tenant and region.
The separate 32-byte server key comes from `ICHECK_AI_MANAGED_SECRET_KEY_FILE`;
root-owned `0440` or API-owned `0400` regular single-link files are accepted.
Missing, unsafe or incorrect key custody fails closed. Master-key rotation and
cross-server recovery are administrative operations, not implicit regeneration.
Back up this encryption key securely and separately from database backups.
A database dump alone cannot decrypt keys. A compromised API process with access
to both database and server key can; encryption at rest is not protection from
server compromise. Browser password managers/extensions remain outside this boundary.

Use **Replace saved key** for write-only API-key rotation. Use **Disable outbound
access** to revoke this provider's approval. Revision checks reject stale updates.
If another administrator changes the connection, reload the browser page and
verify the key/catalog again before retrying a stale operation.
Revocation blocks new runtime admissions, not an already dispatched provider
request. It still takes precedence if the hostname is in the static allowlist.
Approval is exact, provider-bound and namespace-local: it does not add a global
hostname/wildcard, permit alternate paths/ports, or authorize another provider.
Managed profiles cannot be rebound to another provider or resolved by collectors.
Health and model runtimes reject redirects and ignore ambient HTTP proxy variables.
No outbound firewall, SNMP allowlist or EVE-NG connectivity settings are changed.

```text
GET  /api/v1/ai/openrouter/setup
POST /api/v1/ai/openrouter/connections
PUT  /api/v1/ai/openrouter/{provider_id}/connection
POST /api/v1/ai/openrouter/{provider_id}/check
POST /api/v1/ai/openrouter/{provider_id}/configure
```

The input schema uses secret values only on the two write-only managed-key
operations. All read schemas are explicit redacted metadata. Browser writes use
the standard HttpOnly session and CSRF guard. API validation errors omit input
values, including nested or unknown fields.

## Advanced external-reference configuration

1. Add the provider hostname to `ICHECK_AI_ALLOWED_HOSTS`. Exact hostnames and
   `*.example.internal` wildcards are supported.
2. Configure either a process environment token or the control-plane Vault
   client. Vault KV v2 and dynamic secrets both require
   `ICHECK_SERVER_SECRET_VAULT_ADDRESS`, an absolute
   `ICHECK_SERVER_SECRET_VAULT_TOKEN_FILE`, optional namespace, and a 1–30
   second timeout. These advanced reference forms do not accept token values.
3. In `/settings/ai`, create an unscoped `environment` reference such as
   `env://ICHECK_AI_PROVIDER_TOKEN`, a `vault` reference such as
   `vault-kv2://kv/ai/primary#token`, or a `vault_dynamic` reference such as
   `vault-dynamic://ai/creds/runtime`. Its allowed adapter is fixed to
   `ai_provider` by the page. A dynamic endpoint must return exactly one secret
   value in its Vault lease data.
4. Create an OpenAI-compatible provider with that credential profile name or ID.
5. Run the provider health check. It calls the bounded `/models` endpoint and
   persists only status, model count, a redacted error, and audit metadata.
6. Classify the provider as `external`, `private`, or `local`, and declare its
   data-residency label. Register model profiles with `chat` and `json_schema`
   capabilities plus `low`, `standard`, or `premium` cost class.
7. Bind each task purpose to a primary model, zero or more ordered fallback
   models, and iteration, tool-call, timeout, and token budgets. Use
   `investigation` for the agent loop and `capability.authoring` for the
   Collector Designer.
8. At `/settings/agents`, create a versioned AgentProfile that binds a role and
   escalation instructions to one route purpose, permission-scoped Registry or
   exact Tool allowlist, minimum provider privacy, allowed residencies/cost
   classes, and maximum iteration/Tool/time/token budgets.

Supported authentication modes are `none`, `bearer`, and `api_key`. The latter
uses the fixed `X-API-Key` header. Provider requests reject credentials embedded
in URLs, query strings, fragments, redirects, unapproved hosts, oversized
responses, and invalid OpenAI-compatible model-list envelopes.

When an investigation is created, it snapshots the primary and fallback IDs as
well as every execution budget. Runtime fallback therefore cannot be changed by
later route edits. Retryable candidate failures are individually audited and
the successful decision is charged for the cumulative provider-reported tokens
across failed and successful candidates. Request-size and investigation-deadline
failures stop immediately rather than trying another provider.

When a normal `investigation` starts without an explicit selection, it binds
the built-in `l1-operator` profile. An explicit profile may be supplied by name
or ID. Every primary and fallback model must satisfy its provider privacy,
residency, and cost-class policy. The Investigation receives the lower budget
from the route and profile, then freezes the full `icheck.agent-profile/v1`
snapshot. Role and escalation instructions enter a clearly subordinate prompt
section; the product system policy remains authoritative. Permission checks
always run first, and an exact Tool allowlist can only narrow visibility.
Profile revision/disable drift and model-policy drift fail closed before a
model request. Profile creates/updates are audited, optimistic-revisioned, and
the update record contains previous/current policy snapshots.

Capability Studio also requires `chat` and `json_schema`. It sends sanitized
authoring context through the configured `capability.authoring` route, validates
the response against a strict product-owned schema, records only the prompt
hash in audit, and accounts provider-reported tokens on both accepted and
deterministically rejected proposals. See `docs/capability-studio.md`.

The structured gateway now carries valid provider-reported usage through
schema-invalid candidate failures and accumulates it across fallback attempts.
It caps each candidate's output-token parameter to the remaining route budget,
audits any provider-reported overrun, and persists known usage even when the
authoring request fails. A timeout or malformed usage response may still have
incurred an unknown external charge; fallback cannot establish an exact bill.
`capability.model.completed.token_usage` is the cumulative known usage for
the whole structured request; earlier `capability.model.failed.token_usage`
events describe individual candidates and must not be added to it again.
Activation proposal receipts expose that uncertainty, and Studio generation
failure audits retain it. These are accounting safeguards, not an operator- or
tenant-period quota or a guarantee that the provider honored the requested cap.

## AI model-call admission quota

`/settings/ai/authoring-quota` lets a global `ai.manage` administrator set
independent tenant/region and per-actor UTC-day token limits, with an optimistic
policy revision and audited reason. Operators with `assets.activate` or
`investigations.create` and global Studio authors with `capabilities.manage`
can read their own quota headroom;
authenticated requests cannot select another actor through the optional
development-mode actor hint. The quota applies to **every** route invoked via
the structured-authoring gateway, including custom Studio route purposes and
device activation policy proposals. The LangGraph investigation reasoner,
including workflow Agent-loop nodes, uses the same namespace and actor limits.

Admission atomically reserves the route's entire token budget in namespace and
actor buckets before the first provider request. The reservation, quota
counters, and audit commit before network I/O. A known completion settles to
the cumulative provider-reported tokens and releases unused capacity. A
timeout, malformed usage, or other unknown external charge retains at least
the full reservation, even when some tokens are known. Provider-reported
overruns increase the counters beyond the limit and block subsequent calls;
the platform cannot prevent a provider from exceeding the requested cap.
Pending reservations from process loss remain charged for their original UTC
day; the next UTC day has a new bucket, but the unresolved historical receipt
is not silently deleted or forgiven. Policy changes do not rewrite existing
reservations. The database enforces namespace isolation and seals settled
receipts. This is a concurrency-safe **admission** limit, not an exact billing
ledger, provider idempotency guarantee, or monetary spend ceiling. For an
investigation, each model-decision step reserves the remaining investigation
token budget before the first candidate. Candidate fallback usage is added to
the same receipt. A transport failure followed by a successful fallback keeps
the full reservation because the first provider charge is unknown. The
reservation identity is deterministic per investigation and graph iteration:
replaying an already admitted step fails closed without a second provider call.
Manual review is still required after a process-loss replay conflict.

`GET /api/v1/ai/authoring-quota/reservations` keyset-pages read-only receipts
across UTC days. Operators see only their own records; only a global `ai.manage`
administrator can request `scope=namespace`. The default `state=attention`
includes pending and settled-unknown receipts. `state`, `source_entity_id`,
and `older_than_minutes` filters support investigation and stale-hold review.
The quota settings subpage exposes these filters, and an investigation links to
its own receipts. New Agent receipts store the source investigation ID and graph
step separately from the deterministic no-replay key. Old opaque Agent-step
receipts remain explicitly unattributed after migration; they are not guessed
or released. Source attribution is immutable, including during settlement.
The listing is evidence for review, **not** provider billing verification or a
release action. The
populated PostgreSQL source-migration and five-round contention/RLS check (private development evidence; not distributed)
passed on an isolated test cluster. An earlier
five-round private PostgreSQL contention/RLS check (private development evidence; not distributed)
passed for one admitted and one denied concurrent request per round. It does
not establish production throughput. Real-provider charge reconciliation,
historical ledger retention and production Agent concurrency remain acceptance
work. The bounded Studio/Activation Policy proposal/Investigation orphan-closure
path is described below; other source types and live-provider billing
acceptance remain open.

### Governed manual adjustment of uncertain charges

`/settings/ai/quota-reconciliation` is a separate global-AI-admin workflow for
**settled, unknown-charge** receipts only. A signed-in administrator proposes
the provider-confirmed total, an exact evidence SHA-256, an opaque provider
billing reference, and a reason. The evidence itself is not uploaded or
authenticated by iCheck: the digest and reference are human attestations that
a second, distinct administrator must verify out of band. The proposer and
the original model-call actor cannot review the proposal. Rejecting a proposal
changes no quota counters and permits a corrected new proposal.

An approval takes a PostgreSQL receipt lock, rechecks the sealed known/held
usage, and writes one *first* append-only adjustment per original receipt. It applies
the signed difference between the attested total and originally held tokens
to both the namespace and actor bucket for the receipt's original UTC day.
Thus an unexpectedly higher bill adds a debit, while a proven lower bill
releases only the uncertain remainder. The original model-call receipt is never
edited; the read-only receipt view shows both original hold and effective
adjusted amount, and resolved calls leave the unresolved-charge count. Approved
cases and adjustments are sealed, and exact reviewer retries are idempotent.
This is a controlled *manual accounting override*, not
automatic provider-billing reconciliation or proof of evidence authenticity.
Pending receipts cannot use this adjustment path directly; a source-proven hold
may first pass the independent, no-credit recovery path described below. Live
provider evidence adapters and evidence-byte verification remain open.
An isolated PostgreSQL migration, contention and RLS check (private development evidence; not distributed)
passed for the manual ledger; it does not validate the truth of a submitted
billing statement.

When a later model-call settlement disagrees with a sealed receipt, the
service commits a distinct append-only conflict record before reporting the
error to the caller. Repeated identical reports deduplicate under the receipt
lock; neither the sealed receipt nor daily counters change. The global AI
administrator's reconciliation page lists these records across the selected
namespace. A manual proposal cannot attest fewer tokens than any recorded
late known-usage report, and a proposal already awaiting approval is blocked
if a newly arrived report exceeds its total. The reviewer can reject and
repropose with updated evidence. This preserves contradictory provider
observations; it does not establish which observation or bill is correct.
An isolated PostgreSQL race, RLS and migration check (private development evidence; not distributed)
passed. A later report that contradicts an *already applied* manual adjustment
remains visible in this queue; it does not automatically change counters.

`/settings/ai/quota-supplements` handles a subsequently corrected provider
statement. It pages already adjusted receipts and shows their current counted
total. A signed-in global AI administrator proposes a new confirmed total with
fresh evidence digest, reference and reason. The proposal binds the exact
previous adjustment ID, previous total and next sequence number. An independent
administrator, who was neither proposer nor original model-call actor, must
review it. Approval takes the receipt lock, rejects a changed ledger head or
newly higher known-usage report, and appends only the signed delta to the
original UTC day's actor and namespace buckets. The first adjustment, every
earlier supplement and the original receipt stay sealed. A rejected proposal
changes no counters and permits a corrected new proposal; exact reviewer
retries are idempotent. The effective receipt view uses the latest committed
supplement, while retaining the original hold and first adjustment ID. This is
still human-attested accounting, not automatic supplier-bill verification. An
isolated PostgreSQL migration, three-round review-race and RLS check (private development evidence; not distributed)
passed; production and live-provider acceptance remain open.

`/settings/ai/quota-recovery` handles pending receipts abandoned after process
loss. It does not use age alone: an exact source identity must resolve to a
terminal Studio generation attempt, normally succeeded or failed Activation
Policy proposal, or terminal, unowned Investigation Agent execution.
An administratively interrupted Activation Policy proposal is not eligible:
its external model call may still return late. The receipt and terminal source
must have aged at least 24 hours; Studio also requires its ownership lease to
have expired. A bounded, exact-step model-audit candidate chain is
validated before proposal. Its known token total, event count and SHA-256 of
the exact audit rows are sealed with the case. For Activation Policy proposals,
that digest also binds the complete request and terminal result, including a
zero-event failure. A changed result, model, token total, or request invalidates
the pending review even if its short status and timestamp are unchanged.
Malformed, duplicate, gapped or cross-prompt evidence fails closed. New or
changed model audits invalidate a pending proposal and require rejection and a
fresh proposal.
Other source types and unattributed legacy receipts fail closed. A global,
authenticated human `ai.manage` administrator proposes closure; a different
administrator who was not the original caller must review it. Approval
rechecks receipt/source and audit state under the receipt lock and changes the
pending receipt to `settled` with `external_charge_unknown=true`, the audited
known usage (zero when no model audit exists), and the entire original token
hold. If audited known usage exceeds the hold, only that positive overrun is
added to the original day's actor and namespace buckets; no token is ever
released by closure. A sealed audit-evidence snapshot,
case and unique append-only closure record retain the decision, and later
contradictory settlements enter the conflict ledger. Only a separate billing
attestation can release any tokens. This is not proof the provider call has
ceased; it fences new ownership at the product source, preserves the full
charge, and records a late result rather than treating it as free.
An isolated PostgreSQL migration, three-round review-race and RLS check (private development evidence; not distributed)
passed for this bounded closure path.
The audit-backed recovery migration and repeated native review-race check (private development evidence; not distributed)
also passed. Internal model audits establish recorded usage, not the provider's
final bill; no hold is released by this recovery path.
The native PostgreSQL proposal-source check (private development evidence; not distributed)
passed with a non-owner RLS role and two concurrent reviewers. It does not
establish live-provider charge truth or production-scale throughput.

## Current limitations

- The control plane supports environment, HashiCorp Vault KV v2, and Vault
  dynamic-secret references for AI providers. Vault uses HTTPS except loopback,
  a reread local token file, optional namespace, bounded responses/timeouts, and
  no redirects. Every health, LangGraph reasoner, and Capability Studio request
  acquires a dynamic single-value lease immediately before the HTTP call and
  revokes it on every success or failure path. The value never enters the
  database or audit. Cloud secret-manager adapters and live production Vault
  rotation/lease acceptance remain open.
- Provider health checks validate `/models`; the automated inference and
  fallback suites use controlled OpenAI-compatible gateways. Live-provider
  compatibility and fallback acceptance remain open.
- Persistent principals, roles, token authentication, route-complete scoped
  authorization, investigation permission snapshots, and revocable HttpOnly
  browser sessions with rotating CSRF are implemented. Prebound enterprise
  OIDC Authorization Code/PKCE is implemented; live IdP acceptance and
  trusted-proxy federation remain production gates. Required-auth mode derives
  audit actors from the authenticated principal.
- Provider privacy tier and data residency are enforceable placement labels,
  not a claim that a third-party service actually complies. Contractual and
  live data-residency verification remains an organizational acceptance gate.
