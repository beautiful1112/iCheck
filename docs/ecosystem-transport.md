# Signed ecosystem transport

iCheck separates transport reliability from trust decisions. The transport
worker moves public signed statements and returns public signed evidence; it
does not hold signing keys, create signatures, install packs, publish
Artifacts, activate runtimes, or weaken target-side policy.

The management surface is:

    UI   /studio/catalog/exchange
    POST /api/v1/ecosystem-transport/endpoints
    GET  /api/v1/ecosystem-transport/endpoints
    POST /api/v1/ecosystem-transport/endpoints/{id}/state
    PUT  /api/v1/ecosystem-transport/endpoints/{id}/tls
    POST /api/v1/ecosystem-transport/witness-offers/{id}/dispatch
    POST /api/v1/ecosystem-transport/gossip-offers/{id}/dispatch
    POST /api/v1/ecosystem-transport/promotion-deliveries
    GET  /api/v1/ecosystem-transport/jobs
    POST /api/v1/ecosystem-transport/jobs/{id}/retry
    POST /api/v1/ecosystem-transport/jobs/{id}/cancel
    GET  /api/v1/ecosystem-transport/workers
    GET  /api/v1/ecosystem-transport/health

## Endpoint pinning

Every endpoint has exactly one kind:

- transparency_witness binds an HTTPS URL to one enabled witness identity and
  its already pinned transparency_witness public key; or
- promotion_target binds an HTTPS URL to one exact environment ID and stage;
  or
- gossip_peer binds an HTTPS URL to one exact target region.

URLs must use HTTPS, contain no embedded credentials, query, or fragment, and
match ICHECK_ECOSYSTEM_TRANSPORT_ALLOWED_HOSTS. Wildcard entries match only
subdomains. Redirects are disabled, request timeouts are 1–30 seconds, and
responses are bounded to 1 KiB–5 MB.

An optional credential profile must be enabled, unscoped, and explicitly allow
the ecosystem_transport adapter. The worker resolves exactly one value at
request time and uses it as a Bearer token. The value is never stored in the
endpoint, job, audit ledger, error record, result summary, or API response.

Each endpoint selects `server_auth` or `mutual_tls`. Both modes require normal
certificate-chain and hostname verification with TLS 1.2 or newer. A custom CA
is optional in either mode. Mutual TLS additionally requires a client
certificate and private-key reference; an encrypted key may use a fourth
password reference. All four values are Credential Profile IDs or names, not
PEM, key, or password values. The profiles must be enabled, unscoped, and
allow the `ecosystem_transport` adapter.

`PUT /endpoints/{id}/tls` rotates the complete binding. The caller supplies the
current `expected_tls_revision`; a stale writer receives conflict instead of
silently overwriting a newer identity. Every accepted update increments the
revision and writes a value-free audit record. Pending jobs deliberately use
the latest endpoint identity at send time, and their success summary records
the actual revision plus SHA-256 fingerprints of the custom CA and client
certificate.

The worker resolves TLS material only while sending. On Linux, client
certificate and private key bytes are loaded into the SSL context through
`memfd_create` and `/proc/self/fd`; the descriptors are closed immediately
after `load_cert_chain` and no temporary key file is created. The private key
and password never enter an endpoint row, job, audit event, result summary, or
API response. Invalid PEM/identity material fails permanently; an unavailable
secret provider is retryable. Use Vault KV v2 profiles for production and keep
the worker-local Vault token readable only by the service account.

TLS authenticates the configured server and, in mutual mode, the iCheck
workload. The optional Bearer token is a separate application credential. The
returned signature or exact promotion receipt still authenticates the
application result; mTLS never grants publication or activation authority.

## Durable jobs

Jobs contain only the public checkpoint request, signed promotion envelope, or
quorum-backed gossip document.
A content-addressed key over job kind, endpoint, and signed subject makes
queueing idempotent. PostgreSQL workers claim rows with row locks that skip
already leased work, use hashed lease tokens, recover expired leases, and apply
bounded exponential retry. Permanent protocol/policy failures and exhausted
retries go to dead_letter. Operators may retry non-running failures or cancel
an unleased non-success job.

Only error class and SHA-256 are retained; remote error bodies and messages are
not persisted. The management API also omits the immutable payload snapshot so
signed envelopes do not become a general read-back channel.

The source worker now claims one job immediately before delivery; `batch-size`
is the maximum number processed per cycle. It does not reserve leases for jobs
waiting behind other requests. Each delivery locks and freshly checks the
processing state, worker, token and exact expiry before/after I/O. The timeout
leaves room in the remaining lease, and the final flush rejects expiry before
commit. A row held by an in-flight request is skipped by competing claimers,
even if its lease has expired; the original attempt cannot then commit late.

Endpoint/credential metadata and current witness/policy/key/domain authority
stay shared-locked through I/O and completion. Editors wait on those fences;
after an earlier editor commits, the delivery rechecks its committed state.
Payload checkpoint/target/region/digest/idempotency bindings are independently
validated. Witness sequence admission also serializes absent history. These
locks require bound-namespace READ COMMITTED without DBAPI autocommit.

Evidence ingestion does not commit separately: witness evidence, both audit
events and terminal transport success commit together. Retry/cancel and TLS
edits use fresh mutexes, not cached ORM state. A missing witness policy is read
as its default without granting this worker policy-creation authority.

External HTTP remains **at least once**. If a receiver commits but the worker
loses the response or dies before its SQL commit, replacement may send the same
request again. The receiver must deduplicate the idempotency key and return a
stable signed response. Conflicting evidence fails closed. Neither a transport
receipt nor local SQL fencing proves exactly-once remote effects.

## Witness flow

Each cycle scans the newest 200 unexpired checkpoint offers against enabled
auto_dispatch witness endpoints, chunked in groups of sixteen. It sends the canonical checkpoint statement
plus the idempotency key. A response must be a complete signed witness
attestation.

Success reuses the normal attestation ingest path. That path recomputes the
digest, verifies the domain-separated Ed25519 signature, checks the pinned
witness/key/purpose, binds every checkpoint field, enforces time bounds, and
rejects rollback or conflicting evidence. Existing identical evidence is
idempotent; different evidence for the same witness/checkpoint fails closed.

## Regional gossip flow

Within the same bounded offer window, the worker reconciles checkpoints that
have reached the currently live witness quorum against enabled auto_dispatch gossip peers.
The source region comes from the authenticated request or Worker namespace,
and the endpoint pins a different target region. The remote request uses the
ordinary gossip-ingest contract, so the receiving control plane independently
revalidates the checkpoint, current quorum, every pinned witness signature,
freshness, and fork-alert policy.

Transport success requires an exact receipt: source region, log, epoch,
sequence, head, checkpoint digest, whole-document digest, witness count, and
witness identity set must all match what was sent. A fork receipt must contain
the remote mandatory Alert ID, while a non-fork receipt must not. Exact
delivery is idempotent; receipt drift is a permanent protocol failure.

## Promotion flow

Promotion delivery is always explicit because the worker cannot sign an
attestation. The endpoint binding must match the signed target environment and
stage before queueing. The remote request is the ordinary capability promotion
accept contract, so the target independently rechecks policy, source key,
contiguous sequence, pack lineage, revocation, Artifact state, and
dependencies.

The worker accepts a response only when its receipt exactly matches the signed
source environment, pinned target environment/stage, promotion sequence,
statement digest, and pack digest. Transport success never implies publication
or activation.

## Independent deployment

The reviewed `ecosystem-transport-worker` SQL profile names fourteen relations
and twenty-one UPDATE columns across eight relations. It can manage delivery
leases and append public verified evidence/audit, not configure endpoints,
credentials, quorum or trust; rewrite evidence; access AI/MCP/principal tables;
or publish/promote/activate capabilities. Six single-timestamp grants support
shared metadata locks. They are genuine writable timestamps, including
`artifact_trust_keys.created_at`, not pure SELECT permissions. The trusted core
process binds its namespace; this is not a tenant or remote-worker SQL login.

The source acceptance record (private development evidence; not distributed)
has 86 ordinary and 43 exact-role PostgreSQL passes across targeted runs,
including real row contention, 21 permission denials and four source-process
SIGKILL boundaries with natural lease expiry. HTTPS receivers are fixtures;
no installed systemd, live witness/Vault/mTLS peer, distributed ceremony,
sustained backlog/load or full-product acceptance is claimed. The newest-200
offer window is an explicit backlog/fairness limit, not an unbounded scan.
This source is not in the frozen r31 candidate or installed r30 backend yet.

Install the package entry point and run the supplied unit:

    icheck-ecosystem-transport-worker
    deploy/systemd/icheck-ecosystem-transport-worker.service
    deploy/systemd/ecosystem-transport-worker.env.example

The worker refuses SQLite because safe multi-worker leases require PostgreSQL,
and it refuses to start with an empty transport host allowlist. Run more than
one worker for availability; the database lease prevents concurrent ownership.
The supplied environment example includes the optional Vault provider needed
for production CA/client-identity references. The service needs Linux memfd and
`/proc/self/fd`; it does not need a writable certificate directory.

Remaining production work is live external witness and multi-environment
acceptance, live CI identity-provider acceptance, live vendor recovery
gateway/drill acceptance, and long-duration partition/recovery testing. Verified imported fork
evidence already routes to mandatory critical Alerts and Situations.
