# HTTP and API monitoring

Source implementation as of 12 October 2026. Capability Studio now authors the
same versioned HTTP template that its selected-target test and continuous gateway
use. A reviewed Enable action publishes the exact tested version and approves
collection in one transaction. Fresh metric evidence unlocks a native Grafana
proposal; confirmation returns the real saved dashboard URL. These changes are
deployed in r19.2, with the approved LAB HTTP gateway profile configured. Private HTTP/TLS and
Prometheus tests prove collection with fixture endpoints. Model transport and
Grafana behavior use injected test services, not live conversational qualification.

## Studio conversation and activation

Describe the API measurements under **Monitor a device or API**, supply a
credential-free target URL and select authentication. A sanitized response or
vendor notes are optional under Advanced. Without a sample, local validation is
schema-only and JSON paths remain untested; the UI must not invent collected data.
The model proposes numeric mappings and unsupported measurements. It cannot
change the selected request/authentication, emit executable code or enable itself.

Select a registered HTTP target in the template preview and click **Test selected
target**. The exact immutable version and current device revision are required.
This replaces the connection template, withdraws any old collection approval and
queues the existing scoped Collector lease. After the actual metric-query test,
review the interval and confirm **Enable tested template**. Publication and
monitoring intent commit together; an invalid or stale approval cannot partly
publish the candidate. Protected gateway custody still decides whether Prometheus
can scrape the target.

Status checks query actual Prometheus series for the current enrollment revision.
Every declared metric and adapter health metric needs a fresh sample after
approval, and request success must coexist with a successful scrape. Missing or
stale measurements, failed requests, or changed authority remain unverified.
Counts are aggregated; raw metric values are not copied into PostgreSQL. Original
sample timestamps are checked before attaching a declared metric name, because
[`timestamp`](https://prometheus.io/docs/prometheus/latest/querying/functions/#timestamp)
and [vector operations](https://prometheus.io/docs/prometheus/latest/querying/operators/)
have different name/time semantics. Verification uses bounded query chunks.

Once samples pass, **Prepare native Grafana dashboard** creates one retained
proposal for the enrollment. Open its ordinary Grafana review and confirm the
exact change. Dashboard queries carry device/connection and namespace context;
filters do not enforce device isolation over the shared data source. The saved
URL appears only after confirmed application. Pending or uncertain proposals are
reused for inspection, not repeated writes. Larger templates disclose metrics
omitted by the 20-panel preview limit.

**Edit with AI** creates a new immutable version with the artifact name retained.
It requires a new target test and approval. History/rollback restores an earlier
definition as a newly validated version; review/publish it before selecting and
retesting it. Restore never silently retargets a live enrollment. This path reuses
the existing Collector artifact kind and version registry, with adapter
`http_metrics` and runtime `prometheus_gateway_v1`; no new designer or SQL metric
scheduler is added. Observation output-kind metadata is retained for registry
compatibility, not an instruction to emit inventory envelopes.

## Configure test and enable

1. Register the device’s IP with an HTTP/API connection. Open **Manage → Device
   settings → HTTP/API monitoring template**.
2. Select API JSON measurements or HTTP availability, the request path and port,
   HTTPS and authentication. Select an existing protected credential, or save one
   in Credentials settings. The new HTTPS account type stores username/password;
   existing HTTPS token profiles work for bearer and API-key authentication.
3. Preview the expected numeric metrics. Scalar JSON values use a JSON Pointer;
   arrays use a records pointer and per-record value/label pointers. Counters
   end in `_total`. Advanced details expose labels, certificate/Host name,
   expected statuses, HEAD probes and credential-free curl import.
4. **Save template and test target** withdraws any previous collection approval
   and queues one leased Collector test. The test executes the actual request,
   validates TLS and selected authentication, and requires every declared metric.
   TCP connectivity, HTTP 200 with missing fields, and fixture publication cannot
   satisfy this gate.
5. After the test, approve continuous collection with the existing interval,
   timeout, lifetime and gateway profile controls. Approval is collection intent;
   protected gateway custody and fresh Prometheus samples remain independent
   checks. The dashboard-binding step is not yet part of this interface.

Revisions retain the previous and new declarative definitions in audit history.
Saving a correction queues a new test and requires a new approval. A rotated
HTTP credential invalidates its old test/enrollment binding; existing SNMP and
Windows fingerprint formats are unchanged. The versioned Studio journey above
provides conversation, publication and history/rollback; this direct device form
is a manual correction path and clears any previous artifact-version pin.

## Collection contract

`icheck.http-monitor/v1` is declarative data in the connection configuration. It
contains GET/HEAD, HTTP(S), a credential-free relative path, optional certificate
name, expected status codes, numeric metric mappings and bounded response/record
limits. The test proof binds the normalized definition, target IP/port and current
credential revision. The enrollment also binds device identity, connection
configuration, namespace, scope, approval revision and expiry.

JSON paths follow [JSON Pointer](https://www.rfc-editor.org/info/rfc6901/), including
`~1` and `~0` escapes. Metrics use
[Prometheus text exposition](https://prometheus.io/docs/instrumenting/exposition_formats/).
Duplicate JSON keys or series, missing values, booleans, strings in numeric
fields, non-finite measurements and negative counters fail the test/scrape.
Credentials cannot be exported as fields or labels; echoed protected values are
rejected before any metric bytes are returned.

Prometheus drives collection through the existing authenticated HTTP discovery
job. Each gateway scrape checks current approval before network I/O and again
afterward. The adapter connects only to the approved literal IP, even when a DNS
name is supplied for TLS/Host validation. No proxy, DNS target lookup, redirect,
shell, uploaded executable or model-generated code participates in this path.
Response bytes, records, labels, samples and total elapsed time are bounded.

Probe samples include request success, status, latency and HTTPS certificate
expiry. API mode additionally exports the declared numeric values. An unexpected
status emits request failure, not successful measurements. Gateway `up=1` alone
does not establish HTTP health: iCheck combines request success with scrape
availability and uses the original sample timestamp. Parse/TLS/network failures
cannot reuse an older successful request as current health.

## Protected server configuration

Existing approved network ranges are preserved. A native gateway profile for `https_api` must
explicitly permit sites, CIDRs, ports, credential references, paths and optional
certificate names. Paths can be exact or protected `/prefix/*` entries, so adding
a vendor endpoint within an approved prefix does not require editing core code
or server configuration. Its managed HTTP credential lease is available only to the
configured gateway service, never an ordinary browser or AI principal. Collector
tests use existing scoped worker leases; credentials stay server-side and are
discarded after the attempt.

Anonymous HTTP requires `allow_insecure_http: true` in the protected gateway
profile. Authenticated templates always require HTTPS. Normal OS trust applies
to the Collector; lab certificates need administrator-provisioned trust, not a
template flag disabling verification. The gateway can use its existing protected
TLS CA/client certificate files. Loopback and link-local monitoring targets remain
forbidden in gateway custody.

The extension uses existing JSON/string columns; no separate HTTP schema
migration or metrics table is added. The current paired release and approved LAB
HTTP profile are deployed; selected-target collection still requires the engineer's
explicit test and approval. See the current deployment receipt.

## Remaining preview work

The journey is implemented, fixture-qualified and deployed with the native
gateway/Grafana integration. Live model-backed authoring and actual fresh lab API
samples remain outstanding. SNMP generation, other platform plugins and metric
alerts are implemented separately; their real-target acceptance is not implied
by the HTTP slice.
This adapter supports finite numeric JSON and bounded arrays, not pagination,
OAuth negotiation, arbitrary headers/scripts, mutations or string-to-number
transformations. Unsupported data must be shown explicitly rather than invented.
