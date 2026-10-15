# Metric query authorization

This implementation is packaged in the r34 candidate, not installed r30 acceptance.
The generic metrics API, raw AI PromQL tools and internal indicator polling
constrain series before evaluation. Backend-row RLS alone is not sufficient.

## Query boundary

The authenticated request/investigation namespace must match the selected SQL
session and backend. Namespace-wide scope means that namespace, not the whole
upstream database. Site/device-scoped requests resolve current authorized
device IDs from SQL, with an explicit 10,000-device cap and no truncation.
Every vector selector receives literal `icheck_tenant_id` and
`icheck_region_id` matchers; restricted requests also receive an anchored
Prometheus device-ID regex. Empty device scope produces an impossible
conjunction, excluding unlabeled infrastructure. Backend `external_labels`
and caller-supplied `site`, names or IP aliases cannot grant scope.

`promql-parser==0.10.0` parses the expression tree. Selector replacement covers
joins, arithmetic, set operators, aggregation parameters, ranges and subqueries,
preserving offset and `@` modifiers. Typed literal placeholders avoid the
native formatter's string-escaping defects; correctly quoted originals are
restored once. The outgoing query is parsed again and every selector's mandatory
matchers are verified. No regex-based PromQL parser or unscoped fallback exists.

Input is limited to 8,192 UTF-8 bytes, 512 AST nodes, 128 selectors and
1,000,000 compiled bytes. Expansion overflow is an explicit refusal, not a
partial scope. Unknown syntax/functions and quoted UTF-8 label names are
currently unsupported. `info()` is refused because it implicitly reads info
series outside its visible argument. `label_replace` and `label_join` cannot
rewrite authorization labels. Other output grouping may remove labels: that
is safe only because input series were constrained before aggregation.

PostgreSQL requires transactional READ COMMITTED. Current device membership
and backend revision/enablement are checked again after upstream I/O; changed
authority discards the result. No SQL lock is held across that request. This
is not an atomic revocation guarantee: request authentication and investigation
permission admission retain their existing boundaries, and an already dispatched
read can finish. Upstream credentials are request-local; ambient proxies and
redirects are disabled. Audit retains the existing query reference, not PromQL
or returned data. API actor identity comes from authentication, not the payload.

Internal indicator polling is bound to its selected namespace. Its namespace-wide
queries do not read device inventory or require any expansion of the reviewed
11-relation indicator SQL profile. Namespace-less local service fixtures are
default-namespace-only; public/user queries require a principal.

## Device tools and ingestion

`metrics.get_device_range` selects a literal stable device ID and namespace.
Every returned series must carry that identity and the requested metric name;
name/IP reuse, missing identity and foreign namespace labels are refused.
Existing exporter metric, series, point and output-label limits remain.
Raw instant/range AI tools now support restricted investigations through the
same compiler. Restricted raw LogQL remains refused; this change does not
introduce a general logs authorization gateway.

The evaluator is trusted to honor PromQL. Trusted ingestion must assign the
authorization labels. The GUI monitoring gateway/job uses operator-controlled
namespace/device labels with `honor_labels: false`; arbitrary exporters must
not be allowed to assert another tenant's identity. Legacy unlabeled samples
are intentionally invisible to scoped queries, with no name/IP fallback.
Externally managed backends need equivalent ingestion qualification. Neither
selector rewriting nor synthetic tests establish physical device identity.

## Verification and remaining work

The checkpoint record (private development evidence; not distributed)
records an uninterrupted 60-case focused source run, ten disposable PostgreSQL
checks and ten checks using real Prometheus 3.13.3 evaluation. Synthetic fixtures
include two namespaces, another region, unauthorized devices and a reused IP;
foreign values are excluded before joins, aggregates, scalars and range queries.
The exact indicator role cannot select device inventory and still queries
successfully. These are not real-device, installed gateway or production tests.

The r34 candidate (private development evidence; not distributed)
regenerates constraints/wheelhouse with the parser dependency and batches the
current API/controller/gateway/frontend with h5. Current and historical artifact
helpers now have separate gates. Frozen r31 and installed r30 still contain
their preceding 72-pin runtime and do not contain this change. Native
installation requires explicit deployment approval.
Installed custody/lifecycle, required-auth browser-to-gateway ingestion, real
exporter TLS/auth, production identity/transport/secrets, recovery/drain/capacity,
representative fleet load and the GUI-onboarded lab remain release gates.
The integrated demo has not run.
