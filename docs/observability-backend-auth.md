# Observability backend authentication

Prometheus-compatible Metric Backends and Loki Log Backends use the same
control-plane authentication contract. Operators configure them at
`/settings/observability`; API clients use `POST /api/v1/metrics/backends` or
`POST /api/v1/logs/backends`.

Existing backends are revised with `PUT /api/v1/metrics/backends/{id}` or
`PUT /api/v1/logs/backends/{id}`. The request must include the last observed
`expected_revision`; a stale writer receives `409` and cannot overwrite a
newer operator decision. Accepted revisions increment monotonically, reset
stored health to `unchecked`, and record changed field names plus safe endpoint
and auth metadata in audit. The same UI provides reversible enable/disable;
backend rows and their audit history are not destructively deleted.

## Contract

Each backend declares exactly one authentication mode:

| `auth_type` | Credential value | Emitted request header |
|---|---|---|
| `none` | No Credential Profile is allowed | none |
| `bearer` | opaque token | `Authorization: Bearer …` |
| `basic` | one `username:password` value | RFC 7617-style `Authorization: Basic …` |
| `header` | opaque value | the validated `auth_header_name` |

Authenticated backends must reference an enabled Credential Profile. The
profile must permit `prometheus_query` or `loki_query`, respectively, and must
have an empty Worker selector because the control plane performs these queries.
The custom-header mode rejects malformed names and protected routing,
framing, proxy, cookie, authorization, content, forwarding, and user-agent
headers. Bearer and basic modes own `Authorization`; it cannot be selected as
a custom header.

The Profile stores only an external reference such as
`env://ICHECK_OBSERVABILITY_TOKEN` or a Vault KV v2 reference. The server
resolves exactly one bounded value immediately before each request. It never
returns that value to the browser, persists it in a backend row, or places it
in an audit event. Environment resolution is suitable for a controlled local
deployment; production should use the configured Vault server-secret adapter.
Worker-scoped and dynamic Worker credentials remain outside this boundary.

## Request and failure boundary

Authentication is applied after the backend URL passes its exact/wildcard host
allowlist and before the redirect-disabled HTTP request is opened. The same
contract covers interactive queries, Agent Tool queries, Indicator Worker
polling, and backend health checks because all use the shared metric or log
client.

Resolved values and their generated bearer/basic representations are held only
in request-local memory. If an upstream transport or response body echoes one,
the value is replaced with `[REDACTED]` before an API error or persisted health
message is produced. Query audit records contain request hashes and stable
error types, not PromQL, LogQL, credentials, or response lines.

Configuration fails closed when the Profile is missing, disabled,
adapter-incompatible, Worker-scoped, unresolved, multi-valued, malformed for
basic auth, or contains CR/LF characters. Existing unauthenticated backends are
migrated explicitly to `auth_type=none` and revision zero.

## Acceptance

Automated coverage proves bearer, basic, and custom-header emission; rejects
ambiguous and unsafe configurations; and injects a secret-echoing upstream
failure to verify API and audit redaction. Lab acceptance must additionally
exercise the selected production secret provider and the real Prometheus/Loki
ingress authentication policy.
