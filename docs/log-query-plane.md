# Log query plane

iCheck treats logs as an external evidence plane, not as rows copied into the
control-plane database. The first provider adapter is Loki. Backends, scope
metadata, health state, and hash-only audit records are stored in PostgreSQL;
log lines remain in Loki and are returned only as bounded query results.

## Configuration

Set an exact or wildcard host allowlist before registering a backend:

```bash
ICHECK_LOGS_ALLOWED_HOSTS=loki.example.internal
```

The `/logs` workspace or `POST /api/v1/logs/backends` registers:

- the Loki base URL without embedded credentials, query, or fragment;
- the label that binds streams to a Device, normally `instance`;
- up to 32 labels permitted to leave the log gateway; and
- an explicit `none`, `bearer`, `basic`, or validated custom-header
  authentication mode with its required Credential Profile reference.

Identity and secret-like labels such as `username`, `email`, `authorization`,
`password`, `secret`, and `token` cannot be allowlisted. Credential-backed Loki
queries resolve an enabled, unscoped Profile that permits `loki_query`; secret
values are never accepted in URLs or query arguments and never return through
the API. See [observability backend authentication](./observability-backend-auth.md).

## Query boundaries

```text
POST /api/v1/logs/backends/{backend_id}/query-range
POST /api/v1/logs/backends/{backend_id}/devices/{device_id}/query-range
POST /api/v1/logs/backends/{backend_id}/health
PUT  /api/v1/logs/backends/{backend_id}
```

The update endpoint uses optimistic revision checking and retains a durable
audit trail. Changing configuration or enabled state clears prior health, so a
result obtained under an old URL or credential cannot remain authoritative.

The raw LogQL endpoint requires global authorization scope. A scoped principal
must use the Device endpoint, where the control plane resolves an authorized
Device, builds an anchored regular expression from its exact name and management
IP, uses the backend's configured Device label, and verifies every returned
entry against the same matcher. A backend response outside that selector fails
closed.

The public query contract permits at most seven days and 5,000 entries. Agent
Tools tighten that to 24 hours, 1,000 global entries, or 500 Device entries.
HTTP redirects are rejected, backend responses are capped at 5 MB, log lines at
4,096 characters, and warnings at 100. Common bearer/basic credentials and
password/token/secret assignment forms are replaced with `[REDACTED]` before
the API, AI context, or evidence store can receive them.

Audit events contain the complete query request SHA-256, range, direction,
limits, counts, actor, and stable error type. They do not contain LogQL or log
lines. Agent evidence summaries likewise contain hashes and counts only.

## Agent Tools

- `logs.query_range` is available only to globally scoped Investigations with
  `logs.read`.
- `logs.get_device_range` requires `assets.read` plus `logs.read` and uses the
  server-built Device selector.

Both are read-only `diagnose` Tools in the bounded LangGraph loop. The dedicated
`/logs` page is for human evidence inspection; backend lifecycle and
authentication live at `/settings/observability`. Operators can return to the
AI L1 workspace to correlate selected log evidence with metrics, topology,
Alerts, Situations, and governed diagnostics.

Live Loki compatibility, production Vault/ingress authentication, and
representative log-volume acceptance remain deployment gates for the test lab.
