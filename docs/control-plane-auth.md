# Control-plane authentication and authorization

## Implemented boundary

iCheck now persists control-plane principals, roles, scoped role bindings, and
revocable access tokens. Only a SHA-256 token hash and a non-secret lookup
prefix are stored. The raw token is returned once at issuance and is never
written to an audit event.

`ICHECK_CONTROL_PLANE_AUTH_MODE` has two explicit modes:

- `disabled` is for local development and automated tests. Requests run as the
  visible `development` wildcard principal.
- `required` enforces bearer authentication. `ICHECK_ENVIRONMENT=production`
  refuses to start unless this mode is selected.

The built-in roles are `viewer`, `operator`, `approver`, and `admin`. Bindings
may be global or carry bounded `sites` and `device_ids` scope. Scope is
persisted and snapshotted; per-target enforcement across every legacy API is
still an M1 exit gate.

## One-time bootstrap

Set a long random `ICHECK_CONTROL_PLANE_BOOTSTRAP_TOKEN`, start the API, and
create the first administrator:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/bootstrap \
  -H 'Content-Type: application/json' \
  -H 'X-Icheck-Bootstrap-Token: replace-with-bootstrap-token' \
  -d '{
    "subject": "admin@example.internal",
    "display_name": "Initial Administrator",
    "token_name": "initial-admin",
    "expires_in_hours": 24
  }'
```

Bootstrap fails after the first principal exists. Store the returned access
token in an approved secret manager and remove the bootstrap token from the
service environment. It must not be placed in browser local storage.

Administrative APIs under `/api/v1/auth` create principals and custom roles,
bind roles and scopes, issue tokens, list redacted token metadata, and revoke
tokens. `/api/v1/auth/me` returns the effective server-side identity,
permissions, roles, and merged authorization scope.

## Agent authorization

When a user creates an investigation, iCheck ignores client-supplied authorship
in required mode and snapshots the authenticated principal ID, permission set,
and authorization scope. Later role expansion cannot grant new capabilities to
that in-flight investigation.

The model receives only tools permitted by the immutable snapshot. The tool-call
persistence boundary and database executor enforce the same permission again.
Permission denial is audited without executing the handler.

State-changing tools create an exact, SHA-256-bound action proposal and pause
the same LangGraph thread. A different principal with `changes.approve` must
approve or reject it. A valid decision requeues the existing execution and
resumes the same checkpoint. An `executing` proposal found after worker loss is
not replayed automatically because the external outcome may be ambiguous.

## Remaining production identity work

Bearer tokens provide the persistent API/service identity foundation and the
four-eyes policy has server-side principal enforcement. Production browser
access still needs an OIDC/session or trusted identity-proxy adapter; long-lived
API tokens are not a browser session design. The remaining M1 work also includes
RBAC/scope enforcement on every older asset, collector, alert, metric, and AI
settings route plus mTLS/certificate identity for distributed workers.
