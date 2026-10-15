# Control-plane authentication and authorization

## Implemented boundary

iCheck now persists control-plane principals, roles, scoped role bindings,
revocable access tokens, local human passwords, and short-lived browser sessions.
Access/session/CSRF tokens use SHA-256 hashes and non-secret lookup prefixes.
Passwords use separately salted, versioned PBKDF2-HMAC-SHA-256 hashes with
600,000 iterations, not token hashing. Raw passwords and tokens never appear in
account reads, validation responses, or audit events. The password work factor
follows the [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

`ICHECK_CONTROL_PLANE_AUTH_MODE` has two explicit modes:

- `disabled` is for local development and automated tests. Requests run as the
  visible `development` wildcard principal.
- `required` accepts a bearer token or an authenticated HttpOnly browser
  session. Unsafe cookie-authenticated requests also require a rotating
  `X-Icheck-CSRF-Token`. `ICHECK_ENVIRONMENT=production` refuses to start
  unless required auth and secure session cookies are selected.

The built-in roles are `viewer`, `operator`, `approver`, `capability_author`,
`service_owner`, and `admin`. Bindings may be global or carry bounded `sites`
and `device_ids` scope. Scope is
enforced in inventory, endpoint-child data, alerts, dashboard counts, device
activation, collector workers/deployments/runs, investigations, approvals, and
built-in Agent tools. Global auth administration requires global scope.

Source acceptance and Situation recovery criteria require persisted independent
human identities, not the development wildcard or a service principal. Custom
reviewer roles use `alerts.sources.qualify` for exact source acceptance and
`situations.recovery.qualify` for reusable recovery criteria. Proposal and peer
acceptance also require current `capabilities.read`; emergency revocation does
not. Ordinary persisted Alert readers can query non-material recovery evidence
without implementation access. These permissions do not authorize incident
closure. See [Situation recovery policies](situation-recovery-policies.md).

## Tenant and region boundary

Each persisted principal belongs to exactly one tenant. Requests select an
enabled assigned region with `X-Icheck-Tenant-ID` and
`X-Icheck-Region-ID`; the server rejects cross-tenant selection and regions
outside a principal's optional `allowed_region_ids`. Role bindings and
“global” scope are resolved inside the selected tenant and region.

Operational data is protected by ORM namespace predicates, write guards, and
PostgreSQL RLS. Transaction-local RLS selectors are restored after every
commit. Production API and Worker roles must be non-owner roles without
`BYPASSRLS`; migrations use a separate owner role. All independently deployed
workers require fixed tenant and region UUIDs. See
[`tenant-region-isolation.md`](./tenant-region-isolation.md).

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

The dedicated `/settings/identity` administration page exposes those lifecycle
operations away from the AI L1 workspace. An administrator can create a human
or service Principal assigned initially to the current region without implicit
access, define a custom permission role, bind an explicit role and scope, issue
a one-time-visible token, prebind an OIDC, trusted-proxy, or workload identity,
inspect redacted sessions, and revoke each supported credential.
Federation subjects are accepted once and only their hashes return to the
browser. Session/token hashes are never rendered.

`PATCH /api/v1/auth/principals/{principal_id}` provides reasoned enable/disable.
Disablement atomically marks the Principal unavailable and revokes every active
access token and browser session. Re-enabling does not revive those credentials.
`POST /api/v1/auth/bindings/{binding_id}/revoke` removes a role binding, so its
permissions disappear on the next request. Both operations are audited with a
reason hash. The current administrator cannot disable itself or revoke its own
binding through these endpoints; a second administrator must perform that
change.

## Username and password sign in

The default `/login` form accepts a username and password, not an API token.
The username is the existing human Principal's exact, case-sensitive `subject`;
surrounding username whitespace is ignored. Passwords are not trimmed or
truncated. New passwords contain 15 to 256 characters; long passphrases and
Unicode are supported without composition rules. No default password or public
self-registration is provided.

The evaluation server received this flow in r7, migrated to
`p3t5v7x9z1c4` on 2026-10-11. Its current r17 backend and database revision
`s6w8y0b2d4f7` retain the password migration. A live recheck on 2026-10-12
confirmed the existing administrator can sign in on both LAN HTTPS origins;
its account, password and API token were preserved. No further migration or
application restart was required.
See the [server access guide](engineering-preview-server-access.md) for private
credential custody and the live verification record. Frozen older packages
are not upgraded by this source or host change.

`POST /api/v1/auth/login` accepts `{username, password}` and returns the existing
HttpOnly session cookie and in-memory CSRF value, never an API access token.
It uses the server's `ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_TENANT=local` by default;
API clients can explicitly supply a tenant slug or ID in `tenant`. The web form
uses the configured server tenant. Lookup always stays inside that tenant and
uses the account's home region; existing local roles and allowed regions still
govern subsequent requests. Service accounts, disabled users and unavailable
tenants/regions cannot sign in.

Unknown users, missing passwords and rejected credentials receive the same 401
message and equivalent password-KDF work. Five failed attempts lock an existing
account for five minutes. Counters are stored in SQL and serialized with the
Principal row lock, so API workers and restarts share the lockout. Admin password
resets clear it. Deployments should additionally rate-limit login requests at
their trusted ingress. Browser requests must use an allowed CORS origin; form
submissions are rejected. Login responses are not cacheable.

Administrators with global `auth.admin` set or reset an existing human account's
password in `/settings/identity`, using
`PUT /api/v1/auth/principals/{principal_id}/password` with `{password, reason}`.
The read response exposes only `password_login_configured`, not the password or
hash. Account creation and role binding remain separate; assigning a password
does not grant permissions. A Bootstrap request can optionally set the initial
human password, but existing token-only accounts are not silently assigned one.

For initial provisioning or upgrading a token-only installation, run the bundled
`tools/preview_operator_password.py` (repository path
`deploy/preview_operator_password.py`) in a protected interactive terminal. It
reads an administrator token from a private file and prompts for the password
without echo; there is no password argument or environment-variable option.
This is an administrative API operation, not token-based GUI sign-in.

Any authenticated human can change their own password at `/settings/account`,
using `POST /api/v1/auth/password/change` with `{current_password, new_password}`.
The current password and cookie CSRF protection are required. Changes revoke
all existing browser sessions; self-service change issues a fresh session for
the current browser. An admin resetting their own password must sign in again.
API tokens, workload identities, and Collector/Agent credentials are unchanged.
There is no email-based password recovery in this preview; an administrator
resets the password instead.

`ICHECK_CONTROL_PLANE_PASSWORD_LOGIN_ENABLED=true` is the default. Set it false
only when deliberately using optional enterprise SSO instead. API bearer tokens
continue to work independently of both browser-login switches.

## Legacy token session exchange

The GUI does not accept or store a long-lived access token.
`POST /api/v1/auth/browser-sessions` remains an opt-in programmatic compatibility
endpoint; the API returns an HttpOnly,
SameSite session cookie and a short-lived CSRF value held only in page memory.
After reload, the shared frontend client checks `/auth/me` before the first
unsafe request. A browser session obtains a new CSRF value through the
cookie-authenticated `GET /api/v1/auth/browser-sessions/current/csrf`
endpoint before sending that request; development-mode access skips the CSRF
endpoint. A stale token still triggers one refresh and retry on a CSRF-specific
403. Logout revokes the server-side session before deleting the cookie.
The AI operator sidebar exposes that logout action only when `/auth/me`
identifies a real `browser_session`; development mode does not show a false
logout control.
Administrators can list redacted tenant sessions with
`GET /api/v1/auth/browser-sessions`, revoke one with a reason through
`POST /api/v1/auth/browser-sessions/{session_id}/revoke`, or atomically
revoke every active session for a Principal through
`POST /api/v1/auth/principals/{principal_id}/browser-sessions/revoke`.
Responses never expose session-token or CSRF hashes. OIDC and trusted-proxy
sessions retain their binding provenance; disabling either binding serializes
against login and revokes every linked session in the same transaction.

Configure:

- `ICHECK_CONTROL_PLANE_BROWSER_SESSION_TTL_HOURS` (1–168);
- `ICHECK_CONTROL_PLANE_SESSION_COOKIE_SECURE=true` in production;
- `ICHECK_CONTROL_PLANE_SESSION_COOKIE_SAMESITE=strict` by default.

The login page discovers both implemented enterprise browser adapters. OIDC
uses Authorization Code/PKCE and prebound issuer/subject identities. The
trusted-proxy adapter additionally requires an allowlisted immediate peer, a
root-provisioned shared-secret file, and a prebound issuer/subject identity; it
never accepts a public identity header by itself. Neither adapter grants roles
from ungoverned claims. No local token form is rendered.
`ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED=false` is the default;
enabling it permits only the legacy API token exchange, not a GUI login field. See
[`oidc-federation.md`](./oidc-federation.md) and
[`trusted-proxy-federation.md`](./trusted-proxy-federation.md).

## Browser session and namespace changes

The shared browser client captures the selected tenant, region and session
change at the start of each API request. It first compares browser storage with
the context last observed by this tab, so a click cannot cross into another
tab's newly selected scope before its storage event arrives. It checks the
captured context before sending a mutation and again before returning a
response body. A pending request whose
context changed cannot publish its old result into the new workspace. Scope or
session changes also discard cached CSRF state; late responses cannot refill it.
The server continues to enforce the selected scope and CSRF token independently.

The live investigation EventSource is bound to the same captured context.
Changing scope or session closes open streams; each incoming event is checked
again before it reaches the workspace, including before a cross-tab storage
event arrives. Explicit page cleanup closes the stream idempotently. The server
still authenticates and scopes each stream request. If a new stream is refused
because the context already changed, the workspace waits for its pending
cross-tab refresh instead of treating that expected race as a page failure.

Password sign-in/change, legacy token exchange, enterprise sign-in completion
and logout announce a non-secret session change to other tabs. An expired-session response does the
same. Other tabs hide their current page and navigate to a fresh sign-in or
operator view. A tenant or region change in another tab reloads the page so
previously rendered data is cleared. Frontend-initiated OIDC and trusted-proxy
login return through `/auth/complete`, which checks the new session before
announcing it; the check omits the previous tenant and region selector.

The browser privacy acceptance record (private development evidence; not distributed)
covers request races and a real browser with controlled API responses. Production
IdP, TLS, external revocation timing and the full accessibility/privacy review
remain release gates.

## Agent authorization

When a user creates an investigation, iCheck ignores client-supplied authorship
in required mode and snapshots the authenticated principal ID, permission set,
and authorization scope. Later role expansion cannot grant new capabilities to
that in-flight investigation.

The model receives only tools permitted by the immutable snapshot. The tool-call
persistence boundary and database executor enforce the same permission again.
Built-in device, endpoint-history, and alert tools also apply the snapshotted
device/site scope to their SQL and child records. Scoped PromQL fails closed
until a label-enforcing metrics gateway exists. Permission denial is audited
without executing the handler.

State-changing tools create an exact, SHA-256-bound action proposal and pause
the same LangGraph thread. A different principal with `changes.approve` must
approve or reject it. A valid decision requeues the existing execution and
resumes the same checkpoint. An `executing` proposal found after worker loss is
not replayed automatically because the external outcome may be ambiguous.

Operators with `changes.plan` may bind exact pre-check, dry-run, post-check, or
rollback Tool-call evidence and configure a maintenance window on a governed
change plan. This permission cannot approve the plan. The peer approver still
requires `changes.approve`; approval binds both action and change-plan hashes.

## Reviewed Situation closure authorization

Reviewed Situation closure has its own `situations.closure.qualify` and
`situations.close` permissions. Human qualification also requires `alerts.read`
and `capabilities.read`; the criteria author cannot self-qualify, and the grant
reviewer cannot execute their grant. Current scoped read authority remains
necessary for historical receipt recovery after execution revocation. The
initiating caller/Investigation snapshot and current persisted scope both apply.
These runtime-owned requirements cannot be removed through a Tool alias.
See [reviewed-situation-closure.md](reviewed-situation-closure.md).

## Remaining production identity work

OIDC Authorization Code/PKCE, shared-secret/source-bound trusted-proxy browser
federation with governed prebinding, and distributed Worker mTLS are
implemented. Production still requires live IdP/gateway registration and
claims acceptance, ingress rate limits, live CI-provider acceptance, and (if
desired) an explicitly governed group-to-role mapping policy. The current
runtime deliberately ignores
group claims for authorization. CI OIDC/JWT exchange is implemented with
service-Principal prebinding, one-time jti consumption, bounded icw_ tokens,
and immediate identity-disable enforcement. The environment-owned Worker
CA/proxy rollout remains separate acceptance work. See
[`workload-identity-federation.md`](./workload-identity-federation.md).
