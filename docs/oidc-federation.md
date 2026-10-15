# Enterprise browser identity federation

iCheck supports one OpenID Connect provider through Authorization Code flow,
PKCE S256, and a confidential client. The provider authenticates a human; the
existing iCheck Principal, role bindings, tenant/region assignments, scopes,
approval separation, and audit rules remain the authorization authority.

There is no just-in-time Principal creation and no automatic group-to-role
grant. An administrator must first create the local Principal and governed role
bindings, then bind the provider's stable `sub` value. This prevents a claim or
IdP group naming mistake from creating platform privileges.

## Provider registration

Register this callback at the provider exactly:

```text
https://icheck.example.internal/api/v1/auth/oidc/callback
```

Enable Authorization Code, `client_secret_basic`, and PKCE S256. The current
runtime accepts signed ID tokens using `RS256`, `PS256`, or `ES256`. Do not
request `offline_access`; iCheck does not retain access or refresh tokens.

Generate a transaction-encryption key once:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Place that value and the OIDC client secret in separate root-provisioned files
readable by the `icheck` service account, with no group/other permissions
(normally mode `0600`). Configure:

```text
ICHECK_CONTROL_PLANE_OIDC_ENABLED=true
ICHECK_CONTROL_PLANE_OIDC_DISPLAY_NAME=Enterprise SSO
ICHECK_CONTROL_PLANE_OIDC_ISSUER=https://login.example.internal/tenant
ICHECK_CONTROL_PLANE_OIDC_CLIENT_ID=icheck-control-plane
ICHECK_CONTROL_PLANE_OIDC_CLIENT_SECRET_FILE=/etc/icheck/secrets/oidc-client-secret
ICHECK_CONTROL_PLANE_OIDC_TRANSACTION_SECRET_FILE=/etc/icheck/secrets/oidc-transaction-key
ICHECK_CONTROL_PLANE_OIDC_REDIRECT_URI=https://icheck.example.internal/api/v1/auth/oidc/callback
ICHECK_CONTROL_PLANE_OIDC_SUCCESS_URL=https://icheck.example.internal
ICHECK_CONTROL_PLANE_OIDC_ALLOWED_HOSTS=login.example.internal
ICHECK_CONTROL_PLANE_OIDC_SCOPES=openid profile email
ICHECK_CONTROL_PLANE_OIDC_MAX_PENDING_TRANSACTIONS=10000
ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED=false
```

The issuer must be HTTPS and its exact hostname plus every hostname returned
for authorization, token, and JWKS endpoints must be allowlisted. Redirects are
disabled for server-to-provider requests. The public success URL is an origin,
not an arbitrary redirect prefix. HTTP redirect/success URLs are accepted only
for loopback development and are rejected in production.

## Identity enrollment

During migration, keep local browser login enabled, authenticate as an existing
`auth.admin`, and create or choose a Principal with the required local role
bindings. Bind the stable provider subject:

```text
POST /api/v1/auth/principals/{principal_id}/oidc-identities
{"subject":"provider-stable-sub-value"}
```

The response and database retain only the subject's SHA-256 digest. The issuer
is retained to support operator inspection, plus an issuer digest used for the
lookup. Each external identity maps to at most one Principal, and one Principal
has at most one identity for the configured issuer.

List bindings with:

```text
GET /api/v1/auth/principals/{principal_id}/oidc-identities
```

Disable or restore one with a reason:

```text
PATCH /api/v1/auth/oidc-identities/{identity_id}
{"enabled":false,"reason":"Employment ended"}
```

Disabling the identity locks the binding against concurrent login, blocks new
OIDC logins, and atomically revokes every active browser session issued from
that binding. Administrators may also list/revoke individual sessions or
revoke all sessions for the local Principal through the control-plane session
APIs.

## Login security boundary

`GET /api/v1/auth/oidc/start` creates a ten-minute one-time transaction and
redirects to the discovered authorization endpoint. It binds:

- a random state value stored only as a hash;
- a second HttpOnly, SameSite=Lax browser transaction cookie stored only as a
  hash;
- a random OIDC nonce stored only as a hash;
- a PKCE verifier encrypted with the transaction key;
- a digest of the exact issuer/endpoints/algorithms discovered at start;
- a validated local return path.

The callback locks and consumes the transaction before token exchange. It
re-discovers and compares provider metadata, exchanges the one-time code with
`client_secret_basic` and the PKCE verifier, retrieves a bounded JWKS, verifies
the ID-token signature and allowed algorithm, then validates issuer, audience,
authorized party, nonce, issue time, expiry, and optional not-before. A signed
identity without an enabled prebinding fails closed.

The ID token, provider access token, code, nonce, raw state, raw subject, raw
claims, and PKCE verifier are never persisted. Durable evidence contains only
identity, claims, reason, and transaction failure hashes. A successful login
receives the existing HttpOnly iCheck session plus the same rotating CSRF
boundary used by local session exchange.

Rate-limit `/api/v1/auth/oidc/start` and `/api/v1/auth/oidc/callback` at the
private ingress. Provider discovery/JWKS/token responses are size/time bounded,
expired transaction rows are pruned on login start, and a PostgreSQL advisory
lock enforces the configured active-transaction ceiling across control-plane
processes. Ingress rate limiting remains the first deployment boundary against
anonymous provider and database load.

## Rotation and rollback

Rotate the client-secret file using the provider's overlap procedure, then
restart the control plane. Rotating the Fernet transaction key intentionally
invalidates in-flight logins; wait the configured transaction TTL or accept a
bounded re-login window. Existing browser sessions are unaffected.

`ICHECK_CONTROL_PLANE_LOCAL_BROWSER_LOGIN_ENABLED=true` is a deliberate
migration/break-glass choice: it allows a valid iCheck bearer token to create a
browser session and therefore bypasses enterprise MFA policy. Production
should normally set it to `false` after representative identities have been
accepted. API bearer tokens remain available for governed automation.
