# Trusted-proxy browser federation

iCheck can accept a human identity from an organization-managed authentication
gateway while keeping authorization inside iCheck. This adapter is intended for
an ingress that already enforces SAML, Kerberos, client-certificate, or another
enterprise login before forwarding a request.

The adapter never trusts a public X-Remote-User header. A login is accepted
only when all of these controls agree:

- the immediate TCP peer is inside an explicitly configured IP/CIDR allowlist;
- the proxy overwrites the verification header with the exact value SUCCESS;
- the proxy supplies a shared secret matching a root-provisioned iCheck secret
  file using a constant-time comparison;
- the external subject is already hash-bound to one enabled local Principal;
- that Principal, tenant, region, and local role bindings are still enabled.

There is no just-in-time Principal creation and no claim-to-role mapping. The
gateway authenticates; the existing iCheck RBAC and tenant/region model
authorizes.

## Configuration

Generate at least 32 random bytes and provision the same value to the ingress
and iCheck without placing it in an environment variable:

    openssl rand -base64 48

The iCheck copy must be a regular file readable by the service account and not
accessible by group or others, normally mode 0600.

    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_ENABLED=true
    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_DISPLAY_NAME=Corporate identity gateway
    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_ISSUER=icheck-edge
    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_SUCCESS_URL=https://icheck.example.internal
    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_NETWORKS=127.0.0.1/32,::1/128
    ICHECK_CONTROL_PLANE_TRUSTED_PROXY_SHARED_SECRET_FILES=/etc/icheck/secrets/trusted-proxy-current

The issuer is a stable local identifier for this gateway. Changing it creates a
different identity namespace and therefore requires new explicit bindings. The
success URL must be an HTTPS origin in production. At most two absolute secret
file paths may be configured, which supports overlap during rotation.

The hardened systemd unit binds Uvicorn to loopback and uses
--no-proxy-headers. Keep that option: request.client must be the raw ingress
socket address, not a browser-controlled or forwarded address. When the ingress
is on another host, bind the API only on a private interface, protect that hop
with TLS/firewall policy, and allowlist only the ingress addresses.

## Ingress contract

Only the following callback receives the asserted identity:

    GET /api/v1/auth/trusted-proxy/callback?return_to=/local/path

Before forwarding it, the ingress must remove any client-supplied values and
set all three headers itself:

    X-Icheck-Trusted-Proxy-Verified: SUCCESS
    X-Icheck-Trusted-Proxy-Subject: stable-directory-subject
    X-Icheck-Trusted-Proxy-Secret: root-provisioned-random-value

Do not forward these headers to unrelated upstreams or log request headers.
Keep the API unreachable except through the private ingress. A typical Nginx
deployment uses auth_request, copies only its trusted identity result, and
includes a root-owned snippet containing the proxy_set_header secret line.
The static proxy credential authenticates the ingress, not the person; a
compromised ingress is therefore inside the trust boundary.

The public login page discovers
GET /api/v1/auth/trusted-proxy/config and links to the callback. If the
gateway does not already have an authenticated browser session, it should
intercept that path and complete its own login before forwarding the asserted
identity.

## Identity enrollment

During migration, retain an existing administrator path, create or select the
local Principal, and apply the required local roles/scopes. Bind the gateway's
stable subject:

    POST /api/v1/auth/principals/{principal_id}/trusted-proxy-identities
    {"subject":"stable-directory-subject"}

The raw external subject is accepted once and only its SHA-256 digest is
returned and persisted. Each (issuer, subject) maps to at most one Principal,
and one Principal has at most one identity for the configured issuer.

    GET /api/v1/auth/principals/{principal_id}/trusted-proxy-identities

    PATCH /api/v1/auth/trusted-proxy-identities/{identity_id}
    {"enabled":false,"reason":"Employment ended"}

Disabling a binding locks it against concurrent login, immediately blocks new
gateway logins, and atomically revokes every active browser session issued from
that binding. Administrators may also list/revoke individual sessions or
revoke all sessions for the local Principal.

## Runtime and audit behavior

Successful federation creates the same hashed, revocable, HttpOnly,
SameSite browser session used by OIDC and the local break-glass exchange.
Unsafe cookie-authenticated API operations still require the rotating CSRF
token. A local absolute return path is validated before redirecting; external
redirect targets are rejected.

Every accepted or denied attempt writes a durable
control_plane_trusted_proxy_login_attempts record. It contains only issuer,
subject, immediate-source hashes, the result/failure code, and stable local
record identifiers. The raw external subject and shared secret are never
persisted or copied into audit details. Successful authentication also emits
auth.trusted_proxy.login_succeeded; binding changes are independently audited
with reason hashes.

Rate-limit the callback at the private ingress. Alert on repeated
untrusted_source, invalid_assertion, and identity_not_enrolled outcomes.

## Secret rotation

1. Provision a second mode-0600 file and configure both old and new file paths
   in ICHECK_CONTROL_PLANE_TRUSTED_PROXY_SHARED_SECRET_FILES.
2. Restart iCheck and confirm both credentials are accepted from the allowlisted
   ingress.
3. Change and reload the ingress so it sends only the new value.
4. Remove the old path from iCheck, restart, and securely retire the old file.

The raw secret is read from disk for each login, so an atomic file replacement
also takes effect without database changes. Two explicit files are preferred
for an observable overlap and rollback window.
