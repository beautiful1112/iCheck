# CI workload identity federation

iCheck accepts short-lived signed OIDC/JWT assertions from one configured CI
issuer and exchanges each assertion once for a still-shorter iCheck bearer
token. This removes the need to store a long-lived iCheck administrator token
in a CI secret store.

The external provider authenticates the workload. Authorization remains a
pre-created iCheck service Principal with local role bindings, tenant, region,
and scope. There is no just-in-time Principal creation and no role grant from
repository, branch, environment, or group claims.

## Configuration

Configure the exact issuer, audience that CI must request, and every exact host
that discovery or JWKS retrieval may contact:

    ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_ENABLED=true
    ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_ISSUER=https://token.actions.githubusercontent.com
    ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_AUDIENCE=icheck-ci
    ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_ALLOWED_HOSTS=token.actions.githubusercontent.com
    ICHECK_CONTROL_PLANE_WORKLOAD_OIDC_TIMEOUT_SECONDS=10
    ICHECK_CONTROL_PLANE_WORKLOAD_TOKEN_TTL_MINUTES=15

The issuer and all discovered endpoints must use HTTPS and an allowlisted
hostname. Redirects are disabled. Provider documents and JWKS are bounded to
1 MiB, the key set is bounded to 128 entries, and network timeouts are 1 to 30
seconds. The runtime accepts RS256, PS256, and ES256 only.

GET /api/v1/auth/workload/config exposes the enabled issuer, audience, and
global token TTL so a pipeline can fail early on configuration drift. These
values are policy metadata, not secrets.

## Prebinding

Create a service Principal, apply only the roles and object scope the pipeline
needs, then bind the provider's exact stable subject:

    POST /api/v1/auth/principals/{principal_id}/workload-identities
    {
      "subject": "repo:example/network-automation:ref:refs/heads/main",
      "max_token_ttl_minutes": 10
    }

Human user Principals are rejected. The raw external subject is accepted once;
the API response and database retain only its SHA-256 digest. The configured
audience is also hash-bound. Each issuer/subject pair maps to one service
Principal, and one Principal has at most one identity for the issuer.

    GET /api/v1/auth/principals/{principal_id}/workload-identities

    PATCH /api/v1/auth/workload-identities/{identity_id}
    {
      "enabled": false,
      "max_token_ttl_minutes": 10,
      "reason": "Pipeline retired"
    }

Disabling a workload identity blocks new exchanges and immediately invalidates
every existing icw_ token linked to that identity, even if its stored expiry is
later.

## Token exchange

Request an OIDC token from the CI provider with the configured audience, then
send the standard token-exchange fields:

    POST /api/v1/auth/workload/token
    Content-Type: application/json

    {
      "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
      "subject_token": "<provider JWT>",
      "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"
    }

The successful response is marked Cache-Control: no-store:

    {
      "access_token": "icw_...",
      "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
      "token_type": "Bearer",
      "expires_in": 599
    }

Use that token as a normal Bearer credential on authorized iCheck API routes.
The effective auth method reported by /api/v1/auth/me is workload. The token
expires at the earliest of:

- the provider assertion expiry;
- the global workload-token TTL, 1 to 60 minutes;
- the identity-specific TTL, 1 to 60 minutes.

Only the icw_ prefix and SHA-256 token hash are stored. The raw provider JWT
and raw iCheck token are never persisted or copied to audit details.

## Validation and replay boundary

Every exchange performs fresh allowlisted discovery and JWKS retrieval, verifies
the signature, and then validates exact issuer and configured audience. The
subject and jti must be bounded printable strings. exp and iat are mandatory;
nbf is honored; future, expired, older-than-one-hour, or longer-than-one-hour
assertions fail closed.

The jti digest has a database uniqueness boundary. The first signed assertion
attempt consumes it whether identity lookup succeeds or fails. A concurrent or
later replay cannot issue another token and is recorded as
replayed_assertion.

Each accepted or denied attempt writes a durable
control_plane_workload_exchanges row containing only claim, issuer, subject,
audience, jti, and source-address hashes plus stable local identifiers and
expiry metadata. A success emits auth.workload.token_exchanged with only
hashes and the non-secret iCheck token prefix. Binding changes are separately
audited with a reason hash.

Rate-limit the public exchange endpoint at the private ingress and alert on
provider_unavailable, replayed_assertion, identity_not_enrolled, and repeated
invalid_subject_token outcomes.

## Provider and binding rotation

Provider signing-key rotation is automatic because each exchange retrieves and
verifies the current bounded JWKS. Changing issuer or audience creates a new
trust contract: update configuration, restart, and explicitly create new
bindings rather than silently reusing the old identity hashes.

For repository, branch, or environment changes, create a new exact subject
binding and test it with least-privilege roles before disabling the old one.
Do not implement broad wildcard matching at the ingress; any future
claim-to-policy mapping must be a separately governed, testable feature.
