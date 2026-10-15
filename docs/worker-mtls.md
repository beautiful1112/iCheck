# Distributed Worker mTLS

Collector and remote Agent Worker API traffic uses two independent credentials:

1. a rotating application bearer token that identifies the Worker record;
2. a client certificate verified by a trusted TLS proxy and bound to that same
   Worker record by SHA-256 fingerprint.

Both must match after a Worker is bound. A certificate cannot be active or
staged on another Collector or Agent Worker in the same tenant and region.
PostgreSQL advisory locks serialize cross-table identity claims, while row
locks serialize certificate promotion, cancellation, and revocation.

## Control-plane modes

`ICHECK_WORKER_MTLS_MODE` has three values:

- `disabled`: development default. Forwarded certificate headers are rejected.
  A previously bound Worker also fails closed, preventing a configuration
  downgrade from silently restoring bearer-only access.
- `optional`: migration mode. Unbound Workers may continue bearer-only access.
  Re-registering through verified mTLS binds the presented certificate and
  rotates the bearer token; that Worker can no longer downgrade.
- `required`: every registration and Worker request requires a verified client
  certificate. An unbound record cannot use its bearer token.

`ICHECK_WORKER_MTLS_TRUSTED_PROXIES` is a comma-separated IP/CIDR allowlist for
the TLS terminators permitted to assert certificate identity. It is not a list
of Worker networks. Production should normally contain only the loopback or
private addresses used by the dedicated proxy tier.

## TLS proxy contract

The ASGI application deliberately does not trust public request headers. The
TLS proxy must:

- terminate TLS 1.2 or newer and verify the client chain against the dedicated
  Worker CA, including the deployment's revocation policy;
- remove every inbound `X-iCheck-Client-Cert-*` header before adding its own;
- send the application exactly these values:
  - `X-iCheck-Client-Cert-Verified: SUCCESS`;
  - `X-iCheck-Client-Cert-SHA256`: 64 lowercase hexadecimal SHA-256 digits
    (colon separators are also accepted);
  - `X-iCheck-Client-Cert-Subject`: the verified subject string;
  - `X-iCheck-Client-Cert-Serial`: the verified serial representation;
  - `X-iCheck-Client-Cert-Not-After`: an offset-aware RFC 3339 timestamp;
- connect from an address in `ICHECK_WORKER_MTLS_TRUSTED_PROXIES`;
- keep Uvicorn private. The supplied systemd unit binds it to `127.0.0.1`.

The supplied Uvicorn unit disables generic proxy-header rewriting so
`request.client` remains the raw proxy socket address used by this trust check.
Do not re-enable `--proxy-headers`; client attribution needed elsewhere must use
a separately validated header and must never drive this certificate trust
decision.

Do not map an SHA-1 fingerprint variable into the SHA-256 header. A proxy that
cannot derive all five fields must use a small authenticated identity adapter
or a proxy extension; it must not copy values supplied by the Worker.

## Worker client configuration

The Collector control-plane client disables redirects, verifies the server
hostname, requires TLS 1.2 or newer, and supports:

```text
ICHECK_WORKER_TLS_CA_FILE=/etc/icheck/pki/worker-ca.pem
ICHECK_WORKER_TLS_CERT_FILE=/etc/icheck/pki/collector.pem
ICHECK_WORKER_TLS_KEY_FILE=/etc/icheck/secrets/collector.key
ICHECK_WORKER_TLS_KEY_PASSWORD_FILE=/etc/icheck/secrets/collector-key-password
```

The certificate and CA are not secret. All TLS paths must be absolute. The
private key and optional password file must be regular files with no group or
other permission bits (normally mode `0600`). The password file is optional for
an unencrypted protected-path key. TLS files are rejected for an HTTP
control-plane URL.

The packaged Agent Worker now uses the same hardened HTTPS client for
registration, heartbeat/drain, execution claim, lease renewal, cancellation
observation, bounded graph progress, completion, graph checkpoints, reasoning,
Tool execution, and nested approval/MCP interrupts. Its bearer token, client
certificate, execution ownership, and lease token are therefore enforced on
every `icheck.agent-runtime/v1` operation. The remote Agent Worker has no
database credentials. Workflow outbox reconciliation runs in a separate,
region-pinned control-plane worker. See `agent-runtime-protocol.md`.

## Binding, rotation, and recovery

Initial binding occurs only during successful registration. Re-registration
of a bound Worker must present its active certificate (or an eligible staged
certificate) and always rotates the bearer token.

An `auth.admin` principal manages rotation with optimistic revisions:

```text
POST /api/v1/collector-workers/{id}/mtls-rotation
POST /api/v1/collector-workers/{id}/mtls-rotation/cancel
POST /api/v1/collector-workers/{id}/mtls-revoke

POST /api/v1/agent/workers/{id}/mtls-rotation
POST /api/v1/agent/workers/{id}/mtls-rotation/cancel
POST /api/v1/agent/workers/{id}/mtls-revoke
```

Staging accepts exactly one non-CA PEM certificate, requires client-auth EKU
when EKU is present, rejects expiry and lifetimes over five years, and permits
activation at most 30 days ahead. The first request authenticated by the
eligible staged certificate atomically promotes it; the previous certificate
then fails. Cancellation removes only the staged identity. Emergency
revocation removes active and staged identities, takes the Worker offline, and
invalidates its bearer token. Recovery requires a fresh registration token and
certificate.

Raw certificates, subjects, serials, keys, and reason text are not stored in
audit events. The database retains certificate/subject/serial hashes, validity
windows, revision, and hashed reasons. Relevant event types are:

```text
collector.worker.mtls_bound
collector.worker.mtls_rotation_staged
collector.worker.mtls_rotation_cancelled
collector.worker.mtls_promoted
collector.worker.mtls_revoked
```

Agent events use the same suffixes under `agent.worker.*`.

## Production migration

1. Issue unique client-auth certificates from a dedicated Worker CA.
2. Deploy the trusted TLS proxy and confirm that it strips spoofed identity
   headers. Keep the control plane in `optional` mode.
3. Install the CA, certificate, and protected key files on each Collector;
   restart it so re-registration binds the certificate and rotates its token.
4. Confirm every distributed Worker exposes a current fingerprint and a future
   expiry, then change the control plane to `required` and restart it.
5. Exercise normal traffic, staged cutover, cancellation, emergency revocation,
   expired-certificate denial, untrusted-proxy denial, and proxy bypass denial.

The repository supplies the receiving contract and Collector TLS client. It
does not create a production CA, choose enterprise revocation policy, or deploy
a TLS proxy automatically. Those are environment authority decisions and are
lab/production acceptance gates.
