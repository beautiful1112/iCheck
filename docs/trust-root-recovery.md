# Emergency organization trust-root recovery

iCheck uses emergency root re-anchor only when the currently pinned
organization root cannot participate in normal dual-signed rotation. It is a
pre-authorized, delayed, externally witnessed recovery ceremony, not an
administrator override.

The dedicated Studio surface is:

    UI   /studio/catalog/trust/recovery
    POST /api/v1/organization-trust/domains/{id}/recovery-policy-statements
    POST /api/v1/organization-trust/domains/{id}/recovery-policies
    GET  /api/v1/organization-trust/recovery-policies
    GET  /api/v1/organization-trust/recovery-policies/{id}/export
    POST /api/v1/organization-trust/domains/{id}/recovery-policy-statements/sign
    POST /api/v1/organization-trust/domains/{id}/root-reanchor-statements
    POST /api/v1/organization-trust/domains/{id}/root-reanchor-statements/sign
    POST /api/v1/organization-trust/domains/{id}/root-reanchors/preview
    POST /api/v1/organization-trust/domains/{id}/root-reanchors
    GET  /api/v1/organization-trust/root-reanchors
    GET  /api/v1/organization-trust/root-reanchors/{id}/export
    POST /api/v1/organization-trust/root-reanchors/{id}/execute
    POST /api/v1/organization-trust/root-reanchors/{id}/cancel
    POST /api/v1/organization-trust/recovery-signing/providers
    GET  /api/v1/organization-trust/recovery-signing/providers
    POST /api/v1/organization-trust/recovery-signing/providers/{id}/state
    PUT  /api/v1/organization-trust/recovery-signing/providers/{id}/tls
    GET  /api/v1/organization-trust/recovery-signing/events

## Pre-incident authorization

Recovery trustees use locally pinned Ed25519 public keys with the dedicated
`trust_recovery` purpose. This purpose is opt-in and cannot be distributed by
an organization trust bundle. iCheck never receives a trustee or root private
key.

While the trust domain and current root are still usable, iCheck generates
`icheck.organization-trust-recovery-policy/v1`. The statement binds:

- organization and exact local trust-domain identity;
- monotonically increasing policy version;
- current trust-bundle sequence and digest;
- current root fingerprint;
- two to eight sorted trustee fingerprints;
- a two-to-eight approval quorum that cannot exceed the trustee count;
- a mandatory delay of one to 72 hours; and
- an issue/expiry window of at most 24 hours.

Policy versions advance from the latest retained policy, including one
retired by planned root rotation or completed emergency recovery. The new
root can therefore authorize the next version without reusing sealed history.

The current offline root signs the digest in
`icheck.organization-trust-recovery-policy.signed/v1`. Acceptance rechecks the
domain, bundle head, exact local trustee keys and purposes, root signature,
time window, and version while holding the domain lock. The immutable policy
and its public signed envelope are added to audit and capability transparency
in the same transaction. Policy admission retains the latest recorded policy,
any active policy and the selected root/trustee keys through a PostgreSQL
`READ COMMITTED` transaction, then rechecks key usability, domain binding and signed expiry
immediately before commit. If that final check fails, both the new record and
any attempted retirement of the old policy roll back. An exact signed-envelope
retry returns the original sealed outcome, even after subsequent domain
containment; a conflicting envelope or request reason cannot reuse it. A later
root-signed policy supersedes the old policy.

Any planned dual-signed root rotation retires active recovery policies. A
completed emergency recovery consumes its policy as well. The newly pinned
root must explicitly authorize the next policy after normal service is
restored; authority signed by an earlier root never survives a root change.

## External HSM/KMS signing gateway

The UI and API retain the air-gapped signed-file workflow and add an optional
online signing boundary. iCheck registers an `hsm_gateway` or `kms_gateway`
against an already pinned local public key. Registration binds the gateway
URL, opaque provider key reference, public-key fingerprint, application
credential profile, TLS mode, and TLS credential references. The HTTPS host
must be explicitly allowed by `ICHECK_RECOVERY_SIGNING_ALLOWED_HOSTS`.

Application bearer tokens, custom CAs, and mTLS identities use server-side
credential profiles whose adapter allowlist includes
`trust_recovery_signing`. Worker-scoped profiles are rejected. Secret values
are resolved only for the outbound request and are not copied into the
provider or evidence records. TLS references rotate with an optimistic
revision check. Disabling a provider is an explicit audited break-glass
operation.

For each signature iCheck sends a bounded JSON request containing only:

- the request and statement digests;
- document and signed-envelope format versions;
- the opaque provider key reference;
- the provider ID; and
- the base64 encoding of `<signed-format>\n<statement-digest>`.

The gateway returns the request digest and a normal Ed25519 artifact signature.
iCheck rejects redirects, non-HTTPS or non-allowlisted destinations,
oversized/non-JSON responses, request-digest mismatches, wrong signing keys,
wrong key purposes, disabled/revoked/expired local keys, and invalid
signatures. The returned signature is always reverified locally; a gateway
cannot bypass the ordinary recovery-policy or root-reanchor validator.

Each accepted response creates an immutable, namespace-scoped signing event
with the public signature snapshot, signature/request/response hashes, public
key binding, actor, and TLS evidence. It never stores credentials or private
keys. The request digest is an idempotency key, so an exact retry reuses the
verified public signature without calling the HSM/KMS again. Policy assembly
requires a provider bound to the current root. Re-anchor assembly requires a
provider bound to the selected next root plus distinct providers backed by the
pre-authorized trustee quorum.

## Incident ceremony

The trust domain must first be disabled. This immediately makes all of its
distributed keys unusable while retaining provenance. A new locally pinned
`trust_bundle` public root is selected, but it is not trusted as the domain
authority yet.

Before iCheck will generate a recovery statement, the current transparency
head must have live external witness quorum and must include the active
recovery policy plus the domain-disable event. The generated
`icheck.organization-trust-root-reanchor/v1` statement binds:

- organization, domain, active policy version and policy digest;
- a unique ceremony ID;
- current trust-bundle sequence and digest;
- current and next root fingerprints;
- exact witnessed transparency log ID, epoch, sequence, and head; and
- an issue/expiry window longer than the configured delay and no longer than
  168 hours.

The next root proves possession and at least the configured number of
pre-authorized trustees sign the same digest in
`icheck.organization-trust-root-reanchor.signed/v1`. Preview verifies every
signature, purpose, policy binding, domain/head binding, time boundary, and
live witness checkpoint without changing state.

Proposal persists the exact public envelope, signature hashes and trustee
evidence, sets the earliest execution time, and advances transparency. The
proposal cannot execute until all of the following are true:

1. the one-to-72-hour delay has elapsed;
2. a different authenticated administrator performs execution;
3. the domain remains disabled and its root/bundle state is unchanged;
4. the policy, next root, and every trustee signature remain usable;
5. a new live-quorum checkpoint includes the proposal; and
6. the signed ceremony has not expired.

Execution changes only the pinned authority. It does not enable the domain,
reactivate a distributed key, import a trust bundle, or erase the old public
root. The execution itself advances transparency. Re-enabling the domain is
blocked until yet another live-quorum checkpoint includes that execution.
After the initial witnessed incident head used to create the ceremony, this
adds two more independent witness boundaries: one after proposal and one before
restored authority can affect runtime signature verification.

Restoration now locks the exact post-execution checkpoint, its witness policy,
selected signed attestations, witness pins and signer keys before the domain
is enabled. It verifies the log head has not advanced while acquiring those
locks and rechecks witness quorum, key usability and expiry immediately
before the enablement/audit/transparency commit. A late failure leaves the
domain disabled. Repeating a completed enablement returns its recorded state
without appending another event.

A pending proposal can be cancelled. Cancellation is also appended to
transparency, so a replacement ceremony requires a newly witnessed head.
Exact ceremony and statement digests are unique and cannot be replayed.

## Recorded-authority transaction boundary

Root-reanchor proposal, execution and cancellation now acquire the disabled
trust domain before the ceremony row, so incident containment and recovery
share one database lock order. Proposal and execution retain the active
policy, selected successor/trustee keys, witness configuration and checkpoint
offer while appending transparency evidence and committing the outcome. They
recheck the signed statement, current witness quorum and authority lifetime
after acquiring those locks and immediately before commit. A failed final
check rolls back the pin, policy retirement and history together. These
locking mutations require a PostgreSQL `READ COMMITTED` transaction with
autocommit disabled; unsupported transaction modes fail closed.

Migration `q1s3u5w7y9a2` seals recorded policy and ceremony proof fields with
database update/delete guards. Only a one-way policy retirement or a
pending-to-terminal ceremony transition with the required outcome fields is
allowed. A populated or RLS-hidden downgrade is refused. This prevents
ordinary runtime SQL from changing signed proof, deadline or completed
history, but the guard alone cannot authenticate an actor that supplies every
terminal field. It does not make the database tamper-proof against its owner
or prove that witnesses are operated independently. Other publisher/trust
mutation paths and live independent recovery drills remain separate
acceptance work.

Migration `r2t4v6x8z0b3` makes recorded checkpoint offers and signed witness
attestations append-only for ordinary database roles. A populated or
RLS-hidden downgrade is refused, so a production migration cannot silently
remove that guard from retained public proof. This does not protect against
a database owner or prove that distinct pins correspond to independent
operators or hosting.

## Remaining production integration

The signed file-transfer and complete local lifecycle are implemented.
Credential-backed automated witness delivery is implemented by the separate
ecosystem transport worker, including endpoint mTLS and certificate rotation.
Incident paging, broader organization identity federation, vendor-specific
gateway deployment/acceptance, and live multi-region recovery drills remain
deployment and ecosystem work. The generic, private-key-free HSM/KMS signing
contract, local verification, TLS/credential boundary, quorum assembly, and
immutable evidence lifecycle are implemented.
