# SNMP module generation and legacy attestation

## Native engineering preview source

Deployment update, 13 October: r19.1 now has the protected generator, local MIB
library and isolated Unix-socket broker on this server. Actual API-UID generation
and exporter parser validation passed for standard uptime; the broker is running
and rejects non-API peers. No target, monitoring approval or shared test module
was installed by these checks. Real model/target/fresh-sample acceptance remains
pending. See the deployment receipt (private development evidence; not distributed).
Source qualification notes below describe their earlier checkpoints.

The native source compiles real standard and vendor MIBs into a reviewed,
versioned exporter module. It does not require a separate signed attestation
service for the engineering preview. The older signed Collector/canary path
below remains available; its publication gates and history are unchanged.

`snmp_generator.py` provides a small symbolic profile catalog for standard
network metrics and Cisco CPU utilization. Unsupported profile intents are
returned explicitly. Custom vendor input uses the same compiler: select up to
32 module-qualified readable leaf symbols and supply that MIB family plus its
imports. Studio now uses the shared `icheck.monitoring-template/v1` Collector
contract for SNMP and HTTP rather than a separate designer. The model cannot supply numeric OIDs, exporter YAML, shell commands or
credentials. Net-SNMP, through the actual upstream generator, resolves OIDs,
types, inherited table indexes and enumerations.

Native qualification used the version 0.30.1 generator built from the upstream
release commit, real SNMPv2-MIB/IF-MIB and Cisco's CISCO-PROCESS-MIB with their
dependencies, and the installed version 0.30.1 exporter. Standard uptime,
interface status and 64-bit traffic counters, plus Cisco CPU time-window
gauges, compiled and passed the exporter's `--dry-run` parser. Missing imports
failed instead of producing a canned module. The tests installed candidates
only into temporary catalogs; they made no device requests.
An additional loopback SNMP fixture checks the compiled/installed uptime module
through a real native exporter. `sysUpTime` retains raw TimeTicks (hundredths of
a second); a dashboard must divide by 100 to display seconds. A separate Studio
acceptance now also exercises an actual leased metric test, protected credential
resolution, reviewed enrollment, the existing gateway and a temporary native
Prometheus. It stored `sysUpTime=12345` with the exact enrollment labels and
passed original-sample freshness checks. These are loopback fixtures, not a
qualification of the user's lab devices.

Compilation returns `icheck.snmp-compiled-module/v1`, binding the generator
binary/source version, normalized MIB hashes, selected symbols, collection
bounds, secret-free YAML and expected metric names/OIDs/types. Native commands
have deadlines, limited diagnostic output, no shell or ambient user SNMP
configuration, and do not return raw MIB diagnostics. The output explicitly
says that no live target has been tested and continuous collection is disabled.
Only reviewed leaves may be collected; a broader subtree walk is rejected.

The upstream generator has no `--version` flag. A protected runtime manifest
therefore binds its declared source version to its executable SHA-256. The
native manifest loader requires root-owned, non-writable files and ancestry;
the installed exporter must report the same version. The legacy attestor now
accepts `--generator-manifest` for this case too. Its service template and
example environment refer to `/etc/icheck-workers/snmp-runtime/generator.json`:

```json
{
  "format": "icheck.snmp-generator-runtime/v1",
  "generator_binary": "/opt/icheck/bin/generator",
  "generator_version": "0.30.1",
  "generator_sha256": "<verified-installed-binary-sha256>",
  "exporter_binary": "/opt/icheck/bin/snmp_exporter"
}
```

`snmp_module_install.py` previews and, after explicit confirmation, atomically
appends the exact candidate to a module catalog. It checks the catalog digest
again after native parser validation, preserves existing modules and numeric
enum keys, refuses to overwrite an installed version, and serializes installers.
Changed generation inputs receive a new module name, so old assignments remain
valid and can be used for rollback. Identical installation is idempotent.
The fixed-path native CLI is deployment-only and must run with the installed
isolated interpreter (`python -I -m icheck.snmp_module_install`), not a
user-writable source checkout. Installation does not restart services, assign targets,
publish a capability or approve collection.

At source qualification the generator was a private build output, not yet a
protected installed runtime. Studio now connects conversation, native compilation,
module review/installation, selected-target metric test, reviewed publish/enroll,
fresh per-metric Prometheus proof and native Grafana proposal. The GUI uses the
same guided monitoring panel for both protocols. Raw MIB sources remain in the
server's authoring context; only bounded symbol metadata goes to AI, browser
responses and replay snapshots. Edits create immutable versions; history restores
a prior compiled definition as a new version without editing source files.

### Protected module installation service

The new source service template `icheck-snmp-module-installer.service` runs the
installed isolated interpreter as root with no TCP listener. A bounded Unix
socket at `/run/icheck-snmp-installer/install.sock` accepts only the local API
service UID (`icheck`). The API also requires a human operator with global
`capabilities.manage`, the exact artifact version and a current catalog preview.
The broker writes only `/etc/icheck-workers/snmp-runtime/modules.yml`; requests
cannot select paths, commands, auth profiles or service actions. Lost replies
are reconciled by inspecting the immutable named module rather than blindly
repeating a write. The service is now installed by the approved native deployment;
no general sudo grant was given to the API.

An approved deployment must provision the verified generator and manifest above,
standard MIB dependencies at `/opt/icheck/snmp-mibs` (or a protected configured
`ICHECK_SNMP_GENERATOR_MIB_DIRECTORY`), and the installed broker/service template.
Vendor bundles may be uploaded in Studio, including complete dependencies; an
uploaded dependency replaces a default only in that immutable authoring recipe,
not in the server's shared library. Do not redistribute vendor MIBs without the
required permission. Keep the runtime directory root-owned, group `icheck`,
mode 0750 and its socket mode 0660.

The existing gateway profile must explicitly opt into
`allow_installed_snmp_templates=true` before accepting generated module names.
This exception still requires managed credentials and an exact installed module
digest. Sites, CIDRs, ports, credential scope and finite approval bounds remain
unchanged. Existing SNMP/Windows enrollment fingerprints are preserved; new SNMP
templates additionally bind credential revisions and are withdrawn after a
credential change. Identity-only tests cannot satisfy template enablement.

Before each test and scrape, the worker/gateway validates the installed module;
post-I/O checks fence configuration or authority changes. Every declared metric
must have an actual finite sample. Native template preflight is bounded to
20,000 selected samples and 2 MB; legacy collector limits remain unchanged.
Freshness checks require the exact current enrollment, healthy scrape and each
original raw sample timestamp after approval. Grafana proposals show counters as
rates and uptime in seconds and retain the existing confirmation/rollback path.

Back up the module catalog with existing protected configuration backups. A
rollback reassigns a reviewed earlier template/module version and retests/reapproves
that target; it does not delete history or overwrite a module in use. Uninstalling
the broker should disable/stop that service and remove its socket/runtime directory
only. Preserve the module catalog, enrolled targets, credentials and backups until
their consumers are explicitly withdrawn.

Protected runtime/broker provisioning, the paired backend/GUI release and live
model/device/Grafana engineer acceptance remain outstanding. Subtree selection, lookups,
overrides and notification objects are not supported by this first leaf contract;
this template journey currently uses managed SNMPv2c credentials. Existing external
SNMP paths are retained. Device/vendor availability still needs a real selected target test.
See the source qualification (private development evidence; not distributed).

Upstream references: [native generator and MIB instructions](https://github.com/prometheus/snmp_exporter/tree/v0.30.1/generator),
[Cisco MIB sources](https://github.com/cisco/cisco-mibs/tree/f55dc443daff58dfc86a764047ded2248bb94e12/v2),
and [Net-SNMP standard MIB sources](https://github.com/net-snmp/net-snmp/tree/v5.9/mibs).

## Legacy signed Collector boundary

A MIB-derived proposal is never unlocked or edited in place. iCheck accepts a
separate, signed external attestation and creates a new immutable Collector
version:

```text
validated MIB proposal (publication permanently denied)
        ↓ exact proposal/MIB/generator-module hashes
hardened external generator + module installation + live-device tests
        ↓ Ed25519 signed icheck.snmp-exporter-attestation/v1
validated attested version (direct publication denied)
        ↓ ordinary iCheck Collector canary
passed canary + still-valid attestor key/evidence
        ↓ explicit human canary promotion
published deployable version
```

The control plane implements the signed-envelope verification, immutable
attestation ledger, deployable-version compiler, and canary-only publication
gate. The repository also provides the separate `icheck-snmp-attestor` one-shot
runner and a hardened systemd job template. The current host has Prometheus and
SNMP Exporter installed; it does not yet have the SNMP Exporter `generator`
binary in protected runtime custody or an attestor key/OS identity, so no production
attestation has been issued.

## Signed evidence contract

The signed statement binds all of these values:

- exact proposal Artifact/version/content hash;
- original MIB document hash and deterministic generator-module hash;
- exporter module name;
- generator name/version/binary hash;
- generated and installed module-fragment hashes, which must be identical;
- exporter version/binary hash and a stable installation ID;
- SHA-256 values for the tested target and auth-module name, never their raw
  values;
- at least three successful, zero-timeout scrapes;
- bounded sample, series, label-name, and maximum-duration counts;
- an external evidence-bundle hash; and
- test/issue/expiry timestamps plus a one-time nonce.

Evidence may be at most 24 hours old when signed. An attestation may live for at
most seven days. Future timestamps, expired envelopes, reused nonces/digests,
configuration drift, proposal drift, signature failure, or an unauthorized key
fail closed. Audit stores hashes and bounded counts, not MIB text, target,
auth-module name, credentials, generated configuration, or scrape payloads.

## Trust and signature

The attestor uses a dedicated Ed25519 key registered with only the
`snmp_exporter_attestation` purpose. The signature message is domain separated:

```text
icheck.snmp-exporter-attestation.signed/v1\n<DIGEST_SHA256>
```

The control plane verifies the key purpose, validity interval, revocation
state, optional distributed trust-domain state, digest, base64 signature, and
Ed25519 signature before it creates any deployable version. Key usability and
attestation expiry are checked again during canary promotion. Revoking the key
therefore blocks an already accepted candidate that has not yet been promoted.

## API and publication behavior

```text
GET  /api/v1/snmp-exporter-attestations/proposal-inputs/{proposal_version_id}
POST /api/v1/snmp-exporter-attestations
GET  /api/v1/snmp-exporter-attestations
GET  /api/v1/snmp-exporter-attestations/{attestation_id}
```

Acceptance requires global `capabilities.manage`; reads require global
`capabilities.read`. A successful POST creates
`icheck.snmp-exporter-attested/v1` on the same Artifact and validates it against
the local ledger row. Hand-authored or imported lookalike versions cannot pass
validation because they have no verified local attestation record.

The proposal-input endpoint exports the exact bounded JSON consumed by the
attestor. It revalidates the proposal contract when read, so an operator never
has to reconstruct hashes or generator instructions by hand. The raw MIB is
still supplied through the approved local staging channel and must match the
exported hash.

The resulting validation report says `canary_required=true` and
`publication_blocker=collector_canary_required`. The ordinary Artifact publish
endpoint rejects it. The operator must create a Collector canary with the real
site-local exporter target, approved auth-module name, worker scope, and health
thresholds. Only the internal promotion path for a passed canary can publish
the version.

## Implemented external runner

`icheck-snmp-attestor` performs one bounded run. It accepts absolute regular
files only, re-parses the staged MIB and compares its hash, invokes the pinned
generator without a shell and with a fixed environment/timeout, safe-parses the
generated and installed YAML, and requires the named installed module to equal
the generated module. It then performs three to ten allowlisted exporter
scrapes, parses Prometheus text, retains only hashes/counts/duration, hashes the
raw target and auth-module name, and signs the domain-separated statement with
a mode-0600 Ed25519 key. The output envelope is atomically replaced with mode
0600 when `--output-file` is used.

The runner deliberately does not rewrite the live SNMP Exporter configuration.
Installing/reloading a candidate remains a separately authorized site-local
operation; the attestor proves that the installed named module is byte-model
equivalent to fresh generator output. It also does not submit its result with a
long-lived API token. An authenticated operator or narrowly scoped transport
posts the signed envelope to the control plane.

The non-container deployment files are:

```text
deploy/systemd/icheck-snmp-attestor@.service
deploy/systemd/snmp-attestor.env.example
```

The operational sequence is:

1. Register the attestor public key with only
   `snmp_exporter_attestation` purpose.
2. Download the exact proposal input from the proposal-input API and stage the
   original MIB whose SHA-256 it names.
3. Build and checksum-pin the matching upstream generator, generate the
   candidate, review/install/reload it through the site's change path, and set
   the instance environment file.
4. Run `systemctl start icheck-snmp-attestor@<job>` and inspect the resulting
   mode-0600 envelope.
5. POST the envelope, run the normal Collector canary, and explicitly promote
   only after its health gate passes.

## Deployment requirements

The production attestor must:

1. run outside the API process on a hardened, least-privilege host;
2. receive the original MIB through an approved local staging channel and
   verify its hash against the proposal;
3. use a checksum-pinned SNMP Exporter generator and MIB dependency set;
4. install/reload the reviewed generated module through a separately governed
   site-local change and have the runner prove exact module equality;
5. query a real allowlisted device through the installed module at least three
   times, enforcing timeout and cardinality limits;
6. construct the bounded evidence statement from observed results, not user-
   supplied success flags;
7. protect its dedicated Ed25519 private key in a root-only file, HSM, or KMS;
   and
8. submit the signed envelope over authenticated control-plane transport.

Until the generator, OS identity/key, and service template are deployed and the
lab supplies a real SNMP device/auth configuration, the code path is automated-
acceptance complete but not live-device accepted.
