# Native one-command installer

The r19.28 installer packages the N1–N3 application with automated fresh-host
setup. It runs native Linux processes managed by systemd. Docker is
neither installed nor required. This is a single-node engineering prerelease,
not a production-readiness or thousand-device capacity claim.

## Supported host

- A dedicated, freshly installed Ubuntu 24.04 x86_64 server with systemd.
- At least 3 GiB RAM and 10 GiB free root filesystem space for evaluation.
  Allow additional space for monitored data and backups.
- Root/sudo access, a server IPv4 address, and approved private monitoring CIDRs.
- Outbound HTTPS for the pinned Node.js, Prometheus, SNMP Exporter, Grafana and
  Alertmanager archives, plus access to the configured signed Ubuntu repositories.
- No pre-existing iCheck, PostgreSQL or nginx installation. Existing installations
  and partially completed installs are deliberately refused, not overwritten.

The application, compiled frontend and pinned Python wheels are embedded.
Operating-system packages and the additional services are downloaded. This is
an **online installer**, not a completely offline appliance image.

## Download, verify, install

Download `icheck-0.1.0-preview.r19.28-ubuntu24.04-amd64.run` and `SHA256SUMS`
from the GitHub prerelease Assets section. The automatically generated source
archives are not installers. If the repository is private, first authenticate
to GitHub to download its assets; no GitHub token is needed on the target host.

Verify the downloaded file:

```bash
sha256sum --check --ignore-missing SHA256SUMS
bash icheck-0.1.0-preview.r19.28-ubuntu24.04-amd64.run --check
```

Then start the single installation command:

```bash
sudo bash icheck-0.1.0-preview.r19.28-ubuntu24.04-amd64.run
```

Answer the prompts for the server address, approved monitoring network(s), and
an administrator passphrase. The installer provisions dependencies, service
accounts, database roles and schema, encryption custody, HTTPS, worker mTLS,
the monitoring integrations, and native services. No source compilation is
required. It prints the login URL after verification.

Only the dedicated, root-custodied migration database role can bypass row-level
security for cross-namespace migrations. API and internal worker database roles
are non-superuser runtime roles without that privilege. Collector and Agent
Workers receive no database credentials.

The explicit network bounds permit later user-approved enrollment; they do not
scan, enroll or test any device during installation. The initial site is `LAB`.
Use the GUI to add devices, credentials and AI providers. No AI/search provider
is preconfigured, and automatic AI investigation remains off.

SNMP Exporter requires an auth entry to start. Setup generates an unconfigured,
random per-install community for that requirement, not a shared `public`
community or a credential for any device. Add actual SNMP credentials through
the GUI; managed collection uses isolated credential-bound exporter runs.

## First sign-in

- iCheck username: **admin**.
- iCheck password: the **15-256-character passphrase you entered** during setup.
- There is no shared default password. Existing developer credentials are not shipped.
- Grafana has a separate `admin` account and a randomly generated password.
  Retrieve it on the installed host with:

```bash
sudo cat /etc/icheck-grafana/initial-admin-password
```

Never paste credentials into a GitHub issue. Configure AI provider keys and
device credentials through their protected GUI forms after signing in.

## HTTPS and network exposure

The installer creates a local evaluation CA and a server certificate valid for
90 days. Verify the CA fingerprint through a trusted channel, then trust
`/etc/icheck-preview-ingress/preview-ca.pem` on your own client. Do not disable
browser TLS checks as a deployment solution. Worker mTLS is loopback-only.

Display the CA fingerprint directly on the server:

```bash
sudo openssl x509 -in /etc/icheck-preview-ingress/preview-ca.pem -noout -fingerprint -sha256
```

Only the selected server address and loopback bind the HTTPS listener on 8443.
PostgreSQL, application internals and monitoring services remain local. The
installer does not open a firewall, change DNS, configure a router, or expose
the server to the Internet. A public deployment requires an appropriate trusted
certificate, reviewed firewall policy and separate production acceptance.

Service API tokens and the Grafana integration token have a 30-day evaluation
lifetime; certificates and tokens require operator-managed renewal. This first
installer does not implement automatic rotation or a high-availability setup.

## Automated installation

Automation may supply `--server-ip`, repeated `--monitor-cidr`, `--yes`, and
`--password-file /root/private-admin-password`. The password file must be a
root-owned regular file under protected root-owned directories, with mode `0600`,
no symlink/hardlink, and at most 1024
bytes. It must contain a valid passphrase. Never put a password on the command
line or in an environment variable. Remove the input file securely after use.
The installer does not retain the plaintext iCheck password in its own state.

## Status and failure handling

```bash
sudo systemctl status icheck-control-plane icheck-frontend icheck-collector
sudo systemctl status icheck-prometheus icheck-alertmanager grafana-server
sudo cat /var/lib/icheck-installer/installed.json
```

Success is recorded only after database, service, authenticated API and integration
checks. A failed installation retains its partial state and root-only diagnostics
at `/var/lib/icheck-installer/private-diagnostics.log`. These may contain private
details and must not be uploaded without redaction.

Do not blindly rerun after a failure or delete database/configuration directories.
Investigate the failed stage, or discard only a dedicated disposable test host
and begin again. This release has no destructive automatic rollback or uninstall.
It is a first-install tool, not an in-place upgrade command; use the documented
[native upgrade and backup procedure](engineering-preview-installation.md) for
existing servers. Back up SQL, configuration, encryption custody and monitoring
data before upgrades. Do not run this installer on a server already hosting iCheck.

## Verification boundary

See the prerelease's clean-host acceptance record for the actual tested image,
checks and any remaining limitations. A successful installation does not verify
real device reachability, notification delivery, model quality or fleet capacity.
Those require your environment and separately approved tests.

The installer retains its reviewed payload under the root-only directory printed
at completion. On an otherwise unchanged fresh installation, an administrator
can run `installer/verify_native_installation.py` from that directory with
`sudo /opt/icheck/.venv/bin/python -I`. It checks empty user inventories, native
services, restricted database roles, worker registration, authenticated API
integration and complete frontend/Grafana JavaScript downloads. The optional
`--password-file` verifies password login using a protected local test input.
Do not interpret an empty-inventory check as appropriate after adding real devices.

## Rebuilding the installer

Maintainers build from the checked-in source and the hash-pinned, published
r19.28 Linux amd64 application archive:

```bash
python3 deploy/build_native_installer.py \
  --application /absolute/path/icheck-engineering-preview-0-1-0-r19-28-public-linux-amd64.tar.gz \
  --source "$PWD" \
  --out /absolute/new/path/icheck-0.1.0-preview.r19.28-ubuntu24.04-amd64.run
```

The builder refuses an unqualified application archive, linked or unexpected
archive entries, and existing output files. Publish a newly built file only
after testing that exact file from a fresh supported OS image, rebooting and
rechecking, scanning the source/payload for secrets, and recording its checksum.
