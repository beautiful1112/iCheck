# Prometheus and SNMP Exporter live rollout

## Deployment status

The host-local, non-container installation was completed on 2026-09-18 on the
representative Ubuntu 24.04 LTS `linux-amd64` host `zhao`. Prometheus and SNMP
Exporter are installed as independent systemd services. This completes the
service installation portion of M1; real-device, remote-write, and scale
acceptance remain open before the deployment can be called production-ready.

Installed baseline:

- Prometheus `3.13.3` LTS, SHA-256
  `b349c732d8a853e657d0e7ae1bbad4d11b586615fb65fdc59d896b9f869c001e`.
- SNMP Exporter `0.30.1`, SHA-256
  `026aac4e23447ed593a783eccab9089cd41d77d17c9d2a0ab84398e45a0bb93e`.
- Dedicated non-login service account: `icheck`.
- Binaries: `/opt/icheck/bin`.
- Prometheus configuration: `/etc/icheck/prometheus`.
- SNMP Exporter configuration: `/etc/icheck/snmp/snmp.yml`.
- Prometheus state: `/var/lib/icheck/prometheus`, owned by `icheck:icheck`.
- Prometheus listener: `127.0.0.1:9090`.
- SNMP Exporter listener: `127.0.0.1:9116`.
- Prometheus retention limits: 15 days and 10 GB.
- Services: `icheck-prometheus.service` and
  `icheck-snmp-exporter.service`, both enabled at boot.

## Remaining production inputs

- Initial SNMP target CIDRs, generated modules, and exporter-side auth names.
- Firewall paths from Prometheus to SNMP Exporter and network devices.
- Optional remote-write endpoint plus an external credential reference.
- Representative target counts, scrape intervals, and series-cardinality
  budgets for capacity testing.

No SNMP community, SNMPv3 password, or remote-write token belongs in this
repository or an AI conversation.

## Installation sequence

1. Verify architecture, disk capacity, time synchronization, DNS, firewall, and
   service account prerequisites.
2. Download pinned release artifacts from the official projects and verify
   checksums before placing binaries under `/opt/icheck/bin`.
3. Install generated SNMP modules and protected auth configuration under
   `/etc/icheck/snmp`; secrets use a root-readable external environment or
   secret-provider file.
4. Install Prometheus configuration and file-discovery targets under
   `/etc/icheck/prometheus` and create `/var/lib/icheck/prometheus`.
5. Validate configuration, install the supplied systemd units, daemon-reload,
   enable, and start both services.
6. Register the Prometheus query endpoint in iCheck and run its health check.
7. Verify a real SNMP target, scrape freshness, timeout behavior, label and
   series cardinality, restart recovery, and optional remote-write delivery.

## Acceptance evidence

Verified on 2026-09-18:

- Official release archive checksums matched the pinned values above.
- `promtool check config` passed as the unprivileged `icheck` account.
- SNMP Exporter configuration dry-run passed as the `icheck` account.
- `systemd-analyze verify` passed for both installed service units.
- Both services reported `active` and `enabled`.
- Prometheus `/-/healthy` and `/-/ready` returned success.
- SNMP Exporter `/metrics` returned HTTP 200.
- The bounded `vector(1)` query returned a successful vector result.
- Prometheus reported `up == 1` for its own target and the SNMP Exporter target.
- After restarting both services, both returned to `active`; readiness and
  exporter metrics checks passed again.
- No warning-or-higher journal entries were present during the validation
  window.

Still required:

- At least one successful real-device SNMP scrape and one intentionally denied
  target.
- Device scrape freshness, duration, sample count, timeout, label, and series
  cardinality evidence.
- Remote-write queue and delivery evidence when remote storage is enabled.
- Rollback testing against a previously pinned binary/configuration set.

The checked-in systemd and configuration files now match a working host-local
deployment. This is deployment evidence, not yet a production-capacity claim.
The SNMP target file is intentionally empty until approved target addresses and
secret-backed authentication are supplied.
