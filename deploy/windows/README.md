# Windows collection reference

This directory contains reviewed configuration inputs, not evidence of a live
installation.

Use the signed `windows_exporter` MSI from the official project release and pin
the approved version and SHA-256 in the environment deployment repository. The
recommended baseline enables only CPU, disk, memory, network, OS, selected
service, and system collectors. Restrict TCP/9182 at the Windows Firewall to the
site Prometheus addresses.

Continuous path:

```text
Prometheus -> windows_exporter:9182/metrics -> Windows performance data
Prometheus -> remote_write -> scalable metrics backend
```

On-demand diagnostics use the versioned `builtin-psrp-cim-diagnostics`
artifact. Create an `on_demand` deployment with a deployment-scoped credential
profile reference, then call its trigger endpoint. The adapter accepts only the
fixed read-only operations published in that artifact, requires WinRM TLS, and
fails closed until an external credential-provider-backed executor is attached
to the worker. Arbitrary PowerShell is not accepted.
