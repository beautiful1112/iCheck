# Linux and Windows exporter monitoring

The source preview connects Linux and Windows to the same Capability Studio
describe, preview, test and enable journey as SNMP and HTTP. Linux has a private
end-to-end check using real node_exporter host measurements and temporary native
Prometheus. Windows has wire fixtures, TLS/authentication and lifecycle checks;
a real Windows host remains unqualified. Both plugin implementations are deployed
in r19.2. The approved LAB node_exporter gateway profile and online Collector
metric-test capability are configured for explicit GUI testing.
The existing Windows gateway and Collector capabilities are unchanged.

## Engineer workflow

Install the native exporter on the monitored host using your normal host
administration procedure. iCheck does not execute model-generated installation
commands. Add a Linux exporter or Windows exporter connection through Assets,
then choose **Monitor a device or API** in Capability Studio. Describe the
measurements and choose the inferred monitoring technology if needed. HTTPS is
the default; an unauthenticated HTTP exporter needs an explicit protected
gateway exception. Default ports are 9100 for Linux and 9182 for Windows.

Select a saved account or bearer credential rather than placing a secret in the
conversation. Select the registered host after preview. **Test selected target**
binds the immutable version, host, port, selected collectors and credential
revision to the existing Collector lease. It must return every declared metric
with its expected type and a successful result for every selected collector.
A TCP connection, a published draft or exporter `up` is not metric-test proof.

Review the interval and explicitly **Enable tested template**. Publication and
enrollment commit together. The existing private gateway enforces its protected
site, IP/CIDR, port, collector, TLS-name and credential boundaries before and after
target I/O. Fresh Prometheus samples for each measurement and collector-health
series are required before the UI reports successful collection.

**Prepare native Grafana dashboard** produces a retained proposal with raw
measurements, counter rates, CPU busy percentage, measured memory utilization
and uptime. A separate explicit confirmation saves it in Grafana and returns
the saved URL. Dashboard filters do not enforce device-level isolation. Edit
the template through conversation; restoring a prior definition creates a new
version. Changed templates or credentials require a new target test and approval.

## Supported measurements

| Group | Linux collector | Windows collector | Measurements |
| --- | --- | --- | --- |
| CPU | cpu | cpu | CPU time counters, with busy utilization derived in Grafana |
| Memory | meminfo | memory | Available and total memory bytes; utilization derived from both |
| Disk | filesystem | logical_disk | Available/free and total filesystem bytes |
| Network | netdev | net | Receive and transmit byte counters |
| Uptime | stat and time | system | Boot timestamp; uptime derived from the clock |

The Linux representative check uses node_exporter 1.12.1. The Windows catalog
matches windows_exporter 0.31.9 documentation, not a runtime test on Windows.
Its memory group uses `windows_memory_available_bytes` and
`windows_memory_physical_total_bytes`, both documented by the
[Windows memory collector](https://github.com/prometheus-community/windows_exporter/blob/v0.31.9/docs/collector.memory.md).
Its uptime group uses `windows_system_boot_time_timestamp`, documented by the
[Windows system collector](https://github.com/prometheus-community/windows_exporter/blob/v0.31.9/docs/collector.system.md).
The selected host must actually enable the required collectors; another version
or missing collector fails the target test instead of inventing a measurement.

Routine Windows metrics use windows_exporter, not scheduled WMI execution.
The existing `psrp_cim` connector separately bounds its operations to
`operating_system`, `computer_system`, `logical_disks` and `network_adapters`.
It does not accept arbitrary WQL or PowerShell. Native Agent tools already
request these preconfigured checks and read their evidence; the source now
fences observation freshness, current target/configuration and request identity.
Live Windows/WinRM qualification remains outstanding.

## Bounded CIM checks through AI

Use a registered **WinRM HTTPS** connection and a protected Windows account.
Apply the published `builtin-psrp-cim-diagnostics` capability in Assets as an
**on-demand** deployment, with the desired fixed operation set. The existing
activation preview binds the device, port, worker selector and credential.
The Collector needs the optional PSRP transport, protected certificate trust
and explicit Windows target/port bounds. No remote check runs merely because
the template is published or the GUI is opened.

`windows.request_diagnostics` selects exactly that preconfigured operation set.
It retains the existing exact-argument human approval before queueing work;
repeating a queued/running request does not create another trigger. The Agent
cannot supply a host, credential, WQL query or PowerShell script.

Once the Collector completes, `windows.get_latest_diagnostics` can receive the
returned `deployment_id` and `requested_at` as its optional `not_before` input.
This distinguishes the requested check from an earlier successful run. Without
new qualifying observations, it returns no fresh evidence; queued/running state
is not query success. The investigation loop must report that gap or stay within
its existing time/step/cost limits rather than infer an answer from old data.

Evidence reads verify the current assignment/device identity, authorized
namespace and deployment, observation timestamps and selected operation set.
They reject old/future observations, changed/disabled bindings and fields with
nonfinite numbers. A bounded result can truncate extra rows, but an explicitly
requested operation must remain represented. Citations carry the actual
observation time and original run ID. Historical records remain available as
history; they are not relabeled as a fresh check after retargeting.

These APIs reuse the existing Tool Registry, Collector leases, approval and
LangGraph runtime. No separate CIM MCP server or additional Agent loop is needed.
The fixed transport and lifecycle are fixture-tested, not proof of a live
Windows session. Routine metric samples still go to Prometheus.

## Deployment and credentials

Deploy the paired application source and prior Grafana migration before enabling
these plugins. Provision native gateway profiles such as `preview-linux` and
`preview-windows` without broadening existing profiles or network approvals.
The Collector needs the matching `node_exporter` or `windows_exporter` capability
and an approved preflight target range. The gateway profile explicitly sets
`allowed_collectors`, `allowed_exporter_server_names` and, where approved,
`allow_insecure_exporter_http` or `allow_managed_exporter_credentials`.
No host services or allowlists were changed by the private acceptance checks.

HTTPS validates the certificate and connects to the approved literal IP, using
the configured certificate name without resolving a different destination.
The Collector uses host trust roots; a private CA must be installed in its
protected trust store. The gateway can use its protected `exporter_tls.ca_file`.
Redirects, ambient proxies and credentials over HTTP are not allowed.
Bodies are bounded to 2 MB and 20,000 samples, with finite values, distinct series,
bounded labels and no explicit timestamps or protected credential echoes.

New protected HTTP credentials can allow native exporters. Existing HTTP-only
profiles keep their original adapter list during rotation; they are not silently
expanded. Create a suitable new profile for an exporter. Secret leases are
no-store, restricted to the assigned worker or configured gateway service, and
revision-bound. Ordinary browser and Agent principals cannot resolve them.
Metrics stay in Prometheus; PostgreSQL retains template, inventory, approval,
credential and verification metadata, not routine exporter samples.

## Qualification and remaining work

The shared [exporter acceptance path](../tests/test_exporter_monitoring.py) covers
real HTTP/TLS fixtures, invalid/missing measurements, collector failure, protected
custody, secret handling, version changes/restoration, fresh sample timestamps,
native Grafana proposals and the private real-Linux/Prometheus path. The
qualification record (private development evidence; not distributed)
separates that evidence from deployment and lab acceptance.

The paired cutover and approved LAB gateway/Collector profiles are deployed.
Still required: live model-backed authoring, representative real Linux/Windows
exporter and WinRM checks, and saved target dashboards with fresh measurements.
Container, VMware and threshold-alert workflows are implemented separately;
their live qualification remains distinct from this source acceptance.
