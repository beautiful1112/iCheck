"use client";
import {FormEvent, useCallback, useEffect, useRef, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {GrafanaResult} from "@/components/grafana-result";
import {type GrafanaChange, type GrafanaConnection} from "@/lib/grafana-plugin";
import {type HTTPMonitorSpec} from "@/lib/http-monitor";
import {defaultMonitoringProfile, exporterCollectors, exporterProtocol, type ExporterMonitorSpec, type ExporterPlugin} from "@/lib/exporter-monitor";

type Target = {device_id: string; connection_id: string; name: string; host: string; site: string;
  device_revision: number; credential_profile_ref: string | null; verification_status: string};
type Credential = {id: string; name: string; kind?: string; enabled: boolean; allowed_adapters?: string[]};
type State = {artifact_version_id: string; version: number; device_revision: number; stage: string; host: string; port: number;
  expected_metrics?: string[] | null;
  template: {plugin: "http" | "snmp" | ExporterPlugin; http_monitor?: HTTPMonitorSpec; exporter_monitor?: ExporterMonitorSpec; port?: number; unsupported_metrics: string[];
    compiled_module?: {module_name: string; expected_metrics: {name: string; type: string}[]}}; module_installed: boolean;
  bound_to_template: boolean; target_test: {metric_samples?: number}; test_error: string | null;
  monitoring: {preview_hash: string; eligible: boolean; blockers: string[]; currently_authorized: boolean;
    enrollment: {revision: number; gateway_profile: string; schedule_seconds: number} | null};
  fresh_samples_verified: boolean; diagnostic?: string | null; metric_evidence?: {name: string; series_count: number}[];
  dashboard_change_id: string | null; dashboard_status: string | null; grafana_dashboard_url: string | null};
const control = "mt-1 block w-full rounded border border-slate-300 bg-white p-2 text-sm";
type ModulePreview = {artifact_version_id: string; module_name: string; metric_names: string[]; installed: boolean;
  expected_catalog_sha256: string; preview_hash: string};

export function StudioMonitoringTarget({sessionId, versionId, versions, canWrite, credentials, initialCredential, interval, onChanged, plugin = "http"}: {
  sessionId: string; versionId: string; versions: {id: string; version: number; status: string}[]; canWrite: boolean;
  credentials: Credential[]; initialCredential: string; interval: number; onChanged: () => Promise<void>; plugin?: "http" | "snmp" | ExporterPlugin;
}) {
  const [version, setVersion] = useState(versionId);
  const [targets, setTargets] = useState<Target[]>([]); const [selected, setSelected] = useState("");
  const [targetSearch, setTargetSearch] = useState(""); const [hasMoreTargets, setHasMoreTargets] = useState(false);
  const [targetsLoading, setTargetsLoading] = useState(true); const [targetError, setTargetError] = useState("");
  const [state, setState] = useState<State | null>(null); const [credential, setCredential] = useState(initialCredential);
  const [schedule, setSchedule] = useState(String(interval)); const [gateway, setGateway] = useState<string>(defaultMonitoringProfile(plugin === "http" ? "https_api" : plugin === "snmp" ? "snmp" : exporterProtocol(plugin)));
  const [modulePreview, setModulePreview] = useState<ModulePreview | null>(null);
  const [installApproved, setInstallApproved] = useState(false);
  const [reason, setReason] = useState("Approve the reviewed template on this explicitly selected target.");
  const [approved, setApproved] = useState(false); const [busy, setBusy] = useState(""); const [error, setError] = useState("");
  const [backends, setBackends] = useState<{id: string; name: string; enabled: boolean}[]>([]); const [backend, setBackend] = useState("");
  const [grafanaConnections, setGrafanaConnections] = useState<GrafanaConnection[]>([]); const [grafana, setGrafana] = useState("");
  const [proposal, setProposal] = useState<GrafanaChange | null>(null);
  const epoch = useRef(0); const requests = useRef(0); const polls = useRef(0);
  const target = targets.find(row => row.connection_id === selected);
  const path = `/capability-studio/sessions/${sessionId}/monitoring`;
  const params = useCallback((verify = false) => new URLSearchParams({artifact_version_id: version,
    device_id: target?.device_id || "", connection_id: target?.connection_id || "",
    ...(verify ? {verify_samples: "true"} : {}), ...(backend ? {backend_id: backend} : {})}), [version, target, backend]);
  const refresh = useCallback(async (verify = false) => {
    if (!target) return;
    const context = epoch.current, request = ++requests.current;
    const next = await apiFetch<State>(path + "/state?" + params(verify));
    if (context === epoch.current && request === requests.current) {setState(next); setError("");}
    return next;
  }, [path, params, target]);
  useEffect(() => {
    const owner = epoch, serial = requests;
    const current = ++owner.current;
    Promise.all([apiFetch<typeof backends>("/metrics/backends").catch(() => []), apiFetch<GrafanaConnection[]>("/grafana/connections").catch(() => [])])
      .then(([metrics, dashboards]) => {
        if (current !== epoch.current) return;
        setBackends(metrics.filter(row => row.enabled)); if (metrics.filter(row => row.enabled).length === 1) setBackend(metrics.find(row => row.enabled)!.id);
        setGrafanaConnections(dashboards.filter(row => row.enabled)); if (dashboards.filter(row => row.enabled).length === 1) setGrafana(dashboards.find(row => row.enabled)!.id);
      }).catch(cause => {if (current === epoch.current) setError(cause instanceof Error ? cause.message : "Unable to load registered targets");});
    return () => {owner.current++; serial.current++;};
  // Only session ownership changes reload the registered metadata, not a poll.
  }, [path, initialCredential]);
  useEffect(() => {
    let active = true;
    const context = epoch.current;
    const timer = window.setTimeout(() => {
      void apiFetch<{targets: Target[]; has_more: boolean}>(path + "/targets?" + new URLSearchParams({search: targetSearch}))
        .then(choices => {
          if (!active || context !== epoch.current) return;
          setTargets(choices.targets); setHasMoreTargets(choices.has_more); setTargetError("");
          if (choices.targets.length === 1) {
            setSelected(choices.targets[0].connection_id);
            setCredential(choices.targets[0].credential_profile_ref || initialCredential);
          }
        }).catch(cause => {
          if (active && context === epoch.current) setTargetError(cause instanceof Error ? cause.message : "Unable to find registered targets");
        }).finally(() => {if (active && context === epoch.current) setTargetsLoading(false);});
    }, 250);
    return () => {active = false; window.clearTimeout(timer);};
  }, [path, targetSearch, initialCredential]);
  function findTargets(value: string) {
    requests.current++; polls.current = 0;
    setTargetSearch(value); setTargetsLoading(true); setTargets([]); setSelected("");
    setState(null); setProposal(null); setModulePreview(null); setApproved(false); setInstallApproved(false);
    setHasMoreTargets(false); setTargetError(""); setError("");
  }
  useEffect(() => {const timer = window.setTimeout(() => setVersion(versionId), 0); return () => window.clearTimeout(timer);}, [versionId]);
  useEffect(() => {
    requests.current++; polls.current = 0;
    const timer = window.setTimeout(() => {setState(null); setApproved(false); setProposal(null); setModulePreview(null); setInstallApproved(false);
      void refresh().catch(cause => setError(cause instanceof Error ? cause.message : "Unable to read template binding"));}, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);
  useEffect(() => {
    if (!state || !target || busy || !["testing", "enabled_awaiting_fresh_samples"].includes(state.stage) || polls.current >= 20) return;
    const timer = window.setTimeout(() => {polls.current++; void refresh(state.monitoring.currently_authorized)
      .catch(cause => setError(cause instanceof Error ? cause.message : "Status check failed; refresh explicitly"));}, 3000);
    return () => window.clearTimeout(timer);
  }, [state, target, busy, refresh]);
  async function run(label: string, action: () => Promise<void>) {
    if (busy) return; const context = epoch.current; setBusy(label); setError("");
    try {await action();} catch(cause) {if (context === epoch.current) setError(cause instanceof Error ? cause.message : "Operation failed; refresh the retained state before retrying");}
    finally {if (context === epoch.current) setBusy("");}
  }
  function payload() {return {artifact_version_id: version, device_id: target!.device_id, connection_id: target!.connection_id,
    expected_device_revision: state?.device_revision || target!.device_revision, actor: "web.capabilityStudio", reason};}
  async function testTarget() {if (!target) return; await run("test", async () => {
    const next = await apiFetch<State>(path + "/test", {method: "POST", body: JSON.stringify({...payload(),
      credential_profile_ref: plugin !== "snmp" && (state?.template.exporter_monitor || state?.template.http_monitor)?.auth_mode === "none" ? null : credential || null})});
    setState(next); setApproved(false); polls.current = 0;
  });}
  async function enable(event: FormEvent) {event.preventDefault(); if (!approved || !state || !target) return;
    await run("enable", async () => {const next = await apiFetch<State>(path + "/enable", {method: "POST", body: JSON.stringify({
      ...payload(), expected_revision: state.monitoring.enrollment?.revision || 0, preview_hash: state.monitoring.preview_hash,
      gateway_profile: gateway, schedule_seconds: Number(schedule), timeout_seconds: Math.min(10, Number(schedule) - 1), validity_hours: 168,
      ...(plugin === "snmp" ? {modules: [state.template.compiled_module!.module_name]} : state.template.exporter_monitor ?
        {collectors: exporterCollectors(state.template.exporter_monitor)} : {})})});
      setState(next); setApproved(false); polls.current = 0; await onChanged();
    });}
  async function dashboard() {if (!target || !grafana || !state?.fresh_samples_verified) return;
    await run("dashboard", async () => {const query = params(); query.set("grafana_connection_id", grafana);
      setProposal(await apiFetch<GrafanaChange>(path + "/dashboard-proposal?" + query, {method: "POST"})); await refresh(true);
    });}
  async function previewModule() {await run("module-preview",async () => {
    setModulePreview(await apiFetch<ModulePreview>(path+"/module-preview?"+new URLSearchParams({artifact_version_id:version}))); setInstallApproved(false);
  });}
  async function installModule() {if (!modulePreview || !installApproved) return;
    await run("install-module",async () => {setModulePreview(await apiFetch<ModulePreview>(path+"/install-module",{method:"POST",body:JSON.stringify({
      artifact_version_id:version,expected_catalog_sha256:modulePreview.expected_catalog_sha256,preview_hash:modulePreview.preview_hash,
      actor:"web.capabilityStudio",reason:"Install the explicitly reviewed native SNMP module without enabling collection."})}));
      setInstallApproved(false); await refresh();
    });}
  const monitor = state?.template.exporter_monitor || state?.template.http_monitor;
  const compatibility = plugin === "snmp" ? "snmp_v2c" : monitor?.auth_mode === "basic" ? "http_basic" : "https_token";
  const authentication = plugin === "snmp" || Boolean(monitor && monitor.auth_mode !== "none");
  const nativeExporter = plugin === "linux" || plugin === "windows" || plugin === "containers" || plugin === "vmware";
  const label = plugin === "snmp" ? "SNMP" : plugin === "http" ? "HTTP/API" : plugin === "linux" ? "Linux exporter" : plugin === "containers" ? "Container exporter" : plugin === "vmware" ? "VMware exporter" : "Windows exporter";
  return <section className="space-y-3 rounded-lg border border-violet-200 bg-violet-50/40 p-4" aria-label={`Test and enable ${plugin.toUpperCase()} monitoring`}>
    <h3 className="font-semibold">Test and enable the monitoring template</h3>
    <p className="text-xs text-muted-foreground">No target is contacted until you choose Test. Collection starts only after your exact-version approval and protected gateway checks.</p>
    <label className="block text-sm">Template version<select className={control} value={version} disabled={!!busy} onChange={e => setVersion(e.target.value)}>
      {versions.filter(row => row.id === versionId || row.status === "published").map(row => <option key={row.id} value={row.id}>Version {row.version} · {row.status}</option>)}</select></label>
    <label className="block text-sm">Find registered targets<input className={control} type="search" maxLength={200}
      value={targetSearch} disabled={!!busy} onChange={e => findTargets(e.target.value)} placeholder="Device name or address" /></label>
    {targetsLoading ? <p role="status" className="text-xs">Finding registered targets…</p> : null}
    {hasMoreTargets && <p className="text-xs">Showing the first 100 matches. Refine the name or address to find another target.</p>}
    {targetError && <p role="alert" className="text-xs text-red-700">{targetError}</p>}
    <label className="block text-sm">Registered {label} target<select className={control} value={selected} disabled={!!busy || targetsLoading} onChange={e => {setSelected(e.target.value); setCredential(targets.find(row => row.connection_id === e.target.value)?.credential_profile_ref || initialCredential);}}><option value="">Select a registered device</option>
      {targets.map(row => <option key={row.connection_id} value={row.connection_id}>{row.name} · {row.host}</option>)}</select></label>
    {!targetsLoading && !targetError && !targets.length && <p className="text-sm">{targetSearch.trim() ? "No matching enabled targets. Try another name or address, or clear the search." : <>Add a {label} connection in <a className="underline" href="/assets/devices/add">Assets</a> first. Location is optional; Collector scope is still required.</>}</p>}
    {nativeExporter && <p className="text-xs">The exporter must already be installed on the monitored host. AI does not run installation commands. Every requested metric and collector result must pass the host test.</p>}
    {plugin === "containers" && <p className="text-xs">cAdvisor source integration: real-container lab acceptance is pending. Only matching runtime containers with images and fresh source measurements count; host cgroups and scrape availability do not prove workload health.</p>}
    {plugin === "vmware" && <p className="text-xs">VMware source preview: real-vSphere qualification is pending. This target is the exporter endpoint, not an ESXi SDK address. Fresh Prometheus samples show collection receipt time; the upstream omits original performance timestamps. Collection does not prove object health.</p>}
    {state && <><p className="text-sm">Version {state.version} · {state.host}:{state.port || state.template.port} · {nativeExporter ? label : plugin === "snmp" ? "SNMPv2c" : `${state.template.http_monitor?.method} ${state.template.http_monitor?.path}`}</p>
      {plugin === "vmware" && <p className="text-xs">Selected object: {state.template.exporter_monitor?.vmware_scope} · {state.template.exporter_monitor?.vmware_name} · {state.template.exporter_monitor?.vmware_datacenter || "unambiguous observed datacenter"}</p>}
      <p className="break-words text-xs">Expected metrics: {(state.expected_metrics || (plugin === "snmp" ? state.template.compiled_module!.expected_metrics : state.template.http_monitor?.metrics || []).map(row => row.name)).join(", ") || "HTTP success, status, latency and HTTPS certificate expiry"}</p>
      {plugin === "snmp" && !state.module_installed && <div className="space-y-2 rounded border border-amber-300 bg-amber-50 p-3">
        <p className="text-sm">The compiled module is not installed on this server. Installation preserves existing modules and does not start collection.</p>
        <Button type="button" variant="outline" disabled={!canWrite || !!busy} onClick={() => void previewModule()}>Review module installation</Button>
        {modulePreview && !modulePreview.installed && <><p className="break-words text-xs">Reviewed metrics: {modulePreview.metric_names.join(", ")}</p>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={installApproved} onChange={e => setInstallApproved(e.target.checked)} />Install this exact reviewed module on this server. Collection stays disabled.</label>
          <Button type="button" disabled={!installApproved || !!busy || !canWrite} onClick={() => void installModule()}>Install reviewed module</Button></>}
      </div>}
      {state.template.unsupported_metrics.length > 0 && <p className="text-xs text-amber-800">Unsupported: {state.template.unsupported_metrics.join("; ")}</p>}
      <p role="status" className="text-sm">{state.fresh_samples_verified ? "Fresh Prometheus samples verified for every declared metric." :
        state.stage === "testing" ? "Target metric test is queued or running." : state.stage === "tested_not_enabled" ? "Target test passed. Continuous collection is not enabled." :
          state.stage === "enabled_awaiting_fresh_samples" ? "Collection intent approved. Waiting for fresh actual metric samples; exporter up alone is not sufficient." : "Test this exact template on the selected target."}</p>
      {state.test_error && <p role="alert" className="text-xs text-red-700">{state.test_error}</p>}
      {state.diagnostic && <p className="text-xs text-amber-800">{state.diagnostic}</p>}
      {authentication && <label className="block text-sm">Protected target credential<select className={control} value={credential} disabled={!!busy || !canWrite} onChange={e => setCredential(e.target.value)}>
        <option value="">Choose a saved credential</option>{credentials.filter(row => row.enabled && row.kind === compatibility && (!nativeExporter || row.allowed_adapters?.includes(exporterProtocol(plugin as ExporterPlugin)))).map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>}
      <div className="flex flex-wrap gap-3"><Button type="button" variant="outline" onClick={() => void testTarget()} disabled={!canWrite || !!busy || state.stage === "testing" || (authentication && !credential) || (plugin === "snmp" && !state.module_installed)}>Test selected target</Button>
        <Button type="button" variant="outline" disabled={!!busy} onClick={() => {polls.current = 0; void run("refresh", async () => {await refresh(true);});}}>Refresh evidence</Button></div>
      {canWrite && state.bound_to_template && state.monitoring.eligible && !state.monitoring.currently_authorized && <form onSubmit={event => void enable(event)} className="space-y-3">
        <label className="block text-sm">Collection interval in seconds<input className={control} required type="number" min={15} max={3600} value={schedule} onChange={e => {setSchedule(e.target.value); setApproved(false);}} /></label>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approved} onChange={e => setApproved(e.target.checked)} />Enable this exact template version and tested target at the displayed interval. This also saves the reviewed template.</label>
        <details><summary className="cursor-pointer text-xs">Advanced collection approval</summary><label className="mt-2 block text-sm">Protected gateway profile<input className={control} required value={gateway} onChange={e => {setGateway(e.target.value); setApproved(false);}} /></label>
          <label className="mt-2 block text-sm">Approval reason<input className={control} required minLength={10} value={reason} onChange={e => setReason(e.target.value)} /></label><p className="mt-1 text-xs">Approval expires after 168 hours; timeout is bounded to 10 seconds. No network allowlist is widened.</p></details>
        <Button disabled={!approved || !!busy}>Enable tested template</Button>
      </form>}
      <label className="block text-sm">Prometheus connection<select className={control} value={backend} disabled={!!busy} onChange={e => setBackend(e.target.value)}><option value="">Choose a metrics connection</option>{backends.map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>
      {state.fresh_samples_verified && <div className="space-y-2"><label className="block text-sm">Grafana connection<select className={control} value={grafana} onChange={e => setGrafana(e.target.value)}><option value="">Choose configured Grafana</option>{grafanaConnections.map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>
        {state.grafana_dashboard_url ? <a className="block text-sm text-violet-700 underline" href={state.grafana_dashboard_url}>Open saved Grafana dashboard</a> : <Button disabled={!canWrite || !grafana || !!busy} variant="outline" onClick={() => void dashboard()}>Prepare native Grafana dashboard</Button>}
        {state.dashboard_change_id && !proposal && !state.grafana_dashboard_url && <a className="block text-sm underline" href={`/dashboards?change=${state.dashboard_change_id}`}>Review retained Grafana proposal</a>}
      </div>}
    </>}
    <GrafanaResult result={proposal} />
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
  </section>;
}
