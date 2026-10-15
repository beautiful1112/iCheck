"use client";

import Link from "next/link";
import {StudioRuntimeRestore} from "@/components/studio-runtime-restore";
import {FormEvent, useCallback, useEffect, useRef, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {Textarea} from "@/components/ui/textarea";
import {StudioAgentConversation} from "@/components/studio-agent-conversation";
import {StudioMonitoringTarget} from "@/components/studio-monitoring-target";
import {StudioNav} from "@/components/studio-nav";
import {ResearchSources} from "@/components/research-sources";
import {exporterProtocol, type ExporterPlugin} from "@/lib/exporter-monitor";
import {authoringKind, canPublish, credentialFreeTarget, inferTask, legacyKind, permits, previewFacts,
  publishedVersion, tasks, validReference, validationFor, isMonitoring, isExtension, monitoringPlugin, inferMonitoringSource,
  type Capability, type StudioPrincipal, type StudioSession, type StudioTask} from "@/lib/studio-builder";

type Attempt = {id: string; request_key: string; status: string; lease_expires_at: string; failure_code: string | null};
type Credential = {id: string; name: string; enabled: boolean; kind?: string; allowed_adapters?: string[]};
type Format = "metrics" | "snmp" | "linux" | "windows" | "containers" | "vmware" | "sample" | "openapi" | "mib" | "command";

export default function CapabilityStudioPage() {
  const [principal, setPrincipal] = useState<StudioPrincipal | null>(null);
  const [sessions, setSessions] = useState<StudioSession[]>([]);
  const [library, setLibrary] = useState<Capability[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [requestedTemplateVersion, setRequestedTemplateVersion] = useState("");
  const [nativeId, setNativeId] = useState("");
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [task, setTask] = useState<StudioTask | null>(null);
  const [brief, setBrief] = useState("");
  const [title, setTitle] = useState("");
  const [target, setTarget] = useState("");
  const [interval, setInterval] = useState("60");
  const [credential, setCredential] = useState("");
  const [format, setFormat] = useState<Format | null>(null);
  const [monitorMode, setMonitorMode] = useState<"api" | "probe">("api");
  const [authentication, setAuthentication] = useState<"none" | "bearer" | "basic" | "api_key">("none");
  const [snmpProfile, setSnmpProfile] = useState<"standard-network" | "cisco-cpu" | "custom">("standard-network");
  const [mibDocuments, setMibDocuments] = useState<string[]>([]);
  const [exporterScheme, setExporterScheme] = useState<"http" | "https">("https");
  const [exporterPort, setExporterPort] = useState("");
  const [containerName, setContainerName] = useState("");
  const [containerId, setContainerId] = useState("");
  const [vmwareScope, setVmwareScope] = useState<"hosts" | "vms" | "datastores">("hosts");
  const [vmwareName, setVmwareName] = useState("");
  const [vmwareDatacenter, setVmwareDatacenter] = useState("");
  const [exporterServerName, setExporterServerName] = useState("");
  const [sample, setSample] = useState("");
  const [sourceText, setSourceText] = useState("");
  const [operation, setOperation] = useState("");
  const [commandProfile, setCommandProfile] = useState("linux.ip_address_json");
  const [refinement, setRefinement] = useState("");
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [handoff, setHandoff] = useState<{id: string; investigation_id: string; kind: string; description: string; reason: string} | null>(null);
  const loadedHandoff = useRef("");
  const epoch = useRef(0);
  const read = useRef(0);
  const kind = inferTask(brief, task);
  const inputFormat = format || inferMonitoringSource(brief);
  const exporter = inputFormat === "linux" || inputFormat === "windows" || inputFormat === "containers" || inputFormat === "vmware";
  const selected = sessions.find(row => row.id === selectedId) || null;
  const selectedKind=selected?.artifact_kind;
  const selectedExtension = selected ? isExtension(selected) : false;
  const facts = selected ? previewFacts(selected) : null;
  const report = validationFor(selected);
  const manage = Boolean(permits(principal, "capabilities.manage") && principal?.authorization_scope.all);
  const currentAttempt = attempts.find(row => row.id === selected?.generation_attempt_id);

  useEffect(()=>{
    if(!selectedKind)return;
    const timer=window.setTimeout(()=>setTask(selectedExtension?"extension":selectedKind==="collector"?"monitor":legacyKind(selectedKind)?"dashboard":"automate"),0);
    return()=>window.clearTimeout(timer);
  },[selectedKind,selectedId,selectedExtension]);

  const reload = useCallback(async () => {
    const context = epoch.current, request = ++read.current;
    try {
      const identity = await apiFetch<StudioPrincipal>("/auth/me");
      const [drafts, artifacts, refs, managed] = await Promise.all([
        permits(identity, "capabilities.read") ? apiFetch<StudioSession[]>("/capability-studio/sessions?limit=100") : Promise.resolve([]),
        permits(identity, "capabilities.read") ? apiFetch<Capability[]>("/artifacts?limit=100") : Promise.resolve([]),
        permits(identity, "credentials.read") ? apiFetch<Credential[]>("/credential-profiles").catch(() => []) : Promise.resolve([]),
        permits(identity, "credentials.read") ? apiFetch<Credential[]>("/device-credentials").catch(() => []) : Promise.resolve([]),
      ]);
      const params = new URLSearchParams(window.location.search);
      const capabilityRequest = params.get("capability_request");
      if (validReference(capabilityRequest) && loadedHandoff.current !== capabilityRequest) {
        const handoffRequest = await apiFetch<{id: string; investigation_id: string; kind: string; description: string; reason: string; studio_session_id?: string | null}>(`/autonomy/requests/${capabilityRequest}`);
        if (context !== epoch.current || request !== read.current) return;
        loadedHandoff.current = capabilityRequest; setHandoff(handoffRequest);
        if (validReference(handoffRequest.studio_session_id)) params.set("session", handoffRequest.studio_session_id);
        setBrief(`Create a ${handoffRequest.kind === "mcp" ? "MCP server" : handoffRequest.kind}. ${handoffRequest.description}\nWhy it is needed: ${handoffRequest.reason}`);
        setTask(handoffRequest.kind === "mcp" ? "extension" : handoffRequest.kind === "collector" ? "monitor" : "automate");
      }
      const requested = params.get("session");
      if (validReference(requested) && !drafts.some(row => row.id === requested)) drafts.unshift(await apiFetch<StudioSession>(`/capability-studio/sessions/${requested}`));
      if (context !== epoch.current || request !== read.current) return;
      setPrincipal(identity); setSessions(drafts); setLibrary(artifacts); setCredentials(refs.map(ref => ({...ref, kind: managed.find(row => row.id === ref.id)?.kind})));
      if (validReference(requested)) setSelectedId(requested);
      const artifact = params.get("artifact");
      if (validReference(artifact)) {
        const details = artifacts.find(row => row.id === artifact) || await apiFetch<Capability>(`/artifacts/${artifact}`);
        if (context !== epoch.current || request !== read.current) return;
        const sessionId = details.labels?.studio_session_id;
        if (validReference(sessionId) && !drafts.some(row => row.id === sessionId)) {
          drafts.unshift(await apiFetch<StudioSession>(`/capability-studio/sessions/${sessionId}`));
          if (context !== epoch.current || request !== read.current) return;
          setSessions([...drafts]);
        }
        if (!artifacts.some(row => row.id === artifact)) setLibrary([...artifacts, details]);
        const existing = drafts.find(row => row.artifact_id === artifact);
        if (existing) setSelectedId(existing.id);
        const pinned = params.get("template_version");
        if (validReference(pinned)) {
          setRequestedTemplateVersion(pinned);
          if (!artifacts.find(row => row.id === artifact)?.versions.some(row => row.id === pinned && row.status === "published")) {
            setError("The linked template version is no longer published. Review its history before selecting a replacement.");
          }
        }
      }
      const investigation = params.get("investigation");
      if (validReference(investigation)) setNativeId(investigation);
    } catch (cause) {if (context === epoch.current && request === read.current) setError(cause instanceof Error ? cause.message : "Unable to load Capability Studio");}
  }, []);
  useEffect(() => {
    const context = epoch;
    const reset = () => {
      context.current++; read.current++; setPrincipal(null); setSessions([]); setLibrary([]); setCredentials([]);
      setHandoff(null); loadedHandoff.current = "";
      setSelectedId(""); setRequestedTemplateVersion(""); setNativeId(""); setAttempts([]); setTask(null); setBrief(""); setTitle(""); setTarget("");
      setCredential(""); setSample(""); setSourceText(""); setOperation(""); setFormat(null); setRefinement("");
      setMonitorMode("api"); setAuthentication("none");
      setSnmpProfile("standard-network"); setMibDocuments([]);
      setApproved(false); setBusy(null); setError(null); setNotice(null);
      window.history.replaceState(null, "", "/studio/builder"); void reload();
    };
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => {const request = new URLSearchParams(window.location.search).get("create"); if (request === "workflow") setTask("automate"); else if (tasks.some(item => item.id === request)) setTask(request as StudioTask); void reload();}, 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [reload]);
  useEffect(() => {
    let active = true;
    const context = epoch.current;
    const timer = window.setTimeout(() => {
      setAttempts([]); setApproved(false);
      if (selectedId) void apiFetch<Attempt[]>(`/capability-studio/sessions/${selectedId}/generations`)
        .then(rows => {if (active && context === epoch.current) setAttempts(rows);})
        .catch(() => {if (active && context === epoch.current) setNotice("Authoring history is unavailable. Refresh before retrying a model request.");});
    }, 0);
    return () => {active = false; window.clearTimeout(timer);};
  }, [selectedId, selected?.artifact_version_id, selected?.generation_attempt_id, selected?.status]);

  function chooseSession(id: string) {
    setSelectedId(id); setRequestedTemplateVersion(""); setNativeId(""); setApproved(false); setRefinement(""); setNotice(null); setError(null);
    window.history.replaceState(null, "", "/studio/builder?session=" + encodeURIComponent(id) + (handoff ? "&capability_request=" + encodeURIComponent(handoff.id) : ""));
  }
  function storeSession(row: StudioSession) {
    setSessions(old => [row, ...old.filter(item => item.id !== row.id)]);
    chooseSession(row.id);
  }
  async function run(name: string, action: (context: number) => Promise<void>) {
    if (busy) return;
    const context = epoch.current; setBusy(name); setError(null); setNotice(null);
    try {await action(context);}
    catch (cause) {if (context === epoch.current) {await reload(); if (context === epoch.current) setError(cause instanceof Error ? cause.message : "Operation failed. Inspect the retained draft before retrying.");}}
    finally {if (context === epoch.current) setBusy(null);}
  }
  async function create(event: FormEvent) {
    event.preventDefault();
    if (brief.trim().length < 10) return;
    if (kind === "dashboard") {
      if (!permits(principal, "investigations.create") || !permits(principal, "metrics.read") || !principal?.authorization_scope.all) {setError("The Grafana builder needs global metric-read and investigation-create permission."); return;}
      await run("dashboard", async context => {
        const created = await apiFetch<{id: string}>("/agent/investigations", {method: "POST", body: JSON.stringify({
          title: title.trim() || brief.trim().slice(0, 100), objective: brief.trim() + "\nUse the native Grafana tools. Discover actual metrics and create or revise a validated proposal, returning its review link. Do not apply a dashboard, enroll devices, run target probes or enable collection. Report unavailable data explicitly.",
          scope: {capability_task: "grafana-dashboard"}, route_purpose: "investigation", created_by: "web.capabilityStudio"})});
        if (context !== epoch.current) return;
        setNativeId(created.id); setSelectedId(""); window.history.replaceState(null, "", "/studio/builder?investigation=" + created.id);
        await apiFetch(`/agent/investigations/${created.id}/start`, {method: "POST", body: JSON.stringify({actor: "web.capabilityStudio"})});
      });
      return;
    }
    if (!manage) return;
    await run("preview", async context => {
      let input: Record<string, unknown> = {};
      const requestedKind = handoff && ["skill", "workflow", "tool"].includes(handoff.kind) ? handoff.kind : authoringKind(brief);
      let endpoint = "/capability-studio/sessions/" + (requestedKind === "workflow" ? "workflows" : requestedKind === "skill" ? "skills" : "tools");
      if (kind === "extension") endpoint = "/capability-studio/sessions/extensions";
      if (kind === "monitor") {
        endpoint = "/capability-studio/sessions";
        if (inputFormat === "metrics") input = {target_url: credentialFreeTarget(target.trim()), http_monitoring: {
          mode: monitorMode, auth_mode: authentication, schedule_seconds: Number(interval), credential_profile_ref: credential || null},
          ...(sample.trim() ? {sample_document: JSON.parse(sample)} : {})};
        else if (exporter) input = {exporter_monitoring: {plugin: inputFormat, scheme: exporterScheme,
          auth_mode: authentication === "api_key" ? "none" : authentication, port: exporterPort ? Number(exporterPort) : null,
          server_name: exporterServerName.trim() || null, ...(inputFormat === "containers" ? {container_name: containerName.trim() || null, container_id: containerId.trim() || null} : {}),
          ...(inputFormat === "vmware" ? {vmware_scope: vmwareScope, vmware_name: vmwareName.trim(), vmware_datacenter: vmwareDatacenter.trim() || null} : {}),
          schedule_seconds: Number(interval), credential_profile_ref: credential || null}};
        else if (inputFormat === "snmp") input = {snmp_monitoring: {profile: snmpProfile, schedule_seconds:Number(interval),
          credential_profile_ref:credential || null, mib_documents:[...mibDocuments,...(sample.trim() ? [sample] : [])]}};
        else if (inputFormat === "mib") input = {mib_input: {mib_document_text: sample}};
        else if (inputFormat === "openapi") input = {openapi_document_text: sample, operation_id: operation, ...(target.trim() ? {target_url: credentialFreeTarget(target.trim())} : {})};
        else if (inputFormat === "command") input = {command_input: {command_profile: commandProfile, target_host: target.trim(), target_port: 22, sample_output: sample}};
        else input = {target_url: credentialFreeTarget(target.trim()), sample_document: JSON.parse(sample)};
        if (sourceText.trim() && inputFormat !== "mib") Object.assign(input, {source_document_text: sourceText, source_document_name: "operator-notes.md", source_document_media_type: "text/markdown"});
      }
      const narrative = brief.trim() + (kind === "monitor" ? `\nRequested interval: ${interval} seconds\nCredential reference: ${credential || "None; selected during target activation"}` : "");
      const created = await apiFetch<StudioSession>(endpoint, {method: "POST", body: JSON.stringify({title: title.trim() || brief.trim().slice(0, 100), brief: narrative, ...input, route_purpose: "capability.authoring", created_by: "capability.author"})});
      if (context !== epoch.current) return;
      storeSession(created); // Keep its identity visible even when the external model outcome is uncertain.
      if (handoff) {
        await apiFetch(`/autonomy/requests/${handoff.id}/studio-session`, {method: "PUT", body: JSON.stringify({session_id: created.id})});
        if (context !== epoch.current) return;
      }
      const generated = await apiFetch<StudioSession>(`/capability-studio/sessions/${created.id}/generate`, {method: "POST", body: JSON.stringify({actor: "capability.author", request_key: crypto.randomUUID()})});
      if (context !== epoch.current) return;
      storeSession(generated); await reload();
    });
  }
  async function refine(event: FormEvent) {
    event.preventDefault(); if (!selected || !refinement.trim() || !manage || legacyKind(selected.artifact_kind)) return;
    await run("refine", async context => {
      const result = await apiFetch<StudioSession>(`/capability-studio/sessions/${selected.id}/messages`, {method: "POST", body: JSON.stringify({actor: "capability.author", content: refinement.trim(), request_key: crypto.randomUUID()})});
      if (context === epoch.current) {setRefinement(""); storeSession(result);}
    });
  }
  async function publish() {
    if (!approved || !canPublish(selected, principal)) return;
    await run("save", async context => {
      const result = await apiFetch<StudioSession>(`/capability-studio/sessions/${selected!.id}/publish`, {method: "POST", body: JSON.stringify({actor: "capability.publisher", expected_artifact_version_id: selected!.artifact_version_id})});
      if (context === epoch.current) {storeSession(result); setNotice("Template saved. No target has been enabled by publishing it."); await reload();}
    });
  }
  async function retry() {
    if (!selected || !currentAttempt || !manage) return;
    await run("inspect", async context => {
      await apiFetch(`/capability-studio/sessions/${selected.id}/generations/${currentAttempt.request_key}/retry`, {method: "POST", body: JSON.stringify({actor: "capability.author"})});
      if (context === epoch.current) {await reload(); setNotice("Recorded outcome inspected. Review the current draft before saving.");}
    });
  }
  async function restoreRuntime(sourceVersion:number,reason:string){
    if(!selected||!manage||!selected.artifact_version_id)return;
    await run("restore",async context=>{
      const restored=await apiFetch<StudioSession>(`/capability-studio/sessions/${selected.id}/restore-preview`,{method:"POST",body:JSON.stringify({
        source_version:sourceVersion,expected_artifact_version_id:selected.artifact_version_id,reason,actor:"capability.operator"})});
      if(context===epoch.current){storeSession(restored);await reload();setNotice("Prior definition prepared as a new reviewed draft. No check was run or recurring trigger changed.");}
    });
  }
  return <main className="min-h-screen bg-slate-50 p-4 text-slate-800 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <StudioNav current="builder" />
    {handoff && <section aria-label="Troubleshooting handoff" className="rounded-lg border bg-white p-4">
      <p className="font-semibold">Capability requested during troubleshooting</p>
      <p className="mt-1 text-sm">{handoff.reason}</p>
      <p className="mt-1 text-sm text-muted-foreground">The brief is ready below. AI generation starts only when you ask for a preview; installation still requires your approval.</p>
      <Link className="mt-2 inline-block text-sm underline" href={`/?investigation=${handoff.investigation_id}`}>Return to the investigation and continue</Link>
    </section>}
    <header><h1 className="text-2xl font-semibold">{selected || nativeId ? "Capability conversation" : "Create a capability"}</h1><p className="mt-2 text-sm text-muted-foreground">{selected || nativeId ? "Continue this conversation to refine your capability. Versions and installation are managed separately." : "Describe what you want to observe or automate. AI creates a draft for your review."}</p></header>
    {error ? <p role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error}</p> : null}
    {notice ? <p role="status" className="rounded-xl border bg-white p-4 text-sm">{notice}</p> : null}
    <div className="mx-auto max-w-4xl">
      <div className="min-w-0 space-y-5">
        {!selected && !nativeId && <section className="space-y-4 rounded-xl border bg-white p-5">
          <div className="flex flex-wrap gap-2">{tasks.map(item => <Button key={item.id} variant={task === item.id ? "default" : "outline"} type="button" disabled={busy !== null} onClick={() => {setTask(item.id); setApproved(false); setNotice(null); setError(null);}}>{item.label}</Button>)}</div>
          <ol aria-label="Capability creation steps" className="flex flex-wrap gap-4 text-xs text-muted-foreground"><li>1 Describe</li><li>2 Preview</li><li>3 Test</li><li>4 Enable</li></ol>
          <form onSubmit={event => void create(event)} className="space-y-4">
            <label className="block text-sm font-medium">What should this capability do?<Textarea className="mt-2" required minLength={10} maxLength={9000} rows={4} value={brief} onChange={event => setBrief(event.target.value)} placeholder="For example: check our inventory API every minute and record changed IP/MAC addresses. Or build a Grafana interface-traffic dashboard." /></label>
            <p className="text-xs text-muted-foreground">Suggested task: {tasks.find(item => item.id === kind)?.label}. Never paste passwords or tokens here; use a protected credential reference.</p>
            {kind === "monitor" ? <div className="space-y-3">
              <label className="block text-sm">Monitoring technology<select className="mt-2 w-full rounded border p-2" value={inputFormat} onChange={event => {setFormat(event.target.value as Format); setCredential(""); setAuthentication("none"); setExporterPort("");}}>
                <option value="metrics">HTTP/API</option><option value="snmp">SNMP</option><option value="linux">Linux · node_exporter</option><option value="windows">Windows · windows_exporter</option><option value="containers">Containers · cAdvisor (source preview)</option><option value="vmware">VMware · exporter (source preview)</option><option value="sample">API inventory observations</option>
                {!["metrics", "snmp", "linux", "windows", "containers", "vmware", "sample"].includes(inputFormat) && <option value={inputFormat}>Advanced source: {inputFormat}</option>}</select></label>
              {inputFormat !== "snmp" && !exporter && <label className="block text-sm">Target URL or host<Input className="mt-2" value={target} onChange={event => setTarget(event.target.value)} placeholder="Credential-free URL or selected command host" /></label>}
              {exporter && <><div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Exporter transport<select className="mt-2 w-full rounded border p-2" value={exporterScheme} onChange={e => {setExporterScheme(e.target.value as typeof exporterScheme); setAuthentication("none"); setCredential("");}}><option value="https">Verified HTTPS</option><option value="http">HTTP · explicit gateway exception required</option></select></label>
                <label className="text-sm">Authentication<select className="mt-2 w-full rounded border p-2" disabled={exporterScheme === "http"} value={authentication === "api_key" ? "none" : authentication} onChange={e => {setAuthentication(e.target.value as typeof authentication); setCredential("");}}><option value="none">No authentication</option><option value="basic">Username / password</option><option value="bearer">Bearer token</option></select></label>
                <label className="text-sm">Exporter port<Input className="mt-2" type="number" min={1} max={65535} value={exporterPort} onChange={e => setExporterPort(e.target.value)} placeholder={inputFormat === "linux" ? "9100" : inputFormat === "containers" ? "8080" : inputFormat === "vmware" ? "9272" : "9182"} /></label>
                {inputFormat === "containers" && <><label className="text-sm">Exact container name (optional)<Input className="mt-2" value={containerName} onChange={e => {setContainerName(e.target.value); setContainerId("");}} placeholder="Blank means all currently observed runtime containers" /></label><label className="text-sm">Exact cgroup/container ID (optional)<Input className="mt-2" value={containerId} onChange={e => {setContainerId(e.target.value); setContainerName("");}} placeholder="Use ID instead of name; never the host root /" /></label></>}
                {inputFormat === "vmware" && <><label className="text-sm">VMware object type<select aria-label="VMware object type" className="mt-2 w-full rounded border p-2" value={vmwareScope} onChange={e => setVmwareScope(e.target.value as typeof vmwareScope)}><option value="hosts">ESXi host</option><option value="vms">Virtual machine</option><option value="datastores">Datastore</option></select></label><label className="text-sm">Exact VMware object name<Input required maxLength={255} className="mt-2" value={vmwareName} onChange={e => setVmwareName(e.target.value)} placeholder="Observed exporter label, not an invented object ID" /></label><label className="text-sm">Datacenter (optional)<Input maxLength={255} className="mt-2" value={vmwareDatacenter} onChange={e => setVmwareDatacenter(e.target.value)} placeholder="Use when names are repeated across datacenters" /></label></>}
                {exporterScheme === "https" && <label className="text-sm">Certificate server name (optional)<Input className="mt-2" value={exporterServerName} onChange={e => setExporterServerName(e.target.value)} placeholder="Host DNS name in the certificate" /></label>}</div>
                <p className="text-xs">Select the registered exporter endpoint after preview. Its exporter must be installed already; AI selects supported measurements, not installation commands. {inputFormat === "vmware" ? "Requires an existing vmware_exporter 0.18.x-compatible endpoint, preconfigured with a read-only vSphere account and verified vCenter TLS. iCheck credentials protect that endpoint, not the SDK account. Datastores support capacity/free bytes; VM guest disks need VMware Tools. Real-vSphere acceptance is pending. Source performance timestamps are unavailable; collection receipt is not object health." : inputFormat === "containers" ? "cAdvisor must already run on the monitored host. Source integration is fixture-tested; real-container acceptance is pending. CPU is reported in cores, memory in working-set/limit bytes. Fresh source timestamps are required; no workload readiness is inferred." : inputFormat === "windows" ? "Memory reports available and physical-total bytes; Grafana derives utilization from tested samples. WMI/CIM remains a separate bounded diagnostic tool." : "CPU, memory, filesystems, network counters and uptime are supported groups."}</p></>}
              {inputFormat === "snmp" && <><label className="block text-sm">SNMP profile<select className="mt-2 w-full rounded border p-2" value={snmpProfile} onChange={e => setSnmpProfile(e.target.value as typeof snmpProfile)}><option value="standard-network">Standard network: uptime, interfaces and traffic</option><option value="cisco-cpu">Cisco CPU: requires vendor MIBs</option><option value="custom">Custom vendor MIB metrics</option></select></label><p className="text-xs">Choose the actual registered device after preview. Vendor MIBs and dependencies can be uploaded under Advanced input.</p></>}
              {inputFormat === "metrics" && <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Monitoring type<select className="mt-2 w-full rounded border p-2" value={monitorMode} onChange={e => setMonitorMode(e.target.value as typeof monitorMode)}><option value="api">Numeric API JSON metrics</option><option value="probe">HTTP availability, status, latency and TLS</option></select></label>
                <label className="text-sm">Authentication<select className="mt-2 w-full rounded border p-2" value={authentication} onChange={e => {setAuthentication(e.target.value as typeof authentication); setCredential("");}}><option value="none">No authentication</option><option value="bearer">Bearer token</option><option value="basic">Username / password</option><option value="api_key">API-key header</option></select></label></div>}
              <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Requested interval (seconds)<Input className="mt-2" type="number" min={15} max={3600} required value={interval} onChange={event => setInterval(event.target.value)} /></label>
                <label className="text-sm">Credential reference for target activation<select aria-label="Credential reference for target activation" className="mt-2 w-full rounded border p-2" value={credential} onChange={event => setCredential(event.target.value)}><option value="">Choose when testing</option>{credentials.filter(row => row.enabled && (inputFormat === "snmp" ? row.kind === "snmp_v2c" : (!exporter && inputFormat !== "metrics") || row.kind === (authentication === "basic" ? "http_basic" : "https_token")) && (!exporter || row.allowed_adapters?.includes(exporterProtocol(inputFormat as ExporterPlugin)))).map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label></div>
              <p className="text-xs text-amber-800">{inputFormat === "metrics" ? "AI proposes a declarative Prometheus template. Select and test a registered target below before enabling it; no sample or source document is required for a schema-only proposal." : "Draft validation does not contact this target. Fresh Prometheus collection and exporter installation are separate activation steps."}</p>
            </div> : null}
            <details className="rounded-lg border p-3"><summary className="cursor-pointer text-sm">Advanced input and source documents</summary><div className="mt-4 space-y-3">
              <label className="block text-sm">Optional capability name<Input value={title} onChange={event => setTitle(event.target.value)} maxLength={255} /></label>
              {kind === "monitor" ? <>
                <label className="block text-sm">Source format<select aria-label="Source format" className="mt-2 w-full rounded border p-2" value={inputFormat} onChange={event => {setFormat(event.target.value as Format); setCredential(""); setAuthentication("none");}}><option value="metrics">HTTP/API metrics for Prometheus</option><option value="snmp">SNMP metrics for Prometheus</option><option value="linux">Linux exporter metrics</option><option value="windows">Windows exporter metrics</option><option value="containers">Container cAdvisor metrics</option><option value="vmware">VMware object metrics</option><option value="sample">API JSON inventory response</option><option value="openapi">OpenAPI GET inventory operation</option><option value="mib">Legacy SNMP MIB proposal</option><option value="command">Fixed read-only SSH command output</option></select></label>
                {inputFormat === "snmp" && <label className="block text-sm">Vendor MIB bundle and dependencies<input className="mt-2 block w-full text-xs" type="file" multiple accept=".mib,.my,.txt" onChange={event => {
                  const files=Array.from(event.target.files || []); const context=epoch.current;
                  if (files.length > 16 || files.some(file => file.size > 1000000) || files.reduce((sum,file) => sum+file.size,0) > 2000000) setError("Upload at most 16 MIBs, 1 MB each and 2 MB total.");
                  else void Promise.all(files.map(file => file.text())).then(texts => {if (context===epoch.current) setMibDocuments(texts);}).catch(() => setError("Unable to read the selected MIB files."));
                  event.currentTarget.value="";
                }} /><span className="text-xs">{mibDocuments.length} uploaded MIB sources. Only symbol metadata goes to AI; native compilation uses the source files.</span></label>}
                {inputFormat === "openapi" ? <label className="block text-sm">Operation ID<Input value={operation} onChange={event => setOperation(event.target.value)} /></label> : null}
                {inputFormat === "command" ? <label className="block text-sm">Fixed command profile<select aria-label="Fixed command profile" className="mt-2 w-full rounded border p-2" value={commandProfile} onChange={event => setCommandProfile(event.target.value)}><option value="linux.ip_address_json">Linux IP and MAC inventory</option><option value="linux.route_json">Linux routes</option></select></label> : null}
                <label className="block text-sm">Sanitized response, definition or command output<Textarea className="mt-2 font-mono text-xs" value={sample} onChange={event => setSample(event.target.value)} rows={8} maxLength={1000000} placeholder="Supply actual bounded sample data or a vendor definition. No synthetic sample is prefilled." /></label>
                <label className="block text-sm">Upload source document<input aria-label="Upload source document" className="mt-2 block w-full text-xs" type="file" accept=".json,.yaml,.yml,.mib,.txt" onChange={event => {const file = event.target.files?.[0]; const context = epoch.current; if (file && file.size <= 1000000) void file.text().then(text => {if (context === epoch.current) setSample(text);}); else if (file) setError("Source file exceeds 1 MB."); event.currentTarget.value = "";}} /></label>
                {inputFormat === "mib" ? <p className="text-xs text-amber-800">A parsed MIB is not an installed exporter module. This draft stays non-publishable until generator, installation and live-device qualification are completed.</p> : null}
                <label className="block text-sm">Optional vendor notes<Textarea value={sourceText} onChange={event => setSourceText(event.target.value)} rows={3} maxLength={65536} /></label>
              </> : <p className="text-xs">{kind === "extension" ? "Describe the vendor and tools you need. The first runtime supports Netmiko interface checks and protected configuration backups. Generated code and fixtures do not install a server or grant device access." : "The builder chooses native Grafana tools or an existing workflow/Skill contract from your task. No implementation-type selection is required."}</p>}
            </div></details>
            <p className="text-xs text-muted-foreground">Preview starts a model-backed run using your configured route and budgets. Opening this page does not call a model or probe a device.</p>
            <Button disabled={busy !== null || brief.trim().length < 10 || (kind === "dashboard" ? !permits(principal, "investigations.create") : !manage)}>{busy ? "Working…" : "Ask AI to preview"}</Button>
            {kind === "monitor" && !sample.trim() && !["metrics","snmp","linux","windows","containers","vmware"].includes(inputFormat) ? <p className="text-xs">Provide the source response or MIB under Advanced input before previewing an inventory collector. Existing devices can be added or configured in <Link className="text-violet-700 underline" href="/assets/devices">Assets</Link>.</p> : null}
          </form>
        </section>}
        {nativeId ? <StudioAgentConversation id={nativeId} onRefine={async (content, changeId) => {
          await run("dashboard-revision", async context => {
            const created = await apiFetch<{id: string}>("/agent/investigations", {method: "POST", body: JSON.stringify({
              title: "Revise Grafana proposal", objective: content + `\nRead the previous Grafana change ${changeId} with grafana.changes.get, inspect the current remote resource when present, and propose a new validated dashboard revision. Do not apply changes or repeat any uncertain write.`,
              scope: {capability_task: "grafana-dashboard"}, route_purpose: "investigation", created_by: "web.capabilityStudio"})});
            if (context !== epoch.current) return;
            setNativeId(created.id); window.history.replaceState(null, "", "/studio/builder?investigation=" + created.id);
            await apiFetch(`/agent/investigations/${created.id}/start`, {method: "POST", body: JSON.stringify({actor: "web.capabilityStudio"})});
          });
        }} /> : null}
        {selected ? <section className="space-y-4 rounded-xl border bg-white p-5" aria-label="Capability preview">
          <h2 className="text-lg font-semibold">{selected.title} · {selected.status}</h2>
          {legacyKind(selected.artifact_kind) ? <p className="text-sm text-amber-800">Historical service artifact, retained read-only. New metric dashboards are authored in Grafana.</p> : <>
            <dl className="grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Target</dt><dd className="break-all">{facts?.target}</dd></div><div><dt className="text-muted-foreground">Requested interval</dt><dd>{facts?.interval ? facts.interval + " seconds (intent, not an active schedule)" : "Chosen at runtime"}</dd></div>
              <div><dt className="text-muted-foreground">Credential reference</dt><dd className="break-all">{facts?.credential || "Selected at activation; no secret in the template"}</dd></div><div><dt className="text-muted-foreground">Result</dt><dd>{facts?.result}</dd></div></dl>
            <div><h3 className="text-sm font-medium">Expected outputs or steps</h3><ul className="mt-2 list-inside list-disc text-sm">{facts?.outcomes.map((value, index) => <li key={index}>{value}</li>)}</ul></div>
            <div><h3 className="text-sm font-medium">Test result</h3><p className="mt-2 text-sm">{report ? "Recorded draft validation is available. This is not a live target test or fresh metric proof." : "No validated current draft. Inspect the authoring request or revise the input."}</p></div>
          </>}
          <section aria-label="Authoring conversation" className="space-y-3">{selected.messages.map(message => <article key={message.id} className="rounded-lg bg-slate-50 p-3 text-sm"><p className="mb-1 text-xs font-medium">{message.role === "user" ? "You" : "AI / validator"}</p><p className="whitespace-pre-wrap break-words">{message.content}</p><ResearchSources content={message.structured_content} /></article>)}</section>
          {!legacyKind(selected.artifact_kind) && manage ? <form onSubmit={event => void refine(event)} className="space-y-2"><label className="block text-sm">Tell AI what to change<Textarea className="mt-2" value={refinement} onChange={event => setRefinement(event.target.value)} rows={3} maxLength={20000} /></label><Button variant="outline" disabled={busy !== null || !refinement.trim()}>Preview revision</Button></form> : null}
          {canPublish(selected, principal) ? <div className="space-y-3"><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} />Save this exact validated template. This does not enable a target.</label><Button disabled={!approved || busy !== null} onClick={() => void publish()}>Save reviewed template</Button></div> : null}
          {manage&&["workflow","skill"].includes(selected.artifact_kind)&&selected.artifact_version_id&&["validated","published"].includes(selected.status)?
            <StudioRuntimeRestore key={selected.artifact_version_id} currentVersion={selected.artifact_version_id} versions={library.find(row=>row.id===selected.artifact_id)?.versions||[]}
              disabled={busy!==null} onRestore={restoreRuntime}/>:null}
          {isMonitoring(selected) && selected.artifact_version_id && ["validated", "published"].includes(selected.status) ? <StudioMonitoringTarget
            key={`${selected.id}:${selected.artifact_version_id}:${requestedTemplateVersion}`} sessionId={selected.id} versionId={requestedTemplateVersion || (selected.status === "validated" ? selected.artifact_version_id :
              publishedVersion(library.find(row => row.id === selected.artifact_id) || {id: "", name: "", kind: "", description: "", versions: []})?.id || selected.artifact_version_id)}
            versions={library.find(row => row.id === selected.artifact_id)?.versions || []} canWrite={manage && permits(principal, "assets.write")}
            credentials={credentials} initialCredential={facts?.credential && credentials.some(row => row.id === facts.credential) ? facts.credential : ""}
            interval={Number(facts?.interval || (monitoringPlugin(selected) === "http" ? 60 : 30))} onChanged={reload} plugin={monitoringPlugin(selected)} /> : null}
          {isExtension(selected) && selected.artifact_id ? <div className="rounded-lg bg-violet-50 p-4 text-sm"><p>Editing this draft does not change the installed server. Review its tools and approve one reusable package—no device selection is needed to install.</p><Link className="mt-2 inline-block font-medium text-violet-700 underline" href={`/studio/mcp?artifact=${selected.artifact_id}`}>Review and install MCP server</Link></div> : null}
          {selected.status === "published" && !legacyKind(selected.artifact_kind) && !isMonitoring(selected) && !isExtension(selected) ? <div className="space-y-2 text-sm"><p>Next: {selected.artifact_kind === "collector" ? "select a device, review its assignment and enable collection in Assets. A fresh sample is still required." : "choose inputs and explicitly launch the saved capability. Saving is not a run."}</p>
            <Link className="text-violet-700 underline" href={selected.artifact_kind === "collector" ? "/assets/devices" : selected.artifact_kind === "workflow" || selected.artifact_kind === "skill" ? `/?${selected.artifact_kind}_version=${selected.artifact_version_id}` : "/studio/artifacts"}>Use saved capability</Link></div> : null}
          <details><summary className="cursor-pointer text-sm">Advanced definition, validation, permissions and history</summary><div className="mt-3 space-y-3">
            <p className="text-xs">{selected.tokens_used} known tokens · version {selected.artifact_version_id || "Not allocated"}</p>
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">{JSON.stringify({definition: selected.current_spec, validation: report, authoring_requests: attempts}, null, 2)}</pre>
            {currentAttempt && manage && !legacyKind(selected.artifact_kind) ? <Button variant="outline" disabled={busy !== null} onClick={() => void retry()}>Inspect or resume the same authoring request</Button> : null}
            {selected.artifact_id ? <Link className="block text-sm text-violet-700 underline" href={`/studio/artifacts?artifact=${selected.artifact_id}`}>{isExtension(selected) ? "Source version history" : "Version history and rollback"}</Link> : null}
          </div></details>
        </section> : null}
      </div>
    </div>
  </div></main>;
}
