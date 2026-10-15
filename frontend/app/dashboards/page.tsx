"use client";

import Link from "next/link";
import {useCallback, useEffect, useRef, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {canManageGrafana, readableDefinition, type GrafanaChange, type GrafanaConnection, type GrafanaPrincipal} from "@/lib/grafana-plugin";
import {grafanaOverviewHref} from "@/lib/grafana-links";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {DashboardAiAuthoring} from "@/components/dashboard-ai-authoring";
import type {DashboardTarget} from "@/lib/dashboard-authoring";

type Resource = {uid: string; title: string; resource_version: string; url: string};
type NativeResource = {metadata: {name: string; resourceVersion: string}; spec: Record<string, unknown>};

export default function DashboardsPage() {
  const [connections, setConnections] = useState<GrafanaConnection[]>([]);
  const [selected, setSelected] = useState("");
  const [principal, setPrincipal] = useState<GrafanaPrincipal | null>(null);
  const [changes, setChanges] = useState<GrafanaChange[]>([]);
  const [reviewId, setReviewId] = useState("");
  const [resources, setResources] = useState<Resource[]>([]);
  const [metrics, setMetrics] = useState<string[]>([]);
  const [title, setTitle] = useState("Operations metrics");
  const [metric, setMetric] = useState("up");
  const [editing, setEditing] = useState<NativeResource | null>(null);
  const [advancedDefinition, setAdvancedDefinition] = useState("");
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [aiTarget, setAiTarget] = useState<DashboardTarget | null>(null);
  const epoch = useRef(0);
  const connection = connections.find(row => row.id === selected);
  const review = changes.find(row => row.id === reviewId);
  const readable = review ? readableDefinition(review.definition) : null;
  const manage = canManageGrafana(principal);
  const load = useCallback(async () => {
    const current = epoch.current;
    try {
      const [rows, plans, identity] = await Promise.all([apiFetch<GrafanaConnection[]>("/grafana/connections"),
        apiFetch<GrafanaChange[]>("/grafana/changes"), apiFetch<GrafanaPrincipal>("/auth/me")]);
      let requested = new URLSearchParams(window.location.search).get("change") || "";
      if (requested && /^[0-9a-f-]{36}$/.test(requested) && !plans.some(plan => plan.id === requested)) {
        plans.unshift(await apiFetch<GrafanaChange>(`/grafana/changes/${requested}`));
      } else if (!/^[0-9a-f-]{36}$/.test(requested)) requested = "";
      if (current !== epoch.current) return;
      setConnections(rows); setChanges(plans); setPrincipal(identity);
      const requestedConnection = new URLSearchParams(window.location.search).get("connection");
      setSelected(value => rows.some(row => row.id === value) ? value : rows.find(row => row.id === requestedConnection && row.enabled)?.id || rows.find(row => row.enabled)?.id || "");
      setReviewId(value => requested || value || plans[0]?.id || "");
    } catch (error) {if (current === epoch.current) setNotice(error instanceof Error ? error.message : "Unable to load dashboard changes");}
  }, []);
  useEffect(() => {
    const context = epoch;
    const reset = () => {epoch.current++; setConnections([]); setChanges([]); setPrincipal(null); setResources([]); setMetrics([]);
      setSelected(""); setReviewId(""); setEditing(null); setAiTarget(null); setAdvancedDefinition(""); setApproved(false); setBusy(false); setNotice(null); void load();};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => void load(), 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [load]);
  useEffect(() => {
    const id = selected;
    let active = true;
    const timer = window.setTimeout(() => {
      setResources([]); setMetrics([]); setEditing(null); setAdvancedDefinition(""); setApproved(false);
      if (!id) return;
      void Promise.all([apiFetch<{dashboards: Resource[]; truncated: boolean}>(`/grafana/connections/${id}/resources`),
        apiFetch<{metrics: string[]}>(`/grafana/connections/${id}/metrics?limit=200`)]).then(([result, catalog]) => {
        if (active && selected === id) {setResources(result.dashboards); setMetrics(catalog.metrics);
          setMetric(value => catalog.metrics.includes(value) ? value : catalog.metrics[0] || "");
          if (result.truncated) setNotice("Showing the first managed dashboards. Use AI search or an exact UID for additional resources.");}
      }).catch(error => {if (active) setNotice(error instanceof Error ? error.message : "Grafana resource discovery failed");});
    }, 0);
    return () => {active = false; window.clearTimeout(timer);};
  }, [selected]);
  async function run(action: () => Promise<string>) {
    if (busy) return;
    const current = epoch.current; setBusy(true); setNotice(null);
    try {const text = await action(); if (current === epoch.current) {setNotice(text); setApproved(false); await load();}}
    catch (error) {if (current === epoch.current) setNotice(error instanceof Error ? error.message : "Dashboard operation failed");}
    finally {if (current === epoch.current) setBusy(false);}
  }
  function selectReview(id: string) {setReviewId(id); setApproved(false);}
  const reviewAiProposal = useCallback(async (id: string) => {
    const current = epoch.current;
    try {
      const plan = await apiFetch<GrafanaChange>(`/grafana/changes/${id}`);
      if (current !== epoch.current) return;
      setChanges(old => [plan, ...old.filter(row => row.id !== plan.id)]); setReviewId(plan.id); setApproved(false);
      const params = new URLSearchParams(window.location.search); params.set("change", plan.id);
      window.history.replaceState(null, "", `/dashboards?${params}`);
    } catch (cause) {if (current === epoch.current) setNotice(cause instanceof Error ? cause.message : "Unable to load AI proposal");}
  }, []);
  function selectAiTarget(target: DashboardTarget | null) {
    const params = new URLSearchParams(window.location.search); params.delete("investigation");
    window.history.replaceState(null, "", `/dashboards?${params}`); setAiTarget(target);
    window.setTimeout(() => {document.getElementById("dashboard-ai")?.scrollIntoView({behavior: "smooth", block: "start"});
      document.querySelector<HTMLTextAreaElement>("#dashboard-ai textarea")?.focus({preventScroll: true});}, 0);
  }
  async function preview() {
    if (!connection || busy) return;
    await run(async () => {
      const spec = advancedDefinition.trim() ? JSON.parse(advancedDefinition) as Record<string, unknown> :
        editing ? {...editing.spec, title} : {title, schemaVersion: 41, time: {from: "now-1h", to: "now"},
          panels: [{id: 1, title: "Observed metric", type: "timeseries", gridPos: {x: 0, y: 0, w: 24, h: 8},
            datasource: {type: "prometheus", uid: connection.datasource_uid}, targets: [{refId: "A", expr: metric, range: true}]}]};
      const plan = await apiFetch<GrafanaChange>(`/grafana/connections/${connection.id}/preview`, {method: "POST",
        headers: {"Content-Type": "application/json"}, body: JSON.stringify({definition: spec,
          ...(editing ? {resource_uid: editing.metadata.name, expected_resource_version: editing.metadata.resourceVersion} : {})})});
      setReviewId(plan.id); window.history.replaceState(null, "", `/dashboards?change=${plan.id}`);
      return "Preview saved. Grafana has not been changed. Review and confirm below.";
    });
  }
  return <main className="mx-auto max-w-5xl space-y-6 p-6">
    <nav className="flex flex-wrap gap-4 text-sm text-violet-700"><Link href="/">AI Operator</Link>
      <a href={grafanaOverviewHref}>Open Grafana</a><Link href="/settings/grafana">Connection settings</Link></nav>
    <header><h1 className="text-2xl font-semibold">Grafana dashboards</h1>
      <p className="mt-2 text-sm text-muted-foreground">Describe what you want. AI builds or revises your dashboard here; review the proposal before applying it to Grafana.</p></header>
    {notice ? <p role="status" className="rounded-xl border bg-slate-50 p-4 text-sm">{notice}</p> : null}
    <section className="space-y-4 rounded-xl border bg-white p-5">
      <label className="block text-sm">Grafana connection<select aria-label="Grafana connection" className="mt-2 w-full rounded border p-2" value={selected} onChange={event => {epoch.current++; setAiTarget(null); setSelected(event.target.value);
        const params = new URLSearchParams(window.location.search); params.set("connection", event.target.value); params.delete("investigation"); window.history.replaceState(null, "", `/dashboards?${params}`);}}>
        <option value="">Choose a connection</option>{connections.filter(row => row.enabled).map(row => <option key={row.id} value={row.id}>{row.name}</option>)}
      </select></label>
    </section>
    {connection && <DashboardAiAuthoring key={`${connection.id}:${aiTarget?.uid || "new"}`} connection={connection} principal={principal}
      target={aiTarget} onNew={() => selectAiTarget(null)} onProposal={reviewAiProposal}/>}
    <section className="space-y-4 rounded-xl border bg-white p-5">
      {!connection ? <p className="text-sm">Configure a protected Grafana connection to discover metrics and save dashboard proposals.</p> : <>
        <h2 className="font-semibold">Installed dashboards</h2><ul className="space-y-2 text-sm">{resources.map(row => <li key={row.uid} className="flex flex-wrap items-center gap-3">
          <a href={row.url} className="text-violet-700 underline">{row.title}</a>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => selectAiTarget(row)}>Edit with AI</Button>
        </li>)}</ul>
        <details><summary className="cursor-pointer text-sm">Advanced: manual preview and JSON definition</summary><div className="mt-4 space-y-3">
          <p className="text-xs text-muted-foreground">Optional manual controls. These do not call AI. For customization in plain language, use the AI editor above.</p>
          <ul className="space-y-2">{resources.map(row => <li key={row.uid} className="flex flex-wrap items-center gap-3"><span className="text-sm">{row.title}</span><Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => {
            const result = await apiFetch<{resource: NativeResource}>(`/grafana/connections/${connection.id}/resources/dashboard/${row.uid}`);
            setEditing(result.resource); setTitle(String(result.resource.spec.title)); setAdvancedDefinition("");
            return "Current Grafana definition loaded. Edit its title or use Advanced details, then preview the revision.";
          })}>Load for manual editing</Button></li>)}</ul>
          <label className="block text-sm">Dashboard title<Input value={title} onChange={event => setTitle(event.target.value)} maxLength={255} /></label>
          {!editing ? <label className="block text-sm">Observed metric<select aria-label="Observed metric" className="mt-2 w-full rounded border p-2" value={metric} onChange={event => setMetric(event.target.value)}>
            {metrics.map(value => <option key={value} value={value}>{value}</option>)}</select></label> : <p className="text-xs">Revising {editing.metadata.name} at version {editing.metadata.resourceVersion}. Existing panels are retained.</p>}
          <label className="block text-sm">Optional native Grafana definition (overrides the title and metric fields above)<textarea aria-label="Optional native Grafana definition" rows={8} className="mt-2 w-full rounded border p-3 font-mono text-xs"
            value={advancedDefinition} onChange={event => setAdvancedDefinition(event.target.value)} placeholder="Leave blank for the simple preview. Never include tokens or credentials." /></label>
          <div className="flex gap-2"><Button disabled={busy || !title.trim() || (!editing && !metric && !advancedDefinition.trim())} onClick={() => void preview()}>Preview dashboard</Button>
            <Button variant="outline" onClick={() => {setEditing(null); setAdvancedDefinition("");}}>Start a new draft</Button></div>
        </div></details>
      </>}
    </section>
    <section className="space-y-4 rounded-xl border bg-white p-5"><h2 className="font-semibold">Review proposed changes</h2>
      <select aria-label="Dashboard change" className="w-full rounded border p-2" value={reviewId} onChange={event => selectReview(event.target.value)}>
        <option value="">Choose a proposal</option>{changes.map(row => <option key={row.id} value={row.id}>{String(row.definition.title)} · {row.status}</option>)}
      </select>
      {review ? <article className="space-y-3 text-sm"><h3 className="text-lg font-medium">{String(review.definition.title)}</h3>
        <p>{review.previous_resource ? `Revise ${review.resource_kind} from version ${review.expected_resource_version}` : `Create ${review.resource_kind}`} · {review.status}</p>
        <p>Folder: {review.folder_uid}. {Array.isArray(review.definition.panels) ? `${review.definition.panels.length} metric panels.` : "Folder title change."}</p>
        <p className="break-all">Target: {review.resource_uid}. Data source: {connections.find(row => row.id === review.connection_id)?.datasource_uid || "See connection settings"}.</p>
        {review.resource_kind === "dashboard" && readable ? <div aria-label="Proposed dashboard display settings" className="space-y-2 rounded border bg-slate-50 p-3">
          {readable.description ? <p className="whitespace-pre-wrap break-words">{readable.description}</p> : null}
          <dl className="space-y-2"><div><dt className="font-medium">Saved time range</dt><dd className="break-words">{readable.timeRange}</dd></div>
            <div><dt className="font-medium">Browser auto-refresh</dt><dd className="break-words">{readable.refresh}</dd></div>
            <div><dt className="font-medium">Timezone</dt><dd className="break-words">{readable.timezone}</dd></div></dl>
          <p className="text-xs text-muted-foreground">These are the proposed saved settings, not a URL override or collection schedule. Check them against your request before applying.</p>
        </div> : null}
        {readable?.panels.length ? <ul aria-label="Proposed panels and queries" className="space-y-3">{readable.panels.map((panel, index) => <li key={index} className="rounded border p-3">
          <p className="font-medium">{panel.title} <span className="font-normal text-muted-foreground">({panel.type})</span></p>
          {panel.queries.map((query, number) => <pre key={number} className="mt-2 whitespace-pre-wrap break-all rounded bg-slate-50 p-2 text-xs">{query}</pre>)}
        </li>)}</ul> : null}
        {readable?.variables.length ? <div><p className="font-medium">Dashboard variables</p><ul className="mt-2 space-y-1">{readable.variables.map(variable => <li key={variable.name} className="break-all">{variable.name} · {variable.type} · {variable.query}</li>)}</ul></div> : null}
        <p className="text-xs text-muted-foreground">This does not enable collection or change a monitored device. Dashboard filters are not device-level isolation; validation does not prove fresh samples.</p>
        {review.status === "proposed" ? <><label className="flex items-start gap-2"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} />Apply this exact reviewed change to Grafana.</label>
          <Button disabled={!manage || !approved || busy} onClick={() => void run(async () => {
            const result = await apiFetch<GrafanaChange>(`/grafana/changes/${review.id}/confirm`, {method: "POST", headers: {"Content-Type": "application/json"},
              body: JSON.stringify({expected_plan_hash: review.plan_hash, confirm: true})});
            return result.status === "applied" ? "Saved in Grafana. Open the real resource below." : `Recorded state: ${result.status}. No unverified success is claimed.`;
          })}>Confirm and apply</Button></> : null}
        {review.status === "unknown" || review.status === "applying" ? <Button variant="outline" disabled={!manage || busy} onClick={() => void run(async () => {
          const result = await apiFetch<GrafanaChange>(`/grafana/changes/${review.id}/confirm`, {method: "POST", headers: {"Content-Type": "application/json"},
            body: JSON.stringify({expected_plan_hash: review.plan_hash, confirm: true})}); return `Inspection state: ${result.status}. No write was repeated.`;
        })}>Inspect uncertain result</Button> : null}
        {review.status === "applied" ? <div className="flex flex-wrap gap-3"><a className="text-violet-700 underline" href={review.resource_url}>Open saved resource in Grafana</a>
          {review.previous_resource ? <Button variant="outline" disabled={busy} onClick={() => void run(async () => {
            const result = await apiFetch<GrafanaChange>(`/grafana/changes/${review.id}/restore-preview`, {method: "POST"});
            setReviewId(result.id); window.history.replaceState(null, "", `/dashboards?change=${result.id}`);
            return "Previous definition loaded as a new proposal. Review and confirm the restoration.";
          })}>Preview rollback</Button> : null}</div> : null}
        {review.error_code ? <p role="alert" className="text-amber-700">{review.error_code}. Refresh Grafana and review a new proposal if the resource changed.</p> : null}
        {!manage ? <p className="text-xs">A globally scoped human with metrics.manage permission must confirm.</p> : null}
        <details><summary className="cursor-pointer">Advanced exact definition and retained previous version</summary>
          <pre className="mt-3 max-h-96 overflow-auto rounded bg-slate-50 p-3 text-xs">{JSON.stringify({proposed: review.definition, previous: review.previous_resource}, null, 2)}</pre></details>
      </article> : <p className="text-sm text-muted-foreground">No proposal selected. Ask AI for a dashboard or use the quick preview.</p>}
    </section>
  </main>;
}
