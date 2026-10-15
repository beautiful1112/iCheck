"use client";

import Link from "next/link";
import {FormEvent, useEffect, useRef, useState} from "react";
import {Activity, ArrowLeft, ArrowRight, RefreshCw} from "lucide-react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";

type Target = {
  device_id: string; connection_id: string; name: string; host: string; port: number | null;
  site: string | null; category: string; protocol: string; adapter: string; state: string; reason: string;
  currently_authorized: boolean; interval_seconds: number | null; enrollment_revision: number | null;
  last_observed_at: string | null; sample_age_seconds: number | null; observation_source: string | null;
  device_alert_count: number | null; dashboards: {title: string; url: string}[];
  template_version_id: string | null; studio_url: string;
};
type Resource = {id: string; device_id?: string; resource_type: string; name: string; host: string | null;
  site: string | null; kind: string; category: string; state: string; reason: string; checks: Target[];
  device_alert_count: number | null; dashboards: {title: string; url: string}[]; manage_url: string};
type Overview = {items: Resource[]; categories: {id: string; label: string; count: number}[];
  total: number; offset: number; limit: number; checked_at: string; diagnostic: string | null; boundary: string};
type Measurements = {fresh_samples_verified: boolean; checked_at: string; diagnostic: string | null;
  metric_evidence: {name: string; series_count: number; oldest_sample_timestamp: number | null}[]};
const stateLabels: Record<string, string> = {enabled: "Collecting", pending: "Setup pending", disabled: "Disabled", not_monitored: "Not monitored",
  failing: "Needs attention", stale: "Stale collection", unknown: "Awaiting evidence"};
const stateColors: Record<string, string> = {enabled: "bg-emerald-50 text-emerald-800", pending: "bg-slate-100 text-slate-700", on_demand: "bg-slate-100 text-slate-700",
  disabled: "bg-slate-100 text-slate-600", failing: "bg-red-50 text-red-800", stale: "bg-amber-50 text-amber-900", unknown: "bg-amber-50 text-amber-900"};
const time = (value: string | null) => value ? new Date(value).toLocaleString() : "No current observation";

export default function MonitoringPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const [draftSearch, setDraftSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [evidence, setEvidence] = useState<Record<string, Measurements>>({});
  const [checking, setChecking] = useState<string | null>(null);
  const [checkErrors, setCheckErrors] = useState<Record<string, string>>({});
  const epoch = useRef(0);

  useEffect(() => {
    const serial = ++epoch.current;
    const controller = new AbortController();
    setLoading(true); setData(null); setError(""); setEvidence({}); setCheckErrors({}); setChecking(null);
    const reset = () => {epoch.current++; controller.abort(); setData(null); setEvidence({}); setCheckErrors({}); setChecking(null); setRefresh(value => value + 1);};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    window.addEventListener("storage", storage);
    window.addEventListener("icheck:namespace-changed", reset);
    const query = new URLSearchParams({offset: String(offset), limit: "25", search});
    if (category) query.set("category", category);
    apiFetch<Overview>(`/monitoring/overview?${query}`, {signal: controller.signal})
      .then(result => {if (epoch.current === serial) setData(result);})
      .catch(cause => {if (epoch.current === serial) setError(cause instanceof Error ? cause.message : "Monitoring could not be loaded.");})
      .finally(() => {if (epoch.current === serial) setLoading(false);});
    return () => {epoch.current++; controller.abort(); window.removeEventListener("storage", storage); window.removeEventListener("icheck:namespace-changed", reset);};
  }, [category, search, offset, refresh]);

  async function checkMeasurements(target: Target) {
    if (checking) return;
    const serial = epoch.current;
    setChecking(target.connection_id); setCheckErrors(current => ({...current, [target.connection_id]: ""}));
    try {
      const result = await apiFetch<Measurements>(`/assets/devices/${encodeURIComponent(target.device_id)}/connections/${encodeURIComponent(target.connection_id)}/monitoring/measurements`);
      if (serial === epoch.current) setEvidence(current => ({...current, [target.connection_id]: result}));
    } catch (cause) {
      if (serial === epoch.current) setCheckErrors(current => ({...current, [target.connection_id]: cause instanceof Error ? cause.message : "Measurements could not be checked."}));
    } finally {if (serial === epoch.current) setChecking(null);}
  }
  function submitSearch(event: FormEvent) {event.preventDefault(); setOffset(0); setSearch(draftSearch.trim());}

  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-7xl space-y-6">
    <nav aria-label="Monitoring navigation" className="flex flex-wrap gap-4 text-sm text-violet-700">
      <Link href="/">AI Operator</Link><Link href="/studio">Capability Studio</Link>
      <Link href="/assets/devices">Assets</Link><Link href="/alerts">Alerts</Link>
      <Link href="/alerts/metric-rules">Metric alert rules</Link><Link href="/alerts/alertmanager">Alertmanager</Link><Link href="/settings/observability">Prometheus settings</Link>
    </nav>
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><div className="flex items-center gap-2"><Activity className="size-6 text-violet-600"/><h1 className="text-2xl font-semibold">Monitoring</h1></div>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">Your managed devices and services. Each resource appears once, with its monitoring checks and related alerts.</p></div>
      <div className="flex gap-2"><Button variant="outline" disabled={loading} onClick={() => setRefresh(value => value + 1)}><RefreshCw className="mr-2 size-4"/>Refresh</Button>
        <Button asChild><Link href="/studio">Add monitoring</Link></Button></div>
    </header>
    <section aria-label="Monitoring categories" className="flex flex-wrap gap-2">
      <Button variant={category ? "outline" : "default"} aria-pressed={!category} onClick={() => {setCategory(""); setOffset(0);}}>All {data ? `(${data.categories.reduce((sum, row) => sum + row.count, 0)})` : ""}</Button>
      {(data?.categories || []).map(row => <Button key={row.id} variant={category === row.id ? "default" : "outline"} aria-pressed={category === row.id}
        onClick={() => {setCategory(row.id); setOffset(0);}}>{row.label} ({row.count})</Button>)}
    </section>
    <form onSubmit={submitSearch} className="flex max-w-xl gap-2">
      <label className="sr-only" htmlFor="monitoring-search">Search name, address, type or site</label>
      <Input id="monitoring-search" value={draftSearch} maxLength={128} onChange={event => setDraftSearch(event.target.value)} placeholder="Search name, address, type or site"/>
      <Button variant="outline">Search</Button>
    </form>
    {error && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error}</p>}
    {loading && <p role="status" className="text-sm text-slate-600">Loading configured monitoring…</p>}
    {data && <>
      <p className="text-xs text-slate-500">{data.total} managed resources · Checked {time(data.checked_at)}. Counts include disabled resources and those awaiting monitoring setup.</p>
      {data.diagnostic && <p role="status" className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900">Some collection evidence is unavailable. Inventory remains visible. Check the Prometheus connection and your metric-read access.</p>}
      {!data.items.length ? <section className="rounded-xl border bg-white p-8 text-center"><h2 className="font-semibold">No matching resources</h2>
        <p className="mt-2 text-sm text-slate-600">Choose another category or add a target through Assets or Capability Studio.</p></section> :
      <div className="space-y-3">{data.items.map(resource => {
        return <article key={`${resource.resource_type}:${resource.id}`} className="rounded-xl border bg-white p-5" aria-label={resource.name}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div><h2 className="font-semibold">{resource.name}</h2><p className="mt-1 text-sm text-slate-600">{resource.host ? `${resource.host} · ` : ""}{resource.kind.replaceAll("_", " ")}{resource.site ? ` · ${resource.site}` : ""}</p></div>
            <span className={`rounded-full px-3 py-1 text-xs font-medium ${stateColors[resource.state] || stateColors.pending}`}>{stateLabels[resource.state] || resource.state}</span>
          </div>
          <p className="mt-3 text-sm text-slate-600">{resource.reason}</p>
          {resource.device_alert_count !== null && <p className="mt-3 text-sm">Active device alerts: {resource.device_alert_count}</p>}
          <div className="mt-4 flex flex-wrap gap-4 text-sm text-violet-700">
            <Link href={resource.manage_url}>{resource.resource_type === "service" ? "Open service" : "Manage device"}</Link>
            {resource.device_id && <Link href={`/alerts?device_id=${encodeURIComponent(resource.device_id)}`}>View alerts</Link>}
            <Link href="/studio">Add or edit monitoring</Link>
            {resource.dashboards.map(link => <a key={link.url} href={link.url}>{link.title} ↗</a>)}
          </div>
          {!!resource.checks.length && <details className="mt-4 border-t pt-3"><summary className="cursor-pointer text-sm font-medium">Monitoring checks ({resource.checks.length})</summary>
            {resource.checks.map(target => {const measurement = evidence[target.connection_id]; return <section key={target.connection_id} className="mt-4 rounded border p-3" aria-label={`${target.protocol} monitoring check`}>
            <h3 className="text-sm font-medium">{target.protocol} · {stateLabels[target.state] || target.state}</h3>
            <p className="mt-2 text-xs">{target.reason}</p>
            <p className="mt-2 text-xs text-slate-500">Interval: {target.interval_seconds ? `${target.interval_seconds}s` : "Not enrolled"} · Last observation: {time(target.last_observed_at)}</p>
            <Link className="mt-2 inline-block text-xs text-violet-700" href={target.studio_url}>{target.template_version_id ? "Edit monitoring template" : "Choose a template"}</Link>
            <p className="mt-3 text-xs text-slate-600">{target.observation_source || "No current collection source"}. A successful scrape alone does not verify every requested measurement.</p>
            <Button variant="outline" className="mt-3" disabled={!!checking || !target.currently_authorized || !target.template_version_id} onClick={() => void checkMeasurements(target)}>
              {checking === target.connection_id ? "Checking stored samples…" : "Check measurement freshness"}</Button>
            {!target.currently_authorized || !target.template_version_id ? <p className="mt-2 text-xs text-slate-500">Enable a tested Studio template to check its measurements.</p> : <p className="mt-2 text-xs text-slate-500">Reads existing Prometheus samples; does not probe or enroll the target.</p>}
            {checkErrors[target.connection_id] && <p role="alert" className="mt-2 text-sm text-red-700">{checkErrors[target.connection_id]}</p>}
            {measurement && <div role="status" className="mt-3 text-sm"><p>{measurement.fresh_samples_verified ? "Fresh samples verified for all declared measurements." : "Complete fresh measurements have not been verified."}</p>
              <p className="mt-1 text-xs text-slate-500">Checked {time(measurement.checked_at)}. {measurement.diagnostic}</p>
              <ul className="mt-2 space-y-1">{measurement.metric_evidence.map(metric => <li key={metric.name} className="break-all text-xs">{metric.name} · {metric.series_count} series · oldest sample {metric.oldest_sample_timestamp ? new Date(metric.oldest_sample_timestamp * 1000).toLocaleString() : "unavailable"}</li>)}</ul></div>}
            {!target.dashboards.length && <p className="mt-3 text-xs text-slate-500">No saved target dashboard is available here. Open Studio to bind one.</p>}
            </section>;})}
          </details>}
        </article>;
      })}</div>}
      <div className="flex items-center justify-between gap-3 text-sm"><Button variant="outline" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - data.limit))}><ArrowLeft className="mr-1 size-4"/>Previous</Button>
        <span>{data.total ? `${offset + 1}–${Math.min(offset + data.items.length, data.total)} of ${data.total}` : "0 resources"}</span>
        <Button variant="outline" disabled={offset + data.items.length >= data.total} onClick={() => setOffset(offset + data.limit)}>Next<ArrowRight className="ml-1 size-4"/></Button></div>
    </>}
  </div></main>;
}
