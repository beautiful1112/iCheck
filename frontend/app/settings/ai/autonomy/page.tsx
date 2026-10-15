"use client";

import Link from "next/link";
import {useCallback, useEffect, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";

type Policy = {
  revision: number; enabled: boolean; scope: {all: boolean; sites: string[]}; severities: string[];
  daily_limit: number; max_concurrent: number; cooldown_seconds: number; max_alert_age_seconds: number;
  paused_until: string | null; dispatcher_healthy: boolean; dispatcher_status: string; runs_today: number;
};
type Event = {id: string; alert_id: string; investigation_id: string | null; status: string; reason: string; created_at: string};

export default function AutomaticInvestigationSettings() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [sites, setSites] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const reload = useCallback(async () => {
    try {
      const [settings, rows] = await Promise.all([
        apiFetch<Policy>("/autonomy/alert-policy"), apiFetch<Event[]>("/autonomy/alert-events"),
      ]);
      setPolicy(settings); setSites(settings.scope.sites.join(", ")); setEvents(rows); setError("");
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Unable to load automatic investigation settings");}
  }, []);
  useEffect(() => {const timer = window.setTimeout(() => void reload(), 0); return () => window.clearTimeout(timer);}, [reload]);
  async function save() {
    if (!policy || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await apiFetch<Policy>("/autonomy/alert-policy", {method: "PUT", body: JSON.stringify({
        expected_revision: policy.revision, enabled: policy.enabled,
        scope: policy.scope.all ? {all: true, sites: []} : {all: false, sites: sites.split(",").map(value => value.trim()).filter(Boolean)},
        severities: policy.severities, daily_limit: policy.daily_limit, max_concurrent: policy.max_concurrent,
        cooldown_seconds: policy.cooldown_seconds, max_alert_age_seconds: policy.max_alert_age_seconds,
        paused_until: policy.paused_until,
      })});
      setPolicy(saved); setNotice("Policy saved. No existing alerts were backfilled. Running investigations retain their original limits.");
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Unable to save policy");}
    finally {setBusy(false);}
  }
  return <main className="mx-auto max-w-4xl space-y-6 p-6">
    <nav className="flex flex-wrap gap-4"><Link href="/">AI Operator</Link><Link href="/alerts">Alerts</Link><Link href="/settings/ai">AI settings</Link></nav>
    <header><h1 className="text-2xl font-semibold">Automatic investigation</h1>
      <p className="mt-2 text-muted-foreground">Let AI investigate new alerts, choose relevant tools and report its findings. No workflow or per-device tool setup is required.</p></header>
    {error && <p role="alert" className="text-red-700">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {policy && <section className="space-y-5 rounded-xl border bg-white p-6">
      <label className="flex items-center gap-3"><input type="checkbox" checked={policy.enabled} disabled={busy}
        onChange={event => setPolicy({...policy, enabled: event.target.checked})}/>Enable automatic read-only investigation</label>
      <p className="text-sm text-muted-foreground">Saving an enabled policy authorizes AI model charges and relevant read-only device checks within this scope and your existing AI budgets. It does not authorize device changes, package installation or automatic alert closure.</p>
      <p className="text-sm text-muted-foreground">Silencing or closing the triggering alert also stops its automatic AI investigation. Acknowledgement alone does not. An in-flight call may finish; no next call is admitted after the stop is observed. Ending a silence does not restart a stopped investigation.</p>
      <div><label htmlFor="automatic-investigation-scope">Managed resources</label>
        <select id="automatic-investigation-scope" className="mt-1 block w-full min-w-0 max-w-full rounded border p-2" value={policy.scope.all ? "all" : "sites"}
          onChange={event => setPolicy({...policy, scope: {...policy.scope, all: event.target.value === "all"}})}>
          <option value="all">All managed resources in this workspace</option><option value="sites">Resources at selected sites</option>
        </select></div>
      {!policy.scope.all && <div><label htmlFor="automatic-investigation-sites">Site names, separated by commas</label>
        <Input id="automatic-investigation-sites" value={sites} onChange={event => setSites(event.target.value)} placeholder="LAB, Hong Kong"/>
        <p className="text-sm text-muted-foreground">Includes newly added resources at these sites. No individual device selection.</p></div>}
      <fieldset><legend>Alert severity</legend><div className="mt-2 flex flex-wrap gap-5">{["critical", "warning", "info"].map(severity =>
        <label key={severity} className="flex items-center gap-2 capitalize"><input type="checkbox" checked={policy.severities.includes(severity)}
          onChange={event => setPolicy({...policy, severities: event.target.checked ? [...policy.severities, severity] : policy.severities.filter(value => value !== severity)})}/>{severity}</label>)}</div></fieldset>
      <div className="grid gap-4 sm:grid-cols-2">
        <div><label htmlFor="automatic-investigation-daily">Maximum investigations per day (UTC)</label><Input id="automatic-investigation-daily" type="number" min={1} max={1000} value={policy.daily_limit} onChange={event => setPolicy({...policy, daily_limit: Number(event.target.value)})}/></div>
        <div><label htmlFor="automatic-investigation-concurrent">Maximum simultaneous investigations</label><Input id="automatic-investigation-concurrent" type="number" min={1} max={20} value={policy.max_concurrent} onChange={event => setPolicy({...policy, max_concurrent: Number(event.target.value)})}/></div>
      </div>
      <details className="rounded border p-3"><summary>Grouping and maintenance</summary><div className="mt-3 space-y-4">
        <p className="text-sm">Related alerts share an investigation. Completed groups have a cooldown; stale alerts are not automatically investigated.</p>
        <div><label htmlFor="automatic-investigation-cooldown">Related-alert cooldown (seconds)</label><Input id="automatic-investigation-cooldown" type="number" min={60} max={86400} value={policy.cooldown_seconds} onChange={event => setPolicy({...policy, cooldown_seconds: Number(event.target.value)})}/></div>
        <div><label htmlFor="automatic-investigation-age">Maximum alert age before starting (seconds)</label><Input id="automatic-investigation-age" type="number" min={60} max={3600} value={policy.max_alert_age_seconds} onChange={event => setPolicy({...policy, max_alert_age_seconds: Number(event.target.value)})}/></div>
        <Button variant="outline" onClick={() => setPolicy({...policy, paused_until: new Date(Date.now() + 3600000).toISOString()})}>Pause for one hour after saving</Button>{" "}
        {policy.paused_until && <><Button variant="outline" onClick={() => setPolicy({...policy, paused_until: null})}>Clear pause</Button><p>Paused until {new Date(policy.paused_until).toLocaleString()}</p></>}
      </div></details>
      <div className="flex gap-3"><Button disabled={busy || !policy.severities.length} onClick={() => void save()}>{busy ? "Saving…" : "Save policy"}</Button><Button variant="outline" disabled={busy} onClick={() => void reload()}>Refresh</Button></div>
      <p role="status" className="text-sm">Dispatcher: {policy.dispatcher_healthy ? policy.dispatcher_status.replaceAll("_", " ") : "not reporting — automatic dispatch is not confirmed"}. Started today: {policy.runs_today}.</p>
    </section>}
    <section><h2 className="text-lg font-semibold">Recent automatic decisions</h2><p className="text-sm text-muted-foreground">Shows investigations started, related alerts grouped, and alerts skipped. Investigation findings do not automatically close an alert.</p>
      {!events.length && <p className="mt-3">No automatic decisions recorded.</p>}
      <ul className="mt-3 space-y-3">{events.map(event => <li key={event.id} className="rounded border bg-white p-4"><p className="font-medium capitalize">{event.status}</p><p>{event.reason}</p>
        <p className="text-sm text-muted-foreground">{new Date(event.created_at).toLocaleString()}</p>
        {event.investigation_id && <Link className="underline" href={`/?investigation=${event.investigation_id}`}>Open investigation</Link>}</li>)}</ul>
    </section>
  </main>;
}
