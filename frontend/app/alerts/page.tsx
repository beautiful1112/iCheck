"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { networkDashboardHref } from "@/lib/grafana-links";
import { DeviceDashboards } from "@/components/device-dashboards";

type Severity = "info" | "warning" | "critical";
type Status = "open" | "acknowledged" | "resolved";
type Principal = { subject: string; permissions: string[]; authorization_scope: { all?: boolean } };
type Alert = {
  id: string; title: string; description: string; event_type: string; entity_type: string;
  entity_id: string; severity: Severity; status: Status; occurrence_count: number;
  first_seen: string; last_seen: string; acknowledged_at: string | null; acknowledged_by: string | null;
  details?: {dashboard_url?: string; investigation_url?: string; fault_recovery_verified?: boolean};
};
type Rule = { id: string; name: string; event_type: string; severity: Severity; enabled: boolean; cooldown_seconds: number; conditions: { threshold?: number } };
type Event = "wireless.rssi.low" | "endpoint.ip.changed" | "endpoint.new";
const selectClass = "mt-2 h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm";
function permits(principal: Principal | null, permission: string) {
  return Boolean(principal?.permissions.includes("*") || principal?.permissions.includes(permission));
}

export default function AlertsPage() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [filter, setFilter] = useState<Status | "">("open");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [event, setEvent] = useState<Event>("wireless.rssi.low");
  const [severity, setSeverity] = useState<Severity>("warning");
  const [threshold, setThreshold] = useState("-75");
  const [cooldown, setCooldown] = useState("300");
  const [enabled, setEnabled] = useState(true);
  const [deviceFilter, setDeviceFilter] = useState<string | null>(null);
  const loadVersion = useRef(0);
  const load = useCallback(async () => {
    const version = ++loadVersion.current;
    setLoading(true); setError(null); setAlerts([]); setRules([]); setPrincipal(null);
    try {
      const identity = await apiFetch<Principal>("/auth/me");
      if (!permits(identity, "alerts.read")) throw new Error("Your identity needs alerts.read to inspect alert evidence.");
      const requestedDevice = new URLSearchParams(window.location.search).get("device_id");
      const requestedAlert = new URLSearchParams(window.location.search).get("alert");
      const episode = requestedAlert && /^[0-9a-f-]{36}$/i.test(requestedAlert) ? requestedAlert : null;
      const device = requestedDevice && /^[0-9a-f-]{36}$/i.test(requestedDevice) ? requestedDevice : null;
      const [nextAlerts, nextRules] = await Promise.all([
        apiFetch<Alert[]>(`/alerts?limit=1000${episode ? `&alert_id=${encodeURIComponent(episode)}` : filter ? `&status=${filter}` : ""}${device ? `&device_id=${encodeURIComponent(device)}` : ""}`),
        apiFetch<Rule[]>("/alert-rules"),
      ]);
      if (loadVersion.current !== version) return;
      setPrincipal(identity); setAlerts(nextAlerts); setRules(nextRules); setDeviceFilter(device);
    } catch (cause) {
      if (loadVersion.current === version) setError(cause instanceof Error ? cause.message : "Unable to read alert evidence");
    } finally { if (loadVersion.current === version) setLoading(false); }
  }, [filter]);
  useEffect(() => {
    const counter = loadVersion;
    const timer = window.setTimeout(() => void load(), 0);
    return () => { window.clearTimeout(timer); ++counter.current; };
  }, [load]);

  const canCreate = permits(principal, "alerts.admin") && principal?.authorization_scope.all === true;
  const canAcknowledge = permits(principal, "alerts.manage");
  async function createRule(submit: FormEvent<HTMLFormElement>) {
    submit.preventDefault();
    if (!canCreate || busy || loading) return;
    setBusy("rule"); setError(null); setNotice(null);
    try {
      const saved = await apiFetch<Rule>("/alert-rules", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), event_type: event, severity, enabled,
          cooldown_seconds: Number(cooldown), conditions: event === "wireless.rssi.low" ? { threshold: Number(threshold) } : {} }),
      });
      setNotice(`Rule saved: ${saved.name}. It evaluates supported incoming inventory observations, not arbitrary Prometheus thresholds.`);
      setName(""); await load();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Rule creation failed"); }
    finally { setBusy(null); }
  }
  async function acknowledge(alert: Alert) {
    if (!canAcknowledge || busy || loading || alert.status !== "open" || !principal) return;
    setBusy(alert.id); setError(null); setNotice(null);
    try {
      await apiFetch(`/alerts/${encodeURIComponent(alert.id)}/acknowledge`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actor: principal.subject }),
      });
      setNotice(`Acknowledged ${alert.title}. Acknowledgement does not resolve the source fault.`);
      await load();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Acknowledgement failed"); }
    finally { setBusy(null); }
  }
  async function closeExternal(alert: Alert) {
    if (!canAcknowledge || busy || loading || !principal || alert.status === "resolved" || !["external.zabbix", "external.solarwinds_orion", "external.rest_webhook"].includes(alert.event_type)) return;
    setBusy(alert.id); setError(null); setNotice(null);
    try {
      await apiFetch(`/alerts/${encodeURIComponent(alert.id)}/resolve`, {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({actor: principal.subject}),
      });
      setNotice("Closed in iCheck and automatic investigation stopped. The monitoring source was not changed; closure does not prove fault recovery.");
      await load();
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Closure failed");}
    finally {setBusy(null);}
  }
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <nav aria-label="Operations"><Link href="/">AI Operator</Link><span aria-hidden="true"> · </span><Link href="/investigations">Investigations</Link><span aria-hidden="true"> · </span><Link href="/assets/devices">Devices</Link><span aria-hidden="true"> · </span><Link href="/alerts/metric-rules">Prometheus metric rules</Link><span aria-hidden="true"> · </span><Link href="/alerts/alertmanager">Alertmanager</Link></nav>
    <header className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-2xl font-semibold">Alert evidence</h1><p className="mt-2 text-sm text-muted-foreground">Collected source alerts, retained episodes and explicit acknowledgement. The AI workspace remains focused on investigations.</p></div><Button variant="outline" disabled={loading || busy !== null} onClick={() => void load()}>Refresh</Button></header>
    {error ? <p role="alert" className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</p> : null}
    {notice ? <p role="status" className="rounded-lg bg-violet-50 p-4 text-sm text-violet-800">{notice}</p> : null}
    <section className="space-y-4" aria-label="Source alerts">
      {deviceFilter && <p className="text-sm">Showing the selected device&apos;s alerts. <Link className="text-violet-700 underline" href="/monitoring">Back to Monitoring</Link> · <a className="text-violet-700 underline" href="/alerts">All alerts</a></p>}
      <label className="block max-w-xs text-sm font-medium">Alert status<select className={selectClass} value={filter} disabled={busy !== null} onChange={(change) => setFilter(change.target.value as Status | "")}><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option><option value="">All statuses</option></select></label>
      {loading ? <p role="status">Loading retained alerts…</p> : null}
      {alerts.length === 1000 ? <p role="status" className="text-sm text-amber-800">Bounded listing: up to 1,000 most recent alerts. Older episodes may be omitted.</p> : null}
      {!alerts.length && !loading && !error ? <p className="rounded-xl border bg-white p-8 text-center text-sm text-muted-foreground">No authorized alerts match this filter. Adding a device alone does not create a source alert.</p> : null}
      {alerts.map((alert) => <article key={alert.id} className="space-y-3 rounded-xl border bg-white p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">{alert.title}</h2><div className="mt-2 flex flex-wrap gap-2"><Badge variant="outline">{alert.severity}</Badge><Badge variant="outline">{alert.status}</Badge><span className="text-xs text-muted-foreground">{alert.event_type} · {alert.occurrence_count} observations</span></div></div>{canAcknowledge && alert.status === "open" ? <Button variant="outline" disabled={busy !== null || loading} onClick={() => void acknowledge(alert)} aria-label={`Acknowledge ${alert.title}`}>{busy === alert.id ? "Acknowledging…" : "Acknowledge"}</Button> : null}</div>
        {alert.description ? <p className="text-sm">{alert.description}</p> : null}<p className="break-all text-xs text-muted-foreground">Source {alert.entity_type}: {alert.entity_id} · First {new Date(alert.first_seen).toLocaleString()} · Last {new Date(alert.last_seen).toLocaleString()}</p>
        {["external.zabbix", "external.solarwinds_orion", "external.rest_webhook"].includes(alert.event_type) && <div className="space-y-2"><p className="text-xs text-muted-foreground">Retained external alert episode. Acknowledgement does not stop AI; closure does. Local closure does not change the source or verify recovery.</p>
          {canAcknowledge && alert.status !== "resolved" && <Button variant="outline" disabled={busy !== null || loading} onClick={() => void closeExternal(alert)}>Close in iCheck and stop AI</Button>}</div>}
        {alert.event_type==="metric.prometheus"&&<p className="text-xs text-amber-800">Alertmanager notification received. {alert.status==="resolved"?"Prometheus condition cleared; infrastructure recovery remains unverified.":"Acknowledgement will not clear the Prometheus condition."}</p>}
        {alert.event_type==="metric.prometheus"&&alert.details?.dashboard_url?.startsWith("https://")&&<a className="mr-4 inline-block text-sm text-violet-700 underline" href={alert.details.dashboard_url}>Open metric alert context in Grafana</a>}
        {alert.event_type==="metric.prometheus"&&alert.details?.investigation_url?.startsWith("/?brief=")&&<Link className="inline-block text-sm text-violet-700 underline" href={alert.details.investigation_url}>Prepare an AI investigation</Link>}
        {alert.event_type !== "metric.prometheus" && alert.entity_type === "device" && Number.isFinite(Date.parse(alert.last_seen)) ?
          <><DeviceDashboards deviceId={alert.entity_id} from={String(Date.parse(alert.last_seen) - 15 * 60 * 1000)} to={String(Date.parse(alert.last_seen) + 15 * 60 * 1000)} />
          <a className="inline-block text-xs text-violet-700 underline" href={networkDashboardHref(alert.entity_id,
            String(Date.parse(alert.last_seen) - 15 * 60 * 1000), String(Date.parse(alert.last_seen) + 15 * 60 * 1000))}>Open legacy SNMP dashboard</a></> : null}
        {alert.acknowledged_at ? <p className="text-xs">Acknowledged by {alert.acknowledged_by || "Unknown actor"} at {new Date(alert.acknowledged_at).toLocaleString()}</p> : null}<details><summary className="cursor-pointer text-xs">Episode reference</summary><p className="mt-2 break-all font-mono text-xs">{alert.id}</p></details>
      </article>)}
    </section>
    <details className="rounded-xl border bg-white p-4"><summary className="cursor-pointer font-semibold">Inventory alert rules · {rules.length}</summary><p className="mt-3 text-sm text-muted-foreground">These rules evaluate supported inventory events. Metric indicators and collector-health conditions have separate contracts; a generic rule is not a Prometheus polling job.</p><ul className="mt-4 space-y-3">{rules.map((rule) => <li key={rule.id} className="rounded-lg border p-3 text-sm"><p className="font-medium">{rule.name} · {rule.enabled ? "Enabled" : "Disabled"}</p><p className="mt-1 text-xs text-muted-foreground">{rule.event_type} · {rule.severity} · cooldown {rule.cooldown_seconds}s{rule.event_type === "wireless.rssi.low" ? ` · RSSI below ${rule.conditions.threshold ?? -75} dBm` : ""}</p></li>)}</ul></details>
    {canCreate ? <details className="rounded-xl border bg-white p-4"><summary className="cursor-pointer font-semibold">Create an inventory alert rule</summary><form onSubmit={createRule} className="mt-4 grid gap-4 sm:grid-cols-2">
      <label className="text-sm font-medium">Rule name<Input className="mt-2" required maxLength={255} value={name} onChange={(change) => setName(change.target.value)} /></label>
      <label className="text-sm font-medium">Inventory event<select className={selectClass} value={event} onChange={(change) => setEvent(change.target.value as Event)}><option value="wireless.rssi.low">Weak Wi-Fi signal</option><option value="endpoint.ip.changed">Endpoint IP changed</option><option value="endpoint.new">New endpoint observed</option></select></label>
      <label className="text-sm font-medium">Severity<select className={selectClass} value={severity} onChange={(change) => setSeverity(change.target.value as Severity)}><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option></select></label>
      <label className="text-sm font-medium">Cooldown in seconds<Input className="mt-2" required type="number" min={0} max={86400} step={1} value={cooldown} onChange={(change) => setCooldown(change.target.value)} /></label>
      {event === "wireless.rssi.low" ? <label className="text-sm font-medium">RSSI threshold in dBm<Input className="mt-2" required type="number" min={-150} max={0} step={1} value={threshold} onChange={(change) => setThreshold(change.target.value)} /></label> : null}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(change) => setEnabled(change.target.checked)} /> Enable the rule after creation</label>
      <p className="text-xs text-muted-foreground sm:col-span-2">This policy affects the current namespace. It does not contact or change devices. A collected observation is still required to create an alert.</p>
      <Button type="submit" disabled={busy !== null || loading || !name.trim()} className="sm:col-span-2">{busy === "rule" ? "Saving rule…" : "Create rule"}</Button>
    </form></details> : !loading && principal ? <p className="text-xs text-muted-foreground">Rule creation requires alerts.admin and global authorization scope in the current namespace. Acknowledgement separately requires alerts.manage.</p> : null}
  </div></main>;
}
