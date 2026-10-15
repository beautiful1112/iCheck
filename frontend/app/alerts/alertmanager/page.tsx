"use client";
import Link from "next/link";
import {FormEvent, useCallback, useEffect, useRef, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {Textarea} from "@/components/ui/textarea";

type Rule = {id: string; name: string; revision: number; enabled: boolean};
type Silence = {id: string; rule_name: string; revision: number; starts_at: string; ends_at: string; state: string; fingerprint: string};
type Receipt = {id: string; action: string; created_at: string; status: string; silence_id: string | null; reason: string};
type Overview = {ready: boolean; provisioned: boolean; receiver_identity_configured: boolean; checked_at: string; version: string | null;
  diagnostics: string[]; rules: Rule[]; rules_truncated: boolean;
  receivers: {name: string; integrations: {type: string; count: number; send_resolved: boolean[]}[]}[];
  routes: {index: number; parent: number | null; depth: number; receiver: string; matchers: string[]; group_by: string[];
    group_wait: string; group_interval: string; repeat_interval: string; continue: boolean; time_intervals_configured: boolean}[];
  alerts: {rule_id: string; revision: number; name: string; severity: string; device_id: string; status: string; starts_at: string;
    silenced_count: number; inhibited_count: number; receivers: string[]; dashboard_url: string | null; investigation_url: string | null}[];
  silences: Silence[]; requests: Receipt[]; alerts_truncated?: boolean; silences_truncated?: boolean;
  counters: {integration: string; attempts: number; failures: number}[];
  delivery_history: {id: string; received_at: string; receiver: string; alert_count: number;
    episodes: {rule_id: string; device_id?: string; alert_id: string | null; source_status: string; fault_recovery_verified: boolean}[]}[]};
const when = (value: string) => new Date(value).toLocaleString();
const box = "space-y-3 rounded-xl border bg-white p-5";

export default function AlertmanagerPage() {
  const [data, setData] = useState<Overview | null>(null), [error, setError] = useState("");
  const [busy, setBusy] = useState(""), [manage, setManage] = useState(false);
  const [ruleId, setRuleId] = useState(""), [minutes, setMinutes] = useState(60), [reason, setReason] = useState("");
  const [approved, setApproved] = useState(false), [ending, setEnding] = useState<Silence | null>(null);
  const [last, setLast] = useState<Receipt | null>(null), [refresh, setRefresh] = useState(0);
  const epoch = useRef(0), requestKey = useRef<string | null>(null), expireKey = useRef<string | null>(null);
  const rule = data?.rules.find(row => row.id === ruleId);
  const load = useCallback(async () => {
    const serial = epoch.current;
    const [principal, result] = await Promise.all([
      apiFetch<{permissions: string[]; authorization_scope: {all?: boolean}; principal_type: string}>("/auth/me"),
      apiFetch<Overview>("/alertmanager/overview"),
    ]);
    if (serial !== epoch.current) return;
    setData(result);
    setApproved(false);
    setManage(principal.principal_type === "user" && principal.authorization_scope.all === true &&
      ["alerts.admin", "metrics.manage", "metrics.read", "alerts.read"].every(value => principal.permissions.includes("*") || principal.permissions.includes(value)));
  }, []);
  useEffect(() => {
    const serial = ++epoch.current;
    const reset = () => {epoch.current++; setData(null); setError(""); setManage(false); setRuleId(""); setReason(""); setApproved(false);
      setEnding(null); setLast(null); setBusy(""); requestKey.current = null; expireKey.current = null; setRefresh(value => value + 1);};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    window.addEventListener("storage", storage); window.addEventListener("icheck:namespace-changed", reset);
    void load().catch(cause => {if (serial === epoch.current) setError(String(cause));});
    return () => {epoch.current++; window.removeEventListener("storage", storage); window.removeEventListener("icheck:namespace-changed", reset);};
  }, [load, refresh]);
  async function action(label: string, fn: () => Promise<Receipt | void>) {
    if (busy) return;
    const serial = epoch.current; setBusy(label); setError("");
    try {const result = await fn(); if (serial === epoch.current) {if (result) setLast(result); await load();}}
    catch (cause) {if (serial === epoch.current) setError(cause instanceof Error ? cause.message : "Request failed. Inspect its outcome before retrying.");}
    finally {if (serial === epoch.current) {setBusy(""); setApproved(false);}}
  }
  function changed() {setApproved(false); requestKey.current = null; setLast(null);}
  async function create(event: FormEvent) {
    event.preventDefault(); if (!approved || !manage || !rule) return;
    requestKey.current ||= crypto.randomUUID();
    await action("create", () => apiFetch<Receipt>("/alertmanager/silences", {method: "POST", body: JSON.stringify({
      request_key: requestKey.current, confirm: true, rule_id: rule.id, expected_revision: rule.revision,
      duration_minutes: minutes, reason})}));
  }
  async function end() {
    if (!ending || !approved || !manage) return;
    const serial = epoch.current;
    expireKey.current ||= crypto.randomUUID();
    await action("expire", () => apiFetch<Receipt>(`/alertmanager/silences/${ending.id}/expire`, {method: "POST", body: JSON.stringify({
      request_key: expireKey.current, confirm: true, expected_fingerprint: ending.fingerprint})}));
    if (serial === epoch.current) setEnding(null);
  }
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-6xl space-y-5">
    <nav aria-label="Alertmanager navigation" className="flex flex-wrap gap-4 text-sm text-violet-700"><Link href="/">AI Operator</Link><Link href="/monitoring">Monitoring</Link><Link href="/alerts">Alert evidence</Link><Link href="/alerts/metric-rules">Prometheus metric rules</Link></nav>
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-semibold">Alertmanager</h1><p className="mt-2 text-sm text-slate-600">Notification routing, maintenance silences and delivery receipts for this trusted workspace.</p></div>
      <Button variant="outline" disabled={!!busy} onClick={() => void action("refresh", load)}>Refresh status</Button></header>
    {error && <p role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{error}</p>}
    {!data && !error && <p role="status">Loading Alertmanager…</p>}
    {data && <>
      <section className={box} aria-label="Connection readiness"><h2 className="font-semibold">Connection readiness</h2>
        <p>{data.ready ? "Ready" : data.provisioned ? "Unavailable" : "Not provisioned"}{data.version ? ` · Alertmanager ${data.version}` : ""}</p>
        <p className="text-sm">Receiver identity: {data.receiver_identity_configured ? "configured" : "not configured"} · Checked {when(data.checked_at)}</p>
        <p className="text-xs text-slate-600">The private listener stays server-side. Readiness and routing configuration do not prove successful notification delivery.</p>
        {data.diagnostics.map(message => <p role="status" className="text-sm text-amber-900" key={message}>{message}. Empty sections below are not evidence of a healthy or quiet system.</p>)}</section>
      <section className={box} aria-label="Active notifications"><h2 className="font-semibold">Active notifications</h2>
        <p className="text-xs text-slate-600">Shows native alerts matching retained iCheck rule versions. Suppression is not resolution or verified recovery.</p>
        {!data.alerts.length && <p className="text-sm">No matching active notifications in the current response.</p>}
        {data.alerts.map((row, index) => <article key={`${row.rule_id}:${row.revision}:${index}`} className="space-y-2 rounded border p-3 text-sm">
          <h3 className="font-medium">{row.name} · {row.severity} · {row.status}</h3><p>Rule revision {row.revision} · Started {when(row.starts_at)} · {row.silenced_count} silences · {row.inhibited_count} inhibitions</p>
          <p>Receivers: {row.receivers.join(", ") || "Awaiting processing"}</p><div className="flex flex-wrap gap-3 text-violet-700">
            <Link href={`/assets/devices?device=${encodeURIComponent(row.device_id)}`}>Device</Link><Link href={`/alerts?device_id=${encodeURIComponent(row.device_id)}`}>Alert evidence</Link>
            {row.dashboard_url && <a href={row.dashboard_url}>Open Grafana</a>}{row.investigation_url && <Link href={row.investigation_url}>Prepare investigation</Link>}</div></article>)}
        {data.alerts_truncated && <p>Only the first 500 native entries were inspected.</p>}</section>
      <div className="grid gap-5 lg:grid-cols-2"><section className={box}><h2 className="font-semibold">Receivers</h2>
        {!data.receivers.length && <p className="text-sm">Receiver configuration is unavailable.</p>}
        {data.receivers.map(row => <article key={row.name} className="rounded border p-3 text-sm"><h3 className="font-medium">{row.name}</h3>
          {row.integrations.map(item => <p key={item.type}>{item.type} · {item.count} destinations · Cleared-condition messages: {item.send_resolved.some(Boolean) ? "enabled for at least one destination" : "not enabled"}</p>)}</article>)}
        <p className="text-xs text-slate-600">URLs, tokens and credentials are hidden. Receiver edits remain protected native configuration in this preview; the included destination is the iCheck inbox.</p></section>
        <section className={box}><h2 className="font-semibold">Routing</h2>{data.routes.map(row => <article key={row.index} className="space-y-1 rounded border p-3 text-sm">
          <h3 className="font-medium">{row.parent === null ? "Root route" : `Route ${row.index} · parent ${row.parent}`} → {row.receiver}</h3>
          <p className="break-words">Match: {row.matchers.join("; ") || "Inherit / all matching alerts"}</p><p>Group by: {row.group_by.join(", ") || "Inherited"}</p>
          <p>First wait {row.group_wait} · Group interval {row.group_interval} · Repeat {row.repeat_interval}</p><p>Continue: {row.continue ? "yes" : "no"}{row.time_intervals_configured ? " · Time restrictions configured" : ""}</p></article>)}</section></div>
      <section className={box}><h2 className="font-semibold">Maintenance silences</h2>
        <p className="text-sm text-slate-600">A silence also stops automatic AI investigation of matching triggering alerts, not only notifications. Already dispatched calls may finish. Ending a silence does not restart stopped investigations.</p>
        <p className="text-sm">Silences stop notifications, not Prometheus evaluation or data collection. They do not acknowledge or resolve iCheck episodes.</p>
        {data.silences.map(row => <article key={row.id} className="space-y-2 rounded border p-3 text-sm"><h3 className="font-medium">{row.rule_name} · revision {row.revision} · {row.state}</h3>
          <p>{when(row.starts_at)} → {when(row.ends_at)}</p><Button variant="outline" disabled={!manage || !!busy || row.state === "expired"} onClick={() => {setEnding(row); setApproved(false); expireKey.current = null;}}>Review ending this silence</Button></article>)}
        {!data.silences.length && <p className="text-sm">No iCheck-scoped silences in the current response.</p>}
        <p className="text-xs text-slate-600">Only exact workspace/rule silences are shown here. Broader externally managed silences may still suppress an active notification.</p>
        {data.silences_truncated && <p>Only the first 500 native silences were inspected.</p>}
        {ending ? <div className="space-y-3 rounded border border-amber-200 bg-amber-50 p-4" aria-label="End silence review"><p>End the silence for {ending.rule_name}, revision {ending.revision}, before {when(ending.ends_at)}? Notifications can resume immediately.</p>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approved} disabled={!!busy} onChange={event => setApproved(event.target.checked)}/>I approve ending this exact silence.</label>
          <Button disabled={!manage || !approved || !!busy} onClick={() => void end()}>End reviewed silence</Button><Button className="ml-2" variant="outline" disabled={!!busy} onClick={() => {setEnding(null); setApproved(false);}}>Cancel</Button></div> :
          <form className="space-y-3 rounded border p-4" onSubmit={event => void create(event)} aria-label="Create silence"><h3 className="font-medium">Silence one rule revision</h3>
            <fieldset disabled={!manage || !!busy || !data.ready} className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Rule<select className="mt-1 block w-full rounded border bg-white p-2" required value={ruleId} onChange={event => {setRuleId(event.target.value); changed();}}>
              <option value="">Choose an enabled metric rule</option>{data.rules.filter(row => row.enabled && row.revision > 0).map(row => <option key={row.id} value={row.id}>{row.name} · revision {row.revision}</option>)}</select></label>
              <label className="text-sm">Duration in minutes<Input className="mt-1" type="number" min={1} max={1440} required value={minutes} onChange={event => {setMinutes(Number(event.target.value)); changed();}}/></label>
              <label className="text-sm sm:col-span-2">Maintenance reason (no credentials)<Textarea className="mt-1" required minLength={3} maxLength={300} value={reason} onChange={event => {setReason(event.target.value); changed();}}/></label></fieldset>
            {rule && <p className="text-sm">Review: suppress notifications and stop automatic AI investigations triggered by {rule.name}, revision {rule.revision}, for {minutes} minutes starting now. Other revisions and rules are unaffected.</p>}
            <label className="flex items-start gap-2 text-sm"><input type="checkbox" disabled={!manage || !!busy || !rule} checked={approved} onChange={event => setApproved(event.target.checked)}/>I approve this rule and duration, notification suppression and stopping its automatic AI investigations.</label>
            <Button disabled={!manage || !!busy || !data.ready || !rule || !approved || reason.trim().length < 3}>Create reviewed silence</Button></form>}
        {!manage && <p className="text-sm">Silence changes require a current human administrator with global alert and metric-management permissions.</p>}</section>
      {last && <p role="status" className="rounded border bg-white p-3 text-sm">{last.action} request: {last.status}. {last.status !== "confirmed" ? "Inspect the request below; do not create a replacement to hide an uncertain outcome." : "Native state verified; this is not fault recovery."}</p>}
      <section className={box}><h2 className="font-semibold">Delivery history</h2><p className="text-sm">Accepted Alertmanager webhook receipts in the iCheck inbox, newest 100. These do not prove delivery to email, SMS or other external receivers.</p>
        {!data.delivery_history.length && <p className="text-sm">No notification receipt recorded yet.</p>}
        {data.delivery_history.map(row => <article className="rounded border p-3 text-sm" key={row.id}><p>{when(row.received_at)} · {row.receiver} · {row.alert_count} accepted alert updates</p>
          {row.episodes.map((item, index) => <p key={index}>{item.source_status === "resolved" ? "Condition cleared; recovery unverified" : "Firing notification received"}{item.alert_id ? <> · <Link className="text-violet-700 underline" href={item.device_id ? `/alerts?device_id=${encodeURIComponent(item.device_id)}` : "/alerts"}>Open alert evidence</Link></> : null}</p>)}</article>)}
        <h3 className="font-medium">Native delivery attempt counters</h3>{data.counters.map(row => <p className="text-sm" key={row.integration}>{row.integration}: {row.attempts} attempts · {row.failures} failures</p>)}
        <p className="text-xs text-slate-600">Counters are cumulative since Alertmanager started, may include retries, and are not per-message delivery history.</p></section>
      <details className={box}><summary className="cursor-pointer font-medium">Silence request history and uncertain outcomes</summary>
        {data.requests.map(row => <article className="space-y-2 rounded border p-3 text-sm" key={row.id}><p>{row.action} · {row.status} · {when(row.created_at)}</p><p className="break-words">{row.reason}</p>
          {row.status !== "confirmed" && <Button variant="outline" disabled={!manage || !!busy} onClick={() => void action("inspect", () => apiFetch<Receipt>(`/alertmanager/requests/${row.id}/inspect`, {method: "POST"}))}>Inspect outcome without resending</Button>}</article>)}</details>
    </>}
    {busy && <p role="status" className="text-sm">{busy === "refresh" ? "Refreshing native status…" : "Checking the selected operation…"}</p>}
  </div></main>;
}
