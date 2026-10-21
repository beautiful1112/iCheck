"use client";

import Link from "next/link";
import {useCallback, useEffect, useRef, useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {apiFetch} from "@/lib/icheck-api";
import {externalAlertLabel, feedApproval, type AlertFeed, type ExternalAlerts} from "@/lib/integration-alerts";

const message = (error: unknown) => error instanceof Error ? error.message : "External alert request failed.";
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not yet";

export function IntegrationAlerts({path, revision, enabled, epochRef}: {
  path: string; revision: number; enabled: boolean; epochRef: {current: number};
}) {
  const [feed, setFeed] = useState<AlertFeed | null>(null);
  const [view, setView] = useState<ExternalAlerts | null>(null);
  const [offset, setOffset] = useState(0); const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [notice, setNotice] = useState("");
  const [seconds, setSeconds] = useState(60);
  const mounted = useRef(false), submitting = useRef(false), requests = useRef(0), seenRevision = useRef(-1);
  const read = useCallback(async () => {
    const serial = epochRef.current, request = ++requests.current;
    const [saved, events] = await Promise.all([apiFetch<AlertFeed>(`${path}/alert-feed`),
      apiFetch<ExternalAlerts>(`${path}/external-alerts?limit=50&offset=${offset}`)]);
    if (!mounted.current || serial !== epochRef.current || request !== requests.current) return;
    if (saved.revision !== seenRevision.current) {setSeconds(saved.interval_seconds); seenRevision.current = saved.revision;}
    setFeed(saved); setView(events);
  }, [path, offset, epochRef]);
  useEffect(() => {
    mounted.current = true;
    const serial = epochRef.current, context = requests;
    const update = () => {if (!submitting.current) void read().catch(error => {
      if (mounted.current && serial === epochRef.current) setError(message(error));
    });};
    const initial = window.setTimeout(update, 0);
    // Local status only: GET never initiates a remote request or an AI run.
    const timer = window.setInterval(update, 10_000);
    return () => {mounted.current = false; context.current++; window.clearTimeout(initial); window.clearInterval(timer);};
  }, [read, refresh, epochRef]);
  async function write(suffix: string, payload: unknown, method = "PUT") {
    if (submitting.current) return;
    const serial = epochRef.current; submitting.current = true; setBusy(true); setError(""); setNotice("");
    try {
      await apiFetch(`${path}/${suffix}`, {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
      if (mounted.current && serial === epochRef.current) {
        setNotice(suffix === "alert-feed" ? "Alert feed settings saved. AI investigation still requires the separate automatic-investigation policy."
          : "Automatic investigation stopped for this episode. Source notifications and device configuration were not changed.");
        await read();
      }
    } catch (error) {
      if (mounted.current && serial === epochRef.current) {
        setError(message(error));
        await read().catch(() => {if (mounted.current && serial === epochRef.current) {setFeed(null); setView(null);}});
      }
    } finally {if (mounted.current && serial === epochRef.current) {setBusy(false); submitting.current = false;}}
  }
  return <section className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">External alerts</h2>
      <Button variant="outline" disabled={busy} onClick={() => {setError(""); setRefresh(n => n + 1);}}>Refresh alerts</Button></div>
    <p className="mt-2 text-sm text-slate-600">Read source alerts and recovery events in the saved groups. Only a single, reviewed asset mapping can enter the native alert and AI investigation flow.</p>
    {error && <p role="alert" className="mt-3 rounded bg-red-50 p-3 text-sm text-red-800">{error}</p>}
    {notice && <p role="status" className="mt-3 rounded bg-violet-50 p-3 text-sm">{notice}</p>}
    {feed && <form className="mt-4 space-y-3 border-b pb-5" onSubmit={event => {
      event.preventDefault();
      try {void write("alert-feed", feedApproval(feed, revision, true, seconds));} catch (error) {setError(message(error));}
    }}>
      <p className="text-sm font-medium">{feed.enabled ? "Alert feed enabled" : "Alert feed paused"} · {feed.phase.replaceAll("_", " ")}</p>
      <p className="text-xs text-slate-500">Last successful source read: {date(feed.last_success_at)} · Next read: {feed.enabled ? date(feed.next_run_at) : "Paused"}</p>
      {feed.last_error && <p className="text-sm text-amber-800">Source read failed: {feed.last_error}. History is retained; missing data is not recovery.</p>}
      <label className="block max-w-xs text-sm">Alert polling interval (seconds)
        <Input type="number" required min={60} max={3600} step={1} disabled={busy} value={seconds} onChange={event => setSeconds(Number(event.target.value))} /></label>
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !enabled}>{feed.enabled ? "Save alert feed" : "Enable alert feed"}</Button>
        {feed.enabled && <Button type="button" variant="outline" disabled={busy} onClick={() => void write("alert-feed", feedApproval(feed, revision, false, feed.interval_seconds))}>Pause alert feed and investigation</Button>}
      </div>
      {!enabled && <p className="text-sm">Enable the scoped connection first.</p>}
      <p className="text-xs text-slate-500">Enabling approves recurring read-only source queries, not AI spending. Connection changes pause this feed. Silence or closure stops automatic investigation; acknowledgement does not. A stopped episode never restarts automatically.</p>
      <Link className="inline-block text-sm text-violet-700 underline" href="/settings/ai/autonomy">Configure automatic investigation policy</Link>
    </form>}
    {view ? <div className="mt-4 space-y-3">
      <p className="text-sm">{view.total} retained source events</p>
      {!view.items.length && <p className="text-sm text-slate-600">No source events imported yet. Enable the feed after reviewing your asset mappings.</p>}
      {view.items.map(row => <article key={row.id} className="rounded-lg border p-4">
        <h3 className="break-words font-medium">{row.title}</h3>
        <p className="mt-1 text-sm">{externalAlertLabel(row)} · Source severity {row.native_severity}</p>
        <p className="mt-2 text-xs text-slate-500">Source event {row.source_event_id} · {row.mapping} · Checked {date(row.checked_at)}</p>
        {row.stopped_at && <p className="mt-2 text-sm text-amber-800">Automatic investigation stopped: {row.stop_reason}</p>}
        {!row.alert_id && <p className="mt-2 text-xs">No native alert or AI run. Review asset mapping; multi-host events remain source evidence only.</p>}
        <div className="mt-3 flex flex-wrap gap-3 items-center">
          {row.alert_id && <Link className="text-sm text-violet-700 underline" href={`/alerts?alert=${encodeURIComponent(row.alert_id)}`}>View native alert</Link>}
          <Button variant="outline" disabled={busy || !!row.stopped_at || row.source_state === "resolved"}
            onClick={() => void write(`external-alerts/${row.id}/silence`, {expected_revision: revision,
              expected_event_checked_at: row.checked_at, confirm: true}, "POST")}>Silence AI for this episode</Button>
        </div>
      </article>)}
      <p className="text-xs text-slate-500">“Silence AI” stops iCheck investigation only; it does not silence source notifications. Source-side suppression and closure are checked before AI/tool execution and on polling. An already in-flight request may finish.</p>
      <div className="flex gap-2"><Button variant="outline" disabled={busy || offset === 0} onClick={() => {setView(null); setOffset(offset - 50);}}>Previous alerts</Button>
        <Button variant="outline" disabled={busy || offset + 50 >= view.total} onClick={() => {setView(null); setOffset(offset + 50);}}>Next alerts</Button></div>
    </div> : <p role="status" className="mt-4 text-sm">Loading external alert status…</p>}
  </section>;
}
