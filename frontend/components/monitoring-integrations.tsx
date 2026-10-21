"use client";

import Link from "next/link";
import {FormEvent, ReactNode, useCallback, useEffect, useRef, useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {IntegrationScheduleForm} from "@/components/integration-schedule";
import {IntegrationMapping} from "@/components/integration-mapping";
import {IntegrationAlerts} from "@/components/integration-alerts";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {advanceSync, resumable, syncLabel, type Integration, type IntegrationSync, type ImportedResources, type IntegrationSchedule} from "@/lib/monitoring-integrations";

const BASE = "/integrations/connections";
const providers: Record<string, string> = {zabbix: "Zabbix", solarwinds_orion: "SolarWinds Platform / Orion", rest_webhook: "REST / webhook bridge"};
const card = "rounded-xl border border-slate-200 bg-white p-5 sm:p-6";
const post = <T,>(path: string, body: unknown, method = "POST") => apiFetch<T>(path,
  {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
const message = (error: unknown) => error instanceof Error ? error.message : "The integration request failed";
type Preview = {items: {ref: {remote_id: string}; name: string; monitoring_enabled: boolean}[]; truncated: boolean};
type Groups = {items: {id: string; name: string}[]; truncated: boolean};

function Frame({title, children}: {title: string; children: ReactNode}) {
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <nav aria-label="Integration navigation" className="flex flex-wrap gap-4 text-sm text-violet-700">
      <Link href="/">AI Operator</Link><Link href="/monitoring">Monitoring</Link><Link href="/integrations">Integrations</Link>
    </nav><header><h1 className="break-words text-2xl font-semibold">{title}</h1>
      <p className="mt-2 text-sm text-slate-600">Bring in resources from your monitoring products. Keep their collection and history at the source.</p></header>{children}
  </div></main>;
}

// Invalidate pending responses, drafts and the sync loop on workspace changes.
function useBoundary(epoch: {current: number}, reset: () => void, identity = "catalog") {
  useEffect(() => {
    const context = epoch;
    const refresh = () => {context.current++; reset();};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) refresh();};
    const timer = window.setTimeout(refresh, 0);
    window.addEventListener("icheck:namespace-changed", refresh); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", refresh); window.removeEventListener("storage", storage);};
  }, [epoch, reset, identity]);
}

export function IntegrationLibrary() {
  const [rows, setRows] = useState<Integration[]>([]);
  const [offset, setOffset] = useState(0);
  const [name, setName] = useState(""); const [url, setUrl] = useState(""); const [token, setToken] = useState("");
  const [provider, setProvider] = useState("zabbix");
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const submitting = useRef(false);
  const reset = useCallback(() => {setRows([]); setName(""); setUrl(""); setToken(""); setUsername(""); setPassword(""); setError(""); setBusy(false); submitting.current = false; setLoading(true); setOffset(0); setRefresh(n => n + 1);}, []);
  const epoch = useRef(0);
  useBoundary(epoch, reset);
  useEffect(() => {
    const serial = epoch.current;
    let active = true;
    const timer = window.setTimeout(() => {
      void apiFetch<Integration[]>(`${BASE}?limit=25&offset=${offset}`).then(value => {
        if (active && serial === epoch.current) setRows(value);
      }).catch(error => {if (active && serial === epoch.current) setError(message(error));})
        .finally(() => {if (active && serial === epoch.current) setLoading(false);});
    }, 1);
    return () => {active = false; window.clearTimeout(timer);};
  }, [offset, refresh, epoch]);
  async function create(event: FormEvent) {
    event.preventDefault(); if (submitting.current) return;
    const serial = epoch.current; submitting.current = true; setBusy(true); setError("");
    try {
      const row = await post<Integration>(BASE, {name, api_url: url, provider, ...(provider === "solarwinds_orion" ? {username, password} : {token})});
      if (serial === epoch.current) {setToken(""); window.location.assign(`/integrations/${encodeURIComponent(row.id)}`);}
    } catch (error) {if (serial === epoch.current) setError(message(error));}
    finally {if (serial === epoch.current) {setToken(""); setPassword(""); setBusy(false); submitting.current = false;}}
  }
  return <Frame title="Monitoring integrations">
    {error && <p role="alert" className="rounded-lg bg-red-50 p-4 text-red-800">{error}</p>}
    <section className={card}><h2 className="font-semibold">Your connections</h2>
      {loading ? <p role="status" className="mt-3">Loading connections…</p> : !rows.length ? <p className="mt-3 text-slate-600">No connections on this page.</p> :
        <div className="mt-4 grid gap-3 sm:grid-cols-2">{rows.map(row => <Link key={row.id} href={`/integrations/${encodeURIComponent(row.id)}`} className="rounded-lg border p-4 hover:border-violet-500">
          <h3 className="break-words font-medium">{row.name}</h3><p className="mt-2 text-sm text-slate-600">{providers[row.provider]} · {row.enabled ? "Enabled" : "Disabled"} · {row.group_ids.length} groups</p>
          <span className="mt-3 block text-sm text-violet-700">Manage connection →</span></Link>)}</div>}
      <div className="mt-4 flex gap-2"><Button variant="outline" disabled={loading || offset === 0} onClick={() => {setOffset(offset - 25); setLoading(true);}}>Previous</Button>
        <Button variant="outline" disabled={loading || rows.length < 25} onClick={() => {setOffset(offset + 25); setLoading(true);}}>Next</Button></div>
    </section>
    <section className={card}><h2 className="font-semibold">Connect a monitoring product</h2><p className="mt-2 text-sm text-slate-600">Save first, then choose source groups. Nothing is queried or imported when you save.</p>
      <form onSubmit={create} className="mt-4 space-y-4"><fieldset disabled={busy} className="grid gap-4 sm:grid-cols-2">
        <label className="text-sm sm:col-span-2">Product<select className="mt-1 block w-full rounded border p-2" value={provider} onChange={e => {setProvider(e.target.value); setToken(""); setPassword(""); setUsername(""); setUrl("");}}>
          {Object.entries(providers).map(([id, title]) => <option key={id} value={id}>{title}</option>)}</select></label>
        <label className="text-sm">Connection name<Input required maxLength={128} value={name} onChange={e => setName(e.target.value)} /></label>
        <label className="text-sm">HTTPS API URL<Input required type="url" value={url} placeholder={provider === "solarwinds_orion" ? "https://orion.example.test:17774" : provider === "rest_webhook" ? "https://bridge.example.test/read" : "https://zabbix.example.test/zabbix"} onChange={e => setUrl(e.target.value)} /></label>
        {provider === "solarwinds_orion" ? <><label className="text-sm">Read-only SWIS username<Input required autoComplete="off" maxLength={255} value={username} onChange={e => setUsername(e.target.value)} /></label>
          <label className="text-sm">SWIS password<Input required type="password" autoComplete="new-password" maxLength={2048} value={password} onChange={e => setPassword(e.target.value)} /></label></> :
          <label className="text-sm sm:col-span-2">Read-only API token<Input required type="password" autoComplete="new-password" minLength={16} maxLength={4096} value={token} onChange={e => setToken(e.target.value)} /></label>}
        <Button type="submit">{busy ? "Saving…" : "Save connection"}</Button>
      </fieldset></form><p className="mt-3 text-xs text-slate-500">The server administrator must approve the HTTPS origin. Tokens are encrypted, never displayed again, and never stored in the browser.</p>
    </section><p className="text-sm text-slate-500">Orion supports node alerts and response-time history through SWIS v3, not SolarWinds SaaS. The REST bridge requires the icheck.monitoring-bridge/v1 contract. Live compatibility must be checked against your product version.</p>
  </Frame>;
}

export function IntegrationDetail({id}: {id: string}) {
  const path = `${BASE}/${encodeURIComponent(id)}`;
  const [connection, setConnection] = useState<Integration | null>(null);
  const [schedule, setSchedule] = useState<IntegrationSchedule | null>(null);
  const [runs, setRuns] = useState<IntegrationSync[]>([]); const [resources, setResources] = useState<ImportedResources | null>(null);
  const [groups, setGroups] = useState<Groups | null>(null); const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState(""); const [token, setToken] = useState("");
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [tab, setTab] = useState("setup"); const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false); const [notice, setNotice] = useState(""); const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const seenRevision = useRef(""); const reads = useRef(0);
  const submitting = useRef(false); const stopped = useRef(false);
  const reset = useCallback(() => {setConnection(null); setSchedule(null); setRuns([]); setResources(null); setGroups(null); setSelected([]); setPreview(null);
    setSearch(""); setToken(""); setUsername(""); setPassword(""); setBusy(false); setError(""); setNotice(""); seenRevision.current = ""; submitting.current = false; stopped.current = true; setOffset(0); setRefresh(n => n + 1);}, []);
  const epoch = useRef(0);
  useBoundary(epoch, reset, id);
  const read = useCallback(async (serial: number) => {
    const request = ++reads.current;
    const [row, history, items, savedSchedule] = await Promise.all([apiFetch<Integration>(path), apiFetch<IntegrationSync[]>(`${path}/syncs`),
      apiFetch<ImportedResources>(`${path}/resources?limit=50&offset=${offset}`), apiFetch<IntegrationSchedule>(`${path}/schedule`)]);
    if (serial !== epoch.current || request !== reads.current) return;
    if (seenRevision.current !== `${row.id}:${row.revision}`) {setSelected(row.group_ids); setPreview(null); seenRevision.current = `${row.id}:${row.revision}`;}
    setConnection(row); setRuns(history); setResources(items); setSchedule(savedSchedule);
  }, [path, offset, epoch]);
  useEffect(() => {
    const serial = epoch.current;
    let active = true;
    const timer = window.setTimeout(() => {if (active) void read(serial).catch(error => {if (active && serial === epoch.current) setError(message(error));});}, 1);
    return () => {active = false; window.clearTimeout(timer);};
  }, [read, refresh, epoch]);
  useEffect(() => {
    if (!schedule?.enabled) return;
    const serial = epoch.current;
    // GET status only. The browser never dispatches scheduled source operations.
    const timer = window.setInterval(() => {if (!submitting.current) void read(serial).catch(error => {
      if (serial === epoch.current) setError(message(error));
    });}, 10_000);
    return () => window.clearInterval(timer);
  }, [schedule?.enabled, read]);
  async function act(action: (serial: number) => Promise<void>) {
    if (submitting.current) return;
    const serial = epoch.current; submitting.current = true; stopped.current = false; setBusy(true); setError(""); setNotice("");
    try {await action(serial); if (serial === epoch.current) await read(serial);}
    catch (error) {if (serial === epoch.current) {setError(message(error)); await read(serial).catch(() => {});}}
    finally {if (serial === epoch.current) {setToken(""); setBusy(false); submitting.current = false;}}
  }
  const latest = runs[0] || null;
  const dirty = !!connection && [...selected].sort().join(",") !== [...connection.group_ids].sort().join(",");
  const confirm = {expected_revision: connection?.revision, confirm: true};
  async function sync(serial: number) {
    if (!connection) return;
    let row = connection;
    if (!row.enabled) {
      row = await post<Integration>(path, {expected_revision: row.revision, enabled: true}, "PUT");
      if (serial !== epoch.current) return;
      setConnection(row);
    }
    let run = await post<IntegrationSync>(`${path}/syncs`, {expected_revision: row.revision, confirm: true});
    if (serial !== epoch.current) return;
    setTab("resources"); setRuns(history => [run, ...history.filter(item => item.id !== run.id)]);
    if (run.status !== "failed" || run.can_resume) {
      run = await advanceSync(run, current => post<IntegrationSync>(`${path}/syncs/${current.id}/step`, {
        expected_revision: row.revision, expected_cursor: current.cursor, confirm: true}),
      () => stopped.current || serial !== epoch.current,
      current => setRuns(history => [current, ...history.filter(item => item.id !== current.id)]));
    }
    if (serial === epoch.current) setNotice(syncLabel(run));
  }
  return <Frame title={connection?.name || "Monitoring connection"}>
    {error && <p role="alert" className="rounded-lg bg-red-50 p-4 text-red-800">{error}</p>}
    {notice && <p role="status" className="rounded-lg bg-violet-50 p-4 text-sm text-violet-900">{notice}</p>}
    {!connection ? <p role="status">{error ? "Connection unavailable." : "Loading connection…"}</p> : <>
      <section className={card}><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold">{connection.enabled ? "Enabled" : "Disabled"}</h2>
        <p className="mt-1 break-all text-sm text-slate-500">{connection.api_url}</p></div><Button variant="outline" disabled={busy} onClick={() => void act(async () => {})}>Refresh</Button></div>
        <p className="mt-3 text-sm">{latest && latest.connection_revision !== connection.revision ? "Configuration changed · start a new sync" : syncLabel(latest)}</p><p className="mt-1 text-xs text-slate-500">A completed scan does not prove device health or delete missing resources. Pause automatic sync to run manually.</p>
        <div className="mt-4 flex flex-wrap gap-3"><Button disabled={busy || dirty || !connection.group_ids.length || !schedule || schedule.enabled} onClick={() => void act(sync)}>
          {resumable(latest, connection) ? "Resume sync" : connection.enabled ? "Sync resources" : "Enable and sync resources"}</Button>
          {busy && <Button variant="outline" onClick={() => {stopped.current = true; setNotice("Pausing after the current request. Imported results are retained.");}}>Pause after this request</Button>}
          {connection.enabled && <Button variant="outline" disabled={busy} onClick={() => void act(async serial => {
            await post(path, {...confirm, confirm: undefined, enabled: false}, "PUT"); if (serial === epoch.current) {setPreview(null); setNotice("Disabled. Source history is retained; no recurring work is running.");}
          })}>Disable connection</Button>}</div>
      </section>
      {schedule && <IntegrationScheduleForm key={`${connection.id}:${schedule.revision}`} schedule={schedule} busy={busy}
        canEnable={!dirty && !!connection.group_ids.length} onSave={(enabled, interval, retention) => void act(async serial => {
          let row = connection; let scheduleRevision = schedule.revision;
          if (enabled && !row.enabled) {
            row = await post<Integration>(path, {expected_revision: row.revision, enabled: true}, "PUT");
            if (serial !== epoch.current) return;
            if (scheduleRevision) scheduleRevision++;
          }
          await post(`${path}/schedule`, {expected_revision: row.revision, expected_schedule_revision: scheduleRevision,
            confirm: true, enabled, interval_seconds: interval, retention_days: retention}, "PUT");
          if (serial === epoch.current) setNotice(enabled ? "Automatic sync approved. The server worker will process the saved groups." : "Automatic sync paused. Imported inventory and resumable progress are retained.");
        })} />}
      <nav aria-label="Connection sections" className="flex flex-wrap gap-2">{[["setup", "Setup & preview"], ["resources", "Imported resources"], ["mapping", "Asset mapping"], ["alerts", "External alerts"], ["history", "Sync history"]].map(([key, label]) =>
        <Button key={key} variant={tab === key ? "default" : "outline"} aria-pressed={tab === key} onClick={() => setTab(key)}>{label}</Button>)}</nav>
      {tab === "alerts" && <IntegrationAlerts key={`${connection.id}:${connection.revision}`} path={path} revision={connection.revision} enabled={connection.enabled} epochRef={epoch} />}
      {tab === "setup" && <section className={card}><h2 className="font-semibold">Choose source groups</h2><p className="mt-2 text-sm text-slate-600">Select groups once, not devices individually. Loading groups contacts {providers[connection.provider]}; saving your selection does not.</p>
        <form className="mt-4 flex flex-wrap gap-2" onSubmit={event => {event.preventDefault(); void act(async serial => {
          const result = await post<Groups>(`${path}/groups`, {...confirm, search}); if (serial === epoch.current) setGroups(result);
        });}}><label className="min-w-0 flex-1 text-sm">Find groups<Input value={search} maxLength={128} onChange={event => setSearch(event.target.value)} /></label>
          <Button variant="outline" disabled={busy} className="self-end">Load groups</Button></form>
        <div className="mt-4 grid max-h-72 gap-2 overflow-y-auto sm:grid-cols-2">{groups?.items.map(group => <label key={group.id} className="flex items-start gap-2 rounded-lg border p-3 text-sm">
          <input type="checkbox" disabled={busy} checked={selected.includes(group.id)} onChange={event => setSelected(ids => event.target.checked ? [...ids, group.id] : ids.filter(id => id !== group.id))} /><span className="break-all">{group.name}</span></label>)}</div>
        {groups?.truncated && <p className="mt-2 text-xs text-amber-800">More groups exist. Narrow your search; previously selected groups remain selected.</p>}
        <p className="mt-3 text-sm">{selected.length} groups selected{dirty ? " · Unsaved changes" : ""}</p>
        <div className="mt-4 flex flex-wrap gap-2"><Button disabled={busy || !dirty || !selected.length || selected.length > 100} onClick={() => void act(async serial => {
          await post(path, {expected_revision: connection.revision, enabled: connection.enabled, group_ids: selected}, "PUT"); if (serial === epoch.current) setPreview(null);
        })}>Save group selection</Button><Button variant="outline" disabled={busy || dirty || !connection.group_ids.length} onClick={() => void act(async serial => {
          const result = await post<Preview>(`${path}/preview`, confirm); if (serial === epoch.current) setPreview(result);
        })}>Preview resources</Button></div>
        {preview && <div className="mt-5 border-t pt-4"><h3 className="font-medium">Discovery preview · {preview.items.length} resources{preview.truncated ? " (more available)" : ""}</h3>
          <p className="mt-1 text-xs text-slate-500">Nothing has been imported by this preview.</p><ul className="mt-3 space-y-2">{preview.items.map(item => <li key={item.ref.remote_id} className="break-words text-sm">{item.name} · {item.monitoring_enabled ? "Monitoring configured at source" : "Disabled at source"}</li>)}</ul>
          {!preview.items.length && <p className="mt-3 text-sm">No visible resources returned. Check group selection and source permissions.</p>}</div>}
        <details className="mt-6 border-t pt-4"><summary className="cursor-pointer text-sm">Replace saved credential</summary><form className="mt-3 space-y-3" onSubmit={event => {event.preventDefault(); void act(async serial => {
          try {await post(path, {expected_revision: connection.revision, enabled: connection.enabled, ...(connection.provider === "solarwinds_orion" ? {username, password} : {token})}, "PUT"); if (serial === epoch.current) {setPreview(null); setNotice("Credential replaced. Run a new preview before synchronizing.");}}
          finally {if (serial === epoch.current) {setToken(""); setPassword("");}}
        });}}>{connection.provider === "solarwinds_orion" ? <><label className="block text-sm">Read-only SWIS username<Input required maxLength={255} value={username} onChange={event => setUsername(event.target.value)} /></label>
          <label className="block text-sm">New SWIS password<Input required type="password" maxLength={2048} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} /></label></> :
          <label className="block text-sm">New read-only API token<Input type="password" required minLength={16} maxLength={4096} autoComplete="new-password" value={token} onChange={event => setToken(event.target.value)} /></label>}
          <Button variant="outline" disabled={busy || (connection.provider === "solarwinds_orion" ? !username || !password : !token)}>Replace credential</Button></form></details>
      </section>}
      {tab === "resources" && <section className={card}><h2 className="font-semibold">Imported source inventory</h2><p className="mt-2 text-sm text-slate-600">{resources?.total || 0} resources observed under this configuration. Review links to existing assets in Asset mapping; no duplicate collection is started.</p>
        <div className="mt-4 divide-y">{resources?.items.map(item => <article key={item.id} className="py-3"><h3 className="break-words font-medium">{item.name}</h3>
          <p className="mt-1 text-sm text-slate-600">Source ID {item.remote_id} · {item.monitoring_enabled ? "Monitoring configured at source" : "Disabled at source"}</p>
          <p className="mt-1 text-xs text-slate-500">Observed {new Date(item.observed_at).toLocaleString()} · {item.last_run_id === latest?.id ? "Seen in latest scan" : "Retained from an earlier scan; current presence is unconfirmed"} · Device health unknown</p></article>)}</div>
        {!resources?.items.length && <p className="mt-4 text-sm">No resources on this page. Saved history from older configuration revisions is retained, but not presented as current scope.</p>}
        <div className="mt-4 flex gap-2"><Button variant="outline" disabled={busy || !offset} onClick={() => setOffset(offset - 50)}>Previous resources</Button>
          <Button variant="outline" disabled={busy || offset + 50 >= (resources?.total || 0)} onClick={() => setOffset(offset + 50)}>Next resources</Button></div>
      </section>}
      {tab === "mapping" && <IntegrationMapping key={`${connection.id}:${connection.revision}:${latest?.id}:${latest?.status}`} path={path} epochRef={epoch} />}
      {tab === "history" && <section className={card}><h2 className="font-semibold">Recent synchronization history</h2><p className="mt-2 text-xs text-slate-500">Last 20 scans. Saved progress survives page refresh. Enabled schedules continue on the server; manual scans require Resume.</p>
        {runs.map(run => <article key={run.id} className="mt-4 border-t pt-4"><h3 className="text-sm font-medium">{syncLabel(run)}</h3><p className="mt-1 text-xs text-slate-500">{new Date(run.started_at).toLocaleString()} · Configuration revision {run.connection_revision}</p></article>)}
        {!runs.length && <p className="mt-4 text-sm">No synchronization has been started.</p>}</section>}
    </>}
  </Frame>;
}
