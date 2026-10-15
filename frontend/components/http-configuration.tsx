"use client";
import {FormEvent, useEffect, useRef, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {type HTTPMonitorSpec, type HTTPMetric, templateSummary, testedTemplate} from "@/lib/http-monitor";
import {Button} from "@/components/ui/button";

type Props = {spec?: HTTPMonitorSpec; port: number | null; credential: string | null; status: string;
  proof: Record<string, unknown>; canWrite: boolean; onSave: (spec: HTTPMonitorSpec, port: number, credential: string | null) => Promise<void>};
const input = "mt-1 block w-full rounded border border-slate-300 bg-white p-2 text-xs disabled:bg-slate-100";
const blankMetric = (): HTTPMetric => ({name: "", type: "gauge", value_pointer: ""});

export function HTTPConfiguration(props: Props) {
  const [mode, setMode] = useState<"api" | "probe">(props.spec?.mode || "api");
  const [scheme, setScheme] = useState<"http" | "https">(props.spec?.scheme || "https");
  const [path, setPath] = useState(props.spec?.path || "/");
  const [port, setPort] = useState(String(props.port || 443));
  const [auth, setAuth] = useState<HTTPMonitorSpec["auth_mode"]>(props.spec?.auth_mode || "none");
  const [credential, setCredential] = useState(props.credential || "");
  const [header, setHeader] = useState(props.spec?.credential_header || "X-API-Key");
  const [serverName, setServerName] = useState(props.spec?.server_name || "");
  const [method, setMethod] = useState<"GET" | "HEAD">(props.spec?.method || "GET");
  const [statuses, setStatuses] = useState((props.spec?.expected_statuses || [200]).join(","));
  const [metrics, setMetrics] = useState<HTTPMetric[]>(props.spec?.metrics.length ? props.spec.metrics : [blankMetric()]);
  const [refs, setRefs] = useState<Array<{id: string; name: string; kind: string; site: string; enabled: boolean}>>([]);
  const [curl, setCurl] = useState(""); const [busy, setBusy] = useState(false); const [notice, setNotice] = useState("");
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    apiFetch<typeof refs>("/device-credentials").then(rows => {if (alive.current) setRefs(rows);}).catch(() => {});
    return () => {alive.current = false;};
  }, []);
  const draft: HTTPMonitorSpec = {...props.spec, mode, scheme, method: mode === "api" ? "GET" : method, path, auth_mode: auth,
    credential_header: header, server_name: serverName || null, expected_statuses: statuses.split(",").map(value => Number(value.trim())),
    metrics: mode === "api" ? metrics : []};
  const summary = templateSummary(draft);
  const tested = testedTemplate(props.status, props.proof, props.spec);
  const disabled = !props.canWrite || busy || props.status === "running";
  const compatible = refs.filter(ref => ref.enabled && ref.kind === (auth === "basic" ? "http_basic" : "https_token"));
  function changeMetric(index: number, change: Partial<HTTPMetric>) {setMetrics(old => old.map((row, i) => i === index ? {...row, ...change} : row));}
  async function parse() {
    const command = curl; setCurl(""); setBusy(true); setNotice("");
    try {
      const parsed = await apiFetch<{host: string; port: number; request: HTTPMonitorSpec}>("/assets/http-monitor/preview-request", {method: "POST", body: JSON.stringify({curl: command})});
      if (!alive.current) return;
      setScheme(parsed.request.scheme); setPath(parsed.request.path); setPort(String(parsed.port)); setMethod(parsed.request.method);
      setServerName(!/^\d+\.\d+\.\d+\.\d+$/.test(parsed.host) && !parsed.host.includes(":") ? parsed.host : "");
      setNotice("Request parsed, not tested. It will connect only to this device’s registered IP; the URL host is used for TLS/Host validation.");
    } catch (cause) {if (alive.current) setNotice(cause instanceof Error ? cause.message : "Request could not be parsed");}
    finally {if (alive.current) setBusy(false);}
  }
  async function save(event: FormEvent) {
    event.preventDefault(); if (disabled) return;
    setBusy(true); setNotice("");
    try {await props.onSave(draft, Number(port), auth === "none" ? null : credential || null);
      if (alive.current) setNotice("Template saved; a target metric test is queued. Continuous collection still needs your approval after that test succeeds.");}
    catch (cause) {if (alive.current) setNotice(cause instanceof Error ? cause.message : "Template save failed");}
    finally {if (alive.current) setBusy(false);}
  }
  return <section aria-label="HTTP/API monitoring template" className="mt-3 rounded-lg border p-3">
    <h3 className="text-sm font-semibold">HTTP/API monitoring template</h3>
    <p className="mt-1 text-xs text-muted-foreground">Select numeric JSON measurements or test HTTP availability. No shell commands or generated code are executed.</p>
    <p role="status" className="mt-2 text-xs">{props.status === "running" ? "Testing the selected target…" : tested ? `Saved template’s target test succeeded: ${Number(props.proof.metric_samples) || 0} mapped samples. Unsaved edits are not tested; this is not proof of continuous collection.` : "Current template has no successful metric-query test. TCP connectivity alone is not sufficient."}</p>
    <form onSubmit={save} className="mt-3 space-y-3">
      <fieldset disabled={disabled} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs">Monitor<select className={input} value={mode} onChange={e => setMode(e.target.value as typeof mode)}><option value="api">API JSON measurements</option><option value="probe">HTTP availability</option></select></label>
          <label className="text-xs">Transport<select className={input} value={scheme} onChange={e => {setScheme(e.target.value as typeof scheme); if (port === "443" || port === "80") setPort(e.target.value === "https" ? "443" : "80");}}><option value="https">HTTPS (certificate verified)</option><option value="http">HTTP (anonymous, protected gateway exception required)</option></select></label>
          <label className="text-xs">Request path<input className={input} required maxLength={2048} value={path} onChange={e => setPath(e.target.value)} placeholder="/api/stats" /></label>
          <label className="text-xs">Port<input className={input} type="number" required min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} /></label>
          <label className="text-xs">Authentication<select className={input} value={auth} onChange={e => {setAuth(e.target.value as typeof auth); setCredential("");}}><option value="none">No authentication</option><option value="bearer">Bearer token</option><option value="basic">Username / password</option><option value="api_key">API-key header</option></select></label>
          {auth !== "none" && <label className="text-xs">Protected credential reference<select className={input} required value={credential} onChange={e => setCredential(e.target.value)}><option value="">Select a saved credential</option>{compatible.map(ref => <option key={ref.id} value={ref.id}>{ref.name} ({ref.site})</option>)}</select></label>}
        </div>
        {auth !== "none" && <p className="text-xs text-muted-foreground">Save credentials in <a className="underline" href="/settings/credentials">Credentials settings</a>. Values are never entered here or in chat. Authentication requires HTTPS.</p>}
        {mode === "api" && <div className="space-y-2"><h4 className="text-xs font-semibold">Expected numeric metrics</h4>{metrics.map((metric, index) => <div key={index} className="grid gap-2 rounded border p-2 sm:grid-cols-2">
          <label className="text-xs">Metric name<input className={input} required maxLength={128} value={metric.name} onChange={e => changeMetric(index, {name: e.target.value})} placeholder="vendor_queue_depth" /></label>
          <label className="text-xs">JSON Pointer<input className={input} required maxLength={512} value={metric.value_pointer} onChange={e => changeMetric(index, {value_pointer: e.target.value})} placeholder="/queue/depth" /></label>
          <label className="text-xs">Type<select className={input} value={metric.type} onChange={e => changeMetric(index, {type: e.target.value as HTTPMetric["type"]})}><option value="gauge">Gauge (current measurement)</option><option value="counter">Counter (cumulative total)</option></select></label>
          <label className="text-xs">Records array pointer (optional)<input className={input} maxLength={512} value={metric.records_pointer || ""} onChange={e => changeMetric(index, {records_pointer: e.target.value || null})} placeholder="/ports" /></label>
          <details className="sm:col-span-2"><summary className="cursor-pointer text-xs">Advanced metric labels</summary><p className="mt-1 text-xs">Array records need labels that distinguish each series. Credential fields are rejected.</p>
            {Object.entries(metric.labels || {}).map(([name, pointer], position) => <div key={position} className="mt-2 grid gap-2 sm:grid-cols-2">
              <label className="text-xs">Label name<input className={input} maxLength={64} value={name} onChange={e => changeMetric(index, {labels: Object.fromEntries(Object.entries(metric.labels || {}).map(([key, value], i) => [i === position ? e.target.value : key, value]))})} /></label>
              <label className="text-xs">Label JSON Pointer<input className={input} maxLength={512} value={pointer} onChange={e => changeMetric(index, {labels: {...metric.labels, [name]: e.target.value}})} /></label>
              <Button type="button" variant="outline" size="sm" onClick={() => changeMetric(index, {labels: Object.fromEntries(Object.entries(metric.labels || {}).filter(([key]) => key !== name))})}>Remove label</Button>
            </div>)}
            <Button type="button" size="sm" variant="outline" className="mt-2" disabled={Object.keys(metric.labels || {}).length >= 8}
              onClick={() => {let next = 1; while (`label_${next}` in (metric.labels || {})) next++; changeMetric(index, {labels: {...metric.labels, [`label_${next}`]: ""}});}}>Add label</Button>
          </details>
          {metrics.length > 1 && <Button type="button" variant="outline" size="sm" onClick={() => setMetrics(old => old.filter((_, i) => i !== index))}>Remove metric</Button>}
        </div>)}<Button type="button" size="sm" variant="outline" disabled={metrics.length >= 32} onClick={() => setMetrics(old => [...old, blankMetric()])}>Add metric</Button></div>}
        <details><summary className="cursor-pointer text-xs">Advanced request details</summary><div className="mt-2 space-y-2">
          <label className="block text-xs">Certificate / Host name (optional, connection stays pinned to device IP)<input className={input} maxLength={253} value={serverName} onChange={e => setServerName(e.target.value)} /></label>
          <label className="block text-xs">Successful HTTP status codes (comma separated)<input className={input} required maxLength={100} value={statuses} onChange={e => setStatuses(e.target.value)} /></label>
          {auth === "api_key" && <label className="block text-xs">API-key header name<input className={input} maxLength={64} value={header} onChange={e => setHeader(e.target.value)} /></label>}
          {mode === "probe" && <label className="block text-xs">Method<select className={input} value={method} onChange={e => setMethod(e.target.value as typeof method)}><option value="GET">GET</option><option value="HEAD">HEAD</option></select></label>}
          <label className="block text-xs">Import a credential-free curl GET/HEAD request<textarea className={input} maxLength={8192} value={curl} onChange={e => setCurl(e.target.value)} placeholder="curl -sS https://api.example.test/stats" /></label>
          <Button type="button" size="sm" variant="outline" disabled={!curl.trim()} onClick={() => void parse()}>Preview request only</Button>
        </div></details>
        <div className="rounded bg-slate-50 p-2 text-xs"><p>{summary.request}</p><p className="mt-1">Expected: {summary.metrics.join("; ")}</p><p className="mt-1">Saving withdraws the old collection approval and queues a new target test.</p></div>
        <Button size="sm" disabled={disabled || (auth !== "none" && (!credential || scheme !== "https"))}>Save template and test target</Button>
      </fieldset>
    </form>
    {notice && <p role="status" className="mt-2 text-xs">{notice}</p>}
  </section>;
}
