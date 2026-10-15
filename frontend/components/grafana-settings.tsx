"use client";

import {FormEvent, useCallback, useEffect, useRef, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {canManageGrafana, type GrafanaConnection, type GrafanaPrincipal} from "@/lib/grafana-plugin";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";

type Setup = {storage_ready: boolean; connections: GrafanaConnection[]; warning: string};

export function GrafanaSettings() {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [principal, setPrincipal] = useState<GrafanaPrincipal | null>(null);
  const [name, setName] = useState("native-grafana");
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:3001/grafana");
  const [publicUrl, setPublicUrl] = useState("");
  const [source, setSource] = useState("icheck-prometheus");
  const [folder, setFolder] = useState("icheck");
  const [token, setToken] = useState("");
  const [rotations, setRotations] = useState<Record<string, string>>({});
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [secure, setSecure] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const epoch = useRef(0);
  const reload = useCallback(async () => {
    const current = epoch.current;
    try {
      const [next, identity] = await Promise.all([apiFetch<Setup>("/grafana/setup"), apiFetch<GrafanaPrincipal>("/auth/me")]);
      if (current === epoch.current) {setSetup(next); setPrincipal(identity);}
    } catch (error) {if (current === epoch.current) setNotice(error instanceof Error ? error.message : "Unable to load Grafana settings");}
  }, []);
  useEffect(() => {
    const context = epoch;
    const reset = () => {epoch.current++; setToken(""); setRotations({}); setAcknowledged(false); setSetup(null); setPrincipal(null); setBusy(false); setNotice(null); void reload();};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => {
      setPublicUrl(window.location.origin + "/grafana/");
      setSecure(window.location.protocol === "https:" || ["localhost", "127.0.0.1"].includes(window.location.hostname));
      void reload();
    }, 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {context.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [reload]);
  const manage = canManageGrafana(principal);
  async function run(action: () => Promise<string>) {
    if (busy) return;
    const current = epoch.current; setBusy(true); setNotice(null);
    try {const text = await action(); if (current === epoch.current) {setNotice(text); await reload();}}
    catch (error) {if (current === epoch.current) setNotice(error instanceof Error ? error.message : "Grafana operation failed");}
    finally {if (current === epoch.current) setBusy(false);}
  }
  async function connect(event: FormEvent) {
    event.preventDefault();
    if (!manage || !secure || !acknowledged || !setup?.storage_ready || token.length < 10) return;
    const submitted = token; setToken("");
    await run(async () => {await apiFetch("/grafana/connections", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, api_url: apiUrl, public_url: publicUrl, datasource_uid: source,
        folder_uid: folder, token: submitted, shared_dataset_acknowledged: true})}); return "Grafana connection saved. The token is encrypted server-side.";});
  }
  return <section className="space-y-5 rounded-xl border bg-white p-5">
    <div><h2 className="text-lg font-semibold">Grafana connection</h2><p className="mt-2 text-sm text-muted-foreground">Use a separate Grafana service-account token with managed-folder editing rights. Your web password is not an API token.</p></div>
    {notice ? <p role="status" className="rounded border bg-slate-50 p-3 text-sm">{notice}</p> : null}
    {setup?.connections.map(row => <article key={row.id} className="space-y-3 rounded-lg border p-4 text-sm">
      <h3 className="font-medium">{row.name} · {row.enabled ? "Enabled" : "Disabled"}</h3>
      <p>{row.public_url} · Token {row.token_configured ? "configured" : "missing"}</p>
      <div className="flex flex-wrap gap-2"><Button variant="outline" disabled={busy} onClick={() => void run(async () => {
        const health = await apiFetch<{database: string; datasource_status: string}>(`/grafana/connections/${row.id}/health`);
        return `Grafana database: ${health.database}; Prometheus source: ${health.datasource_status}. This is not device collection proof.`;
      })}>Check connection</Button>{manage ? <Button variant="outline" disabled={busy} onClick={() => void run(async () => {
        await apiFetch(`/grafana/connections/${row.id}`, {method: "PUT", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({expected_revision: row.revision, enabled: !row.enabled})});
        return row.enabled ? "AI Grafana integration disabled. Grafana and collection services are unchanged." : "Grafana integration enabled.";
      })}>{row.enabled ? "Disable integration" : "Enable integration"}</Button> : null}</div>
      {manage ? <details><summary className="cursor-pointer">Rotate service token</summary>
        <form className="mt-3 flex flex-wrap gap-2" onSubmit={event => {event.preventDefault(); if (!secure || !rotations[row.id] || busy) return;
          const submitted = rotations[row.id]; setRotations(current => ({...current, [row.id]: ""})); void run(async () => {await apiFetch(`/grafana/connections/${row.id}`, {
            method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({expected_revision: row.revision, enabled: row.enabled, token: submitted})});
            return "Token rotated. Pending proposals require fresh review.";});}}>
          <label className="min-w-52 flex-1">New service token<Input aria-label={`New service token for ${row.name}`} type="password" autoComplete="off" value={rotations[row.id] || ""} onChange={event => setRotations(current => ({...current, [row.id]: event.target.value}))} /></label>
          <Button disabled={!secure || busy || (rotations[row.id] || "").length < 10}>Rotate token</Button>
        </form></details> : null}
    </article>)}
    {manage ? <form onSubmit={event => void connect(event)} className="space-y-4">
      <label className="block text-sm">Connection name<Input value={name} onChange={event => setName(event.target.value)} required maxLength={128} /></label>
      <label className="block text-sm">Grafana browser URL<Input value={publicUrl} onChange={event => setPublicUrl(event.target.value)} required /></label>
      <label className="block text-sm">Service-account token<Input type="password" autoComplete="off" value={token} onChange={event => setToken(event.target.value)} required maxLength={4096} /></label>
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />
        This trusted engineering workspace may read the shared metric dataset. Dashboard variables and folders do not enforce device-level isolation.</label>
      <details><summary className="cursor-pointer text-sm">Advanced connection details</summary><div className="mt-3 space-y-3 text-sm">
        <label className="block">Server-side API URL<Input value={apiUrl} onChange={event => setApiUrl(event.target.value)} /></label>
        <label className="block">Prometheus data-source UID<Input value={source} onChange={event => setSource(event.target.value)} /></label>
        <label className="block">Managed folder UID<Input value={folder} onChange={event => setFolder(event.target.value)} /></label>
      </div></details>
      <Button disabled={busy || !secure || !setup?.storage_ready || !acknowledged || token.length < 10}>Save Grafana connection</Button>
      {!setup?.storage_ready ? <p className="text-sm text-amber-700">Protected integration key storage must be provisioned by the installer.</p> : null}
      {!secure ? <p className="text-sm text-amber-700">Open the protected HTTPS GUI before entering a service token.</p> : null}
    </form> : <p className="text-sm text-muted-foreground">Global metrics.manage permission is required to configure this integration.</p>}
  </section>;
}
