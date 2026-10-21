"use client";

import Link from "next/link";
import {useCallback, useEffect, useRef, useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";

type Component = {name: string; kind: string; spec: {provider?: string; mcp_server_name?: string}};
type Package = {format_version: string; name: string; version: string; description: string; components: Component[]; digest_sha256: string};
type Choices = {versions: {id: string; name: string; kind: string; version: number}[]; connections: {id: string; name: string; provider: string}[]; mcp_servers: {name: string}[]};
type Review = {installable: boolean; already_imported: boolean; blockers: string[]; pending_components: string[]; activation: string};
type Receipt = {id: string; name: string; version: string; artifact_version_ids: string[]; status: string; pending: boolean;
  components: {id: string; artifact_id: string; name: string; kind: string; status: string; pending: boolean}[]};
const BASE = "/operations-packages";
const card = "rounded-xl border border-slate-200 bg-white p-5";
const post = <T,>(url: string, body: unknown) => apiFetch<T>(url, {method: "POST", body: JSON.stringify(body)});

function download(content: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], {type: "application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url);
}

export default function OperationPackagesPage() {
  const [builtins, setBuiltins] = useState<Package[]>([]);
  const [choices, setChoices] = useState<Choices>({versions: [], connections: [], mcp_servers: []});
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [selected, setSelected] = useState<Package | null>(null);
  const [builtin, setBuiltin] = useState(false);
  const [signature, setSignature] = useState<unknown>(null);
  const [connections, setConnections] = useState<Record<string, string>>({});
  const [servers, setServers] = useState<Record<string, string>>({});
  const [review, setReview] = useState<Review | null>(null);
  const [versions, setVersions] = useState<string[]>([]);
  const [name, setName] = useState("shared-operations");
  const [version, setVersion] = useState("1.0.0");
  const [description, setDescription] = useState("");
  const [error, setError] = useState(""); const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const reload = useCallback(async (serial: number) => {
    const [catalog, options, history] = await Promise.all([apiFetch<Package[]>(BASE + "/builtins"),
      apiFetch<Choices>(BASE + "/choices"), apiFetch<Receipt[]>(BASE)]);
    if (serial !== epoch.current) return;
    setBuiltins(catalog); setChoices(options); setReceipts(history);
  }, []);
  useEffect(() => {
    const boundary = epoch;
    const reset = () => {
      const serial = ++boundary.current;
      setSelected(null); setSignature(null); setReview(null); setConnections({}); setServers({}); setVersions([]);
      setBuiltins([]); setChoices({versions: [], connections: [], mcp_servers: []}); setReceipts([]);
      setError(""); setNotice(""); setBusy(false);
      void reload(serial).catch(error => {if (serial === epoch.current) setError(error.message);});
    };
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(reset, 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {boundary.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [reload]);
  function select(pack: Package, shipped: boolean, sig: unknown = null) {
    setSelected(pack); setBuiltin(shipped); setSignature(sig); setReview(null); setConnections({}); setServers({}); setNotice(""); setError("");
  }
  async function action(operation: "preview" | "import") {
    if (!selected || busy) return;
    const serial = epoch.current; setBusy(true); setError(""); setNotice("");
    try {
      const path = builtin ? `${BASE}/builtins/${encodeURIComponent(selected.name)}/${operation}` : `${BASE}/${operation}`;
      const payload = {package: selected, signature,
        connections: Object.fromEntries(Object.entries(connections).filter(([, value]) => value)),
        mcp_servers: servers, ...(operation === "import" ? {confirm: true} : {})};
      if (operation === "preview") {const result = await post<Review>(path, payload); if (serial === epoch.current) setReview(result);}
      else {
        await post<Receipt>(path, payload);
        if (serial === epoch.current) {setReview(null); setNotice("Package imported. Components waiting for an included MCP server remain drafts. No tools were registered, devices contacted or schedules started.");}
        await reload(serial);
      }
    } catch (cause) {if (serial === epoch.current) setError(cause instanceof Error ? cause.message : "Package request failed");}
    finally {if (serial === epoch.current) setBusy(false);}
  }
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-6xl space-y-6">
    <nav className="flex flex-wrap gap-4 text-sm text-violet-700"><Link href="/studio">Capability Studio</Link><Link href="/integrations">Monitoring integrations</Link><Link href="/studio/catalog/packs">Advanced signed packs</Link></nav>
    <header><h1 className="text-2xl font-semibold">Operation packages</h1><p className="mt-2 text-slate-600">Built-in operations and reusable packages from your team. Review dependencies, bind local connections, then import once.</p></header>
    {error && <p role="alert" className="rounded bg-red-50 p-3 text-red-800">{error}</p>}
    {notice && <p role="status" className="rounded bg-green-50 p-3 text-green-800">{notice}</p>}
    <section className={card}><h2 className="text-lg font-semibold">Built-in packages</h2>
      <div className="mt-4 grid gap-4 md:grid-cols-2">{builtins.map(pack => <article key={pack.name} className="rounded-lg border p-4">
        <h3 className="font-medium">{pack.description}</h3><p className="mt-2 text-sm text-slate-600">{pack.components.length} components · Version {pack.version} · {receipts.some(r => r.name === pack.name && r.version === pack.version) ? "Imported; activation is separate" : "Not imported"}</p>
        <p className="mt-2 text-xs">{Array.from(new Set(pack.components.map(c => c.kind))).join(" · ")}</p>
        <div className="mt-3 flex gap-3"><Button disabled={busy} variant="outline" onClick={() => select(pack, true)}>Review package</Button><Button variant="ghost" onClick={() => download(pack, pack.name + ".json")}>Export</Button></div>
      </article>)}</div>
    </section>
    <section className={card}><h2 className="text-lg font-semibold">Import a shared package</h2>
      <p className="mt-2 text-sm text-slate-600">Choose an operations-package JSON file. Signatures are checked when supplied and required when your installation policy mandates them.</p>
      <label className="mt-4 block text-sm">Package file<input className="mt-2 block max-w-full" disabled={busy} type="file" accept=".json,application/json" onChange={async event => {
        const file = event.target.files?.[0]; event.target.value = ""; if (!file) return; const serial = epoch.current;
        try {
          if (file.size > 2_000_000) throw new Error("Package exceeds 2 MB");
          const document = JSON.parse(await file.text()); const pack = document?.package || document;
          if (!pack || pack.format_version !== "icheck.operations-package/v1" || typeof pack.name !== "string"
            || typeof pack.version !== "string" || typeof pack.digest_sha256 !== "string"
            || !Array.isArray(pack.components) || !pack.components.length || pack.components.length > 20
            || pack.components.some((c: Component) => !c || typeof c.name !== "string" || typeof c.kind !== "string"
              || !c.spec || typeof c.spec !== "object" || Array.isArray(c.spec))) throw new Error("Select an iCheck operations package");
          if (serial === epoch.current) select(pack, false, document.signature || null);
        } catch (cause) {if (serial === epoch.current) setError(cause instanceof Error ? cause.message : "Invalid package");}
      }} /></label>
    </section>
    {selected && <section className={card}><h2 className="text-lg font-semibold">Review: {selected.name} · {selected.version}</h2>
      <fieldset disabled={busy}><ul className="mt-3 space-y-2">{selected.components.map(component => <li key={component.name} className="rounded border p-3">
        <p className="break-words font-medium">{component.name} <span className="text-sm font-normal text-slate-500">· {component.kind}</span></p>
        {component.kind === "connector" && <label className="mt-2 block text-sm">Local {component.spec.provider} connection
          <select className="mt-1 block w-full rounded border p-2" value={connections[component.name] || ""} onChange={e => {setConnections({...connections, [component.name]: e.target.value}); setReview(null);}}>
            <option value="">Select a saved connection</option>{choices.connections.filter(c => c.provider === component.spec.provider).map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
          <Link className="mt-1 block text-violet-700 underline" href="/integrations">Add a connection</Link></label>}
        {component.kind === "tool" && <label className="mt-2 block text-sm">Local MCP server<select className="mt-1 block w-full rounded border p-2" value={servers[component.name] || component.spec.mcp_server_name || ""} onChange={e => {setServers({...servers, [component.name]: e.target.value}); setReview(null);}}>
          <option value="">Select an MCP server</option>{choices.mcp_servers.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}</select></label>}
      </li>)}</ul></fieldset>
      <p className="mt-3 text-sm text-slate-600">Endpoints, credentials, device selections and schedules are not imported. MCP server packages remain one server with all their tools.</p>
      <div className="mt-4 flex flex-wrap gap-3"><Button variant="outline" disabled={busy} onClick={() => void action("preview")}>Check readiness</Button>
        <Button disabled={busy || !review?.installable || review.already_imported} onClick={() => void action("import")}>Approve and import</Button></div>
      {review && <div className="mt-4" role="status"><p>{review.already_imported ? "Already imported" : review.installable ? "Ready for local validation and import" : "Needs local setup"}</p>
        {!!review.pending_components?.length && <p className="mt-2 text-sm text-amber-800">These components will remain inactive drafts until the included MCP servers are installed: {review.pending_components.join(", ")}.</p>}
        <ul className="mt-2 list-inside list-disc text-sm text-amber-800">{review.blockers.map(item => <li key={item}>{item}</li>)}</ul><p className="mt-2 text-sm text-slate-500">{review.activation}</p></div>}
    </section>}
    <section className={card}><h2 className="text-lg font-semibold">Export your capabilities</h2>
      <p className="mt-2 text-sm text-slate-600">Select validated versions. Local registry IDs and collector credential bindings are excluded. Recipes containing other local references, real addresses or endpoint literals must be made portable first.</p>
      <form className="mt-4 space-y-4" onSubmit={async event => {
        event.preventDefault(); if (busy) return; const serial = epoch.current; setBusy(true); setError("");
        try {const pack = await post<Package>(BASE + "/export", {name, version, description, artifact_version_ids: versions});
          if (serial === epoch.current) download(pack, pack.name + ".json");}
        catch (cause) {if (serial === epoch.current) setError(cause instanceof Error ? cause.message : "Export failed");}
        finally {if (serial === epoch.current) setBusy(false);}
      }}><fieldset disabled={busy} className="space-y-3">
        <label className="block text-sm">Package name<Input required pattern="[a-z][a-z0-9-]*" maxLength={80} value={name} onChange={e => setName(e.target.value)} /></label>
        <label className="block text-sm">Version<Input required pattern="[0-9]+\.[0-9]+\.[0-9]+" value={version} onChange={e => setVersion(e.target.value)} /></label>
        <label className="block text-sm">Description<Input required maxLength={4000} value={description} onChange={e => setDescription(e.target.value)} /></label>
        <div className="max-h-64 space-y-2 overflow-y-auto">{choices.versions.map(v => <label key={v.id} className="flex gap-2 text-sm"><input type="checkbox" checked={versions.includes(v.id)} onChange={e => setVersions(e.target.checked ? [...versions, v.id] : versions.filter(id => id !== v.id))} />{v.name} · {v.kind} · v{v.version}</label>)}</div>
        <Button disabled={!versions.length || versions.length > 20} type="submit">Download portable package</Button>
      </fieldset></form>
    </section>
    <section className={card}><h2 className="text-lg font-semibold">Imported packages</h2>
      <p className="mt-2 text-sm text-slate-600">Import records are not runtime-health claims. Publish workflows and skills in the version library; install MCP servers in Studio. Enable schedules separately.</p>
      <ul className="mt-3 space-y-3">{receipts.map(row => <li key={row.id} className="border-t pt-3"><p>{row.name} · {row.version} · {row.artifact_version_ids.length} artifacts</p>
        <ul className="mt-2 space-y-2">{row.components?.map(c => <li key={c.id} className="flex flex-wrap gap-3 text-sm">
          <span>{c.name} · {c.pending ? "Waiting for MCP dependency" : c.status}</span>
          <Link className="text-violet-700 underline" href={c.kind === "mcp" ? `/studio/mcp?artifact=${c.artifact_id}` : `/studio/artifacts?artifact=${c.artifact_id}`}>{c.kind === "mcp" ? "Install / manage MCP server" : "Review / publish"}</Link>
        </li>)}</ul>
        {row.pending && <Button className="mt-3" disabled={busy} variant="outline" onClick={async () => {
          const serial = epoch.current; setBusy(true); setError("");
          try {await post(BASE + "/" + row.id + "/prepare", {}); await reload(serial);}
          catch (cause) {if (serial === epoch.current) setError(cause instanceof Error ? cause.message : "Dependencies are not ready");}
          finally {if (serial === epoch.current) setBusy(false);}
        }}>Recheck dependencies and validate drafts</Button>}
      </li>)}</ul>
      {!receipts.length && <p className="mt-3 text-sm">No packages imported.</p>}
      <div className="mt-4 flex flex-wrap gap-4 text-sm text-violet-700"><Link href="/studio">Open capability library</Link><Link href="/studio/artifacts">Publish reviewed versions</Link><Link href="/studio/workflows">Workflow runs and schedules</Link></div>
    </section>
  </div></main>;
}
