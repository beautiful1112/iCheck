"use client";
import Link from "next/link";
import {useEffect, useRef, useState} from "react";
import {useStudioCatalog} from "@/components/use-studio-catalog";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {ProtectedBackupDownload} from "@/components/configuration-backups";
import {backupReceipt} from "@/lib/configuration-backups";
import {apiFetch} from "@/lib/icheck-api";
import {permits} from "@/lib/studio-builder";

type Target = {connection_id: string; device_id: string; name: string; enabled: boolean};
type Test = {id: string; tool_name: string; device_id: string; status: string; result: Record<string, unknown>; completed_at: string};

function Diagnostics({artifactId, versionId, tools, canWrite}: {artifactId: string; versionId: string;
  tools: {name: string; operation: string; commands: string[]}[]; canWrite: boolean}) {
  const [search, setSearch] = useState(""), [targets, setTargets] = useState<Target[]>([]), [connection, setConnection] = useState("");
  const [history, setHistory] = useState<Test[]>([]), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const active = useRef(true), locked = useRef(false);
  const target = targets.find(row => row.connection_id === connection);
  useEffect(() => {
    active.current = true;
    void apiFetch<Test[]>(`/capability-studio/extensions/tests?artifact_version_id=${versionId}`).then(rows => {if (active.current) setHistory(rows);})
      .catch(() => {if (active.current) setError("Test history could not be loaded.");});
    return () => {active.current = false;};
  }, [versionId]);
  async function run(tool: typeof tools[number]) {
    if (locked.current || !target?.enabled || !canWrite) return;
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await apiFetch<Test>("/capability-studio/extensions/tests", {method: "POST", body: JSON.stringify({
        request_key: crypto.randomUUID(), artifact_version_id: versionId, connection_id: connection, tool_name: tool.name,
      })});
      if (active.current) setHistory(rows => [result, ...rows]);
    } catch (cause) {if (active.current) setError(cause instanceof Error ? cause.message : "Device test failed");}
    finally {locked.current = false; if (active.current) setBusy(false);}
  }
  return <div className="space-y-5">
    <Link className="text-violet-700 underline" href={`/studio/mcp?artifact=${artifactId}`}>Back to MCP server</Link>
    <h1 className="text-2xl font-semibold">Optional device tests</h1>
    <p className="text-sm text-slate-600">Installation does not require these tests. Run one only to diagnose device access or inspect a tool’s result. Tests contact the selected device; backup tests save an encrypted configuration backup.</p>
    <form className="flex gap-2" onSubmit={event => {
      event.preventDefault(); if (busy) return; setConnection(""); setTargets([]); setBusy(true); setError("");
      void apiFetch<Target[]>("/capability-studio/extensions/targets?search=" + encodeURIComponent(search))
        .then(rows => {if (active.current) setTargets(rows);})
        .catch(() => {if (active.current) setError("Devices could not be loaded.");})
        .finally(() => {if (active.current) setBusy(false);});
    }}><label className="flex-1">Find a test device<Input value={search} maxLength={128} onChange={event => setSearch(event.target.value)} /></label><Button variant="outline" disabled={busy || !canWrite}>Find</Button></form>
    <label className="block">Test device<select className="mt-2 block w-full rounded border bg-white p-2" value={connection} disabled={busy} onChange={event => setConnection(event.target.value)}>
      <option value="">Select an optional test device</option>{targets.map(row => <option key={row.connection_id} value={row.connection_id} disabled={!row.enabled}>{row.name}</option>)}
    </select></label>
    {target && <Link className="text-sm text-violet-700 underline" href={`/assets/devices?device=${target.device_id}`}>Manage this device’s credentials, SSH identity and compatibility in Assets</Link>}
    <ul className="space-y-3">{tools.map(tool => <li key={tool.name} className="rounded border bg-white p-4"><h2 className="font-medium">{tool.name}</h2><p className="my-2 text-xs text-slate-600">{tool.commands.join(" · ")}</p>
      <Button variant="outline" disabled={busy || !canWrite || !target?.enabled} onClick={() => void run(tool)}>{tool.operation === "backup" ? "Run test and save backup" : "Run read-only test"}</Button></li>)}</ul>
    {error && <p role="alert" className="text-red-700">{error}</p>}
    <h2 className="text-lg font-semibold">Saved test history</h2>
    {!history.length && <p className="text-sm">No tests recorded for this version.</p>}
    {history.map(test => {const receipt = test.status === "succeeded" ? backupReceipt(test.result) : null; return <section key={test.id} className="space-y-2 rounded border bg-white p-4 text-sm">
      <p>{test.tool_name} · {test.status} · {test.completed_at ? new Date(test.completed_at).toLocaleString() : "In progress"}</p>
      <Link className="text-violet-700 underline" href={`/assets/devices?device=${test.device_id}`}>Open tested device</Link>
      {receipt ? <ProtectedBackupDownload receipt={receipt} canDownload={true} /> : <pre className="max-h-60 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(test.result, null, 2)}</pre>}
    </section>;})}
  </div>;
}

export default function MCPTestPage() {
  const {artifacts, principal, warnings, loading} = useStudioCatalog("mcp");
  const [selected, setSelected] = useState("");
  useEffect(() => {const timer = window.setTimeout(() => setSelected(new URLSearchParams(window.location.search).get("version") || ""), 0); return () => window.clearTimeout(timer);}, []);
  const artifact = artifacts[0], version = artifact?.versions.find(row => row.id === selected);
  const spec = version?.definition?.spec as {tools?: {name: string; operation: string; commands: string[]}[]} | undefined;
  const canWrite = !!principal?.authorization_scope.all && ["capabilities.manage", "assets.read", "assets.activate", "tools.admin"].every(permission => permits(principal, permission));
  return <main className="min-h-screen bg-slate-50 p-6"><div className="mx-auto max-w-3xl">
    {warnings.map(message => <p key={message} role="alert">{message}</p>)}
    {loading ? <p role="status">Loading package…</p> : artifact && version && spec?.tools ?
      <Diagnostics key={`${principal?.subject}:${artifact.id}:${version.id}`} artifactId={artifact.id} versionId={version.id} tools={spec.tools} canWrite={canWrite} /> : <p>Select a validated package version from <Link href="/studio">Capability Studio</Link>.</p>}
  </div></main>;
}
