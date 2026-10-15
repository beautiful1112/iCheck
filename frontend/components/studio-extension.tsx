"use client";

import Link from "next/link";
import {useCallback, useEffect, useRef, useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";

type Policy = {mode: "authorized_inventory"; scope: Record<string, unknown>};
type Installation = {id: string; artifact_id: string; active_version_id: string; previous_version_id: string | null;
  revision: number; enabled: boolean; target_policy: Policy | null; previous_target_policy: Policy | null;
  tool_ids: Record<string, string>; last_health_status: string; bindings: {host: string}[]};

export function StudioExtension({artifactId, versionId, spec, canWrite, onChanged}: {
  artifactId: string; versionId: string; spec: Record<string, unknown>; canWrite: boolean; canDownload: boolean; onChanged: () => Promise<void>;
}) {
  const [installed, setInstalled] = useState<Installation | null>(null);
  const [configured, setConfigured] = useState(false), [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [restoreApproved, setRestoreApproved] = useState(false);
  const generation = useRef(0), reads = useRef(0), locked = useRef(false);
  const tools = (Array.isArray(spec.tools) ? spec.tools : []) as {name: string; operation: string}[];
  const current = installed?.enabled && installed.active_version_id === versionId && installed.target_policy?.mode === "authorized_inventory";
  const reload = useCallback(async () => {
    const epoch = generation.current, request = ++reads.current;
    setLoading(true); setRestoreApproved(false);
    try {
      const runtime = await apiFetch<{storage_configured: boolean; items: Installation[]}>("/capability-studio/extensions?artifact_id=" + encodeURIComponent(artifactId));
      if (epoch !== generation.current || request !== reads.current) return;
      setConfigured(runtime.storage_configured); setInstalled(runtime.items.find(row => row.artifact_id === artifactId) || null);
    } catch (cause) {
      if (epoch === generation.current && request === reads.current) {
        setConfigured(false); setInstalled(null); setError(cause instanceof Error ? cause.message : "Unable to read installation status");
      }
    } finally {if (epoch === generation.current && request === reads.current) setLoading(false);}
  }, [artifactId]);
  useEffect(() => {
    ++generation.current;
    const timer = window.setTimeout(() => void reload(), 0);
    return () => {generation.current++; window.clearTimeout(timer);};
  }, [reload, versionId]);
  async function action(path: string, body: Record<string, unknown>) {
    if (locked.current || loading || !canWrite) return;
    const epoch = generation.current;
    locked.current = true; setBusy(true); setError("");
    try {
      await apiFetch(path, {method: "POST", body: JSON.stringify(body)});
      if (epoch === generation.current) {await reload(); await onChanged();}
    } catch (cause) {if (epoch === generation.current) setError(cause instanceof Error ? cause.message : "Installation failed");}
    finally {locked.current = false; if (epoch === generation.current) {setBusy(false); setRestoreApproved(false);}}
  }
  return <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-5 text-sm" aria-label="Extension installation">
    <h2 className="text-lg font-semibold">{current ? "Ready for AI Operator" : "Approve this MCP server"}</h2>
    <p>Install once. AI Operator selects devices from inventory when you ask it to use these tools. Device access, saved credentials and permissions are reused automatically.</p>
    <dl className="grid gap-3 rounded-lg bg-slate-50 p-4 sm:grid-cols-2">
      <div><dt className="text-slate-500">Access</dt><dd>Authorized devices in this workspace; each caller’s access still applies.</dd></div>
      <div><dt className="text-slate-500">Effects</dt><dd>Read-only device commands{tools.some(tool => tool.operation === "backup") ? " and encrypted configuration backup storage" : ""}. No device configuration changes or schedules.</dd></div>
    </dl>
    {!current && <>
      <p>iCheck checks the generated code with isolated fixtures, starts the managed MCP runtime to discover its tools, and registers them together. Installation does not log in to devices.</p>
      {installed && !installed.target_policy && <p className="rounded bg-amber-50 p-3">This older installation is limited to {installed.bindings.length} tested targets. Approving below replaces that restriction with reusable, permission-checked inventory access.</p>}
      <Button disabled={!canWrite || !configured || loading || busy || !tools.length} onClick={() => void action("/capability-studio/extensions/install", {
        artifact_version_id: versionId, expected_revision: installed?.revision || 0, access_mode: "authorized_inventory",
      })}>{busy ? "Validating and installing…" : installed ? "Approve and activate this version" : "Approve and install"}</Button>
    </>}
    {installed && <div className="space-y-2 border-t pt-4">
      <p role="status">{installed.enabled ? "Installed and registered" : "Installed but disabled"} · {Object.keys(installed.tool_ids).length} tools</p>
      <p className="text-slate-500">{installed.enabled ? "Managed runtime starts on demand for tool calls." : "Tools are unavailable to AI Operator until reactivated."}</p>
      {installed.enabled && <Link href="/" className="inline-block font-medium text-violet-700 underline">Use in AI Operator</Link>}
    </div>}
    <details className="border-t pt-3"><summary className="cursor-pointer text-slate-600">Advanced · runtime and version controls</summary>
      <div className="mt-3 space-y-3">
        <p>Device credentials, fingerprint trust and SSH compatibility are shared <Link href="/assets/devices" className="text-violet-700 underline">device access settings in Assets</Link>, not MCP installation settings.</p>
        <Link href={`/studio/mcp/test?artifact=${artifactId}&version=${versionId}`} className="inline-block text-violet-700 underline">Optional device test and backup history</Link>
        {installed && <>
          <p className="break-all">Active version: {installed.active_version_id} · Revision {installed.revision} · Last runtime result: {installed.last_health_status}</p>
          <Button variant="outline" disabled={!canWrite || loading || busy || !installed.enabled} onClick={() => void action(`/capability-studio/extensions/${installed.id}/disable`, {expected_revision: installed.revision})}>Disable tools</Button>
          {installed.previous_version_id && <div className="space-y-2">
            <p className="break-all">Previous version: {installed.previous_version_id}. Access: {installed.previous_target_policy ? "authorized inventory" : "previously tested targets"}. Restoring enables that version, not device configuration.</p>
            <label className="flex gap-2"><input type="checkbox" checked={restoreApproved} disabled={busy || loading} onChange={event => setRestoreApproved(event.target.checked)} />Restore this previous version and its access policy.</label>
            <Button variant="outline" disabled={!canWrite || loading || busy || !restoreApproved} onClick={() => void action(`/capability-studio/extensions/${installed.id}/rollback`, {expected_revision: installed.revision})}>Restore previous version</Button>
          </div>}
        </>}
        <Button variant="outline" disabled={busy || loading} onClick={() => void reload()}>Refresh status</Button>
      </div>
    </details>
    {!canWrite && <p role="status">Administrator approval is required to install this package.</p>}
    {!loading && !configured && <p role="status">Managed runtime is unavailable. Your draft is saved.</p>}
    {loading && <p role="status">Loading installation status…</p>}
    {error && <p role="alert" className="text-red-700">{error}</p>}
  </section>;
}
