"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "@/lib/icheck-api";
import { Button } from "@/components/ui/button";

export function SNMPConfiguration({ modules, pending, onSave }: {
  modules: string[]; pending: boolean; onSave: (modules: string[]) => Promise<void>;
}) {
  const [catalog, setCatalog] = useState<string[]>([]);
  const [selected, setSelected] = useState(modules);
  const [canWrite, setCanWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    Promise.all([apiFetch<{ modules: string[] }>("/assets/snmp-modules"),
      apiFetch<{ permissions: string[] }>("/auth/me")]).then(([result, principal]) => {
      if (cancelled) return;
      setCatalog(result.modules);
      setCanWrite(principal.permissions.includes("*") || principal.permissions.includes("assets.write"));
    }).catch((failure) => { if (!cancelled) setError(failure instanceof Error ? failure.message : "Module catalog unavailable"); });
    return () => { cancelled = true; };
  }, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (busy || pending || !canWrite || !selected.length || selected.some((name) => !catalog.includes(name))) return;
    setBusy(true); setError(null);
    try { await onSave(selected); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "Unable to save SNMP configuration"); }
    finally { setBusy(false); }
  }
  const unknown = selected.filter((name) => !catalog.includes(name));
  return <details className="mt-3 border-t border-[#eceef0] pt-3" open={catalog.length > 0 && modules.some((name) => !catalog.includes(name))}>
    <summary className="cursor-pointer text-xs font-semibold">SNMP module configuration</summary>
    <p className="mt-2 text-xs text-muted-foreground">Verification uses a small identity query to discover sysName. These modules select monitoring data: if_mib for interfaces, system for system information. Collector adapters are not module names.</p>
    {unknown.length > 0 && catalog.length > 0 ? <p role="alert" className="mt-2 text-xs text-red-700">Invalid saved modules: {unknown.join(", ")}. Select installed modules below to replace them.</p> : null}
    {error ? <p role="alert" className="mt-2 text-xs text-red-700">{error}</p> : null}
    <form onSubmit={save} className="mt-2 space-y-2">
      <label className="block text-xs">Installed SNMP monitoring modules
        <select multiple aria-label="Installed SNMP monitoring modules" value={selected.filter((name) => catalog.includes(name))}
          disabled={!canWrite || busy || pending} onChange={(event) => setSelected(Array.from(event.target.selectedOptions, (option) => option.value))}
          className="mt-1 block h-28 w-full rounded border border-[#c9cdd4] bg-white p-2 text-xs">
          {catalog.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </label>
      <p className="text-[11px] text-muted-foreground">Ctrl/Cmd-click to select multiple modules. Saving queues verification and withdraws any previous continuous-monitoring approval; approve monitoring again after verification.</p>
      <Button type="submit" size="sm" variant="outline" disabled={!canWrite || busy || pending || !selected.length || unknown.length > 0}>Save modules and reverify</Button>
    </form>
  </details>;
}
