"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Interface = {
  device_id: string; device_name: string; if_index: string; name: string | null;
  description: string | null; alias: string | null; observed_at: string;
  metrics: Record<string, number>; evidence_ids: Record<string, string>;
  metric_observed_at: Record<string, string>;
};
type Page = { items: Interface[]; truncated: boolean; samples_examined: number; boundary: string };
const operStatus: Record<number, string> = { 1: "Up", 2: "Down", 3: "Testing", 4: "Unknown", 5: "Dormant", 6: "Not present", 7: "Lower layer down" };

export default function InterfacesPage() {
  const [page, setPage] = useState<Page | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    setLoading(true);
    setPage(null);
    try {
      setPage(await apiFetch<Page>("/assets/interfaces?limit=1000"));
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to read interface observations");
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { const timer = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(timer); }, [load]);
  const items = useMemo(() => (page?.items || []).filter((item) =>
    [item.device_name, item.name, item.description, item.alias, item.if_index]
      .some((value) => value?.toLowerCase().includes(query.toLowerCase()))), [page, query]);
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-6xl space-y-5">
    <nav aria-label="Inventory"><Link href="/">AI workspace</Link><span aria-hidden="true"> · </span><Link href="/assets/devices">Devices</Link><span aria-hidden="true"> · </span><Link href="/assets/endpoints">Terminals and history</Link></nav>
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h1 className="text-2xl font-semibold">Collected interfaces</h1><p className="mt-2 text-sm text-muted-foreground">Last recorded SNMP interface observations, not live health or a complete hardware snapshot.</p></div><Button variant="outline" disabled={loading} onClick={() => void load()}>Refresh</Button></div>
    <label className="block text-sm">Search device, interface or description<Input className="mt-2" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
    {error ? <p role="alert" className="rounded-lg bg-red-50 p-4 text-red-700">{error}</p> : null}
    {loading ? <p role="status">Loading collected evidence…</p> : null}
    {page?.truncated ? <p role="status" className="rounded-lg bg-amber-50 p-4">Bounded result. Filter by device through the API to inspect additional evidence.</p> : null}
    <div className="overflow-x-auto rounded-xl border bg-white"><table className="w-full text-left text-sm"><caption className="sr-only">Collected interface inventory</caption><thead><tr>{["Device", "Interface", "Description", "Observed operational state", "Last observation", "Evidence"].map((text) => <th key={text} scope="col" className="p-3">{text}</th>)}</tr></thead><tbody>
      {items.map((item) => <tr key={`${item.device_id}:${item.if_index}`} className="border-t"><td className="p-3">{item.device_name}</td><td className="p-3">{item.name || `ifIndex ${item.if_index}`}<p className="text-xs text-muted-foreground">Index {item.if_index}</p></td><td className="p-3">{item.description || item.alias || "Not observed"}</td><td className="p-3">{operStatus[item.metrics.ifOperStatus] || "Not observed"}{item.metric_observed_at.ifOperStatus ? <p className="text-xs text-muted-foreground">{new Date(item.metric_observed_at.ifOperStatus).toLocaleString()}</p> : null}</td><td className="p-3">{new Date(item.observed_at).toLocaleString()}</td><td className="p-3"><details><summary>Source records</summary><ul className="mt-2 space-y-1">{Object.entries(item.evidence_ids).map(([metric, id]) => <li key={metric} className="break-all text-xs">{metric}: {id}</li>)}</ul></details></td></tr>)}
      {!items.length && !loading && !error ? <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">No collected interface samples. Enable an approved SNMP if_mib collector; creating a device alone does not create evidence.</td></tr> : null}
    </tbody></table></div>
    {page ? <p className="text-xs text-muted-foreground">{page.samples_examined} authorized samples examined. {page.boundary}.</p> : null}
  </div></main>;
}
