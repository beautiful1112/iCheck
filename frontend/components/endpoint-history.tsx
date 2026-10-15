"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/icheck-api";

type Record = { id: string; active: boolean; first_seen: string; last_seen: string; ip_address?: string | null; source?: string; interface_name?: string | null; ssid?: string | null; access_point?: string | null };
type History = { id: string; mac_address: string; truncated: string[]; ip_history: Record[]; wired_history: Record[]; wireless_history: Record[] };

export function EndpointHistory({ endpointId }: { endpointId: string }) {
  const [history, setHistory] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let current = true;
    const timer = window.setTimeout(() => {
      setHistory(null); setError(null);
      void apiFetch<History>(`/endpoints/${encodeURIComponent(endpointId)}/history?limit=50`).then(
        (value) => { if (current) setHistory(value); },
        (cause) => { if (current) setError(cause instanceof Error ? cause.message : "Unable to read history"); },
      );
    }, 0);
    return () => { current = false; window.clearTimeout(timer); };
  }, [endpointId]);
  const visible = history?.id === endpointId ? history : null;
  return <section aria-label="IP MAC and attachment history" className="space-y-3">
    <h3 className="text-sm font-semibold">IP/MAC and attachment history</h3>
    <p className="text-xs text-muted-foreground">Retained source observations, including inactive records. Not a complete physical identity assertion.</p>
    {error ? <p role="alert" className="text-xs text-red-700">{error}</p> : null}
    {!visible && !error ? <p role="status" className="text-xs">Loading history…</p> : null}
    {visible ? ([ ["IP addresses", visible.ip_history], ["Wired attachments", visible.wired_history], ["Wi-Fi terminals", visible.wireless_history] ] as const).map(([label, rows]) => <details key={label} className="rounded-lg border p-3"><summary className="cursor-pointer text-xs font-medium">{label} · {rows.length} records</summary><ul className="mt-3 space-y-2">{rows.map((row) => <li key={row.id} className="rounded-lg bg-slate-50 p-3 text-xs"><p>{row.ip_address || row.interface_name || row.ssid || "Unspecified"} · {row.active ? "Active observation" : "Historical observation"}</p><p className="mt-1 text-muted-foreground">{row.source || row.access_point || "Controller observation"} · First {new Date(row.first_seen).toLocaleString()} · Last {new Date(row.last_seen).toLocaleString()}</p></li>)}</ul>{!rows.length ? <p className="mt-2 text-xs text-muted-foreground">No authorized records.</p> : null}</details>) : null}
    {visible?.truncated.length ? <p role="status" className="text-xs text-amber-800">Additional history exists. This view shows up to 50 records per family.</p> : null}
  </section>;
}
