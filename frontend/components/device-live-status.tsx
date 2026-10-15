"use client";

import { Badge } from "@/components/ui/badge";
import { healthEvidenceKey, healthLabel, type DeviceHealth } from "@/lib/asset-inventory";

export function healthTone(state?: string): string {
  if (state === "up") return "border-green-200 bg-green-50 text-green-800";
  if (state === "poll_failed") return "border-red-200 bg-red-50 text-red-800";
  if (["degraded", "stale"].includes(state || "")) return "border-amber-200 bg-amber-50 text-amber-800";
  return "border-slate-200 bg-slate-50 text-slate-700";
}

export function DeviceLiveStatus({ health }: { health?: DeviceHealth }) {
  return <section aria-label="Live collection status" className="space-y-3 rounded-lg border bg-white p-4">
    <div className="flex flex-wrap items-center gap-3"><h2 className="text-sm font-semibold">Live monitoring status</h2>
      <Badge className={healthTone(health?.state)}>{healthLabel(health?.state)}</Badge></div>
    <p className="text-xs text-muted-foreground">{health?.reason || "Current collection evidence has not been loaded."}</p>
    <p className="text-xs text-muted-foreground">A successful enrollment check is historical verification, not live availability. A failed poll does not prove that the device is powered off.</p>
    {health?.checked_at ? <p className="text-xs text-muted-foreground">Checked {new Date(health.checked_at).toLocaleString()}</p> : null}
    {health?.connections.map((connection, index) => <div key={healthEvidenceKey(connection, index)} className="rounded border p-3 text-xs">
      <p className="font-medium">{connection.protocol.toUpperCase()} · {healthLabel(connection.state)}</p>
      <p className="mt-1 text-muted-foreground">{connection.reason}</p>
      <p className="mt-1 text-muted-foreground">Source: {connection.source}. Last observation: {connection.observed_at ? new Date(connection.observed_at).toLocaleString() : "Not available"}.</p>
    </div>)}
  </section>;
}
