"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  Cable,
  Clock3,
  Globe2,
  MonitorSmartphone,
  Network,
  Radio,
  RefreshCw,
  Router,
  Search,
  Signal,
  UserRound,
  Wifi,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { EndpointHistory } from "@/components/endpoint-history";
import { cn } from "@/lib/utils";

type CurrentIP = {
  address: string;
  source: string;
  vlan_id: number | null;
  collector_device_id: string | null;
  first_seen: string;
  last_seen: string;
  network_observation_state?: string | null;
  network_observed_at?: string | null;
};

type CurrentAttachment = {
  source: string;
  collector_device_id: string | null;
  interface_name: string | null;
  vlan_id: number | null;
  last_seen: string;
  network_observation_state?: string | null;
  network_observed_at?: string | null;
};

function NetworkSourceQuality({ state }: { state?: string | null }) {
  if (!state) return null;
  return (
    <Badge variant="outline" className={cn("ml-2 text-[9px]",
      state === "conflict" ? "border-amber-300 text-amber-800" : "text-muted-foreground")}>
      {state === "conflict" ? "Source conflict" : state === "accepted" ? "Logical observation" : "Legacy / unqualified"}
    </Badge>
  );
}

type WirelessSession = {
  id: string;
  controller_id: string;
  ip_address: string | null;
  access_point: string | null;
  ssid: string | null;
  band: string | null;
  channel: number | null;
  vlan_id: number | null;
  rssi: number | null;
  snr: number | null;
  connected_at: string | null;
  last_seen: string;
};

type Endpoint = {
  id: string;
  mac_address: string;
  hostname: string | null;
  username: string | null;
  vendor: string | null;
  first_seen: string;
  last_seen: string;
  current_ips: CurrentIP[];
  current_attachments: CurrentAttachment[];
  current_wireless_sessions: WirelessSession[];
};

type Device = {
  id: string;
  name: string;
  kind: string;
  site: string | null;
};

function relativeTime(value: string) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function signalTone(rssi: number | null) {
  if (rssi === null) return "text-muted-foreground";
  if (rssi >= -60) return "text-[#166534]";
  if (rssi >= -72) return "text-[#92400e]";
  return "text-[#991b1b]";
}

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextEndpoints, nextDevices] = await Promise.all([
        apiFetch<Endpoint[]>("/endpoints?limit=1000"),
        apiFetch<Device[]>("/devices?limit=1000"),
      ]);
      setEndpoints(nextEndpoints);
      setDevices(nextDevices);
      setLoadedAt(Date.now());
      setSelectedId((current) =>
        current && nextEndpoints.some((item) => item.id === current)
          ? current
          : nextEndpoints[0]?.id || null,
      );
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load endpoint inventory");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const devicesById = useMemo(
    () => new Map(devices.map((device) => [device.id, device])),
    [devices],
  );
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return endpoints;
    return endpoints.filter((endpoint) =>
      [
        endpoint.mac_address,
        endpoint.hostname,
        endpoint.username,
        endpoint.vendor,
        ...endpoint.current_ips.map((item) => item.address),
        ...endpoint.current_wireless_sessions.map((item) => item.ssid),
      ].some((value) => value?.toLowerCase().includes(needle)),
    );
  }, [endpoints, query]);
  const selected = endpoints.find((item) => item.id === selectedId) || null;
  const wirelessCount = endpoints.filter((item) => item.current_wireless_sessions.length > 0).length;
  const wiredCount = endpoints.filter((item) => item.current_attachments.length > 0).length;
  const recentCount = endpoints.filter(
    (item) =>
      loadedAt > 0 &&
      loadedAt - new Date(item.last_seen).getTime() < 60 * 60_000,
  ).length;

  function deviceName(id: string | null) {
    if (!id) return "Unbound collector";
    const device = devicesById.get(id);
    return device ? `${device.name}${device.site ? ` · ${device.site}` : ""}` : id;
  }

  return (
    <main className="min-h-screen bg-[#f4f5f7] text-slate-900">
      <header data-text-surface="dark" className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-4 px-4 sm:px-6 xl:px-8">
          <Link href="/" className="grid size-9 place-items-center rounded-md bg-[#5856d6]" aria-label="Back to operations"><Activity className="size-[18px]" /></Link>
          <div><p className="text-sm font-semibold">iCheck Endpoint Identity</p><p className="text-xs text-muted-foreground">IP, MAC, wired attachment, and Wi-Fi controller evidence</p></div>
          <Badge className="ml-auto border-emerald-400/30 bg-emerald-400/10 text-emerald-200">Observed state</Badge>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 xl:px-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
          <div>
            <Link href="/assets/devices" className="mb-3 inline-flex items-center gap-1.5 text-xs font-medium text-[#5856d6]"><ArrowLeft className="size-3.5" /> Managed devices</Link>
            <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-[-0.02em]"><span className="grid size-10 place-items-center rounded-lg bg-[#e9e8fb] text-[#5856d6]"><MonitorSmartphone className="size-5" /></span>Observed endpoints</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">Terminal identity is kept in this focused evidence workspace. The AI operator receives only bounded, minimized endpoint history when it needs it.</p>
          </div>
          <Button variant="outline" className="ml-auto bg-white" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("size-4", loading && "animate-spin")} /> Refresh</Button>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {([
            ["Total identities", endpoints.length, MonitorSmartphone, "text-violet-600"],
            ["Seen within 1h", recentCount, Clock3, "text-emerald-600"],
            ["Active wired", wiredCount, Cable, "text-blue-600"],
            ["Active wireless", wirelessCount, Wifi, "text-cyan-600"],
          ] as const).map(([label, value, Icon, tone]) => (
            <div key={String(label)} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"><div className="flex items-center"><div><p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{String(label)}</p><p className="mt-1 text-2xl font-semibold">{String(value)}</p></div><Icon className={cn("ml-auto size-5", String(tone))} /></div></div>
          ))}
        </div>

        {error ? <div className="mt-5 rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-700">{error}</div> : null}

        <div className="mt-5 grid min-h-[680px] gap-5 lg:grid-cols-[420px_minmax(0,1fr)]">
          <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-100 p-4"><div className="relative"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search MAC, IP, host, user, SSID…" className="pl-9" /></div><p className="mt-2 text-[10px] text-muted-foreground">{filtered.length} of {endpoints.length} identities</p></div>
            <div className="max-h-[610px] overflow-y-auto divide-y divide-slate-100">
              {filtered.map((endpoint) => {
                const isWireless = endpoint.current_wireless_sessions.length > 0;
                const isSelected = selectedId === endpoint.id;
                return (
                  <button key={endpoint.id} onClick={() => setSelectedId(endpoint.id)} className={cn("w-full px-4 py-3 text-left transition hover:bg-slate-50", isSelected && "bg-violet-50 hover:bg-violet-50")}>
                    <div className="flex items-center gap-3"><span className={cn("grid size-9 shrink-0 place-items-center rounded-xl", isWireless ? "bg-cyan-50 text-cyan-600" : "bg-blue-50 text-blue-600")}>{isWireless ? <Wifi className="size-4" /> : <Cable className="size-4" />}</span><div className="min-w-0"><p className="truncate text-xs font-semibold">{endpoint.hostname || endpoint.mac_address}</p><p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{endpoint.mac_address}</p></div><span className="ml-auto shrink-0 text-[9px] text-muted-foreground">{relativeTime(endpoint.last_seen)}</span></div>
                  <div className="mt-2 flex flex-wrap gap-1.5">{endpoint.current_ips.slice(0, 2).map((ip) => <Badge key={`${ip.address}-${ip.source}-${ip.collector_device_id}-${ip.vlan_id}`} variant="outline" className="font-mono text-[9px]">{ip.address}{ip.vlan_id !== null ? ` · VLAN ${ip.vlan_id}` : ""}</Badge>)}{endpoint.current_wireless_sessions[0]?.ssid ? <Badge className="bg-cyan-50 text-[9px] text-cyan-700">{endpoint.current_wireless_sessions[0].ssid}</Badge> : null}</div>
                  </button>
                );
              })}
              {!filtered.length && !loading ? <div className="py-16 text-center text-xs text-muted-foreground">No matching endpoints.</div> : null}
            </div>
          </section>

          <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            {selected ? (
              <>
                <div className="border-b border-slate-100 px-5 py-4"><div className="flex items-start"><div><p className="text-[10px] font-semibold uppercase tracking-wide text-violet-600">Endpoint identity</p><h2 className="mt-1 text-lg font-semibold">{selected.hostname || "Unnamed endpoint"}</h2><p className="mt-1 font-mono text-xs text-muted-foreground">{selected.mac_address}</p></div><Badge variant="outline" className="ml-auto">Seen {relativeTime(selected.last_seen)}</Badge></div></div>
                <div className="space-y-5 p-5">
                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="rounded-xl bg-slate-50 p-3"><p className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Vendor</p><p className="mt-1 text-xs font-medium">{selected.vendor || "Unknown"}</p></div>
                    <div className="rounded-xl bg-slate-50 p-3"><p className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Last user</p><p className="mt-1 flex items-center gap-1 text-xs font-medium"><UserRound className="size-3" />{selected.username || "Not observed"}</p></div>
                    <div className="rounded-xl bg-slate-50 p-3"><p className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">First seen</p><p className="mt-1 text-xs font-medium">{new Date(selected.first_seen).toLocaleString()}</p></div>
                  </div>

                  <div><h3 className="flex items-center gap-2 text-xs font-semibold"><Globe2 className="size-4 text-violet-600" /> Current IP observations</h3><div className="mt-2 grid gap-2">{selected.current_ips.map((ip) => <div key={`${ip.address}-${ip.source}-${ip.collector_device_id}-${ip.vlan_id}`} className="flex flex-wrap items-center gap-y-1 rounded-xl border border-slate-200 px-3 py-2.5"><span className="font-mono text-xs font-semibold">{ip.address}</span><Badge variant="outline" className="ml-3 text-[9px]">{ip.source}</Badge><NetworkSourceQuality state={ip.network_observation_state} /><span className="ml-auto text-[10px] text-muted-foreground">{ip.vlan_id !== null ? `VLAN ${ip.vlan_id} · ` : ""}{deviceName(ip.collector_device_id)}</span></div>)}{!selected.current_ips.length ? <p className="rounded-xl bg-slate-50 p-3 text-xs text-muted-foreground">No current IP observation.</p> : null}</div></div>

                  <div><h3 className="flex items-center gap-2 text-xs font-semibold"><Network className="size-4 text-blue-600" /> Wired attachment</h3><div className="mt-2 grid gap-2">{selected.current_attachments.map((attachment, index) => <div key={`${attachment.collector_device_id}-${attachment.interface_name}-${index}`} className="flex items-center rounded-xl border border-slate-200 px-3 py-2.5"><Router className="size-4 text-blue-600" /><div className="ml-3"><p className="text-xs font-semibold">{deviceName(attachment.collector_device_id)}</p><p className="mt-0.5 text-[10px] text-muted-foreground">{attachment.interface_name || "Unknown interface"}{attachment.vlan_id !== null ? ` · VLAN ${attachment.vlan_id}` : ""} · {attachment.source}</p><NetworkSourceQuality state={attachment.network_observation_state} /></div><span className="ml-auto text-[9px] text-muted-foreground">{relativeTime(attachment.last_seen)}</span></div>)}{!selected.current_attachments.length ? <p className="rounded-xl bg-slate-50 p-3 text-xs text-muted-foreground">No active wired attachment.</p> : null}</div></div>

                  <div><h3 className="flex items-center gap-2 text-xs font-semibold"><Radio className="size-4 text-cyan-600" /> Wi-Fi controller sessions</h3><div className="mt-2 grid gap-2">{selected.current_wireless_sessions.map((session) => <div key={session.id} className="rounded-xl border border-slate-200 p-3"><div className="flex items-center"><Wifi className="size-4 text-cyan-600" /><p className="ml-2 text-xs font-semibold">{session.ssid || "Unknown SSID"}</p><span className="ml-auto text-[9px] text-muted-foreground">{relativeTime(session.last_seen)}</span></div><p className="mt-2 text-[10px] text-muted-foreground">Controller: {deviceName(session.controller_id)}</p><div className="mt-2 flex flex-wrap gap-2 text-[10px]"><Badge variant="outline">AP {session.access_point || "unknown"}</Badge>{session.band ? <Badge variant="outline">{session.band}</Badge> : null}{session.channel !== null ? <Badge variant="outline">Channel {session.channel}</Badge> : null}{session.vlan_id !== null ? <Badge variant="outline">VLAN {session.vlan_id}</Badge> : null}<span className={cn("ml-auto flex items-center gap-1 font-semibold", signalTone(session.rssi))}><Signal className="size-3" />{session.rssi !== null ? `${session.rssi} dBm` : "No RSSI"}{session.snr !== null ? ` · SNR ${session.snr}` : ""}</span></div></div>)}{!selected.current_wireless_sessions.length ? <p className="rounded-xl bg-slate-50 p-3 text-xs text-muted-foreground">No active Wi-Fi controller session.</p> : null}</div></div>

                  <EndpointHistory key={selected.id} endpointId={selected.id} />
                  <Link href="/assets/interfaces" className="text-xs text-violet-700 underline">Inspect collected interface inventory</Link>
                </div>
              </>
            ) : (
              <div className="grid min-h-[680px] place-items-center text-center"><div><MonitorSmartphone className="mx-auto size-9 text-slate-300" /><h2 className="mt-3 text-sm font-semibold">No endpoint selected</h2><p className="mt-1 text-xs text-muted-foreground">Observed terminals appear after wired, IP, DHCP, or controller ingestion.</p></div></div>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
