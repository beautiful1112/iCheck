"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Bot,
  CheckCircle2,
  Database,
  Loader2,
  Plus,
  RefreshCw,
  ScrollText,
  Search,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type LogBackend = {
  id: string;
  name: string;
  provider: string;
  query_base_url: string;
  device_label: string;
  allowed_labels: string[];
  enabled: boolean;
  last_checked_at: string | null;
  last_health_status: string | null;
};

type Device = {
  id: string;
  name: string;
  kind: string;
  management_ip: string | null;
  site: string | null;
};

type LogEntry = {
  timestamp: string;
  labels: Record<string, string>;
  line: string;
};

type LogResult = {
  backend_id: string;
  provider: string;
  entries: LogEntry[];
  truncated: boolean;
  warnings: string[];
  queried_at: string;
};

function localDateTime(date: Date) {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function labelSummary(labels: Record<string, string>) {
  return Object.entries(labels)
    .map(([key, value]) => `${key}=${value}`)
    .join(" · ");
}

export default function LogsPage() {
  const now = useMemo(() => new Date(), []);
  const [backends, setBackends] = useState<LogBackend[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [backendId, setBackendId] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [mode, setMode] = useState<"device" | "logql">("device");
  const [query, setQuery] = useState('{job=~".+"}');
  const [start, setStart] = useState(
    localDateTime(new Date(now.getTime() - 60 * 60_000)),
  );
  const [end, setEnd] = useState(localDateTime(now));
  const [limit, setLimit] = useState(200);
  const [result, setResult] = useState<LogResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [backendName, setBackendName] = useState("");
  const [backendUrl, setBackendUrl] = useState("");
  const [deviceLabel, setDeviceLabel] = useState("instance");
  const [allowedLabels, setAllowedLabels] = useState(
    "instance,job,host,hostname,app,service,level,severity,namespace,container,source",
  );

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextBackends, nextDevices] = await Promise.all([
        apiFetch<LogBackend[]>("/logs/backends?limit=500"),
        apiFetch<Device[]>("/devices?limit=1000"),
      ]);
      setBackends(nextBackends);
      setDevices(nextDevices);
      setBackendId((current) =>
        nextBackends.some((item) => item.id === current)
          ? current
          : nextBackends.find((item) => item.enabled)?.id || "",
      );
      setDeviceId((current) =>
        nextDevices.some((item) => item.id === current)
          ? current
          : nextDevices[0]?.id || "",
      );
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load log sources");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  async function runQuery() {
    if (!backendId || (mode === "device" && !deviceId)) return;
    setRunning(true);
    setError(null);
    try {
      const path =
        mode === "device"
          ? `/logs/backends/${backendId}/devices/${deviceId}/query-range`
          : `/logs/backends/${backendId}/query-range`;
      const data = await apiFetch<LogResult>(path, {
        method: "POST",
        body: JSON.stringify({
          ...(mode === "logql" ? { query } : {}),
          start: new Date(start).toISOString(),
          end: new Date(end).toISOString(),
          direction: "backward",
          limit,
          timeout_seconds: 15,
          actor: "logs.workspace",
        }),
      });
      setResult(data);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : "Log query failed");
    } finally {
      setRunning(false);
    }
  }

  async function registerBackend() {
    setRegistering(true);
    setError(null);
    try {
      await apiFetch<LogBackend>("/logs/backends", {
        method: "POST",
        body: JSON.stringify({
          name: backendName,
          provider: "loki",
          query_base_url: backendUrl,
          device_label: deviceLabel,
          allowed_labels: allowedLabels
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          created_by: "logs.workspace",
        }),
      });
      setBackendName("");
      setBackendUrl("");
      setShowRegister(false);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to register backend");
    } finally {
      setRegistering(false);
    }
  }

  async function checkHealth() {
    if (!backendId) return;
    setRunning(true);
    try {
      await apiFetch(`/logs/backends/${backendId}/health?actor=logs.workspace`, {
        method: "POST",
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Health check failed");
    } finally {
      setRunning(false);
    }
  }

  const selectedBackend = backends.find((item) => item.id === backendId);

  return (
    <main className="min-h-screen bg-[#f5f6f8] text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-[1500px] items-center gap-3 px-5 py-4">
          <Link
            href="/"
            className="grid size-9 place-items-center rounded-xl border border-slate-200 text-slate-600 hover:text-violet-700"
            aria-label="Back to AI operator"
          >
            <ArrowLeft className="size-4" />
          </Link>
          <div className="grid size-9 place-items-center rounded-xl bg-violet-600 text-white">
            <ScrollText className="size-4" />
          </div>
          <div>
            <h1 className="text-sm font-semibold">Log evidence</h1>
            <p className="text-[11px] text-muted-foreground">
              Bounded, audited Loki queries outside the AI L1 home
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh
            </Button>
            <Button size="sm" onClick={() => setShowRegister(true)}>
              <Plus className="size-3.5" /> Register Loki
            </Button>
            <Button size="sm" variant="outline" asChild>
              <Link href="/settings/observability">Auth settings</Link>
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1500px] gap-5 px-5 py-5 lg:grid-cols-[350px_minmax(0,1fr)]">
        <aside className="space-y-4">
          <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex items-center gap-2">
              <Database className="size-4 text-violet-600" />
              <h2 className="text-xs font-semibold">Evidence source</h2>
            </div>
            <label htmlFor="log-backend" className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              Backend
            </label>
            <select
              id="log-backend"
              value={backendId}
              onChange={(event) => setBackendId(event.target.value)}
              className="mt-1 h-9 w-full rounded-md border border-slate-200 bg-white px-3 text-xs"
            >
              <option value="">Select a backend</option>
              {backends.map((backend) => (
                <option key={backend.id} value={backend.id}>
                  {backend.name}
                </option>
              ))}
            </select>
            {selectedBackend ? (
              <div className="mt-3 rounded-xl bg-slate-50 p-3 text-[10px] text-slate-600">
                <div className="flex items-center gap-2">
                  <Server className="size-3.5" />
                  <span className="truncate font-medium">{selectedBackend.query_base_url}</span>
                  <Badge variant="outline" className="ml-auto text-[9px]">
                    {selectedBackend.last_health_status || "unchecked"}
                  </Badge>
                </div>
                <p className="mt-2">Device label: <span className="font-mono">{selectedBackend.device_label}</span></p>
                <button className="mt-2 font-semibold text-violet-700" onClick={() => void checkHealth()}>
                  Run health check
                </button>
              </div>
            ) : null}

            <div className="mt-4 grid grid-cols-2 rounded-lg bg-slate-100 p-1 text-[10px] font-semibold">
              <button
                className={cn("rounded-md px-2 py-2", mode === "device" && "bg-white text-violet-700 shadow-sm")}
                onClick={() => setMode("device")}
              >
                Device scoped
              </button>
              <button
                className={cn("rounded-md px-2 py-2", mode === "logql" && "bg-white text-violet-700 shadow-sm")}
                onClick={() => setMode("logql")}
              >
                Global LogQL
              </button>
            </div>

            {mode === "device" ? (
              <>
                <label htmlFor="log-device" className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Device</label>
                <select
                  id="log-device"
                  value={deviceId}
                  onChange={(event) => setDeviceId(event.target.value)}
                  className="mt-1 h-9 w-full rounded-md border border-slate-200 bg-white px-3 text-xs"
                >
                  <option value="">Select a device</option>
                  {devices.map((device) => (
                    <option key={device.id} value={device.id}>
                      {device.name}{device.site ? ` · ${device.site}` : ""}
                    </option>
                  ))}
                </select>
                <div className="mt-3 flex gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-[10px] text-emerald-800">
                  <ShieldCheck className="mt-0.5 size-3.5 shrink-0" />
                  The control plane builds and verifies the exact device label selector.
                </div>
              </>
            ) : (
              <>
                <label htmlFor="log-query" className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">LogQL</label>
                <Textarea id="log-query" value={query} onChange={(event) => setQuery(event.target.value)} className="mt-1 min-h-24 font-mono text-[11px]" />
                <p className="mt-2 text-[10px] text-amber-700">Global LogQL is rejected for site- or device-scoped identities.</p>
              </>
            )}

            <div className="mt-4 grid grid-cols-2 gap-2">
              <div><label htmlFor="log-from" className="text-[10px] font-semibold text-muted-foreground">From</label><Input id="log-from" type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} className="mt-1 text-[11px]" /></div>
              <div><label htmlFor="log-to" className="text-[10px] font-semibold text-muted-foreground">To</label><Input id="log-to" type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} className="mt-1 text-[11px]" /></div>
            </div>
            <label htmlFor="log-limit" className="mt-3 block text-[10px] font-semibold text-muted-foreground">Maximum entries</label>
            <Input id="log-limit" type="number" min={1} max={1000} value={limit} onChange={(event) => setLimit(Number(event.target.value))} className="mt-1 text-xs" />
            <Button className="mt-4 w-full" onClick={() => void runQuery()} disabled={running || !backendId || (mode === "device" && !deviceId)}>
              {running ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />} Query evidence
            </Button>
          </section>

          <Link href="/" data-text-surface="dark" className="flex items-center gap-3 rounded-2xl bg-slate-900 p-4 text-white shadow-sm">
            <div className="grid size-9 place-items-center rounded-xl bg-violet-500/20"><Bot className="size-4 text-violet-300" /></div>
            <div><p className="text-xs font-semibold">Ask the AI operator</p><p className="mt-0.5 text-[10px] text-muted-foreground">Let the Agent correlate logs with metrics and topology.</p></div>
          </Link>
        </aside>

        <section className="min-h-[680px] rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center border-b border-slate-100 px-5 py-4">
            <div><h2 className="text-xs font-semibold">Query result</h2><p className="mt-0.5 text-[10px] text-muted-foreground">Newest evidence first · common credentials redacted</p></div>
            {result ? <div className="ml-auto flex gap-2"><Badge variant="outline">{result.entries.length} entries</Badge>{result.truncated ? <Badge className="bg-amber-100 text-amber-800">truncated</Badge> : null}</div> : null}
          </div>
          {error ? <div className="m-5 rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-700">{error}</div> : null}
          {!result && !error ? (
            <div className="grid min-h-[580px] place-items-center text-center"><div><ScrollText className="mx-auto size-9 text-slate-300" /><h3 className="mt-3 text-sm font-semibold">No log evidence loaded</h3><p className="mt-1 text-xs text-muted-foreground">Choose a device and bounded time window to begin.</p></div></div>
          ) : null}
          {result ? (
            <div className="divide-y divide-slate-100">
              {result.warnings.map((warning) => <div key={warning} className="bg-amber-50 px-5 py-2 text-[10px] text-amber-800">{warning}</div>)}
              {result.entries.map((entry, index) => (
                <article key={`${entry.timestamp}-${index}`} className="grid gap-2 px-5 py-3 hover:bg-slate-50 md:grid-cols-[180px_minmax(0,1fr)]">
                  <time className="font-mono text-[10px] text-muted-foreground">{new Date(entry.timestamp).toLocaleString()}</time>
                  <div className="min-w-0"><p className="break-words font-mono text-[11px] leading-5 text-slate-800">{entry.line}</p><p className="mt-1 truncate text-[9px] text-muted-foreground" title={labelSummary(entry.labels)}>{labelSummary(entry.labels)}</p></div>
                </article>
              ))}
              {!result.entries.length ? <div className="py-20 text-center text-xs text-muted-foreground">No entries matched this bounded query.</div> : null}
            </div>
          ) : null}
        </section>
      </div>

      {showRegister ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/40 p-4">
          <div className="w-full max-w-lg rounded-2xl bg-white p-5 shadow-2xl">
            <div className="flex items-center"><div><h2 className="text-sm font-semibold">Register Loki backend</h2><p className="text-[10px] text-muted-foreground">The host must be in ICHECK_LOGS_ALLOWED_HOSTS.</p></div><button className="ml-auto rounded-md p-2 hover:bg-slate-100" onClick={() => setShowRegister(false)}><X className="size-4" /></button></div>
            <div className="mt-5 space-y-3"><Input placeholder="Backend name" value={backendName} onChange={(event) => setBackendName(event.target.value)} /><Input placeholder="https://loki.example.internal" value={backendUrl} onChange={(event) => setBackendUrl(event.target.value)} /><Input placeholder="Device label" value={deviceLabel} onChange={(event) => setDeviceLabel(event.target.value)} /><Textarea value={allowedLabels} onChange={(event) => setAllowedLabels(event.target.value)} className="min-h-20 font-mono text-xs" /><p className="text-[10px] text-muted-foreground">This quick path creates an unauthenticated backend. Use <Link href="/settings/observability" className="font-semibold text-violet-700">Observability settings</Link> for bearer, basic, or custom-header authentication.</p></div>
            <div className="mt-5 flex justify-end gap-2"><Button variant="outline" onClick={() => setShowRegister(false)}>Cancel</Button><Button onClick={() => void registerBackend()} disabled={registering || !backendName.trim() || !backendUrl.trim()}>{registering ? <Loader2 className="size-4 animate-spin" /> : <CheckCircle2 className="size-4" />} Register</Button></div>
          </div>
        </div>
      ) : null}
    </main>
  );
}
