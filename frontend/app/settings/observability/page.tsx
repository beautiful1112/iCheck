"use client";

import Link from "next/link";
import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  Database,
  KeyRound,
  Loader2,
  Pencil,
  Power,
  RefreshCw,
  ScrollText,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Adapter = "prometheus_query" | "loki_query";
type AuthType = "none" | "bearer" | "basic" | "header";

type CredentialProfile = {
  id: string;
  name: string;
  provider: string;
  allowed_adapters: string[];
  worker_selector: Record<string, string>;
  enabled: boolean;
};

type Backend = {
  id: string;
  name: string;
  provider: string;
  query_base_url: string;
  auth_type: AuthType;
  auth_header_name: string | null;
  credential_profile_ref: string | null;
  remote_write_url?: string | null;
  external_labels?: Record<string, string>;
  device_label?: string;
  allowed_labels?: string[];
  enabled: boolean;
  revision: number;
  last_checked_at: string | null;
  last_health_status: string | null;
  last_health_error: string | null;
};

type BackendDraft = {
  name: string;
  url: string;
  authType: AuthType;
  authHeaderName: string;
  credentialRef: string;
};

const emptyDraft: BackendDraft = {
  name: "",
  url: "",
  authType: "none",
  authHeaderName: "",
  credentialRef: "",
};

const inputClass =
  "h-10 border-slate-300 bg-white text-sm shadow-none focus-visible:border-violet-600 focus-visible:ring-violet-600/15";
const selectClass =
  "h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-700 outline-none focus:border-violet-600 focus:ring-2 focus:ring-violet-100";

function FieldLabel({ children }: { children: ReactNode }) {
  return <span className="mb-1.5 block text-xs font-semibold text-slate-600">{children}</span>;
}

function healthTone(status: string | null) {
  if (status === "healthy") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "unhealthy") return "border-red-200 bg-red-50 text-red-700";
  return "border-slate-200 bg-slate-50 text-slate-600";
}

export default function ObservabilitySettingsPage() {
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [metrics, setMetrics] = useState<Backend[]>([]);
  const [logs, setLogs] = useState<Backend[]>([]);
  const [metricDraft, setMetricDraft] = useState<BackendDraft>(emptyDraft);
  const [logDraft, setLogDraft] = useState<BackendDraft>(emptyDraft);
  const [editingMetricId, setEditingMetricId] = useState<string | null>(null);
  const [editingLogId, setEditingLogId] = useState<string | null>(null);
  const [credentialName, setCredentialName] = useState("");
  const [credentialProvider, setCredentialProvider] = useState<"environment" | "vault">("environment");
  const [secretRef, setSecretRef] = useState("env://ICHECK_OBSERVABILITY_TOKEN");
  const [credentialTarget, setCredentialTarget] = useState<"metrics" | "logs" | "both">("metrics");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextCredentials, nextMetrics, nextLogs] = await Promise.all([
        apiFetch<CredentialProfile[]>("/credential-profiles?enabled=true&limit=1000"),
        apiFetch<Backend[]>("/metrics/backends?limit=500"),
        apiFetch<Backend[]>("/logs/backends?limit=500"),
      ]);
      setCredentials(
        nextCredentials.filter(
          (item) =>
            item.enabled &&
            Object.keys(item.worker_selector).length === 0 &&
            (item.allowed_adapters.includes("prometheus_query") ||
              item.allowed_adapters.includes("loki_query")),
        ),
      );
      setMetrics(nextMetrics);
      setLogs(nextLogs);
    } catch (cause) {
      setMessage({
        error: true,
        text: cause instanceof Error ? cause.message : "Unable to load observability settings",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const credentialNames = useMemo(
    () => new Map(
      credentials.flatMap((credential) => [
        [credential.id, credential.name],
        [credential.name, credential.name],
      ]),
    ),
    [credentials],
  );

  function eligible(adapter: Adapter) {
    return credentials.filter((item) => item.allowed_adapters.includes(adapter));
  }

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("credential");
    setMessage(null);
    const allowedAdapters =
      credentialTarget === "both"
        ? ["prometheus_query", "loki_query"]
        : [credentialTarget === "metrics" ? "prometheus_query" : "loki_query"];
    try {
      await apiFetch("/credential-profiles", {
        method: "POST",
        body: JSON.stringify({
          name: credentialName,
          provider: credentialProvider,
          secret_ref: secretRef,
          allowed_adapters: allowedAdapters,
          worker_selector: {},
          created_by: "observability.settings",
        }),
      });
      setCredentialName("");
      setMessage({ error: false, text: "Credential reference created. No secret value was stored in iCheck." });
      await load();
    } catch (cause) {
      setMessage({ error: true, text: cause instanceof Error ? cause.message : "Unable to create credential reference" });
    } finally {
      setBusy(null);
    }
  }

  function credentialId(reference: string | null) {
    if (!reference) return "";
    return credentials.find(
      (credential) =>
        credential.id === reference || credential.name === reference,
    )?.id || reference;
  }

  function updatePayload(
    kind: "metrics" | "logs",
    backend: Backend,
    draft: BackendDraft,
    enabled = backend.enabled,
  ) {
    const common = {
      expected_revision: backend.revision,
      name: draft.name,
      provider: kind === "metrics" ? "prometheus" : "loki",
      query_base_url: draft.url,
      auth_type: draft.authType,
      auth_header_name: draft.authType === "header" ? draft.authHeaderName : null,
      credential_profile_ref: draft.authType === "none" ? null : draft.credentialRef,
      enabled,
      actor: "observability.settings",
    };
    return kind === "metrics"
      ? {
          ...common,
          remote_write_url: backend.remote_write_url || null,
          external_labels: backend.external_labels || {},
        }
      : {
          ...common,
          device_label: backend.device_label || "instance",
          allowed_labels: backend.allowed_labels || ["instance"],
        };
  }

  function beginEdit(kind: "metrics" | "logs", backend: Backend) {
    const draft = {
      name: backend.name,
      url: backend.query_base_url,
      authType: backend.auth_type,
      authHeaderName: backend.auth_header_name || "",
      credentialRef: credentialId(backend.credential_profile_ref),
    };
    if (kind === "metrics") {
      setMetricDraft(draft);
      setEditingMetricId(backend.id);
    } else {
      setLogDraft(draft);
      setEditingLogId(backend.id);
    }
  }

  function cancelEdit(kind: "metrics" | "logs") {
    if (kind === "metrics") {
      setMetricDraft(emptyDraft);
      setEditingMetricId(null);
    } else {
      setLogDraft(emptyDraft);
      setEditingLogId(null);
    }
  }

  async function saveBackend(kind: "metrics" | "logs") {
    const draft = kind === "metrics" ? metricDraft : logDraft;
    const editingId = kind === "metrics" ? editingMetricId : editingLogId;
    const existing = (kind === "metrics" ? metrics : logs).find(
      (backend) => backend.id === editingId,
    );
    setBusy(kind);
    setMessage(null);
    try {
      const common = {
        name: draft.name,
        query_base_url: draft.url,
        auth_type: draft.authType,
        auth_header_name: draft.authType === "header" ? draft.authHeaderName : null,
        credential_profile_ref: draft.authType === "none" ? null : draft.credentialRef,
      };
      const path = existing
        ? `/${kind}/backends/${existing.id}`
        : kind === "metrics"
          ? "/metrics/backends"
          : "/logs/backends";
      const body = existing
        ? updatePayload(kind, existing, draft)
        : {
            ...common,
            provider: kind === "metrics" ? "prometheus" : "loki",
            created_by: "observability.settings",
            ...(kind === "logs"
              ? {
                  device_label: "instance",
                  allowed_labels: ["instance", "job", "host", "hostname", "app", "service", "level", "severity", "namespace", "container", "source"],
                }
              : {}),
          };
      await apiFetch(path, {
        method: existing ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      cancelEdit(kind);
      setMessage({ error: false, text: `${kind === "metrics" ? "Metric" : "Log"} backend ${existing ? "updated" : "registered"}.` });
      await load();
    } catch (cause) {
      setMessage({ error: true, text: cause instanceof Error ? cause.message : "Unable to register backend" });
    } finally {
      setBusy(null);
    }
  }

  async function toggleBackend(kind: "metrics" | "logs", backend: Backend) {
    setBusy(`toggle-${backend.id}`);
    setMessage(null);
    try {
      const draft = {
        name: backend.name,
        url: backend.query_base_url,
        authType: backend.auth_type,
        authHeaderName: backend.auth_header_name || "",
        credentialRef: credentialId(backend.credential_profile_ref),
      };
      await apiFetch(`/${kind}/backends/${backend.id}`, {
        method: "PUT",
        body: JSON.stringify(
          updatePayload(kind, backend, draft, !backend.enabled),
        ),
      });
      setMessage({
        error: false,
        text: `${backend.name} ${backend.enabled ? "disabled" : "enabled"}.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        error: true,
        text: cause instanceof Error ? cause.message : "Unable to change backend state",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function checkHealth(kind: "metrics" | "logs", backendId: string) {
    setBusy(backendId);
    setMessage(null);
    try {
      await apiFetch(`/${kind}/backends/${backendId}/health?actor=observability.settings`, { method: "POST" });
      await load();
    } catch (cause) {
      setMessage({ error: true, text: cause instanceof Error ? cause.message : "Health check failed" });
    } finally {
      setBusy(null);
    }
  }

  function backendForm(
    kind: "metrics" | "logs",
    draft: BackendDraft,
    setDraft: (value: BackendDraft) => void,
  ) {
    const adapter: Adapter = kind === "metrics" ? "prometheus_query" : "loki_query";
    const editingId = kind === "metrics" ? editingMetricId : editingLogId;
    const availableCredentials = eligible(adapter);
    const ready =
      draft.name.trim() &&
      draft.url.trim() &&
      (draft.authType === "none" || draft.credentialRef) &&
      (draft.authType !== "header" || draft.authHeaderName.trim());
    return (
      <div className="grid gap-4 sm:grid-cols-2">
        <label><FieldLabel>Backend name</FieldLabel><Input className={inputClass} value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder={kind === "metrics" ? "regional-prometheus" : "central-loki"} /></label>
        <label><FieldLabel>Query URL</FieldLabel><Input className={inputClass} value={draft.url} onChange={(event) => setDraft({ ...draft, url: event.target.value })} placeholder={kind === "metrics" ? "https://prometheus.example.net" : "https://loki.example.net"} /></label>
        <label><FieldLabel>Authentication</FieldLabel><select className={selectClass} value={draft.authType} onChange={(event) => setDraft({ ...draft, authType: event.target.value as AuthType, authHeaderName: event.target.value === "header" ? draft.authHeaderName : "" })}><option value="none">None</option><option value="bearer">Bearer token</option><option value="basic">Basic username:password</option><option value="header">Custom header</option></select></label>
        {draft.authType !== "none" ? <label><FieldLabel>Credential Profile</FieldLabel><select className={selectClass} value={draft.credentialRef} onChange={(event) => setDraft({ ...draft, credentialRef: event.target.value })}><option value="">Select a control-plane profile</option>{availableCredentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} · {credential.provider}</option>)}</select></label> : <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">No authentication header will be sent.</div>}
        {draft.authType === "header" ? <label className="sm:col-span-2"><FieldLabel>Custom header name</FieldLabel><Input className={inputClass} value={draft.authHeaderName} onChange={(event) => setDraft({ ...draft, authHeaderName: event.target.value })} placeholder={kind === "logs" ? "X-Scope-OrgID" : "X-API-Key"} /></label> : null}
        <div className="flex gap-2 sm:col-span-2"><Button onClick={() => void saveBackend(kind)} disabled={!ready || busy !== null}>{busy === kind ? <Loader2 className="size-4 animate-spin" /> : <CheckCircle2 className="size-4" />} {editingId ? "Save revision" : `Register ${kind === "metrics" ? "metric" : "log"} backend`}</Button>{editingId ? <Button variant="outline" onClick={() => cancelEdit(kind)} disabled={busy !== null}><X className="size-4" /> Cancel</Button> : null}</div>
      </div>
    );
  }

  function backendList(kind: "metrics" | "logs", items: Backend[]) {
    return (
      <div className="space-y-2">
        {items.map((backend) => (
          <div key={backend.id} className="rounded-xl border border-slate-200 bg-white p-3">
            <div className="flex items-start gap-3">
              <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-violet-50 text-violet-700">{kind === "metrics" ? <Activity className="size-4" /> : <ScrollText className="size-4" />}</div>
              <div className="min-w-0"><div className="flex items-center gap-2"><p className="text-sm font-semibold text-slate-800">{backend.name}</p>{!backend.enabled ? <Badge variant="outline" className="border-slate-300 bg-slate-100 text-slate-600">disabled</Badge> : null}</div><p className="mt-0.5 truncate text-[11px] text-muted-foreground">{backend.query_base_url}</p><p className="mt-1 text-[10px] text-muted-foreground">{backend.auth_type === "none" ? "No authentication" : `${backend.auth_type} · ${credentialNames.get(backend.credential_profile_ref || "") || "Credential Profile"}`} · revision {backend.revision}</p>{backend.last_health_error ? <p className="mt-1 line-clamp-2 text-[10px] text-red-600">{backend.last_health_error}</p> : null}</div>
              <div className="ml-auto flex shrink-0 items-center gap-2"><Badge variant="outline" className={healthTone(backend.last_health_status)}>{backend.last_health_status || "unchecked"}</Badge><Button size="sm" variant="outline" aria-label={`Edit ${backend.name}`} onClick={() => beginEdit(kind, backend)} disabled={busy !== null}><Pencil className="size-3.5" /></Button><Button size="sm" variant="outline" aria-label={`${backend.enabled ? "Disable" : "Enable"} ${backend.name}`} onClick={() => void toggleBackend(kind, backend)} disabled={busy !== null}>{busy === `toggle-${backend.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <Power className="size-3.5" />}</Button><Button size="sm" variant="outline" aria-label={`Check ${backend.name}`} onClick={() => void checkHealth(kind, backend.id)} disabled={busy !== null || !backend.enabled}>{busy === backend.id ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}</Button></div>
            </div>
          </div>
        ))}
        {!items.length ? <p className="rounded-xl border border-dashed border-slate-300 p-5 text-center text-xs text-muted-foreground">No backend registered yet.</p> : null}
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-[1500px] items-center gap-3 px-5 py-4"><Link href="/" aria-label="Back to AI operator" className="grid size-9 place-items-center rounded-xl border border-slate-200 text-slate-600 hover:text-violet-700"><ArrowLeft className="size-4" /></Link><div className="grid size-9 place-items-center rounded-xl bg-violet-600 text-white"><Database className="size-4" /></div><div><h1 className="text-sm font-semibold">Observability backends</h1><p className="text-[11px] text-muted-foreground">Prometheus and Loki query planes · Credential Profile references only</p></div><Button className="ml-auto" size="sm" variant="outline" onClick={() => void load()} disabled={loading}>{loading ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />} Refresh</Button></div></header>

      <div className="mx-auto max-w-[1500px] space-y-5 px-5 py-5">
        {message ? <div className={`rounded-xl border px-4 py-3 text-xs ${message.error ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"}`}>{message.text}</div> : null}
        <div className="grid gap-5 xl:grid-cols-[390px_minmax(0,1fr)]">
          <Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><KeyRound className="size-4 text-violet-600" />Credential reference</CardTitle><CardDescription>Store only an environment or Vault reference. The resolved value never returns to the browser.</CardDescription></CardHeader><CardContent><form className="space-y-3" onSubmit={(event) => void createCredential(event)}><label><FieldLabel>Profile name</FieldLabel><Input className={inputClass} value={credentialName} onChange={(event) => setCredentialName(event.target.value)} placeholder="observability-readonly" /></label><label><FieldLabel>Provider</FieldLabel><select className={selectClass} value={credentialProvider} onChange={(event) => setCredentialProvider(event.target.value as "environment" | "vault")}><option value="environment">Environment</option><option value="vault">Vault KV v2</option></select></label><label><FieldLabel>Secret reference</FieldLabel><Input className={inputClass} value={secretRef} onChange={(event) => setSecretRef(event.target.value)} /></label><label><FieldLabel>Allowed query adapters</FieldLabel><select className={selectClass} value={credentialTarget} onChange={(event) => setCredentialTarget(event.target.value as "metrics" | "logs" | "both")}><option value="metrics">Prometheus only</option><option value="logs">Loki only</option><option value="both">Prometheus and Loki</option></select></label><Button type="submit" disabled={!credentialName.trim() || !secretRef.trim() || busy !== null}>{busy === "credential" ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />} Create reference</Button></form></CardContent></Card>

          <div className="grid gap-5 lg:grid-cols-2"><Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><Activity className="size-4 text-violet-600" />Metric query plane</CardTitle><CardDescription>Register a host allowlisted by ICHECK_METRICS_ALLOWED_HOSTS.</CardDescription></CardHeader><CardContent>{backendForm("metrics", metricDraft, setMetricDraft)}</CardContent></Card><Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><ScrollText className="size-4 text-violet-600" />Log query plane</CardTitle><CardDescription>Register a host allowlisted by ICHECK_LOGS_ALLOWED_HOSTS.</CardDescription></CardHeader><CardContent>{backendForm("logs", logDraft, setLogDraft)}</CardContent></Card></div>
        </div>

        <div className="grid gap-5 lg:grid-cols-2"><Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><Server className="size-4" />Metric backends</CardTitle><CardDescription>{metrics.length} registered query sources</CardDescription></CardHeader><CardContent>{backendList("metrics", metrics)}</CardContent></Card><Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><Server className="size-4" />Log backends</CardTitle><CardDescription>{logs.length} registered query sources · <Link href="/logs" className="font-semibold text-violet-700">open evidence workspace</Link></CardDescription></CardHeader><CardContent>{backendList("logs", logs)}</CardContent></Card></div>
      </div>
    </main>
  );
}
