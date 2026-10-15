"use client";

import Link from "next/link";
import {
  FormEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  ArrowLeft,
  Bot,
  Clock3,
  Gauge,
  Loader2,
  Plus,
  RefreshCw,
  Save,
  ServerCog,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Pool = "collector" | "agent";

type ScalingPolicy = {
  id: string;
  name: string;
  pool: Pool;
  selector: Record<string, string>;
  required_capabilities: string[];
  enabled: boolean;
  min_replicas: number;
  max_replicas: number;
  target_queue_per_replica: number;
  scale_out_step: number;
  scale_in_step: number;
  queue_age_target_seconds: number;
  heartbeat_timeout_seconds: number;
  cooldown_seconds: number;
  revision: number;
  update_reason: string;
  updated_at: string;
};

type ScalingDecision = {
  id: string;
  policy_id: string;
  policy_revision: number;
  queue_depth: number;
  oldest_queue_age_seconds: number | null;
  current_replicas: number;
  ready_replicas: number;
  busy_replicas: number;
  stale_replicas: number;
  desired_replicas: number;
  direction: "scale_out" | "scale_in" | "hold";
  reasons: string[];
  observed_at: string;
};

type ScalingApplicationEvent = {
  id: string;
  decision_id: string;
  provider_subject: string;
  idempotency_key: string;
  status: "accepted" | "applying" | "applied" | "failed" | "rejected";
  observed_replicas: number;
  detail_code: string;
  error_sha256: string | null;
  created_at: string;
};

type Draft = {
  name: string;
  pool: Pool;
  selector: string;
  capabilities: string;
  enabled: boolean;
  minReplicas: string;
  maxReplicas: string;
  queueTarget: string;
  scaleOutStep: string;
  scaleInStep: string;
  queueAge: string;
  heartbeatTimeout: string;
  cooldown: string;
  reason: string;
};

const blankDraft: Draft = {
  name: "",
  pool: "collector",
  selector: "",
  capabilities: "",
  enabled: true,
  minReplicas: "1",
  maxReplicas: "20",
  queueTarget: "4",
  scaleOutStep: "2",
  scaleInStep: "1",
  queueAge: "30",
  heartbeatTimeout: "60",
  cooldown: "120",
  reason: "",
};

const inputClass =
  "h-10 border-slate-300 bg-white text-sm shadow-none focus-visible:border-violet-600 focus-visible:ring-violet-600/15";

function toDraft(policy: ScalingPolicy): Draft {
  return {
    name: policy.name,
    pool: policy.pool,
    selector: Object.entries(policy.selector)
      .map(([key, value]) => `${key}=${value}`)
      .join(", "),
    capabilities: policy.required_capabilities.join(", "),
    enabled: policy.enabled,
    minReplicas: String(policy.min_replicas),
    maxReplicas: String(policy.max_replicas),
    queueTarget: String(policy.target_queue_per_replica),
    scaleOutStep: String(policy.scale_out_step),
    scaleInStep: String(policy.scale_in_step),
    queueAge: String(policy.queue_age_target_seconds),
    heartbeatTimeout: String(policy.heartbeat_timeout_seconds),
    cooldown: String(policy.cooldown_seconds),
    reason: "",
  };
}

function parseSelector(value: string): Record<string, string> {
  const pairs = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [key, ...rest] = item.split("=");
      return [key.trim(), rest.join("=").trim()] as const;
    });
  if (pairs.some(([key, entry]) => !key || !entry)) {
    throw new Error("Each worker selector must use key=value syntax.");
  }
  return Object.fromEntries(pairs);
}

function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <span className="mb-1.5 block text-xs font-semibold text-slate-600">
      {children}
    </span>
  );
}

export default function ScalingSettingsPage() {
  const [policies, setPolicies] = useState<ScalingPolicy[]>([]);
  const [decisions, setDecisions] = useState<ScalingDecision[]>([]);
  const [applicationEvents, setApplicationEvents] = useState<ScalingApplicationEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft>(blankDraft);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextPolicies, nextDecisions, nextApplicationEvents] = await Promise.all([
        apiFetch<ScalingPolicy[]>("/scaling/policies"),
        apiFetch<ScalingDecision[]>("/scaling/decisions?limit=200"),
        apiFetch<ScalingApplicationEvent[]>("/scaling/application-events?limit=200"),
      ]);
      setPolicies(nextPolicies);
      setDecisions(nextDecisions);
      setApplicationEvents(nextApplicationEvents);
      setSelectedId((current) => {
        if (current === "new") return current;
        const selected = nextPolicies.find((item) => item.id === current) || nextPolicies[0];
        if (selected) setDraft(toDraft(selected));
        return selected?.id || "new";
      });
      setMessage(null);
    } catch (cause) {
      setMessage({
        error: true,
        text: cause instanceof Error ? cause.message : "Unable to load scaling policy",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selected = policies.find((item) => item.id === selectedId) || null;
  const latestByPolicy = useMemo(() => {
    const result = new Map<string, ScalingDecision>();
    decisions.forEach((decision) => {
      if (!result.has(decision.policy_id)) result.set(decision.policy_id, decision);
    });
    return result;
  }, [decisions]);
  const latestApplicationByDecision = useMemo(() => {
    const result = new Map<string, ScalingApplicationEvent>();
    applicationEvents.forEach((event) => {
      if (!result.has(event.decision_id)) result.set(event.decision_id, event);
    });
    return result;
  }, [applicationEvents]);

  function choose(policy: ScalingPolicy) {
    setSelectedId(policy.id);
    setDraft(toDraft(policy));
    setMessage(null);
  }

  function createNew() {
    setSelectedId("new");
    setDraft(blankDraft);
    setMessage(null);
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selected && draft.reason.trim().length < 3) {
      setMessage({ error: true, text: "Add an audit reason before revising this policy." });
      return;
    }
    setBusy("save");
    try {
      const payload = {
        name: draft.name.trim(),
        pool: draft.pool,
        selector: draft.pool === "collector" ? parseSelector(draft.selector) : {},
        required_capabilities: draft.capabilities
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        enabled: draft.enabled,
        min_replicas: Number(draft.minReplicas),
        max_replicas: Number(draft.maxReplicas),
        target_queue_per_replica: Number(draft.queueTarget),
        scale_out_step: Number(draft.scaleOutStep),
        scale_in_step: Number(draft.scaleInStep),
        queue_age_target_seconds: Number(draft.queueAge),
        heartbeat_timeout_seconds: Number(draft.heartbeatTimeout),
        cooldown_seconds: Number(draft.cooldown),
        reason: draft.reason.trim() || "Create regional worker scaling policy.",
      };
      const saved = selected
        ? await apiFetch<ScalingPolicy>(`/scaling/policies/${selected.id}`, {
            method: "PUT",
            body: JSON.stringify({ ...payload, expected_revision: selected.revision }),
          })
        : await apiFetch<ScalingPolicy>("/scaling/policies", {
            method: "POST",
            body: JSON.stringify(payload),
          });
      setSelectedId(saved.id);
      setMessage({ error: false, text: `Saved ${saved.pool} policy revision ${saved.revision}.` });
      await load();
    } catch (cause) {
      setMessage({ error: true, text: cause instanceof Error ? cause.message : "Unable to save policy" });
    } finally {
      setBusy(null);
    }
  }

  async function evaluate() {
    setBusy("evaluate");
    try {
      const results = await apiFetch<ScalingDecision[]>("/scaling/evaluate", {
        method: "POST",
      });
      setMessage({ error: false, text: `Recorded ${results.length} bounded recommendation${results.length === 1 ? "" : "s"}.` });
      await load();
    } catch (cause) {
      setMessage({ error: true, text: cause instanceof Error ? cause.message : "Unable to evaluate policy" });
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1400px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link href="/" className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700" aria-label="Back to AI operator">
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2"><Gauge className="size-5 text-violet-600" /><h1 className="text-xl font-semibold tracking-tight">Worker capacity policy</h1></div>
              <p className="mt-1 text-xs text-muted-foreground">Regional recommendations and opt-in allowlisted systemd application for bare-metal Worker pools.</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} />Refresh</Button>
            <Button size="sm" className="bg-violet-600 hover:bg-violet-700" onClick={() => void evaluate()} disabled={busy !== null}>{busy === "evaluate" ? <Loader2 className="animate-spin" /> : <Gauge />}Evaluate now</Button>
          </div>
        </header>

        {message && <div className={`mt-5 rounded-xl border px-4 py-3 text-sm ${message.error ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"}`}>{message.text}</div>}

        <section className="mt-6 grid gap-5 lg:grid-cols-[0.72fr_1.28fr]">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <div className="flex items-center justify-between"><div><CardTitle className="text-base">Regional pools</CardTitle><CardDescription>Policies are isolated to the active tenant and region.</CardDescription></div><Button size="sm" variant="outline" onClick={createNew}><Plus />New</Button></div>
            </CardHeader>
            <CardContent className="space-y-3">
              {loading ? <div className="flex h-32 items-center justify-center text-sm text-muted-foreground"><Loader2 className="mr-2 size-4 animate-spin" />Loading capacity state</div> : policies.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 p-6 text-center text-sm text-muted-foreground">No scaling policy exists in this region.</div> : policies.map((policy) => {
                const decision = latestByPolicy.get(policy.id);
                return <button key={policy.id} type="button" onClick={() => choose(policy)} className={`w-full rounded-xl border p-4 text-left transition ${selectedId === policy.id ? "border-violet-300 bg-violet-50" : "border-slate-200 bg-white hover:border-slate-300"}`}>
                  <div className="flex items-start justify-between gap-3"><span><span className="block text-sm font-semibold">{policy.name}</span><span className="mt-1 block text-[11px] text-muted-foreground">{policy.pool} · r{policy.revision}</span></span><Badge variant={policy.enabled ? "default" : "outline"}>{policy.enabled ? "Enabled" : "Disabled"}</Badge></div>
                  {decision ? <div className="mt-3 grid grid-cols-3 gap-2 text-center"><span className="rounded-lg bg-white p-2 text-xs"><strong className="block text-base">{decision.queue_depth}</strong>queued</span><span className="rounded-lg bg-white p-2 text-xs"><strong className="block text-base">{decision.current_replicas}</strong>current</span><span className="rounded-lg bg-white p-2 text-xs"><strong className="block text-base text-violet-700">{decision.desired_replicas}</strong>desired</span></div> : <p className="mt-3 text-xs text-amber-700">Awaiting first controller evaluation.</p>}
                </button>;
              })}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader><CardTitle className="flex items-center gap-2 text-base">{draft.pool === "collector" ? <ServerCog className="size-4 text-violet-600" /> : <Bot className="size-4 text-violet-600" />}{selected ? `Edit ${selected.name}` : "Create capacity policy"}</CardTitle><CardDescription>The controller records desired replicas; an independently deployed provider may apply explicitly allowlisted process changes.</CardDescription></CardHeader>
            <CardContent>
              <form className="grid gap-4 sm:grid-cols-2" onSubmit={save}>
                <label><FieldLabel>Name</FieldLabel><Input required className={inputClass} value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></label>
                <label><FieldLabel>Pool</FieldLabel><select className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm" value={draft.pool} onChange={(event) => setDraft((current) => ({ ...current, pool: event.target.value as Pool, selector: event.target.value === "agent" ? "" : current.selector }))}><option value="collector">Collector workers</option><option value="agent">Agent workers</option></select></label>
                <label><FieldLabel>{draft.pool === "collector" ? "Worker selector (key=value)" : "Worker selector"}</FieldLabel><Input className={inputClass} disabled={draft.pool === "agent"} value={draft.selector} onChange={(event) => setDraft((current) => ({ ...current, selector: event.target.value }))} placeholder="site=HKG, tier=edge" /></label>
                <label><FieldLabel>Required capabilities</FieldLabel><Input className={inputClass} value={draft.capabilities} onChange={(event) => setDraft((current) => ({ ...current, capabilities: event.target.value }))} placeholder={draft.pool === "collector" ? "snmp_exporter, http_json" : "openai_compatible"} /></label>
                {([
                  ["Minimum replicas", "minReplicas"], ["Maximum replicas", "maxReplicas"], ["Queue per replica", "queueTarget"], ["Scale-out step", "scaleOutStep"], ["Scale-in step", "scaleInStep"], ["Queue age target (s)", "queueAge"], ["Heartbeat timeout (s)", "heartbeatTimeout"], ["Cooldown (s)", "cooldown"],
                ] as Array<[string, keyof Draft]>).map(([label, key]) => <label key={key}><FieldLabel>{label}</FieldLabel><Input required type="number" min={key === "minReplicas" || key === "queueAge" || key === "cooldown" ? "0" : "1"} className={inputClass} value={String(draft[key])} onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))} /></label>)}
                <label className="sm:col-span-2"><FieldLabel>{selected ? "Revision reason" : "Creation reason"}</FieldLabel><Input required={Boolean(selected)} className={inputClass} value={draft.reason} onChange={(event) => setDraft((current) => ({ ...current, reason: event.target.value }))} placeholder="Why this capacity policy is safe and necessary" /></label>
                <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 sm:col-span-2"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))} className="size-4 accent-violet-600" /><span className="text-sm font-medium">Controller evaluates this policy</span></label>
                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4 sm:col-span-2"><div className="flex items-center gap-2 text-xs text-muted-foreground"><ShieldCheck className="size-4 text-emerald-600" />Bounded steps, cooldown, stale-worker exclusion, and immutable audit decisions.</div><Button className="bg-violet-600 hover:bg-violet-700" disabled={busy !== null}>{busy === "save" ? <Loader2 className="animate-spin" /> : <Save />}Save policy</Button></div>
              </form>
            </CardContent>
          </Card>
        </section>

        <Card className="mt-5 border-slate-200 shadow-sm"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Clock3 className="size-4 text-violet-600" />Immutable recommendation history</CardTitle><CardDescription>Latest 200 decisions and capacity-provider receipts in the active regional boundary.</CardDescription></CardHeader><CardContent><div className="overflow-x-auto"><table className="w-full min-w-[980px] text-left text-xs"><thead className="border-b border-slate-200 text-muted-foreground"><tr><th className="px-3 py-2">Observed</th><th className="px-3 py-2">Policy</th><th className="px-3 py-2">Queue</th><th className="px-3 py-2">Ready / stale</th><th className="px-3 py-2">Current → desired</th><th className="px-3 py-2">Provider state</th><th className="px-3 py-2">Reason</th></tr></thead><tbody>{decisions.slice(0, 30).map((decision) => { const policy = policies.find((item) => item.id === decision.policy_id); const application = latestApplicationByDecision.get(decision.id); return <tr key={decision.id} className="border-b border-slate-100"><td className="px-3 py-3 text-muted-foreground">{new Date(decision.observed_at).toLocaleString()}</td><td className="px-3 py-3 font-medium">{policy?.name || decision.policy_id}</td><td className="px-3 py-3">{decision.queue_depth}</td><td className="px-3 py-3">{decision.ready_replicas} / {decision.stale_replicas}</td><td className="px-3 py-3"><Badge variant="outline">{decision.current_replicas} → {decision.desired_replicas}</Badge></td><td className="px-3 py-3">{application ? <div><Badge variant={application.status === "failed" || application.status === "rejected" ? "destructive" : "outline"}>{application.status}</Badge><div className="mt-1 text-[10px] text-muted-foreground">{application.provider_subject} · {application.observed_replicas} observed</div></div> : <span className="text-muted-foreground">not reported</span>}</td><td className="px-3 py-3 text-muted-foreground">{decision.reasons.join(", ")}</td></tr>; })}</tbody></table></div></CardContent></Card>
      </div>
    </main>
  );
}
