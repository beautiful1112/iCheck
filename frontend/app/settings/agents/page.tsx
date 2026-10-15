"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  BrainCircuit,
  CheckCircle2,
  Coins,
  Fingerprint,
  Gauge,
  Loader2,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Wrench,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type PrivacyTier = "external" | "private" | "local";
type CostClass = "low" | "standard" | "premium";
type ToolPolicy = "permission_scoped" | "allowlist";

type AgentProfile = {
  id: string;
  name: string;
  description: string;
  role_instructions: string;
  escalation_instructions: string;
  route_purpose: string;
  tool_policy: ToolPolicy;
  allowed_tool_names: string[];
  minimum_provider_privacy: PrivacyTier;
  allowed_data_residencies: string[];
  allowed_model_cost_classes: CostClass[];
  max_iterations: number;
  max_tool_calls: number;
  timeout_seconds: number;
  token_budget: number;
  enabled: boolean;
  revision: number;
  updated_by: string;
  update_reason: string;
  updated_at: string;
};

type ModelRoute = {
  id: string;
  purpose: string;
  enabled: boolean;
};

type AgentTool = {
  id: string;
  name: string;
  description: string;
  read_only: boolean;
  risk_level: string;
  enabled: boolean;
};

type ProfileDraft = {
  name: string;
  description: string;
  roleInstructions: string;
  escalationInstructions: string;
  routePurpose: string;
  toolPolicy: ToolPolicy;
  allowedTools: string[];
  minimumPrivacy: PrivacyTier;
  dataResidencies: string;
  allowedCosts: CostClass[];
  maxIterations: string;
  maxToolCalls: string;
  timeoutSeconds: string;
  tokenBudget: string;
  enabled: boolean;
  reason: string;
};

const selectClass =
  "h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-700 outline-none focus:border-violet-500 focus:ring-2 focus:ring-violet-500/15";

function blankDraft(routePurpose = "investigation"): ProfileDraft {
  return {
    name: "",
    description: "",
    roleInstructions: "",
    escalationInstructions: "",
    routePurpose,
    toolPolicy: "permission_scoped",
    allowedTools: [],
    minimumPrivacy: "external",
    dataResidencies: "",
    allowedCosts: ["low", "standard", "premium"],
    maxIterations: "8",
    maxToolCalls: "20",
    timeoutSeconds: "300",
    tokenBudget: "50000",
    enabled: true,
    reason: "",
  };
}

function profileDraft(profile: AgentProfile): ProfileDraft {
  return {
    name: profile.name,
    description: profile.description,
    roleInstructions: profile.role_instructions,
    escalationInstructions: profile.escalation_instructions,
    routePurpose: profile.route_purpose,
    toolPolicy: profile.tool_policy,
    allowedTools: profile.allowed_tool_names,
    minimumPrivacy: profile.minimum_provider_privacy,
    dataResidencies: profile.allowed_data_residencies.join(", "),
    allowedCosts: profile.allowed_model_cost_classes,
    maxIterations: String(profile.max_iterations),
    maxToolCalls: String(profile.max_tool_calls),
    timeoutSeconds: String(profile.timeout_seconds),
    tokenBudget: String(profile.token_budget),
    enabled: profile.enabled,
    reason: "",
  };
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <span className="mb-1.5 block text-xs font-semibold text-slate-600">{children}</span>;
}

export default function AgentProfilesPage() {
  const [profiles, setProfiles] = useState<AgentProfile[]>([]);
  const [routes, setRoutes] = useState<ModelRoute[]>([]);
  const [tools, setTools] = useState<AgentTool[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<ProfileDraft>(blankDraft());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [profileData, routeData, toolData] = await Promise.all([
        apiFetch<AgentProfile[]>("/ai/agent-profiles"),
        apiFetch<ModelRoute[]>("/ai/routes"),
        apiFetch<AgentTool[]>("/agent/tools?enabled=true&limit=1000"),
      ]);
      setProfiles(profileData);
      setRoutes(routeData.filter((item) => item.enabled));
      setTools(toolData.filter((item) => item.enabled));
      setSelectedId((current) => {
        if (current === "new") return current;
        const next = profileData.find((item) => item.id === current) || profileData[0];
        if (next) setDraft(profileDraft(next));
        return next?.id || "new";
      });
      setMessage(null);
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to load AgentProfiles",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selected = profiles.find((item) => item.id === selectedId) || null;

  function choose(profile: AgentProfile) {
    setSelectedId(profile.id);
    setDraft(profileDraft(profile));
    setMessage(null);
  }

  function createNew() {
    setSelectedId("new");
    setDraft(blankDraft(routes[0]?.purpose || "investigation"));
    setMessage(null);
  }

  function toggleCost(cost: CostClass) {
    setDraft((current) => ({
      ...current,
      allowedCosts: current.allowedCosts.includes(cost)
        ? current.allowedCosts.filter((item) => item !== cost)
        : [...current.allowedCosts, cost],
    }));
  }

  function toggleTool(name: string) {
    setDraft((current) => ({
      ...current,
      allowedTools: current.allowedTools.includes(name)
        ? current.allowedTools.filter((item) => item !== name)
        : [...current.allowedTools, name],
    }));
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (draft.allowedCosts.length === 0) {
      setMessage({ tone: "error", text: "Allow at least one model cost class." });
      return;
    }
    if (draft.toolPolicy === "allowlist" && draft.allowedTools.length === 0) {
      setMessage({ tone: "error", text: "Select at least one Tool for allowlist mode." });
      return;
    }
    if (selected && draft.reason.trim().length < 3) {
      setMessage({ tone: "error", text: "Add an audit reason before revising a profile." });
      return;
    }
    const common = {
      name: draft.name.trim(),
      description: draft.description.trim(),
      role_instructions: draft.roleInstructions.trim(),
      escalation_instructions: draft.escalationInstructions.trim(),
      route_purpose: draft.routePurpose,
      tool_policy: draft.toolPolicy,
      allowed_tool_names: draft.toolPolicy === "allowlist" ? draft.allowedTools : [],
      minimum_provider_privacy: draft.minimumPrivacy,
      allowed_data_residencies: draft.dataResidencies
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean),
      allowed_model_cost_classes: draft.allowedCosts,
      max_iterations: Number(draft.maxIterations),
      max_tool_calls: Number(draft.maxToolCalls),
      timeout_seconds: Number(draft.timeoutSeconds),
      token_budget: Number(draft.tokenBudget),
      enabled: draft.enabled,
    };
    setSaving(true);
    setMessage(null);
    try {
      let saved: AgentProfile;
      if (selected) {
        saved = await apiFetch<AgentProfile>(`/ai/agent-profiles/${selected.id}`, {
          method: "PUT",
          body: JSON.stringify({
            ...common,
            expected_revision: selected.revision,
            reason: draft.reason.trim(),
            actor: "platform.admin",
          }),
        });
      } else {
        saved = await apiFetch<AgentProfile>("/ai/agent-profiles", {
          method: "POST",
          body: JSON.stringify({ ...common, created_by: "platform.admin" }),
        });
      }
      await load();
      setSelectedId(saved.id);
      setDraft(profileDraft(saved));
      setMessage({
        tone: "success",
        text: `${saved.name} revision ${saved.revision} is ready for new Investigations.`,
      });
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to save AgentProfile",
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1450px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/settings/ai"
              className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700"
              aria-label="Back to AI settings"
            >
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <BrainCircuit className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">Agent profiles</h1>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Versioned role, Tool, placement, cost, and budget policy for AI operators.
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={createNew}>
              <Plus className="size-3.5" /> New profile
            </Button>
            <Button variant="outline" size="sm" onClick={() => void load()}>
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh
            </Button>
          </div>
        </header>

        {message ? (
          <div className={cn(
            "mt-5 flex items-start gap-2 rounded-xl border px-4 py-3 text-sm",
            message.tone === "success"
              ? "border-emerald-200 bg-emerald-50 text-emerald-800"
              : "border-red-200 bg-red-50 text-red-800",
          )}>
            {message.tone === "success" ? <CheckCircle2 className="mt-0.5 size-4" /> : <AlertTriangle className="mt-0.5 size-4" />}
            {message.text}
          </div>
        ) : null}

        <section className="mt-6 grid items-start gap-5 lg:grid-cols-[310px_minmax(0,1fr)]">
          <aside className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-100 px-4 py-3">
              <p className="text-xs font-semibold text-slate-700">Available profiles</p>
              <p className="mt-1 text-[10px] text-muted-foreground">New runs freeze one exact revision.</p>
            </div>
            <div className="space-y-1 p-2">
              {loading && profiles.length === 0 ? (
                <div className="grid min-h-32 place-items-center"><Loader2 className="size-5 animate-spin text-violet-500" /></div>
              ) : profiles.map((profile) => (
                <button
                  type="button"
                  key={profile.id}
                  onClick={() => choose(profile)}
                  className={cn(
                    "w-full rounded-xl px-3 py-3 text-left hover:bg-slate-50",
                    selectedId === profile.id && "bg-violet-50 hover:bg-violet-50",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-xs font-semibold text-slate-700">{profile.name}</p>
                    <span className={cn("size-2 rounded-full", profile.enabled ? "bg-emerald-500" : "bg-red-400")} />
                  </div>
                  <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{profile.description || "No description"}</p>
                  <div className="mt-2 flex gap-1.5">
                    <Badge variant="outline" className="text-[8px]">r{profile.revision}</Badge>
                    <Badge variant="outline" className="text-[8px] capitalize">{profile.minimum_provider_privacy}</Badge>
                    <Badge variant="outline" className="text-[8px]">{profile.tool_policy === "allowlist" ? `${profile.allowed_tool_names.length} Tools` : "Scoped Registry"}</Badge>
                  </div>
                </button>
              ))}
            </div>
          </aside>

          <form onSubmit={save} className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-violet-600">
                  {selected ? `Revision ${selected.revision}` : "New policy"}
                </p>
                <h2 className="mt-1 text-lg font-semibold">{selected ? selected.name : "Create AgentProfile"}</h2>
              </div>
              <label className="flex items-center gap-2 text-xs font-semibold text-slate-600">
                Enabled
                <Switch checked={draft.enabled} onCheckedChange={(enabled) => setDraft((current) => ({ ...current, enabled }))} className="data-[state=checked]:bg-violet-600" />
              </label>
            </div>

            <div className="space-y-6 p-5 sm:p-6">
              <section className="grid gap-4 sm:grid-cols-2">
                <label>
                  <FieldLabel>Profile name</FieldLabel>
                  <Input required value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value.toLowerCase() }))} placeholder="network-l1" />
                </label>
                <label>
                  <FieldLabel>Model route</FieldLabel>
                  <select required className={selectClass} value={draft.routePurpose} onChange={(event) => setDraft((current) => ({ ...current, routePurpose: event.target.value }))}>
                    {routes.map((route) => <option key={route.id} value={route.purpose}>{route.purpose}</option>)}
                  </select>
                </label>
                <label className="sm:col-span-2">
                  <FieldLabel>Description</FieldLabel>
                  <Input value={draft.description} onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))} placeholder="Bounded L1 operator for the network domain" />
                </label>
                <label className="sm:col-span-2">
                  <FieldLabel>Role instructions</FieldLabel>
                  <Textarea required value={draft.roleInstructions} onChange={(event) => setDraft((current) => ({ ...current, roleInstructions: event.target.value }))} className="min-h-28" placeholder="How this Agent should investigate and communicate…" />
                </label>
                <label className="sm:col-span-2">
                  <FieldLabel>Escalation instructions</FieldLabel>
                  <Textarea value={draft.escalationInstructions} onChange={(event) => setDraft((current) => ({ ...current, escalationInstructions: event.target.value }))} className="min-h-20" placeholder="When and why this Agent must stop and escalate…" />
                </label>
              </section>

              <section className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex items-center gap-2"><Fingerprint className="size-4 text-violet-600" /><h3 className="text-sm font-semibold">Model placement policy</h3></div>
                <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Every primary and fallback model must satisfy all three controls.</p>
                <div className="mt-4 grid gap-4 sm:grid-cols-2">
                  <label>
                    <FieldLabel>Minimum provider privacy</FieldLabel>
                    <select className={selectClass} value={draft.minimumPrivacy} onChange={(event) => setDraft((current) => ({ ...current, minimumPrivacy: event.target.value as PrivacyTier }))}>
                      <option value="external">External allowed</option>
                      <option value="private">Private tenant or local</option>
                      <option value="local">Local only</option>
                    </select>
                  </label>
                  <label>
                    <FieldLabel>Allowed residencies, comma separated</FieldLabel>
                    <Input value={draft.dataResidencies} onChange={(event) => setDraft((current) => ({ ...current, dataResidencies: event.target.value }))} placeholder="hkg, sgp (empty means any)" />
                  </label>
                </div>
                <div className="mt-4">
                  <FieldLabel>Allowed model cost classes</FieldLabel>
                  <div className="flex flex-wrap gap-2">
                    {(["low", "standard", "premium"] as CostClass[]).map((cost) => (
                      <button type="button" key={cost} onClick={() => toggleCost(cost)} className={cn("rounded-lg border px-3 py-2 text-xs font-semibold capitalize", draft.allowedCosts.includes(cost) ? "border-violet-300 bg-violet-100 text-violet-800" : "border-slate-200 bg-white text-muted-foreground")}>
                        <Coins className="mr-1.5 inline size-3.5" />{cost}
                      </button>
                    ))}
                  </div>
                </div>
              </section>

              <section className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex items-center gap-2"><Wrench className="size-4 text-violet-600" /><h3 className="text-sm font-semibold">Tool policy</h3></div>
                <div className="mt-4 grid gap-4 sm:grid-cols-2">
                  <label>
                    <FieldLabel>Selection mode</FieldLabel>
                    <select className={selectClass} value={draft.toolPolicy} onChange={(event) => setDraft((current) => ({ ...current, toolPolicy: event.target.value as ToolPolicy, allowedTools: event.target.value === "allowlist" ? current.allowedTools : [] }))}>
                      <option value="permission_scoped">Permission-scoped Registry</option>
                      <option value="allowlist">Exact Tool allowlist</option>
                    </select>
                  </label>
                  <div className="rounded-lg bg-white p-3 text-[10px] leading-4 text-muted-foreground">
                    Permission checks always apply. An allowlist can only narrow the Tools visible to this Agent; it cannot grant access.
                  </div>
                </div>
                {draft.toolPolicy === "allowlist" ? (
                  <div className="mt-4 grid max-h-56 gap-2 overflow-y-auto sm:grid-cols-2">
                    {tools.map((tool) => (
                      <label key={tool.id} className="flex cursor-pointer items-start gap-2 rounded-lg border border-slate-200 bg-white p-3">
                        <input type="checkbox" checked={draft.allowedTools.includes(tool.name)} onChange={() => toggleTool(tool.name)} className="mt-0.5 accent-violet-600" />
                        <span><span className="block text-xs font-semibold text-slate-700">{tool.name}</span><span className="mt-1 block text-[9px] text-muted-foreground">{tool.read_only ? "read-only" : "change"} · {tool.risk_level}</span></span>
                      </label>
                    ))}
                  </div>
                ) : null}
              </section>

              <section>
                <div className="flex items-center gap-2"><Gauge className="size-4 text-violet-600" /><h3 className="text-sm font-semibold">Budget ceilings</h3></div>
                <p className="mt-1 text-[10px] text-muted-foreground">The Investigation receives the lower value from its model route and AgentProfile.</p>
                <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  {[
                    ["Iterations", "maxIterations"],
                    ["Tool calls", "maxToolCalls"],
                    ["Timeout seconds", "timeoutSeconds"],
                    ["Token budget", "tokenBudget"],
                  ].map(([label, key]) => (
                    <label key={key}>
                      <FieldLabel>{label}</FieldLabel>
                      <Input type="number" min={1} required value={draft[key as keyof Pick<ProfileDraft, "maxIterations" | "maxToolCalls" | "timeoutSeconds" | "tokenBudget">]} onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))} />
                    </label>
                  ))}
                </div>
              </section>

              {selected ? (
                <label>
                  <FieldLabel>Audit reason for this revision</FieldLabel>
                  <Textarea value={draft.reason} onChange={(event) => setDraft((current) => ({ ...current, reason: event.target.value }))} className="min-h-20" placeholder="Why is this Agent policy changing?" />
                </label>
              ) : null}

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-5">
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground"><ShieldCheck className="size-4 text-violet-600" /> Policy is rechecked before model invocation; drift fails closed.</div>
                <Button disabled={saving || routes.length === 0} className="bg-violet-600 hover:bg-violet-700">
                  {saving ? <Loader2 className="animate-spin" /> : <Save />}
                  {selected ? "Save revision" : "Create profile"}
                </Button>
              </div>
            </div>
          </form>
        </section>
      </div>
    </main>
  );
}
