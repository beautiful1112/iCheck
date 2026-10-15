"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Clock3,
  FileCheck2,
  Fingerprint,
  Loader2,
  RefreshCw,
  Save,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type RiskClass = "low" | "medium" | "high" | "critical";

type ChangeRiskPolicy = {
  id: string;
  risk_class: RiskClass;
  execution_enabled: boolean;
  maintenance_window_required: boolean;
  max_window_minutes: number;
  require_evidence_summary: boolean;
  require_authorization_binding: boolean;
  revision: number;
  updated_by: string;
  update_reason: string;
  updated_at: string;
};

type PolicyDraft = {
  execution_enabled: boolean;
  maintenance_window_required: boolean;
  max_window_minutes: string;
  require_evidence_summary: boolean;
  require_authorization_binding: boolean;
  reason: string;
};

const riskTone: Record<RiskClass, string> = {
  low: "border-emerald-200 bg-emerald-50 text-emerald-700",
  medium: "border-sky-200 bg-sky-50 text-sky-700",
  high: "border-amber-200 bg-amber-50 text-amber-800",
  critical: "border-red-200 bg-red-50 text-red-700",
};

function policyDraft(policy: ChangeRiskPolicy): PolicyDraft {
  return {
    execution_enabled: policy.execution_enabled,
    maintenance_window_required: policy.maintenance_window_required,
    max_window_minutes: String(policy.max_window_minutes),
    require_evidence_summary: policy.require_evidence_summary,
    require_authorization_binding: policy.require_authorization_binding,
    reason: "",
  };
}

function PolicyToggle({
  checked,
  description,
  label,
  onCheckedChange,
}: {
  checked: boolean;
  description: string;
  label: string;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4 rounded-xl border border-slate-200 bg-white px-3.5 py-3">
      <span>
        <span className="block text-xs font-semibold text-slate-700">{label}</span>
        <span className="mt-1 block text-[10px] leading-4 text-muted-foreground">{description}</span>
      </span>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        className="mt-0.5 data-[state=checked]:bg-violet-600"
      />
    </label>
  );
}

export default function ChangeRiskPolicyPage() {
  const [policies, setPolicies] = useState<ChangeRiskPolicy[]>([]);
  const [drafts, setDrafts] = useState<Record<string, PolicyDraft>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const next = await apiFetch<ChangeRiskPolicy[]>(
        "/agent/change-risk-policies",
      );
      setPolicies(next);
      setDrafts(
        Object.fromEntries(next.map((policy) => [policy.id, policyDraft(policy)])),
      );
      setMessage(null);
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to load risk policies",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  function updateDraft(
    policyId: string,
    update: Partial<PolicyDraft>,
  ) {
    setDrafts((current) => ({
      ...current,
      [policyId]: { ...current[policyId], ...update },
    }));
  }

  async function save(policy: ChangeRiskPolicy) {
    const draft = drafts[policy.id];
    if (!draft) return;
    const minutes = Number(draft.max_window_minutes);
    if (!Number.isInteger(minutes) || minutes < 5 || minutes > 480) {
      setMessage({
        tone: "error",
        text: "Maintenance windows must be between 5 and 480 whole minutes.",
      });
      return;
    }
    if (draft.reason.trim().length < 3) {
      setMessage({ tone: "error", text: "Add a reason before saving policy changes." });
      return;
    }
    setSaving(policy.id);
    setMessage(null);
    try {
      await apiFetch<ChangeRiskPolicy>(
        `/agent/change-risk-policies/${policy.risk_class}`,
        {
          method: "PATCH",
          body: JSON.stringify({
            expected_revision: policy.revision,
            execution_enabled: draft.execution_enabled,
            maintenance_window_required: draft.maintenance_window_required,
            max_window_minutes: minutes,
            require_evidence_summary: draft.require_evidence_summary,
            require_authorization_binding: draft.require_authorization_binding,
            reason: draft.reason.trim(),
          }),
        },
      );
      await load();
      setMessage({
        tone: "success",
        text: `${policy.risk_class} policy saved. Existing frozen plans will fail closed on drift.`,
      });
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to save risk policy",
      });
    } finally {
      setSaving(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1280px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/approvals"
              className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700"
              aria-label="Back to governed actions"
            >
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">
                  Change risk policies
                </h1>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Versioned execution guardrails applied before planning and rechecked at approval.
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => void load()}>
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </header>

        <div className="mt-4"><Link href="/settings/change-policy/preapprovals" className="inline-flex rounded-lg border border-violet-200 bg-white px-3 py-2 text-xs font-semibold text-violet-700">Reviewed change preapprovals</Link></div>

        {message ? (
          <div
            className={cn(
              "mt-5 flex items-start gap-2 rounded-xl border px-4 py-3 text-sm",
              message.tone === "success"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : "border-red-200 bg-red-50 text-red-800",
            )}
          >
            {message.tone === "error" ? (
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            ) : (
              <ShieldCheck className="mt-0.5 size-4 shrink-0" />
            )}
            {message.text}
          </div>
        ) : null}

        <section className="mt-6 rounded-2xl border border-violet-200 bg-violet-50/60 p-5">
          <div className="flex items-start gap-3">
            <Fingerprint className="mt-0.5 size-5 shrink-0 text-violet-600" />
            <div>
              <h2 className="text-sm font-semibold text-violet-950">Fail-closed semantics</h2>
              <p className="mt-1 max-w-4xl text-xs leading-5 text-violet-800">
                Every governed plan freezes this policy&apos;s ID, revision, and limits. A later policy change never silently alters an approved plan; the old plan must be regenerated and reviewed.
              </p>
            </div>
          </div>
        </section>

        {loading && policies.length === 0 ? (
          <div className="grid min-h-80 place-items-center">
            <Loader2 className="size-6 animate-spin text-violet-500" />
          </div>
        ) : (
          <section className="mt-5 grid gap-5 lg:grid-cols-2">
            {policies.map((policy) => {
              const draft = drafts[policy.id];
              if (!draft) return null;
              return (
                <Card key={policy.id} className="border-slate-200 shadow-sm">
                  <CardHeader className="border-b border-slate-100">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={cn("capitalize", riskTone[policy.risk_class])}>
                            {policy.risk_class}
                          </Badge>
                          <Badge variant="outline" className="text-[9px] text-muted-foreground">
                            revision {policy.revision}
                          </Badge>
                        </div>
                        <CardTitle className="mt-3 text-base capitalize">
                          {policy.risk_class} risk changes
                        </CardTitle>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          policy.execution_enabled
                            ? "border-emerald-200 text-emerald-700"
                            : "border-red-200 text-red-700",
                        )}
                      >
                        {policy.execution_enabled ? "Executable" : "Paused"}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3 pt-5">
                    <PolicyToggle
                      label="Allow execution"
                      description="When disabled, new plans and existing frozen plans fail closed."
                      checked={draft.execution_enabled}
                      onCheckedChange={(checked) => updateDraft(policy.id, { execution_enabled: checked })}
                    />
                    <PolicyToggle
                      label="Require a maintenance window"
                      description="The approved action may execute only inside its frozen time window."
                      checked={draft.maintenance_window_required}
                      onCheckedChange={(checked) => updateDraft(policy.id, { maintenance_window_required: checked })}
                    />
                    <PolicyToggle
                      label="Require bounded dry-run evidence"
                      description="The Tool contract must expose only schema-approved scalar preview fields."
                      checked={draft.require_evidence_summary}
                      onCheckedChange={(checked) => updateDraft(policy.id, { require_evidence_summary: checked })}
                    />
                    <PolicyToggle
                      label="Require authorization target binding"
                      description="The change target must bind to an authorized device or site field."
                      checked={draft.require_authorization_binding}
                      onCheckedChange={(checked) => updateDraft(policy.id, { require_authorization_binding: checked })}
                    />

                    <label className="block rounded-xl border border-slate-200 bg-white px-3.5 py-3">
                      <span className="flex items-center gap-2 text-xs font-semibold text-slate-700">
                        <Clock3 className="size-3.5 text-violet-600" /> Maximum window
                      </span>
                      <div className="mt-2 flex items-center gap-2">
                        <Input
                          type="number"
                          min={5}
                          max={480}
                          step={1}
                          value={draft.max_window_minutes}
                          onChange={(event) => updateDraft(policy.id, { max_window_minutes: event.target.value })}
                          className="h-9 max-w-32 bg-white"
                        />
                        <span className="text-xs text-muted-foreground">minutes</span>
                      </div>
                    </label>

                    <label className="block">
                      <span className="mb-1.5 flex items-center gap-2 text-xs font-semibold text-slate-700">
                        <FileCheck2 className="size-3.5 text-violet-600" /> Audit reason
                      </span>
                      <Textarea
                        value={draft.reason}
                        onChange={(event) => updateDraft(policy.id, { reason: event.target.value })}
                        placeholder="Why is this guardrail changing?"
                        className="min-h-20 bg-white text-xs"
                      />
                    </label>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                      <p className="max-w-sm text-[9px] leading-4 text-muted-foreground">
                        Last changed by {policy.updated_by} · {new Date(policy.updated_at).toLocaleString()}
                      </p>
                      <Button
                        onClick={() => void save(policy)}
                        disabled={saving !== null}
                        className="bg-violet-600 hover:bg-violet-700"
                      >
                        {saving === policy.id ? (
                          <Loader2 className="animate-spin" />
                        ) : (
                          <Save />
                        )}
                        Save revision
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </section>
        )}
      </div>
    </main>
  );
}
