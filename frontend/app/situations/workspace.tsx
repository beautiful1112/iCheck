"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bot,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  Clock,
  ExternalLink,
  FileSearch,
  GitBranch,
  Loader2,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type Severity = "critical" | "warning" | "info";
type SituationStatus = "open" | "acknowledged" | "resolved";

type Situation = {
  id: string;
  correlation_version: string;
  status: SituationStatus;
  severity: Severity;
  priority_score: number;
  title: string;
  summary: string;
  primary_entity_type: string;
  primary_entity_id: string;
  alert_count: number;
  active_alert_count: number;
  occurrence_count: number;
  correlation_confidence: number;
  first_seen: string;
  last_seen: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
  updated_at: string;
};

type SituationAlert = {
  alert_id: string;
  condition_source_id?: string | null;
  role: string;
  correlation_reason: string;
  correlation_confidence: number;
  correlation_evidence: Record<string, unknown>;
  event_type: string;
  severity: Severity;
  status: SituationStatus;
  title: string;
  description: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
};

type SituationEvent = {
  id: string;
  sequence: number;
  event_type: string;
  actor: string;
  details: Record<string, unknown>;
  created_at: string;
};

type SituationInvestigation = {
  id: string;
  title: string;
  status: string;
  confidence: number | null;
  conclusion: string | null;
  created_at: string;
  updated_at: string;
};

type SituationDetail = {
  situation: Situation;
  alerts: SituationAlert[];
  events: SituationEvent[];
  investigations: SituationInvestigation[];
  alerts_truncated: boolean;
  events_truncated: boolean;
};

type SituationExternalReference = {
  id: string;
  integration_event_id: string;
  binding_id: string;
  situation_id: string;
  investigation_id: string | null;
  provider_key: string;
  remote_id: string;
  remote_url: string | null;
  remote_status: string | null;
  remote_updated_at: string | null;
  source_tool_call_id: string;
  created_at: string;
  updated_at: string;
};

type SituationImpact = {
  situation_id: string;
  root_node_id: string;
  generated_at: string;
  scope_applied: boolean;
  hypothesis_boundary: "deterministic_context_not_root_cause";
  nodes: Array<{
    id: string;
    entity_id: string;
    node_type: "device" | "endpoint" | "knowledge_entity" | "service" | "external_entity";
    role: "root" | "adjacent" | "scoped_component" | "dependency" | "impacted_service";
    label: string;
    kind: string;
    site: string | null;
    status: string;
    observed_at: string;
    criticality: "tier_0" | "tier_1" | "tier_2" | "tier_3" | null;
    business_impact: "critical" | "high" | "moderate" | "low" | null;
    slo_target_percent: number | null;
    owner_team: string | null;
  }>;
  edges: Array<{
    id: string;
    relationship_type: string;
    source: string;
    target: string;
    evidence_type: string;
    evidence_id: string;
    observed_at: string;
  }>;
  paths: Array<{
    target_node_id: string;
    node_ids: string[];
    edge_ids: string[];
    relationship_types: string[];
    hop_count: number;
  }>;
  summary: {
    native_neighbor_count: number;
    knowledge_entity_count: number;
    service_count: number;
    service_dependency_count: number;
    path_count: number;
  };
  nodes_truncated: boolean;
  edges_truncated: boolean;
};

type SituationHypothesis = {
  id: string;
  situation_id: string;
  investigation_id: string;
  statement: string;
  status: "candidate" | "proposed" | "accepted" | "rejected" | "superseded";
  current_confidence: number;
  revision_count: number;
  source_model_id: string;
  reviewed_by: string | null;
  review_reason: string | null;
  reviewed_at: string | null;
  revisions: Array<{
    id: string;
    checkpoint_id: string;
    revision: number;
    iteration: number;
    confidence: number;
    evidence: Array<{
      evidence_reference_id: string;
      stance: "supporting" | "contradicting";
      evidence_type: string;
      evidence_id: string;
      summary: string;
      observed_at: string | null;
    }>;
    created_at: string;
  }>;
  revisions_truncated: boolean;
  created_at: string;
  updated_at: string;
};

type SituationImpactAssessment = {
  id: string;
  situation_id: string;
  investigation_id: string;
  checkpoint_id: string;
  contract_version: "icheck.situation-impact-assessment/v1";
  status: "proposed" | "accepted" | "rejected";
  impact_level: "unknown" | "none" | "low" | "medium" | "high" | "critical";
  summary: string;
  confidence: number;
  affected_node_ids: string[];
  uncertainty: string[];
  service_context_snapshot: Array<{
    service_id: string;
    service_key: string;
    name: string;
    owner_team: string;
    criticality: "tier_0" | "tier_1" | "tier_2" | "tier_3";
    business_impact: "critical" | "high" | "moderate" | "low";
    business_impact_summary: string;
    slo_target_percent: number | null;
    recovery_time_objective_minutes: number | null;
    recovery_point_objective_minutes: number | null;
    catalog_revision: number;
  }>;
  dependency_context_snapshot: Array<{
    dependency_id: string;
    source_service_id: string;
    source_service_key: string;
    source_service_name: string;
    target_service_id: string;
    target_service_key: string;
    target_service_name: string;
    dependency_type: "synchronous" | "asynchronous" | "data" | "shared_infrastructure";
    critical: boolean;
    evidence_note: string;
    recorded_at: string;
  }>;
  source_model_id: string;
  created_by: string;
  reviewed_by: string | null;
  review_reason: string | null;
  reviewed_at: string | null;
  evidence: Array<{
    evidence_reference_id: string;
    evidence_type: string;
    evidence_id: string;
    summary: string;
    observed_at: string | null;
  }>;
  created_at: string;
  updated_at: string;
};

function relativeTime(value: string) {
  const minutes = Math.max(
    0,
    Math.round((Date.now() - new Date(value).getTime()) / 60_000),
  );
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.round(minutes / 60)}h ago`;
  return `${Math.round(minutes / 1440)}d ago`;
}

function severityClass(severity: Severity) {
  if (severity === "critical") return "border-red-200 bg-red-50 text-red-700";
  if (severity === "warning") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-sky-200 bg-sky-50 text-sky-700";
}

function statusClass(status: SituationStatus) {
  if (status === "open") return "border-red-200 bg-red-50 text-red-700";
  if (status === "acknowledged") {
    return "border-violet-200 bg-violet-50 text-violet-700";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function eventLabel(value: string) {
  const labels: Record<string, string> = {
    "situation.created": "Situation created",
    "alert.attached": "Alert evidence attached",
    "alert.state_changed": "Alert state changed",
    "situation.severity_changed": "Priority changed",
    "situation.acknowledged": "Operator acknowledged",
    "situation.attention_reopened": "New evidence reopened attention",
    "situation.resolved": "Situation resolved",
    "investigation.created": "AI investigation linked",
    "hypotheses.proposed": "AI hypotheses proposed",
    "hypothesis.accepted": "Hypothesis accepted",
    "hypothesis.rejected": "Hypothesis rejected",
    "impact_assessment.proposed": "AI impact assessment proposed",
    "impact_assessment.accepted": "Impact assessment accepted",
    "impact_assessment.rejected": "Impact assessment rejected",
  };
  return labels[value] || value.replaceAll(".", " · ");
}

type SituationWorkspaceProps = {
  initialSituationId?: string;
  detailOnly?: boolean;
};

export function SituationWorkspace({
  initialSituationId,
  detailOnly = false,
}: SituationWorkspaceProps) {
  const [situations, setSituations] = useState<Situation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(
    initialSituationId || null,
  );
  const [detail, setDetail] = useState<SituationDetail | null>(null);
  const [impact, setImpact] = useState<SituationImpact | null>(null);
  const [hypotheses, setHypotheses] = useState<SituationHypothesis[]>([]);
  const [impactAssessments, setImpactAssessments] = useState<SituationImpactAssessment[]>([]);
  const [externalReferences, setExternalReferences] = useState<SituationExternalReference[]>([]);
  const [reviewNotes, setReviewNotes] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<SituationStatus | "active" | "all">("active");
  const [loading, setLoading] = useState(!detailOnly);
  const [detailLoading, setDetailLoading] = useState(detailOnly);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const rows = await apiFetch<Situation[]>("/situations?limit=500");
      setSituations(rows);
      setSelectedId((current) => current || rows[0]?.id || null);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load Situations");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (situationId: string) => {
    setDetailLoading(true);
    try {
      const [nextDetail, nextImpact, nextHypotheses, nextImpactAssessments, nextExternalReferences] = await Promise.all([
        apiFetch<SituationDetail>(`/situations/${situationId}`),
        apiFetch<SituationImpact>(`/situations/${situationId}/impact`),
        apiFetch<SituationHypothesis[]>(`/situations/${situationId}/hypotheses`),
        apiFetch<SituationImpactAssessment[]>(`/situations/${situationId}/impact-assessments`),
        apiFetch<SituationExternalReference[]>(`/situations/${situationId}/external-references`),
      ]);
      setDetail(nextDetail);
      setImpact(nextImpact);
      setHypotheses(nextHypotheses);
      setImpactAssessments(nextImpactAssessments);
      setExternalReferences(nextExternalReferences);
      setError(null);
    } catch (cause) {
      setImpact(null);
      setHypotheses([]);
      setImpactAssessments([]);
      setExternalReferences([]);
      setError(cause instanceof Error ? cause.message : "Unable to load Situation evidence");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    if (detailOnly) return;
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [detailOnly, load]);

  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return situations.filter((item) => {
      if (status === "active" && item.status === "resolved") return false;
      if (status !== "active" && status !== "all" && item.status !== status) {
        return false;
      }
      if (!normalized) return true;
      return [
        item.title,
        item.summary,
        item.primary_entity_type,
        item.primary_entity_id,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalized);
    });
  }, [query, situations, status]);

  const selected = detailOnly
    ? detail?.situation || null
    : filtered.find((item) => item.id === selectedId) || filtered[0] || null;

  useEffect(() => {
    if (detailOnly || !selected) return;
    const timer = window.setTimeout(() => void loadDetail(selected.id), 0);
    return () => window.clearTimeout(timer);
  }, [detailOnly, loadDetail, selected]);

  useEffect(() => {
    if (!detailOnly || !initialSituationId) return;
    const timer = window.setTimeout(
      () => void loadDetail(initialSituationId),
      0,
    );
    return () => window.clearTimeout(timer);
  }, [detailOnly, initialSituationId, loadDetail]);

  async function acknowledge() {
    if (!selected || selected.status !== "open") return;
    setBusy("acknowledge");
    try {
      await apiFetch(`/situations/${selected.id}/acknowledge`, {
        method: "POST",
        body: JSON.stringify({
          actor: "web.operator",
          reason: "Operator accepted ownership from the Situation workspace",
        }),
      });
      if (detailOnly) {
        await loadDetail(selected.id);
      } else {
        await Promise.all([load(), loadDetail(selected.id)]);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to acknowledge Situation");
    } finally {
      setBusy(null);
    }
  }

  async function investigate() {
    if (!selected) return;
    setBusy("investigate");
    try {
      const scope = {
        situation_id: selected.id,
        entity_type: selected.primary_entity_type,
        entity_id: selected.primary_entity_id,
        requested_output_contract: "icheck.situation-impact-assessment/v1",
        ...(selected.primary_entity_type === "device" ||
        selected.primary_entity_type === "collector_device"
          ? { device_ids: [selected.primary_entity_id] }
          : {}),
      };
      const investigation = await apiFetch<{ id: string }>(
        "/agent/investigations",
        {
          method: "POST",
          body: JSON.stringify({
            title: `Investigate Situation: ${selected.title}`,
            objective: `Investigate Situation ${selected.id}. ${selected.summary}`,
            scope,
            situation_id: selected.id,
            route_purpose: "investigation",
            created_by: "web.operator",
          }),
        },
      );
      await apiFetch(`/agent/investigations/${investigation.id}/start`, {
        method: "POST",
        body: JSON.stringify({ actor: "web.operator" }),
      });
      window.location.assign(`/?investigation=${investigation.id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to start investigation");
      setBusy(null);
    }
  }

  async function reviewHypothesis(
    hypothesisId: string,
    decision: "accept" | "reject",
  ) {
    if (!selected) return;
    const reason = (reviewNotes[hypothesisId] || "").trim();
    if (reason.length < 3) {
      setError("Add a review reason before accepting or rejecting an AI hypothesis");
      return;
    }
    setBusy(`hypothesis:${hypothesisId}`);
    try {
      await apiFetch(
        `/situations/${selected.id}/hypotheses/${hypothesisId}/${decision}`,
        {
          method: "POST",
          body: JSON.stringify({ actor: "web.operator", reason }),
        },
      );
      setReviewNotes((current) => ({ ...current, [hypothesisId]: "" }));
      await loadDetail(selected.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to review hypothesis");
    } finally {
      setBusy(null);
    }
  }

  async function reviewImpactAssessment(
    assessmentId: string,
    decision: "accept" | "reject",
  ) {
    if (!selected) return;
    const reason = (reviewNotes[assessmentId] || "").trim();
    if (reason.length < 3) {
      setError("Add a review reason before accepting or rejecting an AI impact assessment");
      return;
    }
    setBusy(`impact-assessment:${assessmentId}`);
    try {
      await apiFetch(
        `/situations/${selected.id}/impact-assessments/${assessmentId}/${decision}`,
        {
          method: "POST",
          body: JSON.stringify({ actor: "web.operator", reason }),
        },
      );
      setReviewNotes((current) => ({ ...current, [assessmentId]: "" }));
      await loadDetail(selected.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to review impact assessment");
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="flex h-screen min-h-[720px] flex-col overflow-hidden bg-[#f5f6f8] text-slate-900">
      <header className="flex h-16 shrink-0 items-center justify-between border-b border-slate-200 bg-white px-5">
        <div className="flex items-center gap-3">
          <Link href={detailOnly ? "/situations" : "/"} className="rounded-md p-2 text-muted-foreground hover:bg-slate-100" aria-label={detailOnly ? "Back to Situation queue" : "Back to AI operator"}>
            <ArrowLeft className="size-4" />
          </Link>
          <span className="grid size-9 place-items-center rounded-xl bg-[#202940] text-white">
            <Activity className="size-4" />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold">{detailOnly ? "Situation Detail" : "Situation Intelligence"}</h1>
              <Badge className="border-violet-200 bg-violet-50 text-[10px] text-violet-700">deterministic policies v1–v3</Badge>
            </div>
            <p className="text-xs text-muted-foreground">Correlated symptoms · preserved evidence · durable investigations</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/topology"><GitBranch className="size-3.5" /> Topology</Link></Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => {
              if (detailOnly && initialSituationId) {
                void loadDetail(initialSituationId);
              } else {
                void load();
              }
            }}
            disabled={detailOnly ? detailLoading : loading}
          >
            <RefreshCw className={cn("size-3.5", (detailOnly ? detailLoading : loading) && "animate-spin")} /> Refresh
          </Button>
        </div>
      </header>

      {error && (
        <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700"><XCircle className="size-4" /> {error}</div>
      )}

      <div className={cn("grid min-h-0 flex-1", detailOnly ? "grid-cols-1" : "grid-cols-[360px_minmax(600px,1fr)]")}>
        {!detailOnly ? <aside className="min-h-0 border-r border-slate-200 bg-white">
          <div className="space-y-3 border-b border-slate-200 p-4">
            <div className="relative">
              <Search className="absolute left-3 top-2.5 size-3.5 text-muted-foreground" />
              <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search entity or symptom" className="h-9 bg-slate-50 pl-9 text-xs" />
            </div>
            <div className="flex gap-1.5">
              {(["active", "open", "acknowledged", "resolved", "all"] as const).map((value) => (
                <button key={value} onClick={() => setStatus(value)} className={cn("rounded-md px-2 py-1.5 text-[10px] font-semibold capitalize", status === value ? "bg-[#202940] text-white" : "bg-slate-100 text-muted-foreground hover:bg-slate-200")}>{value}</button>
              ))}
            </div>
          </div>
          <div className="h-[calc(100%-109px)] overflow-y-auto p-2">
            {filtered.map((item) => (
              <div key={item.id} className={cn("mb-1.5 rounded-xl border p-3 transition", selected?.id === item.id ? "border-violet-300 bg-violet-50/50 shadow-sm" : "border-transparent hover:border-slate-200 hover:bg-slate-50")}>
                <button type="button" onClick={() => setSelectedId(item.id)} className="w-full text-left">
                  <div className="flex items-start justify-between gap-2">
                    <span className="line-clamp-2 text-xs font-semibold leading-5 text-slate-800">{item.title}</span>
                    <span className={cn("mt-1 size-2 shrink-0 rounded-full", item.severity === "critical" ? "bg-red-500" : item.severity === "warning" ? "bg-amber-500" : "bg-sky-500")} />
                  </div>
                  <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{item.summary}</p>
                </button>
                <div className="mt-2 flex items-center justify-between text-[9px] text-muted-foreground">
                  <span>{item.active_alert_count} active · score {item.priority_score} · {relativeTime(item.last_seen)}</span>
                  <Link href={`/situations/${item.id}`} className="flex items-center gap-0.5 font-semibold text-violet-700 hover:text-violet-900" aria-label={`Open focused details for ${item.title}`}>
                    Details <ChevronRight className="size-3" />
                  </Link>
                </div>
              </div>
            ))}
            {!loading && !filtered.length && <div className="py-16 text-center text-xs text-muted-foreground">No matching Situations.</div>}
          </div>
        </aside> : null}

        <section className="min-h-0 overflow-y-auto p-5 lg:p-7">
          {detailLoading && (!detail || detail.situation.id !== selected?.id) ? (
            <div className="grid h-full place-items-center text-muted-foreground"><Loader2 className="size-5 animate-spin" /></div>
          ) : selected && detail && detail.situation.id === selected.id ? (
            <div className="mx-auto max-w-6xl space-y-5">
              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="max-w-3xl">
                    <div className="flex items-center gap-2"><Badge variant="outline" className={severityClass(selected.severity)}>{selected.severity}</Badge><Badge variant="outline" className={statusClass(selected.status)}>{selected.status}</Badge><span className="text-[10px] text-muted-foreground">score {selected.priority_score}</span><span className="font-mono text-[9px] text-muted-foreground">{selected.correlation_version}</span></div>
                    <h2 className="mt-3 text-xl font-semibold tracking-tight">{selected.title}</h2>
                    <p className="mt-2 text-sm leading-6 text-slate-600">{selected.summary}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Link className="self-center text-xs text-sky-700 underline" href={`/situations/${encodeURIComponent(selected.id)}/recovery`}>Recovery evidence</Link>
                    <Link className="self-center text-xs text-sky-700 underline" href={`/situations/${encodeURIComponent(selected.id)}/closure`}>Reviewed closure</Link>
                    {!detailOnly ? (
                      <Button asChild variant="outline" size="sm" className="gap-2">
                        <Link href={`/situations/${selected.id}`}><ExternalLink className="size-3.5" /> Focused view</Link>
                      </Button>
                    ) : null}
                    {selected.status === "open" && <Button variant="outline" size="sm" className="gap-2" onClick={() => void acknowledge()} disabled={busy !== null}><ShieldCheck className="size-3.5" /> Acknowledge</Button>}
                    <Button size="sm" className="gap-2 bg-violet-600 hover:bg-violet-700" onClick={() => void investigate()} disabled={busy !== null}>{busy === "investigate" ? <Loader2 className="size-3.5 animate-spin" /> : <Bot className="size-3.5" />} Investigate</Button>
                  </div>
                </div>
                <div className="mt-5 grid gap-3 border-t border-slate-100 pt-5 sm:grid-cols-4">
                  {[["Active alerts", selected.active_alert_count], ["Total alerts", selected.alert_count], ["Occurrences", selected.occurrence_count], ["Correlation", `${Math.round(selected.correlation_confidence * 100)}%`]].map(([label, value]) => (
                    <div key={String(label)} className="rounded-xl bg-slate-50 px-4 py-3"><div className="text-lg font-semibold">{String(value)}</div><div className="mt-1 text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{String(label)}</div></div>
                  ))}
                </div>
                <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 text-[10px] text-muted-foreground"><span>Entity: <strong className="font-mono text-slate-700">{selected.primary_entity_type}/{selected.primary_entity_id}</strong></span><span>First seen: {relativeTime(selected.first_seen)}</span><span>Last evidence: {relativeTime(selected.last_seen)}</span></div>
              </div>

              <div className="grid items-start gap-5 xl:grid-cols-[1.15fr_0.85fr]">
                <div className="space-y-5">
                  <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h3 className="text-sm font-semibold">Correlated alert evidence</h3><p className="mt-1 text-[11px] text-muted-foreground">Source Alerts remain individually inspectable</p></div><AlertTriangle className="size-4 text-amber-500" /></div>
                    <div className="divide-y divide-slate-100">
                      {detail.alerts.map((alert) => (
                        <div key={alert.alert_id} className="px-5 py-4">
                          <div className="flex items-start justify-between gap-3"><div><div className="text-xs font-semibold text-slate-800">{alert.title}</div><div className="mt-1 font-mono text-[9px] text-muted-foreground">{alert.event_type}</div></div><div className="flex gap-1"><Badge variant="outline" className={cn("text-[9px]", severityClass(alert.severity))}>{alert.severity}</Badge><Badge variant="outline" className="text-[9px]">{alert.status}</Badge></div></div>
                          <p className="mt-2 text-xs leading-5 text-slate-600">{alert.description || "No additional description."}</p>
                          {alert.condition_source_id ? <Link className="mt-2 inline-block text-xs text-sky-700 underline" href={`/assets/condition-sources/${encodeURIComponent(alert.condition_source_id)}`}>Source qualification · no closure authority</Link> : null}
                          <div className="mt-2 text-[9px] text-muted-foreground">{alert.occurrence_count} occurrence{alert.occurrence_count === 1 ? "" : "s"} · {alert.correlation_reason.replaceAll("_", " ")} · {Math.round(alert.correlation_confidence * 100)}% · {relativeTime(alert.last_seen)}</div>
                          {alert.correlation_evidence.evidence_type === "reviewed_service_component" ? <div className="mt-2 rounded-md border border-violet-100 bg-violet-50 px-2.5 py-2 font-mono text-[9px] text-violet-700">reviewed service evidence · revision {String(alert.correlation_evidence.service_revision)} · 15 minute window</div> : null}
                          {alert.correlation_evidence.evidence_type === "fresh_topology_adjacency" ? <div className="mt-2 rounded-md border border-sky-100 bg-sky-50 px-2.5 py-2 font-mono text-[9px] text-sky-700">non-causal topology evidence · {String(alert.correlation_evidence.topology_relationship_type)} · frozen {relativeTime(String(alert.correlation_evidence.topology_observed_at))}</div> : null}
                        </div>
                      ))}
                    </div>
                  </div>
                  {impact?.situation_id === selected.id ? (
                    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-semibold">Impact context</h3>
                            <Badge variant="outline" className="border-sky-200 bg-sky-50 text-[9px] text-sky-700">not a root-cause claim</Badge>
                          </div>
                          <p className="mt-1 text-[11px] text-muted-foreground">Authorized current-state paths with durable edge evidence</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button asChild variant="outline" size="sm" className="h-7 gap-1.5 text-[10px]">
                            <Link href={`/topology?situation_id=${selected.id}`}><GitBranch className="size-3" /> Open graph</Link>
                          </Button>
                          <Network className="size-4 text-sky-600" />
                        </div>
                      </div>
                      <div className="grid grid-cols-5 gap-2 px-5 pt-4">
                        {[
                          ["Adjacent", impact.summary.native_neighbor_count],
                          ["Knowledge", impact.summary.knowledge_entity_count],
                          ["Services", impact.summary.service_count],
                          ["Dependencies", impact.summary.service_dependency_count],
                          ["Paths", impact.summary.path_count],
                        ].map(([label, value]) => (
                          <div key={String(label)} className="rounded-lg bg-slate-50 px-3 py-2 text-center">
                            <div className="text-sm font-semibold text-slate-800">{String(value)}</div>
                            <div className="mt-0.5 text-[9px] uppercase tracking-wide text-muted-foreground">{String(label)}</div>
                          </div>
                        ))}
                      </div>
                      <div className="space-y-1.5 p-3">
                        {impact.paths.slice(0, 8).map((path) => {
                          const target = impact.nodes.find((item) => item.id === path.target_node_id);
                          return (
                            <div key={path.target_node_id} className="rounded-xl border border-slate-100 px-3 py-2.5">
                              <div className="flex items-center justify-between gap-3">
                                <span className="truncate text-xs font-medium text-slate-700">{target?.label || path.target_node_id}</span>
                                <span className="shrink-0 text-[9px] text-muted-foreground">{path.hop_count} hop{path.hop_count === 1 ? "" : "s"}</span>
                              </div>
                              <div className="mt-1 truncate font-mono text-[9px] text-muted-foreground">{path.relationship_types.join(" → ")}</div>
                            </div>
                          );
                        })}
                        {!impact.paths.length ? <div className="py-5 text-center text-xs text-muted-foreground">No current related topology evidence.</div> : null}
                        {impact.paths.length > 8 || impact.nodes_truncated || impact.edges_truncated ? <div className="px-2 pt-1 text-[9px] text-amber-600">Bounded result · additional context is available.</div> : null}
                      </div>
                    </div>
                  ) : null}
                  <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-semibold">AI impact assessments</h3>
                          <Badge variant="outline" className="border-amber-200 bg-amber-50 text-[9px] text-amber-700">proposals, not facts</Badge>
                        </div>
                        <p className="mt-1 text-[11px] text-muted-foreground">Evidence-cited service impact, separately governed from deterministic context</p>
                      </div>
                      <Activity className="size-4 text-amber-600" />
                    </div>
                    <div className="divide-y divide-slate-100">
                      {impactAssessments.map((assessment) => (
                        <div key={assessment.id} className="px-5 py-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="flex flex-wrap items-center gap-1.5">
                                <Badge variant="outline" className={cn("text-[9px]", assessment.impact_level === "critical" || assessment.impact_level === "high" ? "border-red-200 bg-red-50 text-red-700" : assessment.impact_level === "medium" ? "border-amber-200 bg-amber-50 text-amber-700" : "border-sky-200 bg-sky-50 text-sky-700")}>{assessment.impact_level} impact</Badge>
                                <span className="text-[9px] text-muted-foreground">{Math.round(assessment.confidence * 100)}% confidence</span>
                              </div>
                              <p className="mt-2 text-xs leading-5 text-slate-700">{assessment.summary}</p>
                            </div>
                            <Badge variant="outline" className={cn("shrink-0 text-[9px]", assessment.status === "accepted" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : assessment.status === "rejected" ? "border-slate-200 bg-slate-50 text-muted-foreground" : "border-amber-200 bg-amber-50 text-amber-700")}>{assessment.status}</Badge>
                          </div>
                          {assessment.affected_node_ids.length ? (
                            <div className="mt-3 flex flex-wrap gap-1.5">
                              {assessment.affected_node_ids.map((nodeId) => {
                                const node = impact?.nodes.find((item) => item.id === nodeId);
                                return <span key={nodeId} className="rounded-md bg-slate-50 px-2 py-1 text-[9px] text-slate-600">{node?.label || nodeId}</span>;
                              })}
                            </div>
                          ) : null}
                          {assessment.service_context_snapshot.map((service) => (
                            <div key={service.service_id} className="mt-3 rounded-lg border border-violet-100 bg-violet-50/60 px-3 py-2.5">
                              <div className="flex flex-wrap items-center gap-1.5 text-[9px]">
                                <span className="font-semibold text-violet-800">{service.name}</span>
                                <span className="text-violet-500">{service.criticality} · {service.business_impact} impact · catalog r{service.catalog_revision}</span>
                              </div>
                              <p className="mt-1 text-[10px] leading-4 text-slate-600">Owner {service.owner_team}{service.slo_target_percent === null ? "" : ` · SLO ${service.slo_target_percent}%`}</p>
                            </div>
                          ))}
                          {assessment.dependency_context_snapshot.map((dependency) => (
                            <div key={dependency.dependency_id} className="mt-2 rounded-lg border border-sky-100 bg-sky-50/60 px-3 py-2.5">
                              <div className="flex flex-wrap items-center gap-1.5 text-[9px]">
                                <span className="font-semibold text-sky-800">{dependency.source_service_name} → {dependency.target_service_name}</span>
                                <span className="text-sky-500">{dependency.dependency_type}{dependency.critical ? " · critical path" : ""}</span>
                              </div>
                              <p className="mt-1 text-[10px] leading-4 text-slate-600">{dependency.evidence_note}</p>
                            </div>
                          ))}
                          <div className="mt-3 space-y-1.5">
                            {assessment.evidence.slice(0, 3).map((evidence) => (
                              <div key={evidence.evidence_reference_id} className="rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2 text-[10px] leading-4 text-slate-600">
                                <span className="mr-1.5 font-semibold text-emerald-600">evidence</span>{evidence.summary}
                              </div>
                            ))}
                          </div>
                          {assessment.uncertainty.length ? <p className="mt-2 text-[10px] leading-4 text-amber-700">Uncertainty: {assessment.uncertainty.join(" · ")}</p> : null}
                          {assessment.status === "proposed" ? (
                            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                              <Input value={reviewNotes[assessment.id] || ""} onChange={(event) => setReviewNotes((current) => ({ ...current, [assessment.id]: event.target.value }))} placeholder="Required review reason" className="h-8 flex-1 bg-slate-50 text-[10px]" />
                              <div className="flex gap-1.5">
                                <Button size="sm" variant="outline" className="h-8 text-[10px]" disabled={busy !== null} onClick={() => void reviewImpactAssessment(assessment.id, "reject")}>Reject</Button>
                                <Button size="sm" className="h-8 bg-emerald-600 text-[10px] hover:bg-emerald-700" disabled={busy !== null} onClick={() => void reviewImpactAssessment(assessment.id, "accept")}>Accept</Button>
                              </div>
                            </div>
                          ) : assessment.review_reason ? <p className="mt-3 text-[10px] text-muted-foreground">Reviewed by {assessment.reviewed_by}: {assessment.review_reason}</p> : null}
                        </div>
                      ))}
                      {!impactAssessments.length ? <div className="py-7 text-center text-xs text-muted-foreground">No governed AI impact assessment has been persisted.</div> : null}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-semibold">AI hypotheses</h3>
                          <Badge variant="outline" className="border-violet-200 bg-violet-50 text-[9px] text-violet-700">proposals, not facts</Badge>
                        </div>
                        <p className="mt-1 text-[11px] text-muted-foreground">Confidence history and cited Investigation evidence</p>
                      </div>
                      <BrainCircuit className="size-4 text-violet-600" />
                    </div>
                    <div className="divide-y divide-slate-100">
                      {hypotheses.map((hypothesis) => {
                        const latest = hypothesis.revisions[hypothesis.revisions.length - 1];
                        return (
                          <div key={hypothesis.id} className="px-5 py-4">
                            <div className="flex items-start justify-between gap-3">
                              <p className="text-xs font-medium leading-5 text-slate-800">{hypothesis.statement}</p>
                              <Badge variant="outline" className={cn("shrink-0 text-[9px]", hypothesis.status === "accepted" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : hypothesis.status === "rejected" || hypothesis.status === "superseded" ? "border-slate-200 bg-slate-50 text-muted-foreground" : "border-violet-200 bg-violet-50 text-violet-700")}>{hypothesis.status}</Badge>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {hypothesis.revisions.map((revision) => (
                                <span key={revision.id} className="rounded-md bg-slate-50 px-2 py-1 text-[9px] text-muted-foreground">i{revision.iteration} · {Math.round(revision.confidence * 100)}%</span>
                              ))}
                            </div>
                            {latest?.evidence.length ? (
                              <div className="mt-3 space-y-1.5">
                                {latest.evidence.slice(0, 3).map((evidence) => (
                                  <div key={`${latest.id}:${evidence.evidence_reference_id}`} className="rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2 text-[10px] leading-4 text-slate-600">
                                    <span className={cn("mr-1.5 font-semibold", evidence.stance === "supporting" ? "text-emerald-600" : "text-red-600")}>{evidence.stance}</span>
                                    {evidence.summary}
                                  </div>
                                ))}
                              </div>
                            ) : <p className="mt-2 text-[10px] text-amber-600">No evidence citation is attached to this revision.</p>}
                            {hypothesis.status === "proposed" ? (
                              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                                <Input value={reviewNotes[hypothesis.id] || ""} onChange={(event) => setReviewNotes((current) => ({ ...current, [hypothesis.id]: event.target.value }))} placeholder="Required review reason" className="h-8 flex-1 bg-slate-50 text-[10px]" />
                                <div className="flex gap-1.5">
                                  <Button size="sm" variant="outline" className="h-8 text-[10px]" disabled={busy !== null} onClick={() => void reviewHypothesis(hypothesis.id, "reject")}>Reject</Button>
                                  <Button size="sm" className="h-8 bg-emerald-600 text-[10px] hover:bg-emerald-700" disabled={busy !== null} onClick={() => void reviewHypothesis(hypothesis.id, "accept")}>Accept</Button>
                                </div>
                              </div>
                            ) : hypothesis.review_reason ? <p className="mt-3 text-[10px] text-muted-foreground">Reviewed by {hypothesis.reviewed_by}: {hypothesis.review_reason}</p> : null}
                          </div>
                        );
                      })}
                      {!hypotheses.length ? <div className="py-7 text-center text-xs text-muted-foreground">No AI hypothesis has been persisted for this Situation.</div> : null}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                    <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h3 className="text-sm font-semibold">Linked investigations</h3><p className="mt-1 text-[11px] text-muted-foreground">Durable AI reasoning bound to this Situation</p></div><FileSearch className="size-4 text-violet-600" /></div>
                    <div className="p-3">{detail.investigations.length ? detail.investigations.map((item) => (
                      <Link key={item.id} href={`/?investigation=${item.id}`} className="group flex items-center gap-3 rounded-xl px-3 py-3 hover:bg-slate-50"><span className="grid size-8 place-items-center rounded-lg bg-violet-50 text-violet-600"><Bot className="size-4" /></span><span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{item.title}</span><span className="mt-1 block text-[9px] capitalize text-muted-foreground">{item.status.replaceAll("_", " ")} · {relativeTime(item.updated_at)}</span></span><ChevronRight className="size-3.5 text-slate-300 group-hover:text-muted-foreground" /></Link>
                    )) : <div className="py-7 text-center text-xs text-muted-foreground">No AI investigation linked yet.</div>}</div>
                  </div>
                  {externalReferences.length ? (
                    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h3 className="text-sm font-semibold">External references</h3><p className="mt-1 text-[11px] text-muted-foreground">Remote status is observed evidence; local lifecycle remains authoritative</p></div><ExternalLink className="size-4 text-sky-600" /></div>
                      <div className="divide-y divide-slate-100">
                        {externalReferences.map((reference) => (
                          <div key={reference.id} className="px-5 py-4">
                            <div className="flex items-start justify-between gap-3"><div className="min-w-0"><div className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">{reference.provider_key}</div>{reference.remote_url ? <a href={reference.remote_url} target="_blank" rel="noreferrer" className="mt-1 flex items-center gap-1 truncate font-mono text-xs font-semibold text-sky-700 hover:underline">{reference.remote_id}<ExternalLink className="size-3 shrink-0" /></a> : <div className="mt-1 truncate font-mono text-xs font-semibold text-slate-700">{reference.remote_id}</div>}</div><Badge variant="outline" className="shrink-0 text-[9px]">{reference.remote_status || "status unknown"}</Badge></div>
                            <div className="mt-2 text-[9px] text-muted-foreground">Updated {relativeTime(reference.remote_updated_at || reference.updated_at)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                  <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h3 className="text-sm font-semibold">Situation timeline</h3><p className="mt-1 text-[11px] text-muted-foreground">Correlation and lifecycle audit</p></div><Clock className="size-4 text-sky-600" /></div>
                  <div className="p-5">{detail.events.map((event, index) => (
                    <div key={event.id} className="relative flex gap-3 pb-5 last:pb-0">{index < detail.events.length - 1 && <span className="absolute left-[7px] top-4 h-[calc(100%-6px)] w-px bg-slate-200" />}<span className={cn("relative z-10 mt-1 size-3.5 shrink-0 rounded-full border-2 border-white ring-1 ring-slate-200", event.event_type === "situation.resolved" ? "bg-emerald-500" : event.event_type.includes("severity") || event.event_type.includes("reopened") ? "bg-amber-500" : "bg-violet-500")} /><div className="min-w-0 flex-1"><div className="text-xs font-medium text-slate-700">{eventLabel(event.event_type)}</div><div className="mt-1 text-[9px] text-muted-foreground">#{event.sequence} · {event.actor} · {relativeTime(event.created_at)}</div>{event.details.reason ? <div className="mt-1.5 text-[10px] text-muted-foreground">{String(event.details.reason).replaceAll("_", " ")}</div> : null}</div></div>
                  ))}</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="grid h-full place-items-center text-center"><div><CheckCircle2 className="mx-auto size-8 text-emerald-500" /><h2 className="mt-3 text-sm font-semibold">No Situation selected</h2><p className="mt-1 text-xs text-muted-foreground">Choose a correlated operational issue from the queue.</p></div></div>
          )}
        </section>
      </div>
    </main>
  );
}
