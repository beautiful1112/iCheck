"use client";

import Link from "next/link";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUp,
  Bell,
  Bot,
  Boxes,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock,
  Command,
  Database,
  FileSearch,
  GitBranch,
  Loader2,
  Menu,
  Network,
  RefreshCw,
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Wrench,
  X,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

const API_URL =
  process.env.NEXT_PUBLIC_ICHECK_API_URL || "http://localhost:8000/api/v1";

type InvestigationStatus =
  | "pending"
  | "running"
  | "waiting_approval"
  | "completed"
  | "escalated"
  | "failed"
  | "cancelled";

type ExecutionStatus =
  | "queued"
  | "running"
  | "waiting_approval"
  | "succeeded"
  | "failed"
  | "cancelled";

type Investigation = {
  id: string;
  title: string;
  objective: string;
  scope: Record<string, unknown>;
  status: InvestigationStatus;
  route_id: string;
  model_id: string;
  max_iterations: number;
  max_tool_calls: number;
  timeout_seconds: number;
  token_budget: number;
  iterations_used: number;
  tool_calls_used: number;
  tokens_used: number;
  confidence: number | null;
  conclusion: string | null;
  uncertainty: string[];
  escalation_reason: string | null;
  created_by: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

type AgentExecution = {
  id: string;
  investigation_id: string;
  status: ExecutionStatus;
  worker_id: string | null;
  lease_expires_at: string | null;
  attempt_count: number;
  cancellation_requested_at: string | null;
  cancellation_requested_by: string | null;
  cancellation_reason: string | null;
  started_at: string | null;
  last_heartbeat_at: string | null;
  finished_at: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
};

type InvestigationCheckpoint = {
  id: string;
  investigation_id: string;
  sequence: number;
  node: string;
  state: Record<string, unknown>;
  state_hash: string;
  created_by: string;
  created_at: string;
};

type Evidence = {
  id: string;
  investigation_id: string;
  evidence_type: string;
  evidence_id: string;
  summary: string;
  observed_at: string | null;
  created_at: string;
};

type ToolCall = {
  id: string;
  investigation_id: string;
  tool_id: string;
  iteration: number;
  call_hash: string;
  arguments: Record<string, unknown>;
  status: string;
  result: Record<string, unknown> | unknown[] | null;
  result_hash: string | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};

type ExecutionEvent = {
  id: string;
  execution_id: string;
  sequence: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
};

type AlertRecord = {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "warning" | "info";
  status: "open" | "acknowledged" | "resolved";
  entity_id: string;
  event_type: string;
  occurrence_count: number;
  last_seen: string;
};

type DashboardSummary = {
  devices: number;
  endpoints: number;
  active_wireless_clients: number;
  open_alerts: number;
  critical_alerts: number;
  recent_alerts: AlertRecord[];
};

type CollectorHealth = {
  workers_total: number;
  workers_online: number;
  workers_stale: number;
  deployments_total: number;
  deployments_enabled: number;
  deployments_leased: number;
  deployments_due: number;
  running_runs: number;
  failed_runs_last_hour: number;
};

type AgentWorker = {
  id: string;
  name: string;
  capabilities: string[];
  labels: Record<string, string>;
  state: "online" | "draining" | "offline";
  last_heartbeat_at: string;
};

type InvestigationDetail = {
  investigation: Investigation;
  execution: AgentExecution | null;
  checkpoints: InvestigationCheckpoint[];
  evidence: Evidence[];
  toolCalls: ToolCall[];
};

const terminalExecutionStatuses: ExecutionStatus[] = [
  "succeeded",
  "failed",
  "cancelled",
  "waiting_approval",
];

const streamedEventTypes = [
  "execution.queued",
  "execution.claimed",
  "execution.reassigned",
  "execution.cancellation_requested",
  "execution.cancelled",
  "execution.completed",
  "execution.reconciled",
  "graph.reason",
  "graph.tools",
  "graph.finalize",
];

const navigation = [
  { label: "AI operator", icon: Sparkles, href: "/", active: true },
  { label: "Investigations", icon: FileSearch, href: "#investigations" },
  { label: "Approvals", icon: ShieldCheck, href: "/approvals" },
  { label: "Alerts", icon: Bell, href: "#alerts" },
  { label: "Assets", icon: Boxes, href: "/assets/devices" },
  { label: "Topology", icon: GitBranch, badge: "Next" },
  { label: "Workflows", icon: Command, badge: "Next" },
];

class APIError extends Error {
  status: number;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "APIError";
    this.status = status;
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const document = (await response.json()) as { detail?: string };
      if (document.detail) detail = document.detail;
    } catch {
      // Preserve the HTTP status when a proxy returns a non-JSON error page.
    }
    throw new APIError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

function relativeTime(value: string | null): string {
  if (!value) return "not yet";
  const delta = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.round(delta / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function titleFromObjective(objective: string): string {
  const normalized = objective.replace(/\s+/g, " ").trim();
  if (normalized.length <= 84) return normalized;
  return `${normalized.slice(0, 81).trimEnd()}…`;
}

function statusTone(status: InvestigationStatus | ExecutionStatus): string {
  if (status === "completed" || status === "succeeded") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  if (status === "running") {
    return "border-violet-200 bg-violet-50 text-violet-700";
  }
  if (status === "queued" || status === "pending") {
    return "border-sky-200 bg-sky-50 text-sky-700";
  }
  if (status === "waiting_approval") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  if (status === "failed" || status === "escalated") {
    return "border-red-200 bg-red-50 text-red-700";
  }
  return "border-slate-200 bg-slate-50 text-slate-600";
}

function humanStatus(status: string): string {
  return status.replaceAll("_", " ");
}

function eventLabel(eventType: string): string {
  const labels: Record<string, string> = {
    "execution.queued": "Investigation queued",
    "execution.claimed": "Agent worker claimed execution",
    "execution.reassigned": "Execution resumed by another worker",
    "execution.cancellation_requested": "Cancellation requested",
    "execution.cancelled": "Execution cancelled",
    "execution.completed": "Execution finished",
    "execution.reconciled": "Execution state reconciled",
    "graph.reason": "AI evaluated evidence and next action",
    "graph.tools": "Tools executed and evidence captured",
    "graph.finalize": "Conclusion finalized",
  };
  return labels[eventType] || eventType.replaceAll(".", " · ");
}

function StatusBadge({ status }: { status: InvestigationStatus | ExecutionStatus }) {
  const active = status === "running" || status === "queued";
  return (
    <Badge
      variant="outline"
      className={cn("capitalize", statusTone(status))}
    >
      {active ? <span className="size-1.5 animate-pulse rounded-full bg-current" /> : null}
      {humanStatus(status)}
    </Badge>
  );
}

function EmptyState({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof FileSearch;
  title: string;
  detail: string;
}) {
  return (
    <div className="grid min-h-44 place-items-center rounded-xl border border-dashed border-slate-200 bg-slate-50/60 px-6 text-center">
      <div>
        <span className="mx-auto mb-3 grid size-10 place-items-center rounded-xl bg-white text-slate-400 shadow-sm ring-1 ring-slate-200">
          <Icon className="size-5" aria-hidden="true" />
        </span>
        <p className="text-sm font-semibold text-slate-700">{title}</p>
        <p className="mx-auto mt-1 max-w-sm text-xs leading-5 text-slate-500">{detail}</p>
      </div>
    </div>
  );
}

export default function Home() {
  const [mobileNav, setMobileNav] = useState(false);
  const [objective, setObjective] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [connection, setConnection] = useState<"connecting" | "live" | "offline">(
    "connecting",
  );
  const [error, setError] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [collectorHealth, setCollectorHealth] = useState<CollectorHealth | null>(null);
  const [workers, setWorkers] = useState<AgentWorker[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const eventCursor = useRef(0);

  const loadOverview = useCallback(async () => {
    try {
      const [nextInvestigations, nextSummary, nextCollectorHealth, nextWorkers] =
        await Promise.all([
          apiFetch<Investigation[]>("/agent/investigations?limit=30"),
          apiFetch<DashboardSummary>("/dashboard/summary"),
          apiFetch<CollectorHealth>("/collectors/health"),
          apiFetch<AgentWorker[]>("/agent/workers?limit=100"),
        ]);
      setInvestigations(nextInvestigations);
      setSummary(nextSummary);
      setCollectorHealth(nextCollectorHealth);
      setWorkers(nextWorkers);
      setSelectedId((current) => current || nextInvestigations[0]?.id || null);
      setConnection("live");
      setError(null);
    } catch (caught) {
      setConnection("offline");
      setError(caught instanceof Error ? caught.message : "The API is unavailable");
    }
  }, []);

  const loadInvestigation = useCallback(async (investigationId: string) => {
    setDetailLoading(true);
    try {
      const [investigation, checkpoints, evidence, toolCalls] = await Promise.all([
        apiFetch<Investigation>(`/agent/investigations/${investigationId}`),
        apiFetch<InvestigationCheckpoint[]>(
          `/agent/investigations/${investigationId}/checkpoints?limit=50`,
        ),
        apiFetch<Evidence[]>(
          `/agent/investigations/${investigationId}/evidence?limit=100`,
        ),
        apiFetch<ToolCall[]>(
          `/agent/investigations/${investigationId}/tool-calls?limit=100`,
        ),
      ]);
      let execution: AgentExecution | null = null;
      try {
        execution = await apiFetch<AgentExecution>(
          `/agent/investigations/${investigationId}/execution`,
        );
      } catch (caught) {
        if (!(caught instanceof APIError) || caught.status !== 404) {
          throw caught;
        }
      }
      setDetail({ investigation, execution, checkpoints, evidence, toolCalls });
      if (execution) {
        const executionEvents = await apiFetch<ExecutionEvent[]>(
          `/agent/executions/${execution.id}/events?limit=500`,
        );
        eventCursor.current = executionEvents.at(-1)?.sequence || 0;
        setEvents(executionEvents);
      } else {
        eventCursor.current = 0;
        setEvents([]);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load investigation");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void loadOverview(), 0);
    const refresh = window.setInterval(() => void loadOverview(), 15_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(refresh);
    };
  }, [loadOverview]);

  useEffect(() => {
    if (!selectedId) return;
    const timer = window.setTimeout(() => void loadInvestigation(selectedId), 0);
    return () => window.clearTimeout(timer);
  }, [loadInvestigation, selectedId]);

  const execution = detail?.execution || null;
  useEffect(() => {
    if (!execution || terminalExecutionStatuses.includes(execution.status)) return;

    const source = new EventSource(
      `${API_URL}/agent/executions/${execution.id}/events/stream?after_sequence=${eventCursor.current}`,
    );
    const receive = (message: MessageEvent<string>) => {
      try {
        const next = JSON.parse(message.data) as ExecutionEvent;
        eventCursor.current = Math.max(eventCursor.current, next.sequence);
        setEvents((current) => {
          if (current.some((item) => item.id === next.id)) return current;
          return [...current, next].sort((left, right) => left.sequence - right.sequence);
        });
        if (next.event_type.startsWith("graph.") || next.event_type === "execution.completed") {
          void loadInvestigation(execution.investigation_id);
          void loadOverview();
        }
      } catch {
        // Stream control events have a different payload and are handled below.
      }
    };
    streamedEventTypes.forEach((eventType) => source.addEventListener(eventType, receive));
    source.addEventListener("stream.end", () => {
      source.close();
      void loadInvestigation(execution.investigation_id);
      void loadOverview();
    });
    return () => source.close();
  }, [execution, loadInvestigation, loadOverview]);

  async function startInvestigation() {
    const nextObjective = objective.trim();
    if (!nextObjective || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const investigation = await apiFetch<Investigation>("/agent/investigations", {
        method: "POST",
        body: JSON.stringify({
          title: titleFromObjective(nextObjective),
          objective: nextObjective,
          scope: {},
          route_purpose: "investigation",
          created_by: "web.operator",
        }),
      });
      await apiFetch(`/agent/investigations/${investigation.id}/start`, {
        method: "POST",
        body: JSON.stringify({ actor: "web.operator" }),
      });
      setObjective("");
      setSelectedId(investigation.id);
      await Promise.all([loadOverview(), loadInvestigation(investigation.id)]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to start investigation");
    } finally {
      setSubmitting(false);
    }
  }

  async function cancelExecution() {
    if (!execution) return;
    try {
      await apiFetch(`/agent/executions/${execution.id}/cancel`, {
        method: "POST",
        body: JSON.stringify({
          actor: "web.operator",
          reason: "Operator requested cancellation from the investigation workspace.",
        }),
      });
      await Promise.all([
        loadOverview(),
        loadInvestigation(execution.investigation_id),
      ]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to cancel execution");
    }
  }

  const activeInvestigations = useMemo(
    () =>
      investigations.filter((item) =>
        ["pending", "running", "waiting_approval"].includes(item.status),
      ),
    [investigations],
  );
  const approvalCount = investigations.filter(
    (item) => item.status === "waiting_approval",
  ).length;
  const onlineAgentWorkers = workers.filter((worker) => worker.state === "online").length;
  const healthSignals = useMemo(() => {
    if (!collectorHealth) return [];
    return [
      {
        label: "Collector workers",
        value: `${collectorHealth.workers_online}/${collectorHealth.workers_total}`,
        detail:
          collectorHealth.workers_total === 0
            ? "No collector worker registered"
            : collectorHealth.workers_stale > 0
              ? `${collectorHealth.workers_stale} heartbeat stale`
              : "All registered workers current",
        risk:
          collectorHealth.workers_total === 0 || collectorHealth.workers_stale > 0,
      },
      {
        label: "Collection queue",
        value: String(collectorHealth.deployments_due),
        detail: `${collectorHealth.running_runs} runs active now`,
        risk: collectorHealth.deployments_due > 0,
      },
      {
        label: "Recent failures",
        value: String(collectorHealth.failed_runs_last_hour),
        detail: "Collector runs in the last hour",
        risk: collectorHealth.failed_runs_last_hour > 0,
      },
    ];
  }, [collectorHealth]);

  return (
    <div className="min-h-screen bg-[#f5f6f8] text-slate-900">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-[248px] -translate-x-full flex-col border-r border-white/10 bg-[#182134] text-white shadow-2xl transition-transform lg:translate-x-0",
          mobileNav && "translate-x-0",
        )}
      >
        <div className="flex h-16 items-center justify-between border-b border-white/10 px-5">
          <Link href="/" className="flex items-center gap-3" onClick={() => setMobileNav(false)}>
            <span className="grid size-9 place-items-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-950/30">
              <Activity className="size-[18px]" aria-hidden="true" />
            </span>
            <div>
              <p className="text-base font-semibold tracking-[-0.02em]">iCheck</p>
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                AI operator
              </p>
            </div>
          </Link>
          <Button
            variant="ghost"
            size="icon-sm"
            className="text-slate-400 hover:bg-white/10 hover:text-white lg:hidden"
            onClick={() => setMobileNav(false)}
            aria-label="Close navigation"
          >
            <X />
          </Button>
        </div>

        <div className="px-4 pt-5">
          <div className="rounded-xl border border-white/10 bg-white/[0.04] p-3">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
              <span
                className={cn(
                  "size-2 rounded-full",
                  connection === "live"
                    ? "bg-emerald-400 shadow-[0_0_10px_#34d399]"
                    : connection === "connecting"
                      ? "animate-pulse bg-amber-400"
                      : "bg-red-400",
                )}
              />
              {connection === "live"
                ? "Control plane connected"
                : connection === "connecting"
                  ? "Connecting to control plane"
                  : "Control plane unavailable"}
            </div>
            <p className="mt-1.5 truncate text-[10px] text-slate-500" title={API_URL}>
              {API_URL}
            </p>
          </div>
        </div>

        <nav className="mt-4 space-y-1 px-3" aria-label="Primary navigation">
          {navigation.map((item) => {
            const content = (
              <>
                <item.icon className="size-[17px]" aria-hidden="true" />
                <span>{item.label}</span>
                {item.badge ? (
                  <span className="ml-auto rounded-md bg-white/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-slate-400">
                    {item.badge}
                  </span>
                ) : null}
              </>
            );
            const classes = cn(
              "flex h-10 w-full items-center gap-3 rounded-lg px-3 text-sm font-medium text-slate-400 transition-colors hover:bg-white/[0.06] hover:text-white",
              item.active && "bg-white/[0.09] text-white ring-1 ring-white/10",
              !item.href && "cursor-default",
            );
            return item.href ? (
              <Link
                key={item.label}
                href={item.href}
                className={classes}
                onClick={() => setMobileNav(false)}
              >
                {content}
              </Link>
            ) : (
              <span key={item.label} className={classes}>
                {content}
              </span>
            );
          })}
        </nav>

        <div className="mt-auto border-t border-white/10 p-3">
          <Link
            href="/settings/ai"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-400 transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Settings className="size-[17px]" aria-hidden="true" />
            AI model & routing
          </Link>
          <div className="mt-2 flex items-center gap-3 rounded-xl bg-black/15 px-3 py-3">
            <span className="grid size-8 place-items-center rounded-lg bg-violet-500/20 text-violet-300">
              <Bot className="size-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <p className="text-xs font-medium text-slate-200">Operator workspace</p>
              <p className="truncate text-[10px] text-slate-500">
                Evidence-bound · governed changes
              </p>
            </div>
          </div>
        </div>
      </aside>

      {mobileNav ? (
        <button
          type="button"
          className="fixed inset-0 z-40 bg-slate-950/50 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileNav(false)}
          aria-label="Close navigation overlay"
        />
      ) : null}

      <div className="lg:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon-sm"
              className="lg:hidden"
              onClick={() => setMobileNav(true)}
              aria-label="Open navigation"
            >
              <Menu />
            </Button>
            <div>
              <p className="text-sm font-semibold tracking-tight">L1 operations</p>
              <p className="hidden text-[11px] text-slate-500 sm:block">
                Intent in, evidence-backed action out
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-600 sm:flex">
              <Bot className="size-3.5 text-violet-600" />
              {onlineAgentWorkers} agent worker{onlineAgentWorkers === 1 ? "" : "s"} online
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void loadOverview()}
              aria-label="Refresh operations data"
            >
              <RefreshCw className="size-3.5" />
              <span className="hidden sm:inline">Refresh</span>
            </Button>
          </div>
        </header>

        <main className="mx-auto max-w-[1500px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
          {error ? (
            <div className="mb-5 flex items-start justify-between gap-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              <div className="flex gap-2.5">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <div>
                  <p className="font-semibold">Operator workspace needs attention</p>
                  <p className="mt-0.5 text-xs text-red-700">{error}</p>
                </div>
              </div>
              <button type="button" onClick={() => setError(null)} aria-label="Dismiss error">
                <X className="size-4" />
              </button>
            </div>
          ) : null}

          <section className="relative overflow-hidden rounded-2xl bg-[#202940] px-5 py-6 text-white shadow-xl shadow-slate-900/10 sm:px-7 sm:py-7 lg:px-9">
            <div className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-violet-500/20 blur-3xl" />
            <div className="pointer-events-none absolute -bottom-32 left-1/3 size-64 rounded-full bg-sky-400/10 blur-3xl" />
            <div className="relative max-w-4xl">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-violet-300">
                <Sparkles className="size-3.5" />
                AI L1 operator
              </div>
              <h1 className="mt-3 text-2xl font-semibold tracking-[-0.035em] sm:text-3xl">
                What should I investigate?
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
                Give the operator an outcome, not a sequence of commands. It will plan,
                call bounded tools, preserve evidence, and surface uncertainty before it
                reaches a conclusion.
              </p>
              <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.07] p-2 shadow-inner backdrop-blur-sm focus-within:border-violet-400/60 focus-within:ring-2 focus-within:ring-violet-400/15">
                <Textarea
                  value={objective}
                  onChange={(event) => setObjective(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      void startInvestigation();
                    }
                  }}
                  placeholder="Example: Find why users at the Hong Kong office are reporting intermittent network access."
                  className="min-h-24 resize-none border-0 bg-transparent px-3 py-3 text-sm leading-6 text-white shadow-none placeholder:text-slate-500 focus-visible:ring-0"
                  disabled={submitting || connection !== "live"}
                />
                <div className="flex items-center justify-between gap-3 px-2 pb-1">
                  <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-400">
                    <span className="rounded-md bg-white/[0.06] px-2 py-1">Read-only by default</span>
                    <span className="rounded-md bg-white/[0.06] px-2 py-1">Audited tools</span>
                    <span className="hidden rounded-md bg-white/[0.06] px-2 py-1 sm:inline">Bounded agent loop</span>
                  </div>
                  <Button
                    size="icon"
                    className="size-9 rounded-xl bg-violet-500 text-white hover:bg-violet-400"
                    onClick={() => void startInvestigation()}
                    disabled={!objective.trim() || submitting || connection !== "live"}
                    aria-label="Start investigation"
                  >
                    {submitting ? <Loader2 className="animate-spin" /> : <ArrowUp />}
                  </Button>
                </div>
              </div>
            </div>
          </section>

          <section className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Investigations active</span>
                <CircleDot className="size-4 text-violet-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{activeInvestigations.length}</p>
              <p className="mt-1 text-[11px] text-slate-500">{investigations.length} retained in the current view</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Operator approvals</span>
                <ShieldCheck className="size-4 text-amber-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{approvalCount}</p>
              <Link
                href="/approvals"
                className="mt-1 inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-violet-700"
              >
                Review exact action plans <ChevronRight className="size-3" />
              </Link>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Open situations</span>
                <Bell className="size-4 text-red-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{summary?.open_alerts ?? "—"}</p>
              <p className="mt-1 text-[11px] text-slate-500">{summary ? `${summary.critical_alerts} critical` : "Awaiting control-plane data"}</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">Evidence coverage</span>
                <Database className="size-4 text-sky-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{summary?.devices ?? "—"}</p>
              <p className="mt-1 text-[11px] text-slate-500">{summary ? `${summary.endpoints} identified endpoints` : "No synthetic inventory"}</p>
            </div>
          </section>

          <div className="mt-5 grid items-start gap-5 xl:grid-cols-[minmax(0,1.65fr)_minmax(330px,0.8fr)]">
            <section className="min-w-0 rounded-2xl border border-slate-200 bg-white shadow-sm" aria-labelledby="investigation-heading">
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
                <div>
                  <div className="flex items-center gap-2">
                    <Bot className="size-4 text-violet-600" />
                    <h2 id="investigation-heading" className="text-sm font-semibold">Investigation workspace</h2>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">Reasoning progress is paired with inspectable evidence and tool activity.</p>
                </div>
                {detail?.investigation ? <StatusBadge status={detail.investigation.status} /> : null}
              </div>

              <div className="p-5 sm:p-6">
                {detailLoading && !detail ? (
                  <div className="grid min-h-80 place-items-center text-sm text-slate-500">
                    <Loader2 className="mb-2 size-5 animate-spin text-violet-500" />
                  </div>
                ) : detail ? (
                  <div>
                    <div className="flex flex-col gap-5 border-b border-slate-100 pb-5 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">Objective</p>
                        <h3 className="mt-2 text-lg font-semibold leading-7 tracking-[-0.02em] text-slate-900">{detail.investigation.title}</h3>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{detail.investigation.objective}</p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {execution && ["queued", "running"].includes(execution.status) ? (
                          <Button variant="outline" size="sm" onClick={() => void cancelExecution()}>
                            <Square className="size-3 fill-current" />
                            Stop
                          </Button>
                        ) : null}
                      </div>
                    </div>

                    <div className="grid gap-3 border-b border-slate-100 py-5 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Confidence</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.confidence === null ? "Not scored" : `${Math.round(detail.investigation.confidence * 100)}%`}</p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Iterations</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.iterations_used}<span className="text-xs font-normal text-slate-400"> / {detail.investigation.max_iterations}</span></p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Tool calls</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.tool_calls_used}<span className="text-xs font-normal text-slate-400"> / {detail.investigation.max_tool_calls}</span></p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Execution</p>
                        <p className="mt-1.5 text-sm font-semibold capitalize">{execution ? humanStatus(execution.status) : "Not started"}</p>
                        {execution?.attempt_count ? <p className="mt-0.5 text-[10px] text-slate-400">Attempt {execution.attempt_count}</p> : null}
                      </div>
                    </div>

                    {detail.investigation.conclusion || detail.investigation.escalation_reason ? (
                      <div className="border-b border-slate-100 py-5">
                        <div className="flex items-center gap-2">
                          {detail.investigation.conclusion ? <CheckCircle2 className="size-4 text-emerald-600" /> : <AlertTriangle className="size-4 text-amber-600" />}
                          <h4 className="text-sm font-semibold">{detail.investigation.conclusion ? "Operator conclusion" : "Escalation reason"}</h4>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-slate-600">{detail.investigation.conclusion || detail.investigation.escalation_reason}</p>
                      </div>
                    ) : null}

                    <div className="grid gap-6 pt-5 lg:grid-cols-2">
                      <div>
                        <div className="mb-3 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Activity className="size-4 text-violet-600" />
                            <h4 className="text-sm font-semibold">Live execution trace</h4>
                          </div>
                          {execution && !terminalExecutionStatuses.includes(execution.status) ? <span className="flex items-center gap-1.5 text-[10px] font-medium text-emerald-600"><span className="size-1.5 animate-pulse rounded-full bg-emerald-500" />SSE live</span> : null}
                        </div>
                        {events.length ? (
                          <ol className="space-y-0">
                            {events.slice(-8).map((event, index, shown) => (
                              <li key={event.id} className="relative flex gap-3 pb-4 last:pb-0">
                                {index < shown.length - 1 ? <span className="absolute left-[7px] top-4 h-full w-px bg-slate-200" /> : null}
                                <span className={cn("relative z-10 mt-1 size-[15px] shrink-0 rounded-full border-[3px] border-white ring-1", event.event_type.startsWith("graph.") ? "bg-violet-500 ring-violet-200" : "bg-slate-400 ring-slate-200")} />
                                <div className="min-w-0">
                                  <p className="text-xs font-medium leading-5 text-slate-700">{eventLabel(event.event_type)}</p>
                                  <p className="text-[10px] text-slate-400">#{event.sequence} · {relativeTime(event.created_at)}</p>
                                </div>
                              </li>
                            ))}
                          </ol>
                        ) : <EmptyState icon={Activity} title="No execution events yet" detail="The timeline begins when an agent worker claims this investigation." />}
                      </div>

                      <div>
                        <div className="mb-3 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Database className="size-4 text-sky-600" />
                            <h4 className="text-sm font-semibold">Evidence ledger</h4>
                          </div>
                          <span className="text-[10px] text-slate-400">{detail.evidence.length} references</span>
                        </div>
                        {detail.evidence.length ? (
                          <div className="space-y-2">
                            {detail.evidence.slice(0, 6).map((item) => (
                              <div key={item.id} className="rounded-xl border border-slate-200 p-3">
                                <div className="flex items-center justify-between gap-3">
                                  <Badge variant="secondary" className="rounded-md font-mono text-[9px]">{item.evidence_type}</Badge>
                                  <span className="text-[9px] text-slate-400">{relativeTime(item.observed_at || item.created_at)}</span>
                                </div>
                                <p className="mt-2 text-xs leading-5 text-slate-600">{item.summary}</p>
                                <p className="mt-1.5 truncate font-mono text-[9px] text-slate-400" title={item.evidence_id}>{item.evidence_id}</p>
                              </div>
                            ))}
                          </div>
                        ) : <EmptyState icon={Database} title="No evidence captured" detail="Evidence created by approved tool calls will appear here with a durable reference." />}
                      </div>
                    </div>

                    <div className="mt-6 grid gap-6 border-t border-slate-100 pt-5 lg:grid-cols-2">
                      <div>
                        <div className="mb-3 flex items-center gap-2">
                          <Wrench className="size-4 text-slate-500" />
                          <h4 className="text-sm font-semibold">Tool activity</h4>
                        </div>
                        {detail.toolCalls.length ? (
                          <div className="overflow-hidden rounded-xl border border-slate-200">
                            {detail.toolCalls.slice(0, 6).map((call) => (
                              <div key={call.id} className="flex items-center gap-3 border-b border-slate-100 px-3 py-2.5 last:border-0">
                                <span className={cn("size-2 rounded-full", call.status === "succeeded" ? "bg-emerald-500" : call.status === "failed" ? "bg-red-500" : "bg-amber-500")} />
                                <div className="min-w-0 flex-1">
                                  <p className="truncate font-mono text-[11px] font-medium text-slate-700">{call.tool_id}</p>
                                  <p className="text-[9px] text-slate-400">Iteration {call.iteration} · {humanStatus(call.status)}</p>
                                </div>
                                <span className="text-[9px] text-slate-400">{relativeTime(call.created_at)}</span>
                              </div>
                            ))}
                          </div>
                        ) : <p className="rounded-xl bg-slate-50 px-4 py-3 text-xs text-slate-500">No tool calls have been made.</p>}
                      </div>
                      <div>
                        <div className="mb-3 flex items-center gap-2">
                          <AlertTriangle className="size-4 text-amber-500" />
                          <h4 className="text-sm font-semibold">Known uncertainty</h4>
                        </div>
                        {detail.investigation.uncertainty.length ? (
                          <ul className="space-y-2">
                            {detail.investigation.uncertainty.map((item) => (
                              <li key={item} className="flex gap-2 rounded-xl bg-amber-50 px-3 py-2.5 text-xs leading-5 text-amber-900">
                                <span className="mt-2 size-1 shrink-0 rounded-full bg-amber-500" />
                                {item}
                              </li>
                            ))}
                          </ul>
                        ) : <p className="rounded-xl bg-slate-50 px-4 py-3 text-xs text-slate-500">The operator has not recorded uncertainty yet.</p>}
                      </div>
                    </div>
                  </div>
                ) : (
                  <EmptyState icon={FileSearch} title="No investigation selected" detail="Start with an operational objective above. The AI operator will create an auditable investigation rather than an ephemeral chat." />
                )}
              </div>
            </section>

            <div className="space-y-5">
              <section id="investigations" className="scroll-mt-24 rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                  <div>
                    <h2 className="text-sm font-semibold">Recent investigations</h2>
                    <p className="mt-1 text-[11px] text-slate-500">Durable operator sessions</p>
                  </div>
                  <span className="grid size-8 place-items-center rounded-lg bg-violet-50 text-violet-600"><Bot className="size-4" /></span>
                </div>
                <div className="max-h-[400px] overflow-y-auto p-2">
                  {investigations.length ? investigations.map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => setSelectedId(item.id)}
                      className={cn("group flex w-full items-start gap-3 rounded-xl px-3 py-3 text-left transition-colors hover:bg-slate-50", selectedId === item.id && "bg-violet-50/70 hover:bg-violet-50")}
                    >
                      <span className={cn("mt-1 grid size-7 shrink-0 place-items-center rounded-lg", item.status === "completed" ? "bg-emerald-100 text-emerald-700" : item.status === "running" ? "bg-violet-100 text-violet-700" : item.status === "failed" || item.status === "escalated" ? "bg-red-100 text-red-700" : "bg-slate-100 text-slate-600")}>
                        {item.status === "completed" ? <CheckCircle2 className="size-3.5" /> : item.status === "running" ? <Zap className="size-3.5" /> : <Clock className="size-3.5" />}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="line-clamp-2 text-xs font-medium leading-5 text-slate-700">{item.title}</span>
                        <span className="mt-1 flex items-center gap-1.5 text-[9px] text-slate-400"><span className="capitalize">{humanStatus(item.status)}</span> · {relativeTime(item.updated_at)}</span>
                      </span>
                      <ChevronRight className="mt-1.5 size-3.5 shrink-0 text-slate-300 group-hover:text-slate-500" />
                    </button>
                  )) : (
                    <div className="px-3 py-8 text-center text-xs text-slate-500">No investigations yet.</div>
                  )}
                </div>
              </section>

              <section className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                  <div>
                    <h2 className="text-sm font-semibold">Collection gaps</h2>
                    <p className="mt-1 text-[11px] text-slate-500">Signals that weaken operator confidence</p>
                  </div>
                  <Network className="size-4 text-sky-600" />
                </div>
                <div className="divide-y divide-slate-100 px-5">
                  {healthSignals.length ? healthSignals.map((signal) => (
                    <div key={signal.label} className="flex items-center gap-3 py-3.5">
                      <span className={cn("grid size-8 place-items-center rounded-lg", signal.risk ? "bg-amber-50 text-amber-600" : "bg-emerald-50 text-emerald-600")}>
                        {signal.risk ? <AlertTriangle className="size-4" /> : <CheckCircle2 className="size-4" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium text-slate-700">{signal.label}</p>
                        <p className="mt-0.5 truncate text-[10px] text-slate-400">{signal.detail}</p>
                      </div>
                      <span className="text-sm font-semibold text-slate-700">{signal.value}</span>
                    </div>
                  )) : <div className="py-6 text-center text-xs text-slate-500">Collector health unavailable.</div>}
                </div>
              </section>

              <section id="alerts" className="scroll-mt-24 rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                  <div>
                    <h2 className="text-sm font-semibold">Priority situations</h2>
                    <p className="mt-1 text-[11px] text-slate-500">Inputs for the next investigation</p>
                  </div>
                  <Bell className="size-4 text-red-500" />
                </div>
                <div className="p-3">
                  {summary?.recent_alerts.length ? summary.recent_alerts.slice(0, 5).map((alert) => (
                    <button
                      type="button"
                      key={alert.id}
                      className="w-full rounded-xl px-2 py-2.5 text-left transition-colors hover:bg-slate-50"
                      onClick={() => setObjective(`Investigate alert: ${alert.title}. ${alert.description} Affected entity: ${alert.entity_id}.`)}
                    >
                      <div className="flex items-start gap-3">
                        <span className={cn("mt-1 size-2 shrink-0 rounded-full", alert.severity === "critical" ? "bg-red-500" : alert.severity === "warning" ? "bg-amber-500" : "bg-sky-500")} />
                        <span className="min-w-0 flex-1">
                          <span className="line-clamp-1 text-xs font-medium text-slate-700">{alert.title}</span>
                          <span className="mt-1 line-clamp-2 text-[10px] leading-4 text-slate-400">{alert.description}</span>
                          <span className="mt-1 block text-[9px] text-slate-400">{alert.entity_id} · {relativeTime(alert.last_seen)}</span>
                        </span>
                      </div>
                    </button>
                  )) : <div className="py-7 text-center text-xs text-slate-500">No alert situations reported.</div>}
                </div>
              </section>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
