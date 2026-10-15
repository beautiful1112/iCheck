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
  ChartLine,
  ChevronRight,
  CircleDot,
  Command,
  Database,
  FileSearch,
  Gauge,
  GitBranch,
  Globe2,
  Loader2,
  LogOut,
  Menu,
  Network,
  RefreshCw,
  ScrollText,
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
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import {
  APIError,
  API_URL,
  BrowserContextChangedError,
  apiFetch,
  authenticatedEventSource,
  clearApiNamespace,
  closeBrowserSession,
} from "@/lib/icheck-api";
import { cn } from "@/lib/utils";
import { OnboardingApproval } from "@/components/onboarding-approval";
import { DeviceEnrollmentResult } from "@/components/device-enrollment-result";
import { AIRuntimeDiagnosis } from "@/components/ai-runtime-diagnosis";
import { grafanaOverviewHref } from "@/lib/grafana-links";
import { GrafanaResult } from "@/components/grafana-result";
import { ConfigurationBackups } from "@/components/configuration-backups";
import {validReference} from "@/lib/studio-builder";
import {checkedRuntimeInput,runtimeDefaults} from "@/lib/runtime-input";
import {RuntimeInputForm} from "@/components/runtime-input-form";
import {InvestigationAssistance} from "@/components/investigation-assistance";

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
  execution_mode: "standard" | "diagnose";
  parent_investigation_id: string | null;
  scope: Record<string, unknown>;
  status: InvestigationStatus;
  route_id: string;
  model_id: string;
  agent_profile_id: string | null;
  agent_profile_snapshot: Record<string, unknown>;
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
  situation_id: string | null;
  skill_artifact_version_id: string | null;
  skill_input: Record<string, unknown>;
  skill_snapshot: Record<string, unknown>;
  structured_output: Record<string, unknown> | null;
  workflow_artifact_version_id: string | null;
  workflow_input: Record<string, unknown>;
  workflow_snapshot: Record<string, unknown>;
  workflow_trigger_event_id: string | null;
  created_by: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

type InvestigationPage = {
  items: Investigation[];
  next_cursor: string | null;
};

type AgentProfileSummary = {
  id: string;
  name: string;
  description: string;
  revision: number;
  minimum_provider_privacy: "external" | "private" | "local";
  tool_policy: "permission_scoped" | "allowlist";
  allowed_tool_names: string[];
  max_iterations: number;
  max_tool_calls: number;
  token_budget: number;
  enabled: boolean;
};

type PublishedSkill = {
  artifact_id: string;
  artifact_name: string;
  version_id: string;
  version: number;
  skill_name: string;
  description: string;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  allowed_tools: string[];
  max_iterations: number;
  max_tool_calls: number;
  max_total_tokens: number;
  content_hash: string;
};

type PublishedWorkflow = {
  artifact_id: string;
  artifact_name: string;
  version_id: string;
  version: number;
  description: string;
  trigger: { trigger_type?: string; event_type?: string | null };
  input_schema: Record<string, unknown>;
  node_count: number;
  required_permissions: string[];
  approval_required: boolean;
  max_runtime_seconds: number;
  max_total_tool_calls: number;
  max_total_tokens: number;
  content_hash: string;
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
  tool_name?: string;
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
  entity_type: string;
  event_type: string;
  occurrence_count: number;
  last_seen: string;
};

type OperatorSummary = {
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

type ProjectionHealth = {
  workers_total: number;
  workers_online: number;
  workers_stale: number;
  pending: number;
  processing: number;
  retry: number;
  succeeded: number;
  ignored: number;
  dead_letter: number;
  oldest_ready_age_seconds: number | null;
  completed_last_hour: number;
};

type PrincipalContext = {
  subject: string;
  auth_method: string;
  role_names: string[];
  permissions: string[];
  authorization_scope: { all?: boolean };
};

function permits(principal: PrincipalContext | null, ...permissions: string[]): boolean {
  return Boolean(principal?.permissions?.includes("*") ||
    permissions.every((permission) => principal?.permissions?.includes(permission)));
}

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
  { label: "Capability Studio", icon: Wrench, href: "/studio" },
  { label: "Monitoring", icon: Activity, href: "/monitoring" },
  { label: "Investigations", icon: FileSearch, href: "/investigations" },
  { label: "Approvals", icon: ShieldCheck, href: "/approvals" },
  { label: "Device credentials", icon: ShieldCheck, href: "/settings/credentials" },
  { label: "Alert evidence", icon: Bell, href: "/alerts" },
  { label: "Assets", icon: Boxes, href: "/assets/devices" },
  { label: "Topology", icon: GitBranch, href: "/topology" },
  { label: "Dashboards", icon: ChartLine, href: grafanaOverviewHref, external: true },
  { label: "Evidence", icon: ScrollText, href: "/logs" },
  { label: "Workflows", icon: Command, href: "/studio/workflows" },
];

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
        <span className="mx-auto mb-3 grid size-10 place-items-center rounded-xl bg-white text-muted-foreground shadow-sm ring-1 ring-slate-200">
          <Icon className="size-5" aria-hidden="true" />
        </span>
        <p className="text-sm font-semibold text-slate-700">{title}</p>
        <p className="mx-auto mt-1 max-w-sm text-xs leading-5 text-muted-foreground">{detail}</p>
      </div>
    </div>
  );
}

export default function Home() {
  const [mobileNav, setMobileNav] = useState(false);
  const desktopNavigation = useRef<HTMLElement>(null);
  const [objective, setObjective] = useState("");
  const [agentProfiles, setAgentProfiles] = useState<AgentProfileSummary[]>([]);
  const [selectedAgentProfile, setSelectedAgentProfile] = useState("l1-operator");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [skills, setSkills] = useState<PublishedSkill[]>([]);
  const [selectedSkillVersionId, setSelectedSkillVersionId] = useState("");
  const [workflows, setWorkflows] = useState<PublishedWorkflow[]>([]);
  const [selectedWorkflowVersionId, setSelectedWorkflowVersionId] = useState("");
  const [outputIntent, setOutputIntent] = useState<
    "" | "topology-proposal"
  >("");
  const [skillInput, setSkillInput] = useState("{}");
  const [submitting, setSubmitting] = useState(false);
  const [connection, setConnection] = useState<"connecting" | "live" | "offline">(
    "connecting",
  );
  const [error, setError] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [summary, setSummary] = useState<OperatorSummary | null>(null);
  const [collectorHealth, setCollectorHealth] = useState<CollectorHealth | null>(null);
  const [projectionHealth, setProjectionHealth] = useState<ProjectionHealth | null>(null);
  const [workers, setWorkers] = useState<AgentWorker[]>([]);
  const [principal, setPrincipal] = useState<PrincipalContext | null>(null);
  const [aiQuota, setAiQuota] = useState<{
    actor_available: number | null;
    namespace_available: number | null;
    unknown_charge_requests: number;
  } | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [events, setEvents] = useState<ExecutionEvent[]>([]);
  const eventCursor = useRef(0);
  const overviewRead = useRef(0);
  const investigationRead = useRef(0);
  const runtimeReference = useRef("");

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 64rem)");
    const closeMobileNavigation = () => {
      if (desktop.matches) setMobileNav(false);
    };
    desktop.addEventListener("change", closeMobileNavigation);
    return () => desktop.removeEventListener("change", closeMobileNavigation);
  }, []);

  const clearWorkspaceData = useCallback(() => {
    overviewRead.current += 1;
    investigationRead.current += 1;
    setInvestigations([]);
    setSummary(null);
    setCollectorHealth(null);
    setProjectionHealth(null);
    setWorkers([]);
    setSkills([]);
    setWorkflows([]);
    setAgentProfiles([]);
    setPrincipal(null);
    setAiQuota(null);
    setSelectedId(null);
    setDetail(null);
    setEvents([]);
    setDetailLoading(false);
    runtimeReference.current = "";
    eventCursor.current = 0;
  }, []);

  const loadOverview = useCallback(async () => {
    const read = ++overviewRead.current;
    try {
      const nextPrincipal = await apiFetch<PrincipalContext>("/auth/me");
      if (read !== overviewRead.current) return;
      const can = (...permissions: string[]) => permits(nextPrincipal, ...permissions);
      const canReadQuota = can("assets.activate") || can("investigations.create") || can("ai.manage") ||
        (can("capabilities.manage") && nextPrincipal.authorization_scope?.all === true);
      const [nextInvestigations, nextSummary, nextCollectorHealth, nextProjectionHealth, nextWorkers, nextSkills, nextWorkflows, nextAgentProfiles, nextQuota] =
        await Promise.all([
          can("investigations.read") ? apiFetch<InvestigationPage>("/agent/investigations/page?limit=30") : Promise.resolve({ items: [] }),
          can("operations.read", "assets.read", "endpoints.read", "alerts.read") ? apiFetch<OperatorSummary>("/operator/summary") : Promise.resolve(null),
          can("collectors.read") ? apiFetch<CollectorHealth>("/collectors/health") : Promise.resolve(null),
          can("collectors.read") ? apiFetch<ProjectionHealth>("/knowledge-projections/health") : Promise.resolve(null),
          can("agent.workers.read") ? apiFetch<AgentWorker[]>("/agent/workers?limit=100") : Promise.resolve([]),
          can("investigations.create") ? apiFetch<PublishedSkill[]>("/skill-runtime/skills") : Promise.resolve([]),
          can("investigations.create") ? apiFetch<PublishedWorkflow[]>("/workflow-runtime/workflows") : Promise.resolve([]),
          can("investigations.create", "ai.profiles.read") ? apiFetch<AgentProfileSummary[]>("/ai/agent-profiles?enabled=true") : Promise.resolve([]),
          canReadQuota ? apiFetch<{
            actor_available: number | null;
            namespace_available: number | null;
            unknown_charge_requests: number;
          }>("/ai/authoring-quota?actor=web.operator").catch(() => null) : Promise.resolve(null),
        ]);
      if (read !== overviewRead.current) return;
      setInvestigations(nextInvestigations.items);
      setSummary(nextSummary);
      setCollectorHealth(nextCollectorHealth);
      setProjectionHealth(nextProjectionHealth);
      setWorkers(nextWorkers);
      setSkills(nextSkills);
      setWorkflows(nextWorkflows);
      setAgentProfiles(nextAgentProfiles);
      setPrincipal(nextPrincipal);
      setAiQuota(nextQuota);
      setSelectedAgentProfile((current) =>
        nextAgentProfiles.some((item) => item.name === current)
          ? current
          : nextAgentProfiles[0]?.name || "",
      );
      const requestedInvestigation = new URLSearchParams(
        window.location.search,
      ).get("investigation");
      const params = new URLSearchParams(window.location.search);
      const skillVersion = params.get("skill_version"), workflowVersion = params.get("workflow_version");
      const runtime = nextSkills.find(item => validReference(skillVersion) && item.version_id === skillVersion) ||
        nextWorkflows.find(item => validReference(workflowVersion) && item.version_id === workflowVersion);
      if (runtime && runtimeReference.current !== runtime.version_id) {
        runtimeReference.current = runtime.version_id;
        setSelectedSkillVersionId(nextSkills.some(item => item.version_id === runtime.version_id) ? runtime.version_id : "");
        setSelectedWorkflowVersionId(nextWorkflows.some(item => item.version_id === runtime.version_id) ? runtime.version_id : "");
        setSkillInput(JSON.stringify(runtimeDefaults(runtime.input_schema), null, 2));
        setOutputIntent("");
      }
      setSelectedId(
        (current) => can("investigations.read")
          ? (validReference(requestedInvestigation) ? requestedInvestigation : null) || current || nextInvestigations.items[0]?.id || null
          : null,
      );
      setConnection("live");
      setError(null);
    } catch (caught) {
      if (read !== overviewRead.current) return;
      clearWorkspaceData();
      setConnection("offline");
      setError(caught instanceof Error ? caught.message : "The API is unavailable");
    }
  }, [clearWorkspaceData]);

  const loadInvestigation = useCallback(async (investigationId: string) => {
    const read = ++investigationRead.current;
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
      if (read !== investigationRead.current) return;
      setDetail({ investigation, execution, checkpoints, evidence, toolCalls });
      if (execution) {
        const executionEvents = await apiFetch<ExecutionEvent[]>(
          `/agent/executions/${execution.id}/events?limit=500`,
        );
        if (read !== investigationRead.current) return;
        eventCursor.current = executionEvents.at(-1)?.sequence || 0;
        setEvents(executionEvents);
      } else {
        eventCursor.current = 0;
        setEvents([]);
      }
    } catch (caught) {
      if (read !== investigationRead.current) return;
      setDetail(null);
      setEvents([]);
      eventCursor.current = 0;
      setError(caught instanceof Error ? caught.message : "Unable to load investigation");
    } finally {
      if (read === investigationRead.current) setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    // Context links prepare a draft only. They never launch an investigation.
    const brief = new URLSearchParams(window.location.search).get("brief");
    if (!brief || brief.length > 4000 || /[\u0000-\u001f\u007f]/.test(brief)) return;
    const timer = window.setTimeout(() => setObjective(brief), 0);
    return () => window.clearTimeout(timer);
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
    const changedNamespace = () => {
      clearWorkspaceData();
      setObjective("");
      setSkillInput("{}");
      setSelectedSkillVersionId("");
      setSelectedWorkflowVersionId("");
      setSelectedAlertId(null);
      setConnection("connecting");
      void loadOverview();
    };
    const changedStorage = (event: StorageEvent) => {
      if (event.key === "icheck.namespace.v1" || event.key === null) changedNamespace();
    };
    window.addEventListener("icheck:namespace-changed", changedNamespace);
    window.addEventListener("storage", changedStorage);
    return () => {
      window.removeEventListener("icheck:namespace-changed", changedNamespace);
      window.removeEventListener("storage", changedStorage);
      overviewRead.current += 1;
      investigationRead.current += 1;
    };
  }, [clearWorkspaceData, loadOverview]);

  useEffect(() => {
    if (!selectedId || connection !== "live") return;
    const timer = window.setTimeout(() => void loadInvestigation(selectedId), 0);
    return () => window.clearTimeout(timer);
  }, [connection, loadInvestigation, selectedId]);

  const execution = connection === "live" ? detail?.execution || null : null;
  useEffect(() => {
    if (!execution || terminalExecutionStatuses.includes(execution.status)) return;
    const read = investigationRead.current;

    let stream: ReturnType<typeof authenticatedEventSource>;
    try {
      stream = authenticatedEventSource(
        "/agent/executions/" +
          execution.id +
          "/events/stream?after_sequence=" +
          eventCursor.current,
      );
    } catch (cause) {
      if (!(cause instanceof BrowserContextChangedError)) throw cause;
      // The session or namespace changed before the storage event reached this tab.
      return;
    }
    const receive = (message: MessageEvent<string>) => {
      if (read !== investigationRead.current) return;
      try {
        const next = JSON.parse(message.data) as ExecutionEvent;
        eventCursor.current = Math.max(eventCursor.current, next.sequence);
        setEvents((current) => {
          if (current.some((item) => item.id === next.id)) return current;
          return [...current, next].sort((left, right) => left.sequence - right.sequence);
        });
        if (next.event_type.startsWith("graph.") || ["execution.completed", "execution.cancelled",
          "execution.cancellation_requested", "execution.reconciled"].includes(next.event_type)) {
          void loadInvestigation(execution.investigation_id);
          void loadOverview();
        }
      } catch {
        // Stream control events have a different payload and are handled below.
      }
    };
    streamedEventTypes.forEach((eventType) => stream.addEventListener(eventType, receive));
    stream.addEventListener("stream.end", () => {
      stream.close();
      if (read !== investigationRead.current) return;
      void loadInvestigation(execution.investigation_id);
      void loadOverview();
    });
    return () => stream.close();
  }, [execution, loadInvestigation, loadOverview]);

  async function startInvestigation() {
    const nextObjective = objective.trim();
    if (!permits(principal, "investigations.create") || connection !== "live" ||
      (!selectedSkillVersionId && !selectedWorkflowVersionId && !nextObjective) || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      let investigation: Investigation;
      if (selectedSkillVersionId || selectedWorkflowVersionId) {
        if(!selectedBoundRuntime)throw new Error("The selected saved capability is no longer available");
        const parsedInput = checkedRuntimeInput(skillInput,selectedBoundRuntime.input_schema);
        const endpoint = selectedSkillVersionId
          ? `/skill-runtime/skills/${selectedSkillVersionId}/investigations`
          : `/workflow-runtime/workflows/${selectedWorkflowVersionId}/investigations`;
        const started = await apiFetch<{ investigation: Investigation }>(
          endpoint,
          {
            method: "POST",
            body: JSON.stringify({
              [selectedSkillVersionId ? "skill_input" : "workflow_input"]: parsedInput,
              scope: {},
              operator_context: nextObjective || undefined,
              route_purpose: "investigation",
              actor: "web.operator",
            }),
          },
        );
        investigation = started.investigation;
      } else {
        const alert = summary?.recent_alerts.find(item => item.id === selectedAlertId);
        const investigationScope = {
          ...(alert ? {alert_id: alert.id, entity_type: alert.entity_type, entity_id: alert.entity_id,
            ...(["device", "collector_device"].includes(alert.entity_type) ? {device_ids: [alert.entity_id]} : {})} : {}),
          ...(outputIntent === "topology-proposal" ? {requested_output_contract: "icheck.topology-proposal/v1"} : {}),
        };
        investigation = await apiFetch<Investigation>("/agent/investigations", {
          method: "POST",
          body: JSON.stringify({
            title: titleFromObjective(nextObjective),
            objective: nextObjective,
            execution_mode: outputIntent ? "standard" : "diagnose",
            scope: investigationScope,
            route_purpose: "investigation",
            agent_profile: selectedAgentProfile || undefined,
            created_by: "web.operator",
          }),
        });
        await apiFetch(`/agent/investigations/${investigation.id}/start`, {
          method: "POST",
          body: JSON.stringify({ actor: "web.operator" }),
        });
      }
      setObjective("");
      setSelectedAlertId(null);
      setOutputIntent("");
      setSelectedId(investigation.id);
      await Promise.all([loadOverview(), loadInvestigation(investigation.id)]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to start investigation");
    } finally {
      setSubmitting(false);
    }
  }

  async function cancelExecution() {
    if (!execution || !permits(principal, "investigations.cancel")) return;
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

  async function signOut() {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await closeBrowserSession();
    } catch (caught) {
      if (!(caught instanceof APIError) || caught.status !== 401) {
        setError(caught instanceof Error ? caught.message : "Unable to sign out");
        setSigningOut(false);
        return;
      }
    }
    clearApiNamespace();
    window.location.assign("/login");
  }

  const activeInvestigations = useMemo(
    () =>
      investigations.filter((item) =>
        ["pending", "running", "waiting_approval"].includes(item.status),
      ),
    [investigations],
  );
  const selectedSkill = useMemo(
    () => skills.find((skill) => skill.version_id === selectedSkillVersionId) || null,
    [selectedSkillVersionId, skills],
  );
  const selectedWorkflow = useMemo(
    () => workflows.find((workflow) => workflow.version_id === selectedWorkflowVersionId) || null,
    [selectedWorkflowVersionId, workflows],
  );
  const selectedBoundRuntime = selectedSkill || selectedWorkflow;
  const approvalCount = investigations.filter(
    (item) => item.status === "waiting_approval",
  ).length;
  const onlineAgentWorkers = workers.filter((worker) => worker.state === "online").length;
  const canCreateInvestigation = permits(principal, "investigations.create");
  const canReadInvestigations = permits(principal, "investigations.read");
  const healthSignals = useMemo(() => {
    if (connection !== "live" || !collectorHealth) return [];
    const signals = [
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
    if (projectionHealth) {
      signals.push(
        {
          label: "Knowledge projection",
          value: `${projectionHealth.workers_online}/${projectionHealth.workers_total}`,
          detail:
            projectionHealth.workers_total === 0
              ? "No projection worker registered"
              : projectionHealth.workers_stale > 0
                ? `${projectionHealth.workers_stale} heartbeat stale`
                : `${projectionHealth.completed_last_hour} envelopes projected in the last hour`,
          risk:
            projectionHealth.workers_total === 0 ||
            projectionHealth.workers_stale > 0,
        },
        {
          label: "Projection queue",
          value: String(
            projectionHealth.pending +
              projectionHealth.retry +
              projectionHealth.processing,
          ),
          detail:
            projectionHealth.dead_letter > 0
              ? `${projectionHealth.dead_letter} dead-letter envelope${projectionHealth.dead_letter === 1 ? "" : "s"}`
              : projectionHealth.oldest_ready_age_seconds !== null
                ? `Oldest ready for ${Math.round(projectionHealth.oldest_ready_age_seconds)}s`
                : "No projection backlog",
          risk:
            projectionHealth.dead_letter > 0 ||
            projectionHealth.retry > 0 ||
            (projectionHealth.oldest_ready_age_seconds ?? 0) > 30,
        },
      );
    }
    return signals;
  }, [collectorHealth, connection, projectionHealth]);

  const sidebarContent = (
    <>
        <div className="flex h-16 items-center justify-between border-b border-white/10 px-5">
          <Link href="/" aria-label="iCheck home" className="flex items-center gap-3" onClick={() => setMobileNav(false)}>
            <span className="grid size-9 place-items-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg shadow-violet-950/30">
              <Activity className="size-[18px]" aria-hidden="true" />
            </span>
            <div>
              <p className="text-base font-semibold tracking-[-0.02em]">iCheck</p>
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                AI operator
              </p>
            </div>
          </Link>
          <Button
            variant="ghost"
            size="icon-sm"
            className="text-muted-foreground hover:bg-white/10 hover:text-white lg:hidden"
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
            <p className="mt-1.5 truncate text-[10px] text-muted-foreground" title={API_URL}>
              {API_URL}
            </p>
          </div>
        </div>

        <nav className="mt-4 space-y-1 px-3" aria-label="Primary navigation">
          {navigation.map((item) => {
            const classes = cn(
              "flex h-10 w-full items-center gap-3 rounded-lg px-3 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white",
              item.active && "bg-white/[0.09] text-white ring-1 ring-white/10",
            );
            if (item.external) {
              return <a key={item.label} href={item.href} className={classes}
                onClick={() => setMobileNav(false)}>
                <item.icon className="size-[17px]" aria-hidden="true" />
                <span>{item.label}</span>
              </a>;
            }
            return (
              <Link
                key={item.label}
                href={item.href}
                className={classes}
                onClick={() => setMobileNav(false)}
              >
                <item.icon className="size-[17px]" aria-hidden="true" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto border-t border-white/10 p-3">
          <Link
            href="/settings/ai"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Settings className="size-[17px]" aria-hidden="true" />
            AI model & routing
          </Link>
          <Link
            href="/settings/observability"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Database className="size-[17px]" aria-hidden="true" />
            Observability backends
          </Link>
          <Link href="/settings/grafana" className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white">
            <ChartLine className="size-[17px]" aria-hidden="true" />Grafana connection
          </Link>
          <Link href="/dashboards" className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white">
            <Wrench className="size-[17px]" aria-hidden="true" />Dashboard proposals
          </Link>
          <Link
            href="/settings/tenancy"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Globe2 className="size-[17px]" aria-hidden="true" />
            Tenant & region
          </Link>
          <Link
            href="/settings/identity"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <ShieldCheck className="size-[17px]" aria-hidden="true" />
            Identity & sessions
          </Link>
          <Link
            href="/settings/account"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <ShieldCheck className="size-[17px]" aria-hidden="true" />
            Account settings
          </Link>
          <Link
            href="/settings/scaling"
            className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-white"
          >
            <Gauge className="size-[17px]" aria-hidden="true" />
            Worker capacity
          </Link>
          <div className="mt-2 flex items-center gap-3 rounded-xl bg-black/15 px-3 py-3">
            <span className="grid size-8 place-items-center rounded-lg bg-violet-500/20 text-violet-300">
              <Bot className="size-4" aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium text-slate-200">{principal?.subject || "Operator workspace"}</p>
              <p className="truncate text-[10px] text-muted-foreground">
                {principal?.role_names.length ? principal.role_names.join(" · ") : "Evidence-bound · governed changes"}
              </p>
            </div>
            {principal?.auth_method === "browser_session" ? (
              <Button
                variant="ghost"
                size="icon-sm"
                className="shrink-0 text-muted-foreground hover:bg-white/10 hover:text-white"
                onClick={() => void signOut()}
                disabled={signingOut}
                aria-label="Sign out"
              >
                {signingOut ? <Loader2 className="animate-spin" /> : <LogOut />}
              </Button>
            ) : null}
          </div>
        </div>
    </>
  );

  return (
    <Sheet open={mobileNav} onOpenChange={setMobileNav}>
    <div className="min-h-screen bg-[#f5f6f8] text-slate-900">
      <aside
        ref={desktopNavigation}
        data-text-surface="dark"
        className="fixed inset-y-0 left-0 z-50 hidden w-[248px] flex-col overflow-y-auto overscroll-contain border-r border-white/10 bg-[#182134] text-white shadow-2xl lg:flex"
      >
        {sidebarContent}
      </aside>
      <SheetContent
        side="left"
        data-text-surface="dark"
        showCloseButton={false}
        className="w-[248px] gap-0 overflow-y-auto overscroll-contain border-white/10 bg-[#182134] p-0 text-white sm:max-w-[248px]"
        onCloseAutoFocus={(event) => {
          if (window.matchMedia("(min-width: 64rem)").matches) {
            event.preventDefault();
            desktopNavigation.current?.querySelector<HTMLElement>("a")?.focus();
          }
        }}
      >
        <SheetTitle className="sr-only">Primary navigation</SheetTitle>
        <SheetDescription className="sr-only">Open an operations page or manage your operator session.</SheetDescription>
        {sidebarContent}
      </SheetContent>

      <div className="lg:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <SheetTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              className="lg:hidden"
              aria-label="Open navigation"
            >
              <Menu />
            </Button>
            </SheetTrigger>
            <div>
              <p className="text-sm font-semibold tracking-tight">L1 operations</p>
              <p className="hidden text-[11px] text-muted-foreground sm:block">
                Intent in, evidence-backed action out
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-600 sm:flex">
              <Bot className="size-3.5 text-violet-600" />
              {connection === "live" && permits(principal, "agent.workers.read") ? `${onlineAgentWorkers} agent worker${onlineAgentWorkers === 1 ? "" : "s"} online` : "Agent worker status unavailable"}
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

          <section data-text-surface="dark" className="relative overflow-hidden rounded-2xl bg-[#202940] px-5 py-6 text-white shadow-xl shadow-slate-900/10 sm:px-7 sm:py-7 lg:px-9">
            <div className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-violet-500/20 blur-3xl" />
            <div className="pointer-events-none absolute -bottom-32 left-1/3 size-64 rounded-full bg-sky-400/10 blur-3xl" />
            <div className="relative max-w-4xl">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-violet-300">
                <Sparkles className="size-3.5" />
                AI L1 operator
              </div>
              <h1 className="mt-3 text-2xl font-semibold tracking-[-0.035em] sm:text-3xl">
                {principal && !canCreateInvestigation ? "Review operations and evidence" : "What should I investigate?"}
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
                {principal && !canCreateInvestigation
                  ? "Read the investigations, evidence, and action plans available to your account."
                  : "Choose autonomous investigation, a governed Skill, or a deterministic Workflow. Every run remains bounded, evidence-backed, and auditable."}
              </p>
              {aiQuota && <p className="mt-2 text-xs text-muted-foreground">
                AI tokens available today: {aiQuota.actor_available?.toLocaleString() ?? "unbounded"} for you · {aiQuota.namespace_available?.toLocaleString() ?? "unbounded"} for this tenant/region
                {aiQuota.unknown_charge_requests ? ` · ${aiQuota.unknown_charge_requests} uncertain charge${aiQuota.unknown_charge_requests === 1 ? "" : "s"}` : ""}.
                {" "}<Link href="/settings/ai/authoring-quota" className="text-violet-300 underline hover:text-white">Quota details</Link>
              </p>}
              {canCreateInvestigation ? <>
              <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:items-center">
                <label htmlFor="operator-mode" className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                  Operator mode
                </label>
                <select
                  id="operator-mode"
                  value={selectedSkillVersionId || selectedWorkflowVersionId || outputIntent}
                  onChange={(event) => {
                    const versionId = event.target.value;
                    if (versionId === "topology-proposal") {
                      setSelectedSkillVersionId("");
                      setSelectedWorkflowVersionId("");
                      setOutputIntent(versionId);
                      setSkillInput("{}");
                      return;
                    }
                    const skill = skills.find((item) => item.version_id === versionId);
                    const workflow = workflows.find((item) => item.version_id === versionId);
                    setSelectedSkillVersionId(skill ? versionId : "");
                    setSelectedWorkflowVersionId(workflow ? versionId : "");
                    setOutputIntent("");
                    setSkillInput(JSON.stringify(runtimeDefaults((skill || workflow)?.input_schema || {}), null, 2));
                    setObjective("");
                    setSelectedAlertId(null);
                  }}
                  disabled={submitting || connection !== "live"}
                  className="h-9 min-w-72 rounded-lg border border-white/15 bg-white/[0.08] px-3 text-xs text-white outline-none transition focus:border-violet-400"
                >
                  <option value="" className="text-slate-900">Investigate with AI — no workflow required</option>
                  <option value="topology-proposal" className="text-slate-900">Generate governed topology proposal</option>
                  {skills.map((skill) => (
                    <option key={skill.version_id} value={skill.version_id} className="text-slate-900">
                      {skill.skill_name} · v{skill.version}
                    </option>
                  ))}
                  {workflows.map((workflow) => (
                    <option
                      key={workflow.version_id}
                      value={workflow.version_id}
                      disabled={workflow.trigger.trigger_type !== "manual"}
                      className="text-slate-900"
                    >
                      Workflow · {workflow.artifact_name} · v{workflow.version}{workflow.trigger.trigger_type !== "manual" ? " (event-triggered)" : ""}
                    </option>
                  ))}
                </select>
              </div>
              {!selectedBoundRuntime && permits(principal, "ai.profiles.read") ? (
                <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
                  <label htmlFor="agent-profile" className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                    Agent profile
                  </label>
                  <select
                    id="agent-profile"
                    value={selectedAgentProfile}
                    onChange={(event) => setSelectedAgentProfile(event.target.value)}
                    disabled={submitting || connection !== "live"}
                    className="h-9 min-w-72 rounded-lg border border-white/15 bg-white/[0.08] px-3 text-xs text-white outline-none transition focus:border-violet-400"
                  >
                    {agentProfiles.map((profile) => (
                      <option key={profile.id} value={profile.name} className="text-slate-900">
                        {profile.name} · r{profile.revision} · {profile.minimum_provider_privacy}
                      </option>
                    ))}
                  </select>
                  {permits(principal, "ai.manage") ? <Link href="/settings/agents" className="text-[10px] font-semibold text-violet-300 hover:text-white">
                    Configure profiles
                  </Link> : null}
                </div>
              ) : null}
              {selectedBoundRuntime ? (
                <div className="mt-3 rounded-xl border border-violet-300/20 bg-violet-400/[0.08] px-4 py-3 text-xs text-slate-300">
                  <p className="font-semibold text-violet-200">{selectedBoundRuntime.description}</p>
                  {selectedSkill ? (
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      Diagnostic Skill · {selectedSkill.allowed_tools.length} pinned tool{selectedSkill.allowed_tools.length === 1 ? "" : "s"} · {selectedSkill.max_iterations} iterations · {selectedSkill.max_tool_calls} calls
                    </p>
                  ) : selectedWorkflow ? (
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      Governed Workflow · {selectedWorkflow.node_count} nodes · {selectedWorkflow.max_total_tool_calls} calls{selectedWorkflow.approval_required ? " · approval path" : ""}
                    </p>
                  ) : null}
                </div>
              ) : null}
              <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.07] p-2 shadow-inner backdrop-blur-sm focus-within:border-violet-400/60 focus-within:ring-2 focus-within:ring-violet-400/15">
                {selectedAlertId ? (
                  <div className="mx-2 mt-2 flex items-center justify-between gap-3 rounded-lg border border-amber-300/20 bg-amber-300/10 px-3 py-2 text-[10px] text-amber-100">
                    <span className="flex items-center gap-2">
                      <Bell className="size-3.5" /> Alert context {selectedAlertId.slice(0, 8)}
                    </span>
                    <button
                      type="button"
                      className="font-semibold text-amber-200 hover:text-white"
                      onClick={() => setSelectedAlertId(null)}
                    >
                      Clear
                    </button>
                  </div>
                ) : null}
                <Textarea
                  aria-label="Investigation objective or operator context"
                  value={objective}
                  onChange={(event) => setObjective(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      void startInvestigation();
                    }
                  }}
                  placeholder={selectedBoundRuntime
                    ? "Optional operator context for this governed run."
                    : outputIntent === "topology-proposal"
                      ? "Example: Create an HQ dependency view from the evidence collected during this investigation."
                      : "Example: Find why users at the Hong Kong office are reporting intermittent network access."}
                  className={cn("resize-none border-0 bg-transparent px-3 py-3 text-sm leading-6 text-white shadow-none placeholder:text-muted-foreground focus-visible:ring-0", selectedBoundRuntime ? "min-h-16" : "min-h-24")}
                  disabled={submitting || connection !== "live"}
                />
                {selectedBoundRuntime ? (
                  <div className="border-t border-white/10 px-3 py-3">
                    <RuntimeInputForm key={selectedBoundRuntime.version_id} schema={selectedBoundRuntime.input_schema} value={skillInput} onChange={setSkillInput}
                      disabled={submitting || connection!=="live"} canReadDevices={permits(principal,"assets.read")}/>
                  </div>
                ) : null}
                <div className="flex items-center justify-between gap-3 px-2 pb-1">
                  <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                    <span className="rounded-md bg-white/[0.06] px-2 py-1">Read-only by default</span>
                    <span className="rounded-md bg-white/[0.06] px-2 py-1">Audited tools</span>
                    <span className="hidden rounded-md bg-white/[0.06] px-2 py-1 sm:inline">AI chooses relevant tools</span>
                    {permits(principal, "ai.manage") && <Link className="text-violet-300 underline" href="/settings/ai/autonomy">Automatic alert investigation</Link>}
                    {outputIntent === "topology-proposal" ? <Link href="/studio/proposals" className="rounded-md bg-sky-400/10 px-2 py-1 text-sky-200 hover:text-white">Human publish required</Link> : null}
                  </div>
                  <Button
                    size="icon"
                    className="size-9 rounded-xl bg-violet-500 text-white hover:bg-violet-400"
                    onClick={() => void startInvestigation()}
                    disabled={(!selectedSkillVersionId && !selectedWorkflowVersionId && !objective.trim()) || (Boolean(selectedSkillVersionId || selectedWorkflowVersionId) && !skillInput.trim()) || submitting || connection !== "live"}
                    aria-label="Start investigation"
                  >
                    {submitting ? <Loader2 className="animate-spin" /> : <ArrowUp />}
                  </Button>
                </div>
              </div>
              </> : <p className="mt-5 text-xs text-muted-foreground" role="status">
                {principal
                  ? "Starting an investigation requires operator access. You can continue reviewing the evidence available below."
                  : "Checking your operator access…"}
              </p>}
            </div>
          </section>

          <section className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Active in recent 30</span>
                <CircleDot className="size-4 text-violet-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{connection === "live" && canReadInvestigations ? activeInvestigations.length : "—"}</p>
              <Link href="/investigations" className="mt-1 inline-flex items-center gap-1 text-[11px] text-violet-700 hover:underline">Open investigation history <ChevronRight className="size-3" /></Link>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Operator approvals</span>
                <ShieldCheck className="size-4 text-amber-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{connection === "live" && canReadInvestigations ? approvalCount : "—"}</p>
              <Link
                href="/approvals"
                className="mt-1 inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-violet-700"
              >
                Review exact action plans <ChevronRight className="size-3" />
              </Link>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Active alerts</span>
                <Bell className="size-4 text-red-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{summary?.open_alerts ?? "—"}</p>
              <p className="mt-1 text-[11px] text-muted-foreground">{summary ? `${summary.critical_alerts} critical · acknowledgement is not resolution` : "Awaiting control-plane data"}</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">Evidence coverage</span>
                <Database className="size-4 text-sky-500" />
              </div>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{summary?.devices ?? "—"}</p>
              <p className="mt-1 text-[11px] text-muted-foreground">{summary ? `${summary.endpoints} identified endpoints` : "No synthetic inventory"}</p>
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
                  <p className="mt-1 text-xs text-muted-foreground">Reasoning progress is paired with inspectable evidence and tool activity.</p>
                </div>
                <div className="flex items-center gap-3">
                  <Link href="/investigations" className="text-xs font-medium text-violet-700 hover:underline">History</Link>
                  {detail?.investigation ? <StatusBadge status={detail.investigation.status} /> : null}
                </div>
              </div>

              <div className="p-5 sm:p-6">
                {connection !== "live" ? (
                  <EmptyState icon={FileSearch} title="Investigation data unavailable" detail="Connect to the control plane to read authorized investigation evidence." />
                ) : !canReadInvestigations ? (
                  <EmptyState icon={FileSearch} title="Investigation access required" detail="Your account does not have access to investigation history." />
                ) : detailLoading && !detail ? (
                  <div className="grid min-h-80 place-items-center text-sm text-muted-foreground">
                    <Loader2 className="mb-2 size-5 animate-spin text-violet-500" />
                  </div>
                ) : detail ? (
                  <div>
                    <div className="flex flex-col gap-5 border-b border-slate-100 pb-5 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Objective</p>
                        <h3 className="mt-2 text-lg font-semibold leading-7 tracking-[-0.02em] text-slate-900">{detail.investigation.title}</h3>
                        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{detail.investigation.objective}</p>
                        <Link href={`/settings/ai/authoring-quota?source_entity_id=${encodeURIComponent(detail.investigation.id)}`} className="mt-2 inline-flex text-xs text-violet-700 underline hover:text-violet-900">Review my model-call receipts for this investigation</Link>
                        {detail.investigation.agent_profile_snapshot.name ? (
                          <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                            <Badge variant="outline" className="border-violet-200 bg-violet-50 text-violet-700">
                              Agent · {String(detail.investigation.agent_profile_snapshot.name)} · r{String(detail.investigation.agent_profile_snapshot.revision)}
                            </Badge>
                            <span>{String(detail.investigation.agent_profile_snapshot.minimum_provider_privacy)} privacy · {String(detail.investigation.agent_profile_snapshot.tool_policy).replaceAll("_", " ")}</span>
                          </div>
                        ) : null}
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {execution && ["queued", "running"].includes(execution.status) && permits(principal, "investigations.cancel") ? (
                          <Button variant="outline" size="sm" onClick={() => void cancelExecution()}>
                            <Square className="size-3 fill-current" />
                            Stop
                          </Button>
                        ) : null}
                      </div>
                    </div>

                    <div className="grid gap-3 border-b border-slate-100 py-5 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Confidence</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.confidence === null ? "Not scored" : `${Math.round(detail.investigation.confidence * 100)}%`}</p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Iterations</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.iterations_used}<span className="text-xs font-normal text-muted-foreground"> / {detail.investigation.max_iterations}</span></p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Tool calls</p>
                        <p className="mt-1.5 text-lg font-semibold">{detail.investigation.tool_calls_used}<span className="text-xs font-normal text-muted-foreground"> / {detail.investigation.max_tool_calls}</span></p>
                      </div>
                      <div className="rounded-xl bg-slate-50 p-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Execution</p>
                        <p className="mt-1.5 text-sm font-semibold capitalize">{execution ? humanStatus(execution.status) : "Not started"}</p>
                        {execution?.attempt_count ? <p className="mt-0.5 text-[10px] text-muted-foreground">Attempt {execution.attempt_count}</p> : null}
                      </div>
                    </div>

                    {execution?.cancellation_reason ? <p role="status" className="border-b border-slate-100 py-4 text-sm text-amber-800">
                      {execution.cancellation_reason}
                    </p> : null}

                    {detail.investigation.conclusion || detail.investigation.escalation_reason ? (
                      <div className="border-b border-slate-100 py-5">
                        <div className="flex items-center gap-2">
                          {detail.investigation.conclusion ? <CheckCircle2 className="size-4 text-emerald-600" /> : <AlertTriangle className="size-4 text-amber-600" />}
                          <h4 className="text-sm font-semibold">{detail.investigation.conclusion ? "Operator conclusion" : "Escalation reason"}</h4>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-slate-600">{detail.investigation.conclusion || detail.investigation.escalation_reason}</p>
                        {detail.investigation.escalation_reason && <AIRuntimeDiagnosis key={detail.investigation.id}
                          investigationId={detail.investigation.id} canManage={permits(principal, "ai.manage")}
                          canRetry={permits(principal, "investigations.create")} />}
                      </div>
                    ) : null}

                    <InvestigationAssistance key={detail.investigation.id} id={detail.investigation.id}
                      status={detail.investigation.status} parentId={detail.investigation.parent_investigation_id}
                      canContinue={canCreateInvestigation} onContinued={id => {
                        window.history.replaceState(null, "", `/?investigation=${id}`);
                        setSelectedId(id); void loadOverview(); void loadInvestigation(id);
                      }}/>
                    {detail.investigation.structured_output ? (
                      <div className="border-b border-slate-100 py-5">
                        <DeviceEnrollmentResult result={detail.investigation.structured_output} />
                        <div className="flex items-center gap-2">
                          <Zap className="size-4 text-violet-600" />
                          <h4 className="text-sm font-semibold">{detail.investigation.skill_artifact_version_id ? "Validated Skill output" : "Workflow result"}</h4>
                        </div>
                        <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-950 p-4 font-mono text-[11px] leading-5 text-slate-200">{JSON.stringify(detail.investigation.structured_output, null, 2)}</pre>
                      </div>
                    ) : null}

                    <div className="grid gap-6 pt-5 lg:grid-cols-2">
                      <div className="min-w-0">
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
                                  <p className="text-[10px] text-muted-foreground">#{event.sequence} · {relativeTime(event.created_at)}</p>
                                </div>
                              </li>
                            ))}
                          </ol>
                        ) : <EmptyState icon={Activity} title="No execution events yet" detail="The timeline begins when an agent worker claims this investigation." />}
                      </div>

                      <div className="min-w-0">
                        <div className="mb-3 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Database className="size-4 text-sky-600" />
                            <h4 className="text-sm font-semibold">Evidence ledger</h4>
                          </div>
                          <span className="text-[10px] text-muted-foreground">{detail.evidence.length} references</span>
                        </div>
                        {detail.evidence.length ? (
                          <div className="space-y-2">
                            {detail.evidence.slice(0, 6).map((item) => (
                              <div key={item.id} className="rounded-xl border border-slate-200 p-3">
                                <div className="flex items-center justify-between gap-3">
                                  <Badge variant="secondary" className="rounded-md font-mono text-[9px]">{item.evidence_type}</Badge>
                                  <span className="text-[9px] text-muted-foreground">{relativeTime(item.observed_at || item.created_at)}</span>
                                </div>
                                <p className="mt-2 text-xs leading-5 text-slate-600">{item.summary}</p>
                                <p className="mt-1.5 truncate font-mono text-[9px] text-muted-foreground" title={item.evidence_id}>{item.evidence_id}</p>
                              </div>
                            ))}
                          </div>
                        ) : <EmptyState icon={Database} title="No evidence captured" detail="Evidence created by approved tool calls will appear here with a durable reference." />}
                      </div>
                    </div>

                    {detail.toolCalls.filter(call => call.status === "succeeded").map(call => <OnboardingApproval key={call.id} result={call.result} />)}
                    {detail.toolCalls.filter(call => call.status === "succeeded").slice(-10).map(call => <GrafanaResult key={`grafana:${call.id}`} result={call.result} toolName={call.tool_name} />)}
                    <ConfigurationBackups investigationId={detail.investigation.id} calls={detail.toolCalls} evidence={detail.evidence}
                      canDownload={permits(principal, "assets.read", "capabilities.manage")} />
                    <div className="mt-6 grid gap-6 border-t border-slate-100 pt-5 lg:grid-cols-2">
                      <div>
                        <div className="mb-3 flex items-center gap-2">
                          <Wrench className="size-4 text-muted-foreground" />
                          <h4 className="text-sm font-semibold">Tool activity</h4>
                        </div>
                        {detail.toolCalls.length ? (
                          <div className="overflow-hidden rounded-xl border border-slate-200">
                            {detail.toolCalls.slice(0, 6).map((call) => (
                              <div key={call.id} className="flex items-center gap-3 border-b border-slate-100 px-3 py-2.5 last:border-0">
                                <span className={cn("size-2 rounded-full", call.status === "succeeded" ? "bg-emerald-500" : call.status === "failed" ? "bg-red-500" : "bg-amber-500")} />
                                <div className="min-w-0 flex-1">
                                  <p className="truncate font-mono text-[11px] font-medium text-slate-700">{call.tool_id}</p>
                                  <p className="text-[9px] text-muted-foreground">Iteration {call.iteration} · {humanStatus(call.status)}</p>
                                </div>
                                <span className="text-[9px] text-muted-foreground">{relativeTime(call.created_at)}</span>
                              </div>
                            ))}
                          </div>
                        ) : <p className="rounded-xl bg-slate-50 px-4 py-3 text-xs text-muted-foreground">No tool calls have been made.</p>}
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
                        ) : <p className="rounded-xl bg-slate-50 px-4 py-3 text-xs text-muted-foreground">The operator has not recorded uncertainty yet.</p>}
                      </div>
                    </div>
                  </div>
                ) : (
                  <EmptyState icon={FileSearch} title="No investigation selected" detail="Start with an operational objective above. The AI operator will create an auditable investigation rather than an ephemeral chat." />
                )}
              </div>
            </section>

            <div className="space-y-5">
              <section className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                  <div>
                    <h2 className="text-sm font-semibold">Collection gaps</h2>
                    <p className="mt-1 text-[11px] text-muted-foreground">Signals that weaken operator confidence</p>
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
                        <p className="mt-0.5 truncate text-[10px] text-muted-foreground">{signal.detail}</p>
                      </div>
                      <span className="text-sm font-semibold text-slate-700">{signal.value}</span>
                    </div>
                  )) : <div className="py-6 text-center text-xs text-muted-foreground">Collector health unavailable.</div>}
                </div>
              </section>

              <section id="alerts" className="scroll-mt-24 rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
                  <div>
                    <h2 className="text-sm font-semibold">Recent alert evidence</h2>
                    <p className="mt-1 text-[11px] text-muted-foreground">Choose context for the next investigation</p>
                  </div>
                  <Link href="/alerts" className="flex items-center gap-1 text-[10px] font-semibold text-violet-700">
                    View all <ChevronRight className="size-3" />
                  </Link>
                </div>
                <div className="p-3">
                  {summary?.recent_alerts.length ? summary.recent_alerts.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="flex items-start gap-1 rounded-xl px-2 py-2.5 transition-colors hover:bg-slate-50">
                      <button
                        type="button"
                        className="min-w-0 flex-1 text-left"
                        onClick={() => {
                          setSelectedSkillVersionId("");
                          setSelectedWorkflowVersionId("");
                          setSelectedAlertId(alert.id);
                          setObjective(
                            `Investigate alert: ${alert.title}. ${alert.description}`,
                          );
                          window.scrollTo({ top: 0, behavior: "smooth" });
                        }}
                      >
                        <span className="flex items-start gap-3">
                          <span className={cn("mt-1 size-2 shrink-0 rounded-full", alert.severity === "critical" ? "bg-red-500" : alert.severity === "warning" ? "bg-amber-500" : "bg-sky-500")} />
                          <span className="min-w-0 flex-1">
                            <span className="line-clamp-1 text-xs font-medium text-slate-700">{alert.title}</span>
                            <span className="mt-1 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{alert.description}</span>
                            <span className="mt-1 block text-[9px] text-muted-foreground">{alert.status} · {alert.entity_id} · {relativeTime(alert.last_seen)}</span>
                          </span>
                        </span>
                      </button>
                      <Link href="/alerts" className="rounded-md p-2 text-muted-foreground hover:bg-white hover:text-violet-700" aria-label={`Open evidence for ${alert.title}`}>
                        <ChevronRight className="size-3.5" />
                      </Link>
                    </div>
                  )) : <div className="py-7 text-center text-xs text-muted-foreground">{connection === "live" && summary ? "No active source alerts." : "Alert evidence unavailable."}</div>}
                </div>
              </section>
            </div>
          </div>
        </main>
      </div>
    </div>
    </Sheet>
  );
}
