"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Gauge,
  Loader2,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Rocket,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type VersionStatus = "draft" | "validated" | "published" | "deprecated";
type RolloutStatus = "running" | "passed" | "aborted" | "promoted";
type FleetStatus = "planned" | "running" | "completed" | "failed" | "rolling_back" | "rolled_back" | "rollback_failed";
type FleetItemStatus = "pending" | "blocked" | "deferred" | "migrated" | "failed" | "rollback_deferred" | "rolled_back" | "rollback_failed";
type AutomationState = "manual" | "armed" | "observing" | "paused" | "aborted" | "completed" | "failed";
type RingStatus = "pending" | "applying" | "observing" | "passed" | "paused" | "aborted" | "failed";

type ArtifactVersion = {
  id: string;
  version: number;
  status: VersionStatus;
  content_hash: string | null;
};

type Artifact = {
  id: string;
  name: string;
  kind: string;
  description: string;
  versions: ArtifactVersion[];
};

type DeviceOption = {
  id: string;
  name: string;
  management_ip: string | null;
  site: string | null;
  identity_revision: number;
  enabled: boolean;
};

type DevicePage = { items: DeviceOption[]; next_cursor: string | null };

type Rollout = {
  id: string;
  name: string;
  artifact_id: string;
  candidate_version_id: string;
  baseline_version_id: string | null;
  deployment_id: string | null;
  status: RolloutStatus;
  target_classification: string | null;
  scope_device_id: string | null;
  scope_device_identity_revision: number | null;
  scope_site: string | null;
  external_source_reason: string | null;
  target_ownership_sha256: string | null;
  target: Record<string, unknown>;
  configuration: Record<string, unknown>;
  worker_selector: Record<string, unknown>;
  credential_profile_ref: string | null;
  schedule_seconds: number;
  min_successful_runs: number;
  max_failed_runs: number;
  min_records_per_run: number;
  successful_runs: number;
  qualifying_runs: number;
  failed_runs: number;
  records_received: number;
  evidence_batches: number;
  last_evidence_sha256: string | null;
  last_run_id: string | null;
  last_gate_result: string | null;
  created_by: string;
  started_at: string;
  deadline_at: string;
  evaluated_at: string | null;
  passed_at: string | null;
  aborted_at: string | null;
  abort_reason: string | null;
  promoted_at: string | null;
  promoted_by: string | null;
  promotion_reason: string | null;
  created_at: string;
  updated_at: string;
};

type FleetRollout = {
  id: string;
  canary_rollout_id: string;
  artifact_id: string;
  from_version_id: string;
  to_version_id: string;
  status: FleetStatus;
  scope_site: string | null;
  include_disabled: boolean;
  batch_size: number;
  max_failures: number;
  progression_mode: "manual" | "automatic";
  ring_percentages: number[];
  observation_seconds: number;
  min_successful_runs_per_deployment: number;
  max_failed_runs_per_ring: number;
  automation_state: AutomationState;
  current_ring_index: number | null;
  automation_updated_at: string | null;
  plan_sha256: string;
  planned_count: number;
  pending_count: number;
  blocked_count: number;
  deferred_count: number;
  migrated_count: number;
  failed_count: number;
  rolled_back_count: number;
  rollback_failed_count: number;
  last_batch_result: Record<string, string | number>;
  created_by: string;
  reason: string;
  started_at: string | null;
  completed_at: string | null;
  rollback_started_at: string | null;
  rolled_back_at: string | null;
  created_at: string;
  updated_at: string;
};

type FleetItem = {
  id: string;
  rollout_id: string;
  deployment_id: string;
  deployment_name: string;
  pre_change_sha256: string;
  post_change_sha256: string;
  status: FleetItemStatus;
  ring_index: number | null;
  block_reason_code: string | null;
  attempt_count: number;
  last_error_code: string | null;
  last_error_sha256: string | null;
  migrated_at: string | null;
  rolled_back_at: string | null;
  created_at: string;
  updated_at: string;
};

type FleetRing = {
  id: string;
  rollout_id: string;
  ring_index: number;
  target_percent: number;
  target_count: number;
  cohort_count: number;
  status: RingStatus;
  healthy_deployments: number;
  missing_evidence_deployments: number;
  successful_runs: number;
  failed_runs: number;
  last_gate_result: string | null;
  evidence_sha256: string | null;
  observation_started_at: string | null;
  passed_at: string | null;
};

function statusClass(status: RolloutStatus) {
  if (status === "promoted") return "border-violet-300 bg-violet-50 text-violet-700";
  if (status === "passed") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "aborted") return "border-red-300 bg-red-50 text-red-700";
  return "border-cyan-300 bg-cyan-50 text-cyan-700";
}

function fleetStatusClass(status: FleetStatus | FleetItemStatus | AutomationState | RingStatus) {
  if (status === "completed" || status === "migrated" || status === "rolled_back" || status === "passed") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "failed" || status === "rollback_failed" || status === "aborted") return "border-red-300 bg-red-50 text-red-700";
  if (status === "blocked" || status === "deferred" || status === "rollback_deferred" || status === "paused") return "border-amber-300 bg-amber-50 text-amber-700";
  if (status === "rolling_back") return "border-violet-300 bg-violet-50 text-violet-700";
  return "border-cyan-300 bg-cyan-50 text-cyan-700";
}

function shortHash(value: string | null) {
  return value ? `${value.slice(0, 12)}…${value.slice(-8)}` : "—";
}

export default function RolloutStudioPage() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [rollouts, setRollouts] = useState<Rollout[]>([]);
  const [fleetRollouts, setFleetRollouts] = useState<FleetRollout[]>([]);
  const [fleetItems, setFleetItems] = useState<FleetItem[]>([]);
  const [fleetRings, setFleetRings] = useState<FleetRing[]>([]);
  const [selectedRolloutId, setSelectedRolloutId] = useState<string | null>(null);
  const [selectedFleetId, setSelectedFleetId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [artifactId, setArtifactId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [name, setName] = useState("candidate-canary");
  const [target, setTarget] = useState('{\n  "url": "https://api.example.test/records"\n}');
  const [targetScope, setTargetScope] = useState<"registered_device" | "external_source">("registered_device");
  const [deviceSearch, setDeviceSearch] = useState("");
  const [deviceOptions, setDeviceOptions] = useState<DeviceOption[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<DeviceOption | null>(null);
  const [deviceSearchError, setDeviceSearchError] = useState<string | null>(null);
  const [externalSourceReason, setExternalSourceReason] = useState("");
  const [configuration, setConfiguration] = useState("{}");
  const [workerSelector, setWorkerSelector] = useState('{\n  "site": "LAB"\n}');
  const [credentialRef, setCredentialRef] = useState("");
  const [scheduleSeconds, setScheduleSeconds] = useState(30);
  const [timeoutSeconds, setTimeoutSeconds] = useState(900);
  const [minSuccess, setMinSuccess] = useState(3);
  const [maxFailures, setMaxFailures] = useState(1);
  const [minRecords, setMinRecords] = useState(1);
  const [reason, setReason] = useState("");
  const [fleetScope, setFleetScope] = useState("LAB");
  const [fleetBatchSize, setFleetBatchSize] = useState(25);
  const [fleetMaxFailures, setFleetMaxFailures] = useState(1);
  const [fleetIncludeDisabled, setFleetIncludeDisabled] = useState(false);
  const [fleetAutomatic, setFleetAutomatic] = useState(false);
  const [fleetRingPercentages, setFleetRingPercentages] = useState("5,25,50,100");
  const [fleetObservationSeconds, setFleetObservationSeconds] = useState(300);
  const [fleetMinHealthyRuns, setFleetMinHealthyRuns] = useState(1);
  const [fleetMaxFailedRuns, setFleetMaxFailedRuns] = useState(0);
  const [fleetPlanReason, setFleetPlanReason] = useState("");
  const [fleetActionReason, setFleetActionReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedRollout = useMemo(
    () => rollouts.find((item) => item.id === selectedRolloutId) || null,
    [rollouts, selectedRolloutId],
  );
  const selectedArtifact = useMemo(
    () => artifacts.find((item) => item.id === artifactId) || null,
    [artifacts, artifactId],
  );
  const relatedFleetRollouts = useMemo(
    () => fleetRollouts.filter((item) => item.canary_rollout_id === selectedRolloutId),
    [fleetRollouts, selectedRolloutId],
  );
  const selectedFleet = useMemo(
    () => fleetRollouts.find((item) => item.id === selectedFleetId) || null,
    [fleetRollouts, selectedFleetId],
  );
  const validatedVersions = useMemo(
    () => (selectedArtifact?.versions || []).filter((item) => item.status === "validated"),
    [selectedArtifact],
  );

  const load = useCallback(async () => {
    try {
      const [allArtifacts, allRollouts, allFleetRollouts] = await Promise.all([
        apiFetch<Artifact[]>("/artifacts?kind=collector&limit=500"),
        apiFetch<Rollout[]>("/collector-canary-rollouts?limit=500"),
        apiFetch<FleetRollout[]>("/collector-fleet-rollouts?limit=500"),
      ]);
      setArtifacts(allArtifacts);
      setRollouts(allRollouts);
      setFleetRollouts(allFleetRollouts);
      setArtifactId((current) => current || allArtifacts[0]?.id || "");
      setSelectedRolloutId((current) =>
        allRollouts.some((item) => item.id === current) ? current : allRollouts[0]?.id || null,
      );
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load rollouts");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const polling = window.setInterval(() => void load(), 5_000);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(polling);
    };
  }, [load]);

  useEffect(() => {
    if (!showCreate || targetScope !== "registered_device") return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const query = new URLSearchParams({ limit: "25" });
      if (deviceSearch.trim()) query.set("search", deviceSearch.trim());
      void apiFetch<DevicePage>(`/assets/devices/page?${query.toString()}`)
        .then((page) => {
          if (!cancelled) {
            setDeviceOptions(page.items);
            setDeviceSearchError(null);
          }
        })
        .catch((cause: unknown) => {
          if (!cancelled) setDeviceSearchError(cause instanceof Error ? cause.message : "Unable to search devices");
        });
    }, 250);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [showCreate, targetScope, deviceSearch]);

  useEffect(() => {
    const timer = window.setTimeout(() => setVersionId(validatedVersions[0]?.id || ""), 0);
    return () => window.clearTimeout(timer);
  }, [validatedVersions]);

  useEffect(() => {
    const matching = fleetRollouts.filter((item) => item.canary_rollout_id === selectedRolloutId);
    const timer = window.setTimeout(() => {
      setSelectedFleetId((current) => matching.some((item) => item.id === current) ? current : matching[0]?.id || null);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fleetRollouts, selectedRolloutId]);

  useEffect(() => {
    if (!selectedFleet) {
      const timer = window.setTimeout(() => { setFleetItems([]); setFleetRings([]); }, 0);
      return () => window.clearTimeout(timer);
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void Promise.all([
        apiFetch<FleetItem[]>(`/collector-fleet-rollouts/${selectedFleet.id}/items?limit=10000`),
        apiFetch<FleetRing[]>(`/collector-fleet-rollouts/${selectedFleet.id}/rings`),
      ])
        .then(([items, rings]) => { if (!cancelled) { setFleetItems(items); setFleetRings(rings); } })
        .catch((cause: unknown) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Unable to load fleet rollout items"); });
    }, 0);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [selectedFleet]);

  async function createRollout(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!versionId) return;
    setBusy("create");
    setError(null);
    try {
      const targetDocument = JSON.parse(target) as Record<string, unknown>;
      const selectorDocument = JSON.parse(workerSelector) as Record<string, string>;
      let boundDevice: DeviceOption | null = null;
      if (targetScope === "registered_device") {
        if (!selectedDevice) throw new Error("Select a registered Device before starting a canary.");
        boundDevice = await apiFetch<DeviceOption>(`/assets/devices/${encodeURIComponent(selectedDevice.id)}`);
        if (
          boundDevice.identity_revision !== selectedDevice.identity_revision
          || boundDevice.management_ip !== selectedDevice.management_ip
          || boundDevice.site !== selectedDevice.site
        ) {
          setSelectedDevice(null);
          throw new Error("Device identity changed. Search and select it again before starting the canary.");
        }
        if (!boundDevice.enabled || !boundDevice.site) throw new Error("The selected Device must be enabled and have a site.");
        if (targetDocument.device_id && targetDocument.device_id !== boundDevice.id) throw new Error("Target JSON device_id conflicts with the selected Device.");
        if (targetDocument.site && targetDocument.site !== boundDevice.site) throw new Error("Target JSON site conflicts with the selected Device.");
        if (selectorDocument.site && selectorDocument.site !== boundDevice.site) throw new Error("Worker selector site conflicts with the selected Device.");
      } else {
        if (targetDocument.device_id) throw new Error("External sources cannot declare a registered Device ID.");
        if (externalSourceReason.trim().length < 10) throw new Error("Explain why this target is an external source.");
      }
      const created = await apiFetch<Rollout>("/collector-canary-rollouts", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          artifact_version_id: versionId,
          scope_device_id: boundDevice?.id ?? null,
          scope_device_identity_revision: boundDevice?.identity_revision ?? null,
          target_classification: targetScope,
          external_source_reason: targetScope === "external_source" ? externalSourceReason.trim() : null,
          scope_site: boundDevice?.site ?? (typeof targetDocument.site === "string" ? targetDocument.site : null),
          target: targetDocument,
          configuration: JSON.parse(configuration) as Record<string, unknown>,
          worker_selector: selectorDocument,
          credential_profile_ref: credentialRef.trim() || null,
          schedule_seconds: scheduleSeconds,
          timeout_seconds: timeoutSeconds,
          min_successful_runs: minSuccess,
          max_failed_runs: maxFailures,
          min_records_per_run: minRecords,
          actor: "capability.reviewer",
        }),
      });
      await load();
      setSelectedRolloutId(created.id);
      setShowCreate(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to start canary");
    } finally {
      setBusy(null);
    }
  }

  async function act(action: "abort" | "promote") {
    if (!selectedRollout || reason.trim().length < 3) return;
    setBusy(action);
    setError(null);
    try {
      await apiFetch<Rollout>(`/collector-canary-rollouts/${selectedRollout.id}/${action}`, {
        method: "POST",
        body: JSON.stringify({
          actor: action === "promote" ? "capability.publisher" : "capability.reviewer",
          reason: reason.trim(),
        }),
      });
      setReason("");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Unable to ${action} rollout`);
    } finally {
      setBusy(null);
    }
  }

  async function createFleetPlan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedRollout || selectedRollout.status !== "promoted" || fleetPlanReason.trim().length < 3) return;
    setBusy("fleet-plan");
    setError(null);
    try {
      const created = await apiFetch<FleetRollout>("/collector-fleet-rollouts", {
        method: "POST",
        body: JSON.stringify({
          canary_rollout_id: selectedRollout.id,
          scope_site: fleetScope.trim() || null,
          include_disabled: fleetIncludeDisabled,
          batch_size: fleetBatchSize,
          max_failures: fleetMaxFailures,
          max_deployments: 10_000,
          progression_mode: fleetAutomatic ? "automatic" : "manual",
          ring_percentages: fleetRingPercentages.split(",").map((value) => Number(value.trim())),
          observation_seconds: fleetObservationSeconds,
          min_successful_runs_per_deployment: fleetMinHealthyRuns,
          max_failed_runs_per_ring: fleetMaxFailedRuns,
          actor: "fleet.operator",
          reason: fleetPlanReason.trim(),
        }),
      });
      setFleetPlanReason("");
      setSelectedFleetId(created.id);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create fleet plan");
    } finally {
      setBusy(null);
    }
  }

  async function actOnFleet(action: "apply-next" | "rollback-next") {
    if (!selectedFleet || fleetActionReason.trim().length < 3) return;
    setBusy(action);
    setError(null);
    try {
      await apiFetch<FleetRollout>(`/collector-fleet-rollouts/${selectedFleet.id}/${action}`, {
        method: "POST",
        body: JSON.stringify({
          actor: "fleet.operator",
          reason: fleetActionReason.trim(),
          plan_sha256: selectedFleet.plan_sha256,
        }),
      });
      setFleetActionReason("");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Unable to ${action} fleet rollout`);
    } finally {
      setBusy(null);
    }
  }

  async function actOnAutomation(action: "pause" | "resume" | "abort") {
    if (!selectedFleet || fleetActionReason.trim().length < 3) return;
    setBusy(`automation-${action}`);
    setError(null);
    try {
      await apiFetch<FleetRollout>(`/collector-fleet-rollouts/${selectedFleet.id}/automation/${action}`, {
        method: "POST",
        body: JSON.stringify({
          actor: "fleet.operator",
          reason: fleetActionReason.trim(),
          plan_sha256: selectedFleet.plan_sha256,
        }),
      });
      setFleetActionReason("");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Unable to ${action} rollout automation`);
    } finally {
      setBusy(null);
    }
  }

  const candidateVersion = selectedRollout
    ? artifacts.flatMap((artifact) => artifact.versions).find((version) => version.id === selectedRollout.candidate_version_id)
    : null;
  const hasActiveFleet = relatedFleetRollouts.some((item) => ["planned", "running", "rolling_back"].includes(item.status));
  const canApplyFleet = Boolean(
    selectedFleet
    && (selectedFleet.status === "planned" || selectedFleet.status === "running")
    && (selectedFleet.progression_mode === "manual" || ["aborted", "failed"].includes(selectedFleet.automation_state)),
  );
  const canRollbackFleet = Boolean(
    selectedFleet
    && selectedFleet.migrated_count > 0
    && ["running", "completed", "failed", "rolling_back"].includes(selectedFleet.status),
  );
  const canPauseAutomation = Boolean(selectedFleet?.progression_mode === "automatic" && ["armed", "observing"].includes(selectedFleet.automation_state));
  const canResumeAutomation = selectedFleet?.progression_mode === "automatic" && selectedFleet.automation_state === "paused";
  const canAbortAutomation = Boolean(selectedFleet?.progression_mode === "automatic" && ["armed", "observing", "paused"].includes(selectedFleet.automation_state));

  return (
    <main className="flex h-screen min-h-[720px] flex-col overflow-hidden bg-[#eef0f5] text-[#253044]">
      <header className="flex h-16 shrink-0 items-center justify-between border-b border-[#d8dbe0] bg-white px-5">
        <div className="flex items-center gap-3">
          <Link href="/studio/artifacts" className="rounded-md p-2 text-[#59677b] transition hover:bg-[#eef0f5]" aria-label="Back to Artifact Library"><ArrowLeft className="h-4 w-4" /></Link>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#303c54] text-white"><Gauge className="h-4 w-4" /></div>
          <div><h1 className="text-sm font-semibold">Collector Rollout Studio</h1><p className="text-xs text-muted-foreground">Validated candidate → shadow canary → health gate → human promotion</p></div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-2" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh</Button>
          <Button size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => setShowCreate((current) => !current)}><Plus className="h-3.5 w-3.5" /> New canary</Button>
        </div>
      </header>

      {error && <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700"><XCircle className="h-4 w-4" /> {error}</div>}

      <div className="grid min-h-0 flex-1 grid-cols-[310px_430px_minmax(400px,1fr)]">
        <aside className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-[#f8f9fb] p-4">
          <div className="mb-3 flex items-center justify-between"><span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Rollouts</span><Badge variant="outline" className="text-[9px]">{rollouts.length}</Badge></div>
          <div className="space-y-2">
            {rollouts.map((rollout) => (
              <button key={rollout.id} onClick={() => { setSelectedRolloutId(rollout.id); setShowCreate(false); }} className={cn("w-full rounded-lg border p-3 text-left transition", selectedRolloutId === rollout.id ? "border-[#5856d6] bg-white shadow-sm" : "border-transparent hover:border-[#d8dbe0] hover:bg-white")}>
                <div className="flex items-center justify-between gap-2"><span className="truncate text-xs font-semibold">{rollout.name}</span><Badge variant="outline" className={cn("text-[9px]", statusClass(rollout.status))}>{rollout.status}</Badge></div>
                <div className="mt-2 text-[10px] text-muted-foreground">{rollout.qualifying_runs}/{rollout.min_successful_runs} healthy · {rollout.failed_runs}/{rollout.max_failed_runs} failed</div>
              </button>
            ))}
            {!loading && rollouts.length === 0 && <div className="rounded-lg border border-dashed border-[#c8cdd5] p-6 text-center text-[11px] leading-5 text-muted-foreground">No Collector canary rollouts yet.</div>}
          </div>
        </aside>

        <section className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-white p-5">
          {showCreate ? (
            <form onSubmit={(event) => void createRollout(event)}>
              <div className="flex items-center gap-2 text-sm font-semibold"><Gauge className="h-4 w-4 text-[#5856d6]" /> Start bounded shadow canary</div>
              <p className="mt-1 text-[11px] leading-5 text-muted-foreground">Only validated polling Collectors are eligible. Shadow envelopes are schema-checked and hash-addressed, never written into the production evidence stream.</p>
              <label className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Rollout name<Input value={name} onChange={(event) => setName(event.target.value)} required className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Collector Artifact<select value={artifactId} onChange={(event) => setArtifactId(event.target.value)} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]">{artifacts.map((artifact) => <option key={artifact.id} value={artifact.id}>{artifact.name}</option>)}</select></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Validated candidate<select value={versionId} onChange={(event) => setVersionId(event.target.value)} required className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]">{validatedVersions.map((version) => <option key={version.id} value={version.id}>Version {version.version} · {shortHash(version.content_hash)}</option>)}</select></label>
              <div className="mt-4 rounded-lg border border-[#dfe2e7] bg-[#f8f9fb] p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Target ownership</p>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <Button type="button" size="sm" variant={targetScope === "registered_device" ? "default" : "outline"} onClick={() => setTargetScope("registered_device")}>Registered Device</Button>
                  <Button type="button" size="sm" variant={targetScope === "external_source" ? "default" : "outline"} onClick={() => setTargetScope("external_source")}>External source</Button>
                </div>
                {targetScope === "registered_device" ? (
                  <div className="mt-3 space-y-2">
                    <label className="block text-[10px] font-semibold text-[#59677b]">Search Devices by name or IP
                      <Input value={deviceSearch} onChange={(event) => setDeviceSearch(event.target.value)} placeholder="Search inventory" className="mt-1 h-9 text-xs font-normal" />
                    </label>
                    <label className="block text-[10px] font-semibold text-[#59677b]">Bind to Device
                      <select value={selectedDevice?.id || ""} onChange={(event) => {
                        const device = deviceOptions.find((item) => item.id === event.target.value) || null;
                        setSelectedDevice(device);
                        if (device?.site) {
                          try {
                            const selector = JSON.parse(workerSelector) as Record<string, string>;
                            setWorkerSelector(JSON.stringify({ ...selector, site: device.site }, null, 2));
                          } catch { /* Let the JSON editor show its own parse error on submit. */ }
                        }
                      }} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs font-normal text-[#253044]">
                        <option value="">Choose a Device…</option>
                        {selectedDevice && !deviceOptions.some((item) => item.id === selectedDevice.id) ? <option value={selectedDevice.id}>{selectedDevice.name} · {selectedDevice.site || "No site"}</option> : null}
                        {deviceOptions.map((device) => <option key={device.id} value={device.id} disabled={!device.enabled || !device.site}>{device.name} · {device.management_ip || "No IP"} · {device.site || "No site"}</option>)}
                      </select>
                    </label>
                    {deviceSearchError ? <p className="text-[11px] text-red-700">{deviceSearchError}</p> : null}
                    {selectedDevice ? <p className="text-[11px] leading-4 text-[#59677b]">Bound to {selectedDevice.name} at {selectedDevice.management_ip || "unaddressed"}, site {selectedDevice.site || "unset"}, identity #{selectedDevice.identity_revision}. Set the target host to this IP or Device name; use External source for another API host. Address or site correction requires a new canary.</p> : <p className="text-[11px] text-muted-foreground">Search returns the first 25 matches; narrow the query to find a Device.</p>}
                  </div>
                ) : (
                  <label className="mt-3 block text-[10px] font-semibold text-[#59677b]">Why is this outside registered Device inventory?
                    <Textarea value={externalSourceReason} onChange={(event) => setExternalSourceReason(event.target.value)} minLength={10} maxLength={1000} rows={3} placeholder="For example, this is an organization IPAM API, not a monitored device endpoint." className="mt-1 text-xs font-normal" />
                  </label>
                )}
              </div>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Target JSON<Textarea value={target} onChange={(event) => setTarget(event.target.value)} rows={5} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <p className="mt-1 text-[11px] text-muted-foreground">Keep Device ID outside Target JSON. Generated registered-device targets must identify the selected Device by management IP or name; unrelated URLs require External source review.</p>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Configuration JSON<Textarea value={configuration} onChange={(event) => setConfiguration(event.target.value)} rows={3} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Worker selector JSON<Textarea value={workerSelector} onChange={(event) => setWorkerSelector(event.target.value)} rows={3} className="mt-1 font-mono text-[10px] normal-case tracking-normal text-[#253044]" /></label>
              <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Credential profile reference<Input value={credentialRef} onChange={(event) => setCredentialRef(event.target.value)} placeholder="Optional external secret reference" className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
              <div className="mt-3 grid grid-cols-2 gap-3">
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Interval seconds<Input type="number" min={5} max={3600} value={scheduleSeconds} onChange={(event) => setScheduleSeconds(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Timeout seconds<Input type="number" min={30} max={86400} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Required healthy runs<Input type="number" min={1} max={100} value={minSuccess} onChange={(event) => setMinSuccess(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Failure limit<Input type="number" min={1} max={100} value={maxFailures} onChange={(event) => setMaxFailures(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
                <label className="col-span-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Minimum records per run<Input type="number" min={0} value={minRecords} onChange={(event) => setMinRecords(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal text-[#253044]" /></label>
              </div>
              <div className="mt-4 flex gap-2"><Button type="submit" size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]" disabled={!versionId || busy !== null || (targetScope === "registered_device" ? !selectedDevice : externalSourceReason.trim().length < 10)}>{busy === "create" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Gauge className="h-3.5 w-3.5" />} Start canary</Button><Button type="button" variant="outline" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button></div>
            </form>
          ) : selectedRollout ? (
            <>
              <div className="flex items-start justify-between gap-3"><div><h2 className="text-base font-semibold">{selectedRollout.name}</h2><p className="mt-1 text-xs text-muted-foreground">Candidate version {candidateVersion?.version ?? "?"}</p></div><Badge variant="outline" className={statusClass(selectedRollout.status)}>{selectedRollout.status}</Badge></div>
              <div className="mt-5 grid grid-cols-2 gap-3">
                {[['Healthy gates', `${selectedRollout.qualifying_runs}/${selectedRollout.min_successful_runs}`], ['Failure gates', `${selectedRollout.failed_runs}/${selectedRollout.max_failed_runs}`], ['Successful runs', selectedRollout.successful_runs], ['Shadow records', selectedRollout.records_received], ['Evidence batches', selectedRollout.evidence_batches], ['Last gate', selectedRollout.last_gate_result || 'waiting']].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-[#dfe2e7] bg-[#f8f9fb] p-3"><div className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</div><div className="mt-1 text-sm font-semibold">{value}</div></div>)}
              </div>
              <div className="mt-4 rounded-lg border border-[#dfe2e7] bg-[#f8f9fb] p-4 text-[11px] leading-5">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Reviewed target ownership</div>
                {selectedRollout.target_ownership_sha256 ? (
                  <>
                    <div className="mt-1 font-semibold text-[#253044]">{selectedRollout.target_classification === "registered_device" ? "Registered Device" : selectedRollout.target_classification === "external_source" ? "External API source" : "Unclassified manual target"}</div>
                    {selectedRollout.scope_device_id ? <div className="mt-1 break-all text-[#59677b]">Device {selectedRollout.scope_device_id} · identity #{selectedRollout.scope_device_identity_revision ?? "?"} · site {selectedRollout.scope_site || "unset"}</div> : null}
                    {selectedRollout.external_source_reason ? <div className="mt-1 text-[#59677b]">Reason: {selectedRollout.external_source_reason}</div> : null}
                    <div className="mt-1 text-muted-foreground">Review digest <code>{shortHash(selectedRollout.target_ownership_sha256)}</code></div>
                  </>
                ) : <div className="mt-1 text-amber-700">Legacy canary: start-time ownership was not recorded. Start a new reviewed canary before publication.</div>}
              </div>
              <div className="mt-4 rounded-lg border border-[#dfe2e7] p-4 text-[10px]"><div className="text-muted-foreground">Last shadow digest</div><code className="mt-1 block break-all">{shortHash(selectedRollout.last_evidence_sha256)}</code><div className="mt-3 text-muted-foreground">Deadline</div><div className="mt-1">{new Date(selectedRollout.deadline_at).toLocaleString()}</div></div>
              {(selectedRollout.abort_reason || selectedRollout.promotion_reason) && <div className={cn("mt-4 rounded-lg border p-3 text-xs leading-5", selectedRollout.status === "aborted" ? "border-red-200 bg-red-50 text-red-700" : "border-violet-200 bg-violet-50 text-violet-700")}>{selectedRollout.abort_reason || selectedRollout.promotion_reason}</div>}
            </>
          ) : <div className="flex h-full items-center justify-center text-xs text-muted-foreground">Select a rollout or start a validated candidate.</div>}
        </section>

        <section className="min-h-0 overflow-y-auto bg-[#f8f9fb] p-5">
          <h2 className="text-sm font-semibold">Human publication gate</h2>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">Passing health checks stops the shadow deployment. Publication and fleet replacement remain separate, explicit decisions.</p>
          {selectedRollout ? (
            <div className="mt-5 rounded-xl border border-[#dfe2e7] bg-white p-5">
              <div className="flex items-start gap-3">
                {selectedRollout.status === "passed" || selectedRollout.status === "promoted" ? <CheckCircle2 className="mt-0.5 h-5 w-5 text-emerald-600" /> : <ShieldAlert className="mt-0.5 h-5 w-5 text-amber-600" />}
                <div>
                  <div className="text-xs font-semibold">{selectedRollout.status === "passed" ? selectedRollout.target_ownership_sha256 ? "Ready for publication" : "Fresh ownership review required" : selectedRollout.status === "running" ? "Canary still collecting evidence" : selectedRollout.status === "promoted" ? "Candidate published" : "Canary was stopped"}</div>
                  <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Promotion publishes the immutable Artifact version. Existing deployments change only through a hash-bound fleet plan below.</p>
                </div>
              </div>
              {selectedRollout.status === "running" || selectedRollout.status === "passed" ? (
                <>
                  <Textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={4} placeholder={selectedRollout.status === "passed" ? "Why is this candidate safe to publish?" : "Why should this rollout be aborted?"} className="mt-5 text-xs" />
                  <div className="mt-3 flex gap-2">
                    {selectedRollout.status === "running" && <Button variant="outline" size="sm" className="gap-2 border-red-200 text-red-700 hover:bg-red-50" onClick={() => void act("abort")} disabled={reason.trim().length < 3 || busy !== null}>{busy === "abort" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />} Abort</Button>}
                    {selectedRollout.status === "passed" && <Button size="sm" className="gap-2 bg-emerald-600 hover:bg-emerald-700" onClick={() => void act("promote")} disabled={!selectedRollout.target_ownership_sha256 || reason.trim().length < 3 || busy !== null}>{busy === "promote" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Rocket className="h-3.5 w-3.5" />} Publish candidate</Button>}
                  </div>
                </>
              ) : null}
            </div>
          ) : <div className="mt-8 rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs text-muted-foreground">No rollout selected.</div>}

          {selectedRollout?.status === "promoted" && (
            <>
              <div className="mt-7 flex items-center gap-2"><Network className="h-4 w-4 text-[#5856d6]" /><h2 className="text-sm font-semibold">Governed fleet replacement</h2></div>
              <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Preview the exact deployment set, then choose manual batches or opt-in automatic rings. Automatic progression requires post-migration Collector runs to pass every observation gate; failures pause closed.</p>

              <form onSubmit={(event) => void createFleetPlan(event)} className="mt-4 rounded-xl border border-[#dfe2e7] bg-white p-4">
                <div className="flex items-center justify-between gap-3"><span className="text-xs font-semibold">Create immutable impact plan</span>{hasActiveFleet && <Badge variant="outline" className="border-amber-300 bg-amber-50 text-[9px] text-amber-700">active plan exists</Badge>}</div>
                <div className="mt-3 grid grid-cols-3 gap-2">
                  <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Site scope<Input value={fleetScope} onChange={(event) => setFleetScope(event.target.value)} placeholder="All sites" className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                  <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Batch size<Input type="number" min={1} max={500} value={fleetBatchSize} onChange={(event) => setFleetBatchSize(Number(event.target.value))} className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                  <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Stop failures<Input type="number" min={1} max={500} value={fleetMaxFailures} onChange={(event) => setFleetMaxFailures(Number(event.target.value))} className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                </div>
                <label className="mt-3 flex items-center gap-2 text-[10px] text-[#59677b]"><input type="checkbox" checked={fleetIncludeDisabled} onChange={(event) => setFleetIncludeDisabled(event.target.checked)} /> Include disabled deployments</label>
                <label className="mt-2 flex items-center gap-2 text-[10px] text-[#59677b]"><input type="checkbox" checked={fleetAutomatic} onChange={(event) => setFleetAutomatic(event.target.checked)} /> Automatic health-gated rings</label>
                {fleetAutomatic && (
                  <div className="mt-3 rounded-lg border border-violet-100 bg-violet-50/50 p-3">
                    <div className="grid grid-cols-2 gap-2">
                      <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Cumulative ring %<Input value={fleetRingPercentages} onChange={(event) => setFleetRingPercentages(event.target.value)} placeholder="5,25,50,100" className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                      <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Observation seconds<Input type="number" min={30} max={86400} value={fleetObservationSeconds} onChange={(event) => setFleetObservationSeconds(Number(event.target.value))} className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                      <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Healthy runs / deployment<Input type="number" min={1} max={20} value={fleetMinHealthyRuns} onChange={(event) => setFleetMinHealthyRuns(Number(event.target.value))} className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                      <label className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground">Failed runs / ring<Input type="number" min={0} max={500} value={fleetMaxFailedRuns} onChange={(event) => setFleetMaxFailedRuns(Number(event.target.value))} className="mt-1 h-8 text-[10px] normal-case tracking-normal text-[#253044]" /></label>
                    </div>
                    <p className="mt-2 text-[9px] leading-4 text-[#6765a7]">The regional rollout controller is the only writer while armed. Pause or abort automation before taking manual batch control.</p>
                  </div>
                )}
                <Textarea value={fleetPlanReason} onChange={(event) => setFleetPlanReason(event.target.value)} rows={3} placeholder="Why should this scope be replaced?" className="mt-3 text-xs" />
                <Button type="submit" size="sm" className="mt-3 gap-2 bg-[#5856d6] hover:bg-[#4947ad]" disabled={hasActiveFleet || fleetPlanReason.trim().length < 3 || busy !== null}>{busy === "fleet-plan" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Network className="h-3.5 w-3.5" />} Build impact plan</Button>
              </form>

              {relatedFleetRollouts.length > 0 && (
                <div className="mt-4 rounded-xl border border-[#dfe2e7] bg-white p-4">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-semibold">Fleet plan evidence</span>
                    <select aria-label="Rollout target fleet" value={selectedFleetId || ""} onChange={(event) => setSelectedFleetId(event.target.value)} className="h-8 max-w-[230px] rounded-md border border-[#c9ced7] bg-white px-2 text-[10px]">
                      {relatedFleetRollouts.map((item) => <option key={item.id} value={item.id}>{item.scope_site || "all sites"} · {item.status} · {new Date(item.created_at).toLocaleString()}</option>)}
                    </select>
                  </div>
                  {selectedFleet && (
                    <>
                      <div className="mt-3 flex items-center justify-between"><code className="text-[9px] text-[#59677b]">{shortHash(selectedFleet.plan_sha256)}</code><div className="flex gap-1"><Badge variant="outline" className={cn("text-[9px]", fleetStatusClass(selectedFleet.status))}>{selectedFleet.status}</Badge>{selectedFleet.progression_mode === "automatic" && <Badge variant="outline" className={cn("text-[9px]", fleetStatusClass(selectedFleet.automation_state))}>auto · {selectedFleet.automation_state}</Badge>}</div></div>
                      <div className="mt-3 grid grid-cols-4 gap-2">
                        {[["planned", selectedFleet.planned_count], ["pending", selectedFleet.pending_count], ["blocked", selectedFleet.blocked_count], ["deferred", selectedFleet.deferred_count], ["migrated", selectedFleet.migrated_count], ["failed", selectedFleet.failed_count], ["restored", selectedFleet.rolled_back_count], ["rollback failed", selectedFleet.rollback_failed_count]].map(([label, value]) => <div key={String(label)} className="rounded-md border border-[#e1e4e9] bg-[#f8f9fb] p-2"><div className="text-[8px] uppercase tracking-wide text-muted-foreground">{label}</div><div className="mt-1 text-xs font-semibold">{value}</div></div>)}
                      </div>
                      {selectedFleet.progression_mode === "automatic" && (
                        <div className="mt-3 space-y-2 rounded-lg border border-violet-100 bg-violet-50/40 p-3">
                          <div className="flex items-center justify-between"><span className="text-[9px] font-semibold uppercase tracking-wide text-[#6765a7]">Health-gated rings</span><span className="text-[9px] text-muted-foreground">{selectedFleet.observation_seconds}s · {selectedFleet.min_successful_runs_per_deployment} healthy / deployment · {selectedFleet.max_failed_runs_per_ring} failed allowed</span></div>
                          {fleetRings.map((ring) => (
                            <div key={ring.id} className="rounded-md border border-violet-100 bg-white p-2">
                              <div className="flex items-center justify-between gap-2"><span className="text-[10px] font-semibold">Ring {ring.ring_index + 1} · {ring.target_percent}% cumulative</span><Badge variant="outline" className={cn("text-[8px]", fleetStatusClass(ring.status))}>{ring.status}</Badge></div>
                              <div className="mt-1 text-[8px] text-muted-foreground">cohort {ring.cohort_count} · target {ring.target_count} · healthy {ring.healthy_deployments}/{ring.cohort_count} · runs {ring.successful_runs} ok / {ring.failed_runs} failed</div>
                              <div className="mt-1 flex items-center justify-between gap-2 text-[8px] text-muted-foreground"><span>{ring.last_gate_result || "not started"}</span><code>{shortHash(ring.evidence_sha256)}</code></div>
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="mt-3 max-h-52 space-y-1 overflow-y-auto rounded-lg border border-[#e1e4e9] p-2">
                        {fleetItems.slice(0, 200).map((item) => <div key={item.id} className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-[#f8f9fb]"><div className="min-w-0"><div className="truncate text-[10px] font-medium">{item.deployment_name}{item.ring_index !== null ? ` · ring ${item.ring_index + 1}` : ""}</div><div className="truncate text-[8px] text-muted-foreground">{item.block_reason_code || item.last_error_code || `${shortHash(item.pre_change_sha256)} → ${shortHash(item.post_change_sha256)}`}</div></div><Badge variant="outline" className={cn("shrink-0 text-[8px]", fleetStatusClass(item.status))}>{item.status}</Badge></div>)}
                        {fleetItems.length === 0 && <div className="p-3 text-center text-[10px] text-muted-foreground">Loading impact evidence…</div>}
                        {fleetItems.length > 200 && <div className="p-2 text-center text-[9px] text-muted-foreground">Showing 200 of {fleetItems.length} items.</div>}
                      </div>
                      {(canApplyFleet || canRollbackFleet || canPauseAutomation || canResumeAutomation || canAbortAutomation) && <Textarea value={fleetActionReason} onChange={(event) => setFleetActionReason(event.target.value)} rows={3} placeholder="Record the reason for this governed action." className="mt-3 text-xs" />}
                      <div className="mt-3 flex flex-wrap gap-2">
                        {canApplyFleet && <Button size="sm" className="gap-2 bg-emerald-600 hover:bg-emerald-700" onClick={() => void actOnFleet("apply-next")} disabled={fleetActionReason.trim().length < 3 || busy !== null}>{busy === "apply-next" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Apply next {selectedFleet.batch_size}</Button>}
                        {canPauseAutomation && <Button variant="outline" size="sm" className="gap-2 border-amber-200 text-amber-700 hover:bg-amber-50" onClick={() => void actOnAutomation("pause")} disabled={fleetActionReason.trim().length < 3 || busy !== null}>{busy === "automation-pause" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Pause className="h-3.5 w-3.5" />} Pause automation</Button>}
                        {canResumeAutomation && <Button size="sm" className="gap-2 bg-emerald-600 hover:bg-emerald-700" onClick={() => void actOnAutomation("resume")} disabled={fleetActionReason.trim().length < 3 || busy !== null}>{busy === "automation-resume" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Resume with fresh window</Button>}
                        {canAbortAutomation && <Button variant="outline" size="sm" className="gap-2 border-red-200 text-red-700 hover:bg-red-50" onClick={() => void actOnAutomation("abort")} disabled={fleetActionReason.trim().length < 3 || busy !== null}>{busy === "automation-abort" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />} Abort automation</Button>}
                        {canRollbackFleet && <Button variant="outline" size="sm" className="gap-2 border-violet-200 text-violet-700 hover:bg-violet-50" onClick={() => void actOnFleet("rollback-next")} disabled={fleetActionReason.trim().length < 3 || busy !== null}>{busy === "rollback-next" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />} Roll back next {selectedFleet.batch_size}</Button>}
                      </div>
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </main>
  );
}
