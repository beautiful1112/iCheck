"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, CheckCircle2, FileCode2, Pencil, Plus, RefreshCw, ShieldCheck, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { APIError, apiFetch } from "@/lib/icheck-api";

type Protocol = "snmp" | "https_api" | "ssh" | "windows_exporter" | "winrm_https" | "icmp";
type Collector = {
  artifact_version_id: string;
  artifact_name: string;
  version: number;
  adapter_type: string;
  target_schema: Record<string, unknown>;
  config_schema: Record<string, unknown>;
  defaults: Record<string, unknown>;
};
type CollectorSummary = Pick<Collector, "artifact_version_id" | "artifact_name" | "version" | "adapter_type">;
type Page<T> = { items: T[]; next_cursor: string | null };
type Policy = {
  id: string;
  name: string;
  version: number;
  revision: number;
  status: "draft" | "validated" | "published" | "deprecated";
  protocol: Protocol;
  adapter_type: string;
  artifact_version_id: string;
  execution_mode: "scheduled" | "on_demand";
  schedule_seconds: number;
  target_template: Record<string, unknown>;
  configuration_defaults: Record<string, unknown>;
  worker_selector: Record<string, unknown>;
};
type DeviceContext = {
  id: string;
  name: string;
  kind: string;
  site: string | null;
  connections: Array<{ protocol: Protocol; verification_status: string }>;
};
type PolicyProposal = {
  proposal_id: string;
  parent_id: string | null;
  draft: {
    name: string;
    protocol: Protocol;
    artifact_version_id: string;
    target_template: Record<string, unknown>;
    configuration_defaults: Record<string, unknown>;
    worker_selector: Record<string, unknown>;
    execution_mode: "scheduled" | "on_demand";
    schedule_seconds: number;
  };
  rationale: string;
  warnings: string[];
  model_id: string;
  tokens_used: number;
  external_charge_unknown: boolean | null;
};
type ProposalRecord = {
  id: string;
  parent_id: string | null;
  device_id: string | null;
  artifact_version_id: string;
  protocol: Protocol;
  brief: string;
  status: "generating" | "succeeded" | "failed";
  result: PolicyProposal | null;
  failure_code: string | null;
  tokens_used: number;
  external_charge_unknown: boolean | null;
  created_at: string;
  recovery_available_at: string;
};
type ScopeDetails = {
  evaluated_at: string;
  advisory_only: boolean;
  device_id: string | null;
  connection_id: string | null;
  protocol: Protocol;
  adapter_type: string | null;
  rendered_target: Record<string, unknown> | null;
  policy_worker_selector: Record<string, string> | null;
  connection_worker_selector: Record<string, string> | null;
  effective_worker_selector: Record<string, string> | null;
  credential_profile_ref: string | null;
  credential_source: string;
  credential_profile_enabled: boolean | null;
  credential_adapter_allowed: boolean | null;
  credential_worker_selector: Record<string, string> | null;
  registered_worker_matches_in_scan: number | null;
  fresh_worker_matches_in_scan: number | null;
  worker_scan_truncated: boolean;
  blockers: string[];
  warnings: string[];
};
type ScopePreview = ScopeDetails & { proposal_id: string; proposal_sha256: string };
type DraftScopePreview = ScopeDetails & { draft_sha256: string };
type AuthoringQuota = {
  actor: string;
  actor_limit: number | null;
  actor_used: number;
  actor_available: number | null;
  namespace_limit: number | null;
  namespace_available: number | null;
  unknown_charge_requests: number;
};

const compatibleAdapters: Record<Protocol, readonly string[]> = {
  snmp: ["snmp_exporter", "snmp_topology"],
  https_api: ["http_json", "http_json_sandbox"],
  ssh: ["ssh", "ssh_command_sandbox"],
  windows_exporter: ["windows_exporter"],
  winrm_https: ["psrp_cim"],
  icmp: ["icmp"],
};
const protocolLabels: Record<Protocol, string> = {
  snmp: "SNMP", https_api: "HTTPS API", ssh: "SSH",
  windows_exporter: "Windows exporter", winrm_https: "WinRM HTTPS", icmp: "ICMP",
};

function jsonObject(source: string, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function ScopeEvaluation({ scope, digest }: { scope: ScopeDetails; digest: string }) {
  return <div className="space-y-2 border-t border-[#e4e6e9] pt-3">
    <p className="font-mono text-[10px] text-muted-foreground">Read-only · evaluated {new Date(scope.evaluated_at).toLocaleString()} · {digest}</p>
    <p>Device: {scope.device_id || "none selected"} · Connection: {scope.connection_id || "none"} · Adapter: {scope.adapter_type || "unavailable"}</p>
    <p>Rendered target:</p><pre className="overflow-auto rounded bg-[#f8f9fa] p-2 font-mono text-[11px] whitespace-pre-wrap">{scope.rendered_target ? JSON.stringify(scope.rendered_target, null, 2) : "Unavailable"}</pre>
    <p>Worker labels: policy {JSON.stringify(scope.policy_worker_selector || {})} + connection {JSON.stringify(scope.connection_worker_selector || {})} → effective {JSON.stringify(scope.effective_worker_selector || {})}</p>
    <p>Credential: {scope.credential_profile_ref || "none"} ({scope.credential_source}) · {scope.credential_profile_enabled === null ? "profile not resolved" : scope.credential_profile_enabled ? "enabled" : "disabled"} · {scope.credential_adapter_allowed === null ? "adapter permission unknown" : scope.credential_adapter_allowed ? "adapter allowed" : "adapter denied"}</p>
    {scope.credential_worker_selector ? <p>Credential-required Worker labels: {JSON.stringify(scope.credential_worker_selector)}</p> : null}
    {scope.registered_worker_matches_in_scan !== null ? <p>Registered Workers matching adapter and labels: {scope.registered_worker_matches_in_scan}; fresh heartbeat: {scope.fresh_worker_matches_in_scan}{scope.worker_scan_truncated ? " (partial 1,000-Worker scan)" : ""}. This is not a run guarantee.</p> : null}
    {scope.blockers.length ? <div className="rounded border border-red-200 bg-red-50 p-2 text-red-800"><p className="font-semibold">Current blockers</p>{scope.blockers.map((blocker, index) => <p key={`${index}-${blocker}`}>{blocker}</p>)}</div> : <p className="text-emerald-700">No blocker found in this advisory check. Formal validation and approval still apply.</p>}
    {scope.warnings.map((warning, index) => <p key={`${index}-${warning}`} className="text-[#8b6300]">{warning}</p>)}
  </div>;
}

export default function ActivationPoliciesPage() {
  const [collectors, setCollectors] = useState<CollectorSummary[]>([]);
  const [selectedCollector, setSelectedCollector] = useState<Collector | null>(null);
  const [collectorCursor, setCollectorCursor] = useState<string | null>(null);
  const [policyCursor, setPolicyCursor] = useState<string | null>(null);
  const [collectorSearch, setCollectorSearch] = useState("");
  const [collectorPrefix, setCollectorPrefix] = useState("");
  const [policySearch, setPolicySearch] = useState("");
  const [policyPrefix, setPolicyPrefix] = useState("");
  const [catalogRevision, setCatalogRevision] = useState(0);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [protocol, setProtocol] = useState<Protocol>("https_api");
  const [artifactVersionId, setArtifactVersionId] = useState("");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("{}");
  const [configuration, setConfiguration] = useState("{}");
  const [workerSelector, setWorkerSelector] = useState('{"site":"${site}"}');
  const [executionMode, setExecutionMode] = useState<"scheduled" | "on_demand">("scheduled");
  const [scheduleSeconds, setScheduleSeconds] = useState(300);
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);
  const [deviceId, setDeviceId] = useState("");
  const [deviceContext, setDeviceContext] = useState<DeviceContext | null>(null);
  const [aiBrief, setAiBrief] = useState("");
  const [proposal, setProposal] = useState<PolicyProposal | null>(null);
  const [scopePreview, setScopePreview] = useState<ScopePreview | null>(null);
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [draftScopePreview, setDraftScopePreview] = useState<{ inputKey: string; result: DraftScopePreview } | null>(null);
  const [draftScopeLoading, setDraftScopeLoading] = useState(false);
  const [draftScopeError, setDraftScopeError] = useState<{ inputKey: string; message: string } | null>(null);
  const [proposalHistory, setProposalHistory] = useState<ProposalRecord[]>([]);
  const [authoringQuota, setAuthoringQuota] = useState<AuthoringQuota | null>(null);
  const [recoveryReasons, setRecoveryReasons] = useState<Record<string, string>>({});
  const [clock, setClock] = useState<number | null>(null);
  const pendingRequest = useRef<{ key: string; input: string } | null>(null);
  const historyRequestSequence = useRef(0);
  const catalogRequestSequence = useRef(0);
  const scopeRequestSequence = useRef(0);
  const draftScopeRequestSequence = useRef(0);
  const proposalRequestSequence = useRef(0);
  const draftInputKey = JSON.stringify({
    name, protocol, artifactVersionId, target, configuration,
    workerSelector, executionMode, scheduleSeconds, deviceId,
  });

  const loadProposalHistory = useCallback(async () => {
    const sequence = ++historyRequestSequence.current;
    const query = new URLSearchParams({ actor: "assets.operator", limit: "30" });
    if (deviceId) query.set("device_id", deviceId);
    const rows = await apiFetch<ProposalRecord[]>(`/assets/activation-policy-proposals?${query}`);
    if (sequence === historyRequestSequence.current) setProposalHistory(rows);
  }, [deviceId]);

  const loadAuthoringQuota = useCallback(async () => {
    try {
      setAuthoringQuota(await apiFetch<AuthoringQuota>(
        "/ai/authoring-quota?actor=assets.operator",
      ));
    } catch {
      setAuthoringQuota(null);
    }
  }, []);

  const load = useCallback(async () => {
    const sequence = ++catalogRequestSequence.current;
    setLoading(true);
    try {
      const collectorParams = new URLSearchParams({ protocol, limit: "50" });
      if (collectorPrefix) collectorParams.set("name_prefix", collectorPrefix);
      const policyParams = new URLSearchParams({ limit: "50" });
      if (policyPrefix) policyParams.set("name_prefix", policyPrefix);
      const [collectorData, policyData] = await Promise.all([
        apiFetch<Page<CollectorSummary>>(`/assets/activation-collectors/page?${collectorParams}`),
        apiFetch<Page<Policy>>(`/assets/activation-policies/page?${policyParams}`),
      ]);
      if (sequence !== catalogRequestSequence.current) return;
      setCollectors(collectorData.items);
      setCollectorCursor(collectorData.next_cursor);
      setPolicies(policyData.items);
      setPolicyCursor(policyData.next_cursor);
      setMessage((current) => current?.error ? null : current);
    } catch (error) {
      if (sequence === catalogRequestSequence.current) setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load activation contracts." });
    } finally {
      if (sequence === catalogRequestSequence.current) setLoading(false);
    }
  }, [protocol, collectorPrefix, policyPrefix]);

  useEffect(() => {
    const requestSequence = catalogRequestSequence;
    const timer = window.setTimeout(() => void load(), 0);
    const onNamespaceChange = () => {
      ++scopeRequestSequence.current;
      ++draftScopeRequestSequence.current;
      ++proposalRequestSequence.current;
      ++historyRequestSequence.current;
      pendingRequest.current = null;
      setBusy(null);
      setSelectedCollector(null);
      setEditingPolicy(null);
      setArtifactVersionId("");
      setDeviceId("");
      setDeviceContext(null);
      setProposal(null);
      setProposalHistory([]);
      setScopePreview(null);
      setScopeError(null);
      setScopeLoading(false);
      setDraftScopePreview(null);
      setDraftScopeError(null);
      setDraftScopeLoading(false);
      setCatalogRevision((value) => value + 1);
      void load();
    };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      ++requestSequence.current;
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [load]);

  useEffect(() => {
    if (!artifactVersionId) {
      const timer = window.setTimeout(() => setSelectedCollector(null), 0);
      return () => window.clearTimeout(timer);
    }
    let active = true;
    void apiFetch<Collector>(`/assets/activation-collectors/${encodeURIComponent(artifactVersionId)}`)
      .then((collector) => {
        if (!active) return;
        if (!compatibleAdapters[protocol].includes(collector.adapter_type)) {
          const params = new URLSearchParams(window.location.search);
          const linkedProtocol = Object.entries(compatibleAdapters).find(([, adapters]) => adapters.includes(collector.adapter_type))?.[0] as Protocol | undefined;
          if (params.get("artifact_version_id") === artifactVersionId && !params.get("protocol") && linkedProtocol) {
            setSelectedCollector(collector);
            setProtocol(linkedProtocol);
          } else {
            setSelectedCollector(null);
            setMessage({ error: true, text: "The selected collector is not compatible with this protocol." });
          }
        } else {
          setSelectedCollector(collector);
        }
      })
      .catch((error) => {
        if (active) {
          setSelectedCollector(null);
          setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load selected collector contract." });
        }
      });
    return () => { active = false; };
  }, [artifactVersionId, protocol, catalogRevision]);

  async function loadMore(kind: "collectors" | "policies") {
    const cursor = kind === "collectors" ? collectorCursor : policyCursor;
    if (!cursor || loading || busy !== null) return;
    const sequence = catalogRequestSequence.current;
    setBusy(`load-${kind}`);
    try {
      const params = new URLSearchParams({ cursor, limit: "50" });
      if (kind === "collectors") {
        params.set("protocol", protocol);
        if (collectorPrefix) params.set("name_prefix", collectorPrefix);
        const page = await apiFetch<Page<CollectorSummary>>(`/assets/activation-collectors/page?${params}`);
        if (sequence !== catalogRequestSequence.current) return;
        setCollectors((old) => [...old, ...page.items]);
        setCollectorCursor(page.next_cursor);
      } else {
        if (policyPrefix) params.set("name_prefix", policyPrefix);
        const page = await apiFetch<Page<Policy>>(`/assets/activation-policies/page?${params}`);
        if (sequence !== catalogRequestSequence.current) return;
        setPolicies((old) => [...old, ...page.items]);
        setPolicyCursor(page.next_cursor);
      }
    } catch (error) {
      if (sequence === catalogRequestSequence.current) setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load another catalog page." });
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void loadAuthoringQuota(), 0);
    const onNamespaceChange = () => { setAuthoringQuota(null); void loadAuthoringQuota(); };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [loadAuthoringQuota]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams(window.location.search);
      const requestedProtocol = params.get("protocol") as Protocol | null;
      if (requestedProtocol && requestedProtocol in protocolLabels) setProtocol(requestedProtocol);
      setArtifactVersionId(params.get("artifact_version_id") || "");
      setDeviceId(params.get("device_id") || "");
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!deviceId) return;
    let active = true;
    void apiFetch<DeviceContext>(`/assets/devices/${encodeURIComponent(deviceId)}`)
      .then((device) => { if (active) setDeviceContext(device); })
      .catch((error) => {
        if (active) setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load device context." });
      });
    return () => { active = false; };
  }, [deviceId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadProposalHistory().catch((error) => {
        setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load proposal history." });
      });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadProposalHistory]);

  useEffect(() => {
    const initial = window.setTimeout(() => setClock(Date.now()), 0);
    const interval = window.setInterval(() => setClock(Date.now()), 30_000);
    return () => { window.clearTimeout(initial); window.clearInterval(interval); };
  }, []);

  const available = useMemo(
    () => collectors.filter((collector) => compatibleAdapters[protocol].includes(collector.adapter_type)),
    [collectors, protocol],
  );
  const selectedOutsidePage = selectedCollector && !available.some((collector) => collector.artifact_version_id === selectedCollector.artifact_version_id);

  async function askAiToDraft() {
    if (!selectedCollector || aiBrief.trim().length < 10) return;
    const sequence = ++proposalRequestSequence.current;
    const input = JSON.stringify({
      protocol, artifact_version_id: selectedCollector.artifact_version_id,
      brief: aiBrief.trim(), device_id: deviceId || null,
      parent_id: proposal?.proposal_id || null,
    });
    if (!pendingRequest.current || pendingRequest.current.input !== input) {
      pendingRequest.current = { key: crypto.randomUUID(), input };
    }
    setBusy("suggest");
    setMessage(null);
    try {
      const result = await apiFetch<PolicyProposal>("/assets/activation-policy-proposals", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          ...JSON.parse(input), actor: "assets.operator",
          request_key: pendingRequest.current.key,
        }),
      });
      if (sequence !== proposalRequestSequence.current) return;
      pendingRequest.current = null;
      ++scopeRequestSequence.current;
      setProposal(result);
      setEditingPolicy(null);
      setScopePreview(null);
      setScopeError(null);
      setAiBrief("");
      setName(result.draft.name);
      setTarget(JSON.stringify(result.draft.target_template, null, 2));
      setConfiguration(JSON.stringify(result.draft.configuration_defaults, null, 2));
      setWorkerSelector(JSON.stringify(result.draft.worker_selector, null, 2));
      setExecutionMode(result.draft.execution_mode);
      setScheduleSeconds(result.draft.schedule_seconds);
      setMessage({ error: false, text: "AI suggestion loaded for review. No policy was saved or published." });
      void loadProposalHistory().catch(() => {});
    } catch (error) {
      if (sequence !== proposalRequestSequence.current) return;
      if (error instanceof APIError && !(error.status === 409 && error.message.includes("in flight"))) {
        pendingRequest.current = null;
      }
      setMessage({ error: true, text: error instanceof Error ? error.message : "AI could not draft a safe policy." });
    } finally {
      if (sequence === proposalRequestSequence.current) {
        setBusy(null);
        void loadAuthoringQuota();
      }
    }
  }

  function restoreProposal(record: ProposalRecord) {
    const result = record.result;
    if (!result) return;
    pendingRequest.current = null;
    ++scopeRequestSequence.current;
    setProposal(result);
    setEditingPolicy(null);
    setScopePreview(null);
    setScopeError(null);
    setProtocol(record.protocol);
    setArtifactVersionId(record.artifact_version_id);
    setName(result.draft.name);
    setTarget(JSON.stringify(result.draft.target_template, null, 2));
    setConfiguration(JSON.stringify(result.draft.configuration_defaults, null, 2));
    setWorkerSelector(JSON.stringify(result.draft.worker_selector, null, 2));
    setExecutionMode(result.draft.execution_mode);
    setScheduleSeconds(result.draft.schedule_seconds);
    setAiBrief("");
    setMessage({ error: false, text: "Saved suggestion restored for review. No policy was saved or published." });
  }

  async function previewSavedScope() {
    if (!proposal) return;
    const sequence = ++scopeRequestSequence.current;
    setScopeLoading(true);
    setScopePreview(null);
    setScopeError(null);
    try {
      const query = new URLSearchParams({ actor: "assets.operator" });
      if (deviceId) query.set("device_id", deviceId);
      const result = await apiFetch<ScopePreview>(
        `/assets/activation-policy-proposals/${encodeURIComponent(proposal.proposal_id)}/scope-preview?${query}`,
      );
      if (sequence === scopeRequestSequence.current) setScopePreview(result);
    } catch (error) {
      if (sequence === scopeRequestSequence.current) {
        setScopeError(error instanceof Error ? error.message : "Unable to evaluate saved suggestion scope.");
      }
    } finally {
      if (sequence === scopeRequestSequence.current) setScopeLoading(false);
    }
  }

  async function interruptProposal(record: ProposalRecord) {
    const reason = (recoveryReasons[record.id] || "").trim();
    if (reason.length < 10) return;
    setBusy(record.id);
    setMessage(null);
    try {
      await apiFetch<ProposalRecord>(`/assets/activation-policy-proposals/${record.id}/interrupt`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ actor: "assets.operator", reason }),
      });
      pendingRequest.current = null;
      setRecoveryReasons((current) => {
        const next = { ...current };
        delete next[record.id];
        return next;
      });
      await loadProposalHistory();
      setMessage({ error: false, text: "Request marked interrupted. Provider billing is unknown; a new request key is needed for another attempt." });
    } catch (error) {
      setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to interrupt this request." });
    } finally {
      setBusy(null);
    }
  }

  function currentDraftPayload() {
    if (!selectedCollector) throw new Error("Choose a published collector compatible with this protocol.");
    return {
      name: name.trim(), protocol,
      artifact_version_id: selectedCollector.artifact_version_id,
      target_template: jsonObject(target, "Target template"),
      configuration_defaults: jsonObject(configuration, "Configuration defaults"),
      worker_selector: jsonObject(workerSelector, "Worker selector"),
      execution_mode: executionMode, schedule_seconds: scheduleSeconds,
      created_by: "assets.operator",
    };
  }

  function loadPolicyIntoEditor(policy: Policy, edit: boolean) {
    ++scopeRequestSequence.current;
    ++draftScopeRequestSequence.current;
    ++proposalRequestSequence.current;
    pendingRequest.current = null;
    setProposal(null);
    setScopePreview(null);
    setScopeError(null);
    setDraftScopePreview(null);
    setDraftScopeError(null);
    setProtocol(policy.protocol);
    setArtifactVersionId(policy.artifact_version_id);
    setSelectedCollector(null);
    setCatalogRevision((value) => value + 1);
    setName(policy.name);
    setTarget(JSON.stringify(policy.target_template, null, 2));
    setConfiguration(JSON.stringify(policy.configuration_defaults, null, 2));
    setWorkerSelector(JSON.stringify(policy.worker_selector, null, 2));
    setExecutionMode(policy.execution_mode);
    setScheduleSeconds(policy.schedule_seconds);
    setEditingPolicy(edit ? policy : null);
    setMessage({ error: false, text: edit
      ? `Editing ${policy.name} v${policy.version}, draft revision ${policy.revision}. Save before validating.`
      : `Loaded ${policy.name} v${policy.version} as a new draft. Saving will create the next policy version.` });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function previewCurrentDraftScope() {
    const sequence = ++draftScopeRequestSequence.current;
    const inputKey = draftInputKey;
    setDraftScopeLoading(true);
    setDraftScopePreview(null);
    setDraftScopeError(null);
    try {
      const result = await apiFetch<DraftScopePreview>(
        "/assets/activation-policies/draft-scope-preview",
        {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ draft: currentDraftPayload(), device_id: deviceId || null }),
        },
      );
      if (sequence === draftScopeRequestSequence.current) {
        setDraftScopePreview({ inputKey, result });
      }
    } catch (error) {
      if (sequence === draftScopeRequestSequence.current) {
        setDraftScopeError({
          inputKey,
          message: error instanceof Error ? error.message : "Unable to evaluate current draft scope.",
        });
      }
    } finally {
      if (sequence === draftScopeRequestSequence.current) setDraftScopeLoading(false);
    }
  }

  async function createPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedCollector) {
      setMessage({ error: true, text: "Choose a published collector compatible with this protocol." });
      return;
    }
    const editing = editingPolicy;
    setBusy("create");
    setMessage(null);
    try {
      const draft = currentDraftPayload();
      const saved = editing
        ? await apiFetch<Policy>(`/assets/activation-policies/${encodeURIComponent(editing.id)}`, {
          method: "PATCH", headers: { "content-type": "application/json" },
          body: JSON.stringify({ expected_revision: editing.revision, draft, actor: "assets.operator" }),
        })
        : await apiFetch<Policy>("/assets/activation-policies", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify(draft),
        });
      setPolicies((current) => editing
        ? current.map((item) => item.id === saved.id ? saved : item)
        : [saved, ...current]);
      setEditingPolicy(editing ? saved : null);
      setMessage({ error: false, text: editing
        ? `Draft ${saved.name} v${saved.version} saved at revision ${saved.revision}. Finish editing before validating.`
        : `Draft ${saved.name} v${saved.version} created. Validate it before publishing.` });
    } catch (error) {
      setMessage({ error: true, text: error instanceof APIError && error.status === 409
        ? "This draft changed or is no longer editable. Your unsaved fields remain here; refresh and reopen the latest draft before retrying."
        : error instanceof Error ? error.message : "Unable to save policy draft." });
    } finally {
      setBusy(null);
    }
  }

  async function advancePolicy(policy: Policy, action: "validate" | "publish") {
    setBusy(policy.id);
    setMessage(null);
    try {
      const updated = await apiFetch<Policy>(`/assets/activation-policies/${policy.id}/${action}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ actor: "assets.operator", ...(action === "validate" ? { expected_revision: policy.revision } : {}) }),
      });
      setPolicies((current) => current.map((item) => item.id === updated.id ? updated :
        action === "publish" && item.name === updated.name && item.status === "published"
          ? { ...item, status: "deprecated" } : item));
      if (editingPolicy?.id === updated.id) setEditingPolicy(null);
      setMessage({
        error: false,
        text: action === "validate"
          ? `${updated.name} v${updated.version} validated. Publish it when the contract is ready.`
          : `${updated.name} v${updated.version} published. It is now available on verified devices.`,
      });
    } catch (error) {
      setMessage({ error: true, text: error instanceof Error ? error.message : `Unable to ${action} policy.` });
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f3f4f7] px-4 py-8 text-[#2c384a] sm:px-6">
      <div className="mx-auto max-w-6xl">
        <Link href="/assets/devices" className="inline-flex items-center gap-1.5 text-xs font-medium text-[#5856d6]"><ArrowLeft className="size-4" /> Device onboarding</Link>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="flex items-center gap-3 text-2xl font-semibold"><FileCode2 className="size-7 text-[#5856d6]" /> Activation policies</h1>
            <p className="mt-2 max-w-3xl text-sm text-muted-foreground">Bind a published collector version to a device transport. Validation and publication are separate governance steps; devices still require a verified connection and an explicit plan approval.</p>
          </div>
          <Button variant="outline" onClick={() => void load()} disabled={loading || busy !== null}><RefreshCw className="size-4" /> Refresh</Button>
        </div>

        {message ? <div role={message.error ? "alert" : "status"} className={`mt-5 rounded-lg border px-4 py-3 text-sm ${message.error ? "border-red-200 bg-red-50 text-red-800" : "border-emerald-200 bg-emerald-50 text-emerald-800"}`}>{message.text}</div> : null}

        <div className="mt-6 grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
          <form onSubmit={(event) => void createPolicy(event)} className="min-w-0 space-y-4 rounded-xl border border-[#d8dbe0] bg-white p-5">
            <div><h2 className="font-semibold">{editingPolicy ? `Edit draft · v${editingPolicy.version} revision ${editingPolicy.revision}` : "Create draft"}</h2><p className="mt-1 text-xs text-muted-foreground">Only published collector versions appear below. No secrets belong in these templates.</p></div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs font-semibold">Protocol<select aria-label="Protocol" value={protocol} disabled={busy !== null} onChange={(event) => { ++scopeRequestSequence.current; ++proposalRequestSequence.current; pendingRequest.current = null; setProtocol(event.target.value as Protocol); setArtifactVersionId(""); setSelectedCollector(null); setProposal(null); setScopePreview(null); setScopeError(null); setScopeLoading(false); }} className="mt-1 block h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-2 text-sm font-normal">{Object.entries(protocolLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
              <label className="text-xs font-semibold">Policy name<Input required value={name} readOnly={editingPolicy !== null} onChange={(event) => setName(event.target.value)} placeholder="vendor-controller-inventory" className="mt-1" /></label>
            </div>
            <div className="flex gap-2"><Input aria-label="Collector name prefix" value={collectorSearch} onChange={(event) => setCollectorSearch(event.target.value)} placeholder="Find published collector by name prefix" maxLength={128} /><Button type="button" variant="outline" disabled={loading || busy !== null} onClick={() => setCollectorPrefix(collectorSearch.trim())}>Find</Button></div>
            <label className="block text-xs font-semibold">Published collector<select aria-label="Published collector" required value={artifactVersionId} disabled={busy !== null} onChange={(event) => { ++scopeRequestSequence.current; ++proposalRequestSequence.current; pendingRequest.current = null; setArtifactVersionId(event.target.value); setSelectedCollector(null); setProposal(null); setScopePreview(null); setScopeError(null); setScopeLoading(false); }} className="mt-1 block h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-2 text-sm font-normal"><option value="">Choose a collector version</option>{selectedCollector && selectedOutsidePage && <option value={selectedCollector.artifact_version_id}>{selectedCollector.artifact_name} v{selectedCollector.version} · {selectedCollector.adapter_type} (linked)</option>}{available.map((collector) => <option key={collector.artifact_version_id} value={collector.artifact_version_id}>{collector.artifact_name} v{collector.version} · {collector.adapter_type}</option>)}</select></label>
            {collectorCursor && <Button type="button" size="sm" variant="outline" disabled={loading || busy !== null} onClick={() => void loadMore("collectors")}>Load more collectors</Button>}
            {selectedCollector ? <details className="rounded-md bg-[#f8f9fa] p-3 text-xs"><summary className="cursor-pointer font-semibold">Collector target and configuration contracts</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap">{JSON.stringify({ target_schema: selectedCollector.target_schema, config_schema: selectedCollector.config_schema, defaults: selectedCollector.defaults }, null, 2)}</pre></details> : <p className="text-xs text-muted-foreground">{available.length ? "Choose a collector to view its contract." : collectorPrefix ? "No published collector matches this protocol and name prefix." : "No published collector supports this protocol yet. Publish one in Studio first."}</p>}
            <div className="space-y-3 rounded-lg border border-[#d5d2f7] bg-[#f7f6ff] p-4">
              <div className="flex items-center justify-between gap-2"><h3 className="flex items-center gap-2 text-sm font-semibold text-[#4947ad]"><Sparkles className="size-4" /> Ask AI to draft</h3><Link href="/settings/ai" className="text-xs text-[#5856d6] underline">Model settings</Link></div>
              <p className="text-xs text-muted-foreground">Describe the read-only endpoint and purpose. We send the collector contract{deviceContext ? ` and limited context for ${deviceContext.name} (${deviceContext.kind}, ${deviceContext.site || "unassigned"})` : ""}, but do not add its management IP or credential references. Do not paste secrets into the brief. Suggestions and briefs are saved as audit history.</p>
              {authoringQuota && <p className="text-xs text-muted-foreground">Today&apos;s authoring admission: {authoringQuota.actor_used.toLocaleString()} used or reserved for {authoringQuota.actor}; available {authoringQuota.actor_available?.toLocaleString() ?? "unbounded"} for this account, {authoringQuota.namespace_available?.toLocaleString() ?? "unbounded"} for the tenant/region{authoringQuota.unknown_charge_requests ? ` · ${authoringQuota.unknown_charge_requests} unresolved charge${authoringQuota.unknown_charge_requests === 1 ? "" : "s"}` : ""}. <Link href="/settings/ai/authoring-quota" className="text-[#5856d6] underline">Quota details</Link></p>}
              <Textarea aria-label="AI policy brief" value={aiBrief} onChange={(event) => setAiBrief(event.target.value)} rows={3} maxLength={3000} placeholder={proposal ? "Ask for a change to the last generated suggestion…" : "Draft a site-scoped policy for the controller inventory API at /api/v1/inventory…"} className="bg-white text-xs" />
              <Button type="button" size="sm" variant="outline" disabled={busy !== null || !selectedCollector || aiBrief.trim().length < 10 || Boolean(deviceId && !deviceContext)} onClick={() => void askAiToDraft()}><Sparkles className="size-4" /> {busy === "suggest" ? "Drafting…" : proposal ? "Refine suggestion" : "Generate suggestion"}</Button>
              {proposal ? <p className="text-[11px] text-muted-foreground">Refinement uses the saved parent suggestion plus your new brief. Manual edits below stay local until you save the draft.</p> : null}
              {proposal ? <div className="space-y-1 rounded-md border border-[#d8dbe0] bg-white p-3 text-xs"><p className="font-semibold">Model rationale</p><p className="text-muted-foreground">{proposal.rationale}</p>{proposal.warnings.map((warning) => <p key={warning} className="text-[#8b6300]">{warning}</p>)}<p className="font-mono text-[10px] text-muted-foreground">Model {proposal.model_id} · {proposal.tokens_used} known tokens{proposal.external_charge_unknown ? " · additional provider charge unknown" : ""}</p></div> : null}
              {proposal ? <div className="space-y-3 rounded-md border border-[#d8dbe0] bg-white p-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2"><div><p className="font-semibold">Saved suggestion scope</p><p className="text-muted-foreground">Evaluate the sealed AI suggestion against the current device, credential profile and Worker registration. This does not evaluate manual edits below.</p></div><Button type="button" size="sm" variant="outline" disabled={scopeLoading || busy !== null} onClick={() => void previewSavedScope()}>{scopeLoading ? "Evaluating…" : "Preview scope"}</Button></div>
                {scopeError ? <p role="alert" className="text-red-700">{scopeError}</p> : null}
                {scopePreview && scopePreview.proposal_id === proposal.proposal_id ? <ScopeEvaluation scope={scopePreview} digest={`suggestion SHA-256 ${scopePreview.proposal_sha256.slice(0, 12)}…`} /> : null}
              </div> : null}
            </div>
            <p className="break-words text-xs text-muted-foreground">Available placeholders: <code>${"{management_ip}"}</code>, <code>${"{port}"}</code>, <code>${"{site}"}</code>, <code>${"{device_id}"}</code>, <code>${"{device_name}"}</code>, <code>${"{protocol}"}</code>. For HTTPS API, set <code>url</code> to the real read-only endpoint, for example <code className="[overflow-wrap:anywhere]">{'{"url":"https://${management_ip}:${port}/api/v1/inventory"}'}</code>. The Worker must separately allowlist the target host.</p>
            <label className="block text-xs font-semibold">Target template (JSON)<Textarea aria-label="Target template" value={target} onChange={(event) => setTarget(event.target.value)} rows={4} className="mt-1 font-mono text-xs" /></label>
            <label className="block text-xs font-semibold">Configuration defaults (JSON)<Textarea aria-label="Configuration defaults" value={configuration} onChange={(event) => setConfiguration(event.target.value)} rows={3} className="mt-1 font-mono text-xs" /></label>
            <label className="block text-xs font-semibold">Worker selector (JSON)<Textarea aria-label="Worker selector" value={workerSelector} onChange={(event) => setWorkerSelector(event.target.value)} rows={2} className="mt-1 font-mono text-xs" /></label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs font-semibold">Execution<select aria-label="Execution" value={executionMode} onChange={(event) => setExecutionMode(event.target.value as "scheduled" | "on_demand")} className="mt-1 block h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-2 text-sm font-normal"><option value="scheduled">Scheduled</option><option value="on_demand">On demand</option></select></label>
              <label className="text-xs font-semibold">Interval in seconds<Input aria-label="Interval in seconds" type="number" min={5} max={86400} value={scheduleSeconds} onChange={(event) => setScheduleSeconds(Number(event.target.value))} className="mt-1" /></label>
            </div>
            <div className="space-y-3 rounded-md border border-[#d8dbe0] bg-[#f8f9fa] p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2"><div><p className="font-semibold">Current editor draft scope</p><p className="text-muted-foreground">Checks exactly the fields above, including your edits. No model call, policy write or deployment.</p></div><Button type="button" size="sm" variant="outline" disabled={draftScopeLoading || busy !== null || !selectedCollector || Boolean(deviceId && !deviceContext)} onClick={() => void previewCurrentDraftScope()}>{draftScopeLoading ? "Evaluating…" : "Preview current draft"}</Button></div>
              {draftScopeError && draftScopeError.inputKey === draftInputKey ? <p role="alert" className="text-red-700">{draftScopeError.message}</p> : null}
              {draftScopePreview && draftScopePreview.inputKey === draftInputKey ? <ScopeEvaluation scope={draftScopePreview.result} digest={`editor SHA-256 ${draftScopePreview.result.draft_sha256.slice(0, 12)}…`} /> : draftScopePreview ? <p className="text-[#8b6300]">Fields changed since the last preview. Preview again to evaluate the current draft.</p> : null}
            </div>
            <div className="flex flex-wrap gap-2"><Button disabled={busy !== null || !selectedCollector}><Plus className="size-4" /> {editingPolicy ? "Save draft revision" : "Create draft"}</Button>{editingPolicy ? <Button type="button" variant="outline" disabled={busy !== null} onClick={() => { setEditingPolicy(null); setMessage({ error: false, text: "Editor closed. Unsaved form changes were not applied to the draft; reopen it to continue editing." }); }}>Finish editing</Button> : null}</div>
          </form>

          <section className="min-w-0 rounded-xl border border-[#d8dbe0] bg-white p-5">
            <h2 className="font-semibold">Policy lifecycle</h2>
            <p className="mt-1 text-xs text-muted-foreground">Drafts can be revised with conflict protection. Validation freezes a revision; publication makes it selectable on verified devices. For later changes, create a new version.</p>
            <div className="mt-3 flex gap-2"><Input aria-label="Policy name prefix" value={policySearch} onChange={(event) => setPolicySearch(event.target.value)} placeholder="Find policy by name prefix" maxLength={128} /><Button type="button" variant="outline" disabled={loading || busy !== null} onClick={() => setPolicyPrefix(policySearch.trim())}>Find</Button></div>
            <div className="mt-4 space-y-3">
              {policies.length === 0 ? <p className="text-sm text-muted-foreground">{loading ? "Loading policies…" : "No activation policies yet."}</p> : policies.map((policy) => (
                <article key={policy.id} className="rounded-lg border border-[#e4e6e9] p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2"><div><h3 className="text-sm font-semibold">{policy.name} v{policy.version}</h3><p className="mt-1 font-mono text-[11px] text-muted-foreground">{protocolLabels[policy.protocol]} · {policy.adapter_type}{policy.status === "draft" ? ` · revision ${policy.revision}` : ""}</p></div><Badge variant="outline">{policy.status}</Badge></div>
                  {policy.status === "draft" ? <div className="mt-3 flex flex-wrap gap-2"><Button size="sm" variant="outline" disabled={busy !== null} onClick={() => loadPolicyIntoEditor(policy, true)}><Pencil className="size-4" /> Edit draft</Button><Button size="sm" variant="outline" disabled={busy !== null || editingPolicy?.id === policy.id} onClick={() => void advancePolicy(policy, "validate")}><CheckCircle2 className="size-4" /> Validate</Button></div> : null}
                  {policy.status !== "draft" ? <div className="mt-3 flex flex-wrap items-center gap-2">
                    {policy.status === "validated" ? <Button size="sm" disabled={busy !== null} onClick={() => void advancePolicy(policy, "publish")}><ShieldCheck className="size-4" /> Publish</Button> : null}
                    <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => loadPolicyIntoEditor(policy, false)}>Use as new version</Button>
                    {policy.status === "published" ? <Link href="/assets/devices" className="text-xs font-semibold text-[#5856d6] hover:underline">Use on a verified device →</Link> : null}
                  </div> : null}
                </article>
              ))}
            </div>
            {policyCursor && <Button type="button" size="sm" variant="outline" className="mt-4" disabled={loading || busy !== null} onClick={() => void loadMore("policies")}>Load more policies</Button>}
          </section>
        </div>

        <section className="mt-5 rounded-xl border border-[#d8dbe0] bg-white p-5">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="font-semibold">AI proposal history</h2><p className="mt-1 text-xs text-muted-foreground">Last 30 requests for {deviceContext ? deviceContext.name : "unbound policies"}. Restoring a suggestion never creates or publishes a policy.</p></div><Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void loadProposalHistory().catch((error) => setMessage({ error: true, text: error instanceof Error ? error.message : "Unable to load history." }))}><RefreshCw className="size-4" /> Refresh history</Button></div>
          <div className="mt-4 space-y-2">
            {proposalHistory.length === 0 ? <p className="text-sm text-muted-foreground">No saved AI requests in this context.</p> : proposalHistory.map((record) => (
              <article key={record.id} className="rounded-lg border border-[#e4e6e9] p-3 text-xs">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div><p className="font-semibold">{record.result?.draft.name || record.brief}</p><p className="mt-1 text-muted-foreground">{record.brief}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{new Date(record.created_at).toLocaleString()} · {record.status} · {record.tokens_used} known tokens{record.parent_id ? " · refinement" : ""}{record.failure_code ? ` · ${record.failure_code}` : ""}{record.external_charge_unknown === false ? "" : " · provider charge unverified"}</p></div>
                  {record.result ? <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => restoreProposal(record)}>Restore suggestion</Button> : null}
                </div>
                {record.status === "generating" ? <div className="mt-3 space-y-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-amber-900">
                  <p>Model work may still be running. After {new Date(record.recovery_available_at).toLocaleString()}, you can explicitly close a stale request. Provider billing may already have occurred; no automatic retry will run.</p>
                  <Textarea aria-label={`Interruption reason for ${record.id}`} value={recoveryReasons[record.id] || ""} onChange={(event) => setRecoveryReasons((current) => ({ ...current, [record.id]: event.target.value }))} rows={2} maxLength={1000} placeholder="Describe why you are closing this stale request…" className="bg-white text-xs" />
                  <Button size="sm" variant="outline" disabled={busy !== null || clock === null || clock < new Date(record.recovery_available_at).getTime() || (recoveryReasons[record.id] || "").trim().length < 10} onClick={() => void interruptProposal(record)}>Mark interrupted</Button>
                </div> : null}
              </article>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
