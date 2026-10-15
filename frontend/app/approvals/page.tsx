"use client";

import RollbackAuthorityReceipt from "./rollback-authority-receipt";
import MCPUnresolvedCustody from "./mcp-unresolved-custody";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CalendarRange,
  CheckCircle2,
  Clock,
  FileSearch,
  Fingerprint,
  Loader2,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
  UserRoundCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { APIError, apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type ProposalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "executing"
  | "succeeded"
  | "failed";

type ActionProposal = {
  id: string;
  investigation_id: string;
  tool_id: string;
  tool_call_id: string | null;
  rollback_of_change_plan_id: string | null;
  iteration: number;
  arguments: Record<string, unknown>;
  purpose: string;
  plan_hash: string;
  status: ProposalStatus;
  requested_by_principal_id: string | null;
  requested_by: string;
  approved_by: string | null;
  decision_reason: string | null;
  error: string | null;
  requested_at: string;
};

type MCPWriteReconciliationPacket = {
  proposal_id: string;
  investigation_id: string;
  tool_call_id: string;
  current_tool_name: string;
  call_started_at: string;
  artifact_activation_id: string | null;
  artifact_version_id: string | null;
  designated_lookup_tool_name: string | null;
  provider_lookup_key: string;
  outcome: "unknown";
  automatic_retry_allowed: false;
};

type MCPWriteObservation = {
  id: string;
  lookup_tool_call_id: string;
  provider_outcome: "applied" | "not_applied" | "unknown";
  provider_reference: string | null;
  observed_at: string;
  recorded_by: string;
  reason: string;
};

type MCPWriteReview = {
  id: string;
  observation_id: string;
  decision: "accept" | "reject" | "inconclusive";
  reviewed_by: string;
  reason: string;
  reviewed_at: string;
};

type MCPWriteSummary = {
  observation_count: number;
  reviewed_count: number;
  accepted_provider_reports: Array<"applied" | "not_applied" | "unknown">;
  contradictory_determinate_reports: boolean;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

type MCPDeclaredProviderLookup = {
  proposal_id: string;
  observation_id: string;
  lookup_tool_call_id: string;
  reported_provider_outcome: "applied" | "not_applied" | "unknown";
  provider_reference: string | null;
  observed_at: string;
  consistency_window_seconds: number;
  max_observation_age_seconds: number;
  correlation_key: "icheck/toolCallId";
  provider_correlation_verified: false;
  final_disposition_allowed: false;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
};

type MCPIndependentEvidenceSummary = {
  proposal_id: string;
  observation_count: number;
  reviewed_count: number;
  accepted_target_states: Array<"present" | "absent" | "unknown">;
  accepted_recipient_receipt_states: Array<"present" | "absent" | "unknown">;
  divergent_determinate_target_states: boolean;
  divergent_determinate_recipient_receipts: boolean;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

type MCPDispositionEvidenceSnapshot = {
  proposal_id: string;
  original_tool_call_id: string;
  provider: MCPWriteSummary;
  independent: MCPIndependentEvidenceSummary;
  contract_qualification: {
    checked_at: string;
    accepted_provider_count: number;
    contract_qualified_provider_count: number;
    unqualified_provider_observation_ids: string[];
    accepted_independent_count: number;
    contract_qualified_independent_count: number;
    unqualified_independent_observation_ids: string[];
    provider_correlation_verified: false;
    final_disposition_allowed: false;
  };
  evidence_manifest: {
    format_version: "icheck.mcp-write-disposition-evidence/v1";
    proposal_id: string;
    original_tool_call_id: string;
    plan_hash: string;
    artifact_activation_id: string | null;
    artifact_version_id: string | null;
    artifact_content_hash: string | null;
    artifact_activation_sha256: string | null;
    evidence_investigation_ids: string[];
    provider_observations: Array<{ observation_id: string; lookup_tool_call_id: string; lookup_result_hash: string }>;
    independent_observations: Array<{ observation_id: string; verification_tool_call_id: string; verification_result_hash: string }>;
  };
  all_evidence_reviewable: true;
  native_transactional_lock: boolean;
  final_disposition_allowed: false;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

type MCPIndependentVerification = {
  proposal_id: string;
  original_tool_call_id: string;
  verification_tool_call_id: string;
  verification_kind: "target_state" | "recipient_receipt";
  observed_target_state: "present" | "absent" | "unknown";
  observed_at: string;
  evidence_reference: string | null;
  bound_value_count: number;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

type MCPIndependentObservation = MCPIndependentVerification & {
  id: string;
  verification_result_hash: string;
  recorded_by: string;
  reason: string;
  created_at: string;
};

type MCPIndependentReview = {
  id: string;
  observation_id: string;
  decision: "accept" | "reject" | "inconclusive";
  reviewed_by: string;
  reason: string;
  reviewed_at: string;
  original_outcome: "unknown";
  automatic_retry_allowed: false;
  delivery_verified: false;
};

type ChangeStage = "precheck" | "dry_run" | "postcheck" | "rollback" | "rollback_check";
type ChangeStageTool = { tool_id: string; tool_name: string; success_path: string; argument_mapping?: Record<string, string>; summary_paths?: string[] };

type GovernedChangePlan = {
  id: string;
  action_proposal_id: string;
  investigation_id: string;
  revision: number;
  status: string;
  risk_class: "low" | "medium" | "high" | "critical";
  target_snapshot: Record<string, unknown>;
  idempotency_key_hash: string;
  maintenance_window_start: string | null;
  maintenance_window_end: string | null;
  plan_hash: string;
  approved_plan_hash: string | null;
  policy_evaluation: {
    approval_ready?: boolean;
    evidence?: Record<string, { present: boolean; passed: boolean; tool_call_id: string | null }>;
  };
  tool_contract_snapshot: {
    requires_maintenance_window?: boolean;
    authorization_target_paths?: Record<string, "device_id" | "site">;
    steps: Record<"precheck" | "dry_run" | "postcheck", ChangeStageTool> & { rollback_check?: ChangeStageTool };
    rollback: { tool_id: string; tool_name: string; success_path: string; argument_mapping?: Record<string, string>; summary_paths?: string[] };
  };
  evidence: Array<{
    id: string;
    stage: ChangeStage;
    tool_call_id: string;
    result_hash: string;
    passed: boolean;
    evidence_snapshot: {
      summary?: Record<string, boolean | number | string>;
    };
    created_at: string;
  }>;
};

type InvestigationToolCall = {
  id: string;
  tool_id: string;
  governed_change_plan_id: string | null;
  governed_stage: ChangeStage | null;
  arguments: Record<string, unknown>;
  status: string;
  result_hash: string | null;
  created_at: string;
};

function relativeTime(value: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

function statusTone(status: ProposalStatus): string {
  if (status === "pending") return "border-amber-200 bg-amber-50 text-amber-700";
  if (status === "approved" || status === "executing") {
    return "border-sky-200 bg-sky-50 text-sky-700";
  }
  if (status === "succeeded") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  return "border-red-200 bg-red-50 text-red-700";
}

function localDateTime(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

export default function ApprovalsPage() {
  const [proposals, setProposals] = useState<ActionProposal[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState<"approve" | "reject" | null>(null);
  const [changePlan, setChangePlan] = useState<GovernedChangePlan | null>(null);
  const [rollbackContext, setRollbackContext] = useState<GovernedChangePlan | null>(null);
  const [toolCalls, setToolCalls] = useState<InvestigationToolCall[]>([]);
  const [investigationStatusRead, setInvestigationStatusRead] = useState<{ investigationId: string; status: string | null } | null>(null);
  const [reconciliationRead, setReconciliationRead] = useState<{ proposalId: string; packet: MCPWriteReconciliationPacket } | null>(null);
  const [observationRead, setObservationRead] = useState<{ proposalId: string; rows: MCPWriteObservation[] } | null>(null);
  const [reviewRead, setReviewRead] = useState<{ proposalId: string; rows: MCPWriteReview[] } | null>(null);
  const [summaryRead, setSummaryRead] = useState<{ proposalId: string; summary: MCPWriteSummary } | null>(null);
  const [providerCorrelationRead, setProviderCorrelationRead] = useState<{ proposalId: string; observationId: string; result: MCPDeclaredProviderLookup } | null>(null);
  const [providerCorrelationBusy, setProviderCorrelationBusy] = useState<string | null>(null);
  const [independentSummaryRead, setIndependentSummaryRead] = useState<{ proposalId: string; summary: MCPIndependentEvidenceSummary } | null>(null);
  const [dispositionRead, setDispositionRead] = useState<{ proposalId: string; snapshot: MCPDispositionEvidenceSnapshot } | null>(null);
  const [dispositionError, setDispositionError] = useState<{ proposalId: string; message: string } | null>(null);
  const [dispositionBusy, setDispositionBusy] = useState(false);
  const dispositionRequestVersion = useRef(0);
  const [verificationRead, setVerificationRead] = useState<{ proposalId: string; result: MCPIndependentVerification } | null>(null);
  const [independentObservationRead, setIndependentObservationRead] = useState<{ proposalId: string; rows: MCPIndependentObservation[] } | null>(null);
  const [independentReviewRead, setIndependentReviewRead] = useState<{ proposalId: string; rows: MCPIndependentReview[] } | null>(null);
  const [verificationCallId, setVerificationCallId] = useState("");
  const [verificationReason, setVerificationReason] = useState("");
  const [verificationBusy, setVerificationBusy] = useState(false);
  const [independentObservationBusy, setIndependentObservationBusy] = useState(false);
  const [independentReviewTargetId, setIndependentReviewTargetId] = useState<string | null>(null);
  const [independentReviewDecision, setIndependentReviewDecision] = useState<"accept" | "reject" | "inconclusive">("inconclusive");
  const [independentReviewReason, setIndependentReviewReason] = useState("");
  const [independentReviewBusy, setIndependentReviewBusy] = useState(false);
  const [lookupCallId, setLookupCallId] = useState("");
  const [lookupReason, setLookupReason] = useState("");
  const [observationBusy, setObservationBusy] = useState(false);
  const [reviewTargetId, setReviewTargetId] = useState<string | null>(null);
  const [reviewDecision, setReviewDecision] = useState<"accept" | "reject" | "inconclusive">("inconclusive");
  const [reviewReason, setReviewReason] = useState("");
  const [reviewBusy, setReviewBusy] = useState(false);
  const [reconciliationLoading, setReconciliationLoading] = useState(false);
  const [governanceLoading, setGovernanceLoading] = useState(false);
  const [governanceBusy, setGovernanceBusy] = useState<string | null>(null);
  const [governanceReason, setGovernanceReason] = useState("");
  const [windowStart, setWindowStart] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [error, setError] = useState<string | null>(null);

  const loadProposals = useCallback(async () => {
    setLoading(true);
    try {
      const next = await apiFetch<ActionProposal[]>("/agent/action-proposals?limit=200");
      setProposals(next);
      setSelectedId((current) =>
        current && next.some((item) => item.id === current)
          ? current
          : next.find((item) => item.status === "pending")?.id || next[0]?.id || null,
      );
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load approvals");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadProposals(), 0);
    return () => window.clearTimeout(timer);
  }, [loadProposals]);

  const selected = useMemo(
    () => proposals.find((item) => item.id === selectedId) || null,
    [proposals, selectedId],
  );
  const pendingCount = proposals.filter((item) => item.status === "pending").length;
  const selectedInvestigationStatus = investigationStatusRead?.investigationId === selected?.investigation_id
    ? investigationStatusRead?.status ?? null : null;
  const selectedReconciliationPacket = reconciliationRead?.proposalId === selected?.id
    ? reconciliationRead?.packet ?? null : null;
  const selectedObservations = observationRead?.proposalId === selected?.id
    ? observationRead?.rows ?? [] : [];
  const selectedReviews = reviewRead?.proposalId === selected?.id
    ? reviewRead?.rows ?? [] : [];
  const selectedSummary = summaryRead?.proposalId === selected?.id
    ? summaryRead?.summary ?? null : null;
  const selectedIndependentSummary = independentSummaryRead?.proposalId === selected?.id
    ? independentSummaryRead?.summary ?? null : null;
  const selectedDispositionSnapshot = dispositionRead?.proposalId === selected?.id
    ? dispositionRead?.snapshot ?? null : null;
  const selectedDispositionError = dispositionError?.proposalId === selected?.id
    ? dispositionError?.message ?? null : null;
  const selectedVerification = verificationRead?.proposalId === selected?.id
    && verificationRead?.result.verification_tool_call_id === verificationCallId.trim()
    ? verificationRead?.result ?? null : null;
  const selectedIndependentObservations = independentObservationRead?.proposalId === selected?.id
    ? independentObservationRead?.rows ?? [] : [];
  const selectedIndependentReviews = independentReviewRead?.proposalId === selected?.id
    ? independentReviewRead?.rows ?? [] : [];

  useEffect(() => {
    if (!selected) return;
    let active = true;
    void apiFetch<{ status: string }>(`/agent/investigations/${selected.investigation_id}`)
      .then((investigation) => {
        if (active) setInvestigationStatusRead({ investigationId: selected.investigation_id, status: investigation.status });
      })
      .catch(() => {
        if (active) setInvestigationStatusRead({ investigationId: selected.investigation_id, status: null });
      });
    return () => { active = false; };
  }, [selected]);

  const loadGovernance = useCallback(async (proposal: ActionProposal) => {
    setGovernanceLoading(true);
    setChangePlan(null);
    setRollbackContext(null);
    try {
      if (proposal.rollback_of_change_plan_id) {
        const parent = await apiFetch<GovernedChangePlan>(`/agent/change-plans/${proposal.rollback_of_change_plan_id}`);
        setRollbackContext(parent);
        setToolCalls([]);
        setWindowStart("");
        setWindowEnd("");
        return;
      }
      const plan = await apiFetch<GovernedChangePlan>(`/agent/action-proposals/${proposal.id}/change-plan`);
      const calls = await apiFetch<InvestigationToolCall[]>(`/agent/investigations/${proposal.investigation_id}/tool-calls?limit=100`);
      setChangePlan(plan);
      setToolCalls(calls);
      setWindowStart(localDateTime(plan.maintenance_window_start));
      setWindowEnd(localDateTime(plan.maintenance_window_end));
    } catch (caught) {
      if (caught instanceof APIError && caught.status === 404) {
        setChangePlan(null);
        setRollbackContext(null);
        setToolCalls([]);
        setWindowStart("");
        setWindowEnd("");
      } else {
        setError(caught instanceof Error ? caught.message : "Unable to load change governance");
      }
    } finally {
      setGovernanceLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!selected) return;
    const timer = window.setTimeout(() => void loadGovernance(selected), 0);
    return () => window.clearTimeout(timer);
  }, [loadGovernance, selected]);

  function stageTool(stage: ChangeStage) {
    if (!changePlan) return null;
    return stage === "rollback"
      ? changePlan.tool_contract_snapshot.rollback
      : changePlan.tool_contract_snapshot.steps[stage];
  }

  function eligibleCall(stage: ChangeStage): InvestigationToolCall | null {
    const tool = stageTool(stage);
    if (!changePlan || !tool) return null;
    const used = new Set(changePlan.evidence.map((item) => item.tool_call_id));
    return toolCalls.find((call) =>
      call.tool_id === tool.tool_id
      && (stage === "rollback" ? call.governed_change_plan_id == null && call.governed_stage == null : call.governed_change_plan_id === changePlan.id && call.governed_stage === stage)
      && call.status === "succeeded"
      && call.result_hash
      && !used.has(call.id)
      && Object.entries(tool.argument_mapping || Object.fromEntries(Object.keys(changePlan.target_snapshot).map((path) => [path, path]))).every(([destinationPath, sourcePath]) => {
        const actual = destinationPath.split(".").reduce<unknown>((value, part) =>
          value && typeof value === "object" ? (value as Record<string, unknown>)[part] : undefined,
        call.arguments);
        const expected = changePlan.target_snapshot[sourcePath];
        return JSON.stringify(actual) === JSON.stringify(expected);
      }),
    ) || null;
  }

  async function bindEvidence(stage: ChangeStage) {
    const call = eligibleCall(stage);
    if (!selected || !changePlan || !call || !governanceReason.trim()) return;
    setGovernanceBusy(stage);
    setError(null);
    try {
      const next = await apiFetch<GovernedChangePlan>(`/agent/action-proposals/${selected.id}/change-plan/evidence`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: changePlan.revision,
          expected_plan_hash: changePlan.plan_hash,
          stage,
          tool_call_id: call.id,
          reason: governanceReason.trim(),
        }),
      });
      setChangePlan(next);
      setGovernanceReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to bind change evidence");
    } finally {
      setGovernanceBusy(null);
    }
  }

  async function saveWindow() {
    if (!selected || !changePlan || !windowStart || !windowEnd || !governanceReason.trim()) return;
    setGovernanceBusy("window");
    setError(null);
    try {
      const next = await apiFetch<GovernedChangePlan>(`/agent/action-proposals/${selected.id}/change-plan/window`, {
        method: "PATCH",
        body: JSON.stringify({
          expected_revision: changePlan.revision,
          expected_plan_hash: changePlan.plan_hash,
          maintenance_window_start: new Date(windowStart).toISOString(),
          maintenance_window_end: new Date(windowEnd).toISOString(),
          reason: governanceReason.trim(),
        }),
      });
      setChangePlan(next);
      setGovernanceReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to update maintenance window");
    } finally {
      setGovernanceBusy(null);
    }
  }

  async function decide(decision: "approve" | "reject") {
    if (!selected || selected.status !== "pending" || !reason.trim()) return;
    setSubmitting(decision);
    setError(null);
    try {
      await apiFetch(`/agent/action-proposals/${selected.id}/decision`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          expected_plan_hash: selected.plan_hash,
          expected_change_plan_hash: changePlan?.plan_hash || null,
          reason: reason.trim(),
        }),
      });
      setReason("");
      await loadProposals();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record decision");
    } finally {
      setSubmitting(null);
    }
  }

  async function loadReconciliationPacket(proposal: ActionProposal) {
    setReconciliationLoading(true);
    setError(null);
    try {
      const packet = await apiFetch<MCPWriteReconciliationPacket>(
        `/agent/action-proposals/${proposal.id}/reconciliation-packet`,
      );
      const rows = await apiFetch<MCPWriteObservation[]>(
        `/agent/action-proposals/${proposal.id}/reconciliation-observations`,
      );
      const reviews = await apiFetch<MCPWriteReview[]>(
        `/agent/action-proposals/${proposal.id}/reconciliation-reviews`,
      );
      const summary = await apiFetch<MCPWriteSummary>(
        `/agent/action-proposals/${proposal.id}/reconciliation-summary`,
      );
      const independentRows = await apiFetch<MCPIndependentObservation[]>(
        `/agent/action-proposals/${proposal.id}/independent-observations`,
      );
      const independentReviews = await apiFetch<MCPIndependentReview[]>(
        `/agent/action-proposals/${proposal.id}/independent-reviews`,
      );
      const independentSummary = await apiFetch<MCPIndependentEvidenceSummary>(
        `/agent/action-proposals/${proposal.id}/independent-evidence-summary`,
      );
      setReconciliationRead({ proposalId: proposal.id, packet });
      setObservationRead({ proposalId: proposal.id, rows });
      setReviewRead({ proposalId: proposal.id, rows: reviews });
      setSummaryRead({ proposalId: proposal.id, summary });
      setIndependentObservationRead({ proposalId: proposal.id, rows: independentRows });
      setIndependentReviewRead({ proposalId: proposal.id, rows: independentReviews });
      setIndependentSummaryRead({ proposalId: proposal.id, summary: independentSummary });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load reconciliation context");
    } finally {
      setReconciliationLoading(false);
    }
  }

  async function inspectCompleteDispositionEvidence(proposal: ActionProposal) {
    const requestVersion = ++dispositionRequestVersion.current;
    setDispositionBusy(true);
    setDispositionRead(null);
    setDispositionError(null);
    try {
      const snapshot = await apiFetch<MCPDispositionEvidenceSnapshot>(
        `/agent/action-proposals/${proposal.id}/disposition-evidence`,
      );
      if (
        snapshot.proposal_id !== proposal.id
        || snapshot.evidence_manifest.proposal_id !== proposal.id
        || snapshot.evidence_manifest.original_tool_call_id !== snapshot.original_tool_call_id
        || snapshot.evidence_manifest.provider_observations.length !== snapshot.provider.observation_count
        || snapshot.evidence_manifest.independent_observations.length !== snapshot.independent.observation_count
      ) {
        throw new Error("The complete evidence manifest does not match its summary");
      }
      if (dispositionRequestVersion.current === requestVersion) {
        setDispositionRead({ proposalId: proposal.id, snapshot });
      }
    } catch (caught) {
      if (dispositionRequestVersion.current === requestVersion) {
        setDispositionError({
          proposalId: proposal.id,
          message: caught instanceof Error ? caught.message : "Unable to review the complete evidence set",
        });
      }
    } finally {
      if (dispositionRequestVersion.current === requestVersion) setDispositionBusy(false);
    }
  }

  function clearDispositionSnapshot() {
    dispositionRequestVersion.current += 1;
    setDispositionRead(null);
    setDispositionError(null);
    setDispositionBusy(false);
  }

  async function recordLookupObservation(proposal: ActionProposal) {
    setObservationBusy(true);
    setError(null);
    clearDispositionSnapshot();
    try {
      await apiFetch<MCPWriteObservation>(
        `/agent/action-proposals/${proposal.id}/reconciliation-observations`,
        {
          method: "POST",
          body: JSON.stringify({
            lookup_tool_call_id: lookupCallId.trim(),
            reason: lookupReason.trim(),
          }),
        },
      );
      clearDispositionSnapshot();
      const rows = await apiFetch<MCPWriteObservation[]>(
        `/agent/action-proposals/${proposal.id}/reconciliation-observations`,
      );
      const summary = await apiFetch<MCPWriteSummary>(
        `/agent/action-proposals/${proposal.id}/reconciliation-summary`,
      );
      setObservationRead({ proposalId: proposal.id, rows });
      setSummaryRead({ proposalId: proposal.id, summary });
      setLookupCallId("");
      setLookupReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record independent lookup");
    } finally {
      setObservationBusy(false);
    }
  }

  async function qualifyIndependentVerification(proposal: ActionProposal) {
    const callId = verificationCallId.trim();
    if (!callId) return;
    setVerificationBusy(true);
    setVerificationRead(null);
    setError(null);
    try {
      const result = await apiFetch<MCPIndependentVerification>(
        `/agent/action-proposals/${proposal.id}/independent-verification/${encodeURIComponent(callId)}`,
      );
      setVerificationRead({ proposalId: proposal.id, result });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to qualify independent evidence");
    } finally {
      setVerificationBusy(false);
    }
  }

  async function recordIndependentObservation(proposal: ActionProposal) {
    if (!selectedVerification || verificationReason.trim().length < 10) return;
    setIndependentObservationBusy(true);
    setError(null);
    clearDispositionSnapshot();
    try {
      await apiFetch<MCPIndependentObservation>(
        `/agent/action-proposals/${proposal.id}/independent-observations`,
        {
          method: "POST",
          body: JSON.stringify({
            verification_tool_call_id: selectedVerification.verification_tool_call_id,
            reason: verificationReason.trim(),
          }),
        },
      );
      clearDispositionSnapshot();
      const rows = await apiFetch<MCPIndependentObservation[]>(
        `/agent/action-proposals/${proposal.id}/independent-observations`,
      );
      const summary = await apiFetch<MCPIndependentEvidenceSummary>(
        `/agent/action-proposals/${proposal.id}/independent-evidence-summary`,
      );
      setIndependentObservationRead({ proposalId: proposal.id, rows });
      setIndependentSummaryRead({ proposalId: proposal.id, summary });
      setVerificationReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to retain independent observation");
    } finally {
      setIndependentObservationBusy(false);
    }
  }

  async function reviewIndependentObservation(proposal: ActionProposal, observationId: string) {
    if (independentReviewReason.trim().length < 10) return;
    setIndependentReviewBusy(true);
    setError(null);
    clearDispositionSnapshot();
    try {
      await apiFetch<MCPIndependentReview>(
        `/agent/action-proposals/${proposal.id}/independent-observations/${observationId}/review`,
        {
          method: "POST",
          body: JSON.stringify({
            decision: independentReviewDecision,
            reason: independentReviewReason.trim(),
          }),
        },
      );
      clearDispositionSnapshot();
      const rows = await apiFetch<MCPIndependentReview[]>(
        `/agent/action-proposals/${proposal.id}/independent-reviews`,
      );
      const summary = await apiFetch<MCPIndependentEvidenceSummary>(
        `/agent/action-proposals/${proposal.id}/independent-evidence-summary`,
      );
      setIndependentReviewRead({ proposalId: proposal.id, rows });
      setIndependentSummaryRead({ proposalId: proposal.id, summary });
      setIndependentReviewTargetId(null);
      setIndependentReviewDecision("inconclusive");
      setIndependentReviewReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to review independent observation");
    } finally {
      setIndependentReviewBusy(false);
    }
  }

  async function reviewLookupObservation(proposal: ActionProposal, observationId: string) {
    setReviewBusy(true);
    setError(null);
    clearDispositionSnapshot();
    try {
      await apiFetch<MCPWriteReview>(
        `/agent/action-proposals/${proposal.id}/reconciliation-observations/${observationId}/review`,
        {
          method: "POST",
          body: JSON.stringify({ decision: reviewDecision, reason: reviewReason.trim() }),
        },
      );
      clearDispositionSnapshot();
      const rows = await apiFetch<MCPWriteReview[]>(
        `/agent/action-proposals/${proposal.id}/reconciliation-reviews`,
      );
      const summary = await apiFetch<MCPWriteSummary>(
        `/agent/action-proposals/${proposal.id}/reconciliation-summary`,
      );
      setReviewRead({ proposalId: proposal.id, rows });
      setSummaryRead({ proposalId: proposal.id, summary });
      setReviewTargetId(null);
      setReviewDecision("inconclusive");
      setReviewReason("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to review lookup evidence");
    } finally {
      setReviewBusy(false);
    }
  }

  async function inspectDeclaredProviderCorrelation(proposal: ActionProposal, observationId: string) {
    setProviderCorrelationBusy(observationId);
    setProviderCorrelationRead(null);
    setError(null);
    try {
      const result = await apiFetch<MCPDeclaredProviderLookup>(
        `/agent/action-proposals/${proposal.id}/reconciliation-observations/${observationId}/declared-correlation`,
      );
      setProviderCorrelationRead({ proposalId: proposal.id, observationId, result });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to inspect declared provider correlation");
    } finally {
      setProviderCorrelationBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1380px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700"
              aria-label="Back to AI operator"
            >
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">Governed actions</h1>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Peer review for exact plans paused inside durable investigations.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <Link href="/settings/change-policy">
                <SlidersHorizontal className="size-3.5" /> Risk policies
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadProposals()}>
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} /> Refresh
            </Button>
          </div>
        </header>

        {error ? (
          <div className="mt-5 flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {error}
          </div>
        ) : null}

        <section className="mt-6 grid gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-muted-foreground">Awaiting peer review</p>
            <p className="mt-2 text-2xl font-semibold">{pendingCount}</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-muted-foreground">Four-eyes rule</p>
            <p className="mt-2 text-sm font-semibold">Requester cannot approve</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-medium text-muted-foreground">Resume behavior</p>
            <p className="mt-2 text-sm font-semibold">Same LangGraph thread</p>
          </div>
        </section>

        <div className="mt-5 grid items-start gap-5 lg:grid-cols-[360px_minmax(0,1fr)]">
          <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-100 px-5 py-4">
              <h2 className="text-sm font-semibold">Action queue</h2>
              <p className="mt-1 text-[11px] text-muted-foreground">Pending plans appear first.</p>
            </div>
            <div className="max-h-[680px] overflow-y-auto p-2">
              {loading && !proposals.length ? (
                <div className="grid min-h-40 place-items-center"><Loader2 className="size-5 animate-spin text-violet-500" /></div>
              ) : proposals.length ? (
                [...proposals]
                  .sort((left, right) => Number(right.status === "pending") - Number(left.status === "pending"))
                  .map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => {
                        setSelectedId(item.id);
                        clearDispositionSnapshot();
                        setReason("");
                        setLookupCallId("");
                        setLookupReason("");
                        setVerificationCallId("");
                        setVerificationReason("");
                        setVerificationRead(null);
                        setIndependentReviewTargetId(null);
                        setIndependentReviewReason("");
                        setReviewTargetId(null);
                        setReviewReason("");
                      }}
                      className={cn(
                        "w-full rounded-xl px-3 py-3 text-left hover:bg-slate-50",
                        item.id === selectedId && "bg-violet-50 hover:bg-violet-50",
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="line-clamp-2 text-xs font-semibold leading-5 text-slate-700">{item.purpose}</p>
                        <Badge variant="outline" className={cn("shrink-0 capitalize", statusTone(item.status))}>{item.status}</Badge>
                      </div>
                      <p className="mt-2 truncate font-mono text-[9px] text-muted-foreground">{item.tool_id}</p>
                      {item.rollback_of_change_plan_id ? <p className="mt-1 text-[9px] font-semibold text-red-600">Rollback · {item.approved_by === "system.rollback_preapproval" ? "separate grant" : "separate approval"}</p> : null}
                      <p className="mt-1 text-[9px] text-muted-foreground">{item.requested_by} · {relativeTime(item.requested_at)}</p>
                    </button>
                  ))
              ) : (
                <div className="px-5 py-12 text-center">
                  <CheckCircle2 className="mx-auto size-8 text-emerald-500" />
                  <p className="mt-3 text-sm font-semibold">No governed actions</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">State-changing requests will pause here.</p>
                </div>
              )}
            </div>
          </section>

          <section className="min-h-[520px] rounded-2xl border border-slate-200 bg-white shadow-sm">
            {selected ? (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Exact action plan</p>
                    <h2 className="mt-2 text-lg font-semibold tracking-tight">{selected.purpose}</h2>
                  </div>
                  <Badge variant="outline" className={cn("capitalize", statusTone(selected.status))}>{selected.status}</Badge>
                </div>
                <div className="space-y-5 p-5 sm:p-6">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl bg-slate-50 p-4">
                      <div className="flex items-center gap-2 text-xs font-semibold"><UserRoundCheck className="size-4 text-violet-600" /> Requester</div>
                      <p className="mt-2 text-sm">{selected.requested_by}</p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">{selected.requested_by_principal_id || "development identity"}</p>
                    </div>
                    <div className="rounded-xl bg-slate-50 p-4">
                      <div className="flex items-center gap-2 text-xs font-semibold"><Clock className="size-4 text-sky-600" /> Investigation</div>
                      <Link href="/" className="mt-2 block truncate font-mono text-xs text-violet-700 hover:underline">{selected.investigation_id}</Link>
                      <p className="mt-1 text-[9px] text-muted-foreground">Iteration {selected.iteration}</p>
                    </div>
                  </div>

                  <div>
                    <p className="text-xs font-semibold">Proposed arguments</p>
                    <pre className="mt-2 max-h-72 overflow-auto rounded-xl bg-[#182134] p-4 text-[11px] leading-5 text-slate-200">{JSON.stringify(selected.arguments, null, 2)}</pre>
                  </div>

                  {governanceLoading ? (
                    <div className="grid min-h-24 place-items-center rounded-xl border border-slate-200"><Loader2 className="size-4 animate-spin text-violet-500" /></div>
                  ) : rollbackContext ? (
                    <div className="rounded-xl border border-red-200 bg-red-50/60 p-4">
                      <div className="flex items-center gap-2 text-xs font-semibold text-red-950"><AlertTriangle className="size-4 text-red-600" /> Separate rollback boundary</div>
                      <p className="mt-2 text-[10px] leading-5 text-red-800">This action is bound to the frozen rollback Tool and target for the parent plan. It needs its own peer decision or independently qualified recovery grant; original primary approval never authorizes it.</p>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        <div className="rounded-lg border border-red-100 bg-white p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Parent plan</p><p className="mt-1 break-all font-mono text-[9px] text-slate-600">{rollbackContext.id}</p><p className="mt-1 text-[9px] font-semibold text-red-700">{rollbackContext.status.replaceAll("_", " ")}</p></div>
                        <div className="rounded-lg border border-red-100 bg-white p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Frozen targets</p><pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[9px] text-slate-600">{JSON.stringify(rollbackContext.target_snapshot, null, 2)}</pre></div>
                      </div>
                      <p className="mt-3 break-all font-mono text-[8px] text-red-700">{rollbackContext.plan_hash}</p>
                    </div>
                  ) : changePlan ? (
                    <div className="rounded-xl border border-violet-200 bg-violet-50/40 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2 text-xs font-semibold text-violet-950"><CalendarRange className="size-4 text-violet-600" /> Evidence-gated change plan</div>
                          <p className="mt-1 text-[10px] text-violet-700">Frozen Tool versions, target identity, dry-run, peer approval, post-check, and rollback.</p>
                        </div>
                        <div className="flex gap-1.5"><Badge variant="outline" className="border-violet-200 bg-white text-[9px] uppercase text-violet-700">{changePlan.risk_class} risk</Badge><Badge variant="outline" className="border-slate-200 bg-white text-[9px] text-slate-600">{changePlan.status.replaceAll("_", " ")}</Badge></div>
                      </div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        <div className="rounded-lg border border-violet-100 bg-white p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Frozen targets</p><pre className="mt-1.5 whitespace-pre-wrap break-all font-mono text-[10px] text-slate-600">{JSON.stringify(changePlan.target_snapshot, null, 2)}</pre>{changePlan.tool_contract_snapshot.authorization_target_paths && Object.keys(changePlan.tool_contract_snapshot.authorization_target_paths).length > 0 ? <><p className="mt-2 text-[8px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">Scope bindings</p><pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[8px] text-muted-foreground">{JSON.stringify(changePlan.tool_contract_snapshot.authorization_target_paths, null, 2)}</pre></> : null}</div>
                        <div className="rounded-lg border border-violet-100 bg-white p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Idempotency key hash</p><p className="mt-1.5 break-all font-mono text-[9px] text-muted-foreground">{changePlan.idempotency_key_hash}</p></div>
                      </div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                        {(["precheck", "dry_run", "postcheck", "rollback", ...(changePlan.tool_contract_snapshot.steps.rollback_check ? ["rollback_check"] : [])] as ChangeStage[]).map((stage) => {
                          const evidence = [...changePlan.evidence].reverse().find((item) => item.stage === stage);
                          const call = eligibleCall(stage);
                          const phaseAllowed = (stage === "precheck" || stage === "dry_run")
                            ? selected.status === "pending"
                            : stage === "rollback_check"
                              ? changePlan.status === "awaiting_rollback_check"
                              : stage === "postcheck"
                              ? changePlan.status === "awaiting_postcheck"
                              : changePlan.status === "rollback_required";
                          const summary = evidence?.evidence_snapshot.summary;
                          return <div key={stage} className="rounded-lg border border-violet-100 bg-white p-3"><div className="flex items-center justify-between gap-2"><p className="text-[10px] font-semibold capitalize text-slate-700">{stage.replace("_", " ")}</p>{evidence ? <Badge variant="outline" className={cn("text-[8px]", evidence.passed ? "border-emerald-200 text-emerald-700" : "border-red-200 text-red-700")}>{evidence.passed ? "passed" : "failed"}</Badge> : <Badge variant="outline" className="text-[8px] text-muted-foreground">missing</Badge>}</div><p className="mt-1 truncate font-mono text-[8px] text-muted-foreground">{stageTool(stage)?.tool_name}</p>{summary && Object.keys(summary).length > 0 ? <pre className="mt-2 overflow-auto rounded-md bg-slate-50 p-2 font-mono text-[8px] leading-4 text-slate-600">{JSON.stringify(summary, null, 2)}</pre> : null}{call && phaseAllowed ? <Button variant="outline" size="sm" className="mt-2 h-7 w-full text-[9px]" onClick={() => void bindEvidence(stage)} disabled={!governanceReason.trim() || governanceBusy !== null}>{governanceBusy === stage ? <Loader2 className="animate-spin" /> : null} Bind latest call</Button> : null}</div>;
                        })}
                      </div>
                      {selected.status === "pending" ? <div className="mt-3 grid gap-2 sm:grid-cols-[1fr_1fr_auto]"><Input type="datetime-local" value={windowStart} onChange={(event) => setWindowStart(event.target.value)} className="bg-white text-xs" aria-label="Maintenance window start" /><Input type="datetime-local" value={windowEnd} onChange={(event) => setWindowEnd(event.target.value)} className="bg-white text-xs" aria-label="Maintenance window end" /><Button variant="outline" onClick={() => void saveWindow()} disabled={!windowStart || !windowEnd || !governanceReason.trim() || governanceBusy !== null}>{governanceBusy === "window" ? <Loader2 className="animate-spin" /> : <CalendarRange />} Save window</Button></div> : null}
                      {(selected.status === "pending" || changePlan.status === "awaiting_postcheck" || changePlan.status === "rollback_required" || changePlan.status === "awaiting_rollback_check") ? <Textarea value={governanceReason} onChange={(event) => setGovernanceReason(event.target.value)} placeholder="Reason for binding evidence or changing the maintenance window" className="mt-3 min-h-16 bg-white text-xs" /> : null}
                      {changePlan.evidence.some((item) => item.stage === "rollback") ? <p className="mt-3 text-[10px] text-slate-600">{changePlan.tool_contract_snapshot.steps.rollback_check ? (changePlan.status === "rolled_back" ? "Original state restored by a separate read-only check. The original remediation still failed." : "Restoration is not verified until the read-only rollback check passes.") : "Legacy rollback declaration only; original-state restoration was not independently checked."}</p> : null}
                      <div className="mt-3 rounded-lg bg-white px-3 py-2"><p className="text-[9px] text-muted-foreground">Current evidence revision hash</p><p className="mt-1 break-all font-mono text-[9px] text-muted-foreground">{changePlan.plan_hash}</p>{changePlan.approved_plan_hash ? <><p className="mt-2 text-[9px] text-muted-foreground">Immutable approval-bound change-plan hash</p><p className="mt-1 break-all font-mono text-[9px] text-muted-foreground">{changePlan.approved_plan_hash}</p></> : null}</div>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-[10px] text-muted-foreground">Legacy exact-plan approval. New production change Tools should publish an <code>icheck.change-tool/v1</code> contract.</div>
                  )}

                  <div className="rounded-xl border border-slate-200 p-4">
                    <div className="flex items-center gap-2 text-xs font-semibold"><Fingerprint className="size-4 text-muted-foreground" /> Approval-bound plan hash</div>
                    <p className="mt-2 break-all font-mono text-[10px] leading-5 text-muted-foreground">{selected.plan_hash}</p>
                    <p className="mt-2 text-[10px] text-muted-foreground">Changing the tool, arguments, or purpose invalidates the decision.</p>
                  </div>

                  {selected.status === "executing" ? (
                    <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs text-amber-950" role="status">
                      <p className="font-semibold">Action outcome not yet confirmed</p>
                      <p className="mt-1 leading-5">{selectedInvestigationStatus && ["escalated", "failed", "cancelled"].includes(selectedInvestigationStatus) ? "The Investigation ended while this action remains executing. The external effect may have occurred; independent reconciliation is required." : "This action has started. A lost result must not be treated as a failed send or permission to retry."} Do not repeat the action or claim success from this status alone.</p>
                      {selected.tool_call_id ? <p className="mt-2 break-all">Provider lookup Tool-call ID: <span className="select-all font-mono">{selected.tool_call_id}</span></p> : <p className="mt-2">No exact Tool-call ID is retained for this action; review its Investigation history before any disposition.</p>}
                      <Link href={`/?investigation=${encodeURIComponent(selected.investigation_id)}`} className="mt-2 inline-block underline">Open Investigation evidence</Link>
                      {selectedInvestigationStatus && ["escalated", "failed", "cancelled"].includes(selectedInvestigationStatus) ? (
                        <div className="mt-3">
                          <Button variant="outline" size="sm" disabled={reconciliationLoading} onClick={() => void loadReconciliationPacket(selected)}>
                            {reconciliationLoading ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Read-only reconciliation context
                          </Button>
                          {selectedReconciliationPacket ? (
                            <div className="mt-2 rounded-lg border border-amber-200 bg-white p-3 text-[10px]">
                              <p className="font-semibold">Original provider outcome: unknown · automatic retry: blocked</p>
                              <p className="mt-1 break-all font-mono">{selectedReconciliationPacket.current_tool_name} · {selectedReconciliationPacket.provider_lookup_key}</p>
                              <p className="mt-1">Tool call started {new Date(selectedReconciliationPacket.call_started_at).toLocaleString()}</p>
                              <p className="mt-1 break-all">Frozen activation: <span className="font-mono">{selectedReconciliationPacket.artifact_activation_id || "not retained for this call"}</span></p>
                              <p className="mt-1">Designated read-only lookup: <span className="font-mono">{selectedReconciliationPacket.designated_lookup_tool_name || "not frozen on this write"}</span></p>
                              {selectedSummary ? (
                                <div className={cn("mt-2 rounded border p-2", selectedSummary.contradictory_determinate_reports ? "border-rose-300 bg-rose-50 text-rose-900" : "border-slate-200 bg-slate-50")}>
                                  <p>{selectedSummary.observation_count} lookup observations · {selectedSummary.reviewed_count} independent reviews</p>
                                  {selectedSummary.contradictory_determinate_reports ? (
                                    <p className="font-semibold">Conflicting accepted provider reports: applied and not applied. The original outcome is still unknown; do not retry or mark delivery verified.</p>
                                  ) : selectedSummary.accepted_provider_reports.length > 0 ? (
                                    <p>Accepted evidence reports: {selectedSummary.accepted_provider_reports.join(", ")}. Original outcome remains unknown; retry and delivery verification remain blocked.</p>
                                  ) : <p>No accepted lookup evidence. Original outcome remains unknown.</p>}
                                </div>
                              ) : null}
                              {selectedIndependentSummary ? (
                                <div className={cn("mt-2 rounded border p-2", selectedIndependentSummary.divergent_determinate_target_states || selectedIndependentSummary.divergent_determinate_recipient_receipts ? "border-rose-300 bg-rose-50 text-rose-900" : "border-slate-200 bg-slate-50")}>
                                  <p>{selectedIndependentSummary.observation_count} visible target or recipient observations · {selectedIndependentSummary.reviewed_count} reviews</p>
                                  <p>Accepted target states: {selectedIndependentSummary.accepted_target_states.join(", ") || "none"} · recipient receipt states: {selectedIndependentSummary.accepted_recipient_receipt_states.join(", ") || "none"}.</p>
                                  {selectedIndependentSummary.divergent_determinate_target_states || selectedIndependentSummary.divergent_determinate_recipient_receipts ? (
                                    <p className="font-semibold">Accepted observations differ. Check timing and source consistency before any decision; the original write remains unknown and retry is blocked.</p>
                                  ) : <p>These observations do not decide the original write or verify delivery.</p>}
                                </div>
                              ) : null}
                              <div className="mt-2 rounded border border-slate-200 bg-slate-50 p-2">
                                <Button variant="outline" size="sm" disabled={dispositionBusy || observationBusy || reviewBusy || independentObservationBusy || independentReviewBusy} onClick={() => void inspectCompleteDispositionEvidence(selected)}>
                                  {dispositionBusy ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Check complete evidence set
                                </Button>
                                <p className="mt-1">This checks all four evidence lists and your access to every referenced Investigation. It is a point-in-time read, not a final action decision.</p>
                                {selectedDispositionError ? (
                                  <p className="mt-2 font-semibold text-rose-800" role="alert">Complete review unavailable: {selectedDispositionError}. The original write remains unknown; do not retry or mark delivery verified.</p>
                                ) : null}
                                {selectedDispositionSnapshot ? (
                                  <>
                                  <div className="mt-2 space-y-1" role="status">
                                    <p>{selectedDispositionSnapshot.provider.observation_count} provider observations and {selectedDispositionSnapshot.provider.reviewed_count} reviews · {selectedDispositionSnapshot.independent.observation_count} target or recipient observations and {selectedDispositionSnapshot.independent.reviewed_count} reviews were included.</p>
                                    <p>Current frozen-contract checks: {selectedDispositionSnapshot.contract_qualification.contract_qualified_provider_count}/{selectedDispositionSnapshot.contract_qualification.accepted_provider_count} accepted provider observations and {selectedDispositionSnapshot.contract_qualification.contract_qualified_independent_count}/{selectedDispositionSnapshot.contract_qualification.accepted_independent_count} accepted target or recipient observations qualify as of {new Date(selectedDispositionSnapshot.contract_qualification.checked_at).toLocaleString()}.</p>
                                    {selectedDispositionSnapshot.contract_qualification.unqualified_provider_observation_ids.length > 0 || selectedDispositionSnapshot.contract_qualification.unqualified_independent_observation_ids.length > 0 ? (
                                      <p className="font-semibold text-rose-800">Some accepted evidence is not currently contract-qualified. It may be stale, lack a frozen declaration or no longer match the retained Tool call; inspect the observations below.</p>
                                    ) : null}
                                    <p>{selectedDispositionSnapshot.native_transactional_lock ? "PostgreSQL proposal lock used." : "SQLite preview only; no native transactional lock."} Contract qualification does not verify provider correlation or external effect. The original write is still unknown; retry, delivery verification and final disposition remain blocked.</p>
                                    {selectedDispositionSnapshot.provider.contradictory_determinate_reports || selectedDispositionSnapshot.independent.divergent_determinate_target_states || selectedDispositionSnapshot.independent.divergent_determinate_recipient_receipts ? (
                                      <p className="font-semibold text-rose-800">Accepted evidence conflicts; investigate the source and timing before any future decision.</p>
                                    ) : null}
                                  </div>
                                  <MCPUnresolvedCustody
                                    key={selected.id}
                                    proposalId={selected.id}
                                    nativeLocking={selectedDispositionSnapshot.native_transactional_lock}
                                  />
                                  </>
                                ) : null}
                              </div>
                              <p className="mt-2">Run a separate read-only provider lookup using this exact Tool-call ID. Recording its result does not resolve the original action or authorize a retry.</p>
                              <div className="mt-3 space-y-2 border-t border-amber-100 pt-3">
                                <Input aria-label="Read-only lookup Tool-call ID" placeholder="Completed read-only lookup Tool-call ID" value={lookupCallId} onChange={(event) => setLookupCallId(event.target.value)} />
                                <Textarea aria-label="Lookup review reason" placeholder="Why does this independent lookup match the original write?" value={lookupReason} onChange={(event) => setLookupReason(event.target.value)} maxLength={1000} />
                                <Button size="sm" disabled={observationBusy || !lookupCallId.trim() || lookupReason.trim().length < 10} onClick={() => void recordLookupObservation(selected)}>
                                  {observationBusy ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Record lookup evidence
                                </Button>
                              </div>
                              <div className="mt-3 space-y-2 border-t border-amber-100 pt-3">
                                <p className="font-semibold">Independent target or recipient state</p>
                                <p>A separate read-only verifier on another MCP server must match the approved target. This preview cannot finish the original write or verify delivery.</p>
                                <Input aria-label="Independent verifier Tool-call ID" placeholder="Completed independent verifier Tool-call ID" value={verificationCallId} onChange={(event) => {
                                  setVerificationCallId(event.target.value);
                                  setVerificationRead(null);
                                }} />
                                <Button variant="outline" size="sm" disabled={verificationBusy || !verificationCallId.trim()} onClick={() => void qualifyIndependentVerification(selected)}>
                                  {verificationBusy ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Inspect independent evidence
                                </Button>
                                {selectedVerification ? (
                                  <div className="rounded border border-slate-200 bg-slate-50 p-2" role="status">
                                    <p className="font-semibold">Observed {selectedVerification.verification_kind.replaceAll("_", " ")}: {selectedVerification.observed_target_state}</p>
                                    <p>Exact target fields matched: {selectedVerification.bound_value_count} · observed {new Date(selectedVerification.observed_at).toLocaleString()}</p>
                                    {selectedVerification.evidence_reference ? <p className="break-all font-mono">Evidence reference: {selectedVerification.evidence_reference}</p> : null}
                                    <p className="font-semibold">Original write: unknown · automatic retry: blocked · delivery: unverified</p>
                                  </div>
                                ) : null}
                                {selectedVerification ? (
                                  <div className="space-y-2">
                                    <Textarea aria-label="Independent observation reason" placeholder="Why does this read-only observation match the approved target?" value={verificationReason} onChange={(event) => setVerificationReason(event.target.value)} maxLength={1000} />
                                    <Button size="sm" disabled={independentObservationBusy || verificationReason.trim().length < 10} onClick={() => void recordIndependentObservation(selected)}>
                                      {independentObservationBusy ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Retain observation only
                                    </Button>
                                  </div>
                                ) : null}
                                {selectedIndependentObservations.length > 0 ? (
                                  <div className="space-y-2 border-t border-slate-200 pt-2">
                                    <p className="font-semibold">Retained independent observations (not a final decision)</p>
                                    {selectedIndependentObservations.map((item) => (
                                      <div key={item.id} className="rounded border border-slate-200 bg-slate-50 p-2">
                                        <p>{item.verification_kind.replaceAll("_", " ")} · {item.observed_target_state} · {new Date(item.observed_at).toLocaleString()}</p>
                                        <p className="break-all font-mono">Verifier call: {item.verification_tool_call_id}</p>
                                        {item.evidence_reference ? <p className="break-all">Reference: {item.evidence_reference}</p> : null}
                                        <p>Recorded by {item.recorded_by}. {item.reason}</p>
                                        <p className="font-semibold">Original outcome unknown; no retry or verified delivery.</p>
                                        {selectedIndependentReviews.find((review) => review.observation_id === item.id) ? (
                                          <div className="mt-2 border-t border-slate-200 pt-2">
                                            {selectedIndependentReviews.filter((review) => review.observation_id === item.id).map((review) => (
                                              <p key={review.id}>Evidence review: {review.decision} · {review.reviewed_by}. {review.reason} The original write is still unknown.</p>
                                            ))}
                                          </div>
                                        ) : (
                                          <div className="mt-2 space-y-2 border-t border-slate-200 pt-2">
                                            <Button variant="outline" size="sm" onClick={() => {
                                              setIndependentReviewTargetId(independentReviewTargetId === item.id ? null : item.id);
                                              setIndependentReviewDecision("inconclusive");
                                              setIndependentReviewReason("");
                                            }}>Review independent evidence</Button>
                                            {independentReviewTargetId === item.id ? (
                                              <div className="space-y-2">
                                                <p>The recorder cannot review their own row. Accepting evidence does not verify delivery or settle the lost write.</p>
                                                <select aria-label="Independent evidence review decision" className="w-full rounded-md border border-slate-200 bg-white p-2" value={independentReviewDecision} onChange={(event) => setIndependentReviewDecision(event.target.value as "accept" | "reject" | "inconclusive")}>
                                                  <option value="inconclusive">Inconclusive evidence</option>
                                                  <option value="accept">Accept evidence only</option>
                                                  <option value="reject">Reject evidence</option>
                                                </select>
                                                <Textarea aria-label="Independent evidence review reason" placeholder="Explain the review of this exact verifier result" value={independentReviewReason} onChange={(event) => setIndependentReviewReason(event.target.value)} maxLength={1000} />
                                                <Button size="sm" disabled={independentReviewBusy || independentReviewReason.trim().length < 10} onClick={() => void reviewIndependentObservation(selected, item.id)}>
                                                  {independentReviewBusy ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />} Record evidence review
                                                </Button>
                                              </div>
                                            ) : null}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                ) : null}
                              </div>
                              {selectedObservations.length > 0 ? (
                                <div className="mt-3 space-y-2 border-t border-amber-100 pt-3">
                                  <p className="font-semibold">Recorded independent observations (not an action decision)</p>
                                  {selectedObservations.map((item) => (
                                    <div key={item.id} className="rounded border border-slate-200 bg-slate-50 p-2">
                                      <p className="font-semibold">Provider reported: {item.provider_outcome.replaceAll("_", " ")}</p>
                                      <p className="break-all font-mono">Lookup call: {item.lookup_tool_call_id}</p>
                                      {item.provider_reference ? <p className="break-all">Provider reference: {item.provider_reference}</p> : null}
                                      <p>Observed {new Date(item.observed_at).toLocaleString()} · recorded by {item.recorded_by}</p>
                                      <p>{item.reason}</p>
                                      {selectedReviews.find((review) => review.observation_id === item.id) ? (
                                        <div className="mt-2 border-t border-slate-200 pt-2">
                                          {selectedReviews.filter((review) => review.observation_id === item.id).map((review) => (
                                            <p key={review.id}>Independent evidence review: {review.decision} · {review.reviewed_by}. {review.reason}</p>
                                          ))}
                                          {selectedReviews.some((review) => review.observation_id === item.id && review.decision === "accept") ? (
                                            <div className="mt-2 space-y-2">
                                              <Button variant="outline" size="sm" disabled={providerCorrelationBusy !== null} onClick={() => void inspectDeclaredProviderCorrelation(selected, item.id)}>
                                                {providerCorrelationBusy === item.id ? <Loader2 className="size-3.5 animate-spin" /> : <FileSearch className="size-3.5" />} Check frozen correlation declaration
                                              </Button>
                                              {providerCorrelationRead?.proposalId === selected.id && providerCorrelationRead.observationId === item.id ? (
                                                <div className="rounded border border-amber-200 bg-amber-50 p-2" role="status">
                                                  <p>Lookup reported {providerCorrelationRead.result.reported_provider_outcome}; its frozen consistency window is {providerCorrelationRead.result.consistency_window_seconds} seconds.</p>
                                                  <p className="font-semibold">The provider’s durable use of {providerCorrelationRead.result.correlation_key} is not yet verified. This check does not authorize a final decision or retry.</p>
                                                </div>
                                              ) : null}
                                            </div>
                                          ) : null}
                                        </div>
                                      ) : (
                                        <div className="mt-2 border-t border-slate-200 pt-2">
                                          <Button variant="outline" size="sm" onClick={() => {
                                            setReviewTargetId(reviewTargetId === item.id ? null : item.id);
                                            setReviewDecision("inconclusive");
                                            setReviewReason("");
                                          }}>Review lookup evidence</Button>
                                          {reviewTargetId === item.id ? (
                                            <div className="mt-2 space-y-2">
                                              <p>The recorder cannot review their own evidence. Accepting evidence does not settle the original write.</p>
                                              <select aria-label="Lookup evidence review decision" className="w-full rounded-md border border-slate-200 bg-white p-2" value={reviewDecision} onChange={(event) => setReviewDecision(event.target.value as "accept" | "reject" | "inconclusive")}>
                                                <option value="inconclusive">Inconclusive evidence</option>
                                                <option value="accept">Accept lookup evidence</option>
                                                <option value="reject">Reject lookup evidence</option>
                                              </select>
                                              <Textarea aria-label="Independent review reason" placeholder="Explain the independent review of this exact lookup" value={reviewReason} onChange={(event) => setReviewReason(event.target.value)} maxLength={1000} />
                                              <Button size="sm" disabled={reviewBusy || reviewReason.trim().length < 10} onClick={() => void reviewLookupObservation(selected, item.id)}>
                                                {reviewBusy ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />} Record independent review
                                              </Button>
                                            </div>
                                          ) : null}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              ) : null}
                            </div>
                          ) : null}
                        </div>
                      ) : null}
                    </div>
                  ) : null}

                  {selected.rollback_of_change_plan_id ? <RollbackAuthorityReceipt key={selected.id} proposalId={selected.id} automatic={selected.approved_by === "system.rollback_preapproval"} /> : null}
                  {selected.status === "pending" ? (
                    <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
                      <p className="text-xs font-semibold text-amber-900">Peer decision</p>
                      <p className="mt-1 text-[10px] text-amber-800">The backend rejects self-approval and stale hashes.</p>
                      <Textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Record the operational reason." className="mt-3 min-h-24 bg-white text-sm" />
                      <div className="mt-3 flex justify-end gap-2">
                        <Button variant="outline" onClick={() => void decide("reject")} disabled={!reason.trim() || submitting !== null}>
                          {submitting === "reject" ? <Loader2 className="animate-spin" /> : <XCircle />} Reject
                        </Button>
                        <Button onClick={() => void decide("approve")} disabled={!reason.trim() || submitting !== null || Boolean(changePlan && changePlan.status !== "ready_for_approval")} className="bg-violet-600 text-white hover:bg-violet-700">
                          {submitting === "approve" ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Approve exact plan
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-600">
                      <p className="font-semibold capitalize">{selected.status} by {selected.approved_by || "runtime"}</p>
                      {selected.decision_reason ? <p className="mt-2 leading-5">{selected.decision_reason}</p> : null}
                      {selected.error ? <p className="mt-2 text-red-700">{selected.error}</p> : null}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="grid min-h-[520px] place-items-center text-center">
                <div><ShieldCheck className="mx-auto size-10 text-slate-300" /><p className="mt-3 text-sm font-semibold">Select an action plan</p></div>
              </div>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
