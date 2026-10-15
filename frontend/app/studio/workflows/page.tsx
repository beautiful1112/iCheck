"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Download,
  GitBranch,
  Loader2,
  Play,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

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
};

type PublishedReport = {
  artifact_id: string;
  name: string;
  description: string;
  version_id: string;
  version: number;
  published_at: string;
  content_hash: string;
  report_title: string;
  lookback_minutes: number;
  section_count: number;
};

type TriggerActivation = {
  id: string;
  artifact_version_id: string;
  event_type: string;
  route_purpose: string;
  run_as_principal_id: string | null;
  authorization_scope: Record<string, unknown>;
  input_mapping: Record<string, string>;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
};

type TriggerEvent = {
  id: string;
  activation_id: string;
  alert_id: string;
  status: string;
  attempt_count: number;
  error_type: string | null;
  error_sha256: string | null;
  created_at: string;
  updated_at: string;
};

type ScheduleExclusionWindow = {
  id: string;
  name: string;
  starts_at: string;
  ends_at: string;
};

type ScheduleActivation = {
  id: string;
  artifact_version_id: string;
  cron_expression: string;
  timezone: string;
  route_purpose: string;
  run_as_principal_id: string | null;
  authorization_scope: Record<string, unknown>;
  workflow_input: Record<string, unknown>;
  report_artifact_version_id: string | null;
  report_input_key: string | null;
  report_attachment_format: string | null;
  report_delivery_tool_name: string | null;
  report_delivery_tool_argument: string | null;
  report_delivery_provider_key: string | null;
  report_delivery_receipt_mapping: Record<string, string>;
  misfire_grace_seconds: number;
  exclusion_windows: ScheduleExclusionWindow[];
  excluded_runs: number;
  last_excluded_at: string | null;
  next_fire_at: string;
  last_fire_at: string | null;
  last_misfire_at: string | null;
  missed_runs: number;
  revision: number;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
};

type ScheduleEvent = {
  id: string;
  activation_id: string;
  scheduled_for: string;
  status: string;
  attempt_count: number;
  skip_reason: string | null;
  exclusion_window_id: string | null;
  error_type: string | null;
  error_sha256: string | null;
  created_at: string;
  updated_at: string;
  investigation_id: string | null;
  investigation_status: string | null;
  report_delivery_tool_call_id: string | null;
  report_delivery_state: "not_dispatched" | "pending" | "reconciliation_required" | "verified" | "unverified" | "legacy_unverified" | null;
};

type ReportDeliveryReceipt = {
  id: string;
  schedule_event_id: string;
  activation_id: string;
  investigation_id: string;
  workflow_artifact_version_id: string;
  workflow_content_hash: string;
  report_artifact_version_id: string;
  report_content_hash: string;
  report_instance_id: string | null;
  report_attachment_id: string | null;
  report_attachment_sha256: string | null;
  provider_key: string;
  delivery_tool_name: string;
  delivery_id: string;
  delivery_url: string | null;
  delivery_status: string | null;
  source_tool_call_id: string;
  delivered_at: string;
  verification_tool_call_id: string | null;
  verified_at: string | null;
  created_at: string;
};

type SituationIntegration = {
  id: string;
  artifact_version_id: string;
  channel_kind: "ticket" | "collaboration";
  event_type: string;
  route_purpose: string;
  run_as_principal_id: string | null;
  authorization_scope: Record<string, unknown>;
  input_mapping: Record<string, string>;
  provider_key: string;
  remote_reference_tool_name: string | null;
  remote_reference_mapping: Record<string, string>;
  inbound_enabled: boolean;
  inbound_key_id: string | null;
  inbound_public_key_sha256: string | null;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
};

type SituationIntegrationReference = {
  id: string;
  integration_event_id: string;
  binding_id: string;
  situation_id: string;
  provider_key: string;
  remote_id: string;
  remote_url: string | null;
  remote_status: string | null;
  remote_updated_at: string | null;
  updated_at: string;
};

type SituationIntegrationInboundEvent = {
  id: string;
  binding_id: string;
  reference_id: string;
  provider_event_id: string;
  event_type: string;
  remote_status: string;
  remote_updated_at: string;
  signature_key_id: string;
  outcome: "accepted" | "ignored_stale";
  received_at: string;
};

type SituationIntegrationEvent = {
  id: string;
  binding_id: string;
  situation_id: string;
  situation_event_id: string;
  event_type: string;
  status: string;
  attempt_count: number;
  error_type: string | null;
  error_sha256: string | null;
  created_at: string;
  updated_at: string;
};

function starterMapping(schema: Record<string, unknown>, triggerType?: string) {
  const properties = schema.properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) return {};
  return Object.fromEntries(
    Object.keys(properties).map((name) => {
      if (triggerType === "situation") {
        if (name === "situation_id") return [name, "situation.id"];
        if (["title", "summary", "status", "severity", "priority_score", "primary_entity_type", "primary_entity_id", "alert_count", "active_alert_count", "occurrence_count", "first_seen", "last_seen"].includes(name)) return [name, `situation.${name}`];
        if (name === "event_type") return [name, "event.event_type"];
        return [name, `event.details.${name}`];
      }
      if (name === "severity") return [name, "alert.severity"];
      if (name === "alert_id") return [name, "alert.id"];
      if (name === "event_type") return [name, "alert.event_type"];
      if (name === "entity_type") return [name, "alert.entity_type"];
      if (["device_id", "endpoint_id", "entity_id"].includes(name)) return [name, "alert.entity_id"];
      return [name, `alert.details.${name}`];
    }),
  );
}

function starterInput(schema: Record<string, unknown>) {
  const properties = schema.properties;
  const required = Array.isArray(schema.required) ? schema.required.filter((item): item is string => typeof item === "string") : [];
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) return {};
  return Object.fromEntries(required.map((name) => {
    const property = (properties as Record<string, Record<string, unknown>>)[name] || {};
    if (Array.isArray(property.enum) && property.enum.length > 0) return [name, property.enum[0]];
    if (property.type === "boolean") return [name, false];
    if (property.type === "integer" || property.type === "number") return [name, 0];
    if (property.type === "array") return [name, []];
    if (property.type === "object") return [name, {}];
    return [name, "replace-me"];
  }));
}

function eventTone(status: string) {
  if (status === "succeeded") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "failed") return "border-red-300 bg-red-50 text-red-700";
  if (status === "skipped") return "border-amber-300 bg-amber-50 text-amber-700";
  if (status === "processing") return "border-violet-300 bg-violet-50 text-violet-700";
  return "border-sky-300 bg-sky-50 text-sky-700";
}

export default function WorkflowRuntimePage() {
  const [workflows, setWorkflows] = useState<PublishedWorkflow[]>([]);
  const [reports, setReports] = useState<PublishedReport[]>([]);
  const [activations, setActivations] = useState<TriggerActivation[]>([]);
  const [events, setEvents] = useState<TriggerEvent[]>([]);
  const [scheduleActivations, setScheduleActivations] = useState<ScheduleActivation[]>([]);
  const [scheduleEvents, setScheduleEvents] = useState<ScheduleEvent[]>([]);
  const [reportDeliveryReceipts, setReportDeliveryReceipts] = useState<ReportDeliveryReceipt[]>([]);
  const [situationIntegrations, setSituationIntegrations] = useState<SituationIntegration[]>([]);
  const [situationIntegrationEvents, setSituationIntegrationEvents] = useState<SituationIntegrationEvent[]>([]);
  const [situationIntegrationReferences, setSituationIntegrationReferences] = useState<SituationIntegrationReference[]>([]);
  const [situationInboundEvents, setSituationInboundEvents] = useState<SituationIntegrationInboundEvent[]>([]);
  const [selectedVersionId, setSelectedVersionId] = useState("");
  const selectedVersionIdRef = useRef("");
  const [selectedReportVersionId, setSelectedReportVersionId] = useState("");
  const selectedReportVersionIdRef = useRef("");
  const [reportInputKey, setReportInputKey] = useState("report");
  const [reportAttachmentFormat, setReportAttachmentFormat] = useState("");
  const [reportDeliveryProviderKey, setReportDeliveryProviderKey] = useState("generic");
  const [reportDeliveryReceiptMapping, setReportDeliveryReceiptMapping] = useState('{\n  "delivery_id": "delivery_id"\n}');
  const [routePurpose, setRoutePurpose] = useState("investigation");
  const [runAsPrincipalId, setRunAsPrincipalId] = useState("");
  const [scope, setScope] = useState("{}");
  const [mapping, setMapping] = useState("{}");
  const [channelKind, setChannelKind] = useState<"ticket" | "collaboration">("ticket");
  const [providerKey, setProviderKey] = useState("generic");
  const [remoteReferenceToolName, setRemoteReferenceToolName] = useState("");
  const [remoteReferenceMapping, setRemoteReferenceMapping] = useState("{}");
  const [inboundEnabled, setInboundEnabled] = useState(false);
  const [inboundKeyId, setInboundKeyId] = useState("");
  const [inboundPublicKeyPem, setInboundPublicKeyPem] = useState("");
  const [cronExpression, setCronExpression] = useState("*/15 * * * *");
  const [scheduleTimezone, setScheduleTimezone] = useState("UTC");
  const [scheduleInput, setScheduleInput] = useState("{}");
  const [misfireGraceSeconds, setMisfireGraceSeconds] = useState(300);
  const [exclusionWindows, setExclusionWindows] = useState<ScheduleExclusionWindow[]>([]);
  const [exclusionName, setExclusionName] = useState("");
  const [exclusionStartsAt, setExclusionStartsAt] = useState("");
  const [exclusionEndsAt, setExclusionEndsAt] = useState("");
  const [exclusionReason, setExclusionReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [nextWorkflows, nextReports, nextActivations, nextEvents, nextSchedules, nextScheduleEvents, nextReportDeliveryReceipts, nextSituationIntegrations, nextSituationEvents, nextSituationReferences, nextSituationInboundEvents] = await Promise.all([
        apiFetch<PublishedWorkflow[]>("/workflow-runtime/workflows"),
        apiFetch<PublishedReport[]>("/reports"),
        apiFetch<TriggerActivation[]>("/workflow-runtime/trigger-activations?limit=500"),
        apiFetch<TriggerEvent[]>("/workflow-runtime/trigger-events?limit=500"),
        apiFetch<ScheduleActivation[]>("/workflow-runtime/schedule-activations?limit=500"),
        apiFetch<ScheduleEvent[]>("/workflow-runtime/schedule-events?limit=500"),
        apiFetch<ReportDeliveryReceipt[]>("/workflow-runtime/report-delivery-receipts?limit=500"),
        apiFetch<SituationIntegration[]>("/workflow-runtime/situation-integrations?limit=500"),
        apiFetch<SituationIntegrationEvent[]>("/workflow-runtime/situation-integration-events?limit=500"),
        apiFetch<SituationIntegrationReference[]>("/workflow-runtime/situation-integration-references?limit=500"),
        apiFetch<SituationIntegrationInboundEvent[]>("/workflow-runtime/situation-integration-inbound-events?limit=500"),
      ]);
      setWorkflows(nextWorkflows);
      setReports(nextReports);
      setActivations(nextActivations);
      setEvents(nextEvents);
      setScheduleActivations(nextSchedules);
      setScheduleEvents(nextScheduleEvents);
      setReportDeliveryReceipts(nextReportDeliveryReceipts);
      setSituationIntegrations(nextSituationIntegrations);
      setSituationIntegrationEvents(nextSituationEvents);
      setSituationIntegrationReferences(nextSituationReferences);
      setSituationInboundEvents(nextSituationInboundEvents);
      const nextSelectedVersionId = selectedVersionIdRef.current || nextWorkflows.find((item) => item.trigger.trigger_type !== "manual")?.version_id || nextWorkflows[0]?.version_id || "";
      const nextSelectedWorkflow = nextWorkflows.find((item) => item.version_id === nextSelectedVersionId);
      const nextSelectedSchedule = nextSchedules.find((item) => item.artifact_version_id === nextSelectedVersionId);
      const nextSelectedReportVersionId = nextSelectedSchedule?.report_artifact_version_id || (nextReports.some((item) => item.version_id === selectedReportVersionIdRef.current) ? selectedReportVersionIdRef.current : "");
      selectedVersionIdRef.current = nextSelectedVersionId;
      selectedReportVersionIdRef.current = nextSelectedReportVersionId;
      setSelectedVersionId(nextSelectedVersionId);
      setSelectedReportVersionId(nextSelectedReportVersionId);
      setReportInputKey(nextSelectedSchedule?.report_input_key || "report");
      setReportAttachmentFormat(nextSelectedSchedule?.report_attachment_format || "");
      setReportDeliveryProviderKey(nextSelectedSchedule?.report_delivery_provider_key || "generic");
      setReportDeliveryReceiptMapping(JSON.stringify(nextSelectedSchedule?.report_delivery_receipt_mapping || { delivery_id: "delivery_id" }, null, 2));
      setMapping(JSON.stringify(nextSelectedWorkflow ? starterMapping(nextSelectedWorkflow.input_schema, nextSelectedWorkflow.trigger.trigger_type) : {}, null, 2));
      setScheduleInput(JSON.stringify(nextSelectedWorkflow ? starterInput(nextSelectedWorkflow.input_schema) : {}, null, 2));
      setExclusionWindows(nextSchedules.find((item) => item.artifact_version_id === nextSelectedVersionId)?.exclusion_windows || []);
      setExclusionReason("");
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load Workflow runtime");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selected = useMemo(
    () => workflows.find((item) => item.version_id === selectedVersionId) || null,
    [selectedVersionId, workflows],
  );
  const selectedActivation = activations.find((item) => item.artifact_version_id === selectedVersionId) || null;
  const selectedSchedule = scheduleActivations.find((item) => item.artifact_version_id === selectedVersionId) || null;
  const selectedSituationIntegration = situationIntegrations.find((item) => item.artifact_version_id === selectedVersionId) || null;
  const selectedEvents = selectedActivation ? events.filter((item) => item.activation_id === selectedActivation.id) : [];
  const selectedScheduleEvents = selectedSchedule ? scheduleEvents.filter((item) => item.activation_id === selectedSchedule.id) : [];
  const selectedReportDeliveryReceipts = selectedSchedule ? reportDeliveryReceipts.filter((item) => item.activation_id === selectedSchedule.id) : [];
  const selectedSituationEvents = selectedSituationIntegration ? situationIntegrationEvents.filter((item) => item.binding_id === selectedSituationIntegration.id) : [];
  const selectedSituationReferences = selectedSituationIntegration ? situationIntegrationReferences.filter((item) => item.binding_id === selectedSituationIntegration.id) : [];
  const selectedSituationInboundEvents = selectedSituationIntegration ? situationInboundEvents.filter((item) => item.binding_id === selectedSituationIntegration.id) : [];

  function chooseReportAttachmentFormat(format: string) {
    setReportAttachmentFormat(format);
    setReportDeliveryReceiptMapping((current) => {
      try {
        const mapping = JSON.parse(current);
        if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) return current;
        if (format) mapping.document_sha256 ||= "document_sha256";
        else delete mapping.document_sha256;
        return JSON.stringify(mapping, null, 2);
      } catch { return current; }
    });
  }

  function chooseWorkflow(versionId: string) {
    selectedVersionIdRef.current = versionId;
    setSelectedVersionId(versionId);
    selectedReportVersionIdRef.current = "";
    setSelectedReportVersionId("");
    setReportInputKey("report");
    setReportAttachmentFormat("");
    setReportDeliveryProviderKey("generic");
    setReportDeliveryReceiptMapping('{\n  "delivery_id": "delivery_id"\n}');
    const workflow = workflows.find((item) => item.version_id === versionId);
    const schedule = scheduleActivations.find((item) => item.artifact_version_id === versionId);
    setMapping(JSON.stringify(workflow ? starterMapping(workflow.input_schema, workflow.trigger.trigger_type) : {}, null, 2));
    setScheduleInput(JSON.stringify(workflow ? starterInput(workflow.input_schema) : {}, null, 2));
    setExclusionWindows(schedule?.exclusion_windows || []);
    setExclusionName("");
    setExclusionStartsAt("");
    setExclusionEndsAt("");
    setExclusionReason("");
    setScope("{}");
    setRunAsPrincipalId("");
    setProviderKey("generic");
    setRemoteReferenceToolName("");
    setRemoteReferenceMapping("{}");
    setInboundEnabled(false);
    setInboundKeyId("");
    setInboundPublicKeyPem("");
    setError(null);
  }

  async function exportReceipt(receipt: ReportDeliveryReceipt) {
    setBusy(`export-receipt-${receipt.id}`);
    setError(null);
    let url: string | null = null;
    try {
      const document = await apiFetch<Record<string, unknown>>(`/workflow-runtime/report-delivery-receipts/${encodeURIComponent(receipt.id)}/export`);
      url = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2)], { type: "application/json" }));
      const anchor = window.document.createElement("a");
      anchor.href = url;
      anchor.download = `icheck-report-receipt-${receipt.id}.json`;
      anchor.click();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Receipt export failed.");
    } finally {
      if (url) URL.revokeObjectURL(url);
      setBusy(null);
    }
  }

  async function activate() {
    if (!selected || selected.trigger.trigger_type !== "alert") return;
    setBusy("activate");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/workflows/${selected.version_id}/trigger-activation`, {
        method: "POST",
        body: JSON.stringify({
          route_purpose: routePurpose,
          run_as_principal_id: runAsPrincipalId.trim() || null,
          authorization_scope: JSON.parse(scope),
          input_mapping: JSON.parse(mapping),
          provider_key: providerKey.trim(),
          remote_reference_tool_name: remoteReferenceToolName.trim() || null,
          remote_reference_mapping: remoteReferenceToolName.trim() ? JSON.parse(remoteReferenceMapping) : {},
          inbound_enabled: inboundEnabled,
          inbound_key_id: inboundEnabled ? inboundKeyId.trim() : null,
          inbound_public_key_pem: inboundEnabled ? inboundPublicKeyPem.trim() : null,
          actor: "capability.publisher",
        }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to activate Workflow trigger");
    } finally {
      setBusy(null);
    }
  }

  async function disable() {
    if (!selectedActivation) return;
    setBusy("disable");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/trigger-activations/${selectedActivation.id}/disable`, {
        method: "POST",
        body: JSON.stringify({ actor: "capability.publisher" }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to disable Workflow trigger");
    } finally {
      setBusy(null);
    }
  }

  async function activateSchedule() {
    if (!selected || selected.trigger.trigger_type !== "schedule") return;
    setBusy("activate-schedule");
    setError(null);
    try {
      const workflowInput = JSON.parse(scheduleInput) as Record<string, unknown>;
      const normalizedReportInputKey = reportInputKey.trim();
      if (selectedReportVersionId) {
        if (!normalizedReportInputKey) throw new Error("Generated report input key is required.");
        delete workflowInput[normalizedReportInputKey];
      }
      await apiFetch(`/workflow-runtime/workflows/${selected.version_id}/schedule-activation`, {
        method: "POST",
        body: JSON.stringify({
          cron_expression: cronExpression,
          timezone: scheduleTimezone,
          route_purpose: routePurpose,
          run_as_principal_id: runAsPrincipalId.trim() || null,
          authorization_scope: JSON.parse(scope),
          workflow_input: workflowInput,
          report_artifact_version_id: selectedReportVersionId || null,
          report_input_key: selectedReportVersionId ? normalizedReportInputKey : null,
          report_attachment_format: selectedReportVersionId ? reportAttachmentFormat || null : null,
          report_delivery_provider_key: selectedReportVersionId ? reportDeliveryProviderKey.trim() : null,
          report_delivery_receipt_mapping: selectedReportVersionId ? JSON.parse(reportDeliveryReceiptMapping) : {},
          misfire_grace_seconds: misfireGraceSeconds,
          exclusion_windows: exclusionWindows,
          actor: "capability.publisher",
        }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to activate Workflow schedule");
    } finally {
      setBusy(null);
    }
  }

  function addExclusionWindow() {
    setError(null);
    const startsAt = new Date(exclusionStartsAt);
    const endsAt = new Date(exclusionEndsAt);
    if (!exclusionName.trim() || Number.isNaN(startsAt.getTime()) || Number.isNaN(endsAt.getTime())) {
      setError("Calendar exclusion needs a name, start, and end.");
      return;
    }
    if (endsAt <= startsAt) {
      setError("Calendar exclusion end must be after its start.");
      return;
    }
    setExclusionWindows((current) => [
      ...current,
      {
        id: `window-${crypto.randomUUID()}`,
        name: exclusionName.trim(),
        starts_at: startsAt.toISOString(),
        ends_at: endsAt.toISOString(),
      },
    ].sort((left, right) => left.starts_at.localeCompare(right.starts_at)));
    setExclusionName("");
    setExclusionStartsAt("");
    setExclusionEndsAt("");
  }

  async function saveScheduleExclusions() {
    if (!selectedSchedule || exclusionReason.trim().length < 3) return;
    setBusy("save-exclusions");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/schedule-activations/${selectedSchedule.id}/exclusions`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: selectedSchedule.revision,
          exclusion_windows: exclusionWindows,
          reason: exclusionReason.trim(),
          actor: "capability.publisher",
        }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update schedule exclusions");
    } finally {
      setBusy(null);
    }
  }

  async function disableSchedule() {
    if (!selectedSchedule) return;
    setBusy("disable-schedule");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/schedule-activations/${selectedSchedule.id}/disable`, {
        method: "POST",
        body: JSON.stringify({ actor: "capability.publisher" }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to disable Workflow schedule");
    } finally {
      setBusy(null);
    }
  }

  function exclusionEditor(includeSave: boolean) {
    return (
      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50/70 p-3">
        <div className="flex items-center justify-between gap-3">
          <div><p className="text-[10px] font-semibold uppercase tracking-wide text-amber-800">Calendar exclusions</p><p className="mt-1 text-[10px] leading-4 text-amber-700">Half-open UTC windows are skipped durably and never dispatched. Browser-local input is converted to UTC.</p></div>
          <Badge variant="outline" className="border-amber-300 bg-white text-amber-800">{exclusionWindows.length}/100</Badge>
        </div>
        <div className="mt-3 space-y-2">
          {exclusionWindows.map((window) => (
            <div key={window.id} className="flex items-start justify-between gap-2 rounded-lg border border-amber-200 bg-white px-3 py-2">
              <div><p className="text-[10px] font-semibold text-[#303744]">{window.name}</p><p className="mt-0.5 font-mono text-[9px] text-muted-foreground">{new Date(window.starts_at).toLocaleString()} → {new Date(window.ends_at).toLocaleString()}</p></div>
              <Button type="button" size="sm" variant="ghost" className="h-7 px-2 text-red-600" onClick={() => setExclusionWindows((current) => current.filter((item) => item.id !== window.id))} disabled={busy !== null}><XCircle className="size-3.5" /></Button>
            </div>
          ))}
          {exclusionWindows.length === 0 ? <p className="rounded-lg border border-dashed border-amber-200 bg-white p-3 text-center text-[10px] text-amber-700">No maintenance or freeze window configured.</p> : null}
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Window name<Input value={exclusionName} onChange={(event) => setExclusionName(event.target.value)} maxLength={128} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label>
          <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Starts<Input type="datetime-local" value={exclusionStartsAt} onChange={(event) => setExclusionStartsAt(event.target.value)} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label>
          <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Ends<Input type="datetime-local" value={exclusionEndsAt} onChange={(event) => setExclusionEndsAt(event.target.value)} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label>
        </div>
        <Button type="button" size="sm" variant="outline" className="mt-2 w-full border-amber-300 bg-white text-amber-800" onClick={addExclusionWindow} disabled={busy !== null || exclusionWindows.length >= 100}>Add exclusion window</Button>
        {includeSave ? (
          <div className="mt-3 border-t border-amber-200 pt-3">
            <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Change reason<Input value={exclusionReason} onChange={(event) => setExclusionReason(event.target.value)} minLength={3} maxLength={1000} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label>
            <Button type="button" size="sm" className="mt-2 w-full bg-amber-600 hover:bg-amber-700" onClick={() => void saveScheduleExclusions()} disabled={busy !== null || exclusionReason.trim().length < 3}>{busy === "save-exclusions" ? <Loader2 className="animate-spin" /> : <ShieldCheck />}Save revision {selectedSchedule ? selectedSchedule.revision + 1 : ""}</Button>
          </div>
        ) : null}
      </div>
    );
  }

  async function activateSituationIntegration() {
    if (!selected || selected.trigger.trigger_type !== "situation") return;
    setBusy("activate-situation");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/workflows/${selected.version_id}/situation-integration`, {
        method: "POST",
        body: JSON.stringify({
          channel_kind: channelKind,
          route_purpose: routePurpose,
          run_as_principal_id: runAsPrincipalId.trim() || null,
          authorization_scope: JSON.parse(scope),
          input_mapping: JSON.parse(mapping),
          actor: "capability.publisher",
        }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to activate Situation integration");
    } finally {
      setBusy(null);
    }
  }

  async function disableSituationIntegration() {
    if (!selectedSituationIntegration) return;
    setBusy("disable-situation");
    setError(null);
    try {
      await apiFetch(`/workflow-runtime/situation-integrations/${selectedSituationIntegration.id}/disable`, {
        method: "POST",
        body: JSON.stringify({ actor: "capability.publisher" }),
      });
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to disable Situation integration");
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="flex min-h-screen flex-col bg-[#eef0f5] text-[#253044] xl:h-screen xl:min-h-[720px] xl:overflow-hidden">
      <header className="flex min-h-16 shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[#d8dbe0] bg-white px-4 py-2 sm:px-5">
        <div className="flex items-center gap-3">
          <Link href="/studio" className="rounded-md p-2 text-[#59677b] transition hover:bg-[#eef0f5]" aria-label="Back to Capability Studio"><ArrowLeft className="h-4 w-4" /></Link>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#303c54] text-white"><GitBranch className="h-4 w-4" /></div>
          <div><h1 className="text-sm font-semibold">Workflow Runtime</h1><p className="text-xs text-muted-foreground">Manual · alert · schedule · Situation integrations · durable outbox</p></div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/studio?create=workflow"><GitBranch className="h-3.5 w-3.5" /> Design Workflow</Link></Button>
          <Button asChild variant="outline" size="sm" className="gap-2"><Link href="/"><Play className="h-3.5 w-3.5" /> Run manual Workflow</Link></Button>
          <Button variant="outline" size="sm" className="gap-2" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh</Button>
        </div>
      </header>

      {error ? <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700"><XCircle className="h-4 w-4" />{error}</div> : null}

      <div className="grid flex-1 grid-cols-1 xl:min-h-0 xl:grid-cols-[320px_430px_minmax(420px,1fr)]">
        <aside className="border-b border-[#d8dbe0] bg-[#f8f9fb] p-3 xl:min-h-0 xl:overflow-y-auto xl:border-b-0 xl:border-r">
          <div className="mb-3 flex items-center justify-between px-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground"><span>Published Workflows</span><Badge variant="outline" className="text-[9px]">{workflows.length}</Badge></div>
          <div className="space-y-2">
            {workflows.map((workflow) => {
              const activation = activations.find((item) => item.artifact_version_id === workflow.version_id) || scheduleActivations.find((item) => item.artifact_version_id === workflow.version_id) || situationIntegrations.find((item) => item.artifact_version_id === workflow.version_id);
              return <button key={workflow.version_id} onClick={() => chooseWorkflow(workflow.version_id)} className={cn("w-full rounded-lg border p-3 text-left transition", selectedVersionId === workflow.version_id ? "border-[#5856d6]/30 bg-white shadow-sm" : "border-transparent hover:border-[#d8dbe0] hover:bg-white")}>
                <div className="flex items-center justify-between gap-2"><span className="truncate text-xs font-semibold">{workflow.artifact_name}</span><Badge variant="outline" className="text-[9px]">v{workflow.version}</Badge></div>
                <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{workflow.description}</p>
                <div className="mt-2 flex items-center gap-1.5"><Badge variant="outline" className="text-[9px]">{workflow.trigger.trigger_type}</Badge>{activation ? <Badge variant="outline" className={activation.enabled ? "border-emerald-300 bg-emerald-50 text-[9px] text-emerald-700" : "text-[9px]"}>{activation.enabled ? "active" : "disabled"}</Badge> : null}</div>
              </button>;
            })}
          </div>
        </aside>

        <section className="border-b border-[#d8dbe0] bg-white p-5 xl:min-h-0 xl:overflow-y-auto xl:border-b-0 xl:border-r">
          {selected ? <>
            <div className="flex items-start justify-between gap-3"><div><h2 className="text-base font-semibold">{selected.artifact_name}</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">{selected.description}</p></div><Badge variant="outline">{selected.node_count} nodes</Badge></div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-[10px]"><div className="rounded-lg bg-[#f5f6f8] p-2.5"><div className="text-muted-foreground">Tool calls</div><div className="mt-1 font-semibold">{selected.max_total_tool_calls}</div></div><div className="rounded-lg bg-[#f5f6f8] p-2.5"><div className="text-muted-foreground">Runtime</div><div className="mt-1 font-semibold">{selected.max_runtime_seconds}s</div></div><div className="rounded-lg bg-[#f5f6f8] p-2.5"><div className="text-muted-foreground">Approval</div><div className="mt-1 font-semibold">{selected.approval_required ? "Required" : "No change path"}</div></div></div>
            {selected.trigger.trigger_type === "manual" ? (
              <div className="mt-5 rounded-xl border border-sky-200 bg-sky-50 p-4 text-xs leading-5 text-sky-800">Manual Workflows are selected and run from the AI L1 home with schema-derived typed input.</div>
            ) : selected.trigger.trigger_type === "alert" ? (
              selectedActivation ? (
                <div className="mt-5 rounded-xl border border-emerald-200 bg-emerald-50 p-4"><div className="flex items-center gap-2 text-sm font-semibold text-emerald-800"><CheckCircle2 className="h-4 w-4" />Trigger {selectedActivation.enabled ? "active" : "disabled"}</div><dl className="mt-3 space-y-2 text-[10px] text-emerald-900"><div><dt className="text-emerald-600">Event</dt><dd className="font-mono">{selectedActivation.event_type}</dd></div><div><dt className="text-emerald-600">Run as</dt><dd className="font-mono">{selectedActivation.run_as_principal_id || "development identity"}</dd></div><div><dt className="text-emerald-600">Scope</dt><dd className="break-all font-mono">{JSON.stringify(selectedActivation.authorization_scope)}</dd></div><div><dt className="text-emerald-600">Mapping</dt><dd className="break-all font-mono">{JSON.stringify(selectedActivation.input_mapping)}</dd></div></dl>{selectedActivation.enabled ? <Button variant="outline" size="sm" className="mt-4 border-red-200 text-red-700" onClick={() => void disable()} disabled={busy !== null}>{busy === "disable" ? <Loader2 className="animate-spin" /> : <XCircle />}Disable trigger</Button> : null}</div>
              ) : (
                <div className="mt-5"><div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-[#5856d6]" />Activate alert trigger</div><p className="mt-1 text-[10px] leading-4 text-muted-foreground">Activation is separate from publication. Required-auth deployments must select an enabled service principal whose current roles and scope authorize every dependency.</p><label className="mt-4 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Route purpose<Input value={routePurpose} onChange={(event) => setRoutePurpose(event.target.value)} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label><label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Run-as principal ID<Input value={runAsPrincipalId} onChange={(event) => setRunAsPrincipalId(event.target.value)} placeholder="Required when auth mode is required" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label><label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Authorization scope JSON<Textarea value={scope} onChange={(event) => setScope(event.target.value)} rows={4} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label><label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Alert → input mapping JSON<Textarea value={mapping} onChange={(event) => setMapping(event.target.value)} rows={7} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label><Button size="sm" className="mt-3 w-full bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => void activate()} disabled={busy !== null}>{busy === "activate" ? <Loader2 className="animate-spin" /> : <ShieldCheck />}Activate exact version</Button></div>
              )
            ) : selected.trigger.trigger_type === "situation" ? (
              selectedSituationIntegration ? (
                <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 p-4"><div className="flex items-center gap-2 text-sm font-semibold text-amber-900"><ShieldCheck className="h-4 w-4" />Situation integration {selectedSituationIntegration.enabled ? "active" : "disabled"}</div><dl className="mt-3 space-y-2 text-[10px] text-amber-950"><div><dt className="text-amber-700">Channel · event</dt><dd className="font-mono">{selectedSituationIntegration.channel_kind} · {selectedSituationIntegration.event_type}</dd></div><div><dt className="text-amber-700">Run as</dt><dd className="font-mono">{selectedSituationIntegration.run_as_principal_id || "development identity"}</dd></div><div><dt className="text-amber-700">Scope</dt><dd className="break-all font-mono">{JSON.stringify(selectedSituationIntegration.authorization_scope)}</dd></div><div><dt className="text-amber-700">Mapping</dt><dd className="break-all font-mono">{JSON.stringify(selectedSituationIntegration.input_mapping)}</dd></div><div><dt className="text-amber-700">Provider · reference Tool</dt><dd className="break-all font-mono">{selectedSituationIntegration.provider_key} · {selectedSituationIntegration.remote_reference_tool_name || "reference capture disabled"}</dd></div>{selectedSituationIntegration.remote_reference_tool_name ? <div><dt className="text-amber-700">Reference output mapping</dt><dd className="break-all font-mono">{JSON.stringify(selectedSituationIntegration.remote_reference_mapping)}</dd></div> : null}{selectedSituationIntegration.inbound_enabled ? <><div><dt className="text-amber-700">Signed webhook</dt><dd className="break-all font-mono">/api/v1/workflow-runtime/situation-integrations/{selectedSituationIntegration.id}/webhook</dd></div><div><dt className="text-amber-700">Key ID · Ed25519 fingerprint</dt><dd className="break-all font-mono">{selectedSituationIntegration.inbound_key_id} · {selectedSituationIntegration.inbound_public_key_sha256}</dd></div></> : <div><dt className="text-amber-700">Inbound reconciliation</dt><dd>disabled</dd></div>}</dl>{selectedSituationIntegration.enabled ? <Button variant="outline" size="sm" className="mt-4 border-red-200 text-red-700" onClick={() => void disableSituationIntegration()} disabled={busy !== null}>{busy === "disable-situation" ? <Loader2 className="animate-spin" /> : <XCircle />}Disable integration</Button> : null}</div>
              ) : (
                <div className="mt-5">
                  <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-[#5856d6]" />Activate Situation integration</div>
                  <p className="mt-1 text-[10px] leading-4 text-muted-foreground">The exact published Workflow must depend on a governed MCP Tool. Lifecycle data is mapped into typed input; change tools retain approval, post-check, and rollback enforcement.</p>
                  <div className="mt-4 grid grid-cols-2 gap-2"><Button type="button" size="sm" variant={channelKind === "ticket" ? "default" : "outline"} onClick={() => setChannelKind("ticket")}>Ticket</Button><Button type="button" size="sm" variant={channelKind === "collaboration" ? "default" : "outline"} onClick={() => setChannelKind("collaboration")}>Collaboration</Button></div>
                  <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Route purpose<Input value={routePurpose} onChange={(event) => setRoutePurpose(event.target.value)} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label>
                  <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Run-as principal ID<Input value={runAsPrincipalId} onChange={(event) => setRunAsPrincipalId(event.target.value)} placeholder="Required when auth mode is required" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label>
                  <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Authorization scope JSON<Textarea value={scope} onChange={(event) => setScope(event.target.value)} rows={4} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                  <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Situation → input mapping JSON<Textarea value={mapping} onChange={(event) => setMapping(event.target.value)} rows={7} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                  <div className="mt-4 border-t border-[#d8dbe0] pt-4">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Remote reference contract</div>
                    <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Optional. The Tool must be a pinned MCP dependency; mapped output paths are checked against its published schema.</p>
                    <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Provider key<Input value={providerKey} onChange={(event) => setProviderKey(event.target.value)} placeholder="servicenow" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label>
                    <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Producing MCP Tool name<Input value={remoteReferenceToolName} onChange={(event) => setRemoteReferenceToolName(event.target.value)} placeholder="ticket.create" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label>
                    <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Tool output → reference mapping JSON<Textarea value={remoteReferenceMapping} onChange={(event) => setRemoteReferenceMapping(event.target.value)} rows={4} placeholder={'{"remote_id":"ticket.id","remote_url":"ticket.url","remote_status":"ticket.status"}'} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                    <label className="mt-3 flex items-start gap-2 text-[10px] leading-4 text-[#5f6978]"><input type="checkbox" checked={inboundEnabled} onChange={(event) => setInboundEnabled(event.target.checked)} className="mt-0.5" /><span><strong className="block text-[#303744]">Enable signed inbound status observations</strong>Remote status never changes the deterministic local Situation lifecycle.</span></label>
                    {inboundEnabled ? (
                      <div className="mt-3 space-y-3">
                        <label className="block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Webhook key ID<Input value={inboundKeyId} onChange={(event) => setInboundKeyId(event.target.value)} className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label>
                        <label className="block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Ed25519 public key PEM<Textarea value={inboundPublicKeyPem} onChange={(event) => setInboundPublicKeyPem(event.target.value)} rows={6} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                      </div>
                    ) : null}
                  </div>
                  <Button size="sm" className="mt-3 w-full bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => void activateSituationIntegration()} disabled={busy !== null}>{busy === "activate-situation" ? <Loader2 className="animate-spin" /> : <ShieldCheck />}Bind exact version</Button>
                </div>
              )
            ) : selectedSchedule ? (
              <div className="mt-5 rounded-xl border border-violet-200 bg-violet-50 p-4">
                <div className="flex items-center gap-2 text-sm font-semibold text-violet-800"><Clock3 className="h-4 w-4" />Schedule {selectedSchedule.enabled ? "active" : "disabled"}</div>
                <dl className="mt-3 space-y-2 text-[10px] text-violet-900"><div><dt className="text-violet-600">Cron · timezone</dt><dd className="font-mono">{selectedSchedule.cron_expression} · {selectedSchedule.timezone}</dd></div><div><dt className="text-violet-600">Next fire</dt><dd>{new Date(selectedSchedule.next_fire_at).toLocaleString()}</dd></div><div><dt className="text-violet-600">Last fire · missed</dt><dd>{selectedSchedule.last_fire_at ? new Date(selectedSchedule.last_fire_at).toLocaleString() : "never"} · {selectedSchedule.missed_runs}</dd></div><div><dt className="text-violet-600">Run as</dt><dd className="font-mono">{selectedSchedule.run_as_principal_id || "development identity"}</dd></div><div><dt className="text-violet-600">Scope</dt><dd className="break-all font-mono">{JSON.stringify(selectedSchedule.authorization_scope)}</dd></div><div><dt className="text-violet-600">Static typed input</dt><dd className="break-all font-mono">{JSON.stringify(selectedSchedule.workflow_input)}</dd></div></dl>
                {selectedSchedule.report_artifact_version_id ? (
                  <div className="mt-3 rounded-lg border border-violet-200 bg-white p-3 text-[10px] text-violet-900">
                    <div className="font-semibold">Generated report delivery</div>
                    <div className="mt-1">{reports.find((item) => item.version_id === selectedSchedule.report_artifact_version_id)?.report_title || "Bound report version"} · input <span className="font-mono">{selectedSchedule.report_input_key}</span></div>
                    <div className="mt-1 break-all font-mono text-[9px] text-violet-600">{selectedSchedule.report_artifact_version_id}</div>
                    <div className="mt-2 border-t border-violet-100 pt-2"><span className="text-violet-600">Receipt producer</span><br /><span className="font-mono">{selectedSchedule.report_delivery_tool_name}.{selectedSchedule.report_delivery_tool_argument}</span></div>
                    <div className="mt-1"><span className="text-violet-600">Provider</span> · <span className="font-mono">{selectedSchedule.report_delivery_provider_key}</span></div>
                    <div className="mt-1 break-all"><span className="text-violet-600">Output mapping</span> · <span className="font-mono">{JSON.stringify(selectedSchedule.report_delivery_receipt_mapping)}</span></div>
                    <p className="mt-2 leading-4 text-violet-700">{selectedSchedule.report_attachment_format ? `Each occurrence saves one snapshot and its ${selectedSchedule.report_attachment_format.toUpperCase()} document. The approved bytes stay fixed through retries.` : "Every occurrence generates current report values under the run-as scope."} Delivery follows the Workflow approval, verification and rollback path.</p>
                  </div>
                ) : null}
                <p className="mt-3 text-[10px] text-violet-700">Calendar revision {selectedSchedule.revision} · {selectedSchedule.excluded_runs} excluded occurrence{selectedSchedule.excluded_runs === 1 ? "" : "s"}{selectedSchedule.last_excluded_at ? ` · last ${new Date(selectedSchedule.last_excluded_at).toLocaleString()}` : ""}</p>
                {selectedSchedule.enabled ? exclusionEditor(true) : null}
                {selectedSchedule.enabled ? <Button variant="outline" size="sm" className="mt-4 border-red-200 text-red-700" onClick={() => void disableSchedule()} disabled={busy !== null}>{busy === "disable-schedule" ? <Loader2 className="animate-spin" /> : <XCircle />}Disable schedule</Button> : null}
              </div>
            ) : (
              <div className="mt-5">
                <div className="flex items-center gap-2 text-sm font-semibold"><Clock3 className="h-4 w-4 text-[#5856d6]" />Activate cron schedule</div>
                <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Five-field cron uses the selected IANA timezone, never runs more often than every five minutes, skips occurrences outside the misfire grace, and dispatches each scheduled time once.</p>
                <div className="mt-4 grid grid-cols-2 gap-3"><label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Cron expression<Input value={cronExpression} onChange={(event) => setCronExpression(event.target.value)} className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label><label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">IANA timezone<Input value={scheduleTimezone} onChange={(event) => setScheduleTimezone(event.target.value)} className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label></div>
                <div className="mt-3 grid grid-cols-2 gap-3"><label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Route purpose<Input value={routePurpose} onChange={(event) => setRoutePurpose(event.target.value)} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label><label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Misfire grace seconds<Input type="number" min={60} max={86400} value={misfireGraceSeconds} onChange={(event) => setMisfireGraceSeconds(Number(event.target.value))} className="mt-1 h-9 text-xs normal-case tracking-normal" /></label></div>
                <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Run-as principal ID<Input value={runAsPrincipalId} onChange={(event) => setRunAsPrincipalId(event.target.value)} placeholder="Required when auth mode is required" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label>
                <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Authorization scope JSON<Textarea value={scope} onChange={(event) => setScope(event.target.value)} rows={4} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                {exclusionEditor(false)}
                <div className="mt-4 rounded-xl border border-indigo-200 bg-indigo-50/70 p-3">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-indigo-800">Generated report input</div>
                  <p className="mt-1 text-[10px] leading-4 text-indigo-700">Optional. Pins one immutable published report version. Each occurrence generates fresh scoped values and may pass them only to a directly bound state-changing MCP Tool; the Workflow still enforces approval, post-check, and rollback.</p>
                  <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Published report
                    <select
                      value={selectedReportVersionId}
                      onChange={(event) => {
                        selectedReportVersionIdRef.current = event.target.value;
                        setSelectedReportVersionId(event.target.value);
                      }}
                      className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]"
                    >
                      <option value="">No generated report</option>
                      {reports.map((report) => <option key={report.version_id} value={report.version_id}>{report.report_title} · v{report.version} · {report.section_count} sections</option>)}
                    </select>
                  </label>
                  {selectedReportVersionId ? <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Delivery content<select value={reportAttachmentFormat} onChange={(event) => chooseReportAttachmentFormat(event.target.value)} className="mt-1 h-9 w-full rounded-md border border-[#c9ced7] bg-white px-2 text-xs normal-case tracking-normal text-[#253044]"><option value="">Current numeric report</option><option value="pdf">Saved PDF document</option><option value="html">Saved HTML document</option><option value="csv">Saved CSV document</option><option value="json">Saved JSON document</option></select><span className="mt-1 block font-normal normal-case tracking-normal text-indigo-700">The adapter retrieves the approved bytes with its own authorized identity. Both delivery and verification must confirm the document fingerprint.</span></label> : null}
                  {selectedReportVersionId ? <div className="mt-3 space-y-3"><label className="block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Workflow input key<Input value={reportInputKey} onChange={(event) => setReportInputKey(event.target.value)} placeholder="report" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label><label className="block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Delivery provider key<Input value={reportDeliveryProviderKey} onChange={(event) => setReportDeliveryProviderKey(event.target.value)} placeholder="smtp" className="mt-1 h-9 font-mono text-xs normal-case tracking-normal" /></label><label className="block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Tool output → receipt mapping JSON<Textarea value={reportDeliveryReceiptMapping} onChange={(event) => setReportDeliveryReceiptMapping(event.target.value)} rows={5} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label><p className="text-[10px] leading-4 text-indigo-700">The unique primary change Tool is inferred from the immutable Workflow binding. Map its string output paths to required <span className="font-mono">delivery_id</span> and optional <span className="font-mono">delivery_url</span>/<span className="font-mono">delivery_status</span>. A receipt is committed only after the Workflow completes.</p></div> : null}
                  {reports.length === 0 ? <p className="mt-2 text-[10px] text-amber-700">No published service-health Report is visible in the current service scope.</p> : null}
                </div>
                <label className="mt-3 block text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Static Workflow input JSON<Textarea value={scheduleInput} onChange={(event) => setScheduleInput(event.target.value)} rows={7} className="mt-1 font-mono text-[10px] normal-case tracking-normal" /></label>
                <Button size="sm" className="mt-3 w-full bg-[#5856d6] hover:bg-[#4947ad]" onClick={() => void activateSchedule()} disabled={busy !== null}>{busy === "activate-schedule" ? <Loader2 className="animate-spin" /> : <Clock3 />}Activate exact version</Button>
              </div>
            )}
          </> : <div className="grid h-full place-items-center text-xs text-muted-foreground">No published Workflow is available.</div>}
        </section>

        <section className="bg-[#f8f9fb] p-5 xl:min-h-0 xl:overflow-y-auto">
          {selected?.trigger.trigger_type === "schedule" ? (
            <>
              <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold">Schedule occurrence outbox</h2><p className="mt-1 text-[10px] text-muted-foreground">One durable event per activation + exact scheduled UTC time.</p></div><Badge variant="outline">{selectedScheduleEvents.length}</Badge></div>
              <div className="mt-4 space-y-2">
                {selectedScheduleEvents.map((event) => {
                  const receipt = selectedReportDeliveryReceipts.find((item) => item.schedule_event_id === event.id);
                  return (
                  <div key={event.id} className="rounded-xl border border-[#dfe2e7] bg-white p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-2">
                        {event.status === "failed" ? <AlertTriangle className="h-4 w-4 shrink-0 text-red-500" /> : event.status === "skipped" ? <ShieldCheck className="h-4 w-4 shrink-0 text-amber-500" /> : <Clock3 className="h-4 w-4 shrink-0 text-violet-500" />}
                        <span className="truncate font-mono text-[10px]">{new Date(event.scheduled_for).toLocaleString()}</span>
                      </div>
                      <Badge variant="outline" className={cn("text-[9px]", eventTone(event.status))}>{event.status === "succeeded" ? "investigation dispatched" : event.status}</Badge>
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[9px] text-muted-foreground">
                      <span>{event.status === "skipped" ? "not dispatched" : `attempt ${event.attempt_count}/3`}</span>
                      <span>{new Date(event.updated_at).toLocaleString()}</span>
                    </div>
                    {event.skip_reason ? <p className="mt-2 text-[10px] text-amber-700">{event.skip_reason.replaceAll("_", " ")} · <span className="font-mono">{event.exclusion_window_id}</span></p> : null}
                    {event.error_type ? <p className="mt-2 text-[10px] text-red-700">{event.error_type} · <span className="font-mono">{event.error_sha256?.slice(0, 12)}</span></p> : null}
                    {event.report_delivery_state === "pending" ? <p className="mt-2 text-[10px] text-indigo-700">{event.investigation_status === "waiting_approval" ? "Waiting for independent approval" : "Delivery evidence pending"} · Investigation {event.investigation_status?.replaceAll("_", " ")}</p> : null}
                    {event.report_delivery_state === "reconciliation_required" ? <div className="mt-2 rounded-lg border border-amber-300 bg-amber-50 p-2 text-[10px] text-amber-900"><p>External delivery may have occurred, but no verified receipt is recorded. Do not resend until the provider or recipient confirms the outcome. Review Investigation <span className="font-mono">{event.investigation_id?.slice(0, 12)}</span> in <Link href="/investigations" className="underline">Investigation history</Link>.</p>{event.report_delivery_tool_call_id ? <p className="mt-1 break-all">Provider lookup Tool-call ID: <span className="font-mono select-all">{event.report_delivery_tool_call_id}</span></p> : null}</div> : null}
                    {event.report_delivery_state === "unverified" ? <p className="mt-2 rounded-lg border border-amber-200 bg-amber-50 p-2 text-[10px] text-amber-800">Execution ended without verified delivery. Review Investigation <span className="font-mono">{event.investigation_id?.slice(0, 12)}</span> ({event.investigation_status}); no success receipt is available.</p> : null}
                    {event.report_delivery_state === "not_dispatched" ? <p className="mt-2 text-[10px] text-muted-foreground">No report delivery Investigation dispatched.</p> : null}
                    {event.report_delivery_state === "verified" && !receipt ? <p className="mt-2 text-[10px] text-emerald-700">Delivery verified · receipt outside the current loaded ledger window.</p> : null}
                    {event.report_delivery_state === "legacy_unverified" && !receipt ? <p className="mt-2 text-[10px] text-amber-800">Legacy receipt · verification unavailable.</p> : null}
                    {receipt ? (
                      <div className={cn("mt-3 rounded-lg border p-3 text-[10px]", receipt.verified_at ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-amber-200 bg-amber-50 text-amber-800")}>
                        <div className="flex items-center justify-between gap-2"><span className="font-semibold">{receipt.verified_at ? "Delivery verified" : "Legacy receipt · verification unavailable"}</span><Badge variant="outline" className="bg-white text-[9px]">{receipt.delivery_status || "recorded"}</Badge></div>
                        <div className="mt-1 font-mono">{receipt.provider_key} · {receipt.delivery_id}</div>
                        {receipt.delivery_url ? <a href={receipt.delivery_url} target="_blank" rel="noreferrer" className="mt-1 block truncate underline">{receipt.delivery_url}</a> : null}
                        <div className="mt-1 text-[9px]">Delivered {new Date(receipt.delivered_at).toLocaleString()} · report {receipt.report_content_hash.slice(0, 12)}</div>
                        {receipt.report_instance_id ? <Link href={`/reports/instances/${encodeURIComponent(receipt.report_instance_id)}/retention`} className="mt-1 block text-[9px] underline">Saved document {receipt.report_attachment_sha256?.slice(0, 12)} · retention details</Link> : null}
                        {receipt.verified_at ? <div className="mt-1 text-[9px]">Verified {new Date(receipt.verified_at).toLocaleString()} · check {receipt.verification_tool_call_id?.slice(0, 12)}</div> : null}
                        <div className="mt-2 flex items-center justify-between gap-2"><span className="text-[9px]">Retained · no automatic pruning</span><Button size="sm" variant="outline" className="h-7 bg-white text-[10px]" disabled={busy !== null} onClick={() => void exportReceipt(receipt)}>{busy === `export-receipt-${receipt.id}` ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}Export JSON</Button></div>
                      </div>
                    ) : null}
                  </div>
                  );
                })}
                {selectedSchedule && selectedScheduleEvents.length === 0 ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">No scheduled occurrence has entered the durable outbox yet.</div> : null}
                {!selectedSchedule ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">Activate this published schedule Workflow to create a governed outbox.</div> : null}
              </div>
            </>
          ) : selected?.trigger.trigger_type === "alert" ? (
            <>
              <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold">Alert trigger outbox</h2><p className="mt-1 text-[10px] text-muted-foreground">One event per activation + deduplicated Alert ID.</p></div><Badge variant="outline">{selectedEvents.length}</Badge></div>
              <div className="mt-4 space-y-2">
                {selectedEvents.map((event) => <div key={event.id} className="rounded-xl border border-[#dfe2e7] bg-white p-4"><div className="flex items-center justify-between gap-3"><div className="flex min-w-0 items-center gap-2">{event.status === "failed" ? <AlertTriangle className="h-4 w-4 shrink-0 text-red-500" /> : <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />}<span className="truncate font-mono text-[10px]">{event.alert_id}</span></div><Badge variant="outline" className={cn("text-[9px]", eventTone(event.status))}>{event.status}</Badge></div><div className="mt-2 flex items-center justify-between text-[9px] text-muted-foreground"><span>attempt {event.attempt_count}/3</span><span>{new Date(event.updated_at).toLocaleString()}</span></div>{event.error_type ? <p className="mt-2 text-[10px] text-red-700">{event.error_type} · <span className="font-mono">{event.error_sha256?.slice(0, 12)}</span></p> : null}</div>)}
                {selectedActivation && selectedEvents.length === 0 ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">No matching Alert has entered this trigger yet.</div> : null}
                {!selectedActivation ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">Activate an alert-triggered Workflow to create a governed outbox.</div> : null}
              </div>
            </>
          ) : selected?.trigger.trigger_type === "situation" ? (
            <>
              <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold">Situation integration outbox</h2><p className="mt-1 text-[10px] text-muted-foreground">One durable delivery per binding and exact Situation timeline event.</p></div><Badge variant="outline">{selectedSituationEvents.length}</Badge></div>
              <div className="mt-4 space-y-2">
                {selectedSituationEvents.map((event) => <div key={event.id} className="rounded-xl border border-[#dfe2e7] bg-white p-4"><div className="flex items-center justify-between gap-3"><div className="min-w-0"><div className="truncate font-mono text-[10px]">{event.event_type}</div><div className="mt-1 truncate font-mono text-[9px] text-muted-foreground">Situation {event.situation_id}</div></div><Badge variant="outline" className={cn("text-[9px]", eventTone(event.status))}>{event.status}</Badge></div><div className="mt-2 flex items-center justify-between text-[9px] text-muted-foreground"><span>attempt {event.attempt_count}/3</span><span>{new Date(event.updated_at).toLocaleString()}</span></div>{event.error_type ? <p className="mt-2 text-[10px] text-red-700">{event.error_type} · <span className="font-mono">{event.error_sha256?.slice(0, 12)}</span></p> : null}</div>)}
                {selectedSituationReferences.length ? <div className="pt-3 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Captured remote references</div> : null}
                {selectedSituationReferences.map((reference) => {
                  const inbound = selectedSituationInboundEvents.find((event) => event.reference_id === reference.id);
                  return <div key={reference.id} className="rounded-xl border border-sky-200 bg-sky-50 p-4"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><div className="truncate font-mono text-[10px] font-semibold text-sky-900">{reference.provider_key} · {reference.remote_id}</div><div className="mt-1 truncate font-mono text-[9px] text-sky-700">Situation {reference.situation_id}</div></div><Badge variant="outline" className="border-sky-300 bg-white text-[9px] text-sky-800">{reference.remote_status || "unknown"}</Badge></div><div className="mt-2 text-[9px] text-sky-700">{reference.remote_url || "No remote URL"}</div>{inbound ? <div className="mt-2 flex items-center justify-between text-[9px] text-sky-800"><span>{inbound.outcome.replaceAll("_", " ")} · {inbound.event_type}</span><span>{new Date(inbound.received_at).toLocaleString()}</span></div> : <div className="mt-2 text-[9px] text-sky-700">No signed inbound observation yet.</div>}</div>;
                })}
                {selectedSituationIntegration && selectedSituationEvents.length === 0 ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">No matching Situation lifecycle event has entered this outbox yet.</div> : null}
                {!selectedSituationIntegration ? <div className="rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">Bind this Situation-triggered Workflow to a ticket or collaboration channel.</div> : null}
              </div>
            </>
          ) : <div className="grid h-full place-items-center rounded-xl border border-dashed border-[#c8cdd5] p-8 text-center text-xs leading-5 text-muted-foreground">Manual Workflow executions appear in the AI L1 workspace.</div>}
        </section>
      </div>
    </main>
  );
}
