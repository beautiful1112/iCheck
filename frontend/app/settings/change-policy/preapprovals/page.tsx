"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import ExecutionQualification from "./execution-qualification";

type Version = { artifact_version_id: string; name: string; kind: string; version: number; content_hash: string };
type VersionPage = { items: Version[]; total: number; truncated: boolean; scan_truncated: boolean };
type Device = { id: string; name: string; site: string | null; enabled: boolean; onboarding_status: string };
type Policy = { id: string; name: string; status: "draft" | "reviewed" | "revoked"; revision: number; tool_artifact_version_id: string; tool_content_hash: string; target_device_id: string; target_site: string; alert_event_type: string; arguments_template: Record<string, unknown>; max_alert_age_seconds: number; max_evidence_age_seconds: number; max_actions_per_alert: number; expires_at: string; created_by: string; reviewed_by: string | null; review_sha256: string | null; authorizes_execution: false };
type Preview = { policy_id: string; change_plan_id: string; candidate_matches: boolean; blocking_reasons: string[]; matched_alert_id: string | null; budget_used: number | null; budget_limit: number | null; authorizes_execution: false };
type Draft = { name: string; versionId: string; deviceId: string; eventType: string; argumentsText: string; maxAlertAge: string; maxEvidenceAge: string; maxActions: string; expiresLocal: string };
const emptyDraft: Draft = { name: "", versionId: "", deviceId: "", eventType: "", argumentsText: '{"device_id":"","idempotency_key":"__ICHECK_IDEMPOTENCY_KEY__"}', maxAlertAge: "300", maxEvidenceAge: "300", maxActions: "1", expiresLocal: "" };
const TOOL_PAGE_SIZE = 100;

function localDateTime(value: string): string {
  const date = new Date(value);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

export default function ChangePreapprovalsPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [versions, setVersions] = useState<Version[]>([]);
  const [selectedVersion, setSelectedVersion] = useState<Version | null>(null);
  const [toolSearch, setToolSearch] = useState("");
  const [toolQuery, setToolQuery] = useState("");
  const [toolOffset, setToolOffset] = useState(0);
  const [toolTotal, setToolTotal] = useState(0);
  const [toolScanTruncated, setToolScanTruncated] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [draft, setDraft] = useState<Draft>({ ...emptyDraft });
  const [editing, setEditing] = useState<Policy | null>(null);
  const [qualifying, setQualifying] = useState<Policy | null>(null);
  const [reason, setReason] = useState("");
  const [planId, setPlanId] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const generation = useRef(0);
  const namespaceEpoch = useRef(0);

  const load = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    try {
      const params = new URLSearchParams({ kind: "tool", preapproval_tool: "true",
        offset: String(toolOffset), limit: String(TOOL_PAGE_SIZE) });
      if (toolQuery) params.set("q", toolQuery);
      const [next, catalog, inventory] = await Promise.all([
        apiFetch<Policy[]>(`/agent/change-preapprovals?offset=${offset}&limit=100`),
        apiFetch<VersionPage>(`/capability-catalog?${params.toString()}`),
        apiFetch<Device[]>("/assets/devices"),
      ]);
      if (current !== generation.current) return;
      setPolicies(next);
      setQualifying((current) => current ? next.find((item) => item.id === current.id && item.status === "reviewed") ?? null : null);
      setVersions(catalog.items);
      setToolTotal(catalog.total);
      setToolScanTruncated(catalog.scan_truncated);
      setDevices(inventory.filter((item) => item.enabled && item.onboarding_status === "active" && item.site));
      if (catalog.scan_truncated) setMessage("The Tool catalog scan reached its limit. Search by name to find an unlisted version.");
    } catch (cause) {
      if (current === generation.current) setMessage(cause instanceof Error ? cause.message : "Unable to load preapproval policies.");
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [offset, toolOffset, toolQuery]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const currentGeneration = generation;
    const onNamespace = () => {
      ++generation.current; ++namespaceEpoch.current;
      setPolicies([]); setVersions([]); setSelectedVersion(null); setDevices([]);
      setToolSearch(""); setToolQuery(""); setToolOffset(0); setToolTotal(0); setToolScanTruncated(false);
      setEditing(null); setQualifying(null); setDraft({ ...emptyDraft });
      setReason(""); setPlanId(""); setPreview(null); setMessage(""); setBusy(false);
      if (offset) setOffset(0);
      else if (!toolOffset && !toolQuery) void load();
    };
    window.addEventListener("icheck:namespace-changed", onNamespace);
    return () => { window.clearTimeout(timer); ++currentGeneration.current; window.removeEventListener("icheck:namespace-changed", onNamespace); };
  }, [load, offset, toolOffset, toolQuery]);

  function update(field: keyof Draft, value: string) {
    setDraft((previous) => ({ ...previous, [field]: value }));
  }

  function searchTools() {
    const query = toolSearch.trim();
    if (toolOffset === 0 && query === toolQuery) void load();
    else { setToolOffset(0); setToolQuery(query); }
  }

  function chooseVersion(value: string) {
    setSelectedVersion(versions.find((item) => item.artifact_version_id === value) ?? null);
    update("versionId", value);
  }

  function chooseDevice(value: string) {
    setDraft((previous) => {
      let argumentsText = previous.argumentsText;
      try {
        const parsed = JSON.parse(argumentsText) as Record<string, unknown>;
        if (typeof parsed.device_id === "string") argumentsText = JSON.stringify({ ...parsed, device_id: value }, null, 2);
      } catch { /* Keep the operator's text for an explicit validation error. */ }
      return { ...previous, deviceId: value, argumentsText };
    });
  }

  function beginEdit(policy: Policy) {
    setEditing(policy);
    setSelectedVersion(null);
    setDraft({ name: policy.name, versionId: policy.tool_artifact_version_id, deviceId: policy.target_device_id,
      eventType: policy.alert_event_type, argumentsText: JSON.stringify(policy.arguments_template, null, 2),
      maxAlertAge: String(policy.max_alert_age_seconds), maxEvidenceAge: String(policy.max_evidence_age_seconds),
      maxActions: String(policy.max_actions_per_alert),
      expiresLocal: localDateTime(policy.expires_at) });
    setReason(""); setPreview(null); setMessage("");
  }

  async function mutate(path: string, method: "POST" | "PATCH", body: Record<string, unknown>, success: string) {
    if (reason.trim().length < 10) { setMessage("Enter an audit reason of at least 10 characters."); return; }
    const current = namespaceEpoch.current;
    setBusy(true); setMessage(""); setPreview(null);
    try {
      await apiFetch(path, { method, body: JSON.stringify({ ...body, reason: reason.trim() }) });
      if (current !== namespaceEpoch.current) return;
      setMessage(success); setReason(""); setEditing(null); setSelectedVersion(null); setDraft({ ...emptyDraft });
      if (offset) { setBusy(false); setOffset(0); } else await load();
    } catch (cause) {
      if (current === namespaceEpoch.current) setMessage(cause instanceof Error ? cause.message : "Policy operation failed.");
    } finally { if (current === namespaceEpoch.current) setBusy(false); }
  }

  function save() {
    const version = selectedVersion?.artifact_version_id === draft.versionId ? selectedVersion
      : versions.find((item) => item.artifact_version_id === draft.versionId);
    if (!version && !editing) { setMessage("Select a ready Tool version with state observations."); return; }
    if (!devices.some((item) => item.id === draft.deviceId)) { setMessage("Select an active device with a site."); return; }
    let argumentsTemplate: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(draft.argumentsText);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Arguments must be a JSON object.");
      argumentsTemplate = parsed as Record<string, unknown>;
    } catch { setMessage("Arguments must be a valid JSON object."); return; }
    const expires = new Date(draft.expiresLocal);
    if (!Number.isFinite(expires.getTime())) { setMessage("Select an expiry within the next 30 days."); return; }
    const settings = { name: draft.name.trim(), target_device_id: draft.deviceId,
      alert_event_type: draft.eventType.trim(), arguments_template: argumentsTemplate,
      max_alert_age_seconds: Number(draft.maxAlertAge), max_evidence_age_seconds: Number(draft.maxEvidenceAge),
      max_actions_per_alert: Number(draft.maxActions),
      expires_at: expires.toISOString() };
    void mutate(editing ? `/agent/change-preapprovals/${editing.id}` : "/agent/change-preapprovals",
      editing ? "PATCH" : "POST", editing ? { ...settings, expected_revision: editing.revision }
        : { ...settings, tool_artifact_version_id: version?.artifact_version_id, expected_content_hash: version?.content_hash },
      "Policy saved as a draft. Review does not authorize unattended execution.");
  }

  async function readPreview(policy: Policy) {
    const current = namespaceEpoch.current;
    setBusy(true); setMessage(""); setPreview(null);
    try {
      const result = await apiFetch<Preview>(`/agent/change-preapprovals/${policy.id}/change-plans/${planId.trim()}/preview`);
      if (current === namespaceEpoch.current) setPreview(result);
    } catch (cause) {
      if (current === namespaceEpoch.current) setMessage(cause instanceof Error ? cause.message : "Unable to preview this plan.");
    } finally { if (current === namespaceEpoch.current) setBusy(false); }
  }

  // Firefox restores dynamic disabled/value state on reload unless the form
  // opts out. Fresh policy/evidence reads, not restored DOM state, own these gates.
  return <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8"><form autoComplete="off" noValidate onSubmit={(event) => event.preventDefault()} className="mx-auto max-w-5xl space-y-5">
    <header className="flex items-start justify-between gap-4"><div className="flex items-start gap-3"><Link href="/settings/change-policy" aria-label="Back to change risk policies" className="rounded-lg border border-slate-200 bg-white p-2"><ArrowLeft className="size-4" /></Link><div><h1 className="text-xl font-semibold">Reviewed change preapprovals</h1><p className="text-sm text-slate-600">Define one low-risk Tool version, device, exact arguments and Alert condition.</p></div></div><Button variant="outline" disabled={loading || busy} onClick={() => void load()}><RefreshCw className="mr-2 size-4" />Refresh</Button></header>
    <p className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">Review and preview do not grant execution authority. A separate independent execution qualification, current desired-state evidence and the host execution switch are required for policy-approved actions.</p>
    {message ? <p role="status" className="rounded-lg border border-slate-200 bg-white p-3 text-sm">{message}</p> : null}
    <Card><CardHeader><CardTitle className="text-base">{editing ? `Revise ${editing.name}` : "Draft exact policy"}</CardTitle></CardHeader><CardContent className="space-y-3 text-sm">
      <div className="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3">
        <div className="flex flex-wrap gap-2"><Input className="min-w-48 flex-1" aria-label="Search eligible Tool versions" placeholder="Search eligible Tool versions" maxLength={100} value={toolSearch} disabled={loading || busy} onChange={(event) => setToolSearch(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); searchTools(); } }} /><Button variant="outline" disabled={loading || busy} onClick={searchTools}>Search Tools</Button></div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600"><span>{toolTotal ? `Ready Tool versions ${toolOffset + 1}–${toolOffset + versions.length} of ${toolTotal}` : "No ready Tool versions match this search"}</span><div className="flex gap-2"><Button size="sm" variant="outline" disabled={loading || busy || toolOffset === 0} onClick={() => setToolOffset(Math.max(0, toolOffset - TOOL_PAGE_SIZE))}>Previous Tools</Button><Button size="sm" variant="outline" disabled={loading || busy || toolOffset + versions.length >= toolTotal} onClick={() => setToolOffset(toolOffset + TOOL_PAGE_SIZE)}>Next Tools</Button></div></div>
        {toolScanTruncated ? <p className="text-xs text-amber-800">The catalog scan is capped; search by Tool name if a version is missing.</p> : null}
      </div>
      <div className="grid gap-3 sm:grid-cols-2"><label className="block">Policy name<Input value={draft.name} maxLength={128} disabled={busy} onChange={(event) => update("name", event.target.value)} /></label><label className="block">Published Tool version<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={draft.versionId} disabled={busy || !!editing} onChange={(event) => chooseVersion(event.target.value)}><option value="">Select a ready Tool</option>{draft.versionId && !versions.some((item) => item.artifact_version_id === draft.versionId) ? <option value={draft.versionId}>{selectedVersion ? `${selectedVersion.name} · v${selectedVersion.version}` : `Current Tool version ${draft.versionId}`}</option> : null}{versions.map((item) => <option key={item.artifact_version_id} value={item.artifact_version_id}>{item.name} · v{item.version}</option>)}</select></label></div>
      <div className="grid gap-3 sm:grid-cols-2"><label className="block">Device<select className="mt-1 block h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={draft.deviceId} disabled={busy} onChange={(event) => chooseDevice(event.target.value)}><option value="">Select an active device</option>{devices.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.site}</option>)}</select></label><label className="block">Exact Alert event type<Input value={draft.eventType} disabled={busy} onChange={(event) => update("eventType", event.target.value)} placeholder="device.interface.down" /></label></div>
      <label className="block">Action argument template<Textarea className="mt-1 min-h-32 font-mono text-xs" value={draft.argumentsText} disabled={busy} onChange={(event) => update("argumentsText", event.target.value)} /></label><p className="text-xs text-muted-foreground">Select a published, governed low-risk Tool with desired-state observations. Keep all action values fixed. Use __ICHECK_IDEMPOTENCY_KEY__ only at the Tool contract&apos;s idempotency path. Include the selected device ID and site when the Tool contract requires them. Older Tool versions without state observations cannot be used for a new preapproval policy.</p>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><label className="block">Maximum Alert age (seconds)<Input type="number" min={60} max={3600} value={draft.maxAlertAge} disabled={busy} onChange={(event) => update("maxAlertAge", event.target.value)} /></label><label className="block">Precheck/dry-run max age (seconds)<Input type="number" min={60} max={3600} value={draft.maxEvidenceAge} disabled={busy} onChange={(event) => update("maxEvidenceAge", event.target.value)} /></label><label className="block">Action budget per Alert<Input type="number" min={1} max={3} value={draft.maxActions} disabled={busy} onChange={(event) => update("maxActions", event.target.value)} /></label><label className="block">Policy expiry<Input type="datetime-local" value={draft.expiresLocal} disabled={busy} onChange={(event) => update("expiresLocal", event.target.value)} /></label></div>
      <label className="block">Audit reason<Input value={reason} disabled={busy} maxLength={512} onChange={(event) => setReason(event.target.value)} placeholder="Why is this exact policy needed?" /></label>
      <div className="flex gap-2"><Button disabled={busy || loading} onClick={save}>{editing ? "Save draft revision" : "Create draft policy"}</Button>{editing ? <Button variant="outline" disabled={busy} onClick={() => { setEditing(null); setSelectedVersion(null); setDraft({ ...emptyDraft }); setReason(""); }}>Cancel edit</Button> : null}</div>
    </CardContent></Card>
    <Card><CardHeader><CardTitle className="text-base">Policies</CardTitle></CardHeader><CardContent className="space-y-3 text-sm">
      {loading && !policies.length ? <p>Loading policies…</p> : !policies.length ? <p>No policies in this namespace.</p> : policies.map((policy) => <section key={policy.id} className="space-y-2 rounded-lg border border-slate-200 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><h2 className="font-medium">{policy.name}</h2><span className="text-amber-800">{policy.status} · separate execution grant required</span></div><p className="break-words text-xs text-slate-600">Version {policy.tool_artifact_version_id} · device {policy.target_device_id} · Alert {policy.alert_event_type} · revision {policy.revision}</p><p className="text-xs text-slate-600">Expires {new Date(policy.expires_at).toLocaleString()} · reviewer {policy.reviewed_by ?? "pending"}</p><div className="flex flex-wrap gap-2"><Button size="sm" variant="outline" disabled={busy || policy.status === "revoked"} onClick={() => beginEdit(policy)}>Edit</Button><Button size="sm" variant="outline" disabled={busy || policy.status !== "draft"} onClick={() => void mutate(`/agent/change-preapprovals/${policy.id}/review`, "POST", { expected_revision: policy.revision }, "Policy reviewed. Execution qualification remains a separate step.")}>Review</Button><Button size="sm" variant="outline" disabled={busy || policy.status === "revoked"} onClick={() => void mutate(`/agent/change-preapprovals/${policy.id}/revoke`, "POST", { expected_revision: policy.revision }, "Policy revoked.")}>Revoke</Button><Button size="sm" variant="outline" disabled={busy || !planId.trim()} onClick={() => void readPreview(policy)}>Preview plan</Button><Button size="sm" variant="outline" disabled={busy || policy.status !== "reviewed"} onClick={() => setQualifying(policy)}>Execution qualification</Button></div></section>)}
      <label className="block">Change plan ID to preview<Input value={planId} disabled={busy} onChange={(event) => setPlanId(event.target.value)} placeholder="UUID from a governed change plan" /></label>
      {preview ? <div role="status" className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm"><p>Candidate matches: {preview.candidate_matches ? "yes" : "no"}. Execution authorization: no.</p>{preview.matched_alert_id ? <p>Alert {preview.matched_alert_id} · budget claims {preview.budget_used}/{preview.budget_limit}</p> : null}<p>Blocking reasons: {preview.blocking_reasons.join(", ")}</p></div> : null}
      <div className="flex items-center justify-between gap-3"><Button variant="outline" size="sm" disabled={busy || loading || offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</Button><span className="text-xs">{policies.length ? `Policies ${offset + 1}–${offset + policies.length}` : "No policies on this page"}</span><Button variant="outline" size="sm" disabled={busy || loading || policies.length < 100} onClick={() => setOffset(offset + 100)}>Next</Button></div>
    </CardContent></Card>
    {qualifying ? <ExecutionQualification key={`${qualifying.id}:${qualifying.review_sha256}`} policy={qualifying} deviceName={devices.find((item) => item.id === qualifying.target_device_id)?.name ?? qualifying.target_device_id} onClose={() => setQualifying(null)} /> : null}
  </form></main>;
}
