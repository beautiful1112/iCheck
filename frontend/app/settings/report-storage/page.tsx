"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Database, Loader2, RefreshCw, Save, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type StoragePolicy = {
  tenant_id: string;
  region_id: string;
  max_instances: number | null;
  max_bytes: number | null;
  used_instances: number;
  used_bytes: number;
  max_attachment_bytes: number | null;
  used_attachment_bytes: number;
  revision: number;
};

function readableBytes(value: number) {
  if (value < 1024) return `${value.toLocaleString()} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function optionalPositiveInteger(value: string, maximum: number, label: string) {
  if (!value.trim()) return null;
  const parsed = Number(value.trim());
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${label} must be a positive whole number within the supported range.`);
  }
  return parsed;
}

export default function ReportStorageSettingsPage() {
  const [policy, setPolicy] = useState<StoragePolicy | null>(null);
  const [instanceLimit, setInstanceLimit] = useState("");
  const [byteLimit, setByteLimit] = useState("");
  const [attachmentLimit, setAttachmentLimit] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const requestId = useRef(0);

  const load = useCallback(async () => {
    const current = ++requestId.current;
    setLoading(true);
    setError(null);
    try {
      const next = await apiFetch<StoragePolicy>("/reports/storage");
      if (current !== requestId.current) return;
      setPolicy(next);
      setInstanceLimit(next.max_instances?.toString() ?? "");
      setByteLimit(next.max_bytes?.toString() ?? "");
      setAttachmentLimit(next.max_attachment_bytes?.toString() ?? "");
    } catch (caught) {
      if (current !== requestId.current) return;
      setPolicy(null);
      setError(caught instanceof Error ? caught.message : "Cannot read report storage policy.");
    } finally {
      if (current === requestId.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    const generation = requestId;
    const onNamespaceChange = () => { setPolicy(null); setNotice(null); setSaving(false); void load(); };
    window.addEventListener("icheck:namespace-changed", onNamespaceChange);
    return () => {
      ++generation.current;
      window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", onNamespaceChange);
    };
  }, [load]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!policy || saving) return;
    setError(null);
    setNotice(null);
    let maxInstances: number | null;
    let maxBytes: number | null;
    let maxAttachmentBytes: number | null;
    try {
      maxInstances = optionalPositiveInteger(instanceLimit, 10_000_000, "Instance limit");
      maxBytes = optionalPositiveInteger(byteLimit, 10_000_000_000_000, "Byte limit");
      maxAttachmentBytes = optionalPositiveInteger(attachmentLimit, 10_000_000_000_000, "Document byte limit");
      if (reason.trim().length < 10 || reason.length > 512) {
        throw new Error("Change reason must be 10–512 characters.");
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Invalid storage policy.");
      return;
    }
    setSaving(true);
    const current = requestId.current;
    try {
      const next = await apiFetch<StoragePolicy>("/reports/storage", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          max_instances: maxInstances, max_bytes: maxBytes,
          max_attachment_bytes: maxAttachmentBytes,
          expected_revision: policy.revision, reason: reason.trim(),
        }),
      });
      if (current !== requestId.current) return;
      setPolicy(next);
      setInstanceLimit(next.max_instances?.toString() ?? "");
      setByteLimit(next.max_bytes?.toString() ?? "");
      setAttachmentLimit(next.max_attachment_bytes?.toString() ?? "");
      setReason("");
      setNotice("Storage limits saved for this tenant and region.");
    } catch (caught) {
      if (current === requestId.current) setError(caught instanceof Error ? caught.message : "Storage policy update failed.");
    } finally {
      if (current === requestId.current) setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#f4f6f8] text-slate-900">
      <header className="flex min-h-16 items-center justify-between border-b border-slate-200 bg-white px-5 py-3">
        <div className="flex items-center gap-3">
          <Link href="/reports" className="rounded-md p-2 text-muted-foreground hover:bg-slate-100" aria-label="Back to reports"><ArrowLeft className="size-4" /></Link>
          <span className="grid size-9 place-items-center rounded-xl bg-indigo-600 text-white"><Database className="size-4" /></span>
          <div><h1 className="text-sm font-semibold">Report storage</h1><p className="text-xs text-muted-foreground">Namespace-local admission limits, separate from retention</p></div>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading || saving}><RefreshCw className="size-3.5" />Refresh</Button>
      </header>

      <div className="mx-auto max-w-3xl space-y-5 p-5 lg:p-8">
        {error ? <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</p> : null}
        {notice ? <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">{notice}</p> : null}
        {loading ? <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Loading namespace usage…</div> : null}
        {policy ? <>
          <Card>
            <CardHeader><CardTitle className="text-base">Retained usage</CardTitle><CardDescription>Current tenant and region only. No snapshot is deleted when a limit is reached.</CardDescription></CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4"><p className="text-xs text-muted-foreground">Saved instances</p><p className="mt-1 text-2xl font-semibold">{policy.used_instances.toLocaleString()}</p><p className="text-xs text-muted-foreground">Limit: {policy.max_instances?.toLocaleString() ?? "unlimited"}</p></div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4"><p className="text-xs text-muted-foreground">Canonical snapshot bytes</p><p className="mt-1 text-2xl font-semibold">{readableBytes(policy.used_bytes)}</p><p className="text-xs text-muted-foreground">Limit: {policy.max_bytes === null ? "unlimited" : readableBytes(policy.max_bytes)}</p></div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4"><p className="text-xs text-muted-foreground">Saved document bytes</p><p className="mt-1 text-2xl font-semibold">{readableBytes(policy.used_attachment_bytes)}</p><p className="text-xs text-muted-foreground">Limit: {policy.max_attachment_bytes === null ? "unlimited" : readableBytes(policy.max_attachment_bytes)}</p></div>
              </div>
              <p className="mt-3 break-all font-mono text-[10px] text-muted-foreground">Tenant {policy.tenant_id} · Region {policy.region_id} · Revision {policy.revision}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4 text-indigo-600" />Admission policy</CardTitle><CardDescription>Requires namespace-wide services.manage. Leave a limit blank for unlimited capacity.</CardDescription></CardHeader>
            <CardContent>
              <form onSubmit={(event) => void save(event)} className="space-y-4">
                <label className="block text-xs font-medium text-slate-700">Maximum saved instances<Input className="mt-1" type="number" min="1" max="10000000" step="1" value={instanceLimit} onChange={(event) => setInstanceLimit(event.target.value)} placeholder="Unlimited" /></label>
                <label className="block text-xs font-medium text-slate-700">Maximum canonical snapshot bytes<Input className="mt-1" type="number" min="1" max="10000000000000" step="1" value={byteLimit} onChange={(event) => setByteLimit(event.target.value)} placeholder="Unlimited" /><span className="mt-1 block font-normal text-muted-foreground">One MiB is 1,048,576 bytes. Document capacity is counted separately.</span></label>
                <label className="block text-xs font-medium text-slate-700">Maximum saved document bytes<Input className="mt-1" type="number" min="1" max="10000000000000" step="1" value={attachmentLimit} onChange={(event) => setAttachmentLimit(event.target.value)} placeholder="Unlimited" /><span className="mt-1 block font-normal text-muted-foreground">Saved delivery attachments consume this capacity. On-demand downloads do not.</span></label>
                <label className="block text-xs font-medium text-slate-700">Change reason<Input className="mt-1" value={reason} maxLength={512} onChange={(event) => setReason(event.target.value)} placeholder="Why is this limit changing?" required /></label>
                <Button type="submit" disabled={saving}>{saving ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}Save limits</Button>
              </form>
              <p className="mt-4 text-xs leading-5 text-muted-foreground">At capacity, new captures are rejected; exact-key retries still return the original report. Configure <Link href="/settings/report-archives" className="text-indigo-700 underline">independent archive sources</Link>, then manage byte verification, legal holds and reviewed purge from each saved report’s retention subpage.</p>
            </CardContent>
          </Card>
        </> : null}
      </div>
    </main>
  );
}
