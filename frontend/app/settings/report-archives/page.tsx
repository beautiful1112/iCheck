"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Archive, Loader2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";

type Source = { id: string; name: string; origin: string; credential_profile_id: string; enabled: boolean; revision: number };
type Profile = { id: string; name: string; enabled: boolean; allowed_adapters: string[]; worker_selector: Record<string, string> };

export default function ReportArchivesSettingsPage() {
  const [sources, setSources] = useState<Source[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [name, setName] = useState("");
  const [origin, setOrigin] = useState("");
  const [profileId, setProfileId] = useState("");
  const [credentialName, setCredentialName] = useState("");
  const [credentialProvider, setCredentialProvider] = useState("vault");
  const [secretRef, setSecretRef] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const generation = useRef(0);
  const mutation = useRef(0);

  const load = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true); setError(null);
    try {
      const [nextSources, nextProfiles] = await Promise.all([
        apiFetch<Source[]>("/reports/archive-sources"), apiFetch<Profile[]>("/credential-profiles"),
      ]);
      if (current !== generation.current) return;
      const usable = nextProfiles.filter((profile) => profile.enabled && profile.allowed_adapters.includes("report_archive") && Object.keys(profile.worker_selector).length === 0);
      setSources(nextSources); setProfiles(usable);
      setProfileId((prior) => usable.some((profile) => profile.id === prior) ? prior : usable[0]?.id ?? "");
    } catch (caught) {
      if (current === generation.current) { setSources([]); setProfiles([]); setError(caught instanceof Error ? caught.message : "Unable to read archive settings."); }
    } finally { if (current === generation.current) setLoading(false); }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    const onChange = () => { ++mutation.current; setSources([]); setProfiles([]); setName(""); setOrigin(""); setProfileId(""); setCredentialName(""); setSecretRef(""); setReason(""); setNotice(null); setBusy(false); void load(); };
    window.addEventListener("icheck:namespace-changed", onChange);
    const currentGeneration = generation;
    return () => { ++currentGeneration.current; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", onChange); };
  }, [load]);

  async function save(path: string, payload: Record<string, unknown>) {
    if (busy) return;
    const isCredential = path === "/credential-profiles";
    if (!isCredential && (reason.trim().length < 10 || reason.length > 512)) { setError("A reason of 10–512 characters is required."); return; }
    const current = generation.current;
    const action = ++mutation.current;
    setBusy(true); setError(null); setNotice(null);
    try {
      await apiFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(isCredential ? payload : { ...payload, reason: reason.trim() }) });
      if (current !== generation.current) return;
      setNotice(isCredential ? "Server credential reference created." : "Archive source configuration saved.");
      if (isCredential) { setCredentialName(""); setSecretRef(""); } else { setReason(""); }
      await load();
    } catch (caught) { if (current === generation.current) setError(caught instanceof Error ? caught.message : "Unable to save archive source."); }
    finally { if (action === mutation.current) setBusy(false); }
  }

  return <main className="min-h-screen bg-[#f4f6f8] text-slate-900">
    <header className="flex min-h-16 items-center justify-between border-b border-slate-200 bg-white px-5 py-3"><div className="flex items-center gap-3"><Link href="/settings/report-storage" className="rounded-md p-2 text-muted-foreground" aria-label="Back to report storage"><ArrowLeft className="size-4" /></Link><span className="grid size-9 place-items-center rounded-xl bg-indigo-600 text-white"><Archive className="size-4" /></span><div><h1 className="text-sm font-semibold">Independent report archives</h1><p className="text-xs text-muted-foreground">Sources belong to the selected tenant and region</p></div></div><Button variant="outline" size="sm" disabled={loading || busy} onClick={() => void load()}><RefreshCw className="size-3.5" />Refresh</Button></header>
    <div className="mx-auto max-w-4xl space-y-5 p-5 lg:p-8">
      {error ? <p role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</p> : null}
      {notice ? <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">{notice}</p> : null}
      {loading ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Loading archive settings…</p> : null}
      <Card><CardHeader><CardTitle className="text-base">Server credential reference</CardTitle><CardDescription>Store a reference, never a token value. Vault must already be configured server-side; environment references are for local development.</CardDescription></CardHeader><CardContent className="space-y-3 text-xs"><label className="block font-medium">Credential profile name<Input className="mt-1" value={credentialName} onChange={(event) => setCredentialName(event.target.value)} maxLength={255} /></label><label className="block font-medium">Provider<select className="mt-1 h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={credentialProvider} onChange={(event) => setCredentialProvider(event.target.value)}><option value="vault">Vault KV v2</option><option value="environment">Environment (development)</option></select></label><label className="block font-medium">Secret reference<Input className="mt-1" value={secretRef} onChange={(event) => setSecretRef(event.target.value)} maxLength={1024} placeholder={credentialProvider === "environment" ? "env://ICHECK_ARCHIVE_TOKEN" : "vault://kv/archive/read-token"} /></label><Button variant="outline" disabled={busy || loading || !credentialName.trim() || !secretRef.trim()} onClick={() => void save("/credential-profiles", { name: credentialName.trim(), provider: credentialProvider, secret_ref: secretRef.trim(), allowed_adapters: ["report_archive"], worker_selector: {}, created_by: "web.archive.settings" })}>Create credential reference</Button></CardContent></Card>
      <Card><CardHeader><CardTitle className="text-base">Pin an archive source</CardTitle><CardDescription>Requires namespace-wide auth.admin and services.manage. Configure a server credential profile with the report_archive adapter before registering an origin.</CardDescription></CardHeader><CardContent className="space-y-4 text-xs">
        <label className="block font-medium">Name<Input className="mt-1" value={name} onChange={(event) => setName(event.target.value)} maxLength={255} /></label>
        <label className="block font-medium">HTTPS origin<Input className="mt-1" value={origin} onChange={(event) => setOrigin(event.target.value)} maxLength={2048} placeholder="https://archive.example.internal" /></label>
        <p className="text-muted-foreground">Host must be deployment-allowlisted in ICHECK_REPORT_ARCHIVE_ALLOWED_HOSTS. No URL paths, inline credentials, redirects or proxy inheritance are accepted.</p>
        <label className="block font-medium">Server credential profile<select className="mt-1 h-9 w-full rounded-md border border-slate-200 bg-white px-3" value={profileId} onChange={(event) => setProfileId(event.target.value)}><option value="">Select usable profile</option>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select></label>
        {!profiles.length && !loading ? <p className="text-amber-800">No namespace-local profile permits report_archive. Create a credential reference above before registering the source.</p> : null}
        <label className="block font-medium">Change reason<Input className="mt-1" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={512} /></label>
        <Button disabled={busy || loading || !name.trim() || !origin.trim() || !profileId} onClick={() => void save("/reports/archive-sources", { name: name.trim(), origin: origin.trim(), credential_profile_id: profileId })}>Register source</Button>
      </CardContent></Card>
      <Card><CardHeader><CardTitle className="text-base">Configured sources</CardTitle><CardDescription>Origin and credential-profile bindings are immutable. Register a replacement source and verify it separately when moving an archive.</CardDescription></CardHeader><CardContent className="space-y-3 text-xs">{sources.map((source) => <div key={source.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 p-3"><div><p className="font-semibold">{source.name} · {source.enabled ? "enabled" : "disabled"}</p><p className="mt-1 break-all font-mono text-muted-foreground">{source.origin}</p></div><Button variant="outline" size="sm" disabled={busy} onClick={() => void save(`/reports/archive-sources/${source.id}/state`, { enabled: !source.enabled, expected_revision: source.revision })}>{source.enabled ? "Disable" : "Enable"}</Button></div>)}{!sources.length && !loading ? <p className="text-muted-foreground">No independent archive source registered.</p> : null}</CardContent></Card>
      <p className="text-xs leading-5 text-muted-foreground">The external gateway implements GET /v1/report-archives/&#123;reference&#125;/content and returns the unchanged complete JSON package. iCheck verifies retrieval but does not upload archives, configure external WORM retention or promise future availability.</p>
    </div>
  </main>;
}
