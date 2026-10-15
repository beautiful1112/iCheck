"use client";

import Link from "next/link";
import {FormEvent, useCallback, useEffect, useRef, useState} from "react";
import {Globe2, RefreshCw} from "lucide-react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";

type Settings = {
  source: "managed" | "environment" | "default";
  provider: string; enabled: boolean; server_enabled: boolean; storage_ready: boolean;
  key_configured: boolean; searxng_url: string | null; revision: number;
  daily_limit: number | null; calls_today: number; quota_timezone: string;
  last_test_status: string | null; last_test_at: string | null;
};
type TestResult = {status: string; message: string; revision: number; settings: Settings};
const field = "h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm";

export function ResearchSettingsForm() {
  const [saved, setSaved] = useState<Settings | null>(null);
  const [provider, setProvider] = useState("brave");
  const [enabled, setEnabled] = useState(false);
  const [key, setKey] = useState("");
  const [url, setUrl] = useState("");
  const [limit, setLimit] = useState("100");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [notice, setNotice] = useState<{error: boolean; text: string} | null>(null);
  const epoch = useRef(0);

  const accept = useCallback((value: Settings) => {
    setSaved(value); setProvider(value.provider === "searxng" ? "searxng" : "brave");
    setEnabled(value.enabled); setKey(""); setUrl(value.searxng_url || "");
    setLimit(String(value.daily_limit ?? 100));
  }, []);
  const load = useCallback(async () => {
    const current = ++epoch.current;
    setLoading(true); setKey(""); setNotice(null);
    try {
      const value = await apiFetch<Settings>("/research/settings");
      if (current === epoch.current) accept(value);
    } catch (error) {
      if (current === epoch.current) {
        setSaved(null);
        setNotice({error: true, text: error instanceof Error ? error.message : "Unable to load search settings"});
      }
    } finally {if (current === epoch.current) setLoading(false);}
  }, [accept]);
  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    const reset = () => {
      epoch.current++; setSaved(null); setKey(""); setUrl(""); setEnabled(false); setBusy(null);
      void load();
    };
    const storage = (event: StorageEvent) => {
      if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset();
    };
    window.addEventListener("icheck:namespace-changed", reset);
    window.addEventListener("storage", storage);
    return () => {
      // Invalidate pending requests; this ref is a counter, not a DOM reference.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      epoch.current++; window.clearTimeout(timer);
      window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);
    };
  }, [load]);

  const originalProvider = saved?.provider === "searxng" ? "searxng" : "brave";
  const dirty = !!saved && (provider !== originalProvider || enabled !== saved.enabled || !!key
    || (provider === "searxng" && url !== (saved.searxng_url || "")) || Number(limit) !== (saved.daily_limit ?? 100));
  const retainedKey = saved?.source === "managed" && saved.provider === "brave" && saved.key_configured;
  const needsKey = provider === "brave" && enabled && !retainedKey && !key;
  const state = !saved ? "Loading" : dirty ? "Unsaved changes" : saved.source === "default" ? "Not configured"
    : !saved.server_enabled ? "Disabled by server" : !saved.enabled ? "Search off"
    : saved.last_test_status === "passed" ? "Connection tested" : saved.last_test_status === "failed" ? "Test failed" : "Not tested";

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!saved) return;
    const current = epoch.current;
    setBusy("save"); setNotice(null);
    try {
      const result = await apiFetch<Settings>("/research/settings", {method: "PUT", headers: {"content-type": "application/json"},
        body: JSON.stringify({expected_revision: saved.revision, provider, enabled, daily_limit: Number(limit),
          ...(provider === "brave" && key ? {api_key: key} : {}), searxng_url: provider === "searxng" ? url : null})});
      if (current !== epoch.current) return;
      accept(result);
      setNotice({error: false, text: "Search settings saved. No search, AI model or device call was made."});
    } catch (error) {
      if (current === epoch.current) setNotice({error: true, text: error instanceof Error ? error.message : "Unable to save search settings"});
    } finally {if (current === epoch.current) {setKey(""); setBusy(null);}}
  }
  async function test() {
    if (!saved || dirty) return;
    const current = epoch.current;
    setBusy("test"); setNotice(null);
    try {
      const result = await apiFetch<TestResult>("/research/settings/test", {method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({expected_revision: saved.revision, approve_charge: true})});
      if (current !== epoch.current) return;
      accept(result.settings); setNotice({error: result.status !== "passed", text: result.message});
    } catch (error) {
      if (current === epoch.current) setNotice({error: true, text: error instanceof Error ? error.message : "Search test failed"});
    } finally {if (current === epoch.current) setBusy(null);}
  }

  return <main className="mx-auto max-w-3xl px-4 py-8 sm:px-6">
    <Link href="/settings/ai" className="text-sm text-violet-700 hover:underline">← AI settings</Link>
    <div className="mt-5 flex items-start justify-between gap-4">
      <div><h1 className="flex items-center gap-2 text-2xl font-semibold"><Globe2 aria-hidden="true" />Internet search</h1>
        <p className="mt-2 text-sm leading-6 text-slate-600">Give AI Operator and Capability Studio access to public references when knowledge is missing. Configure once for this workspace—not for each device.</p></div>
      <Button variant="outline" onClick={() => void load()} disabled={loading || !!busy} aria-label="Refresh search settings"><RefreshCw className="size-4" /></Button>
    </div>
    {notice && <p role={notice.error ? "alert" : "status"} className={`mt-5 rounded-lg border p-3 text-sm ${notice.error ? "border-red-200 bg-red-50 text-red-800" : "border-green-200 bg-green-50 text-green-800"}`}>{notice.text}</p>}
    {loading ? <p className="mt-6" role="status">Loading search settings…</p> : saved && <>
      <section className="mt-6 rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-semibold">Search connection</h2><span className="rounded-full bg-slate-100 px-3 py-1 text-xs">{state}</span>
        </div>
        {!saved.server_enabled && <p className="mb-4 rounded-md bg-amber-50 p-3 text-sm text-amber-900">Internet research is disabled on this server. You can save settings, but an administrator must enable the server’s research capability before calls can run.</p>}
        {saved.source === "environment" && <p className="mb-4 text-sm text-slate-600">Server-file configuration is currently active. Saving here replaces it for this workspace. Enter your provider key once to use GUI-managed storage.</p>}
        <form onSubmit={save} className="space-y-5">
          <fieldset disabled={!!busy} className="space-y-5">
            <div><label htmlFor="research-provider" className="mb-2 block text-sm font-medium">Search provider</label>
              <select id="research-provider" value={provider} className={field} onChange={event => {setProvider(event.target.value); setKey(""); setNotice(null);}}>
                <option value="brave">Brave Search — recommended</option><option value="searxng">SearXNG — existing endpoint</option>
              </select></div>
            {provider === "brave" ? <div>
              <label htmlFor="research-api-key" className="mb-2 block text-sm font-medium">Brave API key</label>
              <Input id="research-api-key" type="password" value={key} onChange={event => setKey(event.target.value)} autoComplete="new-password" spellCheck={false}
                minLength={10} maxLength={512} placeholder={retainedKey ? "Key saved · leave blank to keep it" : "Enter your Brave Search API key"} aria-describedby="research-key-help" />
              <p id="research-key-help" className="mt-2 text-xs leading-5 text-slate-500">Encrypted on the server and never returned to the browser. This is separate from your AI model token. <a href="https://api-dashboard.search.brave.com/documentation/quickstart" target="_blank" rel="noopener noreferrer" className="text-violet-700 underline">Get a Brave API key</a>.</p>
              {!saved.storage_ready && <p className="mt-2 text-sm text-amber-800">Encrypted key storage is not ready. An administrator must provision the platform’s AI encryption key; do not paste a provider key until storage is ready.</p>}
            </div> : <div>
              <label htmlFor="research-endpoint" className="mb-2 block text-sm font-medium">SearXNG search endpoint</label>
              <Input id="research-endpoint" type="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://search.example.org/search" required aria-describedby="research-endpoint-help" />
              <p id="research-endpoint-help" className="mt-2 text-xs leading-5 text-slate-500">Use an existing public HTTPS endpoint with JSON enabled. Private-network addresses and authenticated URLs are not supported. No Brave key is sent to SearXNG.</p>
            </div>}
            <label className="flex items-start gap-3 text-sm"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} className="mt-1" />
              <span><span className="block font-medium">Allow AI to search the internet</span><span className="mt-1 block leading-5 text-slate-500">Saving this enabled setting authorizes search requests within the limit below. Provider charges may apply. Turning it off stops new searches; it does not erase the saved key or block direct public-document reads.</span></span>
            </label>
            <div className="rounded-lg bg-slate-50 p-4">
              <label htmlFor="research-daily-limit" className="mb-2 block text-sm font-medium">Maximum searches per day</label>
              <Input id="research-daily-limit" type="number" min={1} max={10000} required value={limit} onChange={event => setLimit(event.target.value)} className="max-w-40" />
              <p className="mt-2 text-xs leading-5 text-slate-500">Includes connection tests and failed attempts. Resets at midnight UTC. This limits requests, not your provider’s invoice. {saved.source === "managed" && `${saved.calls_today} ${saved.calls_today === 1 ? "request" : "requests"} used today.`}</p>
            </div>
            <Button type="submit" disabled={needsKey || (provider === "brave" && !!key && !saved.storage_ready)}>{busy === "save" ? "Saving…" : "Save settings"}</Button>
          </fieldset>
          <p className="text-xs text-slate-500">Saving does not test the connection or contact a device. {dirty && "You have unsaved changes."}</p>
        </form>
      </section>
      <section className="mt-5 rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
        <h2 className="font-semibold">Test the saved connection</h2>
        <p className="mt-2 text-sm leading-6 text-slate-600">Sends one public documentation search to the saved provider. It may consume a search credit. No AI model, device credentials or lab devices are involved.</p>
        <Button variant="outline" className="mt-4" onClick={() => void test()} disabled={!!busy || dirty || saved.revision === 0 || !saved.enabled || !saved.server_enabled}>
          {busy === "test" ? "Testing…" : "Test search · 1 request"}
        </Button>
        {dirty && <p className="mt-2 text-xs text-slate-500">Save your changes before testing.</p>}
        {!dirty && saved.last_test_at && <p className="mt-3 text-xs text-slate-500">Last test: {saved.last_test_status} · {new Date(saved.last_test_at).toLocaleString()}</p>}
      </section>
      <p className="mt-5 text-xs leading-5 text-slate-500">Research results are references, not permission to change infrastructure. Existing device, workflow and dashboard approval rules still apply.</p>
    </>}
  </main>;
}
