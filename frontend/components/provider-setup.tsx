"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { CheckCircle2, KeyRound, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";
import { AICatalogControls } from "@/components/ai-catalog-controls";
import { AIProviderDiagnosticDetails, type SafeProviderDiagnostic } from "@/components/ai-provider-diagnostic-details";
import { AIProviderTimeoutControl } from "@/components/ai-provider-timeout-control";

type Connection = {
  preset: string; base_url: string; provider_id: string; name: string; revision: number; provider_enabled: boolean; outbound_enabled: boolean;
  key_configured: boolean; last_health_status: string | null;
  request_timeout_seconds: number;
};
type Preset = { id: string; label: string; base_url: string; provider_type: string; notes: string };
type Setup = { storage_ready: boolean; connections: Connection[]; presets: Preset[] };
type CatalogModel = { id: string; name: string; context_window: number | null; capabilities: string[] };
type Check = { connection_revision: number; configuration_hash: string; health: { status: string; error: string | null }; models: CatalogModel[] };
type Probe = { passed: boolean; model_id: string; quota_reservation_id: string; diagnostic: SafeProviderDiagnostic | null };
type Configured = { model: { display_name: string }; routes: { purpose: string }[] };
const selectClass = "h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-3 text-sm";
const fieldClass = "grid gap-1.5 text-sm font-medium";
const buttonClass = "h-auto min-h-9 max-w-full whitespace-normal py-2";
const outlineClass = buttonClass + " border-[#b1b7c1] bg-white text-[#2c384a]";

export function ProviderSetup({ onChanged }: { onChanged: () => Promise<void> }) {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [presetId, setPresetId] = useState("openrouter");
  const [name, setName] = useState("openrouter");
  const [newTimeout, setNewTimeout] = useState("120");
  const [apiKey, setApiKey] = useState("");
  const [approved, setApproved] = useState(false);
  const [check, setCheck] = useState<Check | null>(null);
  const [modelId, setModelId] = useState("");
  const [probe, setProbe] = useState<Probe | null>(null);
  const [approveCharge, setApproveCharge] = useState(false);
  const repair = useRef({ provider: "", model: "", source: "" });
  const [repairSource, setRepairSource] = useState("");
  const [displayName, setDisplayName] = useState("Operations reasoner");
  const [costClass, setCostClass] = useState("standard");
  const [investigation, setInvestigation] = useState(true);
  const [authoring, setAuthoring] = useState(false);
  const [replaceRoutes, setReplaceRoutes] = useState(false);
  const [budgets, setBudgets] = useState({ max_iterations: 8, max_tool_calls: 20, timeout_seconds: 300, token_budget: 50000 });
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ error: boolean; text: string } | null>(null);
  const [secureTransport, setSecureTransport] = useState(false);
  const epoch = useRef(0);
  const connection = setup?.connections.find((item) => item.provider_id === selectedId);
  const retired = connection?.provider_enabled === false;
  const preset = setup?.presets.find(item => item.id === (connection?.preset ?? presetId));
  const endpoint = connection?.base_url ?? preset?.base_url ?? "";
  const providerLabel = preset?.label ?? "AI provider";

  const reload = useCallback(async (selectFirst = false) => {
    const current = epoch.current;
    try {
      const result = await apiFetch<Setup>("/ai/managed/setup");
      if (current !== epoch.current) return;
      setSetup(result);
      if (selectFirst) setSelectedId(result.connections.find(item => item.provider_id === repair.current.provider)?.provider_id ?? result.connections[0]?.provider_id ?? "");
    } catch (error) {
      if (current === epoch.current) setNotice({ error: true, text: error instanceof Error ? error.message : "Unable to load AI provider setup" });
    }
  }, []);

  async function restored() {
    const current = epoch.current;
    setApiKey(""); setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false); setNotice(null);
    await reload();
    if (current === epoch.current) await onChanged();
  }

  useEffect(() => {
    const initial = window.setTimeout(() => {
      const query = new URLSearchParams(window.location.search);
      repair.current = { provider: query.get("repair_provider") ?? "", model: query.get("repair_model") ?? "", source: query.get("repair_source") ?? "" };
      setRepairSource(repair.current.source);
      setSecureTransport(window.location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname));
      void reload(true);
    }, 0);
    const reset = () => {
      epoch.current += 1;
      setApiKey(""); setApproved(false); setSetup(null); setSelectedId(""); setPresetId("openrouter"); setName("openrouter");
      setCheck(null); setModelId(""); setNotice(null); setBusy(false); setReplaceRoutes(false);
      setProbe(null); setApproveCharge(false); setRepairSource(""); repair.current = { provider: "", model: "", source: "" };
      void reload(true);
    };
    const storage = (event: StorageEvent) => {
      if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset();
    };
    window.addEventListener("icheck:namespace-changed", reset);
    window.addEventListener("storage", storage);
    return () => {
      epoch.current += 1;
      window.clearTimeout(initial);
      window.removeEventListener("icheck:namespace-changed", reset);
      window.removeEventListener("storage", storage);
    };
  }, [reload]);

  async function run(operation: () => Promise<string>) {
    if (busy) return;
    const current = epoch.current;
    setBusy(true); setNotice(null);
    try {
      const text = await operation();
      if (current === epoch.current) {
        setNotice({ error: false, text });
        await reload();
        await onChanged();
      }
    } catch (error) {
      if (current === epoch.current) setNotice({ error: true, text: error instanceof Error ? error.message : "AI provider setup failed" });
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }

  function saveKey(event: FormEvent) {
    event.preventDefault();
    if (!secureTransport || !setup?.storage_ready || busy || retired || (!connection && !preset)) return;
    const current = epoch.current;
    const secret = apiKey;
    setApiKey(""); // Write-only input: never persist, return, or redisplay a saved key.
    setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false);
    void run(async () => {
      const result = await apiFetch<Connection>(connection ? `/ai/managed/${connection.provider_id}/connection` : "/ai/managed/connections", {
        method: connection ? "PUT" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(connection
          ? { expected_revision: connection.revision, api_key: secret, outbound_enabled: connection.outbound_enabled }
          : { preset: presetId, name, api_key: secret, approve_outbound: approved, request_timeout_seconds: Number(newTimeout) }),
      });
      if (current === epoch.current) setSelectedId(result.provider_id);
      return connection ? "Key replaced. Verify the new credential before saving routes." : "Key encrypted and provider approved. Check the connection next.";
    });
  }

  function toggleAccess() {
    if (!connection || retired) return;
    setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false);
    void run(async () => {
      await apiFetch(`/ai/managed/${connection.provider_id}/connection`, {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify({ expected_revision: connection.revision, outbound_enabled: !connection.outbound_enabled }),
      });
      return connection.outbound_enabled ? "Outbound approval disabled. New runtime calls are blocked." : "provider approved. Check the connection again.";
    });
  }

  function verify() {
    if (!connection || retired) return;
    const current = epoch.current;
    setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false);
    void run(async () => {
      const result = await apiFetch<Check>(`/ai/managed/${connection.provider_id}/check`, { method: "POST" });
      if (current === epoch.current) {
        setCheck(result);
        if (connection.provider_id === repair.current.provider && result.models.some(item => item.id === repair.current.model)) setModelId(repair.current.model);
      }
      if (result.health.status !== "healthy") throw new Error(result.health.error || "Provider credential check failed");
      return `Credential verified. ${result.models.length} model candidates found. Catalog presence alone does not prove Agent compatibility. Test the selected model before saving.`;
    });
  }

  function testInference() {
    if (!connection || retired || !check || !modelId || !approveCharge || busy) return;
    const current = epoch.current;
    setProbe(null);
    void run(async () => {
      const result = await apiFetch<Probe>(`/ai/managed/${connection.provider_id}/probe`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ expected_connection_revision: check.connection_revision, model_id: modelId, approve_charge: true }),
      });
      if (current === epoch.current) setProbe(result);
      if (!result.passed) throw new Error(result.diagnostic ? `${result.diagnostic.summary} ${result.diagnostic.cause} Next: ${result.diagnostic.recommendation}` : "Model inference test failed; no routes were changed.");
      return "Model passed the fixed-input Agent JSON-schema test. No device data or tools were used; routes have not changed.";
    });
  }

  function configure(event: FormEvent) {
    event.preventDefault();
    if (!connection || retired || check?.health.status !== "healthy" || !modelId || !probe?.passed || probe.model_id !== modelId) return;
    const current = epoch.current;
    void run(async () => {
      const result = await apiFetch<Configured>(`/ai/managed/${connection.provider_id}/configure`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ expected_connection_revision: check.connection_revision, model_id: modelId,
          expected_configuration_hash: check.configuration_hash, probe_reservation_id: probe.quota_reservation_id,
          display_name: displayName, cost_class: costClass,
          purposes: [...(investigation ? ["investigation"] : []), ...(authoring ? ["capability.authoring"] : [])],
          replace_existing_routes: replaceRoutes, ...budgets }),
      });
      if (current === epoch.current) { setCheck(null); setProbe(null); }
      return `${result.model.display_name} saved for ${result.routes.map((route) => route.purpose).join(" and ")}. Previous models and historical runs were retained. Device enrollment still requires its own approval.`;
    });
  }

  return (
    <Card id="guided-provider-setup" className="mb-5 border-[#d8dbe0] bg-white shadow-sm">
      <span id="guided-openrouter-setup" aria-hidden="true" />
      <CardHeader className="border-b border-[#e4e6e9]">
        <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-5 text-[#5856d6]" /> Guided AI provider setup</CardTitle>
        <CardDescription>Choose a provider, save its API key, test a model, then assign its uses. API URL and authentication are configured for you. Existing connections and routes are not switched automatically.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {notice && <p role={notice.error ? "alert" : "status"} className={`rounded-md border p-3 text-sm ${notice.error ? "border-red-200 bg-red-50 text-red-800" : "border-green-200 bg-green-50 text-green-800"}`}>{notice.text}</p>}
        {repairSource && <p className="text-sm">Repair proposal only: review the model, inference test and selected routes before approving changes. <a className="text-violet-700 underline" href={`/?investigation=${encodeURIComponent(repairSource)}`}>Return to the original investigation to retry after repair</a>.</p>}
        {!secureTransport && <p role="alert" className="text-sm text-red-800">Open this page over HTTPS before entering a key. Localhost is allowed for development.</p>}
        {setup && !setup.storage_ready && <p role="alert" className="text-sm text-red-800">Managed key storage is unavailable. Ask the server administrator to provision or restore its encryption key; existing keys cannot be recovered without it.</p>}
        {setup && <label className={fieldClass}>Provider connection
          <select className={selectClass} disabled={busy} value={selectedId} onChange={(event) => { setSelectedId(event.target.value); setApiKey(""); setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false); setNotice(null); setApproved(false); setReplaceRoutes(false); }}>
            <option value="">Create a new connection</option>
            {setup.connections.map((item) => <option key={item.provider_id} value={item.provider_id}>{item.name} · {setup.presets.find(p => p.id === item.preset)?.label ?? item.preset}{item.provider_enabled ? "" : " (retired)"}</option>)}
          </select>
        </label>}
        {setup && !connection && <label className={fieldClass}>AI provider
          <select className={selectClass} value={presetId} disabled={busy} onChange={event => {
            setPresetId(event.target.value); setName(event.target.value); setApiKey(""); setApproved(false);
            setCheck(null); setModelId(""); setProbe(null); setApproveCharge(false); setReplaceRoutes(false); setNotice(null);
          }}>
            {setup.presets.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
          </select>
        </label>}
        {preset && <p className="text-sm leading-6 text-muted-foreground"><strong>{providerLabel}</strong> · {preset.notes}</p>}
        <p className="text-xs text-muted-foreground">Self-hosted OpenAI-compatible servers (for example Ollama/vLLM), private gateways and external secret references are configured under Advanced below. Azure resource endpoints, AWS Bedrock and Vertex AI are not guided presets.</p>
        {retired && connection && <section aria-label="Retired AI provider" className="rounded-md border border-amber-200 bg-amber-50 p-4 text-sm">
          <p role="alert" className="font-medium">Provider retired: {connection.name}. Restore it before verifying the key or using models.</p>
          <p className="mt-2">Your saved key is retained. Restoring this provider does not enable outbound access, restore models or routes, or make an AI call. Review and confirm the restore below, then approve outbound access if it is disabled.</p>
          <AICatalogControls kind="providers" id={connection.provider_id} name={connection.name} enabled={false} onChanged={restored} />
        </section>}
        <div className="grid gap-8 xl:grid-cols-3">
          <section className="space-y-4" aria-labelledby="provider-key-heading">
            <h2 id="provider-key-heading" className="font-semibold">1. Key and outbound allowlist</h2>
            <p className="break-all font-mono text-xs text-muted-foreground">{endpoint}</p>
            {connection && <div className="space-y-2 text-sm">
              <p className="flex items-center gap-2"><KeyRound className="size-4" /> Key saved (write-only)</p>
              <p>Provider status: {retired ? "retired" : "active"}</p>
              <p>Outbound access: {connection.outbound_enabled ? "approved" : "disabled"}</p>
              <Button type="button" variant="outline" className={outlineClass} disabled={busy || retired} onClick={toggleAccess}>{connection.outbound_enabled ? "Disable outbound access" : "Approve provider endpoint"}</Button>
            </div>}
            {connection && <AIProviderTimeoutControl key={connection.provider_id} providerId={connection.provider_id}
              timeoutSeconds={connection.request_timeout_seconds ?? 20} connectionRevision={connection.revision}
              disabled={busy || retired} onChanged={restored} />}
            <form onSubmit={saveKey} className="space-y-4" autoComplete="off">
              {!connection && <label className={fieldClass}>Connection name<Input required maxLength={120} pattern={"[A-Za-z0-9][A-Za-z0-9_. \\-]*"} value={name} onChange={(event) => setName(event.target.value)} disabled={busy} /></label>}
              {!connection && <label className={fieldClass}>Model-call timeout (seconds)<Input type="number" required min={1} max={120} step={1} value={newTimeout} onChange={event => setNewTimeout(event.target.value)} disabled={busy} /></label>}
              <label className={fieldClass}>{connection ? "Replacement Provider API key" : "Provider API key"}
                <Input type="password" autoComplete="off" spellCheck={false} autoCapitalize="none" required minLength={10} maxLength={512} value={apiKey} onChange={(event) => setApiKey(event.target.value)} disabled={busy || retired || !secureTransport || !setup?.storage_ready} placeholder="Paste your inference API key" aria-describedby="provider-key-help" />
              </label>
              <p id="provider-key-help" className="text-xs leading-5 text-muted-foreground">Encrypted on the server with a separate encryption key. Never returned by the API or stored in browser storage. Use an inference key, not a management key.</p>
              {!connection && <label className="flex items-start gap-2 text-sm"><input type="checkbox" required checked={approved} onChange={(event) => setApproved(event.target.checked)} disabled={busy} className="mt-1" /><span>Allow this connection to send credentials and AI requests to the selected provider’s HTTPS endpoint above. Requests leave this server.</span></label>}
              <Button className={buttonClass} disabled={busy || retired || !secureTransport || !setup?.storage_ready || !apiKey || (!connection && !approved)}>{connection ? "Replace saved key" : "Save key and approve provider"}</Button>
            </form>
          </section>
          <section className="space-y-4" aria-labelledby="provider-check-heading">
            <h2 id="provider-check-heading" className="font-semibold">2. Health check and model discovery</h2>
            <p className="text-sm leading-6 text-muted-foreground">Verify the key and retrieve the account’s model catalog. Models may have different capabilities; a successful fixed-input test is required before saving routes. Batch-only variants are excluded.</p>
            <Button type="button" variant="outline" className={outlineClass} disabled={busy || retired || !connection?.outbound_enabled || !setup?.storage_ready} onClick={verify}>Verify key and discover models</Button>
            {check?.health.status === "healthy" && <p className="flex items-center gap-2 text-sm text-green-800"><CheckCircle2 className="size-4" /> Credential verified</p>}
            <p className="text-xs leading-5 text-muted-foreground">This check does not generate text or validate a model’s quality. Investigations and Studio generation make model calls and may incur provider charges.</p>
            <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approveCharge} onChange={event => setApproveCharge(event.target.checked)} disabled={busy || !modelId} className="mt-1" /><span>Allow one inference test for the selected model (up to 512 output tokens; may incur charges). Fixed readiness input only, no inventory or tools.</span></label>
            <Button type="button" variant="outline" className={outlineClass} disabled={busy || retired || !modelId || !approveCharge || check?.health.status !== "healthy"} onClick={testInference}>Test model inference</Button>
            {probe?.diagnostic && <AIProviderDiagnosticDetails diagnostic={probe.diagnostic} />}
            {probe?.passed && probe.model_id === modelId && <p role="status" className="text-sm text-green-800">Inference and Agent decision schema verified. This is not a reasoning-quality or live-device test.</p>}
          </section>
          <section className="space-y-4" aria-labelledby="provider-route-heading">
            <h2 id="provider-route-heading" className="font-semibold">3. Model and agent routes</h2>
            <form onSubmit={configure} className="space-y-4">
              <label className={fieldClass}>Model<select required className={selectClass} disabled={busy || check?.health.status !== "healthy"} value={modelId} onChange={(event) => { setModelId(event.target.value); setProbe(null); setApproveCharge(false); }}>
                <option value="">{check?.health.status === "healthy" ? "Select a model to test" : "Verify the key first"}</option>
                {check?.models.map((model) => <option key={model.id} value={model.id}>{model.name}</option>)}
              </select></label>
              <label className={fieldClass}>Model display name<Input required maxLength={255} value={displayName} onChange={(event) => setDisplayName(event.target.value)} disabled={busy} /></label>
              <label className={fieldClass}>Cost class<select className={selectClass} value={costClass} onChange={(event) => setCostClass(event.target.value)} disabled={busy}><option value="low">Low</option><option value="standard">Standard</option><option value="premium">Premium</option></select></label>
              <fieldset disabled={busy} className="space-y-2 text-sm"><legend className="mb-2 font-medium">Use this model for</legend>
                <label className="flex items-center gap-2"><input type="checkbox" checked={investigation} onChange={(event) => setInvestigation(event.target.checked)} /> AI Operator, alert investigations and dashboard AI</label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={authoring} onChange={(event) => setAuthoring(event.target.checked)} /> Capability Studio authoring</label>
              </fieldset>
              <details className="text-sm"><summary className="cursor-pointer font-medium">Execution budgets</summary><div className="mt-3 grid grid-cols-2 gap-3">
                {([
                  ["max_iterations", "Max iterations", 100], ["max_tool_calls", "Max tool calls", 500],
                  ["timeout_seconds", "Timeout seconds", 3600], ["token_budget", "Token budget", 10000000],
                ] as const).map(([key, label, max]) => <label key={key} className={fieldClass}>{label}<Input type="number" required min={1} max={max} value={budgets[key]} onChange={(event) => setBudgets({ ...budgets, [key]: Number(event.target.value) })} disabled={busy} /></label>)}
              </div></details>
              <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={replaceRoutes} onChange={(event) => setReplaceRoutes(event.target.checked)} disabled={busy} className="mt-1" /><span>Replace existing selected routes, including their fallback lists. If reusing their current model display name, retain the old model with a previous-version label. Unselected routes and historical runs are preserved.</span></label>
              <Button className={buttonClass} disabled={busy || retired || !modelId || !probe?.passed || probe.model_id !== modelId || check?.health.status !== "healthy" || !connection?.outbound_enabled || (!investigation && !authoring)}>Save model and routes</Button>
            </form>
          </section>
        </div>
      </CardContent>
    </Card>
  );
}
