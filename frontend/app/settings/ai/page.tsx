"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  BrainCircuit,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Cpu,
  GitBranch,
  Gauge,
  Globe2,
  KeyRound,
  Plus,
  PlugZap,
  RefreshCw,
  Server,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ProviderSetup } from "@/components/provider-setup";
import { AIProviderTimeoutControl } from "@/components/ai-provider-timeout-control";
import { AICatalogControls } from "@/components/ai-catalog-controls";
import { apiFetch as apiRequest, NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type CredentialProfile = {
  id: string;
  name: string;
  provider: string;
  secret_ref: string;
  allowed_adapters: string[];
  worker_selector: Record<string, string>;
  enabled: boolean;
};

type AIProvider = {
  id: string;
  name: string;
  provider_type: string;
  base_url: string;
  auth_type: "none" | "bearer" | "api_key";
  credential_profile_ref: string | null;
  request_timeout_seconds: number;
  privacy_tier: "external" | "private" | "local";
  data_residency: string;
  enabled: boolean;
  last_health_status: string | null;
  last_health_error: string | null;
  last_checked_at: string | null;
};

type AIModel = {
  id: string;
  provider_id: string;
  display_name: string;
  model_name: string;
  capabilities: string[];
  context_window: number | null;
  max_output_tokens: number | null;
  cost_class: "low" | "standard" | "premium";
  enabled: boolean;
};

type AIModelRoute = {
  id: string;
  purpose: string;
  primary_model_id: string;
  fallback_model_ids: string[];
  max_iterations: number;
  max_tool_calls: number;
  timeout_seconds: number;
  token_budget: number;
  enabled: boolean;
};

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="mb-1.5 block text-xs font-semibold text-[#4f5d73]">
      {children}
    </span>
  );
}

const inputClass =
  "h-10 border-[#b1b7c1] bg-white text-sm shadow-none focus-visible:border-[#5856d6] focus-visible:ring-[#5856d6]/15";
const selectClass =
  "h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-3 text-sm text-[#2c384a] outline-none focus:border-[#5856d6] focus:ring-2 focus:ring-[#5856d6]/15";

export default function AISettingsPage() {
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [models, setModels] = useState<AIModel[]>([]);
  const [routes, setRoutes] = useState<AIModelRoute[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const [credentialName, setCredentialName] = useState("");
  const [credentialProvider, setCredentialProvider] = useState<
    "environment" | "vault" | "vault_dynamic"
  >("environment");
  const [secretRef, setSecretRef] = useState("env://ICHECK_AI_PROVIDER_TOKEN");
  const [providerName, setProviderName] = useState("");
  const [providerType, setProviderType] = useState("openai_compatible");
  const [providerTimeout, setProviderTimeout] = useState("20");
  const [baseUrl, setBaseUrl] = useState("");
  const [authType, setAuthType] = useState<AIProvider["auth_type"]>("bearer");
  const [credentialRef, setCredentialRef] = useState("");
  const [privacyTier, setPrivacyTier] = useState<AIProvider["privacy_tier"]>("external");
  const [dataResidency, setDataResidency] = useState("unspecified");
  const [modelProviderId, setModelProviderId] = useState("");
  const [modelDisplayName, setModelDisplayName] = useState("");
  const [modelName, setModelName] = useState("");
  const [modelCapabilities, setModelCapabilities] = useState("chat,tools,json_schema");
  const [modelCostClass, setModelCostClass] = useState<AIModel["cost_class"]>("standard");
  const [routePurpose, setRoutePurpose] = useState("investigation");
  const [routeModelId, setRouteModelId] = useState("");
  const [routeFallbackIds, setRouteFallbackIds] = useState<string[]>([]);
  const [maxIterations, setMaxIterations] = useState("8");
  const [maxToolCalls, setMaxToolCalls] = useState("20");
  const [timeoutSeconds, setTimeoutSeconds] = useState("300");
  const [tokenBudget, setTokenBudget] = useState("50000");
  const epoch = useRef(0);

  const load = useCallback(async () => {
    const current = epoch.current;
    try {
      const [credentialData, providerData, modelData, routeData] =
        await Promise.all([
          apiRequest<CredentialProfile[]>("/credential-profiles"),
          apiRequest<AIProvider[]>("/ai/providers"),
          apiRequest<AIModel[]>("/ai/models"),
          apiRequest<AIModelRoute[]>("/ai/routes"),
        ]);
      if (current !== epoch.current) return;
      setCredentials(
        credentialData.filter(
          (item) =>
            item.allowed_adapters.includes("ai_provider") &&
            Object.keys(item.worker_selector).length === 0 &&
            (item.provider === "environment" ||
              item.provider === "vault" ||
              item.provider === "vault_kv2" ||
              item.provider === "managed_ai" ||
              item.provider === "vault_dynamic"),
        ),
      );
      setProviders(providerData);
      setModels(modelData);
      setRoutes(routeData);
      const externalCredential = credentialData.find((item) => item.enabled && item.allowed_adapters.includes("ai_provider") && Object.keys(item.worker_selector).length === 0 && item.provider !== "managed_ai");
      if (!credentialRef && externalCredential) {
        setCredentialRef(externalCredential.name);
      }
      if (!modelProviderId && providerData.length > 0) {
        setModelProviderId(providerData[0].id);
      }
      if (!routeModelId && modelData.length > 0) {
        setRouteModelId(modelData[0].id);
      }
    } catch (error) {
      if (current !== epoch.current) return;
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to load AI settings",
      });
    } finally {
      if (current === epoch.current) setLoading(false);
    }
  }, [credentialRef, modelProviderId, routeModelId]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeoutId);
  }, [load]);
  useEffect(() => {
    const reset = () => {
      epoch.current++; setCredentials([]); setProviders([]); setModels([]); setRoutes([]);
      setCredentialRef(""); setModelProviderId(""); setRouteModelId(""); setRouteFallbackIds([]); setMessage(null);
      setLoading(true); void load();
    };
    const storage = (event: StorageEvent) => { if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) reset(); };
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => { epoch.current++; window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage); };
  }, [load]);

  const providerNames = useMemo(
    () => new Map(providers.map((provider) => [provider.id, provider.name])),
    [providers],
  );
  const modelNames = useMemo(
    () => new Map(models.map((model) => [model.id, model.display_name])),
    [models],
  );
  const overviewStats = [
    { label: "AI credentials", value: credentials.filter(item => item.enabled).length, icon: KeyRound },
    { label: "Providers", value: providers.filter(item => item.enabled).length, icon: Server },
    { label: "Models", value: models.filter(item => item.enabled).length, icon: Cpu },
    { label: "Routes", value: routes.filter(item => item.enabled).length, icon: GitBranch },
  ];

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving("credential");
    setMessage(null);
    try {
      await apiRequest<CredentialProfile>("/credential-profiles", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: credentialName,
          provider: credentialProvider,
          secret_ref: secretRef,
          allowed_adapters: ["ai_provider"],
          created_by: "platform.admin",
        }),
      });
      setCredentialName("");
      setMessage({ tone: "success", text: "Token reference created." });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to save token reference",
      });
    } finally {
      setSaving(null);
    }
  }

  async function createProvider(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving("provider");
    setMessage(null);
    try {
      await apiRequest<AIProvider>("/ai/providers", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: providerName,
          provider_type: providerType,
          base_url: baseUrl,
          auth_type: authType,
          credential_profile_ref: authType === "none" ? null : credentialRef,
          request_timeout_seconds: Number(providerTimeout),
          privacy_tier: privacyTier,
          data_residency: dataResidency,
          created_by: "platform.admin",
        }),
      });
      setProviderName("");
      setBaseUrl("");
      setMessage({ tone: "success", text: "AI provider created." });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to create provider",
      });
    } finally {
      setSaving(null);
    }
  }

  async function createModel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving("model");
    setMessage(null);
    try {
      await apiRequest<AIModel>("/ai/models", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider_id: modelProviderId,
          display_name: modelDisplayName,
          model_name: modelName,
          capabilities: modelCapabilities
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          default_parameters: {},
          cost_class: modelCostClass,
          created_by: "platform.admin",
        }),
      });
      setModelDisplayName("");
      setModelName("");
      setMessage({ tone: "success", text: "Model profile created." });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to create model",
      });
    } finally {
      setSaving(null);
    }
  }

  async function createRoute(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving("route");
    setMessage(null);
    try {
      await apiRequest<AIModelRoute>("/ai/routes", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          purpose: routePurpose,
          primary_model_id: routeModelId,
          fallback_model_ids: routeFallbackIds,
          max_iterations: Number(maxIterations),
          max_tool_calls: Number(maxToolCalls),
          timeout_seconds: Number(timeoutSeconds),
          token_budget: Number(tokenBudget),
          created_by: "platform.admin",
        }),
      });
      setRouteFallbackIds([]);
      setMessage({ tone: "success", text: "Model route created." });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to create route",
      });
    } finally {
      setSaving(null);
    }
  }

  async function testProvider(providerId: string) {
    setSaving(`health-${providerId}`);
    setMessage(null);
    try {
      const health = await apiRequest<{
        status: string;
        model_count: number;
        error: string | null;
      }>(`/ai/providers/${providerId}/health?actor=platform.admin`, {
        method: "POST",
      });
      setMessage({
        tone: health.status === "healthy" ? "success" : "error",
        text:
          health.status === "healthy"
            ? `Connection healthy; provider returned ${health.model_count} models.`
            : health.error || "Provider health check failed.",
      });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to test provider",
      });
    } finally {
      setSaving(null);
    }
  }

  return (
    <div className="min-h-screen bg-[#f3f4f7] text-[#2c384a]">
      <header data-text-surface="dark" className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] flex-wrap items-center gap-3 px-4 py-3 sm:px-6 xl:px-8">
          <Link
            href="/"
            className="grid size-9 place-items-center rounded-md bg-[#5856d6] text-white"
            aria-label="Back to operations"
          >
            <Activity className="size-[18px]" />
          </Link>
          <div>
            <p className="text-sm font-semibold">iCheck Administration</p>
            <p className="text-xs text-muted-foreground">AI runtime configuration</p>
          </div>
          <Badge className="ml-auto border-[#7a79df]/50 bg-[#5856d6]/30 text-[#d9d8ff]">
            Governed runtime
          </Badge>
          <Button asChild variant="outline" size="sm" className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white">
            <Link href="/settings/mcp">
              <PlugZap className="size-4" /> MCP Gateway
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white">
            <Link href="/settings/agents">
              <BrainCircuit className="size-4" /> Agent profiles
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white">
            <Link href="/settings/tenancy">
              <Globe2 className="size-4" /> Tenant & region
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white">
            <Link href="/settings/identity">
              <ShieldCheck className="size-4" /> Identity
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="border-white/20 bg-white/5 text-white hover:bg-white/10 hover:text-white">
            <Link href="/settings/scaling">
              <Gauge className="size-4" /> Worker capacity
            </Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 xl:px-8">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Link
              href="/"
              className="mb-3 inline-flex items-center gap-1.5 text-xs font-medium text-[#5856d6] hover:text-[#3c3a9f]"
            >
              <ArrowLeft className="size-3.5" /> Operations workspace
            </Link>
            <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-[-0.02em] text-[#2c384a]">
              <span className="grid size-10 place-items-center rounded-lg bg-[#e9e8fb] text-[#5856d6]">
                <Bot className="size-5" />
              </span>
              AI providers and routing
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              Connect OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Qwen or OpenRouter.
              Keys are encrypted and write-only. Choose which model handles each task;
              private gateways and externally managed secrets remain available below.
            </p>
            <Link href="/settings/ai/proposal-recovery" className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-[#5856d6] hover:underline">
              <ShieldCheck className="size-4" /> Orphaned proposal recovery (global admins)
            </Link>
            <Link href="/settings/ai/authoring-quota" className="mt-2 flex items-center gap-1.5 text-sm font-medium text-[#5856d6] hover:underline">
              <Gauge className="size-4" /> AI model-call quota
            </Link>
          </div>
          <Button
            variant="outline"
            onClick={() => {
              setLoading(true);
              void load();
            }}
            disabled={loading}
            className="border-[#b1b7c1] bg-white text-[#4f5d73]"
          >
            <RefreshCw className={cn("size-4", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>

        {message ? (
          <div
            className={cn(
              "mb-5 flex items-center gap-2 rounded-md border px-4 py-3 text-sm",
              message.tone === "success"
                ? "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#166534]"
                : "border-[#e55353]/30 bg-[#e55353]/10 text-[#a52a2a]",
            )}
          >
            {message.tone === "success" ? (
              <CheckCircle2 className="size-4 shrink-0" />
            ) : (
              <XCircle className="size-4 shrink-0" />
            )}
            {message.text}
          </div>
        ) : null}

        <section className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {overviewStats.map(({ label, value, icon: Icon }) => (
            <Card key={label} className="gap-3 border-[#d8dbe0] bg-white py-4 shadow-sm">
              <CardContent className="flex items-center gap-3 px-4">
                <span className="grid size-9 place-items-center rounded-md bg-[#e9e8fb] text-[#5856d6]">
                  <Icon className="size-4" />
                </span>
                <div>
                  <p className="text-xl font-semibold text-[#2c384a]">{value}</p>
                  <p className="text-xs text-muted-foreground">{label}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </section>

        <Link href="/settings/ai/autonomy" className="mb-5 flex items-center gap-4 rounded-lg border border-[#d8dbe0] bg-white p-5 hover:border-[#5856d6]">
          <div><h2 className="font-semibold">Automatic investigation</h2><p className="mt-1 text-sm text-muted-foreground">Authorize read-only alert investigation for managed resources, with grouping, maintenance pause and daily limits.</p></div>
        </Link>
        <Link href="/settings/ai/research" className="mb-5 flex items-center gap-4 rounded-lg border border-[#d8dbe0] bg-white p-5 hover:border-[#5856d6]">
          <Globe2 className="size-6 shrink-0 text-[#5856d6]" aria-hidden="true" />
          <div><h2 className="font-semibold">Internet search</h2><p className="mt-1 text-sm text-muted-foreground">Connect Brave Search or SearXNG so AI can find public references. Configure the provider, key and request limit.</p></div>
          <span className="ml-auto shrink-0 text-[#5856d6]" aria-hidden="true">→</span>
        </Link>

        <ProviderSetup onChanged={load} />

        <p className="mb-5 text-sm leading-6 text-muted-foreground">Multiple enabled models are available choices, not simultaneous calls. Each purpose route selects one primary model and optional ordered fallbacks. Investigations and Studio can use different models. Remove checks dependencies first; replace or remove a model’s routes before removing the model. Historical runs are retained.</p>

        <details className="rounded-lg border border-[#d8dbe0] bg-white p-4">
        <summary className="cursor-pointer font-medium">Advanced providers and external secret references</summary>
        <div className="mt-4 space-y-2 text-sm leading-6 text-muted-foreground">
          <p><strong>Optional expert settings — guided setup already creates these records for you.</strong> Use this area for self-hosted inference, private gateways, externally managed secrets or custom fallback routes. Do not enter your API key again here.</p>
          <p className="font-medium text-foreground">Secret reference → Provider endpoint → Model profile → Purpose route</p>
          <ol className="ml-5 list-decimal space-y-1">
            <li><strong>Token reference:</strong> a pointer to a secret already provisioned by your administrator. For example, env://ICHECK_AI_PROVIDER_TOKEN names a server environment variable; Vault references name an existing KV field or dynamic-lease role. Do not paste a key here. This form does not create environment variables or configure Vault.</li>
            <li><strong>Provider:</strong> where AI requests go: API protocol, base URL, authentication and token reference. One provider can offer many models. Custom hostnames must already be approved by the server administrator; a guided connection approves only its selected fixed endpoint.</li>
            <li><strong>Model:</strong> a provider’s exact model ID and advertised capabilities. Registering it does not prove inference works; batch variants cannot serve interactive Agents.</li>
            <li><strong>Route:</strong> investigation serves AI Operator, alert investigations and dashboard AI; capability.authoring serves Studio generation. Choose one primary model and ordered fallbacks, not parallel calls. A new purpose name alone does not create a new workflow.</li>
          </ol>
          <p>Remove/Restore is available for each module. Restore does not re-approve outbound access or recover deleted external secrets. Retired names remain reserved for history; restore the existing item instead of creating a duplicate.</p>
          <p>Provider timeout limits one model call; route timeout limits the task. Iteration, tool-call and token budgets bound execution, not a currency bill. Cost class is a policy label, not a price quotation. Privacy tier and data residency are declared policy metadata, not proof of the vendor’s storage location.</p>
        </div>
        <div className="mt-5 grid gap-5 xl:grid-cols-2">
          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="size-4 text-[#5856d6]" /> Token secret reference
              </CardTitle>
              <CardDescription>
                Store only an environment, Vault KV v2, or Vault dynamic-lease
                reference. No plaintext secret belongs in this form. Guided setup stores encrypted keys separately and creates managed-ai references automatically; do not copy or reuse them for another provider.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createCredential} className="grid gap-4 sm:grid-cols-2">
                <label>
                  <FieldLabel>Profile name</FieldLabel>
                  <Input
                    required
                    value={credentialName}
                    onChange={(event) => setCredentialName(event.target.value)}
                    placeholder="openai-production-token"
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Secret provider</FieldLabel>
                  <select
                    value={credentialProvider}
                    onChange={(event) => {
                      const value = event.target.value as
                        | "environment"
                        | "vault"
                        | "vault_dynamic";
                      setCredentialProvider(value);
                      setSecretRef(
                        value === "vault"
                          ? "vault-kv2://kv/ai/primary#token"
                          : value === "vault_dynamic"
                            ? "vault-dynamic://ai/creds/runtime"
                            : "env://ICHECK_AI_PROVIDER_TOKEN",
                      );
                    }}
                    className={selectClass}
                  >
                    <option value="environment">Environment reference</option>
                    <option value="vault">Vault KV v2</option>
                    <option value="vault_dynamic">Vault dynamic lease</option>
                  </select>
                </label>
                <label>
                  <FieldLabel>Secret reference</FieldLabel>
                  <Input
                    required
                    value={secretRef}
                    onChange={(event) => setSecretRef(event.target.value)}
                    placeholder={
                      credentialProvider === "vault"
                        ? "vault-kv2://kv/ai/primary#token"
                        : credentialProvider === "vault_dynamic"
                          ? "vault-dynamic://ai/creds/runtime"
                          : "env://ICHECK_AI_PROVIDER_TOKEN"
                    }
                    className={cn(inputClass, "font-mono text-xs")}
                  />
                </label>
                <div className="sm:col-span-2">
                  <Button disabled={saving === "credential"}>
                    <Plus /> Add token reference
                  </Button>
                </div>
              </form>
              <div className="mt-5 space-y-2 border-t border-[#e4e6e9] pt-4">
                {credentials.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No AI credential profiles yet.</p>
                ) : (
                  credentials.filter(item => item.enabled).map((credential) => (
                    <div
                      key={credential.id}
                      className="rounded-md bg-[#f8f9fa] px-3 py-2.5"
                    >
                      <div>
                        <p className="text-sm font-medium">{credential.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                          {credential.secret_ref}
                        </p>
                      </div>
                      <AICatalogControls key={`${credential.id}:${credential.enabled}`} kind="credentials" id={credential.id} name={credential.name} enabled={credential.enabled} onChanged={load} />
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px]">{credential.provider}</Badge>
                        <ShieldCheck className="size-4 text-[#2eb85c]" />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <Server className="size-4 text-[#5856d6]" /> Provider endpoint
              </CardTitle>
              <CardDescription>
                An OpenAI-compatible gateway or native Anthropic endpoint with administrator-approved outbound access.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createProvider} className="grid gap-4 sm:grid-cols-2">
                <label className="sm:col-span-2">
                  <FieldLabel>API protocol</FieldLabel>
                  <select className={selectClass} value={providerType} onChange={event => {
                    setProviderType(event.target.value);
                    setAuthType(event.target.value === "anthropic" ? "api_key" : "bearer");
                  }}>
                    <option value="openai_compatible">OpenAI-compatible Chat Completions</option>
                    <option value="anthropic">Anthropic Messages</option>
                  </select>
                </label>
                <label>
                  <FieldLabel>Provider name</FieldLabel>
                  <Input
                    required
                    value={providerName}
                    onChange={(event) => setProviderName(event.target.value)}
                    placeholder="primary-ai-gateway"
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Base URL</FieldLabel>
                  <Input
                    required
                    type="url"
                    value={baseUrl}
                    onChange={(event) => setBaseUrl(event.target.value)}
                    placeholder="https://ai.example.net/v1"
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Authentication</FieldLabel>
                  <select
                    className={selectClass}
                    value={authType}
                    onChange={(event) =>
                      setAuthType(event.target.value as AIProvider["auth_type"])
                    }
                  >
                    <option value="bearer">Bearer token</option>
                    <option value="api_key">X-API-Key</option>
                    <option value="none">No authentication</option>
                  </select>
                </label>
                <label>
                  <FieldLabel>Credential profile</FieldLabel>
                  <select
                    className={selectClass}
                    value={credentialRef}
                    onChange={(event) => setCredentialRef(event.target.value)}
                    disabled={authType === "none"}
                    required={authType !== "none"}
                  >
                    <option value="">Select a token reference</option>
                    {credentials.filter((credential) => credential.provider !== "managed_ai").map((credential) => (
                      <option key={credential.id} value={credential.name}>
                        {credential.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <FieldLabel>Privacy tier</FieldLabel>
                  <select
                    className={selectClass}
                    value={privacyTier}
                    onChange={(event) => setPrivacyTier(event.target.value as AIProvider["privacy_tier"])}
                  >
                    <option value="external">External</option>
                    <option value="private">Private tenant</option>
                    <option value="local">Local inference</option>
                  </select>
                </label>
                <label>
                  <FieldLabel>Data residency</FieldLabel>
                  <Input
                    required
                    value={dataResidency}
                    onChange={(event) => setDataResidency(event.target.value.toLowerCase())}
                    placeholder="hkg"
                    className={cn(inputClass, "font-mono text-xs")}
                  />
                </label>
                <label>
                  <FieldLabel>Provider model-call timeout (seconds)</FieldLabel>
                  <Input type="number" required min={1} max={120} step={1} value={providerTimeout}
                    onChange={event => setProviderTimeout(event.target.value)} className={inputClass} />
                </label>
                <div className="sm:col-span-2">
                  <Button disabled={saving === "provider"}>
                    <Plus /> Add provider
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <Cpu className="size-4 text-[#5856d6]" /> Model profile
              </CardTitle>
              <CardDescription>
                Select a provider, then its exact API model ID. The display name is your label. Capabilities describe the application contract; entering them does not test inference. Use guided setup for discovery and a readiness test.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createModel} className="grid gap-4 sm:grid-cols-2">
                <label className="sm:col-span-2">
                  <FieldLabel>Provider</FieldLabel>
                  <select
                    className={selectClass}
                    value={modelProviderId}
                    onChange={(event) => setModelProviderId(event.target.value)}
                    required
                  >
                    <option value="">Select a provider</option>
                    {providers.filter(item => item.enabled).map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <FieldLabel>Display name</FieldLabel>
                  <Input
                    required
                    value={modelDisplayName}
                    onChange={(event) => setModelDisplayName(event.target.value)}
                    placeholder="Operations reasoner"
                    className={inputClass}
                  />
                </label>
                <label className="sm:col-span-2">
                  <FieldLabel>Cost class</FieldLabel>
                  <select
                    className={selectClass}
                    value={modelCostClass}
                    onChange={(event) => setModelCostClass(event.target.value as AIModel["cost_class"])}
                  >
                    <option value="low">Low</option>
                    <option value="standard">Standard</option>
                    <option value="premium">Premium</option>
                  </select>
                </label>
                <label>
                  <FieldLabel>Provider model name</FieldLabel>
                  <Input
                    required
                    value={modelName}
                    onChange={(event) => setModelName(event.target.value)}
                    placeholder="ops-reasoner-v1"
                    className={cn(inputClass, "font-mono text-xs")}
                  />
                </label>
                <label className="sm:col-span-2">
                  <FieldLabel>Capabilities, comma separated</FieldLabel>
                  <Input
                    value={modelCapabilities}
                    onChange={(event) => setModelCapabilities(event.target.value)}
                    className={inputClass}
                  />
                </label>
                <div className="sm:col-span-2">
                  <Button disabled={saving === "model" || providers.length === 0}>
                    <Plus /> Add model
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <GitBranch className="size-4 text-[#5856d6]" /> Agent-loop route
              </CardTitle>
              <CardDescription>
                Choose a model for a task and optional ordered fallback models. Fallbacks are tried on eligible failures, not run together. Budgets apply to the task, not every individual tool.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createRoute} className="grid gap-4 sm:grid-cols-2">
                <label>
                  <FieldLabel>Purpose</FieldLabel>
                  <Input
                    required
                    value={routePurpose}
                    onChange={(event) => setRoutePurpose(event.target.value)}
                    placeholder="investigation"
                    className={cn(inputClass, "font-mono text-xs")}
                  />
                </label>
                <label>
                  <FieldLabel>Primary model</FieldLabel>
                  <select
                    className={selectClass}
                    value={routeModelId}
                    onChange={(event) => {
                      const modelId = event.target.value;
                      setRouteModelId(modelId);
                      setRouteFallbackIds((current) =>
                        current.filter((item) => item !== modelId),
                      );
                    }}
                    required
                  >
                    <option value="">Select a model</option>
                    {models.filter(item => item.enabled).map((model) => (
                      <option key={model.id} value={model.id}>
                        {model.display_name}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="sm:col-span-2">
                  <FieldLabel>Fallback models, in selection order</FieldLabel>
                  <div className="grid gap-2 rounded-md border border-[#d8dbe0] bg-[#f8f9fa] p-3 sm:grid-cols-2">
                    {models
                      .filter((model) => model.id !== routeModelId)
                      .map((model) => {
                        const selected = routeFallbackIds.includes(model.id);
                        return (
                          <label
                            key={model.id}
                            className={cn(
                              "flex cursor-pointer items-center gap-2 rounded-md border bg-white px-3 py-2 text-xs",
                              selected
                                ? "border-[#5856d6] text-[#3c3a9f]"
                                : "border-[#e4e6e9] text-[#5c6873]",
                            )}
                          >
                            <input
                              type="checkbox"
                              checked={selected}
                              onChange={(event) =>
                                setRouteFallbackIds((current) =>
                                  event.target.checked
                                    ? [...current, model.id]
                                    : current.filter((item) => item !== model.id),
                                )
                              }
                              className="accent-[#5856d6]"
                            />
                            <span className="min-w-0 truncate">{model.display_name}</span>
                          </label>
                        );
                      })}
                    {models.length <= 1 ? (
                      <p className="text-xs text-muted-foreground">
                        Register another compatible model to configure fallback.
                      </p>
                    ) : null}
                  </div>
                  {routeFallbackIds.length ? (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {routeFallbackIds.map((modelId, index) => (
                        <Badge
                          key={modelId}
                          variant="outline"
                          className="border-[#c9c8ef] bg-[#f4f3ff] text-[10px] text-[#3c3a9f]"
                        >
                          {index + 1}. {modelNames.get(modelId) || "Unknown model"}
                        </Badge>
                      ))}
                    </div>
                  ) : null}
                  <p className="mt-2 text-[11px] leading-5 text-muted-foreground">
                    Fallback is attempted only after an audited retryable model or
                    provider failure and remains inside the investigation deadline.
                  </p>
                </div>
                <label>
                  <FieldLabel>Max iterations</FieldLabel>
                  <Input
                    type="number"
                    min="1"
                    max="100"
                    value={maxIterations}
                    onChange={(event) => setMaxIterations(event.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Max tool calls</FieldLabel>
                  <Input
                    type="number"
                    min="1"
                    max="500"
                    value={maxToolCalls}
                    onChange={(event) => setMaxToolCalls(event.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Timeout seconds</FieldLabel>
                  <Input
                    type="number"
                    min="1"
                    max="3600"
                    value={timeoutSeconds}
                    onChange={(event) => setTimeoutSeconds(event.target.value)}
                    className={inputClass}
                  />
                </label>
                <label>
                  <FieldLabel>Token budget</FieldLabel>
                  <Input
                    type="number"
                    min="1"
                    max="10000000"
                    value={tokenBudget}
                    onChange={(event) => setTokenBudget(event.target.value)}
                    className={inputClass}
                  />
                </label>
                <div className="sm:col-span-2">
                  <Button disabled={saving === "route" || models.length === 0}>
                    <Plus /> Add route
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>

        </details>

        <Card className="mt-5 border-[#d8dbe0] bg-white shadow-sm">
          <CardHeader className="border-b border-[#e4e6e9]">
            <CardTitle className="flex items-center gap-2 text-base">
              <Sparkles className="size-4 text-[#5856d6]" /> Active AI runtime catalog
            </CardTitle>
            <CardDescription>
              Configured routes govern Studio authoring and bounded LangGraph
              investigations. Provider health does not establish model quality or
              live-device acceptance.
              Route timeouts cover the whole task; provider limits apply to each model attempt.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-5 lg:grid-cols-3">
            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Providers
              </h2>
              <div className="space-y-2">
                {providers.filter(item => item.enabled).map((provider) => (
                  <div key={provider.id} className="rounded-md border border-[#e4e6e9] p-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          "size-2 rounded-full bg-[#8a93a2]",
                          provider.last_health_status === "healthy" && "bg-[#2eb85c]",
                          provider.last_health_status === "unhealthy" && "bg-[#e55353]",
                        )}
                      />
                      <p className="min-w-0 flex-1 truncate text-sm font-medium">
                        {provider.name}
                      </p>
                      <Button
                        type="button"
                        size="xs"
                        variant="outline"
                        onClick={() => void testProvider(provider.id)}
                        disabled={saving === `health-${provider.id}`}
                      >
                        Test
                      </Button>
                    </div>
                    <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground">
                      {provider.base_url}
                    </p>
                    <p className="mt-1 text-[10px] font-medium uppercase tracking-[0.08em] text-muted-foreground">
                      {provider.privacy_tier} · {provider.data_residency}
                    </p>
                    <p className="mt-2 text-xs text-muted-foreground">Model attempt elapsed-time limit: {provider.request_timeout_seconds}s, further bounded by the task and worker lease.</p>
                    {credentials.some(item => item.provider === "managed_ai" && [item.id, item.name].includes(provider.credential_profile_ref ?? ""))
                      ? <a href="#guided-provider-setup" className="mt-2 inline-block text-xs text-violet-700 underline">Edit model-call timeout in Guided AI provider setup</a>
                      : <AIProviderTimeoutControl providerId={provider.id} timeoutSeconds={provider.request_timeout_seconds} onChanged={load} />}
                    {provider.last_health_error ? (
                      <p className="mt-2 text-xs text-[#a52a2a]">
                        {provider.last_health_error}
                      </p>
                    ) : null}
                    <AICatalogControls key={`${provider.id}:${provider.enabled}`} kind="providers" id={provider.id} name={provider.name} enabled={provider.enabled} onChanged={load} />
                  </div>
                ))}
                {providers.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No providers configured.</p>
                ) : null}
              </div>
            </div>

            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Models
              </h2>
              <div className="space-y-2">
                {models.filter(item => item.enabled).map((model) => (
                  <div key={model.id} className="rounded-md border border-[#e4e6e9] p-3">
                    <p className="text-sm font-medium">{model.display_name}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">
                      {model.model_name}
                    </p>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {providerNames.get(model.provider_id) || "Unknown provider"}
                    </p>
                    {model.model_name.toLowerCase().startsWith("qwen/") && providers.some(provider => provider.id === model.provider_id && provider.base_url.replace(/\/$/, "") === "https://openrouter.ai/api/v1") && <p className="mt-2 text-xs text-muted-foreground">
                      Interactive output ceiling: {Math.min(4096, model.max_output_tokens ?? 4096).toLocaleString()} tokens per call, further bounded by remaining tokens.
                      {model.model_name === "qwen/qwen3.8-max-0902" && " Mandatory reasoning enabled at minimal effort."}
                    </p>}
                    <Badge variant="outline" className="mt-2 border-[#d8dbe0] text-[10px] capitalize text-[#5c6873]">
                      {model.cost_class} cost
                    </Badge>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {model.capabilities.map((capability) => (
                        <Badge
                          key={capability}
                          variant="outline"
                          className="border-[#d8dbe0] text-[10px] text-[#5c6873]"
                        >
                          {capability}
                        </Badge>
                      ))}
                    </div>
                    <AICatalogControls key={`${model.id}:${model.enabled}`} kind="models" id={model.id} name={model.display_name} enabled={model.enabled} onChanged={load} />
                  </div>
                ))}
                {models.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No models configured.</p>
                ) : null}
              </div>
            </div>

            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Routes and budgets
              </h2>
              <div className="space-y-2">
                {routes.filter(item => item.enabled).map((route) => (
                  <div key={route.id} className="rounded-md border border-[#e4e6e9] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-mono text-sm font-medium">{route.purpose}</p>
                      <Badge className="border-[#2eb85c]/25 bg-[#2eb85c]/10 text-[#166534]">
                        bounded
                      </Badge>
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {modelNames.get(route.primary_model_id) || "Unknown model"}
                    </p>
                    <AICatalogControls key={`${route.id}:${route.enabled}`} kind="routes" id={route.id} name={route.purpose} enabled={route.enabled} onChanged={load} />
                    {route.fallback_model_ids.length ? (
                      <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                        Fallback: {route.fallback_model_ids
                          .map((modelId) => modelNames.get(modelId) || "Unknown model")
                          .join(" → ")}
                      </p>
                    ) : null}
                    <p className="mt-2 text-[11px] leading-5 text-muted-foreground">
                      {route.max_iterations} iterations · {route.max_tool_calls} tools ·{" "}
                      {route.timeout_seconds}s · {route.token_budget.toLocaleString()} tokens
                    </p>
                  </div>
                ))}
                {routes.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No model routes configured.</p>
                ) : null}
              </div>
            </div>
          </CardContent>
        </Card>
        <details className="mt-5 rounded-lg border border-[#d8dbe0] bg-white p-4">
          <summary className="cursor-pointer font-medium">Retired AI configuration — restore retained items</summary>
          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            {credentials.filter(item => !item.enabled).map(item => <div key={item.id} className="rounded-md border p-3"><p className="text-sm">Token reference: {item.name}</p><AICatalogControls kind="credentials" id={item.id} name={item.name} enabled={false} onChanged={load} /></div>)}
            {providers.filter(item => !item.enabled).map(item => <div key={item.id} className="rounded-md border p-3"><p className="text-sm">Provider: {item.name}</p><AICatalogControls kind="providers" id={item.id} name={item.name} enabled={false} onChanged={load} /></div>)}
            {models.filter(item => !item.enabled).map(item => <div key={item.id} className="rounded-md border p-3"><p className="text-sm">Model: {item.display_name}</p><p className="break-all font-mono text-xs">{item.model_name}</p><AICatalogControls kind="models" id={item.id} name={item.display_name} enabled={false} onChanged={load} /></div>)}
            {routes.filter(item => !item.enabled).map(item => <div key={item.id} className="rounded-md border p-3"><p className="text-sm">Route: {item.purpose}</p><AICatalogControls kind="routes" id={item.id} name={item.purpose} enabled={false} onChanged={load} /></div>)}
          </div>
        </details>
      </main>
    </div>
  );
}
