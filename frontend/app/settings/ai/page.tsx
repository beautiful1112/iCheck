"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Cpu,
  GitBranch,
  KeyRound,
  Plus,
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
import { cn } from "@/lib/utils";

type CredentialProfile = {
  id: string;
  name: string;
  provider: string;
  secret_ref: string;
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

const apiUrl =
  process.env.NEXT_PUBLIC_ICHECK_API_URL || "http://localhost:8000/api/v1";

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, init);
  if (!response.ok) {
    const document = (await response.json().catch(() => null)) as {
      detail?: string | Array<{ msg?: string }>;
    } | null;
    const detail = Array.isArray(document?.detail)
      ? document.detail.map((item) => item.msg || "Validation failed").join("; ")
      : document?.detail;
    throw new Error(detail || `Request failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

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
  const [secretRef, setSecretRef] = useState("env://ICHECK_AI_PROVIDER_TOKEN");
  const [providerName, setProviderName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [authType, setAuthType] = useState<AIProvider["auth_type"]>("bearer");
  const [credentialRef, setCredentialRef] = useState("");
  const [modelProviderId, setModelProviderId] = useState("");
  const [modelDisplayName, setModelDisplayName] = useState("");
  const [modelName, setModelName] = useState("");
  const [modelCapabilities, setModelCapabilities] = useState("chat,tools,json_schema");
  const [routePurpose, setRoutePurpose] = useState("investigation");
  const [routeModelId, setRouteModelId] = useState("");
  const [routeFallbackIds, setRouteFallbackIds] = useState<string[]>([]);
  const [maxIterations, setMaxIterations] = useState("8");
  const [maxToolCalls, setMaxToolCalls] = useState("20");
  const [timeoutSeconds, setTimeoutSeconds] = useState("300");
  const [tokenBudget, setTokenBudget] = useState("50000");

  const load = useCallback(async () => {
    try {
      const [credentialData, providerData, modelData, routeData] =
        await Promise.all([
          apiRequest<CredentialProfile[]>("/credential-profiles"),
          apiRequest<AIProvider[]>("/ai/providers"),
          apiRequest<AIModel[]>("/ai/models"),
          apiRequest<AIModelRoute[]>("/ai/routes"),
        ]);
      setCredentials(
        credentialData.filter((item) => item.provider === "environment"),
      );
      setProviders(providerData);
      setModels(modelData);
      setRoutes(routeData);
      if (!credentialRef && credentialData.length > 0) {
        setCredentialRef(credentialData[0].name);
      }
      if (!modelProviderId && providerData.length > 0) {
        setModelProviderId(providerData[0].id);
      }
      if (!routeModelId && modelData.length > 0) {
        setRouteModelId(modelData[0].id);
      }
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to load AI settings",
      });
    } finally {
      setLoading(false);
    }
  }, [credentialRef, modelProviderId, routeModelId]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeoutId);
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
    { label: "Token references", value: credentials.length, icon: KeyRound },
    { label: "Providers", value: providers.length, icon: Server },
    { label: "Models", value: models.length, icon: Cpu },
    { label: "Routes", value: routes.length, icon: GitBranch },
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
          provider: "environment",
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
          provider_type: "openai_compatible",
          base_url: baseUrl,
          auth_type: authType,
          credential_profile_ref: authType === "none" ? null : credentialRef,
          request_timeout_seconds: 20,
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
      <header className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-4 px-4 sm:px-6 xl:px-8">
          <Link
            href="/"
            className="grid size-9 place-items-center rounded-md bg-[#5856d6] text-white"
            aria-label="Back to operations"
          >
            <Activity className="size-[18px]" />
          </Link>
          <div>
            <p className="text-sm font-semibold">iCheck Administration</p>
            <p className="text-xs text-[#a7b0bf]">AI runtime configuration</p>
          </div>
          <Badge className="ml-auto border-[#7a79df]/50 bg-[#5856d6]/30 text-[#d9d8ff]">
            M2 foundation
          </Badge>
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
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#768192]">
              Configure model endpoints, secret references, model capabilities,
              and bounded agent-loop budgets. Raw tokens never enter this page or
              the iCheck database.
            </p>
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
                ? "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#1b874b]"
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
                  <p className="text-xs text-[#768192]">{label}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </section>

        <div className="grid gap-5 xl:grid-cols-2">
          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="size-4 text-[#5856d6]" /> Token secret reference
              </CardTitle>
              <CardDescription>
                Store only an environment reference. Put the real value in the API
                service environment or a future Vault/KMS adapter.
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
                  <FieldLabel>Secret reference</FieldLabel>
                  <Input
                    required
                    value={secretRef}
                    onChange={(event) => setSecretRef(event.target.value)}
                    placeholder="env://ICHECK_AI_PROVIDER_TOKEN"
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
                  <p className="text-sm text-[#8a93a2]">No AI credential profiles yet.</p>
                ) : (
                  credentials.map((credential) => (
                    <div
                      key={credential.id}
                      className="flex items-center justify-between rounded-md bg-[#f8f9fa] px-3 py-2.5"
                    >
                      <div>
                        <p className="text-sm font-medium">{credential.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-[#768192]">
                          {credential.secret_ref}
                        </p>
                      </div>
                      <ShieldCheck className="size-4 text-[#2eb85c]" />
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
                OpenAI-compatible endpoint with allowlisted outbound access.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createProvider} className="grid gap-4 sm:grid-cols-2">
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
                    {credentials.map((credential) => (
                      <option key={credential.id} value={credential.name}>
                        {credential.name}
                      </option>
                    ))}
                  </select>
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
                Register model identity and capabilities independently of the provider.
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
                    {providers.map((provider) => (
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
                Bind a purpose to a model and deterministic execution budgets.
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
                    {models.map((model) => (
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
                      <p className="text-xs text-[#8a93a2]">
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
                  <p className="mt-2 text-[11px] leading-5 text-[#8a93a2]">
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

        <Card className="mt-5 border-[#d8dbe0] bg-white shadow-sm">
          <CardHeader className="border-b border-[#e4e6e9]">
            <CardTitle className="flex items-center gap-2 text-base">
              <Sparkles className="size-4 text-[#5856d6]" /> Active AI runtime catalog
            </CardTitle>
            <CardDescription>
              Provider health is configuration evidence; the LangGraph runtime is
              the next implementation slice.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-5 lg:grid-cols-3">
            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-[#768192]">
                Providers
              </h2>
              <div className="space-y-2">
                {providers.map((provider) => (
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
                    <p className="mt-2 truncate font-mono text-[11px] text-[#768192]">
                      {provider.base_url}
                    </p>
                    {provider.last_health_error ? (
                      <p className="mt-2 text-xs text-[#a52a2a]">
                        {provider.last_health_error}
                      </p>
                    ) : null}
                  </div>
                ))}
                {providers.length === 0 ? (
                  <p className="text-sm text-[#8a93a2]">No providers configured.</p>
                ) : null}
              </div>
            </div>

            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-[#768192]">
                Models
              </h2>
              <div className="space-y-2">
                {models.map((model) => (
                  <div key={model.id} className="rounded-md border border-[#e4e6e9] p-3">
                    <p className="text-sm font-medium">{model.display_name}</p>
                    <p className="mt-1 font-mono text-xs text-[#768192]">
                      {model.model_name}
                    </p>
                    <p className="mt-2 text-xs text-[#8a93a2]">
                      {providerNames.get(model.provider_id) || "Unknown provider"}
                    </p>
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
                  </div>
                ))}
                {models.length === 0 ? (
                  <p className="text-sm text-[#8a93a2]">No models configured.</p>
                ) : null}
              </div>
            </div>

            <div>
              <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.08em] text-[#768192]">
                Routes and budgets
              </h2>
              <div className="space-y-2">
                {routes.map((route) => (
                  <div key={route.id} className="rounded-md border border-[#e4e6e9] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-mono text-sm font-medium">{route.purpose}</p>
                      <Badge className="border-[#2eb85c]/25 bg-[#2eb85c]/10 text-[#1b874b]">
                        bounded
                      </Badge>
                    </div>
                    <p className="mt-2 text-xs text-[#768192]">
                      {modelNames.get(route.primary_model_id) || "Unknown model"}
                    </p>
                    {route.fallback_model_ids.length ? (
                      <p className="mt-1 text-[11px] leading-5 text-[#8a93a2]">
                        Fallback: {route.fallback_model_ids
                          .map((modelId) => modelNames.get(modelId) || "Unknown model")
                          .join(" → ")}
                      </p>
                    ) : null}
                    <p className="mt-2 text-[11px] leading-5 text-[#8a93a2]">
                      {route.max_iterations} iterations · {route.max_tool_calls} tools ·{" "}
                      {route.timeout_seconds}s · {route.token_budget.toLocaleString()} tokens
                    </p>
                  </div>
                ))}
                {routes.length === 0 ? (
                  <p className="text-sm text-[#8a93a2]">No model routes configured.</p>
                ) : null}
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
