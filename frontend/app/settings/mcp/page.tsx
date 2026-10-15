"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  CircleOff,
  ExternalLink,
  KeyRound,
  Loader2,
  PlugZap,
  RefreshCw,
  Rocket,
  Server,
  ShieldCheck,
  Unplug,
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
import { apiFetch, beginMCPOAuth } from "@/lib/icheck-api";
import { mcpAttestationIsFresh } from "@/lib/mcp-attestation";
import { oauthObservationSummary, type OAuthSummary } from "@/lib/mcp-oauth-observation";
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

type MCPServer = {
  id: string;
  name: string;
  endpoint_url: string;
  protocol_version: "2026-07-28";
  credential_profile_ref: string | null;
  auth_mode: "none" | "credential_profile" | "oauth_authorization_code";
  oauth_client_id: string | null;
  oauth_client_secret_profile_ref: string | null;
  oauth_authorization_server: string | null;
  oauth_requested_scopes: string[];
  oauth_status:
    | "not_configured"
    | "disconnected"
    | "connected"
    | "expired"
    | "revoked"
    | "revocation_pending";
  oauth_issuer: string | null;
  oauth_resource: string | null;
  oauth_granted_scopes: string[];
  oauth_refresh_token_present: boolean;
  oauth_token_expires_at: string | null;
  oauth_generation: string | null;
  oauth_bundle_version: number | null;
  oauth_credential_observation: OAuthSummary["oauth_credential_observation"];
  oauth_connected_at: string | null;
  enabled: boolean;
  last_checked_at: string | null;
  last_health_status: string | null;
  last_health_error: string | null;
  last_tool_count: number | null;
};

type MCPActivation = {
  id: string;
  server_id: string;
  artifact_version_id: string;
  tool_registration_id: string;
  status: "active" | "inactive";
  tool_name: string;
  mcp_tool_name: string;
  contract_sha256: string;
  rollout_state: "canary" | "full" | "blocked";
  traffic_percent: number;
  minimum_successful_calls: number;
  maximum_failed_calls: number;
  circuit_failure_threshold: number;
  successful_calls: number;
  failed_calls: number;
  consecutive_failures: number;
  circuit_state: "closed" | "open";
  last_call_at: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_failure_sha256: string | null;
  circuit_opened_at: string | null;
  promoted_at: string | null;
  promoted_by: string | null;
  promotion_reason: string | null;
  revision: number;
  activated_by: string;
  activation_reason: string;
  attested_at: string;
  deactivation_reason: string | null;
};

type MCPAttestation = {
  id: string;
  server_id: string;
  artifact_version_id: string;
  status:
    | "pending"
    | "processing"
    | "passed"
    | "failed"
    | "dead_letter"
    | "consumed";
  tool_name: string;
  mcp_tool_name: string;
  expected_contract_sha256: string;
  requested_by: string;
  request_reason: string;
  worker_id: string | null;
  attempt_count: number;
  max_attempts: number;
  advertised_tool_count: number | null;
  failure_code: string | null;
  attested_at: string | null;
  expires_at: string | null;
  consumed_at: string | null;
  consumed_by_activation_id: string | null;
  created_at: string;
};

type MCPScopeChallenge = {
  id: string;
  server_id: string;
  activation_id: string | null;
  investigation_id: string | null;
  tool_name: string;
  challenged_scopes: string[];
  requested_scopes: string[];
  resource_metadata_url: string | null;
  status: "pending" | "authorizing" | "resolved";
  occurrence_count: number;
  revision: number;
  approved_at: string | null;
  approved_by: string | null;
  approval_reason: string | null;
  allowlist_expanded: boolean;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
};

type MCPFleetServerTelemetry = {
  server_id: string;
  server_name: string;
  enabled: boolean;
  posture: "healthy" | "degraded" | "critical" | "inactive";
  health_status: string | null;
  health_is_stale: boolean;
  oauth_status: string;
  active_activations: number;
  canary_activations: number;
  full_activations: number;
  blocked_activations: number;
  open_circuits: number;
  successful_calls: number;
  failed_calls: number;
  success_rate_percent: number | null;
  pending_scope_challenges: number;
  authorizing_scope_challenges: number;
  attestation_backlog: number;
  dead_letter_attestations: number;
  fresh_attestations: number;
  last_checked_at: string | null;
};

type MCPFleetTelemetry = {
  generated_at: string;
  stale_after_seconds: number;
  posture: "empty" | "healthy" | "degraded" | "critical";
  server_count: number;
  enabled_server_count: number;
  disabled_server_count: number;
  healthy_server_count: number;
  unhealthy_server_count: number;
  stale_server_count: number;
  unchecked_server_count: number;
  oauth_attention_server_count: number;
  active_activation_count: number;
  canary_activation_count: number;
  full_activation_count: number;
  blocked_activation_count: number;
  open_circuit_count: number;
  successful_calls: number;
  failed_calls: number;
  success_rate_percent: number | null;
  pending_scope_challenge_count: number;
  authorizing_scope_challenge_count: number;
  attestation_backlog_count: number;
  dead_letter_attestation_count: number;
  fresh_attestation_count: number;
  servers: MCPFleetServerTelemetry[];
};

type ArtifactVersion = {
  id: string;
  version: number;
  status: "draft" | "validated" | "published" | "deprecated";
  content_hash: string | null;
  definition: {
    spec?: {
      tool_name?: string;
      mcp_server_name?: string;
      mcp_tool_name?: string;
    };
  };
};

type ToolArtifact = {
  id: string;
  name: string;
  description: string;
  versions: ArtifactVersion[];
};

type PublishedTool = {
  artifactName: string;
  artifactDescription: string;
  version: ArtifactVersion;
  toolName: string;
  serverName: string;
};

const inputClass =
  "h-10 border-[#b1b7c1] bg-white text-sm shadow-none focus-visible:border-[#5856d6] focus-visible:ring-[#5856d6]/15";
const selectClass =
  "h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-3 text-sm text-[#2c384a] outline-none focus:border-[#5856d6] focus:ring-2 focus:ring-[#5856d6]/15";

function FieldLabel({ children, htmlFor }: { children: React.ReactNode; htmlFor: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1.5 block text-xs font-semibold text-[#4f5d73]">
      {children}
    </label>
  );
}

function shortHash(value: string) {
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

export default function MCPGatewayPage() {
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [attestations, setAttestations] = useState<MCPAttestation[]>([]);
  const [activations, setActivations] = useState<MCPActivation[]>([]);
  const [scopeChallenges, setScopeChallenges] = useState<MCPScopeChallenge[]>([]);
  const [fleetTelemetry, setFleetTelemetry] = useState<MCPFleetTelemetry | null>(null);
  const [artifacts, setArtifacts] = useState<ToolArtifact[]>([]);
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [clockNow, setClockNow] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const [serverName, setServerName] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [authMode, setAuthMode] = useState<
    "none" | "credential_profile" | "oauth_authorization_code"
  >("none");
  const [credentialRef, setCredentialRef] = useState("");
  const [oauthClientId, setOauthClientId] = useState("");
  const [oauthClientSecretRef, setOauthClientSecretRef] = useState("");
  const [oauthAuthorizationServer, setOauthAuthorizationServer] = useState("");
  const [oauthScopes, setOauthScopes] = useState("");
  const [credentialName, setCredentialName] = useState("");
  const [credentialPurpose, setCredentialPurpose] = useState<
    "mcp" | "oauth_token" | "oauth_client"
  >("mcp");
  const [credentialProvider, setCredentialProvider] = useState<
    "environment" | "vault" | "mcp_oauth_vault"
  >("environment");
  const [credentialSecretRef, setCredentialSecretRef] = useState("env://ICHECK_MCP_TOKEN");
  const [activationServerId, setActivationServerId] = useState("");
  const [artifactVersionId, setArtifactVersionId] = useState("");
  const [attestationId, setAttestationId] = useState("");
  const [attestationReason, setAttestationReason] = useState("");
  const [activationReason, setActivationReason] = useState("");
  const [canaryPercent, setCanaryPercent] = useState(10);
  const [minimumSuccessfulCalls, setMinimumSuccessfulCalls] = useState(3);
  const [maximumFailedCalls, setMaximumFailedCalls] = useState(1);
  const [circuitFailureThreshold, setCircuitFailureThreshold] = useState(3);

  const load = useCallback(async () => {
    try {
      const [serverData, attestationData, activationData, scopeChallengeData, telemetryData, artifactData, credentialData] =
        await Promise.all([
          apiFetch<MCPServer[]>("/mcp/servers?limit=500"),
          apiFetch<MCPAttestation[]>("/mcp/attestations?limit=500"),
          apiFetch<MCPActivation[]>("/mcp/activations?limit=500"),
          apiFetch<MCPScopeChallenge[]>("/mcp/oauth/scope-challenges?limit=500"),
          apiFetch<MCPFleetTelemetry>("/mcp/fleet/telemetry?server_limit=200"),
          apiFetch<ToolArtifact[]>("/artifacts?kind=tool&limit=500"),
          apiFetch<CredentialProfile[]>("/credential-profiles?enabled=true&limit=500"),
        ]);
      setServers(serverData);
      setAttestations(attestationData);
      setClockNow(new Date().getTime());
      setActivations(activationData);
      setScopeChallenges(scopeChallengeData);
      setFleetTelemetry(telemetryData);
      setArtifacts(artifactData);
      setCredentials(credentialData);
      setActivationServerId((current) => current || serverData[0]?.id || "");
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to load MCP Gateway",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(() => {
    // The async metadata load initializes the clock before publishing rows.
    // Subsequent external timer ticks age receipts without a render cascade.
    const timer = window.setInterval(() => setClockNow(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, []);

  const publishedTools = useMemo<PublishedTool[]>(
    () =>
      artifacts.flatMap((artifact) =>
        artifact.versions
          .filter((version) => version.status === "published")
          .map((version) => ({
            artifactName: artifact.name,
            artifactDescription: artifact.description,
            version,
            toolName: version.definition.spec?.tool_name || artifact.name,
            serverName: version.definition.spec?.mcp_server_name || "",
          })),
      ),
    [artifacts],
  );

  const staticCredentials = useMemo(
    () =>
      credentials.filter(
        (profile) =>
          profile.provider !== "mcp_oauth_vault" &&
          Object.keys(profile.worker_selector).length === 0 &&
          profile.allowed_adapters.some(
            (adapter) => adapter === "mcp" || adapter.startsWith("mcp:"),
          ),
      ),
    [credentials],
  );
  const oauthTokenCredentials = useMemo(
    () =>
      credentials.filter(
        (profile) =>
          profile.provider === "mcp_oauth_vault" &&
          profile.allowed_adapters.some(
            (adapter) => adapter === "mcp" || adapter.startsWith("mcp:"),
          ),
      ),
    [credentials],
  );
  const oauthClientCredentials = useMemo(
    () =>
      credentials.filter((profile) =>
        profile.allowed_adapters.some(
          (adapter) =>
            adapter === "mcp_oauth_client" ||
            adapter.startsWith("mcp_oauth_client:"),
        ),
      ),
    [credentials],
  );

  const selectedServer = servers.find((server) => server.id === activationServerId);
  const eligibleTools = publishedTools.filter(
    (tool) => tool.serverName === selectedServer?.name,
  );
  const eligibleAttestations = attestations.filter(
    (item) => mcpAttestationIsFresh(item, activationServerId, artifactVersionId, clockNow),
  );
  const selectedAttestationFresh = eligibleAttestations.some((item) => item.id === attestationId);
  const latestAttestation = attestations.find(
    (item) =>
      item.server_id === activationServerId &&
      item.artifact_version_id === artifactVersionId,
  );
  const fleetExceptions = fleetTelemetry?.servers.filter(
    (server) => server.posture === "critical" || server.posture === "degraded",
  ) || [];
  const runtimeCallCount =
    (fleetTelemetry?.successful_calls || 0) + (fleetTelemetry?.failed_calls || 0);
  const guardrailCount =
    (fleetTelemetry?.open_circuit_count || 0) +
    (fleetTelemetry?.pending_scope_challenge_count || 0) +
    (fleetTelemetry?.authorizing_scope_challenge_count || 0);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!eligibleTools.some((item) => item.version.id === artifactVersionId)) {
        setArtifactVersionId(eligibleTools[0]?.version.id || "");
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [artifactVersionId, eligibleTools]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!eligibleAttestations.some((item) => item.id === attestationId)) {
        setAttestationId(eligibleAttestations[0]?.id || "");
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [attestationId, eligibleAttestations]);

  useEffect(() => {
    if (loading) return;
    const params = new URLSearchParams(window.location.search);
    const oauthError = params.get("oauth_error");
    const connected = params.get("oauth") === "connected";
    if (!oauthError && !connected) return;
    const timer = window.setTimeout(() => {
      setMessage(
        oauthError
          ? { tone: "error", text: `MCP OAuth failed: ${oauthError.replaceAll("_", " ")}.` }
          : { tone: "success", text: "MCP OAuth connected; tokens are held in Vault, not the control-plane database." },
      );
      params.delete("oauth_error");
      params.delete("oauth");
      params.delete("oauth_server");
      const query = params.toString();
      window.history.replaceState({}, "", window.location.pathname + (query ? `?${query}` : ""));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loading]);

  async function createServer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create-server");
    setMessage(null);
    try {
      const created = await apiFetch<MCPServer>("/mcp/servers", {
        method: "POST",
        body: JSON.stringify({
          name: serverName.trim(),
          endpoint_url: endpointUrl.trim(),
          protocol_version: "2026-07-28",
          auth_mode: authMode,
          credential_profile_ref: authMode === "none" ? null : credentialRef || null,
          oauth_client_id:
            authMode === "oauth_authorization_code" ? oauthClientId.trim() : null,
          oauth_client_secret_profile_ref:
            authMode === "oauth_authorization_code"
              ? oauthClientSecretRef || null
              : null,
          oauth_authorization_server:
            authMode === "oauth_authorization_code"
              ? oauthAuthorizationServer.trim() || null
              : null,
          oauth_requested_scopes:
            authMode === "oauth_authorization_code"
              ? Array.from(
                  new Set(
                    oauthScopes
                      .split(/\s+/)
                      .map((scope) => scope.trim())
                      .filter(Boolean),
                  ),
                )
              : [],
          enabled: true,
          created_by: "platform.admin",
        }),
      });
      setServerName("");
      setEndpointUrl("");
      setAuthMode("none");
      setCredentialRef("");
      setOauthClientId("");
      setOauthClientSecretRef("");
      setOauthAuthorizationServer("");
      setOauthScopes("");
      setActivationServerId(created.id);
      setMessage({
        tone: "success",
        text:
          created.auth_mode === "oauth_authorization_code"
            ? "MCP server registered. Connect OAuth before queuing a Worker attestation."
            : "MCP server registered. Queue an authenticated Worker attestation before activation.",
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to register MCP server",
      });
    } finally {
      setBusy(null);
    }
  }

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create-credential");
    setMessage(null);
    try {
      const created = await apiFetch<CredentialProfile>("/credential-profiles", {
        method: "POST",
        body: JSON.stringify({
          name: credentialName.trim(),
          provider: credentialProvider,
          secret_ref: credentialSecretRef.trim(),
          allowed_adapters: [
            credentialPurpose === "oauth_client" ? "mcp_oauth_client" : "mcp",
          ],
          worker_selector: {},
          enabled: true,
          created_by: "platform.admin",
        }),
      });
      setCredentialName("");
      if (credentialPurpose === "oauth_client") {
        setOauthClientSecretRef(created.id);
      } else {
        setCredentialRef(created.id);
      }
      setMessage({
        tone: "success",
        text:
          credentialPurpose === "oauth_token"
            ? "OAuth Vault token location created; no token exists until authorization completes."
            : "MCP secret reference created without storing secret material.",
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to create MCP secret reference",
      });
    } finally {
      setBusy(null);
    }
  }

  function connectOAuth(server: MCPServer) {
    setBusy(`oauth-${server.id}`);
    setMessage(null);
    beginMCPOAuth(server.id);
  }

  async function approveScopeChallenge(challenge: MCPScopeChallenge) {
    const server = servers.find((item) => item.id === challenge.server_id);
    if (!server) return;
    const missingScopes = challenge.challenged_scopes.filter(
      (scope) => !server.oauth_requested_scopes.includes(scope),
    );
    const allowScopeExpansion =
      missingScopes.length > 0
        ? window.confirm(
            `This challenge asks to add ${missingScopes.join(" ")} to ${server.name}'s persistent OAuth scope allowlist. Continue?`,
          )
        : false;
    if (missingScopes.length > 0 && !allowScopeExpansion) return;
    const reason = window.prompt(
      `Why should ${challenge.tool_name} receive ${challenge.challenged_scopes.join(" ")}?`,
      "Approve the least-privilege runtime scope step-up.",
    );
    if (!reason || reason.trim().length < 3) return;
    setBusy(`approve-scope-${challenge.id}`);
    setMessage(null);
    try {
      await apiFetch(`/mcp/oauth/scope-challenges/${challenge.id}/approve`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: challenge.revision,
          allow_scope_expansion: allowScopeExpansion,
          reason: reason.trim(),
          actor: "platform.approver",
        }),
      });
      setMessage({
        tone: "success",
        text: "Scope policy approved. Start the separate OAuth consent flow to obtain a new token; the Agent will not retry automatically.",
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to approve OAuth scope step-up",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  function authorizeScopeChallenge(challenge: MCPScopeChallenge) {
    setBusy(`authorize-scope-${challenge.id}`);
    setMessage(null);
    beginMCPOAuth(challenge.server_id, "/settings/mcp", challenge.id);
  }

  async function revokeOAuth(server: MCPServer) {
    const reason = window.prompt(
      `Why should OAuth access for ${server.name} be revoked?`,
      "Remove delegated MCP access.",
    );
    if (!reason || reason.trim().length < 3) return;
    setBusy(`revoke-oauth-${server.id}`);
    setMessage(null);
    try {
      await apiFetch(`/mcp/servers/${server.id}/oauth/revoke`, {
        method: "POST",
        body: JSON.stringify({
          reason: reason.trim(),
          actor: "platform.admin",
        }),
      });
      setMessage({
        tone: "success",
        text: `${server.name} OAuth access was disconnected; upstream tokens were revoked when supported and the Vault bundle was deleted.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to revoke MCP OAuth",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function queueAttestation() {
    if (!activationServerId || !artifactVersionId) return;
    setBusy("attest");
    setMessage(null);
    try {
      const queued = await apiFetch<MCPAttestation>(
        `/mcp/servers/${activationServerId}/attestations`,
        {
          method: "POST",
          body: JSON.stringify({
            artifact_version_id: artifactVersionId,
            reason: attestationReason.trim(),
            actor: "platform.approver",
          }),
        },
      );
      setAttestationReason("");
      setMessage({
        tone: "success",
        text:
          queued.status === "passed"
            ? "A still-fresh matching Worker attestation already exists."
            : "Attestation queued. An authenticated MCP Attestor Worker will resolve credentials locally and verify tools/list.",
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to queue MCP attestation",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function activateTool(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!activationServerId || !artifactVersionId) return;
    if (!mcpAttestationIsFresh(attestations.find((item) => item.id === attestationId),
      activationServerId, artifactVersionId)) {
      setMessage({ tone: "error", text: "A fresh matching Worker attestation is required before activation." });
      return;
    }
    setBusy("activate");
    setMessage(null);
    try {
      await apiFetch(`/mcp/servers/${activationServerId}/activations`, {
        method: "POST",
        body: JSON.stringify({
          artifact_version_id: artifactVersionId,
          attestation_id: attestationId,
          canary_percent: canaryPercent,
          minimum_successful_calls: minimumSuccessfulCalls,
          maximum_failed_calls: maximumFailedCalls,
          circuit_failure_threshold: circuitFailureThreshold,
          reason: activationReason.trim(),
          actor: "platform.approver",
        }),
      });
      setActivationReason("");
      setMessage({
        tone: "success",
        text: `The fresh Worker attestation was consumed atomically; a ${canaryPercent}% deterministic canary is now live. Promote only after its evidence gates pass.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to activate MCP tool",
      });
    } finally {
      setBusy(null);
    }
  }

  async function promoteTool(activation: MCPActivation) {
    const reason = window.prompt(
      `Why should ${activation.tool_name} move from canary to 100%?`,
      "Canary success and failure gates passed.",
    );
    if (!reason || reason.trim().length < 3) return;
    setBusy(`promote-${activation.id}`);
    setMessage(null);
    try {
      await apiFetch(`/mcp/activations/${activation.id}/promote`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: activation.revision,
          reason: reason.trim(),
          actor: "platform.approver",
        }),
      });
      setMessage({
        tone: "success",
        text: `${activation.tool_name} passed canary gates and is now available to the full eligible fleet.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to promote MCP canary",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function queueRecoveryAttestation(activation: MCPActivation) {
    setBusy(`reattest-${activation.id}`);
    setMessage(null);
    try {
      await apiFetch<MCPAttestation>(
        `/mcp/servers/${activation.server_id}/attestations`,
        {
          method: "POST",
          body: JSON.stringify({
            artifact_version_id: activation.artifact_version_id,
            reason: "Re-attest the exact contract before circuit recovery.",
            actor: "platform.approver",
          }),
        },
      );
      setMessage({
        tone: "success",
        text: `Recovery attestation queued for ${activation.tool_name}.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to queue recovery attestation",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function recoverTool(activation: MCPActivation) {
    const fresh = attestations.find(
      (item) => mcpAttestationIsFresh(item, activation.server_id, activation.artifact_version_id),
    );
    if (!fresh) {
      setMessage({
        tone: "error",
        text: "Queue and complete a fresh Worker attestation before circuit recovery.",
      });
      return;
    }
    const reason = window.prompt(
      `Why should ${activation.tool_name} return to canary?`,
      "Fresh Worker evidence confirms the endpoint recovered.",
    );
    if (!reason || reason.trim().length < 3) return;
    if (!mcpAttestationIsFresh(fresh, activation.server_id, activation.artifact_version_id)) {
      setMessage({ tone: "error", text: "The Worker attestation expired while reviewing recovery. Obtain fresh evidence." });
      return;
    }
    setBusy(`recover-${activation.id}`);
    setMessage(null);
    try {
      await apiFetch(`/mcp/activations/${activation.id}/recover`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: activation.revision,
          attestation_id: fresh.id,
          canary_percent: Math.min(activation.traffic_percent, 10),
          reason: reason.trim(),
          actor: "platform.approver",
        }),
      });
      setMessage({
        tone: "success",
        text: `${activation.tool_name} circuit closed and returned to a bounded canary.`,
      });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to recover MCP circuit",
      });
      await load();
    } finally {
      setBusy(null);
    }
  }

  async function deactivateTool(activation: MCPActivation) {
    const reason = window.prompt(
      `Why should ${activation.tool_name} be deactivated?`,
      "Retire this exact MCP contract version.",
    );
    if (!reason || reason.trim().length < 3) return;
    setBusy(`deactivate-${activation.id}`);
    setMessage(null);
    try {
      await apiFetch(`/mcp/activations/${activation.id}/deactivate`, {
        method: "POST",
        body: JSON.stringify({
          reason: reason.trim(),
          actor: "platform.approver",
        }),
      });
      setMessage({ tone: "success", text: `${activation.tool_name} is no longer executable.` });
      await load();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to deactivate tool",
      });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="min-h-screen bg-[#f3f4f7] text-[#2c384a]">
      <header data-text-surface="dark" className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-4 px-4 sm:px-6 xl:px-8">
          <Link href="/" className="grid size-9 place-items-center rounded-md bg-[#5856d6]" aria-label="Back to operations">
            <Activity className="size-[18px]" />
          </Link>
          <div>
            <p className="text-sm font-semibold">iCheck Administration</p>
            <p className="text-xs text-muted-foreground">Governed external tool execution</p>
          </div>
          <Badge className="ml-auto border-emerald-300/40 bg-emerald-400/15 text-emerald-100">
            MCP 2026-07-28
          </Badge>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 xl:px-8">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Link href="/studio" className="mb-3 inline-flex items-center gap-1.5 text-xs font-medium text-[#5856d6] hover:text-[#3c3a9f]">
              <ArrowLeft className="size-3.5" /> Capability Studio
            </Link>
            <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-[-0.02em]">
              <span className="grid size-10 place-items-center rounded-lg bg-[#e9e8fb] text-[#5856d6]"><PlugZap className="size-5" /></span>
              MCP Gateway
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              Publishing defines an immutable tool contract. A dedicated authenticated Worker verifies the live server; activation then consumes that fresh attestation before the Agent Loop can call it.
            </p>
          </div>
          <Button variant="outline" onClick={() => { setLoading(true); void load(); }} disabled={loading} className="border-[#b1b7c1] bg-white">
            <RefreshCw className={cn("size-4", loading && "animate-spin")} /> Refresh
          </Button>
        </div>

        {message && (
          <div className={cn("mb-5 flex items-center gap-2 rounded-lg border px-4 py-3 text-sm", message.tone === "success" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700")}>
            {message.tone === "success" ? <CheckCircle2 className="size-4" /> : <XCircle className="size-4" />}
            {message.text}
          </div>
        )}

        <section className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            { label: "Registered servers", value: fleetTelemetry?.server_count || 0, detail: `${fleetTelemetry?.enabled_server_count || 0} enabled`, Icon: Server },
            { label: "Healthy endpoints", value: fleetTelemetry?.healthy_server_count || 0, detail: `${(fleetTelemetry?.stale_server_count || 0) + (fleetTelemetry?.unchecked_server_count || 0)} stale or unchecked`, Icon: ShieldCheck },
            { label: "Active tool calls", value: runtimeCallCount, detail: fleetTelemetry?.success_rate_percent === null || fleetTelemetry?.success_rate_percent === undefined ? "No calls on active tools" : `${fleetTelemetry.success_rate_percent}% succeeded on active tools`, Icon: Activity },
            { label: "Active guardrails", value: guardrailCount, detail: `${fleetTelemetry?.dead_letter_attestation_count || 0} dead-letter attestations`, Icon: CircleOff },
          ].map(({ label, value, detail, Icon }) => (
            <Card key={label} className="border-[#d8dbe0] shadow-none">
              <CardContent className="flex items-center justify-between p-5">
                <div><p className="text-xs font-medium text-muted-foreground">{label}</p><p className="mt-1 text-2xl font-semibold">{value}</p><p className="mt-1 text-[10px] text-muted-foreground">{detail}</p></div>
                <span className="grid size-10 place-items-center rounded-lg bg-[#e9e8fb] text-[#5856d6]"><Icon className="size-5" /></span>
              </CardContent>
            </Card>
          ))}
        </section>

        <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="space-y-6">
            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <CardTitle className="text-base">MCP secret reference</CardTitle>
                <CardDescription>Create a reference for static authentication, an OAuth Vault token location, or a confidential client secret. Never paste a token into iCheck.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={createCredential} className="space-y-4">
                  <div>
                    <FieldLabel htmlFor="mcp-credential-purpose">Credential purpose</FieldLabel>
                    <select id="mcp-credential-purpose"
                      className={selectClass}
                      value={credentialPurpose}
                      onChange={(event) => {
                        const value = event.target.value as typeof credentialPurpose;
                        setCredentialPurpose(value);
                        if (value === "oauth_token") {
                          setCredentialProvider("mcp_oauth_vault");
                          setCredentialSecretRef("mcp-oauth-vault://kv/icheck/mcp/server");
                        } else {
                          setCredentialProvider("environment");
                          setCredentialSecretRef(
                            value === "oauth_client"
                              ? "env://ICHECK_MCP_OAUTH_CLIENT_SECRET"
                              : "env://ICHECK_MCP_TOKEN",
                          );
                        }
                      }}
                    >
                      <option value="mcp">Static MCP request credential</option>
                      <option value="oauth_token">OAuth token bundle location</option>
                      <option value="oauth_client">OAuth confidential client secret</option>
                    </select>
                  </div>
                  <div><FieldLabel htmlFor="mcp-credential-name">Profile name</FieldLabel><Input id="mcp-credential-name" className={inputClass} value={credentialName} onChange={(event) => setCredentialName(event.target.value)} placeholder="mcp-network-readonly" required /></div>
                  <div>
                    <FieldLabel htmlFor="mcp-credential-provider">Secret provider</FieldLabel>
                    <select id="mcp-credential-provider"
                      className={selectClass}
                      value={credentialProvider}
                      disabled={credentialPurpose === "oauth_token"}
                      onChange={(event) => {
                        const value = event.target.value as "environment" | "vault";
                        setCredentialProvider(value);
                        setCredentialSecretRef(
                          value === "vault"
                            ? "vault-kv2://kv/mcp/network#token"
                            : credentialPurpose === "oauth_client"
                              ? "env://ICHECK_MCP_OAUTH_CLIENT_SECRET"
                              : "env://ICHECK_MCP_TOKEN",
                        );
                      }}
                    >
                      {credentialPurpose === "oauth_token" ? (
                        <option value="mcp_oauth_vault">MCP OAuth Vault KV v2</option>
                      ) : (
                        <>
                          <option value="environment">Environment reference</option>
                          <option value="vault">Vault KV v2</option>
                        </>
                      )}
                    </select>
                  </div>
                  <div>
                    <FieldLabel htmlFor="mcp-credential-secret-ref">{credentialPurpose === "oauth_token" ? "Vault token location" : "Secret reference"}</FieldLabel>
                    <Input id="mcp-credential-secret-ref" className={cn(inputClass, "font-mono text-xs")} value={credentialSecretRef} onChange={(event) => setCredentialSecretRef(event.target.value)} placeholder={credentialPurpose === "oauth_token" ? "mcp-oauth-vault://kv/icheck/mcp/network" : credentialProvider === "vault" ? "vault-kv2://kv/mcp/network#token" : "env://ICHECK_MCP_TOKEN"} required />
                    {credentialPurpose === "oauth_token" && <p className="mt-1.5 text-[11px] leading-4 text-muted-foreground">The authorization callback writes the access/refresh bundle directly to this Vault path with CAS. Database rows retain only hashes and lifecycle metadata.</p>}
                  </div>
                  <Button type="submit" disabled={busy !== null || !credentialName.trim() || !credentialSecretRef.trim()} variant="outline" className="w-full border-[#b1b7c1]">
                    {busy === "create-credential" ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />} Add secret reference
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <CardTitle className="text-base">Register MCP server</CardTitle>
                <CardDescription>Non-loopback endpoints require HTTPS and an operations-managed host allowlist.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={createServer} className="space-y-4">
                  <div><FieldLabel htmlFor="mcp-server-name">Stable server name</FieldLabel><Input id="mcp-server-name" className={inputClass} value={serverName} onChange={(event) => setServerName(event.target.value)} placeholder="network-readonly" required /></div>
                  <div><FieldLabel htmlFor="mcp-endpoint-url">Stateless HTTP endpoint</FieldLabel><Input id="mcp-endpoint-url" className={inputClass} value={endpointUrl} onChange={(event) => setEndpointUrl(event.target.value)} placeholder="https://mcp.example.net/rpc" required /></div>
                  <div>
                    <FieldLabel htmlFor="mcp-auth-mode">Authentication</FieldLabel>
                    <select id="mcp-auth-mode"
                      className={selectClass}
                      value={authMode}
                      onChange={(event) => {
                        const value = event.target.value as typeof authMode;
                        setAuthMode(value);
                        setCredentialRef("");
                      }}
                    >
                      <option value="none">No authentication</option>
                      <option value="credential_profile">Static credential profile</option>
                      <option value="oauth_authorization_code">OAuth 2.1 authorization code + PKCE</option>
                    </select>
                  </div>
                  {authMode !== "none" && <div>
                    <FieldLabel htmlFor="mcp-credential-ref">{authMode === "oauth_authorization_code" ? "OAuth token Vault profile" : "Credential profile"}</FieldLabel>
                    <select id="mcp-credential-ref" className={selectClass} value={credentialRef} onChange={(event) => setCredentialRef(event.target.value)}>
                      <option value="">Select a profile</option>
                      {(authMode === "oauth_authorization_code" ? oauthTokenCredentials : staticCredentials).map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.provider}</option>)}
                    </select>
                    <p className="mt-1.5 text-[11px] leading-4 text-muted-foreground">Only a reference crosses the execution lease. Agent Workers resolve it locally and never place token values in LangGraph state.</p>
                  </div>}
                  {authMode === "oauth_authorization_code" && <div className="space-y-4 rounded-lg border border-[#d8dbe0] bg-[#f8f8fb] p-4">
                    <div><FieldLabel htmlFor="mcp-oauth-client-id">OAuth client ID or CIMD URL</FieldLabel><Input id="mcp-oauth-client-id" className={cn(inputClass, "font-mono text-xs")} value={oauthClientId} onChange={(event) => setOauthClientId(event.target.value)} placeholder="https://icheck.example.net/api/v1/mcp/oauth/client-metadata" required /></div>
                    <div><FieldLabel htmlFor="mcp-oauth-authorization-server">Authorization server (optional)</FieldLabel><Input id="mcp-oauth-authorization-server" className={cn(inputClass, "font-mono text-xs")} value={oauthAuthorizationServer} onChange={(event) => setOauthAuthorizationServer(event.target.value)} placeholder="Required only when resource metadata advertises multiple issuers" /></div>
                    <div><FieldLabel htmlFor="mcp-oauth-scopes">Allowed scopes (space separated)</FieldLabel><Input id="mcp-oauth-scopes" className={cn(inputClass, "font-mono text-xs")} value={oauthScopes} onChange={(event) => setOauthScopes(event.target.value)} placeholder="network:read offline_access" /><p className="mt-1.5 text-[11px] leading-4 text-muted-foreground">A 401 scope challenge is authoritative but cannot exceed this allowlist. Leave blank to use protected-resource metadata.</p></div>
                    <div><FieldLabel htmlFor="mcp-oauth-client-secret-ref">Confidential client secret (optional)</FieldLabel><select id="mcp-oauth-client-secret-ref" className={selectClass} value={oauthClientSecretRef} onChange={(event) => setOauthClientSecretRef(event.target.value)}><option value="">Public client / CIMD (PKCE only)</option>{oauthClientCredentials.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.provider}</option>)}</select></div>
                  </div>}
                  <Button type="submit" disabled={busy !== null || !serverName.trim() || !endpointUrl.trim() || (authMode !== "none" && !credentialRef) || (authMode === "oauth_authorization_code" && !oauthClientId.trim())} className="w-full bg-[#5856d6] hover:bg-[#4947ad]">
                    {busy === "create-server" ? <Loader2 className="size-4 animate-spin" /> : <Server className="size-4" />} Register server
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <CardTitle className="text-base">Attest and activate contract</CardTitle>
                <CardDescription>The Attestor Worker resolves Vault credentials locally. Activation is enabled only after exact schema evidence passes.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={activateTool} className="space-y-4">
                  <div><FieldLabel htmlFor="mcp-activation-server-id">MCP server</FieldLabel><select id="mcp-activation-server-id" className={selectClass} value={activationServerId} onChange={(event) => setActivationServerId(event.target.value)}><option value="">Select a server</option>{servers.filter((server) => server.enabled && (server.auth_mode !== "oauth_authorization_code" || server.oauth_status === "connected")).map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}</select></div>
                  <div><FieldLabel htmlFor="mcp-artifact-version-id">Published Tool Artifact</FieldLabel><select id="mcp-artifact-version-id" className={selectClass} value={artifactVersionId} onChange={(event) => setArtifactVersionId(event.target.value)}><option value="">Select a matching contract</option>{eligibleTools.map((tool) => <option key={tool.version.id} value={tool.version.id}>{tool.toolName} · {tool.artifactName} v{tool.version.version}</option>)}</select>{selectedServer && eligibleTools.length === 0 && <p className="mt-1.5 text-[11px] text-amber-700">No published Tool Artifact targets {selectedServer.name}.</p>}</div>
                  <div className="rounded-lg border border-[#d8dbe0] bg-[#f8f8fb] p-4">
                    <FieldLabel htmlFor="mcp-attestation-reason">Worker attestation reason</FieldLabel>
                    <Input id="mcp-attestation-reason" className={inputClass} value={attestationReason} onChange={(event) => setAttestationReason(event.target.value)} placeholder="Verify the deployed server contract and credential boundary" minLength={3} />
                    <Button type="button" onClick={() => void queueAttestation()} disabled={busy !== null || !activationServerId || !artifactVersionId || attestationReason.trim().length < 3} variant="outline" className="mt-3 w-full border-[#5856d6] text-[#5856d6] hover:bg-[#eeedff]">
                      {busy === "attest" ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />} Queue Worker attestation
                    </Button>
                    {latestAttestation && <p className={cn("mt-2 text-[11px]", latestAttestation.status === "passed" ? "text-emerald-700" : latestAttestation.status === "failed" || latestAttestation.status === "dead_letter" ? "text-red-700" : "text-amber-700")}>Latest: {latestAttestation.status.replaceAll("_", " ")} · attempt {latestAttestation.attempt_count}/{latestAttestation.max_attempts}{latestAttestation.failure_code ? ` · ${latestAttestation.failure_code.replaceAll("_", " ")}` : ""}</p>}
                  </div>
                  <div>
                    <FieldLabel htmlFor="mcp-attestation-id">Fresh passed attestation</FieldLabel>
                    <select id="mcp-attestation-id" className={selectClass} value={attestationId} onChange={(event) => setAttestationId(event.target.value)}>
                      <option value="">Wait for an authenticated Worker result</option>
                      {eligibleAttestations.map((item) => <option key={item.id} value={item.id}>{item.tool_name} · expires {new Date(item.expires_at!).toLocaleTimeString()}</option>)}
                    </select>
                  </div>
                  <div className="grid gap-3 rounded-lg border border-[#d8dbe0] bg-[#f8f8fb] p-4 sm:grid-cols-2">
                    <div>
                      <FieldLabel htmlFor="mcp-canary-percent">Initial canary traffic %</FieldLabel>
                      <Input id="mcp-canary-percent" className={inputClass} type="number" min={1} max={100} value={canaryPercent} onChange={(event) => setCanaryPercent(Number(event.target.value))} required />
                    </div>
                    <div>
                      <FieldLabel htmlFor="mcp-minimum-successful-calls">Required successful calls</FieldLabel>
                      <Input id="mcp-minimum-successful-calls" className={inputClass} type="number" min={1} max={1000} value={minimumSuccessfulCalls} onChange={(event) => setMinimumSuccessfulCalls(Number(event.target.value))} required />
                    </div>
                    <div>
                      <FieldLabel htmlFor="mcp-maximum-failed-calls">Canary failure budget</FieldLabel>
                      <Input id="mcp-maximum-failed-calls" className={inputClass} type="number" min={0} max={1000} value={maximumFailedCalls} onChange={(event) => setMaximumFailedCalls(Number(event.target.value))} required />
                    </div>
                    <div>
                      <FieldLabel htmlFor="mcp-circuit-failure-threshold">Consecutive failures to open</FieldLabel>
                      <Input id="mcp-circuit-failure-threshold" className={inputClass} type="number" min={1} max={100} value={circuitFailureThreshold} onChange={(event) => setCircuitFailureThreshold(Number(event.target.value))} required />
                    </div>
                    <p className="text-[11px] leading-4 text-muted-foreground sm:col-span-2">Investigation IDs are assigned deterministically, so retries stay in the same cohort. Promotion remains a separate human action.</p>
                  </div>
                  <div><FieldLabel htmlFor="mcp-activation-reason">Activation reason</FieldLabel><Input id="mcp-activation-reason" className={inputClass} value={activationReason} onChange={(event) => setActivationReason(event.target.value)} placeholder="Reviewed fixtures and approved read-only scope" required minLength={3} /></div>
                  <Button type="submit" disabled={busy !== null || !activationServerId || !artifactVersionId || !selectedAttestationFresh || activationReason.trim().length < 3} className="w-full bg-[#047857] text-white hover:bg-[#065f46]">
                    {busy === "activate" ? <Loader2 className="size-4 animate-spin" /> : <Rocket className="size-4" />} Consume attestation and start canary
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-6">
            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <div className="flex items-start justify-between gap-3">
                  <div><CardTitle className="text-base">Fleet runtime posture</CardTitle><CardDescription>Namespace-scoped database aggregates keep counts complete; only bounded exception details are rendered.</CardDescription></div>
                  <Badge variant="outline" className={cn("capitalize", fleetTelemetry?.posture === "healthy" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : fleetTelemetry?.posture === "critical" ? "border-red-300 bg-red-50 text-red-700" : fleetTelemetry?.posture === "degraded" ? "border-amber-300 bg-amber-50 text-amber-700" : "border-slate-300 bg-slate-50 text-slate-600")}>{fleetTelemetry?.posture || "loading"}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-2 text-xs sm:grid-cols-3">
                  <div className="rounded-lg bg-[#f8f8fb] p-3"><p className="font-semibold text-[#4f5d73]">Health</p><p className="mt-1 text-muted-foreground">{fleetTelemetry?.unhealthy_server_count || 0} unhealthy · {fleetTelemetry?.stale_server_count || 0} stale · {fleetTelemetry?.unchecked_server_count || 0} unchecked</p></div>
                  <div className="rounded-lg bg-[#f8f8fb] p-3"><p className="font-semibold text-[#4f5d73]">Rollout</p><p className="mt-1 text-muted-foreground">{fleetTelemetry?.canary_activation_count || 0} canary · {fleetTelemetry?.full_activation_count || 0} full · {fleetTelemetry?.blocked_activation_count || 0} blocked</p></div>
                  <div className="rounded-lg bg-[#f8f8fb] p-3"><p className="font-semibold text-[#4f5d73]">Safety queue</p><p className="mt-1 text-muted-foreground">{fleetTelemetry?.open_circuit_count || 0} open circuits · {(fleetTelemetry?.pending_scope_challenge_count || 0) + (fleetTelemetry?.authorizing_scope_challenge_count || 0)} scope reviews</p></div>
                </div>
                {fleetExceptions.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-[#c9ced7] p-5 text-center text-xs text-muted-foreground"><CheckCircle2 className="mx-auto mb-2 size-4 text-emerald-600" />No fleet exceptions in the bounded server view.</div>
                ) : (
                  <div className="space-y-2">
                    {fleetExceptions.slice(0, 10).map((server) => (
                      <div key={server.server_id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#d8dbe0] px-3 py-2.5">
                        <div><p className="text-xs font-semibold">{server.server_name}</p><p className="mt-0.5 text-[10px] text-muted-foreground">{server.open_circuits} circuits · {server.pending_scope_challenges + server.authorizing_scope_challenges} scope reviews · {server.dead_letter_attestations} dead letters</p></div>
                        <Badge variant="outline" className={server.posture === "critical" ? "border-red-300 bg-red-50 text-red-700" : "border-amber-300 bg-amber-50 text-amber-700"}>{server.posture}</Badge>
                      </div>
                    ))}
                  </div>
                )}
                {fleetTelemetry && fleetTelemetry.server_count > fleetTelemetry.servers.length && <p className="text-[10px] text-muted-foreground">Aggregate counts cover all {fleetTelemetry.server_count} servers; exception details are capped at {fleetTelemetry.servers.length} rows.</p>}
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><CardTitle className="text-base">Servers</CardTitle><CardDescription>Authenticated Workers update health from bounded tools/list evidence; redirects and unallowlisted destinations fail closed.</CardDescription></CardHeader>
              <CardContent className="space-y-3">
                {servers.length === 0 ? <div className="rounded-lg border border-dashed border-[#c9ced7] p-8 text-center text-sm text-muted-foreground"><CircleOff className="mx-auto mb-2 size-5" />No MCP servers registered.</div> : servers.map((server) => (
                  <div key={server.id} className="rounded-lg border border-[#d8dbe0] bg-white p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-semibold">{server.name}</p>
                          <Badge variant="outline" className={cn("text-[10px]", server.last_health_status === "healthy" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : server.last_health_status === "unhealthy" ? "border-red-300 bg-red-50 text-red-700" : "border-slate-300 text-slate-600")}>{server.last_health_status || "unchecked"}</Badge>
                          {server.auth_mode === "oauth_authorization_code" && <Badge variant="outline" className={cn("text-[10px]", server.oauth_status === "connected" ? "border-indigo-300 bg-indigo-50 text-indigo-700" : server.oauth_status === "revocation_pending" ? "border-amber-300 bg-amber-50 text-amber-700" : "border-slate-300 bg-slate-50 text-slate-600")}>OAuth · {server.oauth_status.replaceAll("_", " ")}</Badge>}
                        </div>
                        <p className="mt-1 break-all text-xs text-muted-foreground">{server.endpoint_url}</p>
                        <p className="mt-1 text-[11px] text-muted-foreground">{server.last_tool_count ?? 0} advertised tools · {server.auth_mode === "oauth_authorization_code" ? "OAuth 2.1 + PKCE" : server.credential_profile_ref ? "static credential reference" : "no auth"}</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {server.auth_mode === "oauth_authorization_code" && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => connectOAuth(server)} className="border-indigo-200 text-indigo-700 hover:bg-indigo-50">{busy === `oauth-${server.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <KeyRound className="size-3.5" />} {server.oauth_status === "connected" ? "Reauthorize" : "Connect"}</Button>}
                        {server.auth_mode === "oauth_authorization_code" && ["connected", "revocation_pending"].includes(server.oauth_status) && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void revokeOAuth(server)} className="border-red-200 text-red-700 hover:bg-red-50">{busy === `revoke-oauth-${server.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <Unplug className="size-3.5" />} {server.oauth_status === "revocation_pending" ? "Retry revoke" : "Revoke"}</Button>}
                      </div>
                    </div>
                    {server.auth_mode === "oauth_authorization_code" && <div className="mt-3 grid gap-2 rounded-md bg-[#f8f8fb] px-3 py-2 text-[11px] text-muted-foreground sm:grid-cols-2">
                      <p className="break-all"><span className="font-semibold text-[#4f5d73]">Issuer:</span> {server.oauth_issuer || server.oauth_authorization_server || "discover on connect"}</p>
                      <p><span className="font-semibold text-[#4f5d73]">Scopes:</span> {(server.oauth_granted_scopes.length ? server.oauth_granted_scopes : server.oauth_requested_scopes).join(" ") || "discover least privilege"}</p>
                      <p><span className="font-semibold text-[#4f5d73]">Control-plane expiry:</span> {server.oauth_token_expires_at ? new Date(server.oauth_token_expires_at).toLocaleString() : "not connected"} <span>(last control-plane resolution)</span></p>
                      <p><span className="font-semibold text-[#4f5d73]">Refresh:</span> {server.oauth_refresh_token_present ? "Vault-held refresh token" : "reauthorization may be required"}</p>
                      {(() => { const summary = oauthObservationSummary(server, clockNow); return <div className="sm:col-span-2" data-oauth-observation={summary.state}>
                        <p className="font-semibold text-[#4f5d73]">{summary.label}</p>
                        {summary.expiry && <p>Observed token expiry: {new Date(summary.expiry).toLocaleString()}</p>}
                        <p>{summary.detail}</p>
                      </div>; })()}
                    </div>}
                    {server.last_health_error && <p className="mt-3 rounded-md bg-red-50 px-3 py-2 text-xs text-red-700">{server.last_health_error}</p>}
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><CardTitle className="text-base">OAuth scope step-up queue</CardTitle><CardDescription>A runtime 403 never grants access or retries by itself. Review the exact scope, approve policy separately, then complete a new PKCE consent flow.</CardDescription></CardHeader>
              <CardContent className="space-y-3">
                {scopeChallenges.length === 0 ? <div className="rounded-lg border border-dashed border-[#c9ced7] p-8 text-center text-sm text-muted-foreground"><ShieldCheck className="mx-auto mb-2 size-5" />No runtime scope challenges.</div> : scopeChallenges.map((challenge) => {
                  const server = servers.find((item) => item.id === challenge.server_id);
                  const missingScopes = challenge.challenged_scopes.filter((scope) => !server?.oauth_requested_scopes.includes(scope));
                  return (
                    <div key={challenge.id} className="rounded-lg border border-[#d8dbe0] bg-white p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-semibold">{challenge.tool_name}</p>
                            <Badge variant="outline" className={cn("text-[10px]", challenge.status === "resolved" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : challenge.status === "authorizing" ? "border-indigo-300 bg-indigo-50 text-indigo-700" : "border-amber-300 bg-amber-50 text-amber-700")}>{challenge.status}</Badge>
                            {missingScopes.length > 0 && challenge.status !== "resolved" && <Badge variant="outline" className="border-red-300 bg-red-50 text-[10px] text-red-700">allowlist expansion</Badge>}
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">{server?.name || challenge.server_id} · seen {challenge.occurrence_count} time{challenge.occurrence_count === 1 ? "" : "s"}</p>
                          <p className="mt-2 font-mono text-[11px] text-[#4f5d73]">{challenge.challenged_scopes.join(" ")}</p>
                          <p className="mt-1 text-[11px] text-muted-foreground">Requested token union: {challenge.requested_scopes.join(" ")}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {challenge.status === "pending" && !challenge.approved_at && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void approveScopeChallenge(challenge)} className="border-amber-200 text-amber-700 hover:bg-amber-50">{busy === `approve-scope-${challenge.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />} {missingScopes.length > 0 ? "Approve + expand" : "Approve scope"}</Button>}
                          {challenge.status === "pending" && challenge.approved_at && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => authorizeScopeChallenge(challenge)} className="border-indigo-200 text-indigo-700 hover:bg-indigo-50">{busy === `authorize-scope-${challenge.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <KeyRound className="size-3.5" />} Authorize step-up</Button>}
                        </div>
                      </div>
                      <div className="mt-3 grid gap-2 rounded-md bg-[#f8f8fb] px-3 py-2 text-[11px] text-muted-foreground sm:grid-cols-3">
                        <p><span className="font-semibold text-[#4f5d73]">First seen:</span> {new Date(challenge.first_seen_at).toLocaleString()}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Last seen:</span> {new Date(challenge.last_seen_at).toLocaleString()}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Revision:</span> {challenge.revision}</p>
                      </div>
                      {challenge.status === "authorizing" && <p className="mt-2 text-[11px] text-indigo-700">Authorization is in progress. Failure returns this challenge to pending; only a token containing every challenged scope resolves it.</p>}
                      {challenge.resolved_at && <p className="mt-2 text-[11px] text-emerald-700">Resolved {new Date(challenge.resolved_at).toLocaleString()} after the new Vault token was verified.</p>}
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><CardTitle className="text-base">Worker attestation ledger</CardTitle><CardDescription>Bearer + mTLS authenticated Workers hold short leases. Vault values never return in these records.</CardDescription></CardHeader>
              <CardContent className="space-y-3">
                {attestations.length === 0 ? <div className="rounded-lg border border-dashed border-[#c9ced7] p-8 text-center text-sm text-muted-foreground"><CircleOff className="mx-auto mb-2 size-5" />No MCP attestations queued.</div> : attestations.map((attestation) => (
                  <div key={attestation.id} className="rounded-lg border border-[#d8dbe0] bg-white p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-semibold">{attestation.tool_name}</p>
                          <Badge variant="outline" className={cn("text-[10px]", attestation.status === "passed" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : attestation.status === "failed" || attestation.status === "dead_letter" ? "border-red-300 bg-red-50 text-red-700" : attestation.status === "consumed" ? "border-indigo-300 bg-indigo-50 text-indigo-700" : "border-amber-300 bg-amber-50 text-amber-700")}>{attestation.status.replaceAll("_", " ")}</Badge>
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">remote: {attestation.mcp_tool_name} · attempt {attestation.attempt_count}/{attestation.max_attempts}</p>
                        <p className="mt-1 font-mono text-[10px] text-muted-foreground" title={attestation.expected_contract_sha256}>{shortHash(attestation.expected_contract_sha256)}</p>
                      </div>
                      <div className="text-right text-[11px] text-muted-foreground">
                        <p>{attestation.worker_id ? `Worker ${attestation.worker_id.slice(0, 8)}…` : "Awaiting Worker"}</p>
                        <p>{attestation.expires_at && attestation.status === "passed" ? `Expires ${new Date(attestation.expires_at).toLocaleString()}` : attestation.failure_code ? attestation.failure_code.replaceAll("_", " ") : new Date(attestation.created_at).toLocaleString()}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader><CardTitle className="text-base">Activation and rollout ledger</CardTitle><CardDescription>Each entry pins one published Artifact version. Canary calls feed durable health gates; an open circuit disables the Tool immediately.</CardDescription></CardHeader>
              <CardContent className="space-y-3">
                {activations.length === 0 ? <div className="rounded-lg border border-dashed border-[#c9ced7] p-8 text-center text-sm text-muted-foreground"><Unplug className="mx-auto mb-2 size-5" />No tool contracts activated.</div> : activations.map((activation) => {
                  const canPromote = activation.status === "active" && activation.rollout_state === "canary" && activation.circuit_state === "closed" && activation.successful_calls >= activation.minimum_successful_calls && activation.failed_calls <= activation.maximum_failed_calls;
                  const hasFreshRecoveryEvidence = attestations.some((item) => mcpAttestationIsFresh(item, activation.server_id, activation.artifact_version_id, clockNow));
                  return (
                    <div key={activation.id} className="rounded-lg border border-[#d8dbe0] bg-white p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-semibold">{activation.tool_name}</p>
                            <Badge variant="outline" className={activation.status === "active" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : "border-slate-300 bg-slate-50 text-slate-600"}>{activation.status}</Badge>
                            <Badge variant="outline" className={cn("text-[10px]", activation.rollout_state === "full" ? "border-indigo-300 bg-indigo-50 text-indigo-700" : activation.rollout_state === "blocked" ? "border-red-300 bg-red-50 text-red-700" : "border-amber-300 bg-amber-50 text-amber-700")}>{activation.rollout_state} · {activation.traffic_percent}%</Badge>
                            <Badge variant="outline" className={activation.circuit_state === "closed" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : "border-red-300 bg-red-50 text-red-700"}>circuit {activation.circuit_state}</Badge>
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">remote: {activation.mcp_tool_name}</p>
                          <p className="mt-1 font-mono text-[10px] text-muted-foreground" title={activation.contract_sha256}>{shortHash(activation.contract_sha256)}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {activation.rollout_state === "canary" && <Button size="sm" variant="outline" disabled={busy !== null || !canPromote} onClick={() => void promoteTool(activation)} className="border-indigo-200 text-indigo-700 hover:bg-indigo-50">{busy === `promote-${activation.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <Rocket className="size-3.5" />} Promote 100%</Button>}
                          {activation.rollout_state === "blocked" && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void queueRecoveryAttestation(activation)} className="border-amber-200 text-amber-700 hover:bg-amber-50">{busy === `reattest-${activation.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />} Re-attest</Button>}
                          {activation.rollout_state === "blocked" && <Button size="sm" variant="outline" disabled={busy !== null || !hasFreshRecoveryEvidence} onClick={() => void recoverTool(activation)} className="border-emerald-200 text-emerald-700 hover:bg-emerald-50">{busy === `recover-${activation.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />} Recover to canary</Button>}
                          {activation.status === "active" && <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void deactivateTool(activation)} className="border-red-200 text-red-700 hover:bg-red-50">{busy === `deactivate-${activation.id}` ? <Loader2 className="size-3.5 animate-spin" /> : <Unplug className="size-3.5" />} Deactivate</Button>}
                        </div>
                      </div>
                      <div className="mt-3 grid gap-2 rounded-md bg-[#f8f8fb] px-3 py-2 text-[11px] text-muted-foreground sm:grid-cols-3">
                        <p><span className="font-semibold text-[#4f5d73]">Success:</span> {activation.successful_calls}/{activation.minimum_successful_calls}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Failures:</span> {activation.failed_calls}/{activation.maximum_failed_calls}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Consecutive:</span> {activation.consecutive_failures}/{activation.circuit_failure_threshold}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Last call:</span> {activation.last_call_at ? new Date(activation.last_call_at).toLocaleString() : "awaiting traffic"}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Revision:</span> {activation.revision}</p>
                        <p><span className="font-semibold text-[#4f5d73]">Promotion:</span> {activation.promoted_at ? new Date(activation.promoted_at).toLocaleString() : "not promoted"}</p>
                      </div>
                      {activation.rollout_state === "blocked" && <p className="mt-2 text-[11px] text-red-700">Circuit recovery requires a new unconsumed Worker attestation for this exact contract.</p>}
                      <p className="mt-3 text-xs leading-5 text-muted-foreground">{activation.activation_reason}</p>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>
        </section>

        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#d8dbe0] bg-white px-4 py-3 text-xs text-muted-foreground">
          <span>Internal platform tools remain local handlers; external user tools cross this MCP governance boundary.</span>
          <Link href="/studio/artifacts" className="inline-flex items-center gap-1 font-semibold text-[#5856d6]">Open Artifact Library <ExternalLink className="size-3" /></Link>
        </div>
      </main>
    </div>
  );
}
