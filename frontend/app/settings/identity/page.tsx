"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UserRoundCog,
  Users,
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
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type PrincipalContext = {
  principal_id: string | null;
  subject: string;
  permissions: string[];
  tenant_id: string;
  region_id: string;
};

type Principal = {
  id: string;
  subject: string;
  display_name: string;
  principal_type: "user" | "service";
  enabled: boolean;
  platform_admin: boolean;
  password_login_configured: boolean;
  allowed_region_ids: string[];
  created_at: string;
};

type Role = {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  system: boolean;
};

type RoleBinding = {
  id: string;
  principal_id: string;
  role_id: string;
  scope: Record<string, unknown>;
  created_at: string;
};

type AccessToken = {
  id: string;
  principal_id: string;
  name: string;
  token_prefix: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revocation_reason: string | null;
  created_at: string;
};

type AccessTokenIssue = {
  token: AccessToken;
  access_token: string;
};

type BrowserSession = {
  id: string;
  principal_id: string;
  auth_source: string;
  federated_identity_id: string | null;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revocation_reason_sha256: string | null;
  created_at: string;
};

type OIDCIdentity = {
  id: string;
  principal_id: string;
  issuer: string;
  issuer_sha256: string;
  subject_sha256: string;
  enabled: boolean;
  last_login_at: string | null;
  created_at: string;
};

type TrustedProxyIdentity = Omit<OIDCIdentity, "last_login_at"> & {
  last_login_at: string | null;
};

type WorkloadIdentity = {
  id: string;
  principal_id: string;
  issuer: string;
  issuer_sha256: string;
  subject_sha256: string;
  audience_sha256: string;
  enabled: boolean;
  max_token_ttl_minutes: number;
  last_exchange_at: string | null;
  created_at: string;
};

type OIDCConfig = {
  enabled: boolean;
  display_name: string | null;
  start_url: string | null;
  local_token_login_enabled: boolean;
};

type TrustedProxyConfig = {
  enabled: boolean;
  display_name: string | null;
  start_url: string | null;
};

type WorkloadConfig = {
  enabled: boolean;
  issuer: string | null;
  audience: string | null;
  token_ttl_minutes: number | null;
};

type IdentityKind = "oidc" | "trusted-proxy" | "workload";
type PageTab = "access" | "federation" | "sessions";

const inputClass =
  "h-10 border-slate-300 bg-white text-sm shadow-none focus-visible:border-violet-600 focus-visible:ring-violet-600/15";
const selectClass =
  "h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm text-slate-800 outline-none focus:border-violet-600 focus:ring-2 focus:ring-violet-600/15";

function formatDate(value: string | null): string {
  if (!value) return "Never";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function shortHash(value: string | null): string {
  if (!value) return "—";
  return value.length > 18 ? value.slice(0, 10) + "…" + value.slice(-6) : value;
}

function isActiveSession(session: BrowserSession): boolean {
  return !session.revoked_at && new Date(session.expires_at).getTime() > Date.now();
}

export default function IdentitySettingsPage() {
  const [context, setContext] = useState<PrincipalContext | null>(null);
  const [principals, setPrincipals] = useState<Principal[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [sessions, setSessions] = useState<BrowserSession[]>([]);
  const [oidcConfig, setOIDCConfig] = useState<OIDCConfig | null>(null);
  const [proxyConfig, setProxyConfig] = useState<TrustedProxyConfig | null>(null);
  const [workloadConfig, setWorkloadConfig] = useState<WorkloadConfig | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [bindings, setBindings] = useState<RoleBinding[]>([]);
  const [tokens, setTokens] = useState<AccessToken[]>([]);
  const [oidcIdentities, setOIDCIdentities] = useState<OIDCIdentity[]>([]);
  const [proxyIdentities, setProxyIdentities] = useState<TrustedProxyIdentity[]>([]);
  const [workloadIdentities, setWorkloadIdentities] = useState<WorkloadIdentity[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [tab, setTab] = useState<PageTab>("access");

  const [principalSubject, setPrincipalSubject] = useState("");
  const [principalName, setPrincipalName] = useState("");
  const [principalType, setPrincipalType] = useState<"user" | "service">("user");
  const [roleId, setRoleId] = useState("");
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDescription, setNewRoleDescription] = useState("");
  const [newRolePermissions, setNewRolePermissions] = useState("");
  const [scopeMode, setScopeMode] = useState<"all" | "sites" | "device_ids">("all");
  const [scopeValues, setScopeValues] = useState("");
  const [tokenName, setTokenName] = useState("");
  const [tokenHours, setTokenHours] = useState("24");
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [identityKind, setIdentityKind] = useState<IdentityKind>("oidc");
  const [identitySubject, setIdentitySubject] = useState("");
  const [workloadTTL, setWorkloadTTL] = useState("30");
  const [reason, setReason] = useState("Administrative change from Identity & Sessions.");

  const selected = principals.find((item) => item.id === selectedId) || null;
  const roleNames = useMemo(
    () => new Map(roles.map((role) => [role.id, role.name])),
    [roles],
  );
  const selectedSessions = sessions.filter((item) => item.principal_id === selectedId);
  const activeSessionCount = sessions.filter(isActiveSession).length;

  const loadSummary = useCallback(async () => {
    setLoading(true);
    try {
      const [nextContext, nextPrincipals, nextRoles, nextSessions, oidc, proxy, workload] =
        await Promise.all([
          apiFetch<PrincipalContext>("/auth/me"),
          apiFetch<Principal[]>("/auth/principals?limit=1000"),
          apiFetch<Role[]>("/auth/roles?limit=1000"),
          apiFetch<BrowserSession[]>("/auth/browser-sessions?limit=1000"),
          apiFetch<OIDCConfig>("/auth/oidc/config"),
          apiFetch<TrustedProxyConfig>("/auth/trusted-proxy/config"),
          apiFetch<WorkloadConfig>("/auth/workload/config"),
        ]);
      setContext(nextContext);
      setPrincipals(nextPrincipals);
      setRoles(nextRoles);
      setSessions(nextSessions);
      setOIDCConfig(oidc);
      setProxyConfig(proxy);
      setWorkloadConfig(workload);
      setRoleId((current) => current || nextRoles[0]?.id || "");
      setSelectedId((current) =>
        nextPrincipals.some((item) => item.id === current)
          ? current
          : nextContext.principal_id || nextPrincipals[0]?.id || "",
      );
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to load identity administration",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetails = useCallback(async (principalId: string) => {
    if (!principalId) return;
    setDetailLoading(true);
    try {
      const [nextBindings, nextTokens, nextOIDC, nextProxy, nextWorkload] =
        await Promise.all([
          apiFetch<RoleBinding[]>(`/auth/principals/${principalId}/bindings`),
          apiFetch<AccessToken[]>(`/auth/principals/${principalId}/tokens?limit=1000`),
          apiFetch<OIDCIdentity[]>(`/auth/principals/${principalId}/oidc-identities`),
          apiFetch<TrustedProxyIdentity[]>(
            `/auth/principals/${principalId}/trusted-proxy-identities`,
          ),
          apiFetch<WorkloadIdentity[]>(
            `/auth/principals/${principalId}/workload-identities`,
          ),
        ]);
      setBindings(nextBindings);
      setTokens(nextTokens);
      setOIDCIdentities(nextOIDC);
      setProxyIdentities(nextProxy);
      setWorkloadIdentities(nextWorkload);
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to load principal details",
      });
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadSummary(), 0);
    return () => window.clearTimeout(timer);
  }, [loadSummary]);

  useEffect(() => {
    if (!selectedId) return;
    const timer = window.setTimeout(() => {
      setNewPassword("");
      setConfirmPassword("");
      void loadDetails(selectedId);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadDetails, selectedId]);

  async function refreshDetails() {
    await loadSummary();
    if (selectedId) await loadDetails(selectedId);
  }

  async function createPrincipal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("principal");
    setMessage(null);
    try {
      const created = await apiFetch<Principal>("/auth/principals", {
        method: "POST",
        body: JSON.stringify({
          subject: principalSubject,
          display_name: principalName,
          principal_type: principalType,
          allowed_region_ids: context?.region_id ? [context.region_id] : [],
        }),
      });
      setPrincipalSubject("");
      setPrincipalName("");
      setSelectedId(created.id);
      setMessage({ tone: "success", text: "Principal created without implicit roles or credentials." });
      await loadSummary();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to create principal" });
    } finally {
      setBusy(null);
    }
  }

  async function setPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    if (newPassword !== confirmPassword) {
      setMessage({ tone: "error", text: "Passwords do not match." });
      return;
    }
    setBusy("password");
    setMessage(null);
    try {
      await apiFetch<Principal>(`/auth/principals/${selected.id}/password`, {
        method: "PUT", body: JSON.stringify({ password: newPassword, reason }),
      });
      if (selected.id === context?.principal_id) {
        window.location.assign("/login");
        return;
      }
      setMessage({ tone: "success", text: "Password saved. Existing browser sessions were revoked; API tokens are unchanged." });
      await refreshDetails();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to set password" });
    } finally {
      setNewPassword("");
      setConfirmPassword("");
      setBusy(null);
    }
  }

  async function setPrincipalEnabled(enabled: boolean) {
    if (!selected) return;
    setBusy("principal-status");
    setMessage(null);
    try {
      await apiFetch<Principal>(`/auth/principals/${selected.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled, reason }),
      });
      setMessage({
        tone: "success",
        text: enabled
          ? "Principal enabled. Previously revoked credentials remain revoked."
          : "Principal disabled; active access tokens and browser sessions were revoked.",
      });
      await refreshDetails();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to update principal" });
    } finally {
      setBusy(null);
    }
  }

  async function addRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const values = scopeValues.split(",").map((item) => item.trim()).filter(Boolean);
    const scope = scopeMode === "all" ? { all: true } : { [scopeMode]: values };
    setBusy("role");
    setMessage(null);
    try {
      await apiFetch<RoleBinding>(`/auth/principals/${selected.id}/bindings`, {
        method: "POST",
        body: JSON.stringify({ role_id: roleId, scope }),
      });
      setScopeValues("");
      setMessage({ tone: "success", text: "Role bound with the declared scope." });
      await loadDetails(selected.id);
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to bind role" });
    } finally {
      setBusy(null);
    }
  }

  async function createRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("new-role");
    setMessage(null);
    try {
      const created = await apiFetch<Role>("/auth/roles", {
        method: "POST",
        body: JSON.stringify({
          name: newRoleName,
          description: newRoleDescription,
          permissions: newRolePermissions
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
        }),
      });
      setNewRoleName("");
      setNewRoleDescription("");
      setNewRolePermissions("");
      setRoleId(created.id);
      setMessage({
        tone: "success",
        text: "Custom role created. Bind it explicitly to grant access.",
      });
      await loadSummary();
    } catch (cause) {
      setMessage({
        tone: "error",
        text: cause instanceof Error ? cause.message : "Unable to create role",
      });
    } finally {
      setBusy(null);
    }
  }

  async function revokeBinding(bindingId: string) {
    if (!selected) return;
    setBusy(`binding-${bindingId}`);
    setMessage(null);
    try {
      await apiFetch<void>(`/auth/bindings/${bindingId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      setMessage({ tone: "success", text: "Role binding revoked immediately." });
      await loadDetails(selected.id);
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to revoke role" });
    } finally {
      setBusy(null);
    }
  }

  async function issueToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setBusy("token");
    setIssuedToken(null);
    setMessage(null);
    try {
      const result = await apiFetch<AccessTokenIssue>(`/auth/principals/${selected.id}/tokens`, {
        method: "POST",
        body: JSON.stringify({ name: tokenName, expires_in_hours: Number(tokenHours) }),
      });
      setIssuedToken(result.access_token);
      setTokenName("");
      setMessage({ tone: "success", text: "Access token issued. It is shown only once." });
      await loadDetails(selected.id);
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to issue token" });
    } finally {
      setBusy(null);
    }
  }

  async function revokeToken(tokenId: string) {
    if (!selected) return;
    setBusy(`token-${tokenId}`);
    setMessage(null);
    try {
      await apiFetch<AccessToken>(`/auth/tokens/${tokenId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      setMessage({ tone: "success", text: "Access token revoked." });
      await loadDetails(selected.id);
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to revoke token" });
    } finally {
      setBusy(null);
    }
  }

  async function copyIssuedToken() {
    if (!issuedToken) return;
    await navigator.clipboard.writeText(issuedToken);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  async function addIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setBusy("identity");
    setMessage(null);
    const path =
      identityKind === "oidc"
        ? "oidc-identities"
        : identityKind === "trusted-proxy"
          ? "trusted-proxy-identities"
          : "workload-identities";
    const payload =
      identityKind === "workload"
        ? { subject: identitySubject, max_token_ttl_minutes: Number(workloadTTL) }
        : { subject: identitySubject };
    try {
      await apiFetch(`/auth/principals/${selected.id}/${path}`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setIdentitySubject("");
      setMessage({
        tone: "success",
        text: "External identity prebound. The raw subject was accepted once and is not returned.",
      });
      await loadDetails(selected.id);
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to bind identity" });
    } finally {
      setBusy(null);
    }
  }

  async function toggleIdentity(
    kind: IdentityKind,
    identity: OIDCIdentity | TrustedProxyIdentity | WorkloadIdentity,
  ) {
    if (!selected) return;
    setBusy(`identity-${identity.id}`);
    setMessage(null);
    const path = kind === "oidc" ? "oidc-identities" : kind === "trusted-proxy" ? "trusted-proxy-identities" : "workload-identities";
    const payload =
      kind === "workload"
        ? {
            enabled: !identity.enabled,
            max_token_ttl_minutes: (identity as WorkloadIdentity).max_token_ttl_minutes,
            reason,
          }
        : { enabled: !identity.enabled, reason };
    try {
      await apiFetch(`/auth/${path}/${identity.id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      setMessage({
        tone: "success",
        text: identity.enabled
          ? "Identity disabled; linked live credentials were invalidated."
          : "Identity enabled for the prebound principal.",
      });
      await refreshDetails();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to update identity" });
    } finally {
      setBusy(null);
    }
  }

  async function revokeSession(sessionId: string) {
    setBusy(`session-${sessionId}`);
    setMessage(null);
    try {
      await apiFetch<BrowserSession>(`/auth/browser-sessions/${sessionId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      setMessage({ tone: "success", text: "Browser session revoked." });
      await loadSummary();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to revoke session" });
    } finally {
      setBusy(null);
    }
  }

  async function revokeAllSessions() {
    if (!selected) return;
    setBusy("all-sessions");
    setMessage(null);
    try {
      const result = await apiFetch<{ revoked_count: number }>(
        `/auth/principals/${selected.id}/browser-sessions/revoke`,
        { method: "POST", body: JSON.stringify({ reason }) },
      );
      setMessage({ tone: "success", text: `${result.revoked_count} browser session(s) revoked.` });
      await loadSummary();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to revoke sessions" });
    } finally {
      setBusy(null);
    }
  }

  const federationRows = [
    ...oidcIdentities.map((identity) => ({ kind: "oidc" as const, identity, lastUse: identity.last_login_at })),
    ...proxyIdentities.map((identity) => ({ kind: "trusted-proxy" as const, identity, lastUse: identity.last_login_at })),
    ...workloadIdentities.map((identity) => ({ kind: "workload" as const, identity, lastUse: identity.last_exchange_at })),
  ];
  const selectedKindEnabled =
    identityKind === "oidc"
      ? oidcConfig?.enabled
      : identityKind === "trusted-proxy"
        ? proxyConfig?.enabled
        : workloadConfig?.enabled;

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1440px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link href="/" className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700" aria-label="Back to AI operator">
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <UserRoundCog className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">Identity & sessions</h1>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">Prebound identities, explicit roles, short-lived credentials, and immediate revocation.</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm"><Link href="/settings/tenancy">Tenant & region</Link></Button>
            <Button variant="outline" size="sm" onClick={() => void refreshDetails()} disabled={loading || busy !== null}>
              <RefreshCw className={loading ? "animate-spin" : ""} />Refresh
            </Button>
          </div>
        </header>

        {message ? (
          <div className={cn("mt-5 rounded-xl border px-4 py-3 text-sm", message.tone === "error" ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700")}>
            {message.text}
          </div>
        ) : null}

        <section className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {[
            { label: "Principals", value: principals.length, ready: true },
            { label: "Active sessions", value: activeSessionCount, ready: true },
            { label: "OIDC browser", value: oidcConfig?.enabled ? "Enabled" : "Off", ready: Boolean(oidcConfig?.enabled) },
            { label: "Identity gateway", value: proxyConfig?.enabled ? "Enabled" : "Off", ready: Boolean(proxyConfig?.enabled) },
            { label: "CI workload OIDC", value: workloadConfig?.enabled ? "Enabled" : "Off", ready: Boolean(workloadConfig?.enabled) },
          ].map((item) => (
            <Card key={item.label} className="border-slate-200 shadow-sm">
              <CardContent className="flex items-center justify-between p-4">
                <div><p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{item.label}</p><p className="mt-1 text-xl font-semibold">{loading ? "—" : item.value}</p></div>
                <span className={cn("size-2 rounded-full", item.ready ? "bg-emerald-500" : "bg-slate-300")} />
              </CardContent>
            </Card>
          ))}
        </section>

        <section className="mt-5 grid gap-5 lg:grid-cols-[360px_minmax(0,1fr)]">
          <div className="space-y-5">
            <Card className="border-slate-200 shadow-sm">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Plus className="size-4 text-violet-600" />Create principal</CardTitle><CardDescription>No role, token, or external identity is granted implicitly.</CardDescription></CardHeader>
              <CardContent>
                <form className="space-y-3" onSubmit={createPrincipal}>
                  <Input required aria-label="Username or service subject" className={inputClass} value={principalSubject} onChange={(event) => setPrincipalSubject(event.target.value)} placeholder="Username, e.g. operator or user@example.com" />
                  <Input required className={inputClass} value={principalName} onChange={(event) => setPrincipalName(event.target.value)} placeholder="Display name" />
                  <select aria-label="Principal type" className={selectClass} value={principalType} onChange={(event) => setPrincipalType(event.target.value as "user" | "service")}>
                    <option value="user">Human user</option><option value="service">Service principal</option>
                  </select>
                  <Button className="w-full bg-violet-600 hover:bg-violet-700" disabled={busy !== null}>{busy === "principal" ? <Loader2 className="animate-spin" /> : <Plus />}Create without access</Button>
                </form>
              </CardContent>
            </Card>

            <Card className="border-slate-200 shadow-sm">
              <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Users className="size-4 text-violet-600" />Principals</CardTitle><CardDescription>{context ? `Authenticated as ${context.subject}` : "Resolving current administrator"}</CardDescription></CardHeader>
              <CardContent className="space-y-2">
                {loading ? <div className="flex h-24 items-center justify-center text-sm text-muted-foreground"><Loader2 className="mr-2 size-4 animate-spin" />Loading</div> : principals.length === 0 ? <p className="rounded-xl bg-slate-50 p-4 text-sm text-muted-foreground">No stored principals in this tenant.</p> : principals.map((principal) => (
                  <button key={principal.id} type="button" onClick={() => setSelectedId(principal.id)} className={cn("w-full rounded-xl border p-3 text-left transition", selectedId === principal.id ? "border-violet-300 bg-violet-50" : "border-slate-200 bg-white hover:border-slate-300")}>
                    <span className="flex items-start justify-between gap-2"><span className="min-w-0"><span className="block truncate text-sm font-semibold">{principal.display_name}</span><span className="block truncate font-mono text-[10px] text-muted-foreground">{principal.subject}</span></span><span className={cn("mt-1 size-2 shrink-0 rounded-full", principal.enabled ? "bg-emerald-500" : "bg-red-400")} /></span>
                    <span className="mt-2 flex gap-1"><Badge variant="outline" className="text-[9px]">{principal.principal_type}</Badge>{principal.platform_admin ? <Badge className="bg-violet-600 text-[9px]">platform admin</Badge> : null}</span>
                  </button>
                ))}
              </CardContent>
            </Card>
          </div>

          <div className="min-w-0 space-y-5">
            {!selected ? (
              <Card className="border-dashed border-slate-300 shadow-none"><CardContent className="flex h-64 items-center justify-center text-sm text-muted-foreground">Select or create a principal to manage access.</CardContent></Card>
            ) : (
              <>
                <Card className="border-slate-200 shadow-sm">
                  <CardContent className="flex flex-col gap-4 p-5 xl:flex-row xl:items-center">
                    <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-violet-100 text-violet-700"><Fingerprint className="size-5" /></span>
                    <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="truncate text-lg font-semibold">{selected.display_name}</h2><Badge variant={selected.enabled ? "default" : "destructive"}>{selected.enabled ? "Enabled" : "Disabled"}</Badge></div><p className="mt-1 truncate font-mono text-xs text-muted-foreground">{selected.subject} · {selected.id}</p></div>
                    <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" onClick={() => void setPrincipalEnabled(!selected.enabled)} disabled={busy !== null || context?.principal_id === selected.id}>{selected.enabled ? <LockKeyhole /> : <Check />}{selected.enabled ? "Disable principal" : "Enable principal"}</Button></div>
                  </CardContent>
                </Card>

                <div className="flex flex-wrap gap-2 rounded-xl border border-slate-200 bg-white p-2 shadow-sm">
                  {(["access", "federation", "sessions"] as const).map((item) => (
                    <button key={item} type="button" onClick={() => setTab(item)} className={cn("rounded-lg px-4 py-2 text-sm font-medium capitalize", tab === item ? "bg-violet-600 text-white" : "text-slate-600 hover:bg-slate-100")}>{item}</button>
                  ))}
                  {detailLoading ? <Loader2 className="ml-auto mr-2 mt-2 size-4 animate-spin text-muted-foreground" /> : null}
                </div>

                <Card className="border-amber-200 bg-amber-50/60 shadow-none">
                  <CardContent className="grid gap-2 p-4 sm:grid-cols-[200px_1fr] sm:items-center"><label htmlFor="identity-change-reason" className="text-xs font-semibold text-amber-900">Reason for revocation/status changes</label><Input id="identity-change-reason" required className="h-9 border-amber-300 bg-white" value={reason} onChange={(event) => setReason(event.target.value)} /></CardContent>
                </Card>

                {tab === "access" ? (
                  <div className="grid gap-5 xl:grid-cols-2">
                    {selected.principal_type === "user" ? (
                      <Card className="border-slate-200 shadow-sm xl:col-span-2">
                        <CardHeader>
                          <CardTitle className="text-base">Web sign-in password</CardTitle>
                          <CardDescription>Username: {selected.subject}. {selected.password_login_configured ? "Password configured." : "Set a password to enable username/password sign-in."} Resetting it signs out existing browser sessions, including your own if this is your account. API tokens are unchanged.</CardDescription>
                        </CardHeader>
                        <CardContent>
                          <form onSubmit={setPassword} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
                            <label className="space-y-1 text-xs">New password
                              <Input required type="password" name="new-password" autoComplete="new-password" minLength={15} maxLength={256} className={inputClass} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
                            </label>
                            <label className="space-y-1 text-xs">Confirm password
                              <Input required type="password" autoComplete="new-password" minLength={15} maxLength={256} className={inputClass} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} />
                            </label>
                            <Button className="self-end" disabled={busy !== null}>Set password</Button>
                          </form>
                          <p className="mt-2 text-xs text-muted-foreground">Use a passphrase of 15 to 256 characters. Passwords cannot be retrieved.</p>
                        </CardContent>
                      </Card>
                    ) : null}
                    <Card className="border-slate-200 shadow-sm">
                      <CardHeader><CardTitle className="text-base">Role bindings</CardTitle><CardDescription>Roles are local authority; external claims never create one.</CardDescription></CardHeader>
                      <CardContent className="space-y-4">
                        <form className="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-3" onSubmit={addRole}>
                          <select aria-label="Role to bind" className={selectClass} value={roleId} onChange={(event) => setRoleId(event.target.value)} required>{roles.map((role) => <option key={role.id} value={role.id}>{role.name}{role.system ? " · built-in" : ""}</option>)}</select>
                          <select aria-label="Role binding resource scope" className={selectClass} value={scopeMode} onChange={(event) => setScopeMode(event.target.value as typeof scopeMode)}><option value="all">All resources in region</option><option value="sites">Selected sites</option><option value="device_ids">Selected device IDs</option></select>
                          {scopeMode !== "all" ? <Input required className={inputClass} value={scopeValues} onChange={(event) => setScopeValues(event.target.value)} placeholder="Comma-separated exact values" /> : null}
                          <Button size="sm" className="bg-violet-600 hover:bg-violet-700" disabled={busy !== null || !selected.enabled}><ShieldCheck />Bind role</Button>
                        </form>
                        <details className="rounded-xl border border-slate-200 bg-white p-3">
                          <summary className="cursor-pointer text-xs font-semibold text-slate-700">Create a custom role</summary>
                          <form className="mt-3 space-y-2" onSubmit={createRole}>
                            <Input required className={inputClass} value={newRoleName} onChange={(event) => setNewRoleName(event.target.value)} placeholder="role_name" pattern="[a-z][a-z0-9_.-]*" />
                            <Input className={inputClass} value={newRoleDescription} onChange={(event) => setNewRoleDescription(event.target.value)} placeholder="Purpose and operating boundary" />
                            <textarea required className="min-h-20 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs outline-none focus:border-violet-600 focus:ring-2 focus:ring-violet-600/15" value={newRolePermissions} onChange={(event) => setNewRolePermissions(event.target.value)} placeholder="Comma-separated permissions, e.g. assets.read, alerts.read" />
                            <Button type="submit" variant="outline" size="sm" disabled={busy !== null}><Plus />Create role</Button>
                          </form>
                        </details>
                        <div className="space-y-2">{bindings.length === 0 ? <p className="rounded-lg bg-slate-50 p-3 text-xs text-muted-foreground">No role bindings.</p> : bindings.map((binding) => <div key={binding.id} className="flex items-start gap-3 rounded-xl border border-slate-200 p-3"><div className="min-w-0 flex-1"><p className="text-sm font-semibold">{roleNames.get(binding.role_id) || binding.role_id}</p><p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">{JSON.stringify(binding.scope)}</p></div><Button variant="outline" size="icon-sm" aria-label="Revoke role binding" onClick={() => void revokeBinding(binding.id)} disabled={busy !== null || context?.principal_id === selected.id}><Trash2 /></Button></div>)}</div>
                      </CardContent>
                    </Card>

                    <Card className="border-slate-200 shadow-sm">
                      <CardHeader><CardTitle className="text-base">API access tokens</CardTitle><CardDescription>For API integrations, not web sign-in. Collector credentials remain separately managed.</CardDescription></CardHeader>
                      <CardContent className="space-y-4">
                        <form className="grid gap-2 sm:grid-cols-[1fr_100px_auto]" onSubmit={issueToken}><Input required className={inputClass} value={tokenName} onChange={(event) => setTokenName(event.target.value)} placeholder="Token purpose" /><Input required type="number" min="1" max="8760" className={inputClass} value={tokenHours} onChange={(event) => setTokenHours(event.target.value)} aria-label="Token lifetime in hours" /><Button className="bg-violet-600 hover:bg-violet-700" disabled={busy !== null || !selected.enabled}><KeyRound />Issue</Button></form>
                        {issuedToken ? <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3"><p className="text-xs font-semibold text-emerald-800">Copy now—this value is not stored in retrievable form.</p><div className="mt-2 flex gap-2"><code className="min-w-0 flex-1 overflow-hidden text-ellipsis rounded bg-white px-2 py-2 text-xs">{issuedToken}</code><Button variant="outline" size="icon" onClick={() => void copyIssuedToken()} aria-label="Copy token">{copied ? <Check /> : <Copy />}</Button></div></div> : null}
                        <div className="space-y-2">{tokens.length === 0 ? <p className="rounded-lg bg-slate-50 p-3 text-xs text-muted-foreground">No access tokens.</p> : tokens.map((token) => <div key={token.id} className="flex items-start gap-3 rounded-xl border border-slate-200 p-3"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-semibold">{token.name}</p><Badge variant={token.revoked_at ? "destructive" : "outline"} className="text-[9px]">{token.revoked_at ? "revoked" : "active"}</Badge></div><p className="mt-1 font-mono text-[10px] text-muted-foreground">{token.token_prefix}… · expires {formatDate(token.expires_at)}</p></div>{!token.revoked_at ? <Button variant="outline" size="icon-sm" aria-label="Revoke access token" onClick={() => void revokeToken(token.id)} disabled={busy !== null}><Trash2 /></Button> : null}</div>)}</div>
                      </CardContent>
                    </Card>
                  </div>
                ) : null}

                {tab === "federation" ? (
                  <Card className="border-slate-200 shadow-sm">
                    <CardHeader><CardTitle className="text-base">Prebound external identities</CardTitle><CardDescription>The raw external subject is accepted once, hashed, and never returned to this page.</CardDescription></CardHeader>
                    <CardContent className="space-y-5">
                      <form className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 lg:grid-cols-[190px_1fr_120px_auto]" onSubmit={addIdentity}>
                        <select aria-label="External identity provider kind" className={selectClass} value={identityKind} onChange={(event) => setIdentityKind(event.target.value as IdentityKind)}><option value="oidc">OIDC browser</option><option value="trusted-proxy">Identity gateway</option><option value="workload">CI workload OIDC</option></select>
                        <Input required className={inputClass} value={identitySubject} onChange={(event) => setIdentitySubject(event.target.value)} placeholder="Exact provider subject" />
                        {identityKind === "workload" ? <Input required type="number" min="1" max="60" className={inputClass} value={workloadTTL} onChange={(event) => setWorkloadTTL(event.target.value)} aria-label="Maximum token TTL in minutes" /> : <div className="hidden lg:block" />}
                        <Button className="bg-violet-600 hover:bg-violet-700" disabled={busy !== null || !selectedKindEnabled || !selected.enabled}><Fingerprint />Prebind</Button>
                      </form>
                      {!selectedKindEnabled ? <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">The selected federation source is disabled in the server environment. Configure and restart the control plane before binding it.</p> : null}
                      <div className="space-y-2">{federationRows.length === 0 ? <p className="rounded-lg bg-slate-50 p-4 text-sm text-muted-foreground">No external identities are bound to this principal.</p> : federationRows.map(({ kind, identity, lastUse }) => <div key={`${kind}-${identity.id}`} className="grid gap-3 rounded-xl border border-slate-200 p-4 md:grid-cols-[150px_1fr_auto] md:items-center"><div><Badge variant="outline">{kind}</Badge><p className="mt-2 text-[10px] text-muted-foreground">Last use {formatDate(lastUse)}</p></div><div className="min-w-0"><p className="truncate text-xs font-medium">{identity.issuer}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">subject sha256 {shortHash(identity.subject_sha256)}</p>{kind === "workload" ? <p className="mt-1 text-[10px] text-muted-foreground">Max TTL {(identity as WorkloadIdentity).max_token_ttl_minutes} minutes</p> : null}</div><Button variant="outline" size="sm" onClick={() => void toggleIdentity(kind, identity)} disabled={busy !== null}>{identity.enabled ? "Disable" : "Enable"}</Button></div>)}</div>
                    </CardContent>
                  </Card>
                ) : null}

                {tab === "sessions" ? (
                  <Card className="border-slate-200 shadow-sm">
                    <CardHeader className="flex-row items-start justify-between gap-4"><div><CardTitle className="text-base">Browser sessions</CardTitle><CardDescription>Only redacted provenance and lifecycle metadata are exposed.</CardDescription></div><Button variant="outline" size="sm" onClick={() => void revokeAllSessions()} disabled={busy !== null || !selectedSessions.some(isActiveSession)}><LockKeyhole />Revoke all active</Button></CardHeader>
                    <CardContent className="space-y-2">{selectedSessions.length === 0 ? <p className="rounded-lg bg-slate-50 p-4 text-sm text-muted-foreground">No browser sessions for this principal.</p> : selectedSessions.map((session) => <div key={session.id} className="grid gap-3 rounded-xl border border-slate-200 p-4 md:grid-cols-[170px_1fr_auto] md:items-center"><div><Badge variant={isActiveSession(session) ? "default" : "outline"}>{isActiveSession(session) ? "active" : session.revoked_at ? "revoked" : "expired"}</Badge><p className="mt-2 font-mono text-[10px] text-muted-foreground">{session.auth_source}</p></div><div><p className="font-mono text-xs text-slate-700">{session.id}</p><p className="mt-1 text-[10px] text-muted-foreground">Created {formatDate(session.created_at)} · expires {formatDate(session.expires_at)} · last used {formatDate(session.last_used_at)}</p>{session.revocation_reason_sha256 ? <p className="mt-1 font-mono text-[10px] text-muted-foreground">reason sha256 {shortHash(session.revocation_reason_sha256)}</p> : null}</div>{isActiveSession(session) ? <Button variant="outline" size="sm" onClick={() => void revokeSession(session.id)} disabled={busy !== null}><Trash2 />Revoke</Button> : null}</div>)}</CardContent>
                  </Card>
                ) : null}
              </>
            )}
          </div>
        </section>

        <footer className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 py-5 text-[11px] text-muted-foreground"><span className="flex items-center gap-1.5"><Activity className="size-3.5" />Identity changes are audited; raw federation subjects, session secrets, and token hashes are never rendered.</span><span>Tenant {context?.tenant_id || "—"} · Region {context?.region_id || "—"}</span></footer>
      </div>
    </main>
  );
}
