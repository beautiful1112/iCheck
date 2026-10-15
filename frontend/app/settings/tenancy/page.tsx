"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useState } from "react";
import {
  ArrowLeft,
  Building2,
  Check,
  Copy,
  Globe2,
  Loader2,
  LockKeyhole,
  Plus,
  RefreshCw,
  Router,
  ShieldCheck,
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
import { apiFetch, setApiNamespace } from "@/lib/icheck-api";

type Tenant = {
  id: string;
  slug: string;
  name: string;
  enabled: boolean;
  default_region_id: string;
};

type Region = {
  id: string;
  tenant_id: string;
  code: string;
  name: string;
  enabled: boolean;
};

type NamespaceContext = {
  tenant: Tenant;
  region: Region;
  allowed_region_ids: string[];
  platform_admin: boolean;
};

type TenantAdminIssue = {
  principal: { id: string; subject: string };
  token: { access_token: string; token: { token_prefix: string } };
};

const inputClass =
  "h-10 border-slate-300 bg-white text-sm shadow-none focus-visible:border-violet-600 focus-visible:ring-violet-600/15";

export default function TenancySettingsPage() {
  const [context, setContext] = useState<NamespaceContext | null>(null);
  const [regions, setRegions] = useState<Region[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [regionCode, setRegionCode] = useState("");
  const [regionName, setRegionName] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [tenantRegionCode, setTenantRegionCode] = useState("primary");
  const [tenantRegionName, setTenantRegionName] = useState("Primary region");
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [adminSubject, setAdminSubject] = useState("");
  const [adminName, setAdminName] = useState("");
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextContext = await apiFetch<NamespaceContext>(
        "/tenancy/context",
      );
      setContext(nextContext);
      const nextRegions = await apiFetch<Region[]>(
        "/tenancy/regions?include_disabled=true",
      );
      setRegions(nextRegions);
      if (nextContext.platform_admin) {
        const nextTenants = await apiFetch<Tenant[]>(
          "/tenancy/tenants?limit=1000",
        );
        setTenants(nextTenants);
        setSelectedTenantId((current) => current || nextTenants[0]?.id || "");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load tenancy");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  function switchRegion(region: Region) {
    if (!context || region.id === context.region.id) return;
    setApiNamespace({ tenantId: context.tenant.id, regionId: region.id });
    window.location.reload();
  }

  async function createRegion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("region");
    setError(null);
    try {
      await apiFetch<Region>("/tenancy/regions", {
        method: "POST",
        body: JSON.stringify({ code: regionCode, name: regionName }),
      });
      setRegionCode("");
      setRegionName("");
      setMessage("Region created with an administrative binding for you.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create region");
    } finally {
      setBusy(null);
    }
  }

  async function createTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("tenant");
    setError(null);
    try {
      const tenant = await apiFetch<Tenant>("/tenancy/tenants", {
        method: "POST",
        body: JSON.stringify({
          slug: tenantSlug,
          name: tenantName,
          default_region_code: tenantRegionCode,
          default_region_name: tenantRegionName,
        }),
      });
      setTenantSlug("");
      setTenantName("");
      setSelectedTenantId(tenant.id);
      setMessage("Tenant created. Provision its first administrator next.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create tenant");
    } finally {
      setBusy(null);
    }
  }

  async function provisionAdmin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("admin");
    setError(null);
    setIssuedToken(null);
    try {
      const result = await apiFetch<TenantAdminIssue>(
        "/tenancy/tenants/" + selectedTenantId + "/admins",
        {
          method: "POST",
          body: JSON.stringify({
            subject: adminSubject,
            display_name: adminName,
            token_name: "initial-tenant-admin",
            expires_in_hours: 24,
          }),
        },
      );
      setIssuedToken(result.token.access_token);
      setAdminSubject("");
      setAdminName("");
      setMessage("Initial administrator created. The token is shown once.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to provision admin");
    } finally {
      setBusy(null);
    }
  }

  async function copyToken() {
    if (!issuedToken) return;
    await navigator.clipboard.writeText(issuedToken);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] px-4 py-6 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1280px]">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link href="/" className="grid size-9 place-items-center rounded-xl border border-slate-200 bg-white text-slate-600 shadow-sm hover:text-violet-700" aria-label="Back to AI operator">
              <ArrowLeft className="size-4" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <Globe2 className="size-5 text-violet-600" />
                <h1 className="text-xl font-semibold tracking-tight">Tenants & regions</h1>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">Select one hard data boundary for the AI operator, collectors, and operational UI.</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm"><Link href="/settings/identity"><ShieldCheck />Identity & sessions</Link></Button>
            <Button asChild variant="outline" size="sm"><Link href="/assets/devices"><Router />Device enrollment</Link></Button>
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} />Refresh</Button>
          </div>
        </header>

        {(error || message) && (
          <div className={"mt-5 rounded-xl border px-4 py-3 text-sm " + (error ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700")}>
            {error || message}
          </div>
        )}

        <section className="mt-6 grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><LockKeyhole className="size-4 text-violet-600" />Active execution boundary</CardTitle>
              <CardDescription>Global RBAC means global inside this tenant and region only.</CardDescription>
            </CardHeader>
            <CardContent>
              {loading || !context ? (
                <div className="flex h-32 items-center justify-center text-sm text-muted-foreground"><Loader2 className="mr-2 size-4 animate-spin" />Resolving authenticated namespace</div>
              ) : (
                <>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4"><div className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tenant</div><div className="mt-2 font-semibold">{context.tenant.name}</div><div className="mt-1 font-mono text-[11px] text-muted-foreground">{context.tenant.slug} · {context.tenant.id}</div></div>
                    <div className="rounded-xl border border-violet-200 bg-violet-50 p-4"><div className="text-[10px] font-semibold uppercase tracking-widest text-violet-600">Active region</div><div className="mt-2 font-semibold text-violet-950">{context.region.name}</div><div className="mt-1 font-mono text-[11px] text-violet-700">{context.region.code} · {context.region.id}</div></div>
                  </div>
                  <div className="mt-5 space-y-2">
                    {regions.map((region) => (
                      <button key={region.id} type="button" disabled={!region.enabled} onClick={() => switchRegion(region)} className="flex w-full items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3 text-left transition hover:border-violet-300 disabled:opacity-50">
                        <span><span className="block text-sm font-medium">{region.name}</span><span className="font-mono text-[10px] text-muted-foreground">{region.code}</span></span>
                        {region.id === context.region.id ? <Badge className="bg-violet-600"><Check />Active</Badge> : <Badge variant="outline">Switch</Badge>}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Plus className="size-4 text-violet-600" />Add a region</CardTitle><CardDescription>The new region starts empty and receives your admin role only.</CardDescription></CardHeader>
            <CardContent><form className="space-y-3" onSubmit={createRegion}><Input required className={inputClass} value={regionCode} onChange={(event) => setRegionCode(event.target.value)} placeholder="region code, e.g. hk-2" /><Input required className={inputClass} value={regionName} onChange={(event) => setRegionName(event.target.value)} placeholder="Region display name" /><Button className="w-full bg-violet-600 hover:bg-violet-700" disabled={busy !== null}>{busy === "region" ? <Loader2 className="animate-spin" /> : <Globe2 />}Create isolated region</Button></form></CardContent>
          </Card>
        </section>

        {context?.platform_admin && (
          <section className="mt-6 grid gap-5 lg:grid-cols-2">
            <Card className="border-slate-200 shadow-sm"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Building2 className="size-4 text-violet-600" />Create tenant</CardTitle><CardDescription>Creates an empty tenant and its first regional control plane.</CardDescription></CardHeader><CardContent><form className="grid gap-3 sm:grid-cols-2" onSubmit={createTenant}><Input required className={inputClass} value={tenantSlug} onChange={(event) => setTenantSlug(event.target.value)} placeholder="tenant-slug" /><Input required className={inputClass} value={tenantName} onChange={(event) => setTenantName(event.target.value)} placeholder="Tenant name" /><Input required className={inputClass} value={tenantRegionCode} onChange={(event) => setTenantRegionCode(event.target.value)} placeholder="primary region code" /><Input required className={inputClass} value={tenantRegionName} onChange={(event) => setTenantRegionName(event.target.value)} placeholder="Primary region name" /><Button className="bg-violet-600 hover:bg-violet-700 sm:col-span-2" disabled={busy !== null}>{busy === "tenant" ? <Loader2 className="animate-spin" /> : <Plus />}Create tenant boundary</Button></form></CardContent></Card>

            <Card className="border-slate-200 shadow-sm"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4 text-violet-600" />Provision first administrator</CardTitle><CardDescription>Issues one short-lived token. It is never stored in this browser.</CardDescription></CardHeader><CardContent><form className="space-y-3" onSubmit={provisionAdmin}><select aria-label="Tenant for the first administrator" className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm" value={selectedTenantId} onChange={(event) => setSelectedTenantId(event.target.value)}>{tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name} · {tenant.slug}</option>)}</select><Input required className={inputClass} value={adminSubject} onChange={(event) => setAdminSubject(event.target.value)} placeholder="admin@example.internal" /><Input required className={inputClass} value={adminName} onChange={(event) => setAdminName(event.target.value)} placeholder="Display name" /><Button variant="outline" className="w-full" disabled={busy !== null || !selectedTenantId}>{busy === "admin" ? <Loader2 className="animate-spin" /> : <ShieldCheck />}Issue tenant admin</Button></form>{issuedToken && <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3"><div className="text-[10px] font-semibold uppercase tracking-widest text-amber-700">Copy now · shown once</div><div className="mt-2 break-all font-mono text-[11px] text-amber-950">{issuedToken}</div><Button size="sm" variant="outline" className="mt-3" onClick={() => void copyToken()}>{copied ? <Check /> : <Copy />}{copied ? "Copied" : "Copy token"}</Button></div>}</CardContent></Card>
          </section>
        )}
      </div>
    </main>
  );
}
