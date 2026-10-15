"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRightLeft,
  Bot,
  CheckCircle2,
  ChartLine,
  CircleDashed,
  Database,
  FileText,
  Fingerprint,
  GitBranch,
  Globe2,
  KeyRound,
  LibraryBig,
  Network,
  PackageCheck,
  PlugZap,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  Wrench,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type ArtifactKind =
  | "collector"
  | "parser"
  | "topology"
  | "tool"
  | "skill"
  | "workflow"
  | "visualization"
  | "report";
type Readiness = "ready" | "blocked" | "declarative";
type ActivationState = "active" | "inactive" | "not_required";

type CatalogItem = {
  artifact_id: string;
  artifact_version_id: string;
  name: string;
  kind: ArtifactKind;
  description: string;
  owner: string;
  tags: string[];
  version: number;
  content_hash: string;
  published_at: string | null;
  runtime: string;
  readiness: Readiness;
  activation_state: ActivationState;
  activation_count: number;
  dependency_count: number;
  required_permissions: string[];
  blockers: string[];
  provenance: {
    source: "local" | "artifact_bundle" | "capability_pack";
    signed: boolean;
    algorithm: string | null;
    key_fingerprint_sha256: string | null;
    verified_at: string | null;
    pack_name: string | null;
    pack_version: string | null;
    pack_digest_sha256: string | null;
  };
  summary: Record<string, unknown>;
};

type CatalogResponse = {
  items: CatalogItem[];
  total: number;
  truncated: boolean;
  scan_truncated: boolean;
  counts: Record<Readiness | ActivationState, number>;
};

const kinds: Array<{ value: ArtifactKind | "all"; label: string }> = [
  { value: "all", label: "All capabilities" },
  { value: "collector", label: "Collectors" },
  { value: "tool", label: "Tools" },
  { value: "skill", label: "Skills" },
  { value: "workflow", label: "Workflows" },
  { value: "topology", label: "Topology views" },
  { value: "parser", label: "Parsers" },
  { value: "visualization", label: "Visualizations" },
  { value: "report", label: "Reports" },
];

const blockerLabels: Record<string, string> = {
  activation_required: "Activation required",
  content_hash_missing: "Immutable content hash missing",
  contract_invalid: "Published contract is no longer valid",
  dependency_drift: "Runtime dependency drift",
  tool_registration_missing: "Tool Registry binding missing",
  tool_registration_disabled: "Tool Registry binding disabled",
  mcp_server_missing: "MCP server missing",
  mcp_server_disabled: "MCP server disabled",
  mcp_server_unhealthy: "MCP server health check failed",
  mcp_protocol_unsupported: "MCP protocol version unsupported",
  mcp_endpoint_invalid: "MCP endpoint violates network policy",
  credential_profile_missing: "Credential profile missing",
  credential_profile_disabled: "Credential profile disabled",
  credential_scope_mismatch: "Credential profile does not allow this MCP server",
};

function readinessClass(readiness: Readiness) {
  if (readiness === "ready") {
    return "border-emerald-300 bg-emerald-50 text-emerald-700";
  }
  if (readiness === "blocked") {
    return "border-red-300 bg-red-50 text-red-700";
  }
  return "border-slate-300 bg-slate-50 text-slate-600";
}

function activationClass(state: ActivationState) {
  if (state === "active") {
    return "border-cyan-300 bg-cyan-50 text-cyan-700";
  }
  if (state === "inactive") {
    return "border-amber-300 bg-amber-50 text-amber-700";
  }
  return "border-slate-300 bg-white text-muted-foreground";
}

function kindIcon(kind: ArtifactKind) {
  if (kind === "collector") return <Database className="h-4 w-4" />;
  if (kind === "tool") return <Wrench className="h-4 w-4" />;
  if (kind === "skill") return <Bot className="h-4 w-4" />;
  if (kind === "workflow") return <GitBranch className="h-4 w-4" />;
  if (kind === "topology") return <Network className="h-4 w-4" />;
  if (kind === "visualization") return <ChartLine className="h-4 w-4" />;
  return <FileText className="h-4 w-4" />;
}

function compactValue(value: unknown) {
  if (Array.isArray(value)) return value.join(", ") || "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function relativeDate(value: string | null) {
  if (!value) return "not recorded";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export default function CapabilityCatalogPage() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<ArtifactKind | "all">("all");
  const [readiness, setReadiness] = useState<Readiness | "all">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const document = await apiFetch<CatalogResponse>(
        "/capability-catalog?limit=500",
      );
      setCatalog(document);
      setSelectedId((current) => current || document.items[0]?.artifact_version_id || null);
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Unable to load capability catalog",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (catalog?.items || []).filter((item) => {
      if (kind !== "all" && item.kind !== kind) return false;
      if (readiness !== "all" && item.readiness !== readiness) return false;
      if (!normalized) return true;
      return [
        item.name,
        item.description,
        item.owner,
        item.kind,
        item.runtime,
        ...item.tags,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalized);
    });
  }, [catalog, kind, query, readiness]);

  const selected =
    filtered.find((item) => item.artifact_version_id === selectedId) ||
    filtered[0] ||
    null;

  const localCounts = useMemo(
    () => ({
      ready: filtered.filter((item) => item.readiness === "ready").length,
      blocked: filtered.filter((item) => item.readiness === "blocked").length,
      active: filtered.filter((item) => item.activation_state === "active").length,
      signed: filtered.filter((item) => item.provenance.signed).length,
    }),
    [filtered],
  );

  return (
    <main className="flex h-screen min-h-[720px] flex-col overflow-hidden bg-[#eef0f5] text-[#253044]">
      <header className="flex min-h-16 shrink-0 flex-wrap items-center justify-between gap-3 border-b border-[#d8dbe0] bg-white px-5 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <Link
            href="/studio"
            className="rounded-md p-2 text-[#59677b] transition hover:bg-[#eef0f5]"
            aria-label="Back to Capability Studio"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#171c2a] text-white">
            <LibraryBig className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold">Capability Catalog</h1>
              <Badge className="border-violet-200 bg-violet-50 text-[10px] text-violet-700">
                live readiness
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              Published contract → dependencies → activation → operator-ready
              {" · "}<Link href="/studio/quality" className="text-indigo-700 underline">Runtime quality</Link>
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/remote">
              <Globe2 className="h-3.5 w-3.5" /> Remote catalogs
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/transparency">
              <Fingerprint className="h-3.5 w-3.5" /> Transparency
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/trust">
              <KeyRound className="h-3.5 w-3.5" /> Organization trust
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/promotions">
              <ArrowRightLeft className="h-3.5 w-3.5" /> Promotions
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/exchange">
              <Send className="h-3.5 w-3.5" /> Exchange
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/catalog/packs">
              <PackageCheck className="h-3.5 w-3.5" /> Organization packs
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/studio/artifacts">
              <FileText className="h-3.5 w-3.5" /> Artifact library
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-2">
            <Link href="/settings/mcp">
              <PlugZap className="h-3.5 w-3.5" /> MCP Gateway
            </Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => void load()}
            disabled={loading}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </header>

      {error && (
        <div className="flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-5 py-2 text-xs text-red-700">
          <XCircle className="h-4 w-4" /> {error}
        </div>
      )}

      <section className="grid shrink-0 grid-cols-4 gap-px border-b border-[#d8dbe0] bg-[#d8dbe0]">
        {[
          ["Ready now", localCounts.ready, CheckCircle2, "text-emerald-600"],
          ["Blocked", localCounts.blocked, XCircle, "text-red-600"],
          ["Active bindings", localCounts.active, Sparkles, "text-cyan-600"],
          ["Signed origin", localCounts.signed, ShieldCheck, "text-violet-600"],
        ].map(([label, value, Icon, color]) => {
          const SummaryIcon = Icon as typeof CheckCircle2;
          return (
            <div key={String(label)} className="flex items-center gap-3 bg-white px-5 py-3">
              <SummaryIcon className={cn("h-4 w-4", String(color))} />
              <div>
                <div className="text-lg font-semibold leading-none">{String(value)}</div>
                <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                  {String(label)}
                </div>
              </div>
            </div>
          );
        })}
      </section>

      <div className="grid min-h-0 flex-1 grid-cols-[245px_minmax(420px,1fr)_390px]">
        <aside className="min-h-0 overflow-y-auto border-r border-[#d8dbe0] bg-[#f8f9fb] p-3">
          <div className="relative mb-4">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search capabilities"
              className="h-9 bg-white pl-9 text-xs"
            />
          </div>

          <div className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Readiness
          </div>
          <div className="mb-5 grid grid-cols-2 gap-1.5">
            {(["all", "ready", "blocked", "declarative"] as const).map((value) => (
              <button
                key={value}
                onClick={() => setReadiness(value)}
                className={cn(
                  "rounded-md border px-2 py-2 text-left text-[11px] capitalize transition",
                  readiness === value
                    ? "border-[#5856d6]/30 bg-white font-semibold text-[#4947ad] shadow-sm"
                    : "border-transparent text-[#59677b] hover:bg-white",
                )}
              >
                {value}
              </button>
            ))}
          </div>

          <div className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Capability type
          </div>
          <div className="space-y-1">
            {kinds.map((item) => (
              <button
                key={item.value}
                onClick={() => setKind(item.value)}
                className={cn(
                  "flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-xs transition",
                  kind === item.value
                    ? "bg-white font-semibold text-[#4947ad] shadow-sm ring-1 ring-[#5856d6]/15"
                    : "text-[#59677b] hover:bg-white",
                )}
              >
                <span>{item.label}</span>
                <span className="text-[10px] tabular-nums text-muted-foreground">
                  {item.value === "all"
                    ? catalog?.items.length || 0
                    : catalog?.items.filter((entry) => entry.kind === item.value).length || 0}
                </span>
              </button>
            ))}
          </div>

          <div className="mt-6 rounded-lg border border-[#d8dbe0] bg-white p-3 text-[11px] leading-5 text-[#59677b]">
            <div className="mb-1 flex items-center gap-2 font-semibold text-[#253044]">
              <ShieldCheck className="h-3.5 w-3.5 text-violet-600" /> Runtime truth
            </div>
            Readiness is recalculated from the published contract, live dependencies,
            and governed activation. It is not a cached authoring status.
          </div>
        </aside>

        <section className="min-h-0 overflow-y-auto p-4">
          <div className="mb-3 flex items-center justify-between px-1">
            <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              {filtered.length} matching capabilities
            </div>
            {(catalog?.truncated || catalog?.scan_truncated) && (
              <span className="text-[10px] text-amber-700">
                {catalog.scan_truncated ? "Catalog scan limit reached" : "First 500 shown"}
              </span>
            )}
          </div>

          {loading && !catalog ? (
            <div className="flex h-64 items-center justify-center text-xs text-muted-foreground">
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> Calculating readiness
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex h-64 flex-col items-center justify-center rounded-xl border border-dashed border-[#cbd1da] bg-white text-center">
              <CircleDashed className="mb-3 h-6 w-6 text-muted-foreground" />
              <div className="text-sm font-semibold">No capability matches</div>
              <div className="mt-1 text-xs text-muted-foreground">Change the search or filters.</div>
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((item) => (
                <button
                  key={item.artifact_version_id}
                  onClick={() => setSelectedId(item.artifact_version_id)}
                  className={cn(
                    "w-full rounded-xl border bg-white p-4 text-left transition",
                    selected?.artifact_version_id === item.artifact_version_id
                      ? "border-[#5856d6]/35 shadow-sm ring-1 ring-[#5856d6]/10"
                      : "border-[#d8dbe0] hover:border-[#b8c0cc]",
                  )}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex min-w-0 gap-3">
                      <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#f0f1f5] text-[#59677b]">
                        {kindIcon(item.kind)}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-semibold">{item.name}</span>
                          <span className="text-[10px] text-muted-foreground">v{item.version}</span>
                        </div>
                        <p className="mt-1 line-clamp-2 text-xs leading-5 text-[#59677b]">
                          {item.description}
                        </p>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <Badge className={cn("text-[9px]", activationClass(item.activation_state))}>
                        {item.activation_state.replace("_", " ")}
                      </Badge>
                      <Badge className={cn("text-[9px]", readinessClass(item.readiness))}>
                        {item.readiness}
                      </Badge>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[#edf0f3] pt-3 text-[10px] text-muted-foreground">
                    <span className="rounded bg-[#f4f5f7] px-2 py-1 capitalize">{item.kind}</span>
                    <span>{item.runtime}</span>
                    <span>·</span>
                    <span>{item.dependency_count} dependencies</span>
                    <span>·</span>
                    <span>{item.required_permissions.length} permissions</span>
                    {item.provenance.signed && (
                      <span className="ml-auto flex items-center gap-1 text-violet-700">
                        <ShieldCheck className="h-3 w-3" /> signed
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <aside className="min-h-0 overflow-y-auto border-l border-[#d8dbe0] bg-white p-5">
          {!selected ? (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
              Select a capability to inspect runtime readiness.
            </div>
          ) : (
            <div>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="mb-2 flex items-center gap-2 text-[#59677b]">
                    {kindIcon(selected.kind)}
                    <span className="text-[10px] font-semibold uppercase tracking-[0.13em]">
                      {selected.kind} · version {selected.version}
                    </span>
                  </div>
                  <h2 className="text-lg font-semibold">{selected.name}</h2>
                </div>
                <Badge className={cn("text-[10px]", readinessClass(selected.readiness))}>
                  {selected.readiness}
                </Badge>
              </div>
              <p className="mt-3 text-xs leading-5 text-[#59677b]">{selected.description}</p>

              {selected.blockers.length > 0 && (
                <div className="mt-5 rounded-lg border border-red-200 bg-red-50 p-3">
                  <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-red-800">
                    <XCircle className="h-3.5 w-3.5" /> Execution blockers
                  </div>
                  <div className="space-y-1.5">
                    {selected.blockers.map((blocker) => (
                      <div key={blocker} className="text-[11px] text-red-700">
                        {blockerLabels[blocker] || blocker.replaceAll("_", " ")}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-5 grid grid-cols-2 gap-2">
                <div className="rounded-lg border border-[#d8dbe0] bg-[#f8f9fb] p-3">
                  <div className="text-[10px] uppercase tracking-[0.11em] text-muted-foreground">Activation</div>
                  <div className="mt-1 text-xs font-semibold capitalize">
                    {selected.activation_state.replace("_", " ")}
                  </div>
                  <div className="mt-1 text-[10px] text-muted-foreground">
                    {selected.activation_count} live bindings
                  </div>
                </div>
                <div className="rounded-lg border border-[#d8dbe0] bg-[#f8f9fb] p-3">
                  <div className="text-[10px] uppercase tracking-[0.11em] text-muted-foreground">Dependencies</div>
                  <div className="mt-1 text-xs font-semibold">{selected.dependency_count}</div>
                  <div className="mt-1 text-[10px] text-muted-foreground">checked at request time</div>
                </div>
              </div>

              <div className="mt-5">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Runtime contract
                </div>
                <dl className="divide-y divide-[#edf0f3] rounded-lg border border-[#d8dbe0]">
                  <div className="flex justify-between gap-4 px-3 py-2.5 text-[11px]">
                    <dt className="text-muted-foreground">Runtime</dt>
                    <dd className="max-w-[220px] break-all text-right font-medium">{selected.runtime}</dd>
                  </div>
                  {Object.entries(selected.summary).map(([key, value]) => (
                    <div key={key} className="flex justify-between gap-4 px-3 py-2.5 text-[11px]">
                      <dt className="capitalize text-muted-foreground">{key.replaceAll("_", " ")}</dt>
                      <dd className="max-w-[220px] break-words text-right font-medium">
                        {compactValue(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="mt-5">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                  Required permissions
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {selected.required_permissions.length ? (
                    selected.required_permissions.map((permission) => (
                      <Badge key={permission} variant="outline" className="bg-white text-[9px]">
                        {permission}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-[11px] text-muted-foreground">No runtime permissions declared</span>
                  )}
                </div>
              </div>

              <div className="mt-5 rounded-lg border border-[#d8dbe0] p-3">
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold">
                  <KeyRound className="h-3.5 w-3.5 text-violet-600" /> Provenance
                </div>
                <div className="space-y-1.5 text-[11px] text-[#59677b]">
                  <div className="flex justify-between gap-3">
                    <span>Origin</span>
                    <span className="font-medium text-[#253044]">
                      {selected.provenance.source === "capability_pack"
                        ? "verified organization pack"
                        : selected.provenance.signed
                          ? "verified artifact bundle"
                          : "local publication"}
                    </span>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span>Content hash</span>
                    <span className="font-mono text-[10px] text-[#253044]">
                      {selected.content_hash.slice(0, 12)}…
                    </span>
                  </div>
                  {selected.provenance.key_fingerprint_sha256 && (
                    <div className="flex justify-between gap-3">
                      <span>Signer</span>
                      <span className="font-mono text-[10px] text-[#253044]">
                        {selected.provenance.key_fingerprint_sha256.slice(0, 12)}…
                      </span>
                    </div>
                  )}
                  {selected.provenance.source === "capability_pack" && (
                    <>
                      <div className="flex justify-between gap-3">
                        <span>Pack</span>
                        <span className="text-right font-medium text-[#253044]">
                          {selected.provenance.pack_name} {selected.provenance.pack_version}
                        </span>
                      </div>
                      <div className="flex justify-between gap-3">
                        <span>Pack digest</span>
                        <span className="font-mono text-[10px] text-[#253044]">
                          {selected.provenance.pack_digest_sha256?.slice(0, 12)}…
                        </span>
                      </div>
                    </>
                  )}
                  <div className="flex justify-between gap-3">
                    <span>Published</span>
                    <span className="text-right text-[#253044]">{relativeDate(selected.published_at)}</span>
                  </div>
                  <div className="flex justify-between gap-3">
                    <span>Owner</span>
                    <span className="text-right text-[#253044]">{selected.owner}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </aside>
      </div>
    </main>
  );
}
