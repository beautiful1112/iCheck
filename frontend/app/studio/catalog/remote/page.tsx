"use client";

import Link from "next/link";
import {
  ChangeEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Eye,
  FileKey2,
  Globe2,
  Loader2,
  PackageCheck,
  RotateCw,
  Power,
  RefreshCw,
  Search,
  ShieldCheck,
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
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type TrustKey = {
  id: string;
  name: string;
  fingerprint_sha256: string;
  enabled: boolean;
};

type RemoteSource = {
  id: string;
  name: string;
  catalog_id: string;
  index_url: string;
  trust_key_id: string;
  enabled: boolean;
  latest_sequence: number | null;
  latest_index_digest_sha256: string | null;
  last_refresh_status: "never" | "succeeded" | "failed";
  last_refresh_at: string | null;
  last_error_sha256: string | null;
  created_by: string;
  created_at: string;
};

type RemoteEntry = {
  id: string;
  source_id: string;
  source_name: string;
  sequence: number;
  issued_at: string;
  expires_at: string;
  pack_name: string;
  pack_version: string;
  platform_api: string;
  pack_digest_sha256: string;
  pack_key_fingerprint_sha256: string;
  predecessor_digest_sha256: string | null;
  download_url: string;
  artifact_count: number;
  dependency_count: number;
  installation_state: "not_installed" | "installed" | "uninstalled";
  revoked: boolean;
  pack_signer_trusted: boolean;
  platform_compatible: boolean;
};

type EntryList = {
  items: RemoteEntry[];
  total: number;
  offset: number;
  limit: number;
};

type PackPreview = {
  pack_name: string;
  pack_version: string;
  operation: "install" | "upgrade";
  installable: boolean;
  already_installed: boolean;
  blockers: string[];
  artifacts: Array<{ name: string; state: string }>;
  dependencies: Array<{ name: string; state: string }>;
};

type KeyRotation = {
  id: string;
  source_id: string;
  from_trust_key_id: string;
  to_trust_key_id: string;
  from_key_fingerprint_sha256: string;
  to_key_fingerprint_sha256: string;
  catalog_sequence: number;
  statement_digest_sha256: string;
  rotated_by: string;
  rotated_at: string;
};

function shortHash(value: string | null) {
  return value ? `${value.slice(0, 12)}…` : "—";
}

function statusClass(status: RemoteSource["last_refresh_status"]) {
  if (status === "succeeded") {
    return "border-emerald-300 bg-emerald-50 text-emerald-700";
  }
  if (status === "failed") {
    return "border-red-300 bg-red-50 text-red-700";
  }
  return "border-slate-300 bg-slate-50 text-slate-600";
}

export default function RemoteCapabilityCatalogsPage() {
  const [sources, setSources] = useState<RemoteSource[]>([]);
  const [entries, setEntries] = useState<RemoteEntry[]>([]);
  const [trustKeys, setTrustKeys] = useState<TrustKey[]>([]);
  const [keyRotations, setKeyRotations] = useState<KeyRotation[]>([]);
  const [name, setName] = useState("");
  const [catalogId, setCatalogId] = useState("");
  const [indexUrl, setIndexUrl] = useState("");
  const [trustKeyId, setTrustKeyId] = useState("");
  const [operationReason, setOperationReason] = useState("");
  const [query, setQuery] = useState("");
  const [previews, setPreviews] = useState<Record<string, PackPreview>>({});
  const [rotationDocuments, setRotationDocuments] = useState<
    Record<string, Record<string, unknown>>
  >({});
  const [rotationFilenames, setRotationFilenames] = useState<Record<string, string>>({});
  const [rotationKeyIds, setRotationKeyIds] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [sourceRows, entryRows, keyRows, rotationRows] = await Promise.all([
        apiFetch<RemoteSource[]>("/remote-capability-catalogs?limit=500"),
        apiFetch<EntryList>(
          "/remote-capability-catalogs/entries/current?limit=500",
        ),
        apiFetch<TrustKey[]>("/artifact-trust-keys"),
        apiFetch<KeyRotation[]>(
          "/remote-capability-catalogs/key-rotations?limit=500",
        ),
      ]);
      setSources(sourceRows);
      setEntries(entryRows.items);
      setTrustKeys(keyRows.filter((key) => key.enabled));
      setKeyRotations(rotationRows);
      setTrustKeyId((current) => (
        current || keyRows.find((key) => key.enabled)?.id || ""
      ));
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load remote capability catalogs",
      );
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const filteredEntries = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return entries;
    return entries.filter((entry) => (
      entry.pack_name.toLowerCase().includes(normalized)
      || entry.source_name.toLowerCase().includes(normalized)
    ));
  }, [entries, query]);

  async function createSource() {
    if (
      !name.trim()
      || !catalogId.trim()
      || !indexUrl.trim()
      || !trustKeyId
    ) return;
    setBusy("create");
    setError(null);
    setMessage(null);
    try {
      const created = await apiFetch<RemoteSource>(
        "/remote-capability-catalogs",
        {
          method: "POST",
          body: JSON.stringify({
            name: name.trim(),
            catalog_id: catalogId.trim(),
            index_url: indexUrl.trim(),
            trust_key_id: trustKeyId,
            created_by: "capability.admin",
          }),
        },
      );
      setName("");
      setCatalogId("");
      setIndexUrl("");
      await load();
      setMessage(
        `${created.name} was pinned. Refresh remains a separate action.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Source creation failed");
    } finally {
      setBusy(null);
    }
  }

  async function refreshSource(source: RemoteSource) {
    const reason = operationReason.trim();
    if (reason.length < 3) return;
    setBusy(`refresh:${source.id}`);
    setError(null);
    setMessage(null);
    try {
      const snapshot = await apiFetch<{ sequence: number; entry_count: number }>(
        `/remote-capability-catalogs/${source.id}/refresh`,
        {
          method: "POST",
          body: JSON.stringify({
            reason,
            actor: "capability.operator",
          }),
        },
      );
      await load();
      setMessage(
        `${source.name} sequence ${snapshot.sequence} verified with ${snapshot.entry_count} entries.`,
      );
    } catch (cause) {
      await load();
      setError(cause instanceof Error ? cause.message : "Catalog refresh failed");
    } finally {
      setBusy(null);
    }
  }

  async function setSourceState(source: RemoteSource) {
    const reason = operationReason.trim();
    if (reason.length < 3) return;
    setBusy(`state:${source.id}`);
    setError(null);
    setMessage(null);
    try {
      const updated = await apiFetch<RemoteSource>(
        `/remote-capability-catalogs/${source.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: !source.enabled,
            reason,
            actor: "capability.admin",
          }),
        },
      );
      await load();
      setMessage(
        `${updated.name} is now ${updated.enabled ? "enabled" : "disabled"}.`,
      );
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Source state change failed",
      );
    } finally {
      setBusy(null);
    }
  }

  async function selectRotation(
    event: ChangeEvent<HTMLInputElement>,
    sourceId: string,
  ) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const document = JSON.parse(await file.text()) as Record<string, unknown>;
      if (
        document.format_version
        !== "icheck.capability-catalog-key-rotation.signed/v1"
      ) {
        throw new Error(
          "Select an icheck.capability-catalog-key-rotation.signed/v1 document",
        );
      }
      setRotationDocuments((current) => ({
        ...current,
        [sourceId]: document,
      }));
      setRotationFilenames((current) => ({
        ...current,
        [sourceId]: file.name,
      }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Rotation JSON is invalid");
    } finally {
      event.target.value = "";
    }
  }

  async function rotateSourceKey(source: RemoteSource) {
    const reason = operationReason.trim();
    const newTrustKeyId = rotationKeyIds[source.id];
    const signedRotation = rotationDocuments[source.id];
    if (reason.length < 3 || !newTrustKeyId || !signedRotation) return;
    setBusy(`rotate:${source.id}`);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<RemoteSource>(
        `/remote-capability-catalogs/${source.id}/rotate-trust-key`,
        {
          method: "POST",
          body: JSON.stringify({
            new_trust_key_id: newTrustKeyId,
            signed_rotation: signedRotation,
            reason,
            actor: "security.admin",
          }),
        },
      );
      setRotationDocuments((current) => {
        const next = { ...current };
        delete next[source.id];
        return next;
      });
      setRotationFilenames((current) => {
        const next = { ...current };
        delete next[source.id];
        return next;
      });
      setRotationKeyIds((current) => {
        const next = { ...current };
        delete next[source.id];
        return next;
      });
      await load();
      setMessage(`${source.name} accepted the dual-signed trust-key rotation.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Trust-key rotation failed");
    } finally {
      setBusy(null);
    }
  }

  async function previewPack(entry: RemoteEntry) {
    const reason = operationReason.trim();
    if (reason.length < 3) return;
    setBusy(`preview:${entry.id}`);
    setError(null);
    setMessage(null);
    try {
      const preview = await apiFetch<PackPreview>(
        `/remote-capability-catalogs/entries/${entry.id}/preview`,
        {
          method: "POST",
          body: JSON.stringify({
            reason,
            actor: "capability.operator",
          }),
        },
      );
      setPreviews((current) => ({ ...current, [entry.id]: preview }));
      setMessage(
        preview.installable
          ? `${entry.pack_name} passed full remote acquisition preview.`
          : `${entry.pack_name} was verified but has installation blockers.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Remote pack preview failed");
    } finally {
      setBusy(null);
    }
  }

  async function installPack(entry: RemoteEntry) {
    const reason = operationReason.trim();
    if (reason.length < 3 || !previews[entry.id]?.installable) return;
    setBusy(`install:${entry.id}`);
    setError(null);
    setMessage(null);
    try {
      const installed = await apiFetch<{
        pack_name: string;
        pack_version: string;
        distribution_channel: string;
      }>(`/remote-capability-catalogs/entries/${entry.id}/install`, {
        method: "POST",
        body: JSON.stringify({
          reason,
          actor: "capability.operator",
        }),
      });
      setPreviews((current) => {
        const next = { ...current };
        delete next[entry.id];
        return next;
      });
      await load();
      setMessage(
        `${installed.pack_name} ${installed.pack_version} was installed from the pinned remote snapshot.`,
      );
    } catch (cause) {
      await load();
      setError(cause instanceof Error ? cause.message : "Remote pack install failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-3 px-5">
          <Link
            href="/studio/catalog"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to catalog"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#171c2a] text-white">
            <Globe2 className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-sm font-semibold">Remote capability catalogs</h1>
            <p className="text-xs text-muted-foreground">
              Pin source → fetch bounded index → verify signature → discover metadata
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              Sources, signer trust and catalog history belong to the selected tenant and region.
            </p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/packs" className="ml-auto">Pack ledger</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/transparency">Transparency</Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => void load()}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Reload
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] space-y-6 px-5 py-6">
        {error && <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700"><XCircle className="h-4 w-4" />{error}</div>}
        {message && <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-700"><CheckCircle2 className="h-4 w-4" />{message}</div>}

        <section className="grid gap-6 xl:grid-cols-[0.8fr_1.2fr]">
          <Card className="h-fit border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Pin a signed source</CardTitle>
              <CardDescription>
                The catalog identity, HTTPS URL, host allowlist, and existing
                Ed25519 trust key are fixed before any network request.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Display name" />
              <Input value={catalogId} onChange={(event) => setCatalogId(event.target.value)} placeholder="Signed catalog ID, for example network-operations" />
              <Input value={indexUrl} onChange={(event) => setIndexUrl(event.target.value)} placeholder="https://capabilities.example.internal/index.json" />
              <NativeSelect aria-label="Trusted signing key" className="w-full" value={trustKeyId} onChange={(event) => setTrustKeyId(event.target.value)}>
                <NativeSelectOption value="">Select trusted signing key</NativeSelectOption>
                {trustKeys.map((key) => <NativeSelectOption key={key.id} value={key.id}>{key.name} · {shortHash(key.fingerprint_sha256)}</NativeSelectOption>)}
              </NativeSelect>
              <Button className="w-full bg-[#5856d6] hover:bg-[#4947ad]" disabled={!name.trim() || !catalogId.trim() || !indexUrl.trim() || !trustKeyId || busy !== null} onClick={() => void createSource()}>
                {busy === "create" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Pin source
              </Button>
              <p className="text-[11px] leading-5 text-muted-foreground">
                Discovery stores only signed index metadata. It does not
                download, install, publish, activate, or execute a pack.
              </p>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Source control</CardTitle>
              <CardDescription>
                Every refresh requires a reason and records sequence, digest,
                signer fingerprint, result, and error hash in audit.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input value={operationReason} onChange={(event) => setOperationReason(event.target.value)} placeholder="Reason for refresh or enable/disable action" />
              {sources.length === 0 ? <div className="rounded-lg border border-dashed border-[#cbd1da] p-10 text-center text-sm text-muted-foreground">No remote sources configured.</div> : sources.map((source) => (
                <div key={source.id} className={cn("rounded-lg border p-4", source.enabled ? "border-[#d8dbe0] bg-white" : "border-slate-300 bg-slate-50")}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold">{source.name}</p>
                      <p className="mt-1 text-[10px] text-muted-foreground">{source.catalog_id} · {source.enabled ? "enabled" : "disabled"}</p>
                    </div>
                    <Badge variant="outline" className={cn("text-[9px]", statusClass(source.last_refresh_status))}>{source.last_refresh_status}</Badge>
                  </div>
                  <p className="mt-2 break-all font-mono text-[9px] text-muted-foreground">{source.index_url}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Badge variant="outline" className="text-[9px]">sequence {source.latest_sequence ?? "—"}</Badge>
                    <Badge variant="outline" className="font-mono text-[9px]">index {shortHash(source.latest_index_digest_sha256)}</Badge>
                    {source.last_error_sha256 && <Badge variant="outline" className="border-red-200 bg-red-50 font-mono text-[9px] text-red-700">error {shortHash(source.last_error_sha256)}</Badge>}
                  </div>
                  <p className="mt-2 text-[10px] text-muted-foreground">{source.last_refresh_at ? `Last refresh ${new Date(source.last_refresh_at).toLocaleString()}` : "Never refreshed"}</p>
                  <div className="mt-3 flex gap-2">
                    <Button variant="outline" size="sm" className="gap-2" disabled={!source.enabled || operationReason.trim().length < 3 || busy !== null} onClick={() => void refreshSource(source)}>
                      {busy === `refresh:${source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Refresh signed index
                    </Button>
                    <Button variant="outline" size="sm" className={cn("gap-2", source.enabled ? "text-red-700" : "text-emerald-700")} disabled={operationReason.trim().length < 3 || busy !== null} onClick={() => void setSourceState(source)}>
                      {busy === `state:${source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Power className="h-3.5 w-3.5" />} {source.enabled ? "Disable" : "Enable"}
                    </Button>
                  </div>
                  <div className="mt-3 grid gap-2 rounded-md border border-violet-100 bg-violet-50/40 p-3 md:grid-cols-[1fr_1fr_auto]">
                    <NativeSelect aria-label="Successor trusted source key"
                      value={rotationKeyIds[source.id] || ""}
                      onChange={(event) => setRotationKeyIds((current) => ({
                        ...current,
                        [source.id]: event.target.value,
                      }))}
                    >
                      <NativeSelectOption value="">Select next trusted key</NativeSelectOption>
                      {trustKeys.filter((key) => key.id !== source.trust_key_id).map((key) => (
                        <NativeSelectOption key={key.id} value={key.id}>
                          {key.name} · {shortHash(key.fingerprint_sha256)}
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                    <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-violet-200 bg-white px-3 py-2 text-[10px] text-violet-700">
                      <FileKey2 className="h-3.5 w-3.5" /> {rotationFilenames[source.id] || "Select dual-signed rotation"}
                      <input
                        type="file"
                        accept=".json,application/json"
                        className="hidden"
                        onChange={(event) => void selectRotation(event, source.id)}
                      />
                    </label>
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-2 border-violet-200 text-violet-700"
                      disabled={
                        operationReason.trim().length < 3
                        || !rotationKeyIds[source.id]
                        || !rotationDocuments[source.id]
                        || busy !== null
                      }
                      onClick={() => void rotateSourceKey(source)}
                    >
                      {busy === `rotate:${source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCw className="h-3.5 w-3.5" />} Rotate key
                    </Button>
                  </div>
                  {keyRotations.filter((item) => item.source_id === source.id).slice(0, 1).map((rotation) => (
                    <p key={rotation.id} className="mt-2 font-mono text-[9px] text-violet-700">
                      last key rotation · sequence {rotation.catalog_sequence} · {shortHash(rotation.from_key_fingerprint_sha256)} → {shortHash(rotation.to_key_fingerprint_sha256)}
                    </p>
                  ))}
                </div>
              ))}
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <CardTitle className="text-base">Current verified discovery</CardTitle>
              <CardDescription>
                Only the newest unexpired snapshot from enabled sources appears.
                A preview fetches and fully verifies the pack; install fetches it
                again and requires the same pinned identity.
              </CardDescription>
              </div>
              <div className="relative w-full max-w-sm">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search packs or sources" />
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {filteredEntries.length === 0 ? <div className="col-span-full rounded-lg border border-dashed border-[#cbd1da] p-10 text-center text-sm text-muted-foreground">No current verified catalog entries.</div> : filteredEntries.map((entry) => (
              <div key={entry.id} className={cn("rounded-lg border p-4", entry.revoked ? "border-red-300 bg-red-50/40" : "border-[#d8dbe0] bg-white")}>
                <div className="flex items-start justify-between gap-3">
                  <div><p className="text-sm font-semibold">{entry.pack_name} {entry.pack_version}</p><p className="mt-1 text-[10px] text-muted-foreground">{entry.source_name} · sequence {entry.sequence}</p></div>
                  <Badge variant="outline" className={cn("text-[9px]", entry.revoked ? "border-red-300 bg-red-50 text-red-700" : entry.installation_state === "installed" ? "border-emerald-300 bg-emerald-50 text-emerald-700" : "border-cyan-300 bg-cyan-50 text-cyan-700")}>{entry.revoked ? "revoked" : entry.installation_state.replace("_", " ")}</Badge>
                </div>
                <div className="mt-3 space-y-1 font-mono text-[9px] text-muted-foreground">
                  <p>pack {shortHash(entry.pack_digest_sha256)}</p>
                  <p>signer {shortHash(entry.pack_key_fingerprint_sha256)}</p>
                  {entry.predecessor_digest_sha256 && <p>predecessor {shortHash(entry.predecessor_digest_sha256)}</p>}
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge variant="outline" className="text-[9px]">{entry.platform_api}</Badge>
                  <Badge variant="outline" className={cn("text-[9px]", entry.platform_compatible ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700")}>{entry.platform_compatible ? "platform compatible" : "platform mismatch"}</Badge>
                  <Badge variant="outline" className={cn("text-[9px]", entry.pack_signer_trusted ? "border-violet-200 bg-violet-50 text-violet-700" : "border-amber-200 bg-amber-50 text-amber-700")}>{entry.pack_signer_trusted ? "pack signer trusted" : "pack signer unknown"}</Badge>
                  <Badge variant="outline" className="text-[9px]">{entry.artifact_count} artifacts</Badge>
                  <Badge variant="outline" className="text-[9px]">{entry.dependency_count} dependencies</Badge>
                </div>
                <p className="mt-3 text-[10px] text-muted-foreground">Expires {new Date(entry.expires_at).toLocaleString()}</p>
                {previews[entry.id] && (
                  <div className={cn(
                    "mt-3 rounded-md border px-3 py-2 text-[10px]",
                    previews[entry.id].installable
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : "border-amber-200 bg-amber-50 text-amber-800",
                  )}>
                    <p className="font-semibold">
                      {previews[entry.id].operation} preview · {previews[entry.id].installable ? "installable" : "blocked"}
                    </p>
                    <p className="mt-1">
                      {previews[entry.id].artifacts.length} artifact actions · {previews[entry.id].dependencies.length} dependency checks
                    </p>
                    {previews[entry.id].blockers.length > 0 && (
                      <p className="mt-1 font-mono">{previews[entry.id].blockers.join(", ")}</p>
                    )}
                  </div>
                )}
                <div className="mt-3 flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-2"
                    disabled={
                      operationReason.trim().length < 3
                      || busy !== null
                      || entry.revoked
                      || !entry.pack_signer_trusted
                    }
                    onClick={() => void previewPack(entry)}
                  >
                    {busy === `preview:${entry.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />} Verify preview
                  </Button>
                  <Button
                    size="sm"
                    className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]"
                    disabled={
                      operationReason.trim().length < 3
                      || busy !== null
                      || !previews[entry.id]?.installable
                      || entry.installation_state !== "not_installed"
                    }
                    onClick={() => void installPack(entry)}
                  >
                    {busy === `install:${entry.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PackageCheck className="h-3.5 w-3.5" />} Install verified pack
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
